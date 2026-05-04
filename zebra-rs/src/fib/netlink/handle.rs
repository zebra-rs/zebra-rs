use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use futures::stream::StreamExt;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::address::{
    AddressAttribute, AddressHeaderFlags, AddressMessage, AddressScope,
};
use netlink_packet_route::link::{
    AfSpecInet6, AfSpecUnspec, InfoData, InfoKind, InfoVxlan, LinkAttribute, LinkFlags, LinkInfo,
    LinkLayerType, LinkMessage,
};
use netlink_packet_route::nexthop::{NexthopAttribute, NexthopFlags, NexthopGroup, NexthopMessage};
use netlink_packet_route::route::{
    MplsLabel, RouteAddress, RouteAttribute, RouteHeader, RouteLwEnCapType, RouteLwTunnelEncap,
    RouteMessage, RouteMplsIpTunnel, RouteNextHop, RouteProtocol, RouteScope, RouteType, RouteVia,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    LinkDummy,
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_LINK,
    },
    new_connection,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::fib::sysctl::sysctl_enable;
use crate::fib::{FibAddr, FibLink, FibMessage, FibRoute};
use crate::rib::entry::RibEntry;
use crate::rib::inst::IlmEntry;
use crate::rib::route::DEBUG_ADDR;
use crate::rib::{
    AddrGenMode, Bridge, Group, GroupTrait, MacAddr, Nexthop, NexthopMulti, NexthopUni, RibType,
    Vxlan, link,
};

// Flip to true to re-enable IPv6 FIB install diagnostic prints.
const DEBUG_V6: bool = false;

// Flip to true to log every SRv6 SID FIB install / uninstall — the
// pre-send netlink attribute dump for the seg6local route, the
// nexthop-skip notice, and the rib-side resolution trace. Errors from
// the kernel are reported regardless. Mirrored by RIB via this same
// constant (re-exported as `crate::fib::netlink::handle::DEBUG_SID`).
pub const DEBUG_SID: bool = false;

/// Mask the lower (128 - prefix_len) bits of an IPv6 address. The
/// kernel ignores bits past the prefix length on install, but masking
/// keeps the netlink trace honest and the address shape predictable
/// for unit tests.
fn mask_v6(addr: std::net::Ipv6Addr, prefix_len: u8) -> std::net::Ipv6Addr {
    if prefix_len >= 128 {
        return addr;
    }
    let bits = u128::from(addr);
    let shift = 128 - u32::from(prefix_len);
    let mask = !0u128 << shift;
    std::net::Ipv6Addr::from(bits & mask)
}

/// Pick the (table, kind, prefix_len, dest_addr) the kernel needs for
/// a SID install / uninstall. Behavior-driven so install and uninstall
/// stay in lock-step:
///
///   End  : table main, kind=Unicast, /128, sid.addr
///          (`ip -6 route add <SID>/128
///           encap seg6local action End dev sr0`)
///   End.X: table main, kind=Unicast, /128, sid.addr
///   uN   : table main, kind=Unicast, /(LB+LN), masked sid.addr
///          (prefix install — the NEXT-C-SID flavor strips and shifts
///          at runtime, so any function under the locator hits this.
///          Same dummy-device trick as End: pointing the install at sr0
///          instead of lo lets us stay in table=main + kind=Unicast.)
///   uA   : table main, kind=Unicast, /128, sid.addr
///          (per-adjacency function is unique; longest-prefix match
///          picks uA over the wider uN entry)
///
/// uN with no SidStructure falls back to /128 — a degenerate state
/// (uSID locator without a derived structure shouldn't happen), but
/// keeps the call total.
///
/// Both End and uN previously hung off table=local + kind=Local + dev=lo
/// to work around the kernel rejecting unicast routes that point at the
/// loopback. Routing the seg6local action through a dummy (sr0) instead
/// gets us back into table=main with kind=Unicast across the board, which
/// keeps `ip -6 route show` honest and avoids the host-local route quirks
/// (e.g. ip-rule lookup local).
fn sid_route_target(
    behavior: crate::rib::SidBehavior,
    addr: std::net::Ipv6Addr,
    structure: Option<crate::rib::SidStructure>,
) -> (u8, RouteType, u8, std::net::Ipv6Addr) {
    use crate::rib::SidBehavior;
    match behavior {
        SidBehavior::End => (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr),
        SidBehavior::EndX => (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr),
        SidBehavior::UN => {
            let plen = structure
                .map(|s| s.lb_bits.saturating_add(s.ln_bits))
                .unwrap_or(128);
            (
                RouteHeader::RT_TABLE_MAIN,
                RouteType::Unicast,
                plen,
                mask_v6(addr, plen),
            )
        }
        SidBehavior::UA => (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr),
        // End.DT4 / End.DT6 are terminal decap+lookup actions. Same
        // FIB shape as End.X — a /128 host route in table=main with
        // kind=Unicast, pointed at sr0 by the static route's
        // ifindex_origin.
        SidBehavior::EndDT4 | SidBehavior::EndDT6 => {
            (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr)
        }
    }
}

/// Check if the kernel supports nexthop ID (kernel >= 5.3).
/// Nexthop table was introduced in Linux kernel 5.3.
fn kernel_supports_nhid() -> bool {
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        // Parse "Linux version X.Y.Z-..."
        let parts: Vec<&str> = version.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "Linux" && parts[1] == "version" {
            let version_str = parts[2];
            let version_parts: Vec<&str> = version_str.split('.').collect();
            if version_parts.len() >= 2
                && let (Ok(major), Ok(minor)) = (
                    version_parts[0].parse::<u32>(),
                    version_parts[1].parse::<u32>(),
                )
            {
                // Nexthop table introduced in kernel 5.3
                return major > 5 || (major == 5 && minor >= 3);
            }
        }
    }
    // Default to false for safety
    false
}

pub struct FibHandle {
    pub handle: rtnetlink::Handle,
    pub use_nhid: bool,
    /// VNI to VXLAN interface index mapping
    /// Used to resolve VNI to the correct VXLAN device for FDB operations
    pub vni_ifindex_map: BTreeMap<u32, u32>,
}

impl FibHandle {
    pub fn new(rib_tx: UnboundedSender<FibMessage>, no_nhid: bool) -> anyhow::Result<Self> {
        let _ = sysctl_enable();

        let (mut connection, handle, mut messages) = new_connection()?;

        let mgroup_flags = RTMGRP_LINK
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_ROUTE
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV6_IFADDR;

        let addr = SocketAddr::new(0, mgroup_flags);
        connection.socket_mut().socket_mut().bind(&addr)?;

        tokio::spawn(connection);

        let tx = rib_tx.clone();
        tokio::spawn(async move {
            while let Some((message, _)) = messages.next().await {
                process_msg(message, tx.clone());
            }
        });

        // Use nhid unless explicitly disabled or kernel doesn't support it
        let use_nhid = if no_nhid {
            // tracing::info!("Nexthop ID disabled by --no-nhid flag, using embedded nexthop");
            false
        } else if kernel_supports_nhid() {
            // tracing::info!("Kernel supports nexthop ID (>= 5.3)");
            true
        } else {
            // tracing::info!("Kernel does not support nexthop ID (< 5.3), using embedded nexthop");
            false
        };

        Ok(Self {
            handle,
            use_nhid,
            vni_ifindex_map: BTreeMap::new(),
        })
    }

    pub async fn route_ipv4_add_uni(&self, prefix: &Ipv4Net, entry: &RibEntry, nexthop: &Nexthop) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };

        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet(prefix.addr()));
        msg.attributes.push(attr);

        if self.use_nhid {
            // Kernel >= 5.3: use nexthop ID
            if let Nexthop::Uni(uni) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        } else {
            // Kernel < 5.3: embed nexthop directly
            if let Nexthop::Uni(uni) = &nexthop {
                match uni.addr {
                    IpAddr::V4(ipv4) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet(ipv4)));
                    }
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)));
                    }
                }
                if let Some(ifindex) = uni.ifindex() {
                    msg.attributes.push(RouteAttribute::Oif(ifindex));
                }
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();
                    let attr = match uni.addr {
                        IpAddr::V4(ipv4) => RouteAttribute::Gateway(RouteAddress::Inet(ipv4)),
                        IpAddr::V6(ipv6) => RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);
                    if let Some(ifindex) = uni.ifindex() {
                        nhop.attributes.push(RouteAttribute::Oif(ifindex));
                    }
                    mpath.push(nhop);
                }
                msg.attributes.push(RouteAttribute::MultiPath(mpath));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("NewRoute error: {prefix} {e}");
            }
        }
    }

    pub async fn route_ipv4_add(&self, prefix: &Ipv4Net, entry: &RibEntry) {
        if !entry.is_protocol() {
            return;
        }
        match &entry.nexthop {
            Nexthop::Uni(_) => {
                self.route_ipv4_add_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::Multi(_) => {
                self.route_ipv4_add_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::List(pro) => {
                for uni in pro.nexthops.iter() {
                    self.route_ipv4_add_uni(prefix, entry, &Nexthop::Uni(uni.clone()))
                        .await;
                }
            }
            _ => {
                //
            }
        }
    }

    pub async fn route_ipv4_del_uni(&self, prefix: &Ipv4Net, entry: &RibEntry, nexthop: &Nexthop) {
        if !entry.is_protocol() {
            return;
        }
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet(prefix.addr()));
        msg.attributes.push(attr);

        let attr = RouteAttribute::Priority(entry.metric);
        msg.attributes.push(attr);

        if self.use_nhid {
            // Kernel >= 5.3: use nexthop ID
            if let Nexthop::Uni(uni) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        } else {
            // Kernel < 5.3: embed nexthop directly
            if let Nexthop::Uni(uni) = &nexthop {
                match uni.addr {
                    IpAddr::V4(ipv4) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet(ipv4)));
                    }
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)));
                    }
                }
                if let Some(ifindex) = uni.ifindex() {
                    msg.attributes.push(RouteAttribute::Oif(ifindex));
                }
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();
                    let attr = match uni.addr {
                        IpAddr::V4(ipv4) => RouteAttribute::Gateway(RouteAddress::Inet(ipv4)),
                        IpAddr::V6(ipv6) => RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);
                    if let Some(ifindex) = uni.ifindex() {
                        nhop.attributes.push(RouteAttribute::Oif(ifindex));
                    }
                    mpath.push(nhop);
                }
                msg.attributes.push(RouteAttribute::MultiPath(mpath));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelRoute error: {e} {prefix}");
            }
        }
    }

    pub async fn route_ipv4_del(&self, prefix: &Ipv4Net, entry: &RibEntry) {
        if !entry.is_protocol() {
            return;
        }

        match &entry.nexthop {
            Nexthop::Link(_) => {}
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv4_del_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::List(list) => {
                for uni in &list.nexthops {
                    self.route_ipv4_del_uni(prefix, entry, &Nexthop::Uni(uni.clone()))
                        .await;
                }
            }
        }
    }

    pub async fn route_ipv6_add_uni(&self, prefix: &Ipv6Net, entry: &RibEntry, nexthop: &Nexthop) {
        if DEBUG_V6 {
            tracing::info!(
                "[IPv6 route_add_uni] prefix={} prefixlen={} rtype={:?} use_nhid={}",
                prefix,
                prefix.prefix_len(),
                entry.rtype,
                self.use_nhid,
            );
        }

        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.destination_prefix_length = prefix.prefix_len();

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };

        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet6(prefix.addr()));
        msg.attributes.push(attr);

        // Seg6local install (operator-configured End.DT6 / End.DT4 /
        // End / uN on a static IPv6 prefix). The seg6local lwtunnel
        // encap can't ride in the kernel nexthop table, so we always
        // embed it on the route — independently of `use_nhid`. The
        // protocol-allocated SID install path goes through
        // `route_sid_install`, which has the same shape; this branch
        // is the static counterpart so user-configured action routes
        // travel the standard `Message::Ipv6Add` pipeline.
        if let Nexthop::Uni(uni) = &nexthop
            && let Some(action) = uni.seg6local_action
        {
            if let Some(ifindex) = uni.ifindex() {
                msg.attributes.push(RouteAttribute::Oif(ifindex));
            }
            if let Some((encap, encap_type)) =
                super::srv6::build_seg6local_attrs(action, None, None)
            {
                msg.attributes.push(encap);
                msg.attributes.push(encap_type);
            }
            msg.attributes.push(RouteAttribute::Priority(uni.metric));

            let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
            req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            let mut response = self.handle.clone().request(req).unwrap();
            while let Some(m) = response.next().await {
                if let NetlinkPayload::Error(e) = m.payload {
                    tracing::warn!(
                        "NewRoute seg6local install error: prefix={prefix} action={action:?} err={e}"
                    );
                }
            }
            return;
        }

        if self.use_nhid {
            if let Nexthop::Uni(uni) = &nexthop {
                if DEBUG_V6 {
                    tracing::info!(
                        "[IPv6 route_add_uni] using nhid: gid={} metric={}",
                        uni.gid,
                        uni.metric
                    );
                }
                msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                if DEBUG_V6 {
                    tracing::info!(
                        "[IPv6 route_add_uni] using nhid (multi): gid={} metric={}",
                        multi.gid,
                        multi.metric
                    );
                }
                msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        } else {
            if let Nexthop::Uni(uni) = &nexthop {
                if DEBUG_V6 {
                    tracing::info!(
                        "[IPv6 route_add_uni] embed nexthop: addr={} ifindex={:?} metric={}",
                        uni.addr,
                        uni.ifindex(),
                        uni.metric
                    );
                }
                match uni.addr {
                    IpAddr::V4(ipv4) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet(ipv4)));
                    }
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)));
                    }
                }
                if let Some(ifindex) = uni.ifindex() {
                    msg.attributes.push(RouteAttribute::Oif(ifindex));
                }
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);

                // Embedded seg6 encap fallback for kernels < 5.3 that don't
                // support nexthop-table lwtunnel encap. The seg6 attributes
                // ride directly on the route message instead of via Nhid.
                if !uni.segs.is_empty() {
                    let encap_type = uni
                        .encap_type
                        .unwrap_or(isis_packet::srv6::EncapType::HEncap);
                    match super::srv6::build_seg6_attrs(&uni.segs, encap_type) {
                        Ok((encap, encap_type_attr)) => {
                            msg.attributes.push(encap);
                            msg.attributes.push(encap_type_attr);
                        }
                        Err(e) => {
                            tracing::warn!("SRv6 embedded encap build failed for {prefix}: {e:#}");
                            return;
                        }
                    }
                }
            }
            if let Nexthop::Multi(multi) = &nexthop {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();
                    let attr = match uni.addr {
                        IpAddr::V4(ipv4) => RouteAttribute::Gateway(RouteAddress::Inet(ipv4)),
                        IpAddr::V6(ipv6) => RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);
                    if let Some(ifindex) = uni.ifindex() {
                        nhop.attributes.push(RouteAttribute::Oif(ifindex));
                    }
                    mpath.push(nhop);
                }
                msg.attributes.push(RouteAttribute::MultiPath(mpath));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        }

        if DEBUG_V6 {
            tracing::info!(
                "[IPv6 route_add_uni] netlink request: af={:?} dest_prefix_len={} attrs={:?}",
                msg.header.address_family,
                msg.header.destination_prefix_length,
                msg.attributes
            );
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload
                && DEBUG_ADDR
            {
                tracing::info!("NewRoute IPv6 error: {prefix} {e}");
            }
        }
    }

    pub async fn route_ipv6_add(&self, prefix: &Ipv6Net, entry: &RibEntry) {
        if !entry.is_protocol() {
            return;
        }
        match &entry.nexthop {
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv6_add_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::List(pro) => {
                for uni in pro.nexthops.iter() {
                    self.route_ipv6_add_uni(prefix, entry, &Nexthop::Uni(uni.clone()))
                        .await;
                }
            }
            _ => {}
        }
    }

    pub async fn route_ipv6_del_uni(&self, prefix: &Ipv6Net, entry: &RibEntry, nexthop: &Nexthop) {
        if !entry.is_protocol() {
            return;
        }

        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.destination_prefix_length = prefix.prefix_len();

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet6(prefix.addr()));
        msg.attributes.push(attr);

        let attr = RouteAttribute::Priority(entry.metric);
        msg.attributes.push(attr);

        // Mirror the seg6local install: when the route was a
        // seg6local route, the kernel matches del on
        // {prefix, table, kind} alone — no encap attrs needed in
        // the del message. Sending the Oif still helps when the
        // user has stacked multiple actions on the same prefix
        // (rare, but harmless to include).
        if let Nexthop::Uni(uni) = &nexthop
            && uni.seg6local_action.is_some()
        {
            if let Some(ifindex) = uni.ifindex() {
                msg.attributes.push(RouteAttribute::Oif(ifindex));
            }
            let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
            req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
            let mut response = self.handle.clone().request(req).unwrap();
            while let Some(m) = response.next().await {
                if let NetlinkPayload::Error(e) = m.payload {
                    tracing::warn!("DelRoute seg6local error: prefix={prefix} err={e}");
                }
            }
            return;
        }

        if self.use_nhid {
            if let Nexthop::Uni(uni) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        } else {
            if let Nexthop::Uni(uni) = &nexthop {
                match uni.addr {
                    IpAddr::V4(ipv4) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet(ipv4)));
                    }
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)));
                    }
                }
                if let Some(ifindex) = uni.ifindex() {
                    msg.attributes.push(RouteAttribute::Oif(ifindex));
                }
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();
                    let attr = match uni.addr {
                        IpAddr::V4(ipv4) => RouteAttribute::Gateway(RouteAddress::Inet(ipv4)),
                        IpAddr::V6(ipv6) => RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);
                    if let Some(ifindex) = uni.ifindex() {
                        nhop.attributes.push(RouteAttribute::Oif(ifindex));
                    }
                    mpath.push(nhop);
                }
                msg.attributes.push(RouteAttribute::MultiPath(mpath));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload
                && DEBUG_ADDR
            {
                tracing::info!("DelRoute IPv6 error: {e} {prefix}");
            }
        }
    }

    pub async fn route_ipv6_del(&self, prefix: &Ipv6Net, entry: &RibEntry) {
        if !entry.is_protocol() {
            return;
        }

        match &entry.nexthop {
            Nexthop::Link(_) => {}
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv6_del_uni(prefix, entry, &entry.nexthop).await;
            }
            Nexthop::List(list) => {
                for uni in &list.nexthops {
                    self.route_ipv6_del_uni(prefix, entry, &Nexthop::Uni(uni.clone()))
                        .await;
                }
            }
        }
    }

    pub async fn nexthop_add(&self, nexthop: &Group) {
        // Skip nexthop table management for kernels < 5.3
        if !self.use_nhid {
            return;
        }

        // Nexthop message.
        let mut msg = NexthopMessage::default();
        msg.header.protocol = RouteProtocol::Zebra;
        msg.header.flags = NexthopFlags::Onlink;

        // Logging purpose.
        let gid: usize;
        let refcnt: usize;

        match nexthop {
            Group::Uni(uni) => {
                // Logging.
                gid = uni.gid();
                refcnt = uni.refcnt();

                if DEBUG_V6 {
                    tracing::info!(
                        "[nexthop_add Uni] gid={} addr={} ifindex={:?} valid={} installed={}",
                        gid,
                        uni.addr,
                        uni.ifindex(),
                        uni.is_valid(),
                        uni.is_installed(),
                    );
                }

                // seg6local can't be advertised via the kernel nexthop
                // table — only seg6 (encap) and mpls are supported as
                // lwtunnel encaps under nh_id. The route install path
                // embeds the encap on the route message instead, so
                // there's nothing to push here. NexthopMap still
                // refcounts the logical group for dedup / cleanup
                // bookkeeping inside zebra-rs.
                if uni.seg6local_action.is_some() {
                    if DEBUG_SID {
                        tracing::info!(
                            "[nexthop_add seg6local] gid={} skipped — seg6local \
                             install rides on the route, not the nh_id",
                            uni.gid(),
                        );
                    }
                    return;
                }

                // Address family follows the gateway address.
                msg.header.address_family = match uni.addr {
                    std::net::IpAddr::V4(_) => AddressFamily::Inet,
                    std::net::IpAddr::V6(_) => AddressFamily::Inet6,
                };

                // Nexthop group ID.
                let attr = NexthopAttribute::Id(uni.gid() as u32);
                msg.attributes.push(attr);

                // Gateway address.
                let attr = match uni.addr {
                    std::net::IpAddr::V4(ipv4) => {
                        NexthopAttribute::Gateway(RouteAddress::Inet(ipv4))
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        NexthopAttribute::Gateway(RouteAddress::Inet6(ipv6))
                    }
                };
                msg.attributes.push(attr);

                // Outgoing if. Origin wins over resolved; fall back to 0
                // ("no Oif attribute") if neither was filled, which is a
                // bug case the kernel will reject — we want it loud.
                let attr = NexthopAttribute::Oif(uni.ifindex().unwrap_or(0));
                msg.attributes.push(attr);

                if DEBUG_V6 {
                    tracing::info!(
                        "[nexthop_add Uni] netlink: af={:?} attrs={:?}",
                        msg.header.address_family,
                        msg.attributes
                    );
                }

                // MPLS.
                if !uni.labels.is_empty() {
                    let attr = NexthopAttribute::EncapType(RouteLwEnCapType::Mpls.into());
                    msg.attributes.push(attr);

                    let last = uni.labels.len() - 1;
                    let stack: Vec<MplsLabel> = uni
                        .labels
                        .iter()
                        .enumerate()
                        .map(|(i, &label)| MplsLabel {
                            label,
                            traffic_class: 0,
                            bottom_of_stack: i == last,
                            ttl: 0,
                        })
                        .collect();
                    let mpls = RouteMplsIpTunnel::Destination(stack);
                    let encap = RouteLwTunnelEncap::Mpls(mpls);
                    let attr = NexthopAttribute::Encap(vec![encap]);
                    msg.attributes.push(attr);
                }

                // SRv6 H.Encap. Mutually exclusive with the MPLS branch
                // above — a NexthopUni won't carry both labels and segs.
                if !uni.segs.is_empty() {
                    let encap_type = uni
                        .encap_type
                        .unwrap_or(isis_packet::srv6::EncapType::HEncap);
                    match super::srv6::build_seg6_lwtunnel(&uni.segs, encap_type) {
                        Ok(lwencap) => {
                            msg.attributes
                                .push(NexthopAttribute::EncapType(RouteLwEnCapType::Seg6.into()));
                            msg.attributes.push(NexthopAttribute::Encap(vec![lwencap]));
                        }
                        Err(e) => {
                            tracing::warn!(
                                "SRv6 nexthop encap build failed for gid {}: {:#}",
                                uni.gid(),
                                e
                            );
                            return;
                        }
                    }
                }
            }
            Group::Multi(multi) => {
                // Logging.
                gid = multi.gid();
                refcnt = multi.refcnt();

                // Unspec.
                msg.header.address_family = AddressFamily::Unspec;

                let attr = NexthopAttribute::Id(multi.gid() as u32);
                msg.attributes.push(attr);

                let attr = NexthopAttribute::GroupType(0);
                msg.attributes.push(attr);

                let mut vec = Vec::<NexthopGroup>::new();
                for (id, weight) in multi.valid.iter() {
                    let mut grp = NexthopGroup::default();
                    let weight = if *weight > 0 { *weight - 1 } else { 0 };
                    grp.id = *id as u32;
                    grp.weight = weight;
                    vec.push(grp);
                }
                let attr = NexthopAttribute::Group(vec);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            match msg.payload {
                NetlinkPayload::Error(e) => {
                    tracing::info!("NewNexthop error: {e} gid: {gid} refcnt: {refcnt}");
                }
                NetlinkPayload::Done(m) => {
                    tracing::info!("NewNexthop done {m:?}");
                }
                _ => {
                    tracing::info!("NewNexthop other return");
                }
            }
        }
    }

    pub async fn nexthop_del(&self, nexthop: &Group) {
        // Skip nexthop table management for kernels < 5.3
        if !self.use_nhid {
            return;
        }

        // Nexthop message.
        let mut msg = NexthopMessage::default();
        msg.header.address_family = AddressFamily::Unspec;

        // Nexthop group ID.
        let attr = NexthopAttribute::Id(nexthop.gid() as u32);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!(
                    "DelNexthop error: {e} gid: {gid} refcnt: {refcnt} nhop: {nexthop:?}",
                    gid = nexthop.gid(),
                    refcnt = nexthop.refcnt(),
                    nexthop = nexthop,
                );
            }
        }
    }

    /// Install an SRv6 SID into the FIB as a local /128 host route.
    /// Uses the nh_id allocated from NexthopMap when the kernel supports
    /// it, otherwise falls back to embedded seg6local encap on the route
    /// itself (kernels < 5.3).
    pub async fn route_sid_install(&self, sid: &crate::rib::Sid, gid: usize, ifindex: u32) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        // {table, kind, prefix_length, dest_addr} all derive from the
        // behavior. The kernel matches install + uninstall on these
        // four header values, so route_sid_uninstall mirrors the same
        // computation.
        //
        //   End  : table main, kind=unicast, /128, sid.addr
        //          (`ip -6 route add <SID>/128
        //           encap seg6local action End dev sr0`)
        //   End.X: table main, kind=unicast, /128, sid.addr
        //          (`ip -6 route add <SID>/128
        //           encap seg6local action End.X nh6 ... dev ...`)
        //   uN   : table main, kind=unicast, /(LB+LN), masked addr
        //          (`ip -6 route add <locator>/<LB+LN>
        //           encap seg6local action End flavors next-csid
        //           lblen <LB> nflen <LN+Fun> dev sr0`)
        //          uN is a *prefix* install so any function value
        //          under the locator hits this entry; the kernel's
        //          NEXT-C-SID flavor strips and shifts at runtime.
        //   uA   : table main, kind=unicast, /128, sid.addr
        //          Each adjacency function is a unique address;
        //          longest-prefix match picks uA over the wider uN
        //          entry. /128 keeps it simple and matches iproute2.
        // RT_TABLE_LOCAL (255) — the fork doesn't expose a named
        // constant for it, so hard-code. See linux/rtnetlink.h.
        let (table, kind, prefix_len, dest_addr) =
            sid_route_target(sid.behavior, sid.addr, sid.structure);
        msg.header.table = table;
        msg.header.destination_prefix_length = prefix_len;
        msg.header.protocol = RouteProtocol::Isis;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = kind;

        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(dest_addr)));

        // seg6local always rides as embedded encap on the route — the
        // kernel nh_id table doesn't accept seg6local lwtunnel encaps
        // even when use_nhid is true for the rest of the FIB. Set Oif
        // so the kernel knows where to bind the action; for End / uN
        // that's loopback, for End.X / uA the outgoing link.
        let _ = gid;
        if ifindex != 0 {
            msg.attributes.push(RouteAttribute::Oif(ifindex));
        }
        let Some((encap, encap_type)) =
            super::srv6::build_seg6local_attrs(sid.behavior, sid.nh6, sid.structure)
        else {
            tracing::warn!(
                "seg6local route encap build skipped for {} (End.X / uA without IPv6 nexthop)",
                sid.addr
            );
            return;
        };
        msg.attributes.push(encap);
        msg.attributes.push(encap_type);

        if DEBUG_SID {
            tracing::info!(
                "[route_sid_install] addr={}/{} behavior={:?} ifindex={} nh6={:?} gid={} \
                 use_nhid={} kind={:?} protocol={:?} attrs={:?}",
                sid.addr,
                msg.header.destination_prefix_length,
                sid.behavior,
                ifindex,
                sid.nh6,
                gid,
                self.use_nhid,
                msg.header.kind,
                msg.header.protocol,
                msg.attributes,
            );
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                // warn level so kernel rejections show up without
                // requiring DEBUG_SID — silent failures here are how
                // a misshaped seg6local install slips through.
                tracing::warn!(
                    "NewRoute SID install error: addr={} behavior={:?} \
                     prefix_len={} table={} kind={:?} ifindex={} nh6={:?} \
                     gid={} use_nhid={} err={}",
                    sid.addr,
                    sid.behavior,
                    prefix_len,
                    table,
                    kind,
                    ifindex,
                    sid.nh6,
                    gid,
                    self.use_nhid,
                    e
                );
            }
        }
    }

    /// Remove a previously-installed SID host route. Idempotent against
    /// the kernel — a missing entry surfaces as an error in the trace
    /// but doesn't propagate.
    pub async fn route_sid_uninstall(&self, sid: &crate::rib::Sid) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        // Same {table, kind, prefix_len, dest_addr} the install used
        // — the kernel matches RTM_DELROUTE on (table, family, dst,
        // prefixlen, kind).
        let (table, kind, prefix_len, dest_addr) =
            sid_route_target(sid.behavior, sid.addr, sid.structure);
        msg.header.table = table;
        msg.header.destination_prefix_length = prefix_len;
        msg.header.protocol = RouteProtocol::Isis;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = kind;

        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(dest_addr)));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                tracing::info!(
                    "DelRoute SID uninstall error: addr={} behavior={:?} err={}",
                    sid.addr,
                    sid.behavior,
                    e
                );
            }
        }
    }

    pub async fn bridge_add(&self, bridge: &Bridge) {
        // First create the bridge interface
        let mut msg = LinkMessage::default();

        let name = LinkAttribute::IfName(bridge.name.clone());
        msg.attributes.push(name);

        let kind = InfoKind::Bridge;
        let link_kind = LinkInfo::Kind(kind);

        let link_info = LinkAttribute::LinkInfo(vec![link_kind]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("NewLink bridge error: {e}");
                return;
            }
        }

        // If we have addr_gen_mode, set it as a second operation
        if let Some(addr_gen_mode) = &bridge.addr_gen_mode {
            self.bridge_set_addr_gen_mode(&bridge.name, addr_gen_mode)
                .await;
        }
    }

    pub async fn bridge_set_addr_gen_mode(&self, name: &str, addr_gen_mode: &AddrGenMode) {
        let mut msg = LinkMessage::default();

        let link_name = LinkAttribute::IfName(name.to_string());
        msg.attributes.push(link_name);

        let mode =
            LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(vec![AfSpecInet6::AddrGenMode(
                u8::from(addr_gen_mode.clone()),
            )])]);
        msg.attributes.push(mode);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink addr-gen-mode error: {e}");
            }
        }
    }

    pub async fn bridge_del(&self, bridge: &Bridge) {
        let mut msg = LinkMessage::default();

        let name = LinkAttribute::IfName(bridge.name.clone());
        msg.attributes.push(name);

        let kind = InfoKind::Bridge;
        let link_kind = LinkInfo::Kind(kind);

        let link_info = LinkAttribute::LinkInfo(vec![link_kind]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelLink error: {}", e);
            }
        }
    }

    pub async fn vxlan_add(&self, vxlan: &Vxlan) {
        // VNI.
        let Some(vni) = vxlan.vni else {
            return;
        };

        // First create the vxlan interface
        let mut msg = LinkMessage::default();

        let name = LinkAttribute::IfName(vxlan.name.clone());
        msg.attributes.push(name);

        // Link kind is VxLAN.
        let kind = InfoKind::Vxlan;
        let link_kind = LinkInfo::Kind(kind);

        // VNI encode.
        let vni = InfoVxlan::Id(vni);
        let mut vxlan_info = vec![vni];

        // Destination port.
        if let Some(dport) = vxlan.dport {
            let port = InfoVxlan::Port(dport);
            vxlan_info.push(port);
        }

        // Local address.
        if let Some(local_addr) = vxlan.local_addr {
            let info = match local_addr {
                IpAddr::V4(addr) => InfoVxlan::Local(addr.octets().to_vec()),
                IpAddr::V6(addr) => InfoVxlan::Local6(addr.octets().to_vec()),
            };
            vxlan_info.push(info);
        }
        let link_info = LinkInfo::Data(InfoData::Vxlan(vxlan_info));

        let attr = LinkAttribute::LinkInfo(vec![link_kind, link_info]);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("NewLink vxlan error: {e}");
                return;
            }
        }

        // If we have addr_gen_mode, set it as a second operation
        if let Some(addr_gen_mode) = &vxlan.addr_gen_mode {
            self.vxlan_set_addr_gen_mode(&vxlan.name, addr_gen_mode)
                .await;
        }
    }

    pub async fn vxlan_set_addr_gen_mode(&self, name: &str, addr_gen_mode: &AddrGenMode) {
        let mut msg = LinkMessage::default();

        let link_name = LinkAttribute::IfName(name.to_string());
        msg.attributes.push(link_name);

        let mode =
            LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(vec![AfSpecInet6::AddrGenMode(
                u8::from(addr_gen_mode.clone()),
            )])]);
        msg.attributes.push(mode);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink addr-gen-mode error: {e}");
            }
        }
    }

    pub async fn vxlan_del(&self, vxlan: &Vxlan) {
        let mut msg = LinkMessage::default();

        let name = LinkAttribute::IfName(vxlan.name.clone());
        msg.attributes.push(name);

        let kind = InfoKind::Vxlan;
        let link_kind = LinkInfo::Kind(kind);

        let link_info = LinkAttribute::LinkInfo(vec![link_kind]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelLink error: {}", e);
            }
        }
    }

    pub async fn link_set_up(&self, ifindex: u32) {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("link_set_up error: {}", e);
            }
        }
    }

    /// Look up a link's ifindex by name via RTM_GETLINK. Returns None on
    /// kernel rejection (most often "device not found").
    pub async fn link_index_by_name(&self, name: &str) -> Option<u32> {
        use futures::TryStreamExt;
        let mut stream = self
            .handle
            .clone()
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match stream.try_next().await {
            Ok(Some(msg)) => Some(msg.header.index),
            _ => None,
        }
    }

    /// Create a dummy link with the given name. Returns the ifindex the
    /// kernel assigned, or None if creation failed (already exists with a
    /// conflicting type, etc.). Mirrors `ip link add <name> type dummy`.
    pub async fn dummy_add(&self, name: &str) -> Option<u32> {
        let result = self
            .handle
            .clone()
            .link()
            .add(LinkDummy::new(name).build())
            .execute()
            .await;
        if let Err(e) = result {
            tracing::warn!("dummy_add({}) error: {}", name, e);
            return None;
        }
        self.link_index_by_name(name).await
    }

    /// Delete a link by name. Idempotent — missing names log at info but
    /// don't propagate.
    pub async fn dummy_del(&self, name: &str) {
        let Some(ifindex) = self.link_index_by_name(name).await else {
            tracing::info!("dummy_del({}) skipped — not present", name);
            return;
        };
        if let Err(e) = self.handle.clone().link().del(ifindex).execute().await {
            tracing::warn!("dummy_del({}) error: {}", name, e);
        }
    }

    pub async fn addr_add_ipv4(
        &self,
        ifindex: u32,
        prefix: &Ipv4Net,
        secondary: bool,
    ) -> anyhow::Result<()> {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;
        msg.header.scope = AddressScope::Universe;
        if secondary {
            msg.header.flags = AddressHeaderFlags::Secondary;
        }
        let attr = AddressAttribute::Local(IpAddr::V4(prefix.addr()));
        msg.attributes.push(attr);

        // If interface is p2p.
        if false {
            let attr = AddressAttribute::Address(IpAddr::V4(prefix.addr()));
            msg.attributes.push(attr);
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self.handle.clone().request(req)?;
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                return Err(anyhow::anyhow!("NewAddress netlink error: {}", e));
            }
        }
        Ok(())
    }

    pub async fn addr_del_ipv4(&self, ifindex: u32, prefix: &Ipv4Net) {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;

        let attr = AddressAttribute::Local(IpAddr::V4(prefix.addr()));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelAddress error: {}", e);
            }
        }
    }

    pub async fn addr_add_ipv6(
        &self,
        ifindex: u32,
        prefix: &Ipv6Net,
        secondary: bool,
    ) -> anyhow::Result<()> {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet6;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;
        msg.header.scope = AddressScope::Universe;
        if secondary {
            msg.header.flags = AddressHeaderFlags::Secondary;
        }
        let attr = AddressAttribute::Local(IpAddr::V6(prefix.addr()));
        msg.attributes.push(attr);

        // If interface is p2p.
        if false {
            let attr = AddressAttribute::Address(IpAddr::V6(prefix.addr()));
            msg.attributes.push(attr);
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self.handle.clone().request(req)?;
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                return Err(anyhow::anyhow!("NewAddress IPv6 netlink error: {}", e));
            }
        }
        Ok(())
    }

    pub async fn addr_del_ipv6(&self, ifindex: u32, prefix: &Ipv6Net) {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet6;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;

        let attr = AddressAttribute::Local(IpAddr::V6(prefix.addr()));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelAddress IPv6 error: {}", e);
            }
        }
    }

    pub async fn ilm_add(&self, label: u32, ilm: &IlmEntry) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Mpls;
        msg.header.destination_prefix_length = 20;

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = match ilm.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };

        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        match ilm.nexthop {
            Nexthop::Uni(ref uni) => {
                let attr = match uni.addr {
                    std::net::IpAddr::V4(ipv4) => RouteAttribute::Via(RouteVia::Inet(ipv4)),
                    std::net::IpAddr::V6(ipv6) => RouteAttribute::Via(RouteVia::Inet6(ipv6)),
                };
                msg.attributes.push(attr);

                if let Some(ifindex) = uni.ifindex() {
                    let attr = RouteAttribute::Oif(ifindex);
                    msg.attributes.push(attr);
                }

                for &label in uni.mpls_label.iter() {
                    let label = MplsLabel {
                        label,
                        traffic_class: 0,
                        bottom_of_stack: true,
                        ttl: 0,
                    };
                    let attr = RouteAttribute::NewDestination(vec![label]);
                    msg.attributes.push(attr);
                }
            }
            Nexthop::Multi(ref multi) => {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();

                    let attr = match uni.addr {
                        std::net::IpAddr::V4(ipv4) => RouteAttribute::Via(RouteVia::Inet(ipv4)),
                        std::net::IpAddr::V6(ipv6) => RouteAttribute::Via(RouteVia::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);

                    if let Some(ifindex) = uni.ifindex() {
                        let attr = RouteAttribute::Oif(ifindex);
                        nhop.attributes.push(attr);
                    }

                    for &label in uni.mpls_label.iter() {
                        let label = MplsLabel {
                            label,
                            traffic_class: 0,
                            bottom_of_stack: true,
                            ttl: 0,
                        };
                        let attr = RouteAttribute::NewDestination(vec![label]);
                        nhop.attributes.push(attr);
                    }

                    mpath.push(nhop);
                }
                let attr = RouteAttribute::MultiPath(mpath);
                msg.attributes.push(attr);
            }
            _ => {
                // no supoort.
                return;
            }
        }

        let attr = RouteAttribute::Destination(RouteAddress::Mpls(MplsLabel {
            label,
            traffic_class: 0,
            bottom_of_stack: true,
            ttl: 0,
        }));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("NewRoute error: {label}: {e}");
            }
        }
    }

    pub async fn ilm_del(&self, label: u32, ilm: &IlmEntry) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Mpls;
        msg.header.destination_prefix_length = 20;

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = match ilm.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };

        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Mpls(MplsLabel {
            label,
            traffic_class: 0,
            bottom_of_stack: true,
            ttl: 0,
        }));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelRoute error: {}", e);
            }
        }
    }

    /// Register VXLAN interface with its VNI for FDB operations
    /// Called when a VXLAN interface is created to establish VNI→ifindex mapping
    pub fn register_vxlan_ifindex(&mut self, vni: u32, ifindex: u32) {
        tracing::info!(
            "[FIB] Registered VXLAN VNI {} with ifindex {}",
            vni,
            ifindex
        );
        self.vni_ifindex_map.insert(vni, ifindex);
    }

    /// Unregister VXLAN interface mapping
    pub fn unregister_vxlan_ifindex(&mut self, vni: u32) {
        tracing::info!("[FIB] Unregistered VXLAN VNI {}", vni);
        self.vni_ifindex_map.remove(&vni);
    }

    /// Add EVPN MAC entry to bridge FDB
    /// Uses RTM_NEWNEIGH to install MAC address in kernel bridge
    pub async fn mac_add(
        &self,
        vni: u32,
        mac: &MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        _seq: u32,
        esi: Option<[u8; 10]>,
    ) {
        // Resolve VNI to VXLAN interface index using the registered mapping
        // If not found, use VNI as fallback (for testing/simple configs)
        let vxlan_ifindex = self.vni_ifindex_map.get(&vni).copied().unwrap_or(vni);

        // Build bridge FDB entry using rtnetlink neighbours API
        use netlink_packet_route::neighbour::{NeighbourAttribute, NeighbourMessage};

        // Create neighbour message for bridge FDB
        let mut msg = NeighbourMessage::default();
        msg.header.family = AddressFamily::Bridge;
        msg.header.ifindex = vxlan_ifindex;
        // NUD_PERMANENT = 0x80
        msg.header.state = netlink_packet_route::neighbour::NeighbourState::Other(0x80);

        // Set flags: NTF_SELF (0x02) | NTF_EXT_LEARNED (0x10), and optionally NTF_STICKY (0x40)
        let mut flag_value: u8 = 0x02 | 0x10;
        if (flags & 0x01) != 0 {
            flag_value |= 0x40;
        }
        use netlink_packet_route::neighbour::NeighbourFlags;
        msg.header.flags = NeighbourFlags::from_bits_retain(flag_value);

        // Add MAC address (NDA_LLADDR)
        msg.attributes
            .push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));

        // Add VNI (NDA_VNI)
        msg.attributes.push(NeighbourAttribute::Vni(vni));

        // Add SRC_VNI (NDA_SRC_VNI)
        msg.attributes.push(NeighbourAttribute::SourceVni(vni));

        // Add Port (NDA_PORT)
        msg.attributes.push(NeighbourAttribute::Port(4789));

        // Add tunnel endpoint (NDA_DST for VXLAN remote VTEP)
        // This attribute is interpreted differently in AF_BRIDGE context:
        // In AF_BRIDGE with VXLAN, NDA_DST specifies the remote tunnel endpoint IP
        if let Some(endpoint) = tunnel_endpoint {
            use netlink_packet_route::neighbour::NeighbourAddress;
            let addr = match endpoint {
                IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
                IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
            };
            msg.attributes
                .push(NeighbourAttribute::TunnelEndpoint(addr));
        }

        // Phase 4D: ESI received and stored. Kernel multi-homing via NDA_NH_ID
        // will be wired in Phase 5 when ECMP nexthop groups are supported.
        if let Some(esi_val) = esi
            && esi_val != [0u8; 10]
        {
            // ESI[0] is the ESI type. ESI[1..9] is the type-specific value.
            tracing::info!("mac_add: ESI type {} for MAC {}", esi_val[0], mac);
        }

        // Build netlink request
        use netlink_packet_route::RouteNetlinkMessage;
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewNeighbour(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE;

        // Send request
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                let has_mapping = self.vni_ifindex_map.contains_key(&vni);
                tracing::info!(
                    "MAC add error for {} (VNI {}, ifindex {}, vni_ifindex_map exists: {}): {}",
                    mac,
                    vni,
                    vxlan_ifindex,
                    has_mapping,
                    e
                );
                if !has_mapping {
                    tracing::info!(
                        "  → VNI {} not registered in vni_ifindex_map (did VXLAN interface register?)",
                        vni
                    );
                }
            }
        }
    }

    /// Delete EVPN MAC entry from bridge FDB
    pub async fn mac_del(&self, vni: u32, mac: &MacAddr) {
        // Resolve VNI to VXLAN interface index using the registered mapping
        let vxlan_ifindex = self.vni_ifindex_map.get(&vni).copied().unwrap_or(vni);

        // Build delete request via netlink
        use netlink_packet_route::neighbour::{NeighbourAttribute, NeighbourMessage};

        let mut msg = NeighbourMessage::default();
        msg.header.family = AddressFamily::Bridge;
        msg.header.ifindex = vxlan_ifindex;

        // Add MAC address for identification
        msg.attributes
            .push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));

        // Add VNI for identification
        msg.attributes.push(NeighbourAttribute::Vni(vni));

        // Build netlink request
        use netlink_packet_route::RouteNetlinkMessage;
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelNeighbour(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        // Send request
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                let has_mapping = self.vni_ifindex_map.contains_key(&vni);
                tracing::info!(
                    "MAC del error for {} (VNI {}, ifindex {}, vni_ifindex_map exists: {}): {}",
                    mac,
                    vni,
                    vxlan_ifindex,
                    has_mapping,
                    e
                );
                if !has_mapping {
                    tracing::info!(
                        "  → VNI {} not registered in vni_ifindex_map (did VXLAN interface register?)",
                        vni
                    );
                }
            }
        }
    }

    /// Add EVPN Type 3 (Inclusive Multicast) entry to kernel MDB
    ///
    /// This creates a multicast database entry for a multicast group that should
    /// be replicated to remote VTEPs. The group and source are encoded in the MDB
    /// entry for kernel multicast forwarding.
    pub async fn mdb_add(
        &self,
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        ifindex: u32,
        seq: u32,
    ) {
        use netlink_packet_route::mdb::{MdbAttribute, MdbMessage};

        // Resolve VNI to VXLAN interface index
        let vxlan_ifindex = ifindex;

        let mut msg = MdbMessage::default();
        msg.header.family = AddressFamily::Bridge;
        msg.header.index = vxlan_ifindex;

        // Encode multicast group and source into MDB entry
        // Format: group_addr (4/16 bytes) + optional source_addr (4/16 bytes)
        let mut mdb_entry_data = Vec::new();
        match group {
            IpAddr::V4(v4) => mdb_entry_data.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => mdb_entry_data.extend_from_slice(&v6.octets()),
        }
        if let Some(src) = source {
            match src {
                IpAddr::V4(v4) => mdb_entry_data.extend_from_slice(&v4.octets()),
                IpAddr::V6(v6) => mdb_entry_data.extend_from_slice(&v6.octets()),
            }
        }

        msg.attributes.push(MdbAttribute::MdbEntry(mdb_entry_data));

        // Build netlink request with RTM_NEWMDB
        use netlink_packet_route::RouteNetlinkMessage;
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewMdb(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
        req.header.sequence_number = seq;

        // Send request
        let mut response = match self.handle.clone().request(req) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::info!("MDB add request error for group {}: {}", group, e);
                return;
            }
        };

        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!(
                    "MDB add error for group {} on VNI {} (ifindex {}, source: {:?}): {}",
                    group,
                    vni,
                    ifindex,
                    source,
                    e
                );
                tracing::info!(
                    "  → Likely cause: VXLAN interface not created or MDB entry format invalid"
                );
                tracing::info!("  → Check if VXLAN interface exists: ip link show");
                tracing::info!("  → Check if interface supports MDB: bridge mdb show");
            }
        }
    }

    /// Delete EVPN Type 3 (Inclusive Multicast) entry from kernel MDB
    pub async fn mdb_del(&self, vni: u32, group: IpAddr, source: Option<IpAddr>, ifindex: u32) {
        use netlink_packet_route::mdb::{MdbAttribute, MdbMessage};

        let vxlan_ifindex = ifindex;

        let mut msg = MdbMessage::default();
        msg.header.family = AddressFamily::Bridge;
        msg.header.index = vxlan_ifindex;

        // Encode multicast group and source for deletion
        let mut mdb_entry_data = Vec::new();
        match group {
            IpAddr::V4(v4) => mdb_entry_data.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => mdb_entry_data.extend_from_slice(&v6.octets()),
        }
        if let Some(src) = source {
            match src {
                IpAddr::V4(v4) => mdb_entry_data.extend_from_slice(&v4.octets()),
                IpAddr::V6(v6) => mdb_entry_data.extend_from_slice(&v6.octets()),
            }
        }

        msg.attributes.push(MdbAttribute::MdbEntry(mdb_entry_data));

        // Build netlink request with RTM_DELMDB
        use netlink_packet_route::RouteNetlinkMessage;
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelMdb(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        // Send request
        let mut response = match self.handle.clone().request(req) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::info!("MDB del request error for group {}: {}", group, e);
                return;
            }
        };

        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("MDB del error for group {} on VNI {}: {}", group, vni, e);
            }
        }
    }
}

fn link_type_msg(link_type: LinkLayerType) -> link::LinkType {
    match link_type {
        LinkLayerType::Ether => link::LinkType::Ethernet,
        LinkLayerType::Loopback => link::LinkType::Loopback,
        _ => link::LinkType::Ethernet,
    }
}

pub fn link_from_msg(msg: LinkMessage) -> FibLink {
    let mut link = FibLink::new();
    link.index = msg.header.index;
    link.link_type = link_type_msg(msg.header.link_layer_type);
    link.flags = msg.header.flags;
    for attr in msg.attributes.into_iter() {
        match attr {
            LinkAttribute::IfName(name) => {
                link.name = name;
            }
            LinkAttribute::Mtu(mtu) => {
                link.mtu = mtu;
            }
            LinkAttribute::Address(addr) => {
                link.mac = MacAddr::from_vec(addr);
                // if addr.len() == 6 {
                //     let slice = addr.as_slice();
                //     let mut mac = [0u8; 6];
                //     mac.copy_from_slice(slice);
                //     link.mac = Some(mac);
                // }
            }
            _ => {}
        }
    }

    link
}

pub fn addr_from_msg(msg: AddressMessage) -> FibAddr {
    let mut os_addr = FibAddr::new();
    os_addr.link_index = msg.header.index;
    for attr in msg.attributes.into_iter() {
        match attr {
            AddressAttribute::Address(addr) => match addr {
                IpAddr::V4(v4) => {
                    if let Ok(v4) = Ipv4Net::new(v4, msg.header.prefix_len) {
                        os_addr.addr = IpNet::V4(v4);
                    }
                }
                IpAddr::V6(v6) => {
                    if let Ok(v6) = Ipv6Net::new(v6, msg.header.prefix_len) {
                        os_addr.addr = IpNet::V6(v6);
                    }
                }
            },
            _ => {
                //
            }
        }
    }
    os_addr
}

struct RouteBuilder {
    pub prefix: Option<IpNet>,
    pub entry: RibEntry,
}

impl RouteBuilder {
    pub fn new() -> Self {
        let mut entry = RibEntry::new(RibType::Kernel);
        entry.set_valid(true);
        Self {
            prefix: None,
            entry,
        }
    }

    pub fn build(mut self) -> (IpNet, RibEntry) {
        match &mut self.entry.nexthop {
            Nexthop::Uni(uni) => {
                // Kernel-dump path: the entry.ifindex is what netlink
                // reported, so it's an origin (the kernel's source of
                // truth). 0 means "no Oif attribute on this route" —
                // record as None rather than fabricate an origin.
                uni.ifindex_origin = (self.entry.ifindex != 0).then_some(self.entry.ifindex);
                uni.metric = self.entry.metric;
            }
            _ => {
                //
            }
        }
        (self.prefix.unwrap(), self.entry)
    }

    pub fn ipv4_prefix(mut self, prefix: Ipv4Net) -> Self {
        self.prefix = Some(IpNet::V4(prefix));
        self
    }

    pub fn ipv6_prefix(mut self, prefix: Ipv6Net) -> Self {
        self.prefix = Some(IpNet::V6(prefix));
        self
    }

    pub fn rtype(mut self, rtype: RibType) -> Self {
        self.entry.rtype = rtype;
        self
    }

    pub fn nexthop(mut self, nexthop: Nexthop) -> Self {
        self.entry.nexthop = nexthop;
        self
    }

    pub fn oif(mut self, oif: u32) -> Self {
        self.entry.ifindex = oif;
        self
    }

    pub fn metric(mut self, metric: u32) -> Self {
        self.entry.metric = metric;
        self
    }

    pub fn is_ipv4(&self) -> bool {
        let Some(prefix) = &self.prefix else {
            return false;
        };
        matches!(prefix, IpNet::V4(_))
    }
}

pub fn route_from_msg(msg: RouteMessage) -> Option<FibRoute> {
    let mut builder = RouteBuilder::new();

    if msg.header.scope == RouteScope::Host {
        return None;
    }
    if msg.header.kind != RouteType::Unicast {
        return None;
    }
    if msg.header.protocol == RouteProtocol::Dhcp {
        builder = builder.rtype(RibType::Dhcp);
    }
    if msg.header.scope == RouteScope::Link {
        builder = builder.rtype(RibType::Connected);
    }
    if msg.header.destination_prefix_length == 0 && msg.header.address_family == AddressFamily::Inet
    {
        let prefix = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        builder = builder.ipv4_prefix(prefix);
    }

    for attr in msg.attributes.into_iter() {
        match attr {
            RouteAttribute::Priority(metric) => {
                builder = builder.metric(metric);
            }
            RouteAttribute::Destination(RouteAddress::Inet(n)) => {
                let prefix = Ipv4Net::new(n, msg.header.destination_prefix_length).unwrap();
                builder = builder.ipv4_prefix(prefix);
            }
            RouteAttribute::Destination(RouteAddress::Inet6(n)) => {
                let prefix = Ipv6Net::new(n, msg.header.destination_prefix_length).unwrap();
                builder = builder.ipv6_prefix(prefix);
            }
            RouteAttribute::Oif(ifindex) => {
                builder = builder.oif(ifindex);
            }
            RouteAttribute::Gateway(RouteAddress::Inet(n)) => {
                let uni = NexthopUni {
                    addr: std::net::IpAddr::V4(n),
                    ..Default::default()
                };
                builder = builder.nexthop(Nexthop::Uni(uni));
            }
            RouteAttribute::MultiPath(e) => {
                let mut multi = NexthopMulti::default();
                for nhop in e.iter() {
                    for attr in nhop.attributes.iter() {
                        if let RouteAttribute::Gateway(RouteAddress::Inet(n)) = attr {
                            let uni = NexthopUni {
                                addr: std::net::IpAddr::V4(*n),
                                ..Default::default()
                            };
                            multi.nexthops.push(uni);
                        }
                    }
                }
                builder = builder.nexthop(Nexthop::Multi(multi));
            }
            RouteAttribute::EncapType(_e) => {
                // tracing::info!("XXX EncapType {}", e);
            }
            RouteAttribute::Encap(_e) => {
                // tracing::info!("XXX Encap {:?}", e);
            }

            _ => {
                //
            }
        }
    }
    if !builder.is_ipv4() {
        return None;
    }

    let (prefix, entry) = builder.build();

    let msg = FibRoute { prefix, entry };

    Some(msg)
}

fn process_msg(msg: NetlinkMessage<RouteNetlinkMessage>, tx: UnboundedSender<FibMessage>) {
    if let NetlinkPayload::InnerMessage(msg) = msg.payload {
        match msg {
            RouteNetlinkMessage::NewLink(msg) => {
                let link = link_from_msg(msg);
                let msg = FibMessage::NewLink(link);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::DelLink(msg) => {
                let link = link_from_msg(msg);
                let msg = FibMessage::DelLink(link);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::NewAddress(msg) => {
                let addr = addr_from_msg(msg);
                let msg = FibMessage::NewAddr(addr);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::DelAddress(msg) => {
                let addr = addr_from_msg(msg);
                let msg = FibMessage::DelAddr(addr);
                tx.send(msg).unwrap();
            }
            RouteNetlinkMessage::NewRoute(msg) => {
                let route = route_from_msg(msg);
                if let Some(route) = route {
                    let msg = FibMessage::NewRoute(route);
                    tx.send(msg).unwrap();
                }
            }
            RouteNetlinkMessage::DelRoute(msg) => {
                let route = route_from_msg(msg);
                if let Some(route) = route {
                    let msg = FibMessage::DelRoute(route);
                    tx.send(msg).unwrap();
                }
            }
            // TODO: Phase 4B - Add MDB message handling when netlink-packet-route supports it
            // RouteNetlinkMessage::NewMdb(_) => {
            //     // Parse MDB message and send MdbAdd message
            // }
            // RouteNetlinkMessage::DelMdb(_) => {
            //     // Parse MDB message and send MdbDel message
            // }
            _ => {}
        }
    }
}
