use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use futures::stream::StreamExt;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::address::{
    AddressAttribute, AddressHeaderFlags, AddressMessage, AddressScope,
};
use netlink_packet_route::link::{
    AfSpecInet6, AfSpecUnspec, InfoBridgePort, InfoData, InfoKind, InfoPortData, InfoPortKind,
    InfoVrf, InfoVxlan, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage,
};
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage};
use netlink_packet_route::nexthop::{NexthopAttribute, NexthopFlags, NexthopGroup, NexthopMessage};
use netlink_packet_route::route::{
    MplsLabel, RouteAddress, RouteAttribute, RouteHeader, RouteLwEnCapType, RouteLwTunnelEncap,
    RouteMessage, RouteMplsIpTunnel, RouteNextHop, RouteProtocol, RouteScope, RouteType, RouteVia,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    LinkDummy, LinkVrf,
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_LINK,
        RTMGRP_NEIGH,
    },
    new_connection,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::fib::sysctl::sysctl_enable;
use crate::fib::{FibAddr, FibLink, FibMessage, FibNeighbor, FibRoute};
use crate::rib::entry::RibEntry;
use crate::rib::inst::{IlmEntry, IlmType};
use crate::rib::tracing::{fib_l2_fdb, fib_l2_mdb, fib_l2_vxlan, fib_nexthop, fib_route, fib_srv6};
use crate::rib::{
    AddrGenMode, Bridge, Group, GroupTrait, MacAddr, Nexthop, NexthopMulti, NexthopUni, RibType,
    Vxlan, link, nexthop::NexthopMember,
};

/// Pull the nexthop-object id (`NHA_ID`) out of an inbound
/// RTM_NEWNEXTHOP / RTM_DELNEXTHOP. The id is the same value RIB hands
/// to the kernel as the route's `Nhid`, so it indexes `NexthopMap`
/// directly. Returns `None` for a malformed message with no id.
fn nexthop_id_from_msg(msg: &NexthopMessage) -> Option<u32> {
    msg.attributes.iter().find_map(|attr| {
        if let NexthopAttribute::Id(id) = attr {
            Some(*id)
        } else {
            None
        }
    })
}

/// Compact one-line dump of a `Nexthop` for diagnostic logging.
/// Surfaces the fields that matter when the kernel rejects an
/// install — `gid` (so we can spot `Nhid(0)` mistakes), per-leg
/// address + resolved ifindex, MPLS label stack, and per-leg
/// weight on Multi.
fn fmt_nexthop_for_trace(nh: &Nexthop) -> String {
    fn fmt_uni(u: &NexthopUni) -> String {
        format!(
            "{{addr={} ifindex={:?} gid={} metric={} mpls={:?} weight={}}}",
            u.addr,
            u.ifindex(),
            u.gid,
            u.metric,
            u.mpls,
            u.weight,
        )
    }
    fn fmt_multi(m: &NexthopMulti) -> String {
        let legs: Vec<String> = m.nexthops.iter().map(fmt_uni).collect();
        format!(
            "Multi{{gid={} metric={} legs=[{}]}}",
            m.gid,
            m.metric,
            legs.join(", ")
        )
    }
    match nh {
        Nexthop::Uni(u) => format!("Uni{}", fmt_uni(u)),
        Nexthop::Multi(m) => fmt_multi(m),
        Nexthop::List(l) => {
            let members: Vec<String> = l
                .nexthops
                .iter()
                .enumerate()
                .map(|(i, m)| match m {
                    NexthopMember::Uni(u) => format!("#{i}=Uni{}", fmt_uni(u)),
                    NexthopMember::Multi(mm) => format!("#{i}={}", fmt_multi(mm)),
                })
                .collect();
            format!("List[{}]", members.join(", "))
        }
        Nexthop::Protect(p) => {
            let fmt_member = |m: &NexthopMember| match m {
                NexthopMember::Uni(u) => format!("Uni{}", fmt_uni(u)),
                NexthopMember::Multi(mm) => fmt_multi(mm),
            };
            format!(
                "Protect[primary={} backup={}]",
                fmt_member(&p.primary),
                fmt_member(&p.backup)
            )
        }
        Nexthop::Link(ifindex) => format!("Link(ifindex={ifindex})"),
    }
}

/// Compact one-line dump of a kernel-side `Group` (the
/// nexthop-table object referenced by `Nhid`). Surfaces the gid,
/// for a Uni leg the (addr, ifindex), for a Multi the member-id
/// list — enough to correlate an `RTM_NEWNEXTHOP` ENODEV with the
/// stale link that produced it.
fn fmt_group_for_trace(group: &Group) -> String {
    match group {
        Group::Uni(u) => format!(
            "Group::Uni{{gid={} addr={} ifindex={:?} valid={} installed={}}}",
            u.gid(),
            u.addr,
            u.ifindex(),
            u.is_valid(),
            u.is_installed(),
        ),
        Group::Multi(m) => {
            let members: Vec<String> = m
                .valid
                .iter()
                .map(|(id, w)| format!("({id}, w={w})"))
                .collect();
            format!(
                "Group::Multi{{gid={} members=[{}]}}",
                m.gid(),
                members.join(", ")
            )
        }
        Group::Protect(p) => format!(
            "Group::Protect{{gid={} primary={} backup={} active={:?} valid={} installed={}}}",
            p.gid(),
            p.primary_gid,
            p.backup_gid,
            p.active,
            p.is_valid(),
            p.is_installed(),
        ),
    }
}

/// The primary member of a `NexthopProtect` as the `Nexthop` the
/// per-route install/delete paths consume. When the resolver
/// allocated a protection indirection group, the route must reference
/// *its* gid instead of the member's own — that id is the handle the
/// switchover swaps. Only the gid changes; address, metric, and encap
/// stay the member's (and on `use_nhid == false` kernels the gid is
/// never read, so this is inert there).
fn protect_primary_nexthop(pro: &crate::rib::nexthop::NexthopProtect) -> Nexthop {
    let mut nh = pro.primary.as_nexthop();
    if pro.gid != 0
        && let Nexthop::Uni(u) = &mut nh
    {
        u.gid = pro.gid;
    }
    nh
}

/// Modern rtnetlink multicast group for nexthop objects
/// (`RTNLGRP_NEXTHOP`, linux/rtnetlink.h). Numbered past the legacy
/// `RTMGRP_*` bind mask, so it's joined via `add_membership`.
const RTNLGRP_NEXTHOP: u32 = 32;

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
/// Stamp a `RouteMessage` with the destination routing-table id.
///
/// Kernel `rtm_table` is a single byte. Table ids `0..=255` fit
/// there; `RT_TABLE_MAIN` (254) is the historical default. Ids
/// greater than 255 — Linux VRF allocators happily hand out
/// 1000+-range ids — must travel in the `RTA_TABLE` netlink
/// attribute instead, with `rtm_table` set to `RT_TABLE_UNSPEC`
/// (0) so the kernel knows to consult the attribute.
fn set_route_table(msg: &mut RouteMessage, table_id: u32) {
    if table_id <= u8::MAX as u32 {
        msg.header.table = table_id as u8;
    } else {
        msg.header.table = RouteHeader::RT_TABLE_UNSPEC;
        msg.attributes.push(RouteAttribute::Table(table_id));
    }
}

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
        // LIB twin of a uA: a block:function prefix entry that matches
        // the uA when it is the carrier's *active* uSID (post-uN-shift
        // DA). /(LB+Fun) with the NEXT-CSID flavor — verified live on
        // 6.8 (shift while uSIDs remain, classic End.X at end-of-
        // carrier).
        SidBehavior::UALib => {
            let plen = structure
                .map(|s| s.lb_bits.saturating_add(s.fun_bits))
                .unwrap_or(128);
            (
                RouteHeader::RT_TABLE_MAIN,
                RouteType::Unicast,
                plen,
                mask_v6(addr, plen),
            )
        }
        // End.DT4 / End.DT6 / End.DT46 / End.M are terminal decap+lookup
        // actions. Same FIB shape as End.X — a /128 host route in
        // table=main with kind=Unicast, pointed at sr0 by the static
        // route's ifindex_origin. (The inner decap lookup table — a VRF
        // for End.DT*, the mirror context for End.M — rides inside the
        // seg6local encap, not here.)
        SidBehavior::EndDT4 | SidBehavior::EndDT6 | SidBehavior::EndDT46 | SidBehavior::EndM => {
            (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr)
        }
        // End.B6.Encaps (SR Policy Binding SID): a /128 host route in
        // table=main; the SRH it pushes rides inside the seg6local
        // encap, not in the route header.
        SidBehavior::EndB6Encap => (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr),
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

/// Op selector for `fdb_neigh_send`. The kernel netlink flag set
/// differs per scenario:
///
/// - `Upsert` — `NLM_F_CREATE | NLM_F_REPLACE`. Right for unicast
///   MAC entries where (ifindex, MAC) is unique; replacing the prior
///   entry on a re-advertise (e.g. MAC mobility) is correct.
///
/// - `Append` — `NLM_F_CREATE | NLM_F_APPEND`. Right for VXLAN
///   ingress-replication entries (zero-MAC with per-peer `dst`).
///   Multiple peers each contribute a `dst` on the same MAC; APPEND
///   adds without erasing the existing remote list, REPLACE would
///   clobber it.
///
/// - `Delete` — plain `NLM_F_REQUEST | NLM_F_ACK` with RTM_DELNEIGH.
#[derive(Clone, Copy)]
enum FdbOp {
    Upsert,
    Append,
    Delete,
}

impl FibHandle {
    pub fn new(rib_tx: UnboundedSender<FibMessage>, no_nhid: bool) -> anyhow::Result<Self> {
        let _ = sysctl_enable();

        let (mut connection, handle, mut messages) = new_connection()?;

        let mgroup_flags = RTMGRP_LINK
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_ROUTE
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV6_IFADDR
            // Covers RTM_NEWNEIGH / RTM_DELNEIGH for AF_INET (ARP),
            // AF_INET6 (NDP), and AF_BRIDGE (FDB) — all three flow
            // through the same group.
            | RTMGRP_NEIGH;

        let addr = SocketAddr::new(0, mgroup_flags);
        connection.socket_mut().socket_mut().bind(&addr)?;

        // RTM_NEWNEXTHOP / RTM_DELNEXTHOP aren't covered by the legacy
        // RTMGRP_* bind mask (it only spans the first ~20 groups). Join
        // the modern multicast group so the kernel delivers nexthop
        // add/del notifications — `process_fib_msg` uses RTM_DELNEXTHOP
        // to reconcile NexthopMap when the kernel drops a nexthop. Needs
        // netlink-packet-route's group-nexthop decode fix (see the
        // `decodes_rtm_newnexthop_group` test). Non-fatal on join error.
        match connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTNLGRP_NEXTHOP)
        {
            Ok(()) => tracing::debug!("fib: joined RTNLGRP_NEXTHOP for nexthop reconciliation"),
            Err(e) => tracing::warn!(
                "fib: could not join RTNLGRP_NEXTHOP ({e}); nexthop reconciliation disabled"
            ),
        }

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

    pub async fn route_ipv4_add_uni(
        &self,
        prefix: &Ipv4Net,
        entry: &RibEntry,
        nexthop: &Nexthop,
        table_id: u32,
    ) -> bool {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();

        set_route_table(&mut msg, table_id);
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
                    // Cross-family gateway (RFC 5549 / RFC 8950: v4
                    // prefix via a v6 next-hop) must ride RTA_VIA —
                    // the kernel rejects an RTA_GATEWAY whose length
                    // doesn't match the route's address family.
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Via(RouteVia::Inet6(ipv6)));
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
                        // Cross-family gateway — RTA_VIA, as above.
                        IpAddr::V6(ipv6) => RouteAttribute::Via(RouteVia::Inet6(ipv6)),
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

        // Pre-send dump — `tracing::debug!` so production stays
        // quiet; enable via `RUST_LOG=zebra_rs::fib=debug` when
        // chasing an install failure.
        tracing::debug!(
            "RTM_NEWROUTE v4 {prefix} use_nhid={} nh={}",
            self.use_nhid,
            fmt_nexthop_for_trace(nexthop),
        );

        let mut ok = true;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                // EEXIST means the route is already in the FIB — treat it
                // as installed. Otherwise the self-heal would keep
                // re-adding it every resolve cycle, forever.
                if e.to_io().raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                ok = false;
                if fib_route() {
                    tracing::info!(
                        "NewRoute error: {prefix} {e} table={table_id} rtype={:?} metric={} use_nhid={} nh={}",
                        entry.rtype,
                        entry.metric,
                        self.use_nhid,
                        fmt_nexthop_for_trace(nexthop),
                    );
                }
            }
        }
        ok
    }

    /// Returns whether the route ended up in the kernel FIB. `true` also
    /// covers EEXIST (already present). `false` means a real netlink
    /// error — commonly EINVAL "nexthop id does not exist" when use_nhid
    /// points at a nexthop the kernel silently dropped on link down. The
    /// caller leaves the route's `fib` flag
    /// clear and forces the nexthop's recreation so the next resolve
    /// pass re-adds it.
    pub async fn route_ipv4_add(&self, prefix: &Ipv4Net, entry: &RibEntry, table_id: u32) -> bool {
        if !entry.is_protocol() {
            return true;
        }
        match &entry.nexthop {
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv4_add_uni(prefix, entry, &entry.nexthop, table_id)
                    .await
            }
            Nexthop::List(pro) => {
                let mut ok = true;
                for member in pro.nexthops.iter() {
                    ok &= self
                        .route_ipv4_add_uni(prefix, entry, &member.as_nexthop(), table_id)
                        .await;
                }
                ok
            }
            Nexthop::Protect(pro) => {
                // Primary and backup install as two kernel routes at
                // their own metrics. The primary references the
                // protection indirection group (when allocated) so a
                // future membership swap rewires every protected
                // prefix at once; the backup keeps its member gid.
                let mut ok = true;
                ok &= self
                    .route_ipv4_add_uni(prefix, entry, &protect_primary_nexthop(pro), table_id)
                    .await;
                ok &= self
                    .route_ipv4_add_uni(prefix, entry, &pro.backup.as_nexthop(), table_id)
                    .await;
                ok
            }
            _ => true,
        }
    }

    pub async fn route_ipv4_del_uni(
        &self,
        prefix: &Ipv4Net,
        entry: &RibEntry,
        nexthop: &Nexthop,
        table_id: u32,
    ) {
        if !entry.is_protocol() {
            return;
        }
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();

        set_route_table(&mut msg, table_id);
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
                    // Cross-family gateway (RFC 5549 / RFC 8950) —
                    // RTA_VIA, mirroring the add path so the delete
                    // matches what was installed.
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Via(RouteVia::Inet6(ipv6)));
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
                        // Cross-family gateway — RTA_VIA, as above.
                        IpAddr::V6(ipv6) => RouteAttribute::Via(RouteVia::Inet6(ipv6)),
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
                && fib_route()
            {
                tracing::info!(
                    "DelRoute error: {prefix} {e} table={table_id} rtype={:?} metric={} use_nhid={} nh={}",
                    entry.rtype,
                    entry.metric,
                    self.use_nhid,
                    fmt_nexthop_for_trace(nexthop),
                );
            }
        }
    }

    pub async fn route_ipv4_del(&self, prefix: &Ipv4Net, entry: &RibEntry, table_id: u32) {
        if !entry.is_protocol() {
            return;
        }

        match &entry.nexthop {
            Nexthop::Link(_) => {}
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv4_del_uni(prefix, entry, &entry.nexthop, table_id)
                    .await;
            }
            Nexthop::List(list) => {
                for member in &list.nexthops {
                    self.route_ipv4_del_uni(prefix, entry, &member.as_nexthop(), table_id)
                        .await;
                }
            }
            Nexthop::Protect(pro) => {
                // Mirror the add path: the primary route was keyed to
                // the indirection gid, so the delete must name it too.
                self.route_ipv4_del_uni(prefix, entry, &protect_primary_nexthop(pro), table_id)
                    .await;
                self.route_ipv4_del_uni(prefix, entry, &pro.backup.as_nexthop(), table_id)
                    .await;
            }
        }
    }

    pub async fn route_ipv6_add_uni(
        &self,
        prefix: &Ipv6Net,
        entry: &RibEntry,
        nexthop: &Nexthop,
        table_id: u32,
    ) -> bool {
        if fib_route() {
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

        set_route_table(&mut msg, table_id);
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
                // Static seg6local action routes keep the legacy
                // RT_TABLE_MAIN decap (table_id 0); per-VRF table
                // selection arrives via the protocol SID path.
                super::srv6::build_seg6local_attrs(action, None, None, 0, &[])
            {
                msg.attributes.push(encap);
                msg.attributes.push(encap_type);
            }
            msg.attributes.push(RouteAttribute::Priority(uni.metric));

            let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
            req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            let mut ok = true;
            let mut response = self.handle.clone().request(req).unwrap();
            while let Some(m) = response.next().await {
                if let NetlinkPayload::Error(e) = m.payload {
                    ok = false;
                    tracing::warn!(
                        "NewRoute seg6local install error: prefix={prefix} action={action:?} err={e}"
                    );
                }
            }
            return ok;
        }

        if self.use_nhid {
            // Pre-send sanity check — mirror of route_ipv4_add_uni.
            let gid_for_check = match &nexthop {
                Nexthop::Uni(u) => Some(u.gid),
                Nexthop::Multi(m) => Some(m.gid),
                _ => None,
            };
            if let Some(0) = gid_for_check {
                tracing::warn!(
                    "RTM_NEWROUTE v6 skipped for {prefix}: nexthop gid is 0 (would Nhid(0) -> ENODEV); nh={}",
                    fmt_nexthop_for_trace(nexthop),
                );
                return false;
            }
            if let Nexthop::Uni(uni) = &nexthop {
                if fib_route() {
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
                if fib_route() {
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
                if fib_route() {
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
                            return false;
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

        if fib_route() {
            tracing::info!(
                "[IPv6 route_add_uni] netlink request: af={:?} dest_prefix_len={} attrs={:?}",
                msg.header.address_family,
                msg.header.destination_prefix_length,
                msg.attributes
            );
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        // Pre-send dump — `tracing::debug!` so production stays
        // quiet; enable via `RUST_LOG=zebra_rs::fib=debug` when
        // chasing an install failure.
        tracing::debug!(
            "RTM_NEWROUTE v6 {prefix} use_nhid={} nh={}",
            self.use_nhid,
            fmt_nexthop_for_trace(nexthop),
        );

        let mut ok = true;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                // EEXIST means the route is already in the FIB — treat it
                // as installed so the self-heal doesn't re-add it forever.
                if e.to_io().raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                ok = false;
                if fib_route() {
                    tracing::info!(
                        "NewRoute IPv6 error: {prefix} {e} use_nhid={} nh={}",
                        self.use_nhid,
                        fmt_nexthop_for_trace(nexthop),
                    );
                }
            }
        }
        ok
    }

    /// IPv6 sibling of [`Self::route_ipv4_add`]; returns whether the
    /// kernel accepted the install.
    pub async fn route_ipv6_add(&self, prefix: &Ipv6Net, entry: &RibEntry, table_id: u32) -> bool {
        if !entry.is_protocol() {
            return true;
        }
        match &entry.nexthop {
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv6_add_uni(prefix, entry, &entry.nexthop, table_id)
                    .await
            }
            Nexthop::List(pro) => {
                let mut ok = true;
                for member in pro.nexthops.iter() {
                    ok &= self
                        .route_ipv6_add_uni(prefix, entry, &member.as_nexthop(), table_id)
                        .await;
                }
                ok
            }
            Nexthop::Protect(pro) => {
                // Primary and backup install as two kernel routes at
                // their own metrics. The primary references the
                // protection indirection group (when allocated) so a
                // future membership swap rewires every protected
                // prefix at once; the backup keeps its member gid.
                let mut ok = true;
                ok &= self
                    .route_ipv6_add_uni(prefix, entry, &protect_primary_nexthop(pro), table_id)
                    .await;
                ok &= self
                    .route_ipv6_add_uni(prefix, entry, &pro.backup.as_nexthop(), table_id)
                    .await;
                ok
            }
            _ => true,
        }
    }

    pub async fn route_ipv6_del_uni(
        &self,
        prefix: &Ipv6Net,
        entry: &RibEntry,
        nexthop: &Nexthop,
        table_id: u32,
    ) {
        if !entry.is_protocol() {
            return;
        }

        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.destination_prefix_length = prefix.prefix_len();

        set_route_table(&mut msg, table_id);
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
                && fib_route()
            {
                tracing::info!(
                    "DelRoute IPv6 error: {prefix} {e} table={table_id} rtype={:?} metric={} use_nhid={} nh={}",
                    entry.rtype,
                    entry.metric,
                    self.use_nhid,
                    fmt_nexthop_for_trace(nexthop),
                );
            }
        }
    }

    pub async fn route_ipv6_del(&self, prefix: &Ipv6Net, entry: &RibEntry, table_id: u32) {
        if !entry.is_protocol() {
            return;
        }

        match &entry.nexthop {
            Nexthop::Link(_) => {}
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv6_del_uni(prefix, entry, &entry.nexthop, table_id)
                    .await;
            }
            Nexthop::List(list) => {
                for member in &list.nexthops {
                    self.route_ipv6_del_uni(prefix, entry, &member.as_nexthop(), table_id)
                        .await;
                }
            }
            Nexthop::Protect(pro) => {
                // Mirror the add path: the primary route was keyed to
                // the indirection gid, so the delete must name it too.
                self.route_ipv6_del_uni(prefix, entry, &protect_primary_nexthop(pro), table_id)
                    .await;
                self.route_ipv6_del_uni(prefix, entry, &pro.backup.as_nexthop(), table_id)
                    .await;
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

                if fib_nexthop() {
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
                    if fib_srv6() {
                        tracing::info!(
                            "[nexthop_add seg6local] gid={} skipped — seg6local \
                             install rides on the route, not the nh_id",
                            uni.gid(),
                        );
                    }
                    return;
                }

                // On-link nexthops with an unspecified gateway
                // (0.0.0.0 / ::) have no representation in the kernel
                // nexthop table — NHA_GATEWAY can't carry the
                // wildcard address and an interface-only nh_id needs
                // a gateway anyway under our address_family setup.
                // RIB only allocates these as the resolved nexthop
                // for OSPF stub-network LSAs and other intra-segment
                // routes that lose to the Connected route, so they
                // never need a kernel nh_id. NexthopMap still tracks
                // them for logical bookkeeping inside zebra-rs.
                if uni.addr.is_unspecified() {
                    tracing::debug!(
                        "[nexthop_add Uni] gid={gid} skipped — addr={} is unspecified, no kernel nh_id needed",
                        uni.addr,
                    );
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

                if fib_nexthop() {
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
            Group::Protect(pro) => {
                // Protection indirection: a 1-member mpath group
                // holding the ACTIVE member (primary in steady state,
                // repair after a switchover). Same encoding as Multi —
                // GroupType 0, kernel weight is value+1 so 0 = 1. The
                // request carries NLM_F_REPLACE, so re-sending after
                // an `active` flip IS the atomic switchover: every
                // route referencing this gid moves in one message.
                gid = pro.gid();
                refcnt = pro.refcnt();

                msg.header.address_family = AddressFamily::Unspec;

                let attr = NexthopAttribute::Id(pro.gid() as u32);
                msg.attributes.push(attr);

                let attr = NexthopAttribute::GroupType(0);
                msg.attributes.push(attr);

                let grp = NexthopGroup {
                    id: pro.active_gid() as u32,
                    weight: 0,
                    ..Default::default()
                };
                let attr = NexthopAttribute::Group(vec![grp]);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let group_summary = fmt_group_for_trace(nexthop);
        tracing::debug!("RTM_NEWNEXTHOP {}", group_summary);

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            match msg.payload {
                NetlinkPayload::Error(e) => {
                    if fib_nexthop() {
                        tracing::info!(
                            "NewNexthop error: {e} gid: {gid} refcnt: {refcnt} {}",
                            group_summary,
                        );
                    }
                }
                // Non-error payloads here are mostly the RTNLGRP_NEXTHOP
                // multicast echoes the kernel delivers on the shared
                // socket while our request is in flight — not real
                // responses. Keep them at debug so steady-state churn
                // doesn't flood the log.
                NetlinkPayload::Done(m) => {
                    tracing::debug!("NewNexthop done {m:?}");
                }
                NetlinkPayload::InnerMessage(e) => {
                    tracing::debug!("NewNexthop inner message {:?}", e);
                }
                NetlinkPayload::Noop => {
                    tracing::debug!("NewNexthop noop");
                }
                NetlinkPayload::Overrun(e) => {
                    tracing::debug!("NewNexthop Overrun {:?}", e);
                }
                _ => {
                    tracing::debug!("NewNexthop other return");
                }
            }
        }
    }

    pub async fn nexthop_del(&self, nexthop: &Group) {
        // Skip nexthop table management for kernels < 5.3
        if !self.use_nhid {
            return;
        }

        // Mirror the unspecified-addr skip in nexthop_add: we never
        // installed a kernel nh_id for these, so don't ask the
        // kernel to delete one (it would just log ENOENT).
        if let Group::Uni(uni) = nexthop
            && uni.addr.is_unspecified()
        {
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
            if let NetlinkPayload::Error(e) = msg.payload
                && fib_nexthop()
            {
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
        let Some((encap, encap_type)) = super::srv6::build_seg6local_attrs(
            sid.behavior,
            sid.nh6,
            sid.structure,
            sid.table_id,
            &sid.segs,
        ) else {
            tracing::warn!(
                "seg6local route encap build skipped for {} (End.X / uA without IPv6 nexthop)",
                sid.addr
            );
            return;
        };
        msg.attributes.push(encap);
        msg.attributes.push(encap_type);

        if fib_srv6() {
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
                // requiring `system tracing fib srv6` — silent failures
                // here are how a misshaped seg6local install slips through.
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
        // First create the bridge interface. Bring it up at creation
        // (`ip link add ... up`) so the device is operational without a
        // separate operator step.
        let mut msg = LinkMessage::default();
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;

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

        // Set the IPv6 address generation mode as a second operation.
        // Defaults to `none` (no kernel-generated link-local on the
        // bridge) when the operator hasn't configured one.
        let addr_gen_mode = bridge.addr_gen_mode.clone().unwrap_or(AddrGenMode::None);
        self.bridge_set_addr_gen_mode(&bridge.name, &addr_gen_mode)
            .await;
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

        // First create the vxlan interface. Bring it up at creation
        // (`ip link add ... up`) so the device is operational without a
        // separate operator step.
        let mut msg = LinkMessage::default();
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;

        let name = LinkAttribute::IfName(vxlan.name.clone());
        msg.attributes.push(name);

        // Link kind is VxLAN.
        let kind = InfoKind::Vxlan;
        let link_kind = LinkInfo::Kind(kind);

        // VNI encode.
        let vni = InfoVxlan::Id(vni);
        let mut vxlan_info = vec![vni];

        // Destination port. Defaults to the IANA-assigned VXLAN port
        // (4789) when the operator hasn't configured one — Linux would
        // otherwise fall back to the legacy 8472.
        let dport = vxlan.dport.unwrap_or(4789);
        vxlan_info.push(InfoVxlan::Port(dport));

        // Local address.
        if let Some(local_addr) = vxlan.local_addr {
            let info = match local_addr {
                IpAddr::V4(addr) => InfoVxlan::Local(addr.octets().to_vec()),
                IpAddr::V6(addr) => InfoVxlan::Local6(addr.octets().to_vec()),
            };
            vxlan_info.push(info);
        }

        // Disable data-plane MAC learning by default (`nolearning`).
        // EVPN populates the FDB from the BGP control plane, so kernel
        // flood-and-learn must be off.
        vxlan_info.push(InfoVxlan::Learning(false));

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

        // Set the IPv6 address generation mode as a second operation.
        // Defaults to `none` (no kernel-generated link-local on the
        // VXLAN device) when the operator hasn't configured one.
        let addr_gen_mode = vxlan.addr_gen_mode.clone().unwrap_or(AddrGenMode::None);
        self.vxlan_set_addr_gen_mode(&vxlan.name, &addr_gen_mode)
            .await;
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

    /// Apply the VXLAN bridge-slave defaults to the port at `ifindex`:
    /// neighbour suppression on (ARP/ND answered locally from the FDB
    /// instead of flooded) and bridge-port MAC learning off (EVPN's BGP
    /// control plane owns the FDB). Equivalent to:
    ///   ip link set <dev> type bridge_slave neigh_suppress on learning off
    /// Called when the RIB observes a VXLAN device gaining a bridge
    /// master; a no-op error is logged if the master is not a bridge.
    pub async fn vxlan_bridge_port_defaults(&self, ifindex: u32) {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;

        let port_data = InfoPortData::BridgePort(vec![
            InfoBridgePort::NeighSupress(true),
            InfoBridgePort::Learning(false),
        ]);
        let link_info = LinkAttribute::LinkInfo(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(port_data),
        ]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink bridge-port defaults error: {e}");
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

    /// Look up an existing kernel link by name and, if it is a VRF
    /// master device, return `(ifindex, table_id)`. Returns `None` if
    /// the link is absent or isn't a VRF. Lets the daemon adopt a VRF
    /// master left over from a previous run (or pre-created by the
    /// operator) instead of failing the create with EEXIST.
    pub async fn vrf_index_table_by_name(&self, name: &str) -> Option<(u32, u32)> {
        use futures::TryStreamExt;
        let mut stream = self
            .handle
            .clone()
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        let msg = match stream.try_next().await {
            Ok(Some(msg)) => msg,
            _ => return None,
        };
        let ifindex = msg.header.index;
        for attr in msg.attributes.iter() {
            let LinkAttribute::LinkInfo(infos) = attr else {
                continue;
            };
            let is_vrf = infos
                .iter()
                .any(|i| matches!(i, LinkInfo::Kind(InfoKind::Vrf)));
            let table = infos.iter().find_map(|i| match i {
                LinkInfo::Data(InfoData::Vrf(data)) => data.iter().find_map(|d| match d {
                    InfoVrf::TableId(t) => Some(*t),
                    _ => None,
                }),
                _ => None,
            });
            if is_vrf && let Some(t) = table {
                return Some((ifindex, t));
            }
        }
        None
    }

    /// Create a Linux VRF master interface bound to `table_id`. Returns
    /// the ifindex the kernel assigned, or None if creation failed
    /// (table-id collision with another VRF master, name collision with
    /// an existing interface, etc.). Mirrors
    /// `ip link add <name> type vrf table <table_id>` followed by
    /// `ip link set <name> up`.
    pub async fn vrf_add(&self, name: &str, table_id: u32) -> Option<u32> {
        let result = self
            .handle
            .clone()
            .link()
            .add(LinkVrf::new(name, table_id).up().build())
            .execute()
            .await;
        if let Err(e) = result {
            tracing::warn!("vrf_add({}, table={}) error: {}", name, table_id, e);
            return None;
        }
        self.link_index_by_name(name).await
    }

    /// Delete a VRF master interface by name. Idempotent — missing names
    /// log at info but don't propagate. Slave interfaces enslaved to this
    /// VRF are detached by the kernel automatically; per-VRF routes in
    /// the associated table are flushed.
    pub async fn vrf_del(&self, name: &str) {
        let Some(ifindex) = self.link_index_by_name(name).await else {
            tracing::info!("vrf_del({}) skipped — not present", name);
            return;
        };
        if let Err(e) = self.handle.clone().link().del(ifindex).execute().await {
            tracing::warn!("vrf_del({}) error: {}", name, e);
        }
    }

    /// Set or clear the IFLA_MASTER (renamed to `Controller` in
    /// netlink-packet-route) of `ifindex`. Pass `master == 0` to detach
    /// (equivalent to `ip link set <link> nomaster`); a non-zero value
    /// enslaves the link to that master device. Used for VRF interface
    /// binding.
    pub async fn link_set_master(&self, ifindex: u32, master: u32) {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;
        msg.attributes.push(LinkAttribute::Controller(master));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                tracing::warn!(
                    "link_set_master(ifindex={}, master={}) error: {}",
                    ifindex,
                    master,
                    e
                );
            }
        }
    }

    /// Set the MTU of `ifindex` via `RTM_NEWLINK` carrying
    /// `IFLA_MTU`. Mirrors `ip link set <link> mtu <n>`. Returns the
    /// kernel error on rejection (e.g. EINVAL when the value is below
    /// the IPv6 minimum of 1280 on a v6-enabled link) so the caller can
    /// surface the reason; the success path relies on the kernel's
    /// echoed `RTM_NEWLINK` to update the cached `Link::mtu`.
    pub async fn link_set_mtu(&self, ifindex: u32, mtu: u32) -> anyhow::Result<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;
        msg.attributes.push(LinkAttribute::Mtu(mtu));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req)?;
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                return Err(anyhow::anyhow!("{}", e));
            }
        }
        Ok(())
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

        // BGP/MPLS-VPN per-VRF decap: emit a pure-pop AF_MPLS
        // route — no NEW_DESTINATION (= no swap), just an
        // `Oif(vrf_ifindex)` so the kernel routes the popped
        // packet via the VRF master, which lands in
        // `vrf_tables[table_id]`. Skips the per-`Nexthop` branch
        // because `IlmEntry::nexthop` is `Nexthop::default()` for
        // this variant.
        if let IlmType::DecapVrf {
            table_id: _,
            vrf_ifindex,
        } = ilm.ilm_type
        {
            msg.attributes.push(RouteAttribute::Oif(vrf_ifindex));
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
                    tracing::info!("ilm_add DecapVrf error: {}", e);
                }
            }
            return;
        }

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

                // The outgoing label stack rides a single RTA_NEWDST:
                // one attribute carrying every label (outermost first),
                // BoS set only on the bottom label. Emitting one
                // NewDestination per label would leave the kernel with
                // just the last (duplicate RTA_NEWDST overwrites), which
                // drops the transport label under a swap-and-push — e.g.
                // an Inter-AS Option B VPNv4 transit `local → [SR, VPN]`.
                if !uni.mpls_label.is_empty() {
                    let last = uni.mpls_label.len() - 1;
                    let stack: Vec<MplsLabel> = uni
                        .mpls_label
                        .iter()
                        .enumerate()
                        .map(|(i, &label)| MplsLabel {
                            label,
                            traffic_class: 0,
                            bottom_of_stack: i == last,
                            ttl: 0,
                        })
                        .collect();
                    msg.attributes.push(RouteAttribute::NewDestination(stack));
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

                    // Full label stack in one RTA_NEWDST (see the Uni arm).
                    if !uni.mpls_label.is_empty() {
                        let last = uni.mpls_label.len() - 1;
                        let stack: Vec<MplsLabel> = uni
                            .mpls_label
                            .iter()
                            .enumerate()
                            .map(|(i, &label)| MplsLabel {
                                label,
                                traffic_class: 0,
                                bottom_of_stack: i == last,
                                ttl: 0,
                            })
                            .collect();
                        nhop.attributes.push(RouteAttribute::NewDestination(stack));
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
        if fib_l2_vxlan() {
            tracing::info!(
                "[FIB] Registered VXLAN VNI {} with ifindex {}",
                vni,
                ifindex
            );
        }
        self.vni_ifindex_map.insert(vni, ifindex);
    }

    /// Unregister VXLAN interface mapping
    pub fn unregister_vxlan_ifindex(&mut self, vni: u32) {
        if fib_l2_vxlan() {
            tracing::info!("[FIB] Unregistered VXLAN VNI {}", vni);
        }
        self.vni_ifindex_map.remove(&vni);
    }

    /// Add EVPN remote MAC to the bridge / VXLAN FDB.
    ///
    /// Linux EVPN-VXLAN forwarding requires **two** FDB entries per
    /// remote MAC, both attached to the VXLAN slave interface but
    /// landing in different kernel tables (selected by the netlink
    /// `NTF_*` flag):
    ///
    ///   1. Bridge master FDB — `NTF_MASTER | NTF_EXT_LEARNED`.
    ///      "MAC X is reachable via this slave port." Without this
    ///      entry, frames arriving at the bridge from a local port
    ///      destined for the remote MAC are flooded to every bridge
    ///      port instead of unicast to the VXLAN slave.
    ///
    ///   2. VXLAN self FDB — `NTF_SELF | NTF_EXT_LEARNED`.
    ///      "When a frame is being forwarded out this VXLAN device,
    ///      encapsulate to remote VTEP `dst`." Carries `NDA_DST`,
    ///      `NDA_VNI`, `NDA_SRC_VNI`, `NDA_PORT`.
    ///
    /// Installing only entry 1 leaves no encap target; installing
    /// only entry 2 causes flooding because the bridge can't learn
    /// from BGP. Both are required and FRR programs both. The third
    /// VLAN-tagged variant FRR sometimes adds is only needed when the
    /// bridge is `vlan_filtering 1`; not implemented here yet.
    pub async fn mac_add(
        &self,
        vni: u32,
        mac: &MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        _seq: u32,
        esi: Option<[u8; 10]>,
    ) {
        let Some(&vxlan_ifindex) = self.vni_ifindex_map.get(&vni) else {
            if fib_l2_fdb() {
                tracing::info!(
                    "mac_add: no local VXLAN for VNI {} — skipping (mac {})",
                    vni,
                    mac
                );
            }
            return;
        };

        if fib_l2_fdb() {
            tracing::info!(
                "mac_add: VNI {} mac {} ifindex {} dst {}",
                vni,
                mac,
                vxlan_ifindex,
                tunnel_endpoint
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "-".into()),
            );
        }

        // Entry 1 — bridge master FDB. No VXLAN-specific attrs.
        // NUD_REACHABLE matches what Linux records for kernel-learned
        // entries and what FRR sets on its master-side install.
        const NTF_MASTER: u8 = 0x04;
        const NTF_SELF: u8 = 0x02;
        const NTF_EXT_LEARNED: u8 = 0x10;
        const NTF_STICKY: u8 = 0x40;
        const NUD_REACHABLE: u16 = 0x02;
        const NUD_PERMANENT: u16 = 0x80;

        self.fdb_neigh_send(
            vxlan_ifindex,
            mac,
            NTF_MASTER | NTF_EXT_LEARNED,
            NUD_REACHABLE,
            None,
            None,
            FdbOp::Upsert,
            "mac_add(master)",
        )
        .await;

        // Entry 2 — VXLAN self FDB. Carries the encap target and VNI.
        let mut self_flags: u8 = NTF_SELF | NTF_EXT_LEARNED;
        if (flags & 0x01) != 0 {
            // BGP signaled MAC mobility "sticky" (RFC 7432 §10.6).
            self_flags |= NTF_STICKY;
        }
        self.fdb_neigh_send(
            vxlan_ifindex,
            mac,
            self_flags,
            NUD_PERMANENT,
            Some(vni),
            tunnel_endpoint,
            FdbOp::Upsert,
            "mac_add(self)",
        )
        .await;

        // ESI received and stored. Kernel multi-homing via NDA_NH_ID
        // will be wired when ECMP nexthop groups are supported.
        if let Some(esi_val) = esi
            && esi_val != [0u8; 10]
            && fib_l2_fdb()
        {
            tracing::info!("mac_add: ESI type {} for MAC {}", esi_val[0], mac);
        }
    }

    /// Build and send a single AF_BRIDGE FDB neighbour message.
    /// `is_add` selects RTM_NEWNEIGH (with `NLM_F_CREATE | NLM_F_REPLACE`
    /// upsert flags) vs RTM_DELNEIGH. `vni` adds NDA_VNI/NDA_SRC_VNI/
    /// NDA_PORT (only meaningful for VXLAN self entries). `dst` adds
    /// NDA_DST (the remote VTEP IP, also self-only).
    #[allow(clippy::too_many_arguments)]
    async fn fdb_neigh_send(
        &self,
        ifindex: u32,
        mac: &MacAddr,
        ntf_flags: u8,
        nud_state: u16,
        vni: Option<u32>,
        dst: Option<IpAddr>,
        op: FdbOp,
        log_label: &str,
    ) {
        use netlink_packet_route::RouteNetlinkMessage;
        use netlink_packet_route::neighbour::{
            NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
        };

        let mut msg = NeighbourMessage::default();
        msg.header.family = AddressFamily::Bridge;
        msg.header.ifindex = ifindex;
        msg.header.state = NeighbourState::Other(nud_state);
        msg.header.flags = NeighbourFlags::from_bits_retain(ntf_flags);

        msg.attributes
            .push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));

        if let Some(vni) = vni {
            msg.attributes.push(NeighbourAttribute::Vni(vni));
            msg.attributes.push(NeighbourAttribute::SourceVni(vni));
            msg.attributes.push(NeighbourAttribute::Port(4789));
        }
        if let Some(endpoint) = dst {
            let addr = match endpoint {
                IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
                IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
            };
            msg.attributes
                .push(NeighbourAttribute::TunnelEndpoint(addr));
        }

        let req = match op {
            FdbOp::Upsert => {
                let mut r = NetlinkMessage::from(RouteNetlinkMessage::NewNeighbour(msg));
                r.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
                r
            }
            FdbOp::Append => {
                // Used for VXLAN BUM ingress-replication entries
                // (zero-MAC + per-peer dst). Multiple peers each
                // contribute their own dst on the same MAC; APPEND
                // adds without clobbering the existing remote list,
                // unlike REPLACE which would erase prior peers' dsts.
                let mut r = NetlinkMessage::from(RouteNetlinkMessage::NewNeighbour(msg));
                r.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;
                r
            }
            FdbOp::Delete => {
                let mut r = NetlinkMessage::from(RouteNetlinkMessage::DelNeighbour(msg));
                r.header.flags = NLM_F_REQUEST | NLM_F_ACK;
                r
            }
        };

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(rsp) = response.next().await {
            if let NetlinkPayload::Error(e) = rsp.payload {
                tracing::info!(
                    "{}: netlink error mac {} ifindex {} flags 0x{:02x}: {}",
                    log_label,
                    mac,
                    ifindex,
                    ntf_flags,
                    e
                );
            }
        }
    }

    /// Delete EVPN MAC entry from bridge FDB
    pub async fn mac_del(&self, vni: u32, mac: &MacAddr) {
        // Mirror `mac_add` — skip when no local VXLAN registered for
        // this VNI. With `mac_add` skipping installs in the same case,
        // there's nothing in the kernel to delete; the old
        // `unwrap_or(vni)` would have issued a stray RTM_DELNEIGH
        // against a random interface.
        let Some(&vxlan_ifindex) = self.vni_ifindex_map.get(&vni) else {
            if fib_l2_fdb() {
                tracing::info!(
                    "mac_del: no local VXLAN for VNI {} — skipping (mac {})",
                    vni,
                    mac
                );
            }
            return;
        };

        if fib_l2_fdb() {
            tracing::info!("mac_del: VNI {} mac {} ifindex {}", vni, mac, vxlan_ifindex);
        }

        // Mirror `mac_add` — remove BOTH the bridge master entry and
        // the VXLAN self entry. NUD state is irrelevant on delete
        // (kernel matches by family/ifindex/MAC + the NTF flag that
        // selects which FDB table to look in); pass 0.
        const NTF_MASTER: u8 = 0x04;
        const NTF_SELF: u8 = 0x02;

        self.fdb_neigh_send(
            vxlan_ifindex,
            mac,
            NTF_MASTER,
            0,
            None,
            None,
            FdbOp::Delete,
            "mac_del(master)",
        )
        .await;
        self.fdb_neigh_send(
            vxlan_ifindex,
            mac,
            NTF_SELF,
            0,
            Some(vni),
            None,
            FdbOp::Delete,
            "mac_del(self)",
        )
        .await;
    }

    /// Install a remote VTEP for VXLAN BUM ingress replication
    /// (EVPN Type-3 Inclusive Multicast).
    ///
    /// **Implementation note**: despite the historical name (`mdb_add`),
    /// this does NOT use kernel MDB. RTM_NEWMDB is for IGMP/MLD
    /// snooping on the bridge — completely separate machinery. The
    /// correct kernel mechanism for VXLAN BUM head-end replication
    /// is an FDB entry on the VXLAN device with a zero MAC and the
    /// remote VTEP IP as `dst`:
    ///
    ///     bridge fdb add 00:00:00:00:00:00 dev <vxlan> dst <peer-VTEP> self
    ///
    /// When the VXLAN device forwards BUM (broadcast / unknown
    /// unicast / multicast) it replicates to every `dst` listed
    /// across its zero-MAC FDB rows. Each peer's Type-3 contributes
    /// one row; we use `NLM_F_APPEND` so multiple peers' `dst`s
    /// coexist instead of clobbering one another.
    ///
    /// The `source` and `seq` parameters from the original MDB
    /// signature are accepted for ABI compatibility but unused here.
    /// Renaming the function and message are a follow-up.
    pub async fn mdb_add(
        &self,
        vni: u32,
        group: IpAddr,
        _source: Option<IpAddr>,
        _ifindex: u32,
        _seq: u32,
    ) {
        let Some(&vxlan_ifindex) = self.vni_ifindex_map.get(&vni) else {
            if fib_l2_mdb() {
                tracing::info!(
                    "mdb_add: no local VXLAN for VNI {} — skipping (group {})",
                    vni,
                    group
                );
            }
            return;
        };

        if fib_l2_mdb() {
            tracing::info!(
                "mdb_add: VNI {} dst {} ifindex {} (zero-MAC FDB / ingress replication)",
                vni,
                group,
                vxlan_ifindex,
            );
        }

        const NTF_SELF: u8 = 0x02;
        const NTF_EXT_LEARNED: u8 = 0x10;
        const NUD_PERMANENT: u16 = 0x80;

        // Zero-MAC entry on the VXLAN device. Note we pass `vni: None`
        // — for ingress-replication entries the kernel uses the
        // VXLAN device's own VNI (set at link creation), and adding
        // NDA_VNI/NDA_SRC_VNI here is incorrect.
        self.fdb_neigh_send(
            vxlan_ifindex,
            &MacAddr::from([0u8; 6]),
            NTF_SELF | NTF_EXT_LEARNED,
            NUD_PERMANENT,
            None,
            Some(group),
            FdbOp::Append,
            "mdb_add(zero-mac)",
        )
        .await;
    }

    /// Remove a remote VTEP from VXLAN BUM ingress replication.
    /// Counterpart of `mdb_add`; same rationale on naming.
    pub async fn mdb_del(&self, vni: u32, group: IpAddr, _source: Option<IpAddr>, _ifindex: u32) {
        let Some(&vxlan_ifindex) = self.vni_ifindex_map.get(&vni) else {
            if fib_l2_mdb() {
                tracing::info!(
                    "mdb_del: no local VXLAN for VNI {} — skipping (group {})",
                    vni,
                    group
                );
            }
            return;
        };

        if fib_l2_mdb() {
            tracing::info!(
                "mdb_del: VNI {} dst {} ifindex {} (zero-MAC FDB / ingress replication)",
                vni,
                group,
                vxlan_ifindex,
            );
        }

        const NTF_SELF: u8 = 0x02;

        self.fdb_neigh_send(
            vxlan_ifindex,
            &MacAddr::from([0u8; 6]),
            NTF_SELF,
            0,
            None,
            Some(group),
            FdbOp::Delete,
            "mdb_del(zero-mac)",
        )
        .await;
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
            }
            LinkAttribute::Controller(idx) => {
                // `IFLA_MASTER` (kernel constant; rtnetlink renamed
                // the variant to `Controller`). Slave-of-bridge /
                // slave-of-VRF membership.
                link.master = Some(idx);
            }
            LinkAttribute::LinkInfo(infos) => {
                // VXLAN link data carries both the VNI (`IFLA_VXLAN_ID`)
                // and the local VTEP source IP (`IFLA_VXLAN_LOCAL` or
                // `IFLA_VXLAN_LOCAL6`). Walk every Vxlan sub-attr and
                // capture them. Non-VXLAN links contribute nothing.
                for info in infos {
                    if let LinkInfo::Data(InfoData::Vxlan(vxlan_attrs)) = info {
                        for v in vxlan_attrs {
                            match v {
                                InfoVxlan::Id(vni) => link.vni = Some(vni),
                                InfoVxlan::Local(bytes) if bytes.len() == 4 => {
                                    link.vxlan_local = Some(IpAddr::V4(std::net::Ipv4Addr::new(
                                        bytes[0], bytes[1], bytes[2], bytes[3],
                                    )));
                                }
                                InfoVxlan::Local6(bytes) if bytes.len() == 16 => {
                                    let mut octets = [0u8; 16];
                                    octets.copy_from_slice(&bytes);
                                    link.vxlan_local =
                                        Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                                }
                                _ => {}
                            }
                        }
                    }
                }
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

    // `rtm_table` is a single byte; ids > 255 arrive as
    // `RT_TABLE_UNSPEC` in the header with the real id in `RTA_TABLE`.
    let mut table_id = msg.header.table as u32;

    for attr in msg.attributes.into_iter() {
        match attr {
            RouteAttribute::Table(t) => {
                table_id = t;
            }
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

    let msg = FibRoute {
        prefix,
        entry,
        table_id,
    };

    Some(msg)
}

/// Translate a kernel `RTM_NEWNEIGH` / `RTM_DELNEIGH` payload into the
/// internal [`FibNeighbor`] form. Supports the three address families
/// the consumer cares about today:
///
/// - `AF_INET` — ARP entries (NDA_DST = IPv4 protocol address,
///   NDA_LLADDR = MAC).
/// - `AF_INET6` — NDP entries (NDA_DST = IPv6 protocol address,
///   NDA_LLADDR = MAC).
/// - `AF_BRIDGE` — FDB entries (NDA_LLADDR = MAC, NDA_DST optional =
///   remote VTEP IP for VXLAN, NDA_VNI optional, NDA_VLAN optional).
///
/// Other families fall through with the header populated and the
/// attribute fields left at their defaults — easier to debug than
/// silently dropping them.
pub fn neighbor_from_msg(msg: NeighbourMessage) -> FibNeighbor {
    let mut nbr = FibNeighbor {
        family: msg.header.family,
        ifindex: msg.header.ifindex,
        state: msg.header.state,
        flags: msg.header.flags,
        ..Default::default()
    };

    for attr in msg.attributes.into_iter() {
        match attr {
            NeighbourAttribute::Destination(addr) => match addr {
                NeighbourAddress::Inet(v4) => nbr.dst = Some(IpAddr::V4(v4)),
                NeighbourAddress::Inet6(v6) => nbr.dst = Some(IpAddr::V6(v6)),
                NeighbourAddress::Other(_) => {}
                // Non-exhaustive enum; future-proof against new variants.
                _ => {}
            },
            NeighbourAttribute::LinkLocalAddress(bytes) => {
                nbr.lladdr = MacAddr::from_vec(bytes);
            }
            NeighbourAttribute::Vlan(vlan) => nbr.vlan = Some(vlan),
            NeighbourAttribute::Vni(vni) => nbr.vni = Some(vni),
            NeighbourAttribute::Controller(idx) => nbr.master = Some(idx),
            _ => {}
        }
    }

    nbr
}

fn process_msg(msg: NetlinkMessage<RouteNetlinkMessage>, tx: UnboundedSender<FibMessage>) {
    // Every arm forwards a parsed event to the RIB inbox. If RIB has
    // already shut down (or panicked) the receiver is dropped and the
    // send returns `SendError`; that is benign here — we don't want a
    // closing channel to take down the netlink reader task with a
    // secondary panic.
    if let NetlinkPayload::InnerMessage(msg) = msg.payload {
        match msg {
            RouteNetlinkMessage::NewLink(msg) => {
                if msg.header.interface_family != AddressFamily::Unspec {
                    return;
                }
                let link = link_from_msg(msg);
                let _ = tx.send(FibMessage::NewLink(link));
            }
            RouteNetlinkMessage::DelLink(msg) => {
                if msg.header.interface_family != AddressFamily::Unspec {
                    return;
                }
                let link = link_from_msg(msg);
                let _ = tx.send(FibMessage::DelLink(link));
            }
            RouteNetlinkMessage::NewAddress(msg) => {
                let addr = addr_from_msg(msg);
                let _ = tx.send(FibMessage::NewAddr(addr));
            }
            RouteNetlinkMessage::DelAddress(msg) => {
                let addr = addr_from_msg(msg);
                let _ = tx.send(FibMessage::DelAddr(addr));
            }
            RouteNetlinkMessage::NewRoute(msg) => {
                if let Some(route) = route_from_msg(msg) {
                    let _ = tx.send(FibMessage::NewRoute(route));
                }
            }
            RouteNetlinkMessage::DelRoute(msg) => {
                if let Some(route) = route_from_msg(msg) {
                    let _ = tx.send(FibMessage::DelRoute(route));
                }
            }
            RouteNetlinkMessage::NewNexthop(msg) => {
                if let Some(id) = nexthop_id_from_msg(&msg) {
                    let _ = tx.send(FibMessage::NewNexthop(id));
                }
            }
            RouteNetlinkMessage::DelNexthop(msg) => {
                if let Some(id) = nexthop_id_from_msg(&msg) {
                    let _ = tx.send(FibMessage::DelNexthop(id));
                }
            }
            RouteNetlinkMessage::NewNeighbour(msg) => {
                let neighbor = neighbor_from_msg(msg);
                let _ = tx.send(FibMessage::NewNeighbor(neighbor));
            }
            RouteNetlinkMessage::DelNeighbour(msg) => {
                let neighbor = neighbor_from_msg(msg);
                let _ = tx.send(FibMessage::DelNeighbor(neighbor));
            }
            // TODO: Add MDB message handling when netlink-packet-route supports it.
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

#[cfg(test)]
mod tests {
    use super::*;

    // Guards the netlink-packet-route group-nexthop decode fix our
    // RTNLGRP_NEXTHOP reconciliation depends on. These are the exact
    // bytes of a kernel group notification (RTM_NEWNEXTHOP, id 15,
    // mpath, members {2, 7}) that the unfixed library dropped with
    // "failed to decode packet ... type 104". If this fails, the dep
    // regressed and reconciliation is silently broken again.
    #[test]
    fn decodes_rtm_newnexthop_group() {
        let bytes: &[u8] = &[
            0x3c, 0x00, 0x00, 0x00, 0x68, 0x00, 0x05, 0x05, 0x59, 0x00, 0x00, 0x00, 0xff, 0x1f,
            0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
            0x0f, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,
            0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = netlink_packet_core::NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes);
        assert!(
            parsed.is_ok(),
            "RTM_NEWNEXTHOP decode regressed: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn set_route_table_uses_rtm_table_byte_for_ids_under_256() {
        let mut msg = RouteMessage::default();
        set_route_table(&mut msg, RouteHeader::RT_TABLE_MAIN as u32);
        assert_eq!(msg.header.table, RouteHeader::RT_TABLE_MAIN);
        // No RTA_TABLE attribute is emitted for the byte-sized case.
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Table(_)))
        );
    }

    #[test]
    fn set_route_table_falls_back_to_rta_table_attribute_for_large_ids() {
        // Linux VRF allocators routinely hand out ids > 255; the
        // single-byte `rtm_table` overflows, so the kernel relies on
        // `RTA_TABLE` instead. `rtm_table` must be `RT_TABLE_UNSPEC`
        // so the kernel reads the attribute.
        let mut msg = RouteMessage::default();
        set_route_table(&mut msg, 1000);
        assert_eq!(msg.header.table, RouteHeader::RT_TABLE_UNSPEC);
        let table_attr = msg
            .attributes
            .iter()
            .find_map(|a| match a {
                RouteAttribute::Table(v) => Some(*v),
                _ => None,
            })
            .expect("RTA_TABLE attribute emitted");
        assert_eq!(table_attr, 1000);
    }
}
