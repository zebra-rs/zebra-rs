use anyhow::{Context, Result};

use ipnet::{IpNet, Ipv4Net};
use netlink_packet_route::link::LinkFlags;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::fib::message::{FibAddr, FibLink};
use crate::fib::os_traffic_dump;
use crate::fib::sysctl::{sysctl_keep_addr_on_down, sysctl_mpls_enable, sysctl_seg6_enable};

use super::entry::RibEntry;
use super::tracing::rib_interface;
use super::util::IpNetExt;
use super::{LinkFlagsExt, MacAddr, Message, Rib, RibType, Vlan};

mod linkflags_serde {
    use super::*;
    pub fn serialize<S>(flags: &LinkFlags, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", flags))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    /// MTU the kernel reported when this link was first observed,
    /// before any operator-configured MTU was applied. Captured once in
    /// `Link::from` and never updated thereafter, so it survives our own
    /// `link_set_mtu` echoing back. Restored when the operator deletes
    /// `interface <name> mtu`. Internal bookkeeping — not part of any
    /// `show` output, so it stays out of the serialized form.
    #[serde(skip)]
    pub original_mtu: u32,
    pub metric: u32,
    #[serde(with = "linkflags_serde")]
    pub flags: LinkFlags,
    pub link_type: LinkType,
    pub label: bool,
    pub mac: Option<MacAddr>,
    pub addr4: Vec<LinkAddr>,
    pub addr6: Vec<LinkAddr>,
    /// `IFLA_MASTER` ifindex when this link is a slave of a bridge or
    /// VRF master. None for top-level links.
    pub master: Option<u32>,
    /// VNI from the kernel's `IFLA_VXLAN_ID` attribute on VXLAN links.
    /// Used by the EVPN advertise path: a bridge's VXLAN slave maps the
    /// bridge to the L2VPN VNI it carries.
    pub vni: Option<u32>,
    /// Local VTEP source IP from `IFLA_VXLAN_LOCAL` / `IFLA_VXLAN_LOCAL6`
    /// on VXLAN links. Used as the BGP MP_REACH nexthop for EVPN
    /// advertisements per RFC 8365 §5.1.3.
    pub vxlan_local: Option<std::net::IpAddr>,
    /// Kernel routing table from `IFLA_VRF_TABLE` on VRF master
    /// devices; `None` for every other link type. Lets an all-VRF
    /// consumer (the cradle port reconcile) resolve a slave's
    /// `master` to its VRF table straight from link state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vrf_table: Option<u32>,
    /// This device is a kernel bridge (`IFLA_INFO_KIND == "bridge"`).
    /// The cradle port reconcile classifies a slave's `master` with it:
    /// bridge ⇒ L2 port in the bridge's flood domain, VRF ⇒ routed port.
    #[serde(skip)]
    pub bridge: bool,
    /// Lower-device ifindex from `IFLA_LINK` on stacked devices — for
    /// an 802.1Q sub-interface, the interface the VLAN rides on. None
    /// for top-level links. Not the same as `master` (enslavement).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<u32>,
    /// 802.1Q VLAN id from `IFLA_VLAN_ID` on VLAN sub-interfaces.
    /// Presence is what classifies the link as a VLAN device — the
    /// name is never parsed; `eth0.100` is only a convention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
    /// Last failure reason from applying the operator-configured MTU
    /// (`mtu_config` keyed by name on `Rib`). `None` once a set
    /// succeeds. Rendered by `show interface` so a kernel rejection
    /// (e.g. an MTU below the IPv6 minimum of 1280 on a v6-enabled
    /// link) is visible to the operator. Display-only — the live MTU
    /// is always whatever the kernel reports in `mtu`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu_error: Option<String>,
}

impl Link {
    pub fn from(link: FibLink) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            original_mtu: link.mtu,
            metric: 1,
            flags: link.flags,
            link_type: link.link_type,
            label: false,
            mac: link.mac,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: link.master,
            vni: link.vni,
            vxlan_local: link.vxlan_local,
            vrf_table: link.vrf_table,
            bridge: link.bridge,
            parent: link.parent,
            vlan_id: link.vlan_id,
            mtu_error: None,
        }
    }

    pub fn is_up(&self) -> bool {
        self.flags.is_up()
    }

    pub fn is_loopback(&self) -> bool {
        self.flags.is_loopback()
    }
}

/// Kernel address scope (`ifa_scope`), the `RT_SCOPE_*` value from the
/// RTM_NEWADDR header. The kernel derives it from the address kind
/// (fe80::/10 → link, loopback → host), so it is authoritative where
/// prefix matching is only heuristic.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddrScope {
    #[default]
    Universe,
    Site,
    Link,
    Host,
    Nowhere,
    Other(u8),
}

impl AddrScope {
    /// Map the raw `ifa_scope` byte from a netlink address message.
    pub fn from_kernel(scope: u8) -> Self {
        match scope {
            0 => Self::Universe,
            200 => Self::Site,
            253 => Self::Link,
            254 => Self::Host,
            255 => Self::Nowhere,
            v => Self::Other(v),
        }
    }

    /// Scope the kernel will assign to `addr` — for the config path,
    /// whose own RTM_NEWADDR never echoes back (see
    /// [`v4_secondary_verdict`] for the same constraint on the
    /// secondary bit).
    pub fn derive(addr: &IpNet) -> Self {
        match addr {
            IpNet::V4(v4) if v4.addr().is_loopback() => Self::Host,
            IpNet::V6(v6) if v6.addr().is_loopback() => Self::Host,
            IpNet::V6(v6) if v6.addr().is_unicast_link_local() => Self::Link,
            _ => Self::Universe,
        }
    }
}

impl fmt::Display for AddrScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Universe => write!(f, "global"),
            Self::Site => write!(f, "site"),
            Self::Link => write!(f, "link"),
            Self::Host => write!(f, "host"),
            Self::Nowhere => write!(f, "nowhere"),
            Self::Other(v) => write!(f, "{}", v),
        }
    }
}

/// Kernel address state from `IFA_FLAGS` (falling back to the legacy
/// 8-bit header flags), normalized per family: the 0x01 bit is
/// IFA_F_SECONDARY on IPv4 but IFA_F_TEMPORARY on IPv6, so `secondary`
/// stays a [`LinkAddr`] field of its own and only the IPv6 reading
/// lands here.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AddrFlags {
    /// IFA_F_TENTATIVE — DAD still running; not yet usable as a source.
    pub tentative: bool,
    /// IFA_F_DADFAILED — a duplicate was detected; the address is dead.
    pub dadfailed: bool,
    /// IFA_F_DEPRECATED — preferred lifetime expired; avoid for new flows.
    pub deprecated: bool,
    /// IFA_F_TEMPORARY (IPv6 only) — RFC 4941 privacy address.
    pub temporary: bool,
    /// IFA_F_OPTIMISTIC — RFC 4429, usable while DAD is still running.
    pub optimistic: bool,
    /// IFA_F_PERMANENT — statically added, no lifetime expiry.
    pub permanent: bool,
    /// IFA_F_NOPREFIXROUTE — kernel did not install the prefix route.
    pub noprefixroute: bool,
}

impl AddrFlags {
    /// Normalize raw kernel flag bits. `is_v6` decides the 0x01 bit:
    /// TEMPORARY on IPv6, SECONDARY on IPv4 (captured elsewhere).
    pub fn from_kernel(is_v6: bool, bits: u32) -> Self {
        Self {
            tentative: bits & 0x40 != 0,
            dadfailed: bits & 0x08 != 0,
            deprecated: bits & 0x20 != 0,
            temporary: is_v6 && bits & 0x01 != 0,
            optimistic: bits & 0x04 != 0,
            permanent: bits & 0x80 != 0,
            noprefixroute: bits & 0x200 != 0,
        }
    }

    /// True when no abnormal state is set — `permanent` alone is the
    /// steady state of a static address, not worth displaying.
    fn display_empty(&self) -> bool {
        !(self.tentative
            || self.dadfailed
            || self.deprecated
            || self.temporary
            || self.optimistic
            || self.noprefixroute)
    }
}

impl fmt::Display for AddrFlags {
    /// Space-separated abnormal-state tokens in `ip addr` vocabulary;
    /// empty for a plain permanent address.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        for (set, name) in [
            (self.tentative, "tentative"),
            (self.dadfailed, "dadfailed"),
            (self.deprecated, "deprecated"),
            (self.temporary, "temporary"),
            (self.optimistic, "optimistic"),
            (self.noprefixroute, "noprefixroute"),
        ] {
            if set {
                write!(f, "{}{}", sep, name)?;
                sep = " ";
            }
        }
        Ok(())
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
pub struct LinkAddr {
    pub addr: IpNet,
    pub ifindex: u32,
    pub secondary: bool,
    pub config: bool,
    pub fib: bool,
    pub scope: AddrScope,
    pub flags: AddrFlags,
    /// Remaining valid lifetime in seconds at the time of the last
    /// kernel notification (`IFA_CACHEINFO`); `u32::MAX` = forever,
    /// `None` = the kernel never reported one (config-path entry).
    pub valid_lft: Option<u32>,
    /// Remaining preferred lifetime; see `valid_lft`.
    pub preferred_lft: Option<u32>,
}

impl LinkAddr {
    /// Build a LinkAddr from a FIB (kernel netlink) message.
    ///
    /// The kernel just told us about this address, so it is installed in the
    /// kernel FIB by definition (`fib = true`). Whether the address was
    /// configured in zebra-rs is not knowable here — callers that received
    /// the FibAddr from the configuration path flip `config = true` after.
    pub fn from(osaddr: FibAddr) -> Self {
        Self {
            addr: osaddr.addr,
            ifindex: osaddr.link_index,
            secondary: osaddr.secondary,
            config: false,
            fib: true,
            scope: osaddr.scope,
            flags: osaddr.flags,
            valid_lft: osaddr.valid_lft,
            preferred_lft: osaddr.preferred_lft,
        }
    }

    pub fn is_v4(&self) -> bool {
        match self.addr {
            IpNet::V4(_) => true,
            IpNet::V6(_) => false,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
pub enum LinkType {
    #[default]
    Unknown,
    Loopback,
    Ethernet,
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Loopback => write!(f, "Loopback"),
            Self::Ethernet => write!(f, "Ethernet"),
        }
    }
}

fn link_info_show(rib: &Rib, link: &Link, buf: &mut String, cb: &impl Fn(&String, &mut String)) {
    writeln!(buf, "Interface: {}", link.name).unwrap();
    write!(buf, "  Hardware is {}", link.link_type).unwrap();
    if link.link_type == LinkType::Ethernet {
        if let Some(mac) = link.mac {
            writeln!(buf, " {}", mac).unwrap();
        } else {
            writeln!(buf).unwrap();
        }
    } else {
        writeln!(buf).unwrap();
    }
    writeln!(
        buf,
        "  index {} metric {} mtu {}",
        link.index, link.metric, link.mtu
    )
    .unwrap();
    if let Some(err) = &link.mtu_error {
        writeln!(buf, "  {}", err).unwrap();
    }
    if let Some(vid) = link.vlan_id {
        write!(buf, "  VLAN id {}", vid).unwrap();
        if let Some(parent) = link.parent {
            match rib.links.get(&parent) {
                Some(p) => writeln!(buf, " parent {} (index {})", p.name, parent).unwrap(),
                None => writeln!(buf, " parent index {}", parent).unwrap(),
            }
        } else {
            writeln!(buf).unwrap();
        }
    }
    write!(
        buf,
        "  Link is {}",
        if link.is_up() { "Up\n" } else { "Down\n" }
    )
    .unwrap();
    writeln!(buf, "  {}", link.flags).unwrap();
    let vrf_label = link_vrf_name(rib, link)
        .map(|n| format!("vrf {}", n))
        .unwrap_or_else(|| "Not bound".to_string());
    writeln!(buf, "  VRF Binding: {}", vrf_label).unwrap();
    writeln!(
        buf,
        "  Label switching is {}",
        if link.label { "enabled" } else { "disabled" }
    )
    .unwrap();
    for addr in link.addr4.iter() {
        write!(buf, "  inet {}", addr.addr).unwrap();
        if addr.secondary {
            write!(buf, " secondary").unwrap();
        }
        addr_tokens_show(buf, addr);
        writeln!(buf).unwrap();
    }
    for addr in link.addr6.iter() {
        write!(buf, "  inet6 {}", addr.addr).unwrap();
        addr_tokens_show(buf, addr);
        writeln!(buf).unwrap();
    }
    cb(&link.name, buf);
}

/// Append the kernel-state tokens for one address line: non-global
/// scope, abnormal `IFA_FLAGS` state, and finite lifetimes. A plain
/// permanent global address contributes nothing, keeping the common
/// case as it always looked.
fn addr_tokens_show(buf: &mut String, addr: &LinkAddr) {
    if addr.scope != AddrScope::Universe {
        write!(buf, " scope {}", addr.scope).unwrap();
    }
    if !addr.flags.display_empty() {
        write!(buf, " {}", addr.flags).unwrap();
    }
    if let (Some(valid), Some(preferred)) = (addr.valid_lft, addr.preferred_lft)
        && valid != u32::MAX
    {
        write!(buf, " valid-lft {} preferred-lft {}", valid, preferred).unwrap();
    }
}

#[derive(Serialize)]
pub struct InterfaceBrief {
    pub interface: String,
    pub status: String,
    pub vrf: String,
    pub addresses: Vec<String>,
}

#[derive(Serialize)]
pub struct InterfaceDetailed {
    pub interface: String,
    pub hardware: String,
    pub index: u32,
    pub metric: u32,
    pub mtu: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu_error: Option<String>,
    pub link_status: String,
    pub flags: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_index: Option<u32>,
    pub vrf_binding: String,
    pub label_switching: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    pub inet_addresses: Vec<InterfaceAddress>,
    pub inet6_addresses: Vec<InterfaceAddressV6>,
}

#[derive(Serialize)]
pub struct InterfaceAddress {
    pub address: String,
    pub secondary: bool,
    pub scope: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_lft: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_lft: Option<u32>,
}

#[derive(Serialize)]
pub struct InterfaceAddressV6 {
    pub address: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_lft: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_lft: Option<u32>,
}

/// The address's abnormal-state flags as display tokens, for JSON output.
fn addr_flag_tokens(flags: &AddrFlags) -> Vec<String> {
    flags
        .to_string()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

pub fn link_brief_show(rib: &Rib, buf: &mut String) {
    // Write the header just once if there is any link
    if !rib.links.is_empty() {
        writeln!(buf, "Interface        Status VRF            Addresses").unwrap();
        writeln!(buf, "---------        ------ ---            ---------").unwrap();
    }

    for link in rib.links.values() {
        let status = if link.is_up() { "Up" } else { "Down" };
        let vrf = link_vrf_name(rib, link).unwrap_or("default");
        let addrs = link.addr4.iter().chain(link.addr6.iter());

        let mut addrs_iter = addrs.peekable();
        if addrs_iter.peek().is_none() {
            // No addresses
            writeln!(buf, "{:<16} {:<6} {:<14}", link.name, status, vrf).unwrap();
        } else {
            let mut first = true;
            for addr in addrs_iter {
                if first {
                    writeln!(
                        buf,
                        "{:<16} {:<6} {:<14} {}",
                        link.name, status, vrf, addr.addr
                    )
                    .unwrap();
                    first = false;
                } else {
                    writeln!(buf, "{:>39}{}", "", addr.addr).unwrap();
                }
            }
        }
    }
}

pub fn link_brief_show_json(rib: &Rib) -> String {
    let mut interfaces = Vec::new();

    for link in rib.links.values() {
        let addresses: Vec<String> = link
            .addr4
            .iter()
            .chain(link.addr6.iter())
            .map(|addr| addr.addr.to_string())
            .collect();

        let interface_brief = InterfaceBrief {
            interface: link.name.clone(),
            status: if link.is_up() {
                "Up".to_string()
            } else {
                "Down".to_string()
            },
            vrf: link_vrf_name(rib, link)
                .map(str::to_string)
                .unwrap_or_else(|| "default".to_string()),
            addresses,
        };

        interfaces.push(interface_brief);
    }

    serde_json::to_string_pretty(&interfaces).unwrap_or_else(|_| "{}".to_string())
}

pub fn link_detailed_show_json(rib: &Rib, link_name: Option<&str>) -> String {
    let mut interfaces = Vec::new();

    if let Some(name) = link_name {
        // Show single interface
        if let Some(link) = rib.link_by_name(name) {
            interfaces.push(link_to_detailed_json(rib, link));
        } else {
            let error = serde_json::json!({
                "error": format!("interface {} not found", name)
            });
            return serde_json::to_string_pretty(&error).unwrap_or_else(|_| "{}".to_string());
        }
    } else {
        // Show all interfaces
        for link in rib.links.values() {
            interfaces.push(link_to_detailed_json(rib, link));
        }
    }

    serde_json::to_string_pretty(&interfaces).unwrap_or_else(|_| "{}".to_string())
}

fn link_to_detailed_json(rib: &Rib, link: &Link) -> InterfaceDetailed {
    let inet_addresses: Vec<InterfaceAddress> = link
        .addr4
        .iter()
        .map(|addr| InterfaceAddress {
            address: addr.addr.to_string(),
            secondary: addr.secondary,
            scope: addr.scope.to_string(),
            flags: addr_flag_tokens(&addr.flags),
            valid_lft: addr.valid_lft,
            preferred_lft: addr.preferred_lft,
        })
        .collect();

    let inet6_addresses: Vec<InterfaceAddressV6> = link
        .addr6
        .iter()
        .map(|addr| InterfaceAddressV6 {
            address: addr.addr.to_string(),
            scope: addr.scope.to_string(),
            flags: addr_flag_tokens(&addr.flags),
            valid_lft: addr.valid_lft,
            preferred_lft: addr.preferred_lft,
        })
        .collect();

    InterfaceDetailed {
        interface: link.name.clone(),
        hardware: format!("{}", link.link_type),
        index: link.index,
        metric: link.metric,
        mtu: link.mtu,
        mtu_error: link.mtu_error.clone(),
        link_status: if link.is_up() {
            "Up".to_string()
        } else {
            "Down".to_string()
        },
        flags: format!("{}", link.flags),
        vlan_id: link.vlan_id,
        parent: link
            .parent
            .and_then(|p| rib.links.get(&p))
            .map(|p| p.name.clone()),
        parent_index: link.parent,
        vrf_binding: link_vrf_name(rib, link)
            .map(|n| format!("vrf {}", n))
            .unwrap_or_else(|| "Not bound".to_string()),
        label_switching: if link.label {
            "enabled".to_string()
        } else {
            "disabled".to_string()
        },
        mac_address: link.mac.map(|mac| format!("{}", mac)),
        inet_addresses,
        inet6_addresses,
    }
}

pub fn link_show(rib: &Rib, mut args: Args, json: bool) -> String {
    let cb = os_traffic_dump();
    let mut buf = String::new();

    if args.is_empty() {
        if json {
            return link_detailed_show_json(rib, None);
        } else {
            for link in rib.links.values() {
                link_info_show(rib, link, &mut buf, &cb);
            }
        }
    } else {
        let link_name = args.string().unwrap();

        if link_name == "brief" {
            if json {
                return link_brief_show_json(rib);
            } else {
                link_brief_show(rib, &mut buf);
                return buf;
            }
        }

        if json {
            return link_detailed_show_json(rib, Some(&link_name));
        } else {
            if let Some(link) = rib.link_by_name(&link_name) {
                link_info_show(rib, link, &mut buf, &cb)
            } else {
                write!(buf, "% interface {} not found", link_name).unwrap();
            }
        }
    }
    buf
}

/// Outcome of merging an incoming LinkAddr into a link's address list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrUpdate {
    /// The address was not present and has been inserted.
    Added,
    /// The address was present and the incoming flags flipped `config` or
    /// `fib` true — a config push landing on an already-known kernel
    /// address, or the kernel confirming a config-driven (re-)install —
    /// or its secondary verdict moved (promotion/demotion).
    Merged,
    /// The address was present and its kernel address state moved —
    /// `IFA_FLAGS` (DAD completing clears tentative, deprecation) or
    /// scope. Re-broadcast to protocol clients: address-state-aware
    /// consumers (BGP next-hop selection) need the transition, and
    /// every registry fed by AddrAdd is idempotent against
    /// re-delivery of a known address.
    Refreshed,
    /// The address was present and nothing broadcast-worthy changed —
    /// a kernel re-notify, or an `IFA_CACHEINFO` lifetime renewal
    /// (adopted into the stored entry silently: every RA refreshes
    /// the lifetimes, and re-broadcasting each one would have IS-IS
    /// re-originating LSPs on the RA interval).
    Unchanged,
}

/// Kernel-mirror of `__inet_insert_ifa`'s IFA_F_SECONDARY verdict for an
/// IPv4 address being installed on `link`: secondary iff another installed
/// primary with the same mask and network already exists. The config path
/// must compute this itself — the kernel excludes the originating socket
/// from the RTNLGRP broadcast, so our own RTM_NEWADDR never echoes back.
pub fn v4_secondary_verdict(link: &Link, v4: Ipv4Net) -> bool {
    link.addr4.iter().any(|e| {
        e.fib
            && !e.secondary
            && matches!(e.addr, IpNet::V4(ev)
                if ev != v4 && ev.prefix_len() == v4.prefix_len() && ev.network() == v4.network())
    })
}

/// Insert a LinkAddr or merge it into an existing entry with the same address.
///
/// In the merge case, the existing entry's `config` and `fib` flags are
/// OR-ed with the incoming flags — this lets the kernel's netlink
/// confirmation of a config-driven address flip `fib` true on the
/// already-present LinkAddr without creating a duplicate — and `secondary`
/// is adopted from the incoming address: kernel events carry the kernel's
/// IFA_F_SECONDARY, and the config path computes the same verdict via
/// [`v4_secondary_verdict`] before calling here. The returned
/// [`AddrUpdate`] tells the caller whether anything actually changed, so
/// redundant kernel notifications aren't re-broadcast to protocol clients.
pub fn link_addr_update(link: &mut Link, addr: LinkAddr) -> AddrUpdate {
    let bucket = if addr.is_v4() {
        &mut link.addr4
    } else {
        &mut link.addr6
    };
    if let Some(existing) = bucket.iter_mut().find(|a| a.addr == addr.addr) {
        let changed = (addr.config && !existing.config)
            || (addr.fib && !existing.fib)
            || existing.secondary != addr.secondary;
        // Kernel metadata (scope, DAD/lifetime state) is only knowable
        // from netlink events — the config path (`addr.config`) carries
        // defaults and must not wipe what the kernel told us. The
        // kernel resends RTM_NEWADDR whenever this state moves (DAD
        // completion flips tentative off, each RA renews the
        // lifetimes), so a kernel event is always the fresher truth.
        // Flag / scope movement is broadcast-worthy (Refreshed);
        // lifetime renewal is adopted silently — see [`AddrUpdate`].
        let mut refreshed = false;
        if !addr.config {
            refreshed = existing.scope != addr.scope || existing.flags != addr.flags;
            existing.scope = addr.scope;
            existing.flags = addr.flags;
            existing.valid_lft = addr.valid_lft;
            existing.preferred_lft = addr.preferred_lft;
        }
        existing.config |= addr.config;
        existing.fib |= addr.fib;
        existing.secondary = addr.secondary;
        return if changed {
            AddrUpdate::Merged
        } else if refreshed {
            AddrUpdate::Refreshed
        } else {
            AddrUpdate::Unchanged
        };
    }
    bucket.push(addr);
    AddrUpdate::Added
}

/// Handle a kernel-side address removal, branching on `config`:
///
/// - If the existing entry was configured (`config = true`), keep it but
///   clear its `fib` flag — the kernel no longer has the address but config
///   intent survives so `link_up` can re-install it later.
/// - If the existing entry was kernel-only (`config = false`), remove it.
///
/// Returns `Some(())` only when the call changed state. A missing entry, or
/// a configured entry whose `fib` flag is already false (a repeated DelAddr
/// notification), returns `None` so callers don't tear down connected
/// routes or re-broadcast the removal for an address we no longer hold.
pub fn link_addr_del(link: &mut Link, addr: LinkAddr) -> Option<()> {
    let bucket = if addr.is_v4() {
        &mut link.addr4
    } else {
        &mut link.addr6
    };
    let pos = bucket.iter().position(|x| x.addr == addr.addr)?;
    if bucket[pos].config {
        if !bucket[pos].fib {
            return None;
        }
        bucket[pos].fib = false;
    } else {
        bucket.remove(pos);
    }
    Some(())
}

/// True when another kernel-installed address in `bucket` shares `addr`'s
/// connected prefix. Mirrors the kernel's own prefix-route refcount
/// (`cleanup_prefix_route`): the connected route for a prefix is installed
/// with its first covering address and withdrawn with its last, so adding
/// or deleting an address while a sibling still covers the prefix must not
/// touch the route.
fn prefix_covered_by_other(bucket: &[LinkAddr], addr: &LinkAddr) -> bool {
    let prefix = addr.addr.apply_mask();
    bucket
        .iter()
        .any(|e| e.fib && e.addr != addr.addr && e.addr.apply_mask() == prefix)
}

impl Rib {
    /// Resolve the EVPN symmetric-IRB L3VNI binding for a VXLAN device by
    /// name: if the operator bound it to a tenant VRF (`vxlan <name> vrf
    /// <vrf>`), return that VRF's `(table_id, router_mac)`. The router-MAC
    /// is the explicit `router-mac` leaf, else the VRF master device's MAC.
    /// Returns `None` for a plain L2VNI device (no VRF binding), an
    /// unresolved VRF, or when no MAC is available yet.
    pub(crate) fn vxlan_l3_binding(&self, name: &str) -> Option<(u32, [u8; 6])> {
        let dev = self.vxlan.get(name)?;
        let vrf_name = dev.vrf.as_ref()?;
        let vrf = self.vrfs.get(vrf_name)?;
        let rmac = dev
            .router_mac
            .or_else(|| self.links.get(&vrf.ifindex).and_then(|l| l.mac))?;
        Some((vrf.table_id, rmac.octets()))
    }

    pub async fn link_add(&mut self, fib_link: FibLink) {
        // `external vnifilter` VXLAN devices (the EVPN model) carry no
        // fixed kernel VNI — `IFLA_VXLAN_ID` is 0. Source the real VNI
        // (and the local VTEP address) from our own config, keyed by
        // device name, whenever the kernel message doesn't carry them.
        // A later partial RTM_NEWLINK — e.g. the one the kernel emits when
        // the device is enslaved to a bridge — carries `IFLA_MASTER` but
        // NOT the nested `IFLA_VXLAN_*` block, so `link_from_msg` rebuilds
        // the link with `vni: None` / `vxlan_local: None`. Refilling from
        // config here keeps both stable across such updates, which the EVPN
        // Type-2 origination depends on for the VTEP nexthop (an SRv6 Type-2
        // rides its End.DT2U SID and tolerated the loss; a VXLAN Type-2 has
        // only the nexthop).
        let mut fib_link = fib_link;
        if let Some(cfg) = self.vxlan.get(&fib_link.name) {
            if (fib_link.vni.is_none() || fib_link.vni == Some(0))
                && let Some(cfg_vni) = cfg.vni
            {
                fib_link.vni = Some(cfg_vni);
            }
            if fib_link.vxlan_local.is_none()
                && let Some(local) = cfg.local_addr
            {
                fib_link.vxlan_local = Some(local);
            }
        }

        if rib_interface() {
            tracing::info!(
                "link_add: ifindex {} name {} vni {:?} master {:?}",
                fib_link.index,
                fib_link.name,
                fib_link.vni,
                fib_link.master,
            );
        }
        // Capture pre-state so we can detect a VXLAN-bridge association
        // gaining valid `(master, vni)` and trigger an FDB rescan. The
        // common case is operator-driven sequence:
        //   1. ip link add br50 type bridge      (no master/vni)
        //   2. ip link add vxlan100 type vxlan id 100   (vni set, no master)
        //   3. ip link set vxlan100 master br50  (master gained — THIS PATH)
        // Without rescan, FDB entries already learned on `br50` between
        // steps 1 and 3 would never reach the EVPN advertise path until
        // they re-learn; with rescan we re-emit `RibRx::FdbAdd` for them.
        let ifindex = fib_link.index;
        let prev_evpn_bridge: Option<u32> = self
            .links
            .get(&ifindex)
            .and_then(|l| if l.vni.is_some() { l.master } else { None });
        // Pre-update VNI snapshot so the existing-link path can fire
        // `register_vxlan_ifindex` / `unregister_vxlan_ifindex` on
        // transitions. Without this, a VXLAN whose RTM_NEWLINK arrives
        // a second time (e.g. partial first emission, then a full one
        // carrying `IFLA_VXLAN_ID`) only gets its VNI cached on `Link`
        // but never registered with FIB — so subsequent `mac_add`
        // calls find no entry in `vni_ifindex_map` and silently skip.
        let prev_vni: Option<u32> = self.links.get(&ifindex).and_then(|l| l.vni);

        // Capture MTU pre-state and the incoming value so a change on an
        // already-known link (operator `interface X mtu N`, or an
        // external `ip link set ... mtu`) can be fanned out to protocol
        // modules that cache it for packet generation (OSPF DD if_mtu,
        // IS-IS hello padding). `prev_mtu` is None for a brand-new link —
        // its mtu rides along on `api_link_add` instead.
        let prev_mtu: Option<u32> = self.links.get(&ifindex).map(|l| l.mtu);
        let new_mtu: u32 = fib_link.mtu;

        // Hardware-address pre-state, for the same reason as `prev_mtu`:
        // IS-IS caches it as the circuit SNPA. `None` for a brand-new
        // link (its address rides on `api_link_add`); `Some(None)` for
        // a known link the kernel reports no address for.
        let prev_mac: Option<Option<MacAddr>> = self.links.get(&ifindex).map(|l| l.mac);

        // Capture master pre-state so an existing link crossing a VRF
        // boundary (operator `interface X vrf Y`, applied by the kernel
        // as an RTM_NEWLINK on an already-known ifindex) can be
        // reconciled below. `link_existed` distinguishes this from a
        // brand-new link, whose notification is handled in the `else`
        // branch via `api_link_add`.
        let link_existed = self.links.contains_key(&ifindex);
        let prev_master: Option<u32> = self.links.get(&ifindex).and_then(|l| l.master);
        let now_master: Option<u32> = fib_link.master;

        if let Some(link) = self.links.get_mut(&fib_link.index) {
            // When link already exists, we are going to check interface up &
            // down event handling.
            if link.is_up() {
                if !fib_link.flags.is_up() {
                    if rib_interface() {
                        tracing::info!(
                            "kernel: link {} (ifindex {}) Up => Down",
                            link.name,
                            link.index
                        );
                    }

                    link.flags = fib_link.flags;
                    let _ = self.tx.send(Message::LinkDown {
                        ifindex: link.index,
                    });
                }
            } else if fib_link.flags.is_up() {
                if rib_interface() {
                    tracing::info!(
                        "kernel: link {} (ifindex {}) Down => Up; recovering connected routes",
                        link.name,
                        link.index
                    );
                }
                link.flags = fib_link.flags;
                let _ = self.tx.send(Message::LinkUp {
                    ifindex: link.index,
                });
            }
            // Master / VNI can change on an existing link too — most
            // commonly when a VXLAN device is enslaved or re-enslaved
            // via `ip link set ... master <br>` after creation. Track
            // them so `vni_for_bridge` reflects the current state and
            // FDB resolution gets the right bridge.
            link.master = fib_link.master;
            link.vni = fib_link.vni;
            // Parent ifindex / VLAN id: adopt-if-present, never clear.
            // A partial RTM_NEWLINK (e.g. the enslave notification, see
            // the VXLAN refill comment above) omits `IFLA_LINKINFO`
            // entirely, and the kernel never changes either value on a
            // live link, so a missing attribute means "unchanged", not
            // "gone".
            if fib_link.parent.is_some() {
                link.parent = fib_link.parent;
            }
            if fib_link.vlan_id.is_some() {
                link.vlan_id = fib_link.vlan_id;
            }
            // Adopt the kernel's current MTU (it may have changed since
            // we last saw this link — our own `link_set_mtu` echoes back
            // here, as does an external `ip link set`). The fan-out to
            // protocols happens after the borrow is released, below.
            link.mtu = fib_link.mtu;
            // Hardware address: adopt-if-present, same rule as parent /
            // vlan_id above. It DOES change on a live link, and our own
            // config is what moves it: the kernel recomputes a bridge's
            // address from its port set whenever that set changes
            // (`br_stp_recalculate_bridge_id`), so `interface <x> bridge
            // <br>` and `vxlan <v> bridge <br>` both retarget it — as does
            // an external `ip link set <dev> address`. Without this the
            // cache keeps the address the link happened to have when it
            // first appeared, which `show interface` then reports for the
            // rest of the run.
            if fib_link.mac.is_some() {
                link.mac = fib_link.mac;
            }
        } else {
            let link = Link::from(fib_link);
            let _ = sysctl_mpls_enable(&link.name);
            let _ = sysctl_seg6_enable(&link.name);
            let _ = sysctl_keep_addr_on_down(&link.name);
            self.api_link_add(&link);
            self.links.insert(link.index, link.clone());

            // Note: VXLAN VNI registration happens in the unified
            // post-block reconciliation below (covers both new-link
            // and existing-link paths uniformly).

            // Replay an operator-configured MTU for a freshly-appeared
            // link (config-before-interface, or interface re-created).
            // Only re-issue when the live value differs; the kernel's
            // echoed RTM_NEWLINK then updates the cached mtu. Scoped to
            // the new-link branch so plain RTM_NEWLINK echoes don't
            // re-attempt a previously-rejected set on every event.
            if let Some(&mtu) = self.mtu_config.get(&link.name)
                && mtu != link.mtu
            {
                let ifindex = link.index;
                let name = link.name.clone();
                match self.fib_handle.link_set_mtu(ifindex, mtu).await {
                    Ok(()) => {
                        if let Some(l) = self.links.get_mut(&ifindex) {
                            l.mtu_error = None;
                        }
                    }
                    Err(e) => {
                        if let Some(l) = self.links.get_mut(&ifindex) {
                            l.mtu_error = Some(format!("MTU set to {mtu} is failed due to {e}"));
                        }
                        tracing::warn!("link_set_mtu({name}, {mtu}) failed: {e}");
                    }
                }
            }

            if !link.is_up() {
                self.make_link_up(link.index).await;
            }
        }

        // Fan out an MTU change on an already-known link to protocol
        // subscribers. `prev_mtu` is Some only when the link existed
        // before this call; a brand-new link carried its mtu on the
        // `api_link_add` above, so this fires only on genuine changes.
        if let Some(prev) = prev_mtu
            && prev != new_mtu
        {
            self.api_link_mtu(ifindex, new_mtu);
        }

        // Likewise for the hardware address. Compare against the value
        // now *stored* rather than `fib_link.mac`, so the adopt-if-present
        // rule above is honoured: an RTM_NEWLINK that omits IFLA_ADDRESS
        // leaves the cache untouched and fires nothing.
        if let Some(prev) = prev_mac
            && let Some(mac) = link_mac_delta(prev, self.links.get(&ifindex).and_then(|l| l.mac))
        {
            self.api_link_mac(ifindex, mac);
        }

        // A master change that crosses a VRF boundary moves this
        // interface between subscriber sets: protocol clients in the
        // *old* VRF must see it leave (DelLink), clients in the *new*
        // VRF must see it arrive (NewLink). The kernel reports the
        // enslave/release as an RTM_NEWLINK on an already-known
        // ifindex, so the new-link branch above (which fires
        // `api_link_add`) is skipped — reconcile the move here. A
        // master change that stays within the same VRF id (e.g. bridge
        // enslave, where the master isn't a VRF device → id 0) is a
        // no-op.
        if link_existed {
            let prev_vrf_id = self.master_vrf_id(prev_master);
            let now_vrf_id = self.master_vrf_id(now_master);
            if prev_vrf_id != now_vrf_id
                && let Some(link) = self.links.get(&ifindex).cloned()
            {
                // Withdraw from the old VRF — addresses first, then the
                // link — so a client tearing down per-interface state
                // sees dependents leave before the interface itself.
                for addr in link.addr4.iter().chain(link.addr6.iter()) {
                    self.api_addr_del_vrf(addr, prev_vrf_id);
                }
                self.api_link_del_vrf(ifindex, prev_vrf_id);
                // Announce to the new VRF — link first, then its
                // addresses — mirroring the subscribe() dump order. The
                // addresses were originally pushed only to the VRF the
                // interface used to sit in, so the new VRF's clients
                // need this replay to learn them.
                self.api_link_add_vrf(&link, now_vrf_id);
                for addr in link.addr4.iter().chain(link.addr6.iter()) {
                    self.api_addr_add_vrf(addr, now_vrf_id);
                }
                // Re-home this interface's own connected-route shadows
                // between the two VRF tables. Each address's connected
                // route was filed in the *old* table — `route_table_for`
                // picked it from the master in effect when the address
                // was learned, which (during a config-driven enslave)
                // is the default table because the kernel's enslaving
                // RTM_NEWLINK hadn't landed yet. Enslaving doesn't move
                // those entries on its own, so without this the connected
                // prefix is missing from `show ip route vrf <N>` and
                // wrongly present in `show ip route`. Pull each one out of
                // the old table (named by `prev_vrf_id`) and re-add it
                // into the new one (derived from the now-updated
                // `link.master`). Connected routes are non-protocol, so
                // this never touches the kernel FIB. Only meaningful while
                // the link is up — a down link has no connected shadow.
                if link.is_up() {
                    for addr in link.addr4.iter().chain(link.addr6.iter()) {
                        self.connected_route_del(ifindex, addr.addr, prev_vrf_id)
                            .await;
                        self.connected_route_add(ifindex, addr.addr).await;
                    }
                }
                // Replay this VRF's static routes now that the interface
                // is enslaved: a route whose gateway sits on this link was
                // unresolvable while the link was still in the default VRF,
                // but the on-link stamp (`Rib::stamp_vrf_onlink`) can pin
                // its egress now that `link.master` reflects the VRF.
                if now_vrf_id != 0
                    && let Some(name) = self
                        .vrfs
                        .values()
                        .find(|v| v.table_id == now_vrf_id)
                        .map(|v| v.name.clone())
                {
                    self.static_vrf_v4.reinstall(&name, &self.tx);
                    self.static_vrf_v6.reinstall(&name, &self.tx);
                }
                // The interface's addresses changed scope: both the
                // VRF it left and the one it joined (and the global
                // pick, which excludes VRF members) may now derive a
                // different Router-ID.
                self.router_id_update();
            } else if prev_master != now_master
                && let Some(link) = self.links.get(&ifindex).cloned()
            {
                // A master change that stays within one VRF id — bridge
                // enslave/release, or a move between bridges — migrates
                // no subscriber set, but the link's `master` is
                // load-bearing for `global_links` consumers (the cradle
                // port reconcile classifies a port L2/L3 from it).
                // Re-announce the updated link as an upsert.
                self.api_link_add_vrf(&link, now_vrf_id);
            }
        }

        // Reconcile FIB's VNI→ifindex map across (prev_vni → now_vni)
        // transitions for both branches uniformly:
        //   None    → Some(n): register (new VXLAN, or pre-existing
        //                      link gained its VXLAN ID)
        //   Some(m) → Some(n), m ≠ n: unregister m, register n
        //   Some(n) → None: unregister n (rare — kernel doesn't
        //                   normally strip the VNI from a live VXLAN)
        //   unchanged: no-op
        // Doing this post-block (rather than only in the new-link
        // branch) is what fixes the case where RTM_NEWLINK is
        // re-emitted with `IFLA_VXLAN_ID` after the link was first
        // observed without it — without reconciliation, the VNI
        // would land on `Link::vni` but never reach `vni_ifindex_map`,
        // and `mac_add` would silently skip every install.
        let now_vni: Option<u32> = self.links.get(&ifindex).and_then(|l| l.vni);
        if prev_vni != now_vni
            && let Some(new) = now_vni
        {
            self.fib_handle.register_vxlan_ifindex(new, ifindex);
            if let Some(local) = self.links.get(&ifindex).and_then(|l| l.vxlan_local) {
                self.api_vxlan_add(new, local);
                let name = self
                    .links
                    .get(&ifindex)
                    .map(|l| l.name.clone())
                    .unwrap_or_default();
                // Tee the VNI binding + local VTEP source to the cradle eBPF
                // data plane (VXLAN only; an SRv6 device's IPv6-local is a
                // no-op there). A device the operator bound to a tenant VRF
                // is an EVPN symmetric-IRB L3VNI — route the inner IP in
                // that VRF with a router-MAC rewrite; a plain device is an
                // L2VNI (bridge domain).
                if let Some((vrf_table_id, rmac)) = self.vxlan_l3_binding(&name) {
                    self.fib_handle
                        .cradle_vni_register_l3(new, local, vrf_table_id, rmac)
                        .await;
                } else if self.vxlan.get(&name).is_none_or(|v| v.vrf.is_none()) {
                    // Plain L2VNI: no tenant-VRF binding configured.
                    self.fib_handle.cradle_vni_register(new, local).await;
                }
                // else: configured as an L3VNI but the VRF isn't resolved
                // yet (config-order race). Don't register it as an L2VNI;
                // the VrfAdd handler re-tees the L3 binding when the VRF
                // appears.
            }
        }

        // Did this link just gain (or change) its EVPN bridge
        // association? If so, walk the neighbor table and re-emit
        // `RibRx::FdbAdd` for every AF_BRIDGE entry on that bridge.
        // BGP's `evpn_originate_macip` is idempotent (update_evpn
        // replaces same ident+remote_id) so duplicate fires are safe.
        let now_evpn_bridge: Option<u32> = self
            .links
            .get(&ifindex)
            .and_then(|l| if l.vni.is_some() { l.master } else { None });
        if let Some(bridge) = now_evpn_bridge
            && prev_evpn_bridge != Some(bridge)
        {
            // The VXLAN just joined a bridge: apply the EVPN bridge-slave
            // defaults on its port (`neigh_suppress on`, `learning off`,
            // `vlan_tunnel on`), and wire the single-VXLAN-device kernel
            // datapath (bridge vlan_filtering + the VLAN 1 -> VNI tunnel
            // mapping) so bridged traffic actually encapsulates.
            self.fib_handle.vxlan_bridge_port_defaults(ifindex).await;
            if let Some(vni) = now_vni {
                self.fib_handle
                    .vxlan_svd_datapath(ifindex, bridge, vni)
                    .await;
            }
            self.rescan_fdb_for_bridge(bridge);
        }

        // Publish EVI membership for everything this event could have
        // moved. Both masters matter: a port changing bridges leaves one
        // EVI set and joins another, and only re-reading both reports the
        // departure. Every port of those bridges is re-read, not just this
        // one — a VXLAN arriving, leaving, or changing its VNI changes the
        // EVI set of every port sharing its bridge, and that VXLAN is the
        // link this event is about.
        self.publish_l2_evis([prev_master, now_master], ifindex);

        // If a VRF binding is pending for this interface (operator
        // configured it before the kernel device appeared, or before
        // the VRF master was created), replay it now.
        let ifname = self
            .links
            .get(&ifindex)
            .map(|l| l.name.clone())
            .unwrap_or_default();
        if let Some(vrf) = self.pending_vrf_bind.get(&ifname).cloned() {
            let _ = self.tx.send(Message::LinkVrfBind {
                ifname: ifname.clone(),
                vrf,
            });
        }

        // Replay any pending bridge binding now that a link (re)appeared.
        // Two cases, both keyed off the just-arrived link, cover either
        // config/creation order:
        //   1. this link is the *slave* that was waiting to be enslaved
        //      (operator set `bridge` before the interface appeared, or
        //      before its bridge existed).
        //   2. this link is the *bridge master* one or more slaves were
        //      waiting on (BridgeAdd's netlink create just echoed back).
        if let Some(bridge) = self.pending_bridge_bind.get(&ifname).cloned() {
            let _ = self.tx.send(Message::LinkBridgeBind {
                ifname: ifname.clone(),
                bridge,
            });
        }
        let waiting: Vec<(String, Option<String>)> = self
            .pending_bridge_bind
            .iter()
            .filter(|(_, b)| b.as_deref() == Some(ifname.as_str()))
            .map(|(slave, b)| (slave.clone(), b.clone()))
            .collect();
        for (slave, bridge) in waiting {
            let _ = self.tx.send(Message::LinkBridgeBind {
                ifname: slave,
                bridge,
            });
        }

        // Replay configured VLAN sub-interfaces waiting on this link as
        // their parent. Covers either order: config-before-parent, and
        // a parent re-created after deletion (the kernel cascades VLAN
        // children away with a deleted parent, so on its return they
        // must be made again). This replay is also the normal path for
        // a same-commit `bridge br0` + `vlan br0.50 interface br0`:
        // when `VlanAdd` is processed the bridge's netlink create has
        // not echoed back into `self.links` yet, so `vlan_apply`
        // defers, and this hook fires on the echo. `vlan_apply` no-ops
        // when the device already exists with the right parent and id.
        let waiting_vlans: Vec<Vlan> = self
            .vlans
            .values()
            .filter(|v| v.parent == ifname)
            .cloned()
            .collect();
        for vlan in waiting_vlans {
            self.vlan_apply(&vlan).await;
        }
    }

    /// Create the kernel device for a configured VLAN sub-interface.
    /// No-op while the parent link is absent — `link_add` replays this
    /// when the parent appears. A pre-existing device of the same name
    /// is adopted when its parent and VLAN id match the config; a
    /// mismatched VLAN device is deleted and re-created, because the
    /// kernel refuses to change either property on a live link. A
    /// same-named link that is NOT a VLAN device (an operator naming
    /// collision with a physical or other logical interface) is left
    /// untouched — deleting it would destroy an interface we don't own.
    pub async fn vlan_apply(&self, vlan: &Vlan) {
        if let Some(existing) = self.link_by_name(&vlan.name) {
            if existing.vlan_id.is_none() {
                tracing::warn!(
                    "vlan {}: a non-VLAN kernel link with this name exists (ifindex {}); not touching it",
                    vlan.name,
                    existing.index
                );
                return;
            }
            let parent_matches = self
                .link_by_name(&vlan.parent)
                .map(|p| existing.parent == Some(p.index))
                .unwrap_or(false);
            if existing.vlan_id == Some(vlan.vlan_id) && parent_matches {
                // Adopt: left over from a previous run, or pre-created
                // by the operator with matching properties.
                return;
            }
            self.fib_handle.vlan_del(&vlan.name).await;
        }
        let Some(parent) = self.link_by_name(&vlan.parent) else {
            // Pending: the parent is not in the kernel yet.
            return;
        };
        self.fib_handle
            .vlan_add(&vlan.name, parent.index, vlan.vlan_id)
            .await;
    }

    pub async fn link_delete(&mut self, oslink: FibLink) {
        // Unregister via the VNI we resolved when the link was added
        // (config-sourced for `external vnifilter` devices, whose kernel
        // `IFLA_VXLAN_ID` is 0). Fall back to the netlink value for a
        // plain fixed-`id` VXLAN.
        let del_vni = self
            .links
            .get(&oslink.index)
            .and_then(|l| l.vni)
            .filter(|v| *v != 0)
            .or(oslink.vni);
        if let Some(vni) = del_vni {
            self.fib_handle.unregister_vxlan_ifindex(vni);
            self.api_vxlan_del(vni);
            // Withdraw the VNI binding from the cradle eBPF data plane
            // (no-op for an SRv6 device / when cradle is off).
            self.fib_handle.cradle_vni_unregister(vni).await;
        }
        // Notify subscribers BEFORE removing the link entry, so the
        // VRF lookup in `api_link_del` still resolves to the right
        // subscribers instead of falling through to default VRF.
        self.api_link_del(oslink.index);
        let master = self.links.get(&oslink.index).and_then(|l| l.master);
        self.links.remove(&oslink.index);
        // Re-publish AFTER the removal so the surviving ports are read
        // against a table this link is already out of: deleting the
        // bridge's VXLAN is exactly how they lose an EVI, and reading
        // first would report the set that just stopped being true. The
        // deleted link is published as well, since its own membership is
        // now empty.
        self.publish_l2_evis([master], oslink.index);
    }

    /// Publish [`RibRx::L2PortEvis`] for `port` and for every port of
    /// `bridges`, re-read from the current link table.
    ///
    /// Deliberately unconditional: the snapshot is idempotent, so
    /// re-sending an unchanged set costs a message and nothing else,
    /// whereas tracking what was last sent per port would be a cache to
    /// keep coherent with the kernel. Subscribers compare against what
    /// they hold, which they must do regardless.
    fn publish_l2_evis(&self, bridges: impl IntoIterator<Item = Option<u32>>, port: u32) {
        let mut ports: BTreeSet<u32> = BTreeSet::new();
        ports.insert(port);
        for bridge in bridges.into_iter().flatten() {
            ports.extend(bridge_ports(&self.links, bridge));
        }
        for port in ports {
            if port == 0 {
                continue;
            }
            self.api_l2_port_evis(port, port_evis(&self.links, port));
        }
    }

    pub fn link_name(&self, link_index: u32) -> String {
        match self.links.get(&link_index) {
            Some(link) => link.name.clone(),
            None => String::from("unknown"),
        }
    }

    pub fn link_by_name(&self, link_name: &str) -> Option<&Link> {
        self.links
            .iter()
            .find_map(|(_, v)| if v.name == link_name { Some(v) } else { None })
    }

    pub fn link_comps(&self) -> Vec<String> {
        self.links.values().map(|link| link.name.clone()).collect()
    }

    /// Completion candidates for the `rib:vrf` dynamic key — the names
    /// of the VRFs currently applied (one per kernel master device).
    pub fn vrf_comps(&self) -> Vec<String> {
        self.vrfs.keys().cloned().collect()
    }

    /// Completion candidates for the `rib:bridge` dynamic key — the
    /// names of the bridges currently configured (the eligible master
    /// devices for `interface <name> master <bridge>`).
    pub fn bridge_comps(&self) -> Vec<String> {
        self.bridges.keys().cloned().collect()
    }

    /// Add an IPv4 or IPv6 address to an interface link.
    ///
    /// This function validates the address before adding it to prevent invalid configurations:
    /// - Rejects addresses with zero prefix length (/0)
    /// - Rejects 0.0.0.0 as an interface address for IPv4
    ///
    /// # Arguments
    /// * `osaddr` - The FIB address containing the IP address, prefix length, and interface index
    /// * `from_config` - true when the address originates from `link_config_exec`
    ///   (i.e. the user configured it through the configuration manager). Sets
    ///   `LinkAddr::config = true` so we can distinguish configured addresses
    ///   from kernel-only addresses (e.g. SLAAC, manual `ip addr add`) and
    ///   recover them across link bounces.
    pub fn addr_add(&mut self, osaddr: FibAddr, from_config: bool) {
        // Validate against zero prefix length - prevents default route addresses on interfaces
        if osaddr.addr.prefix_len() == 0 {
            println!("FIB: zero prefixlen addr!");
            return;
        }

        // Validate against 0.0.0.0 address for IPv4 - prevents unspecified address on interfaces
        if let ipnet::IpNet::V4(v4_net) = osaddr.addr
            && v4_net.addr().is_unspecified()
        {
            println!("FIB: cannot add 0.0.0.0 as interface address");
            return;
        }

        let mut addr = LinkAddr::from(osaddr);
        if from_config {
            addr.config = true;
            // Our own RTM_NEWADDR never echoes back, so mirror the scope
            // the kernel will assign. Flags and lifetimes stay at their
            // defaults — the kernel's own follow-up notification (DAD
            // completion) delivers the truth and link_addr_update adopts
            // it without disturbing the config state.
            addr.scope = AddrScope::derive(&addr.addr);
        }
        if let Some(link) = self.links.get_mut(&addr.ifindex) {
            // Our own RTM_NEWADDR never echoes back (the kernel excludes
            // the originating socket from the RTNLGRP broadcast), so the
            // config path computes the kernel's secondary verdict locally.
            if from_config && let IpNet::V4(v4) = addr.addr {
                addr.secondary = v4_secondary_verdict(link, v4);
            }
            let update = link_addr_update(link, addr.clone());

            // Install the connected route only for the first address that
            // covers the prefix — a sibling address in the same subnet
            // already brought the route up (kernel prefix-route refcount
            // semantics). The interface must be up; link_up replays the
            // connected routes for addresses learned while it was down.
            if update == AddrUpdate::Added && link.is_up() {
                let bucket = if addr.is_v4() {
                    &link.addr4
                } else {
                    &link.addr6
                };
                if !prefix_covered_by_other(bucket, &addr) {
                    match addr.addr {
                        IpNet::V4(v4_addr) => {
                            let prefix = v4_addr.apply_mask();
                            let mut rib = RibEntry::new(RibType::Connected);
                            rib.ifindex = addr.ifindex;
                            rib.set_valid(true);
                            let msg = Message::Ipv4Add { prefix, rib };
                            let _ = self.tx.send(msg);
                        }
                        IpNet::V6(v6_addr) => {
                            let prefix = v6_addr.apply_mask();
                            let mut rib = RibEntry::new(RibType::Connected);
                            rib.ifindex = addr.ifindex;
                            rib.set_valid(true);
                            let msg = Message::Ipv6Add { prefix, rib };
                            let _ = self.tx.send(msg);
                        }
                    }
                }
            }
            // Don't re-broadcast a notification that changed nothing (the
            // kernel echoing an address we already hold, a lifetime-only
            // renewal). Added / Merged / Refreshed all carry state a
            // subscriber can act on; every AddrAdd-fed registry is
            // idempotent against re-delivery of a known address.
            if matches!(
                update,
                AddrUpdate::Added | AddrUpdate::Merged | AddrUpdate::Refreshed
            ) {
                // Broadcast the merged entry, not the raw incoming addr —
                // a config push landing on a kernel-known address must
                // not advertise default kernel metadata over the state
                // netlink already delivered.
                let bucket = if addr.is_v4() {
                    &link.addr4
                } else {
                    &link.addr6
                };
                let canonical = bucket
                    .iter()
                    .find(|a| a.addr == addr.addr)
                    .cloned()
                    .unwrap_or(addr);
                self.api_addr_add(&canonical);
            }
        }
    }

    pub fn addr_del(&mut self, osaddr: FibAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.ifindex) {
            // Ignore a DelAddr for an address we don't hold — the kernel's
            // echo of a config-driven delete, or a repeated notification.
            // Acting on it would tear down the connected route and
            // re-broadcast the removal to every protocol client.
            if link_addr_del(link, addr.clone()).is_none() {
                return;
            }

            // Withdraw the connected route only when the last address
            // covering the prefix went away — a remaining sibling in the
            // same subnet keeps the route alive (kernel prefix-route
            // refcount semantics).
            if link.is_up() {
                let bucket = if addr.is_v4() {
                    &link.addr4
                } else {
                    &link.addr6
                };
                if !prefix_covered_by_other(bucket, &addr) {
                    match addr.addr {
                        IpNet::V4(v4_addr) => {
                            let prefix = v4_addr.apply_mask();
                            let mut rib = RibEntry::new(RibType::Connected);
                            rib.ifindex = addr.ifindex;
                            let msg = Message::Ipv4Del { prefix, rib };
                            let _ = self.tx.send(msg);
                        }
                        IpNet::V6(v6_addr) => {
                            let prefix = v6_addr.apply_mask();
                            let mut rib = RibEntry::new(RibType::Connected);
                            rib.ifindex = addr.ifindex;
                            let msg = Message::Ipv6Del { prefix, rib };
                            let _ = self.tx.send(msg);
                        }
                    }
                }
            }

            self.api_addr_del(&addr);
        }
    }
}

pub struct LinkConfig {}

impl LinkConfig {
    pub fn new() -> Self {
        LinkConfig {}
    }

    pub fn commit(&mut self, _tx: UnboundedSender<Message>) {
        //
    }
}

/// Configure interface IPv4 and IPv6 addresses with validation.
///
/// This function handles configuration of both IPv4 and IPv6 addresses on interfaces with validation:
///
/// **IPv4 validation:**
/// - Rejects 0.0.0.0 as an interface address
/// - Rejects addresses with zero prefix length (/0)
///
/// **IPv6 validation:**
/// - Rejects ::0 as an interface address
/// - Rejects addresses with zero prefix length (/0)
/// - Rejects loopback addresses (::1) on non-loopback interfaces
///
/// # Arguments
/// * `rib` - Mutable reference to the RIB instance
/// * `path` - Configuration path (e.g., "/interface/ipv4/address" or "/interface/ipv6/address")
/// * `args` - Command arguments containing interface name and address
/// * `op` - Configuration operation (set/delete)
// Temporary func
pub async fn link_config_exec(
    rib: &mut Rib,
    path: String,
    mut args: Args,
    op: ConfigOp,
) -> Result<()> {
    const LINK_ERR: &str = "missing interface name";
    const IPV4_ADDR_ERR: &str = "missing ipv4 address";
    const IPV6_ADDR_ERR: &str = "missing ipv6 address";

    let ifname = args.string().context(LINK_ERR)?;

    // let func = self.builder.map.get()
    if path == "/interface/ipv4/address" {
        // `address` is a leaf-list: each commit line carries one value,
        // but drain the deque so a bundled delivery would not silently
        // drop trailing values.
        //
        // `dhcp` is the feature-gated enum arm of the address union
        // (present only under `--feature iso`). The daemon-side DHCP
        // client is not implemented yet, so the value is accepted
        // without kernel action — and it must be consumed here: an
        // unparsed value left in the deque would read as the
        // value-less delete form below, which removes every
        // configured address on the interface.
        let mut dhcp = false;
        let mut values: Vec<Ipv4Net> = Vec::new();
        while let Some(value) = args.string() {
            if value == "dhcp" {
                dhcp = true;
            } else if let Ok(v4addr) = value.parse::<Ipv4Net>() {
                values.push(v4addr);
            }
        }
        if dhcp && values.is_empty() {
            return Ok(());
        }

        if op.is_set() {
            if values.is_empty() {
                return Err(anyhow::anyhow!(IPV4_ADDR_ERR));
            }
            for v4addr in values {
                // Validate against 0.0.0.0 address
                if v4addr.addr().is_unspecified() {
                    println!("Cannot configure 0.0.0.0 as interface address");
                    continue;
                }

                // Validate against zero prefix length
                if v4addr.prefix_len() == 0 {
                    println!("Cannot configure address with zero prefix length");
                    continue;
                }

                if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                    // If the address is already present (configured earlier or
                    // learned from the kernel), just mark it configured: the
                    // kernel add would EEXIST, and adopting a kernel-learned
                    // address lets a later config delete remove it.
                    if let Some(link) = rib.links.get_mut(&ifindex)
                        && let Some(existing) =
                            link.addr4.iter_mut().find(|a| a.addr == IpNet::V4(v4addr))
                    {
                        existing.config = true;
                        continue;
                    }

                    let result = rib.fib_handle.addr_add_ipv4(ifindex, &v4addr).await;
                    match result {
                        Ok(_) => {
                            let addr = FibAddr {
                                addr: ipnet::IpNet::V4(v4addr),
                                link_index: ifindex,
                                secondary: false,
                                ..Default::default()
                            };
                            rib.addr_add(addr, true);
                        }
                        Err(_) => {
                            println!("IPaddress add failure");
                        }
                    }
                }
            }
        } else {
            // Handle IPv4 address deletion. A value-less delete
            // (`delete interface X ipv4 address`) removes every
            // configured address on the interface.
            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                if values.is_empty()
                    && let Some(link) = rib.links.get(&ifindex)
                {
                    values = link
                        .addr4
                        .iter()
                        .filter(|a| a.config)
                        .filter_map(|a| match a.addr {
                            IpNet::V4(v4) => Some(v4),
                            IpNet::V6(_) => None,
                        })
                        .collect();
                }
                for v4addr in values {
                    // Clear `config` on the existing LinkAddr so addr_del
                    // below removes the entry instead of keeping it as a
                    // recovery candidate. Read the primary verdict first:
                    // deleting a primary triggers the kernel's purge cascade
                    // on its same-subnet secondaries.
                    let mut was_primary = false;
                    if let Some(link) = rib.links.get_mut(&ifindex) {
                        let target = IpNet::V4(v4addr);
                        if let Some(existing) = link.addr4.iter_mut().find(|a| a.addr == target) {
                            was_primary = !existing.secondary;
                            existing.config = false;
                        }
                    }
                    rib.fib_handle.addr_del_ipv4(ifindex, &v4addr).await;
                    let addr = FibAddr {
                        addr: ipnet::IpNet::V4(v4addr),
                        link_index: ifindex,
                        secondary: false,
                        ..Default::default()
                    };
                    rib.addr_del(addr);

                    if !was_primary {
                        continue;
                    }
                    // Kernel cascade mirror: deleting a primary also purged
                    // its same-subnet secondaries in the kernel
                    // (promote_secondaries=0 is the default), and none of it
                    // is visible here — the kernel excludes the originating
                    // socket from the RTNLGRP broadcast. Drop kernel-only
                    // siblings to match, and re-install configured ones so
                    // deleting the primary doesn't silently take them down.
                    // The re-add tolerates EEXIST for hosts running
                    // promote_secondaries=1, where the kernel promoted the
                    // first secondary instead of purging.
                    let siblings: Vec<(Ipv4Net, bool)> = rib
                        .links
                        .get(&ifindex)
                        .map(|link| {
                            link.addr4
                                .iter()
                                .filter_map(|a| match a.addr {
                                    IpNet::V4(ev)
                                        if ev.prefix_len() == v4addr.prefix_len()
                                            && ev.network() == v4addr.network() =>
                                    {
                                        Some((ev, a.config))
                                    }
                                    _ => None,
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    for (sib, config) in siblings {
                        let fib_sib = FibAddr {
                            addr: IpNet::V4(sib),
                            link_index: ifindex,
                            secondary: false,
                            ..Default::default()
                        };
                        if config {
                            let _ = rib.fib_handle.addr_add_ipv4(ifindex, &sib).await;
                            rib.addr_add(fib_sib, true);
                        } else {
                            rib.addr_del(fib_sib);
                        }
                    }
                }
            }
        }
        // Config-driven address changes produce no netlink self-echo
        // (the FibMessage::NewAddr/DelAddr path never runs for them),
        // so recompute the auto router-id here.
        rib.router_id_update();
    } else if path == "/interface/ipv6/address" {
        // `address` is a leaf-list: one callback can carry several
        // addresses (config-file load, multi-value commit), so drain the
        // args deque and apply each value independently — reading a
        // single value would silently drop the rest.
        let first = args.v6net().context(IPV6_ADDR_ERR)?;
        let mut v6addrs = vec![first];
        while let Some(more) = args.v6net() {
            v6addrs.push(more);
        }

        let Some(ifindex) = link_lookup(rib, ifname.to_string()) else {
            println!("Interface {} not found", ifname);
            return Ok(());
        };

        if op.is_set() {
            for v6addr in v6addrs {
                // Validate against ::0 address
                if v6addr.addr().is_unspecified() {
                    println!("Cannot configure ::0 as interface address");
                    continue;
                }

                // Validate against zero prefix length
                if v6addr.prefix_len() == 0 {
                    println!("Cannot configure address with zero prefix length");
                    continue;
                }

                // Validate against loopback address on non-loopback interfaces
                if v6addr.addr().is_loopback()
                    && rib
                        .links
                        .get(&ifindex)
                        .is_some_and(|link| !link.is_loopback())
                {
                    println!("Cannot configure loopback address on non-loopback interface");
                    continue;
                }

                // Skip an address already present on the link (config replay
                // or kernel echo already delivered it).
                if rib
                    .links
                    .get(&ifindex)
                    .is_some_and(|link| link.addr6.iter().any(|a| a.addr == IpNet::V6(v6addr)))
                {
                    continue;
                }

                let result = rib.fib_handle.addr_add_ipv6(ifindex, &v6addr).await;
                match result {
                    Ok(_) => {
                        let addr = FibAddr {
                            addr: ipnet::IpNet::V6(v6addr),
                            link_index: ifindex,
                            secondary: false,
                            ..Default::default()
                        };
                        rib.addr_add(addr, true);
                    }
                    Err(_) => {
                        println!("IPv6 address add failure");
                    }
                }
            }
        } else {
            for v6addr in v6addrs {
                // Clear `config` on the existing LinkAddr so the kernel's
                // subsequent DelAddr notification removes the entry instead
                // of keeping it as a recovery candidate.
                if let Some(link) = rib.links.get_mut(&ifindex) {
                    let target = IpNet::V6(v6addr);
                    if let Some(existing) = link.addr6.iter_mut().find(|a| a.addr == target) {
                        existing.config = false;
                    }
                }
                rib.fib_handle.addr_del_ipv6(ifindex, &v6addr).await;
                let addr = FibAddr {
                    addr: ipnet::IpNet::V6(v6addr),
                    link_index: ifindex,
                    secondary: false,
                    ..Default::default()
                };
                rib.addr_del(addr);
            }
        }
    } else if path == "/interface/vrf" {
        // `set interface X vrf Y`   → enslave X to VRF master Y.
        // `delete interface X vrf [Y]` → unbind X from whatever VRF it
        // currently sits in. The optional Y on delete is ignored: the
        // intent is unambiguous and we want to tolerate either form.
        let vrf = if op.is_set() {
            Some(args.string().context("missing vrf name")?)
        } else {
            // Drain any trailing token so it isn't picked up later.
            let _ = args.string();
            None
        };
        let _ = rib.tx.send(Message::LinkVrfBind { ifname, vrf });
    } else if path == "/interface/bridge" {
        // `set interface X bridge BR`   → enslave X to bridge master BR.
        // `delete interface X bridge [BR]` → detach X from its bridge.
        // The optional name on delete is ignored: the intent is
        // unambiguous and we tolerate either form (mirrors `vrf`).
        let bridge = if op.is_set() {
            Some(args.string().context("missing bridge name")?)
        } else {
            // Drain any trailing token so it isn't picked up later.
            let _ = args.string();
            None
        };
        let _ = rib.tx.send(Message::LinkBridgeBind { ifname, bridge });
    } else if path == "/interface/mtu" {
        // `set interface X mtu N`    → record desired MTU and apply it.
        // `delete interface X mtu`   → drop the desired MTU and restore
        // the per-type kernel default (65536 loopback / 1500 otherwise).
        //
        // The configured value is durable desired-state in
        // `rib.mtu_config` (keyed by name) so it survives the interface
        // disappearing and is replayed by `link_add` when it returns.
        // We only *issue* the netlink set here; the kernel's echoed
        // RTM_NEWLINK updates the cached `Link::mtu` (and fans the
        // change out to protocols) via `link_add`. A rejected set
        // produces no echo, so we capture the reason in `Link::mtu_error`
        // for `show interface`.
        if op.is_set() {
            let mtu = args.u32().context("missing mtu value")?;
            rib.mtu_config.insert(ifname.clone(), mtu);
            if let Some(ifindex) = link_lookup(rib, ifname.clone()) {
                match rib.fib_handle.link_set_mtu(ifindex, mtu).await {
                    Ok(()) => {
                        if let Some(link) = rib.links.get_mut(&ifindex) {
                            link.mtu_error = None;
                        }
                    }
                    Err(e) => {
                        if let Some(link) = rib.links.get_mut(&ifindex) {
                            link.mtu_error = Some(format!("MTU set to {mtu} is failed due to {e}"));
                        }
                        tracing::warn!("link_set_mtu({ifname}, {mtu}) failed: {e}");
                    }
                }
            }
        } else {
            // Drain a trailing value token if the delete carried one.
            let _ = args.u32();
            rib.mtu_config.remove(&ifname);
            if let Some(ifindex) = link_lookup(rib, ifname.clone()) {
                // Restore the MTU the kernel reported when we first
                // observed this link, before any operator MTU was
                // applied (see `Link::original_mtu`).
                let original = rib.links.get(&ifindex).map(|l| l.original_mtu);
                if let Some(original) = original {
                    match rib.fib_handle.link_set_mtu(ifindex, original).await {
                        Ok(()) => {
                            if let Some(link) = rib.links.get_mut(&ifindex) {
                                link.mtu_error = None;
                            }
                        }
                        Err(e) => {
                            if let Some(link) = rib.links.get_mut(&ifindex) {
                                link.mtu_error =
                                    Some(format!("MTU set to {original} is failed due to {e}"));
                            }
                            tracing::warn!("link_set_mtu({ifname}, {original}) failed: {e}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn link_lookup(rib: &Rib, name: String) -> Option<u32> {
    for link in rib.links.values() {
        if link.name == name {
            return Some(link.index);
        }
    }

    None
}

/// Resolve the VRF a link is enslaved to, by matching `link.master`
/// against the ifindex of each known VRF master device. Returns
/// `Some(name)` if the link is in a configured VRF, `None` for the
/// default VRF or for slaves of non-VRF masters (e.g. bridges).
pub fn link_vrf_name<'a>(rib: &'a Rib, link: &Link) -> Option<&'a str> {
    let master = link.master?;
    rib.vrfs
        .values()
        .find(|v| v.ifindex == master)
        .map(|v| v.name.as_str())
}

/// The hardware address to fan out after reconciling an already-known
/// link, if any: the address now cached, when it is present and differs
/// from what was cached before. `None` means nothing changed that a
/// subscriber could act on — including a cache that went from an
/// address to none, which the adopt-if-present rule in [`Rib::link_add`]
/// never produces but which would carry nothing to announce anyway.
pub fn link_mac_delta(prev: Option<MacAddr>, now: Option<MacAddr>) -> Option<MacAddr> {
    match now {
        Some(mac) if prev != Some(mac) => Some(mac),
        _ => None,
    }
}

#[cfg(test)]
mod link_mac_delta_tests {
    use super::*;

    fn mac(last: u8) -> MacAddr {
        MacAddr::from([0x02, 0, 0, 0, 0, last])
    }

    /// The bridge case: the address the link was created with gives
    /// way to one recomputed from its port set.
    #[test]
    fn changed_address_is_announced() {
        assert_eq!(link_mac_delta(Some(mac(1)), Some(mac(2))), Some(mac(2)));
    }

    /// Every other RTM_NEWLINK on the link (flag flips, MTU, master)
    /// re-reports the same address; that must not fan out.
    #[test]
    fn unchanged_address_is_silent() {
        assert_eq!(link_mac_delta(Some(mac(1)), Some(mac(1))), None);
    }

    /// A link known without an address that gains one (not something
    /// the kernel does, but the honest answer is to announce it).
    #[test]
    fn first_address_is_announced() {
        assert_eq!(link_mac_delta(None, Some(mac(1))), Some(mac(1)));
    }

    /// Nothing cached now means nothing to announce, whatever was
    /// cached before.
    #[test]
    fn absent_address_is_silent() {
        assert_eq!(link_mac_delta(Some(mac(1)), None), None);
        assert_eq!(link_mac_delta(None, None), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fib::message::FibAddr;
    use ipnet::{IpNet, Ipv4Net};
    use std::net::Ipv4Addr;

    #[test]
    fn test_zero_address_validation() {
        // Test validation logic for 0.0.0.0 address
        let zero_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 24).unwrap()),
            link_index: 1,
            secondary: false,
            ..Default::default()
        };

        // Check that 0.0.0.0 is correctly identified as unspecified
        if let IpNet::V4(v4_net) = zero_addr.addr {
            assert!(
                v4_net.addr().is_unspecified(),
                "0.0.0.0 should be identified as unspecified"
            );
        }
    }

    #[test]
    fn test_zero_prefix_length_validation() {
        // Test validation logic for zero prefix length
        let zero_prefix_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 0).unwrap()),
            link_index: 1,
            secondary: false,
            ..Default::default()
        };

        assert_eq!(
            zero_prefix_addr.addr.prefix_len(),
            0,
            "Prefix length should be 0"
        );
    }

    #[test]
    fn test_valid_address_validation() {
        // Test validation logic for valid address
        let valid_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
            link_index: 1,
            secondary: false,
            ..Default::default()
        };

        // Should pass both validations
        assert_ne!(
            valid_addr.addr.prefix_len(),
            0,
            "Valid address should have non-zero prefix"
        );

        if let IpNet::V4(v4_net) = valid_addr.addr {
            assert!(
                !v4_net.addr().is_unspecified(),
                "Valid address should not be 0.0.0.0"
            );
        }
    }

    fn test_link() -> Link {
        Link {
            index: 1,
            name: "test0".to_string(),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: LinkFlags::empty(),
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: None,
            vni: None,
            vrf_table: None,
            bridge: false,
            vxlan_local: None,
            parent: None,
            vlan_id: None,
            mtu_error: None,
        }
    }

    fn test_addr_v4(addr: Ipv4Addr, prefix_len: u8, config: bool, fib: bool) -> LinkAddr {
        LinkAddr {
            addr: IpNet::V4(Ipv4Net::new(addr, prefix_len).unwrap()),
            ifindex: 1,
            secondary: false,
            config,
            fib,
            ..Default::default()
        }
    }

    #[test]
    fn test_link_addr_update() {
        let mut link = test_link();
        let addr = test_addr_v4(Ipv4Addr::new(192, 168, 1, 1), 24, true, true);

        // Test adding a new address
        let result = link_addr_update(&mut link, addr.clone());
        assert_eq!(result, AddrUpdate::Added);
        assert_eq!(link.addr4.len(), 1, "Link should have 1 IPv4 address");

        // A duplicate add changes nothing and does not duplicate the entry.
        let result = link_addr_update(&mut link, addr);
        assert_eq!(result, AddrUpdate::Unchanged);
        assert_eq!(link.addr4.len(), 1, "Link should still have 1 IPv4 address");
    }

    #[test]
    fn test_link_addr_update_merges_flags() {
        let mut link = test_link();
        // Configured first, fib not yet confirmed.
        let cfg = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, true, false);
        link_addr_update(&mut link, cfg);
        assert!(link.addr4[0].config && !link.addr4[0].fib);

        // Kernel netlink confirmation arrives — should flip fib true on the
        // existing entry, not create a duplicate.
        let kernel = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true);
        let result = link_addr_update(&mut link, kernel.clone());
        assert_eq!(result, AddrUpdate::Merged, "flag flip reports Merged");
        assert_eq!(link.addr4.len(), 1);
        assert!(link.addr4[0].config && link.addr4[0].fib);

        // A second identical kernel notification changes nothing.
        let result = link_addr_update(&mut link, kernel);
        assert_eq!(result, AddrUpdate::Unchanged);
        assert_eq!(link.addr4.len(), 1);
    }

    #[test]
    fn test_link_addr_update_merge_adopts_secondary() {
        let mut link = test_link();
        let cfg = test_addr_v4(Ipv4Addr::new(10, 0, 0, 2), 24, true, true);
        link_addr_update(&mut link, cfg);
        assert!(!link.addr4[0].secondary);

        // A kernel event carrying IFA_F_SECONDARY (external add observed
        // via netlink) updates the merged entry — and counts as a state
        // change, so it is re-broadcast.
        let mut kernel = test_addr_v4(Ipv4Addr::new(10, 0, 0, 2), 24, false, true);
        kernel.secondary = true;
        assert_eq!(link_addr_update(&mut link, kernel), AddrUpdate::Merged);
        assert_eq!(link.addr4.len(), 1);
        assert!(link.addr4[0].secondary && link.addr4[0].config);

        // Promotion: the kernel re-announces the address without the
        // flag — the merge clears it again (Merged, not Unchanged).
        let promoted = test_addr_v4(Ipv4Addr::new(10, 0, 0, 2), 24, false, true);
        assert_eq!(link_addr_update(&mut link, promoted), AddrUpdate::Merged);
        assert!(!link.addr4[0].secondary);

        // Same flag again: nothing changed, nothing re-broadcast.
        let renotify = test_addr_v4(Ipv4Addr::new(10, 0, 0, 2), 24, false, true);
        assert_eq!(link_addr_update(&mut link, renotify), AddrUpdate::Unchanged);
    }

    #[test]
    fn test_link_addr_update_dad_completion_is_refreshed() {
        let mut link = test_link();
        // Kernel announces a fresh static v6 address: tentative while
        // DAD runs.
        let mut tentative = test_addr_v6("2001:db8::1/64", false, true);
        tentative.flags.tentative = true;
        tentative.flags.permanent = true;
        assert_eq!(link_addr_update(&mut link, tentative), AddrUpdate::Added);

        // DAD completes: the kernel resends RTM_NEWADDR with tentative
        // cleared. That is a metadata update of the entry we hold — not
        // a duplicate add, and (for now) not a client re-broadcast.
        let mut done = test_addr_v6("2001:db8::1/64", false, true);
        done.flags.permanent = true;
        assert_eq!(link_addr_update(&mut link, done), AddrUpdate::Refreshed);
        assert_eq!(link.addr6.len(), 1);
        assert!(!link.addr6[0].flags.tentative);
        assert!(link.addr6[0].flags.permanent);

        // The same announcement again changes nothing.
        let mut again = test_addr_v6("2001:db8::1/64", false, true);
        again.flags.permanent = true;
        assert_eq!(link_addr_update(&mut link, again), AddrUpdate::Unchanged);
    }

    #[test]
    fn test_link_addr_update_lifetime_renewal_is_silent() {
        let mut link = test_link();
        let mut slaac = test_addr_v6("2001:db8::5054:ff:fe00:1/64", false, true);
        slaac.valid_lft = Some(86400);
        slaac.preferred_lft = Some(14400);
        assert_eq!(link_addr_update(&mut link, slaac), AddrUpdate::Added);

        // Each RA renews the lifetimes; the stored entry follows but
        // protocol clients are NOT re-notified — Unchanged, not
        // Refreshed, or IS-IS would re-originate LSPs per RA interval.
        let mut renewed = test_addr_v6("2001:db8::5054:ff:fe00:1/64", false, true);
        renewed.valid_lft = Some(86400);
        renewed.preferred_lft = Some(13000);
        assert_eq!(link_addr_update(&mut link, renewed), AddrUpdate::Unchanged);
        assert_eq!(link.addr6[0].preferred_lft, Some(13000));
    }

    #[test]
    fn test_link_addr_update_config_push_keeps_kernel_state() {
        let mut link = test_link();
        // Kernel-known SLAAC-style entry with live metadata.
        let mut kernel = test_addr_v6("2001:db8::1/64", false, true);
        kernel.scope = AddrScope::Universe;
        kernel.flags.permanent = true;
        kernel.valid_lft = Some(86400);
        kernel.preferred_lft = Some(14400);
        link_addr_update(&mut link, kernel);

        // The operator now configures the same address. The config push
        // carries default (unknown) kernel metadata — the merge must
        // flip `config` without wiping what netlink delivered.
        let mut cfg = test_addr_v6("2001:db8::1/64", true, true);
        cfg.scope = AddrScope::derive(&cfg.addr);
        assert_eq!(link_addr_update(&mut link, cfg), AddrUpdate::Merged);
        assert!(link.addr6[0].config);
        assert!(link.addr6[0].flags.permanent, "kernel flags survive");
        assert_eq!(link.addr6[0].valid_lft, Some(86400));
        assert_eq!(link.addr6[0].preferred_lft, Some(14400));
    }

    #[test]
    fn test_addr_scope_derive_mirrors_kernel() {
        let global: IpNet = "2001:db8::1/64".parse().unwrap();
        let ll: IpNet = "fe80::1/64".parse().unwrap();
        let lo6: IpNet = "::1/128".parse().unwrap();
        let v4: IpNet = "10.0.0.1/24".parse().unwrap();
        let lo4: IpNet = "127.0.0.1/8".parse().unwrap();
        assert_eq!(AddrScope::derive(&global), AddrScope::Universe);
        assert_eq!(AddrScope::derive(&ll), AddrScope::Link);
        assert_eq!(AddrScope::derive(&lo6), AddrScope::Host);
        assert_eq!(AddrScope::derive(&v4), AddrScope::Universe);
        assert_eq!(AddrScope::derive(&lo4), AddrScope::Host);
    }

    #[test]
    fn test_v4_secondary_verdict_mirrors_kernel() {
        let mut link = test_link();
        let primary: Ipv4Net = "10.0.0.1/24".parse().unwrap();
        let same_subnet: Ipv4Net = "10.0.0.2/24".parse().unwrap();
        let other_mask: Ipv4Net = "10.0.0.3/25".parse().unwrap();
        let other_subnet: Ipv4Net = "10.1.0.1/24".parse().unwrap();

        // Empty link: first address is primary.
        assert!(!v4_secondary_verdict(&link, primary));
        link_addr_update(
            &mut link,
            test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, true, true),
        );

        // Same mask + same network as an installed primary → secondary.
        assert!(v4_secondary_verdict(&link, same_subnet));
        // A different prefix length is a different subnet to the kernel,
        // even though it overlaps.
        assert!(!v4_secondary_verdict(&link, other_mask));
        // Distinct subnet → its own primary.
        assert!(!v4_secondary_verdict(&link, other_subnet));
        // Re-evaluating the installed address itself is not "another"
        // primary (self is excluded).
        assert!(!v4_secondary_verdict(&link, primary));

        // A primary that is configured but not installed (fib=false,
        // e.g. link down) does not make the newcomer secondary.
        let mut down_link = test_link();
        link_addr_update(
            &mut down_link,
            test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, true, false),
        );
        assert!(!v4_secondary_verdict(&down_link, same_subnet));
    }

    #[test]
    fn test_link_addr_del_keeps_configured_entry() {
        let mut link = test_link();
        link_addr_update(
            &mut link,
            test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, true, true),
        );
        // Kernel removed the address (e.g. interface down + IPv6 flush style).
        let kernel_del = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true);
        let result = link_addr_del(&mut link, kernel_del.clone());
        assert!(result.is_some());
        assert_eq!(link.addr4.len(), 1, "config=true entry kept");
        assert!(link.addr4[0].config);
        assert!(!link.addr4[0].fib, "fib flipped to false");

        // A repeated DelAddr for the same kept entry changes nothing and
        // must report None so callers don't re-broadcast the removal.
        let result = link_addr_del(&mut link, kernel_del);
        assert!(result.is_none(), "repeated delete is a no-op");
        assert_eq!(link.addr4.len(), 1);
    }

    fn test_addr_v6(addr: &str, config: bool, fib: bool) -> LinkAddr {
        LinkAddr {
            addr: addr.parse().unwrap(),
            ifindex: 1,
            secondary: false,
            config,
            fib,
            ..Default::default()
        }
    }

    #[test]
    fn test_prefix_covered_by_other_v4() {
        let a = test_addr_v4(Ipv4Addr::new(192, 168, 1, 1), 24, false, true);
        let b = test_addr_v4(Ipv4Addr::new(192, 168, 1, 2), 24, false, true);
        let other_net = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true);

        // A sibling in the same subnet covers the prefix; an address in a
        // different subnet does not; the address itself never counts.
        assert!(prefix_covered_by_other(&[a.clone(), b.clone()], &a));
        assert!(!prefix_covered_by_other(&[a.clone(), other_net], &a));
        assert!(!prefix_covered_by_other(std::slice::from_ref(&a), &a));

        // A sibling the kernel no longer holds (fib=false recovery
        // candidate) does not keep the connected route alive.
        let mut b_gone = b;
        b_gone.fib = false;
        b_gone.config = true;
        assert!(!prefix_covered_by_other(&[a.clone(), b_gone], &a));
    }

    #[test]
    fn test_prefix_covered_by_other_v6() {
        let a = test_addr_v6("2001:db8:1::1/64", false, true);
        let b = test_addr_v6("2001:db8:1::2/64", false, true);
        let other_net = test_addr_v6("2001:db8:2::1/64", false, true);

        assert!(prefix_covered_by_other(&[a.clone(), b], &a));
        assert!(!prefix_covered_by_other(&[a.clone(), other_net], &a));
    }

    #[test]
    fn test_link_addr_del_removes_kernel_only_entry() {
        let mut link = test_link();
        link_addr_update(
            &mut link,
            test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true),
        );
        let kernel_del = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true);
        let result = link_addr_del(&mut link, kernel_del);
        assert!(result.is_some());
        assert_eq!(link.addr4.len(), 0, "kernel-only entry removed");
    }

    #[test]
    fn test_link_addr_del_legacy() {
        let mut link = test_link();
        let addr1 = test_addr_v4(Ipv4Addr::new(192, 168, 1, 1), 24, false, true);
        let addr2 = test_addr_v4(Ipv4Addr::new(192, 168, 1, 2), 24, false, true);

        // Add two addresses
        link_addr_update(&mut link, addr1.clone());
        link_addr_update(&mut link, addr2.clone());
        assert_eq!(link.addr4.len(), 2, "Link should have 2 IPv4 addresses");

        // Test deleting an existing address
        let result = link_addr_del(&mut link, addr1.clone());
        assert!(result.is_some(), "Deleting existing address should succeed");
        assert_eq!(
            link.addr4.len(),
            1,
            "Link should have 1 IPv4 address after deletion"
        );

        // Test deleting non-existent address
        let result = link_addr_del(&mut link, addr1);
        assert!(
            result.is_none(),
            "Deleting non-existent address should fail"
        );
        assert_eq!(link.addr4.len(), 1, "Link should still have 1 IPv4 address");

        // Delete the remaining address
        let result = link_addr_del(&mut link, addr2);
        assert!(
            result.is_some(),
            "Deleting remaining address should succeed"
        );
        assert_eq!(link.addr4.len(), 0, "Link should have no IPv4 addresses");
    }
}

/// The L2VPN EVIs a bridge port participates in: the VNIs of the VXLAN
/// slaves sharing its bridge. Empty when the port is not enslaved, when
/// its bridge carries no VXLAN, or when `port` is 0 — index 0 is "no
/// port" and must never resolve to whichever link happens to sit there.
///
/// A VXLAN slave is itself a bridge port, so it reports the VNI it
/// carries; that is consistent rather than special-cased.
///
/// Pure over the link table so the bridge walk is testable without a
/// live `Rib` — it is the whole basis of `RibRx::L2PortEvis`.
pub fn port_evis(links: &BTreeMap<u32, Link>, port: u32) -> BTreeSet<u32> {
    if port == 0 {
        return BTreeSet::new();
    }
    let Some(bridge) = links.get(&port).and_then(|link| link.master) else {
        return BTreeSet::new();
    };
    links
        .values()
        .filter(|link| link.master == Some(bridge))
        .filter_map(|link| link.vni)
        .collect()
}

/// Every port enslaved to `bridge`, including its VXLAN slaves. Used to
/// re-publish membership for a whole bridge when anything about it moves,
/// since one VXLAN change alters the EVI set of every port on it.
pub fn bridge_ports(links: &BTreeMap<u32, Link>, bridge: u32) -> Vec<u32> {
    if bridge == 0 {
        return Vec::new();
    }
    links
        .values()
        .filter(|link| link.master == Some(bridge))
        .map(|link| link.index)
        .collect()
}

#[cfg(test)]
mod l2_port_evi_tests {
    use super::*;

    fn link(index: u32, name: &str, master: Option<u32>, vni: Option<u32>) -> Link {
        Link {
            index,
            name: name.into(),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: LinkFlags::Up,
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master,
            vni,
            vxlan_local: None,
            vrf_table: None,
            bridge: master.is_none(),
            parent: None,
            vlan_id: None,
            mtu_error: None,
        }
    }

    fn table(links: Vec<Link>) -> BTreeMap<u32, Link> {
        links.into_iter().map(|l| (l.index, l)).collect()
    }

    /// The case aliasing needs: an access port shares a bridge with a
    /// VXLAN, so it participates in that VXLAN's EVI.
    #[test]
    fn access_port_inherits_its_bridges_vni() {
        let t = table(vec![
            link(10, "br10", None, None),
            link(11, "vxlan10", Some(10), Some(100)),
            link(12, "host0", Some(10), None),
        ]);
        assert_eq!(port_evis(&t, 12), BTreeSet::from([100]));
    }

    /// A VLAN-aware bridge can carry several VNIs; a port on it is in all
    /// of them, so the answer is a set rather than an Option.
    #[test]
    fn a_port_can_be_in_several_evis() {
        let t = table(vec![
            link(10, "br10", None, None),
            link(11, "vxlan10", Some(10), Some(100)),
            link(13, "vxlan20", Some(10), Some(200)),
            link(12, "host0", Some(10), None),
        ]);
        assert_eq!(port_evis(&t, 12), BTreeSet::from([100, 200]));
    }

    /// A port on a bridge with no VXLAN is in no EVI — it is plain L2,
    /// and advertising an A-D for it would attract traffic we cannot
    /// deliver.
    #[test]
    fn a_bridge_without_a_vxlan_yields_no_evi() {
        let t = table(vec![
            link(10, "br10", None, None),
            link(12, "host0", Some(10), None),
        ]);
        assert!(port_evis(&t, 12).is_empty());
    }

    /// An unenslaved port is in no EVI, and must not pick up the VNIs of
    /// some unrelated bridge.
    #[test]
    fn an_unenslaved_port_is_in_no_evi() {
        let t = table(vec![
            link(10, "br10", None, None),
            link(11, "vxlan10", Some(10), Some(100)),
            link(12, "host0", None, None),
        ]);
        assert!(port_evis(&t, 12).is_empty());
    }

    /// Ports of a different bridge must not leak in — the filter is on
    /// the master, not on "any VXLAN anywhere".
    #[test]
    fn a_second_bridges_vni_does_not_leak() {
        let t = table(vec![
            link(10, "br10", None, None),
            link(11, "vxlan10", Some(10), Some(100)),
            link(12, "host0", Some(10), None),
            link(20, "br20", None, None),
            link(21, "vxlan20", Some(20), Some(200)),
        ]);
        assert_eq!(port_evis(&t, 12), BTreeSet::from([100]));
    }

    /// Index 0 is "no port". Resolving it would hand every unattributed
    /// caller whichever link sits at index 0.
    #[test]
    fn port_zero_never_resolves() {
        let t = table(vec![
            link(0, "weird", Some(10), None),
            link(10, "br10", None, None),
            link(11, "vxlan10", Some(10), Some(100)),
        ]);
        assert!(port_evis(&t, 0).is_empty());
        assert!(bridge_ports(&t, 0).is_empty());
    }

    /// A VXLAN slave is a bridge port too and reports its own VNI, so a
    /// caller need not special-case it.
    #[test]
    fn a_vxlan_slave_reports_its_own_vni() {
        let t = table(vec![
            link(10, "br10", None, None),
            link(11, "vxlan10", Some(10), Some(100)),
        ]);
        assert_eq!(port_evis(&t, 11), BTreeSet::from([100]));
    }

    /// Re-publishing a bridge must cover every port on it: one VXLAN
    /// joining changes the EVI set of all of them at once.
    #[test]
    fn bridge_ports_lists_every_slave() {
        let t = table(vec![
            link(10, "br10", None, None),
            link(11, "vxlan10", Some(10), Some(100)),
            link(12, "host0", Some(10), None),
            link(21, "elsewhere", Some(20), None),
        ]);
        let mut ports = bridge_ports(&t, 10);
        ports.sort();
        assert_eq!(ports, vec![11, 12]);
    }
}
