//! The RA host (docs/design/dhcp-client.md §7).
//!
//! On an interface with `ipv6 address autoconf`, ND acts as a host as well
//! as a router: it sends Router Solicitations, and turns the Router
//! Advertisements it hears into a default route, on-link prefixes and SLAAC
//! addresses (RFC 4862). They go to the RIB like any protocol's: the routes
//! as `RibType::Ra` entries (shown `A`, installed as `proto ra`), the
//! addresses as dynamic addresses with kernel lifetimes. The kernel's own RA
//! processing stays off on these interfaces (`accept_ra=0`, D4), so it
//! installs nothing behind the RIB's back.
//!
//! Synchronous and free of I/O, like the rest of the engine: [`RaHosts`]
//! takes link, address and packet events with the time they happen, and
//! leaves what must be done in [`RaHosts::take_actions`] for the `Nd` task
//! to perform. Router Solicitations come out of [`RaHosts::solicit`] as
//! frames for the engine's socket.
//!
//! The RIB keeps one entry per protocol for a prefix, so routes are
//! gathered across interfaces before they are handed over, as the DHCP
//! client's are (`dhcpc/routes.rs`): for each prefix in each VRF, the
//! candidates at the lowest `ra-options default-route-distance` win, and
//! among default routers those of the best RA preference (RFC 4191).
//! Several left are ECMP.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv6Net};
use nd_packet::{
    LinkLayerAddress, NdOption, PrefixInfo, PrefixInfoFlags, RouterAdvert, RouterPreference,
    RouterSolicit,
};

use crate::fib::AddrOpts;
use crate::resolver::LinkDns;
use crate::rib::entry::RibEntry;
use crate::rib::link::AddrOrigin;
use crate::rib::{Message, Nexthop, NexthopMulti, NexthopUni, RibType};

use super::NdSend;
use super::send::{RngSource, ThreadRng};

/// Administrative distance of the RA host's routes when `ra-options
/// default-route-distance` is unset: the DHCP client's, above every
/// routing protocol's.
pub const DEFAULT_DISTANCE: u8 = 210;

/// RFC 4861 §10 host constants.
pub const MAX_RTR_SOLICITATIONS: u32 = 3;
pub const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);
pub const MAX_RTR_SOLICITATION_DELAY: Duration = Duration::from_secs(1);

/// The lifetime that never runs out (RFC 4861 §4.6.2, RFC 8106 §5).
const INFINITY: u32 = u32::MAX;

/// RFC 4862 §5.5.3 (e): an RA can shorten an address's valid lifetime to
/// no less than this, so a forged one cannot take the address away.
const TWO_HOURS: u32 = 7200;

/// Bounds on what RAs can make an interface hold, so a neighbor forging
/// them from many link-local sources cannot grow it without limit (the
/// engine bounds its per-source table the same way,
/// `MAX_TRACKED_SOURCES`). An entry already held is still refreshed;
/// only new ones past the bound are ignored. 16 SLAAC addresses is the
/// kernel's own default (`max_addresses`).
pub const MAX_ROUTERS: usize = 16;
pub const MAX_PREFIXES: usize = 64;
pub const MAX_SLAAC: usize = 16;
pub const MAX_DNS: usize = 8;

/// The operator's configuration for one interface, by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// `ipv6 address autoconf`: run the RA host, and form SLAAC addresses.
    pub autoconf: bool,
    /// `ipv6 address dhcpv6`: run the RA host for the default route and
    /// the on-link prefixes a leased address needs. No SLAAC address
    /// comes of it.
    pub dhcpv6: bool,
    /// `ra-options default-route-distance`.
    pub distance: u8,
    /// `ra-options no-default-route`: routers are listed, not installed.
    pub no_default_route: bool,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            autoconf: false,
            dhcpv6: false,
            distance: DEFAULT_DISTANCE,
            no_default_route: false,
        }
    }
}

impl HostConfig {
    /// Whether the RA host runs: for `autoconf`, and for the DHCPv6
    /// client's `address dhcpv6` (`pd` will ask for it too, §4).
    pub fn enabled(&self) -> bool {
        self.autoconf || self.dhcpv6
    }
}

/// What the RA host needs to know about a link, from the RIB.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostLink {
    pub name: String,
    pub mac: Option<[u8; 6]>,
    /// The bridge or VRF master's ifindex.
    pub master: Option<u32>,
    /// This link is a VRF master: its name is the VRF's.
    pub is_vrf: bool,
    pub up: bool,
}

/// A default router (RFC 4861 §6.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Router {
    pub preference: RouterPreference,
    /// The Router Lifetime it last advertised, in seconds.
    pub lifetime: u16,
    pub expires: Instant,
}

/// A SLAAC address and the deadlines of its lifetimes (`None`: forever).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlaacAddr {
    pub addr: Ipv6Addr,
    pub valid: Option<Instant>,
    pub preferred: Option<Instant>,
}

/// The RA host on one interface.
#[derive(Debug, Clone)]
pub struct Host {
    /// The VRF the interface was in when the host started.
    pub vrf: Option<String>,
    /// Router Solicitations sent in the current burst.
    pub rs_sent: u32,
    /// When the next one is due; `None` once the burst is over or an RA
    /// has answered it.
    pub rs_next: Option<Instant>,
    /// Router Solicitations sent since the host started.
    pub rs_total: u64,
    /// Default routers, by link-local address.
    pub routers: BTreeMap<Ipv6Addr, Router>,
    /// On-link prefixes (PIO with L=1) and when each times out.
    pub on_link: BTreeMap<Ipv6Net, Option<Instant>>,
    /// SLAAC addresses, by the /64 they were formed from.
    pub slaac: BTreeMap<Ipv6Net, SlaacAddr>,
    /// Prefixes whose SLAAC address failed DAD: not formed again while
    /// the host runs, since nothing would make the next try different.
    pub dad_failed: BTreeSet<Ipv6Net>,
    /// RDNSS servers (RFC 8106) and when each times out, in the order a
    /// host uses them (§6.2): the ones heard of last first, those of
    /// one option in the option's order.
    pub dns: Vec<(Ipv6Addr, Option<Instant>)>,
    /// DNSSL domains (RFC 8106) and when each times out, in the same
    /// order (§6.3).
    pub search: Vec<(String, Option<Instant>)>,
    /// The last MTU option heard. Shown, not applied.
    pub mtu: Option<u32>,
}

impl Host {
    fn new(vrf: Option<String>) -> Self {
        Self {
            vrf,
            rs_sent: 0,
            rs_next: None,
            rs_total: 0,
            routers: BTreeMap::new(),
            on_link: BTreeMap::new(),
            slaac: BTreeMap::new(),
            dad_failed: BTreeSet::new(),
            dns: Vec::new(),
            search: Vec::new(),
            mtu: None,
        }
    }

    /// What the host knows of name resolution, for the system resolver:
    /// nothing when no RA has named a server or a domain.
    fn link_dns(&self) -> Option<LinkDns> {
        let dns = LinkDns {
            servers: self.dns.iter().map(|&(a, _)| IpAddr::V6(a)).collect(),
            domains: self.search.iter().map(|(d, _)| d.clone()).collect(),
        };
        (dns != LinkDns::default()).then_some(dns)
    }
}

/// Take in one RDNSS or DNSSL option: its addresses or domains, in
/// order, and the lifetime it gives them all (RFC 8106 §6.2, §6.3).
///
/// - A lifetime of zero takes an item out.
/// - An item held is refreshed where it stands.
/// - A new one goes in ahead of everything held before this option, and
///   behind the option's earlier new ones: what was heard of last is
///   used first, and an option's own order says which of its items is
///   preferred.
///
/// No more than `MAX_DNS` are held. Past that a new one is ignored: the
/// RFC would make room by dropping the one that expires first, which
/// lets whoever advertises last push the others out (see `MAX_ROUTERS`).
fn heard<T: PartialEq + Clone>(
    held: &mut Vec<(T, Option<Instant>)>,
    items: &[T],
    lifetime: u32,
    now: Instant,
) {
    // How many of this option's new items are in already.
    let mut front = 0;
    for item in items {
        let at = held.iter().position(|(have, _)| have == item);
        match (at, lifetime) {
            (Some(at), 0) => {
                held.remove(at);
            }
            (Some(at), _) => held[at].1 = deadline(now, lifetime),
            (None, 0) => {}
            (None, _) if held.len() < MAX_DNS => {
                held.insert(front, (item.clone(), deadline(now, lifetime)));
                front += 1;
            }
            (None, _) => {}
        }
    }
}

/// A route the RA host hands to the RIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaRoute {
    /// Through default routers, each a (link-local gateway, interface)
    /// leg, all at one distance: one leg is a plain route, several ECMP.
    Routers {
        distance: u8,
        legs: Vec<(Ipv6Addr, u32)>,
    },
    /// On-link out of an interface: `dev <if>`, no gateway.
    OnLink { distance: u8, ifindex: u32 },
}

impl RaRoute {
    pub fn entry(&self) -> RibEntry {
        let uni = |addr: Ipv6Addr, ifindex: u32| NexthopUni {
            addr: IpAddr::V6(addr),
            metric: 0,
            weight: 1,
            ifindex_origin: Some(ifindex),
            ..Default::default()
        };
        let mut entry = RibEntry::new(RibType::Ra);
        match self {
            RaRoute::Routers { distance, legs } => {
                entry.distance = *distance;
                entry.nexthop = match legs.as_slice() {
                    [(gateway, ifindex)] => Nexthop::Uni(uni(*gateway, *ifindex)),
                    legs => Nexthop::Multi(NexthopMulti {
                        metric: 0,
                        nexthops: legs.iter().map(|&(gw, ifindex)| uni(gw, ifindex)).collect(),
                        ..Default::default()
                    }),
                };
            }
            RaRoute::OnLink { distance, ifindex } => {
                entry.distance = *distance;
                entry.nexthop = Nexthop::Uni(uni(Ipv6Addr::UNSPECIFIED, *ifindex));
            }
        }
        entry
    }
}

/// Something the `Nd` task does for the RA host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAction {
    /// Turn the kernel's own RA processing off on `ifname`:
    /// `accept_ra=0`, `autoconf=0` (D4).
    DisableKernelRa { ifname: String },
    /// Hand the RIB a route for `prefix` in `vrf` (`None`: the default
    /// table), or take it back (`route: None`).
    Route {
        vrf: Option<String>,
        prefix: Ipv6Net,
        route: Option<RaRoute>,
    },
    /// Put a SLAAC address on an interface, or move its lifetimes.
    AddrAdd {
        ifindex: u32,
        addr: Ipv6Net,
        valid: u32,
        preferred: u32,
    },
    /// Give a SLAAC address up.
    AddrDel { ifindex: u32, addr: Ipv6Net },
    /// Tell the resolver task what RAs now say of name resolution on
    /// `ifname`: `None` when that is nothing (any more). Whether the
    /// host uses it is the resolver's configuration, not the RA host's.
    Dns {
        ifname: String,
        dns: Option<LinkDns>,
    },
}

impl HostAction {
    /// The RIB message, for an action that is one.
    pub fn into_message(self) -> Option<Message> {
        Some(match self {
            HostAction::DisableKernelRa { .. } | HostAction::Dns { .. } => return None,
            HostAction::Route { vrf, prefix, route } => match (vrf, route) {
                (None, Some(route)) => Message::Ipv6Add {
                    prefix,
                    rib: route.entry(),
                },
                (Some(vrf), Some(route)) => Message::Ipv6AddVrf {
                    vrf,
                    prefix,
                    rib: route.entry(),
                },
                (None, None) => Message::Ipv6Del {
                    prefix,
                    rib: RibEntry::new(RibType::Ra),
                },
                (Some(vrf), None) => Message::Ipv6DelVrf {
                    vrf,
                    prefix,
                    rib: RibEntry::new(RibType::Ra),
                },
            },
            HostAction::AddrAdd {
                ifindex,
                addr,
                valid,
                preferred,
            } => Message::AddrDynAdd {
                ifindex,
                addr: IpNet::V6(addr),
                origin: AddrOrigin::Slaac,
                opts: AddrOpts {
                    valid_lft: valid,
                    preferred_lft: preferred,
                    // On-link only by the L flag (RFC 5942), through the
                    // host's own `OnLink` route.
                    noprefixroute: true,
                    broadcast: None,
                },
            },
            HostAction::AddrDel { ifindex, addr } => Message::AddrDynDel {
                ifindex,
                addr: IpNet::V6(addr),
                origin: AddrOrigin::Slaac,
            },
        })
    }
}

/// The interface identifier RFC 4291 Appendix A makes of a MAC address:
/// `ff:fe` in the middle, the universal/local bit flipped.
pub fn eui64(prefix: Ipv6Net, mac: [u8; 6]) -> Ipv6Addr {
    let mut octets = prefix.network().octets();
    octets[8] = mac[0] ^ 0x02;
    octets[9] = mac[1];
    octets[10] = mac[2];
    octets[11] = 0xff;
    octets[12] = 0xfe;
    octets[13] = mac[3];
    octets[14] = mac[4];
    octets[15] = mac[5];
    Ipv6Addr::from(octets)
}

/// When a lifetime of `secs` from `now` runs out; `None` for forever.
fn deadline(now: Instant, secs: u32) -> Option<Instant> {
    (secs != INFINITY).then(|| now + Duration::from_secs(secs.into()))
}

/// Seconds left until `deadline`, rounded up so a lifetime counted down
/// from a whole number of seconds reads back the same; `INFINITY` for
/// forever.
fn remaining(now: Instant, deadline: Option<Instant>) -> u32 {
    match deadline {
        None => INFINITY,
        Some(at) => {
            let left = at.saturating_duration_since(now);
            let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
            secs.min(u64::from(INFINITY - 1)) as u32
        }
    }
}

/// The valid lifetime RFC 4862 §5.5.3 (e) gives an existing address when
/// an RA advertises `advertised` for its prefix and `left` seconds remain.
fn refreshed_valid(advertised: u32, left: u32) -> u32 {
    if advertised > TWO_HOURS || advertised > left {
        advertised
    } else if left <= TWO_HOURS {
        left
    } else {
        TWO_HOURS
    }
}

/// Whether `prefix` is in fe80::/10, which a PIO must not carry.
fn is_link_local(prefix: &Ipv6Net) -> bool {
    prefix.network().segments()[0] & 0xffc0 == 0xfe80
}

/// Every interface's RA host.
pub struct RaHosts {
    config: BTreeMap<String, HostConfig>,
    links: BTreeMap<u32, HostLink>,
    hosts: BTreeMap<u32, Host>,
    /// What the RIB was last told, per (VRF, prefix).
    installed: BTreeMap<(Option<String>, Ipv6Net), RaRoute>,
    /// What the resolver task was last told, per interface name.
    reported_dns: BTreeMap<String, LinkDns>,
    actions: Vec<HostAction>,
    rng: Box<dyn RngSource + Send + Sync>,
}

impl Default for RaHosts {
    fn default() -> Self {
        Self::new()
    }
}

impl RaHosts {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
            links: BTreeMap::new(),
            hosts: BTreeMap::new(),
            installed: BTreeMap::new(),
            reported_dns: BTreeMap::new(),
            actions: Vec::new(),
            rng: Box::new(ThreadRng),
        }
    }

    /// Replace the random source, so tests can pin the RS delay.
    pub fn set_rng(&mut self, rng: Box<dyn RngSource + Send + Sync>) {
        self.rng = rng;
    }

    /// What the `Nd` task has to do since the last call.
    pub fn take_actions(&mut self) -> Vec<HostAction> {
        std::mem::take(&mut self.actions)
    }

    /// The configuration of interface `name` (the defaults when none).
    pub fn config(&self, name: &str) -> HostConfig {
        self.config.get(name).cloned().unwrap_or_default()
    }

    /// The running host on `ifindex`.
    pub fn host(&self, ifindex: u32) -> Option<&Host> {
        self.hosts.get(&ifindex)
    }

    /// Every running host, by ifindex.
    pub fn hosts(&self) -> &BTreeMap<u32, Host> {
        &self.hosts
    }

    /// The routes handed to the RIB, per (VRF, prefix).
    pub fn installed(&self) -> &BTreeMap<(Option<String>, Ipv6Net), RaRoute> {
        &self.installed
    }

    /// Change interface `name`'s configuration, and start, stop or
    /// re-route its host to match.
    pub fn update_config(&mut self, name: &str, now: Instant, f: impl FnOnce(&mut HostConfig)) {
        let mut cfg = self.config(name);
        let was_autoconf = cfg.autoconf;
        f(&mut cfg);
        let autoconf = cfg.autoconf;
        if cfg == HostConfig::default() {
            self.config.remove(name);
        } else {
            self.config.insert(name.to_string(), cfg);
        }
        let ifindex = self
            .links
            .iter()
            .find(|(_, link)| link.name == name)
            .map(|(&ifindex, _)| ifindex);
        if let Some(ifindex) = ifindex {
            let ran = self.hosts.contains_key(&ifindex);
            self.reconcile(ifindex, now);
            if ran {
                self.follow_autoconf(ifindex, was_autoconf, autoconf, now);
            }
        }
        self.publish();
    }

    /// `autoconf` came or went on a host that was running and may go on
    /// running, for `address dhcpv6`. (A host that started or stopped
    /// with the change has seen to its addresses already.)
    fn follow_autoconf(&mut self, ifindex: u32, was: bool, is: bool, now: Instant) {
        let up = self.links.get(&ifindex).is_some_and(|link| link.up);
        let Some(host) = self.hosts.get_mut(&ifindex) else {
            return;
        };
        match (was, is) {
            // Its addresses are given up. The routers and the on-link
            // prefixes are still the host's to use.
            (true, false) => {
                for slaac in std::mem::take(&mut host.slaac).into_values() {
                    self.actions.push(HostAction::AddrDel {
                        ifindex,
                        addr: Ipv6Net::new(slaac.addr, 64).expect("a /64"),
                    });
                }
            }
            // The prefixes an address is formed from come with a Router
            // Advertisement: ask for one, not wait for the next.
            (false, true) if up => Self::restart_solicit(host, self.rng.as_mut(), now),
            _ => {}
        }
    }

    /// A link the RIB announced, or announced again with new attributes:
    /// a rename, a VRF move, an up / down change.
    pub fn link_add(&mut self, ifindex: u32, link: HostLink, now: Instant) {
        let up = link.up;
        let was_up = self.links.insert(ifindex, link).map(|old| old.up);
        // A VRF device's own announce can rename the VRF its members are in.
        let members: Vec<u32> = self
            .links
            .iter()
            .filter(|(_, l)| l.master == Some(ifindex))
            .map(|(&i, _)| i)
            .collect();
        self.reconcile(ifindex, now);
        for member in members {
            self.reconcile(member, now);
        }
        if let Some(was_up) = was_up {
            self.up_changed(ifindex, was_up, up, now);
        }
        self.publish();
    }

    /// The link went up or down. Its routers and prefixes are kept, but
    /// give no routes while it is down; coming up, it solicits again.
    pub fn link_state(&mut self, ifindex: u32, up: bool, now: Instant) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let was_up = std::mem::replace(&mut link.up, up);
        self.up_changed(ifindex, was_up, up, now);
        self.publish();
    }

    fn up_changed(&mut self, ifindex: u32, was_up: bool, up: bool, now: Instant) {
        let Some(host) = self.hosts.get_mut(&ifindex) else {
            return;
        };
        if up && !was_up {
            Self::restart_solicit(host, self.rng.as_mut(), now);
        } else if !up {
            host.rs_next = None;
        }
    }

    /// The link is gone, or moving to another VRF (the RIB announces a
    /// move as a delete and an add). Its addresses are given up, which is
    /// a no-op for a device that no longer exists.
    pub fn link_del(&mut self, ifindex: u32) {
        self.links.remove(&ifindex);
        self.stop(ifindex);
        self.publish();
    }

    /// An IPv6 address event on `ifindex`. A SLAAC address that failed DAD
    /// is given up; one the kernel removed (its lifetime ran out, or an
    /// operator deleted it) is forgotten, so the next RA forms it again.
    pub fn addr_event(&mut self, ifindex: u32, addr: Ipv6Net, dadfailed: bool, add: bool) {
        let Some(host) = self.hosts.get_mut(&ifindex) else {
            return;
        };
        let Some((&prefix, _)) = host
            .slaac
            .iter()
            .find(|(_, slaac)| slaac.addr == addr.addr())
        else {
            return;
        };
        if !add {
            host.slaac.remove(&prefix);
            return;
        }
        if !dadfailed {
            return;
        }
        host.slaac.remove(&prefix);
        host.dad_failed.insert(prefix);
        let name = self.links.get(&ifindex).map_or("?", |l| l.name.as_str());
        tracing::warn!(
            "nd: {name} (ifindex {ifindex}) SLAAC address {} failed DAD: another node on the link uses it; not formed again",
            addr.addr()
        );
        self.actions.push(HostAction::AddrDel { ifindex, addr });
    }

    /// A Router Advertisement from `src` on `ifindex` (RFC 4861 §6.3.4).
    pub fn on_ra(&mut self, ifindex: u32, src: Ipv6Addr, ra: &RouterAdvert, now: Instant) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let cfg = self.config(&link.name);
        let mac = link.mac;
        let Some(host) = self.hosts.get_mut(&ifindex) else {
            return;
        };
        // RFC 4861 §6.1.2: a router advertises from its link-local.
        if !src.is_unicast_link_local() {
            return;
        }
        if ra.router_lifetime > 0
            && (host.routers.contains_key(&src) || host.routers.len() < MAX_ROUTERS)
        {
            host.routers.insert(
                src,
                Router {
                    preference: ra.flags.preference(),
                    lifetime: ra.router_lifetime,
                    expires: now + Duration::from_secs(ra.router_lifetime.into()),
                },
            );
            // RFC 4861 §6.3.7: a host that has heard a router stops
            // soliciting.
            host.rs_next = None;
        } else if ra.router_lifetime == 0 {
            host.routers.remove(&src);
        }
        for option in &ra.options {
            match option {
                NdOption::PrefixInformation(pio) => {
                    Self::prefix(host, &mut self.actions, ifindex, pio, &cfg, mac, now);
                }
                NdOption::Mtu(mtu) => host.mtu = Some(*mtu),
                NdOption::Rdnss(rdnss) => {
                    heard(&mut host.dns, &rdnss.servers, rdnss.lifetime, now);
                }
                NdOption::Dnssl(dnssl) => {
                    heard(&mut host.search, &dnssl.domains, dnssl.lifetime, now);
                }
                _ => {}
            }
        }
        self.publish();
    }

    /// One Prefix Information option: the on-link prefix (RFC 4861
    /// §6.3.4) and the SLAAC address (RFC 4862 §5.5.3).
    fn prefix(
        host: &mut Host,
        actions: &mut Vec<HostAction>,
        ifindex: u32,
        pio: &PrefixInfo,
        cfg: &HostConfig,
        mac: Option<[u8; 6]>,
        now: Instant,
    ) {
        let Ok(prefix) = Ipv6Net::new(pio.prefix, pio.prefix_length) else {
            return;
        };
        let prefix = prefix.trunc();
        if prefix.prefix_len() == 0 || is_link_local(&prefix) || prefix.network().is_multicast() {
            return;
        }
        if pio.flags.contains(PrefixInfoFlags::L) {
            if pio.valid_lifetime == 0 {
                host.on_link.remove(&prefix);
            } else if host.on_link.contains_key(&prefix) || host.on_link.len() < MAX_PREFIXES {
                host.on_link
                    .insert(prefix, deadline(now, pio.valid_lifetime));
            }
        }
        // (c): a preferred lifetime beyond the valid one is an error.
        if !pio.flags.contains(PrefixInfoFlags::A)
            || !cfg.autoconf
            || pio.preferred_lifetime > pio.valid_lifetime
        {
            return;
        }
        // An Ethernet interface identifier is 64 bits, so the prefix must
        // be 64 bits long to make an address of it.
        if prefix.prefix_len() != 64 {
            tracing::debug!("nd: SLAAC needs a /64, not {prefix}");
            return;
        }
        let Some(mac) = mac else {
            return;
        };
        let (addr, valid) = match host.slaac.get(&prefix) {
            // (d): a new prefix with a valid lifetime forms an address.
            None => {
                if pio.valid_lifetime == 0
                    || host.dad_failed.contains(&prefix)
                    || host.slaac.len() >= MAX_SLAAC
                {
                    return;
                }
                (eui64(prefix, mac), pio.valid_lifetime)
            }
            // (e): an address it already formed has its lifetimes
            // refreshed, with the two-hour rule on the valid one.
            Some(slaac) => (
                slaac.addr,
                refreshed_valid(pio.valid_lifetime, remaining(now, slaac.valid)),
            ),
        };
        let preferred = pio.preferred_lifetime.min(valid);
        host.slaac.insert(
            prefix,
            SlaacAddr {
                addr,
                valid: deadline(now, valid),
                preferred: deadline(now, preferred),
            },
        );
        actions.push(HostAction::AddrAdd {
            ifindex,
            addr: Ipv6Net::new(addr, 64).expect("a /64"),
            valid,
            preferred,
        });
    }

    /// The Router Solicitations due by `now`, as frames. `source` gives the
    /// link-local an interface may send from, `None` while it has no usable
    /// one: the solicitation waits for it (RFC 4861 §6.3.7 sends from a
    /// link-local once there is one).
    pub fn solicit(
        &mut self,
        now: Instant,
        source: impl Fn(u32) -> Option<Ipv6Addr>,
    ) -> Vec<NdSend> {
        let mut frames = Vec::new();
        for (&ifindex, host) in self.hosts.iter_mut() {
            let Some(link) = self.links.get(&ifindex) else {
                continue;
            };
            if !link.up || host.rs_next.is_none_or(|at| at > now) {
                continue;
            }
            let Some(src) = source(ifindex) else {
                continue;
            };
            host.rs_sent += 1;
            host.rs_total += 1;
            host.rs_next =
                (host.rs_sent < MAX_RTR_SOLICITATIONS).then(|| now + RTR_SOLICITATION_INTERVAL);
            let options = link
                .mac
                .map(|mac| NdOption::SourceLinkLayerAddress(LinkLayerAddress::ethernet(mac)))
                .into_iter()
                .collect();
            frames.push(NdSend::RouterSolicit {
                ifindex,
                src: Some(src),
                rs: RouterSolicit { options },
            });
        }
        frames
    }

    /// Time out routers, prefixes, addresses and DNS information whose
    /// lifetime ran out by `now`.
    pub fn expire(&mut self, now: Instant) {
        let alive = |at: &Option<Instant>| at.is_none_or(|at| at > now);
        let mut changed = false;
        for (&ifindex, host) in self.hosts.iter_mut() {
            let routers = host.routers.len();
            host.routers.retain(|_, router| router.expires > now);
            let prefixes = host.on_link.len();
            host.on_link.retain(|_, at| alive(at));
            changed |= routers != host.routers.len() || prefixes != host.on_link.len();
            // The kernel has removed an expired address itself; giving it
            // up keeps the RIB's claim in step if its event was missed.
            let gone: Vec<Ipv6Net> = host
                .slaac
                .iter()
                .filter(|(_, slaac)| !alive(&slaac.valid))
                .map(|(&prefix, _)| prefix)
                .collect();
            for prefix in gone {
                if let Some(slaac) = host.slaac.remove(&prefix) {
                    self.actions.push(HostAction::AddrDel {
                        ifindex,
                        addr: Ipv6Net::new(slaac.addr, 64).expect("a /64"),
                    });
                }
            }
            host.dns.retain(|(_, at)| alive(at));
            host.search.retain(|(_, at)| alive(at));
        }
        if changed {
            self.sync_routes();
        }
        self.sync_dns();
    }

    /// The earliest time something is due: a solicitation on an interface
    /// `source` gives a link-local for, or a lifetime running out.
    pub fn next_wakeup(&self, source: impl Fn(u32) -> Option<Ipv6Addr>) -> Option<Instant> {
        let mut times = Vec::new();
        for (&ifindex, host) in &self.hosts {
            if self.links.get(&ifindex).is_some_and(|l| l.up) && source(ifindex).is_some() {
                times.extend(host.rs_next);
            }
            times.extend(host.routers.values().map(|r| r.expires));
            times.extend(host.on_link.values().flatten());
            times.extend(host.slaac.values().filter_map(|s| s.valid));
            times.extend(host.dns.iter().filter_map(|(_, at)| *at));
            times.extend(host.search.iter().filter_map(|(_, at)| *at));
        }
        times.into_iter().min()
    }

    /// The VRF `ifindex` is in: its master's name, when that is a VRF.
    fn vrf_of(&self, ifindex: u32) -> Option<String> {
        let master = self.links.get(&ifindex)?.master?;
        self.links
            .get(&master)
            .filter(|link| link.is_vrf)
            .map(|link| link.name.clone())
    }

    /// Start, stop or restart the host on `ifindex` to match its
    /// configuration and VRF.
    fn reconcile(&mut self, ifindex: u32, now: Instant) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let want = self.config(&link.name).enabled();
        let vrf = self.vrf_of(ifindex);
        let running = self.hosts.get(&ifindex).map(|host| host.vrf.clone());
        match running {
            Some(_) if !want => self.stop(ifindex),
            // A VRF move: everything learned in the old VRF goes, and the
            // host starts again in the new one (D10).
            Some(old) if old != vrf => {
                self.stop(ifindex);
                self.start(ifindex, vrf, now);
            }
            None if want => self.start(ifindex, vrf, now),
            _ => {}
        }
    }

    fn start(&mut self, ifindex: u32, vrf: Option<String>, now: Instant) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        self.actions.push(HostAction::DisableKernelRa {
            ifname: link.name.clone(),
        });
        let mut host = Host::new(vrf);
        if link.up {
            Self::restart_solicit(&mut host, self.rng.as_mut(), now);
        }
        self.hosts.insert(ifindex, host);
    }

    /// Stop the host on `ifindex`: its addresses are given up, and its
    /// routes go at the next [`Self::sync_routes`].
    fn stop(&mut self, ifindex: u32) {
        let Some(host) = self.hosts.remove(&ifindex) else {
            return;
        };
        for slaac in host.slaac.values() {
            self.actions.push(HostAction::AddrDel {
                ifindex,
                addr: Ipv6Net::new(slaac.addr, 64).expect("a /64"),
            });
        }
    }

    /// A new burst of Router Solicitations, the first after a random
    /// delay of up to `MAX_RTR_SOLICITATION_DELAY` (RFC 4861 §6.3.7).
    fn restart_solicit(host: &mut Host, rng: &mut (dyn RngSource + Send + Sync), now: Instant) {
        host.rs_sent = 0;
        host.rs_next = Some(now + rng.duration_in(Duration::ZERO, MAX_RTR_SOLICITATION_DELAY));
    }

    /// What the hosts give now, to those who use it: the routes to the
    /// RIB, the name servers to the resolver task. After every event that
    /// may have changed a host.
    fn publish(&mut self) {
        self.sync_routes();
        self.sync_dns();
    }

    /// Tell the resolver task what the hosts now know of name
    /// resolution: every change, once, by interface name.
    ///
    /// A host says it for as long as it runs and its options have
    /// lifetime left, link up or down: the system resolver itself leaves
    /// a link without carrier alone. A host that stops says nothing any
    /// more, and neither does the old name of an interface renamed.
    fn sync_dns(&mut self) {
        let mut now = BTreeMap::new();
        for (ifindex, host) in &self.hosts {
            if let (Some(link), Some(dns)) = (self.links.get(ifindex), host.link_dns()) {
                now.insert(link.name.clone(), dns);
            }
        }
        for ifname in self.reported_dns.keys() {
            if !now.contains_key(ifname) {
                self.actions.push(HostAction::Dns {
                    ifname: ifname.clone(),
                    dns: None,
                });
            }
        }
        for (ifname, dns) in &now {
            if self.reported_dns.get(ifname) != Some(dns) {
                self.actions.push(HostAction::Dns {
                    ifname: ifname.clone(),
                    dns: Some(dns.clone()),
                });
            }
        }
        self.reported_dns = now;
    }

    /// Hand the RIB the routes the hosts give now, and take back the ones
    /// they no longer give.
    fn sync_routes(&mut self) {
        let mut defaults: BTreeMap<Option<String>, Vec<(u8, RouterPreference, u32, Ipv6Addr)>> =
            BTreeMap::new();
        let mut on_link: BTreeMap<(Option<String>, Ipv6Net), Vec<(u8, u32)>> = BTreeMap::new();
        for (&ifindex, host) in &self.hosts {
            let Some(link) = self.links.get(&ifindex) else {
                continue;
            };
            if !link.up {
                continue;
            }
            let cfg = self.config(&link.name);
            if !cfg.no_default_route {
                let legs = defaults.entry(host.vrf.clone()).or_default();
                for (&gateway, router) in &host.routers {
                    legs.push((cfg.distance, router.preference, ifindex, gateway));
                }
            }
            for &prefix in host.on_link.keys() {
                on_link
                    .entry((host.vrf.clone(), prefix))
                    .or_default()
                    .push((cfg.distance, ifindex));
            }
        }
        let mut wanted = BTreeMap::new();
        for (vrf, legs) in defaults {
            let Some(&(distance, preference, ..)) = legs.iter().min() else {
                continue;
            };
            let mut best: Vec<(Ipv6Addr, u32)> = legs
                .iter()
                .filter(|leg| (leg.0, leg.1) == (distance, preference))
                .map(|&(_, _, ifindex, gateway)| (gateway, ifindex))
                .collect();
            best.sort();
            wanted.insert(
                (vrf, Ipv6Net::default()),
                RaRoute::Routers {
                    distance,
                    legs: best,
                },
            );
        }
        for (key, candidates) in on_link {
            // One interface carries a prefix; two advertising it at once
            // is a misconfiguration the lower ifindex settles.
            if let Some(&(distance, ifindex)) = candidates.iter().min() {
                wanted.insert(key, RaRoute::OnLink { distance, ifindex });
            }
        }
        for (vrf, prefix) in self.installed.keys() {
            if !wanted.contains_key(&(vrf.clone(), *prefix)) {
                self.actions.push(HostAction::Route {
                    vrf: vrf.clone(),
                    prefix: *prefix,
                    route: None,
                });
            }
        }
        for ((vrf, prefix), route) in &wanted {
            if self.installed.get(&(vrf.clone(), *prefix)) != Some(route) {
                self.actions.push(HostAction::Route {
                    vrf: vrf.clone(),
                    prefix: *prefix,
                    route: Some(route.clone()),
                });
            }
        }
        self.installed = wanted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nd_packet::{Dnssl, RaFlags, Rdnss};

    const WAN: u32 = 2;
    const WAN2: u32 = 3;
    const VRF: u32 = 9;
    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    /// A fixed RS delay of 100 ms.
    struct Fixed;
    impl RngSource for Fixed {
        fn duration_in(&mut self, _lo: Duration, _hi: Duration) -> Duration {
            Duration::from_millis(100)
        }
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn ll(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> Ipv6Net {
        s.parse().unwrap()
    }

    fn link(name: &str, up: bool) -> HostLink {
        HostLink {
            name: name.into(),
            mac: Some(MAC),
            master: None,
            is_vrf: false,
            up,
        }
    }

    fn hosts_with(names: &[(u32, &str)], now: Instant) -> RaHosts {
        let mut hosts = RaHosts::new();
        hosts.set_rng(Box::new(Fixed));
        for &(ifindex, name) in names {
            hosts.link_add(ifindex, link(name, true), now);
            hosts.update_config(name, now, |cfg| cfg.autoconf = true);
        }
        hosts
    }

    fn ra(lifetime: u16, options: Vec<NdOption>) -> RouterAdvert {
        RouterAdvert {
            cur_hop_limit: 64,
            flags: RaFlags::empty(),
            router_lifetime: lifetime,
            reachable_time: 0,
            retrans_timer: 0,
            options,
        }
    }

    fn pio(prefix: &str, flags: PrefixInfoFlags, valid: u32, preferred: u32) -> NdOption {
        let prefix = net(prefix);
        NdOption::PrefixInformation(PrefixInfo {
            prefix_length: prefix.prefix_len(),
            flags,
            valid_lifetime: valid,
            preferred_lifetime: preferred,
            prefix: prefix.network(),
        })
    }

    fn routes(actions: &[HostAction]) -> Vec<(Ipv6Net, Option<RaRoute>)> {
        actions
            .iter()
            .filter_map(|a| match a {
                HostAction::Route { prefix, route, .. } => Some((*prefix, route.clone())),
                _ => None,
            })
            .collect()
    }

    fn la() -> PrefixInfoFlags {
        PrefixInfoFlags::L | PrefixInfoFlags::A
    }

    #[test]
    fn eui64_flips_the_universal_local_bit() {
        assert_eq!(
            eui64(net("2001:db8:1::/64"), MAC),
            ll("2001:db8:1:0:5054:ff:fe12:3456")
        );
    }

    #[test]
    fn starting_turns_kernel_ra_off_and_solicits_three_times() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        assert_eq!(
            hosts.take_actions(),
            vec![HostAction::DisableKernelRa {
                ifname: "wan0".into()
            }]
        );
        let src = |_| Some(ll("fe80::1"));
        // Nothing before the random delay; then one every 4 s, three in all.
        assert!(hosts.solicit(now, src).is_empty());
        let mut sent = Vec::new();
        for at in [100, 4100, 8100, 12100, 16100] {
            sent.extend(
                hosts
                    .solicit(now + Duration::from_millis(at), src)
                    .into_iter()
                    .map(|f| (at, f)),
            );
        }
        assert_eq!(sent.len(), 3);
        assert_eq!(
            sent.iter().map(|(at, _)| *at).collect::<Vec<_>>(),
            [100, 4100, 8100]
        );
        let (
            _,
            NdSend::RouterSolicit {
                ifindex,
                src: from,
                rs,
            },
        ) = &sent[0]
        else {
            panic!("not an RS");
        };
        assert_eq!((*ifindex, *from), (WAN, Some(ll("fe80::1"))));
        assert_eq!(
            rs.options,
            vec![NdOption::SourceLinkLayerAddress(
                LinkLayerAddress::ethernet(MAC)
            )]
        );
        assert_eq!(hosts.host(WAN).unwrap().rs_total, 3);
        assert_eq!(hosts.next_wakeup(src), None);
    }

    #[test]
    fn a_solicitation_waits_for_a_usable_link_local() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        let none = |_| None;
        assert!(hosts.solicit(now + secs(5), none).is_empty());
        // Held: no wakeup for it, so the loop does not spin.
        assert_eq!(hosts.next_wakeup(none), None);
        let frames = hosts.solicit(now + secs(5), |_| Some(ll("fe80::1")));
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn an_ra_stops_soliciting_and_gives_the_default_route() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.take_actions();
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![]), now);
        assert_eq!(hosts.host(WAN).unwrap().rs_next, None);
        assert_eq!(
            routes(&hosts.take_actions()),
            vec![(
                Ipv6Net::default(),
                Some(RaRoute::Routers {
                    distance: DEFAULT_DISTANCE,
                    legs: vec![(ll("fe80::1"), WAN)],
                })
            )]
        );
        // The same RA again changes nothing the RIB holds.
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![]), now + secs(10));
        assert!(routes(&hosts.take_actions()).is_empty());
        // Router lifetime 0 withdraws it.
        hosts.on_ra(WAN, ll("fe80::1"), &ra(0, vec![]), now + secs(20));
        assert_eq!(
            routes(&hosts.take_actions()),
            vec![(Ipv6Net::default(), None)]
        );
    }

    #[test]
    fn an_ra_from_a_global_source_is_ignored() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.take_actions();
        hosts.on_ra(WAN, ll("2001:db8::1"), &ra(1800, vec![]), now);
        assert!(hosts.take_actions().is_empty());
        assert!(hosts.host(WAN).unwrap().routers.is_empty());
    }

    #[test]
    fn the_router_lifetime_runs_out() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.on_ra(WAN, ll("fe80::1"), &ra(30, vec![]), now);
        hosts.take_actions();
        assert_eq!(hosts.next_wakeup(|_| None), Some(now + secs(30)));
        hosts.expire(now + secs(29));
        assert!(hosts.take_actions().is_empty());
        hosts.expire(now + secs(30));
        assert_eq!(
            routes(&hosts.take_actions()),
            vec![(Ipv6Net::default(), None)]
        );
    }

    #[test]
    fn preference_then_ecmp_picks_the_routers() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        let high = RouterAdvert {
            flags: RaFlags::empty().with_preference(RouterPreference::High),
            ..ra(1800, vec![])
        };
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![]), now);
        hosts.on_ra(WAN, ll("fe80::2"), &high, now);
        hosts.on_ra(WAN, ll("fe80::3"), &high, now);
        assert_eq!(
            hosts.installed()[&(None, Ipv6Net::default())],
            RaRoute::Routers {
                distance: DEFAULT_DISTANCE,
                legs: vec![(ll("fe80::2"), WAN), (ll("fe80::3"), WAN)],
            }
        );
        // The medium-preference router takes over when the others go.
        hosts.on_ra(WAN, ll("fe80::2"), &ra(0, vec![]), now);
        hosts.on_ra(WAN, ll("fe80::3"), &ra(0, vec![]), now);
        assert_eq!(
            hosts.installed()[&(None, Ipv6Net::default())],
            RaRoute::Routers {
                distance: DEFAULT_DISTANCE,
                legs: vec![(ll("fe80::1"), WAN)],
            }
        );
    }

    #[test]
    fn distance_orders_two_interfaces_and_link_down_fails_over() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0"), (WAN2, "wan1")], now);
        hosts.update_config("wan1", now, |cfg| cfg.distance = 220);
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![]), now);
        hosts.on_ra(WAN2, ll("fe80::2"), &ra(1800, vec![]), now);
        let default = (None, Ipv6Net::default());
        assert_eq!(
            hosts.installed()[&default],
            RaRoute::Routers {
                distance: DEFAULT_DISTANCE,
                legs: vec![(ll("fe80::1"), WAN)],
            }
        );
        hosts.link_state(WAN, false, now);
        assert_eq!(
            hosts.installed()[&default],
            RaRoute::Routers {
                distance: 220,
                legs: vec![(ll("fe80::2"), WAN2)],
            }
        );
        // Back up: the router is still valid, and the better leg returns;
        // the link solicits again.
        hosts.link_state(WAN, true, now + secs(1));
        assert_eq!(
            hosts.installed()[&default],
            RaRoute::Routers {
                distance: DEFAULT_DISTANCE,
                legs: vec![(ll("fe80::1"), WAN)],
            }
        );
        assert_eq!(
            hosts.host(WAN).unwrap().rs_next,
            Some(now + secs(1) + Duration::from_millis(100))
        );
        // At one distance the two are ECMP.
        hosts.update_config("wan1", now, |cfg| cfg.distance = DEFAULT_DISTANCE);
        assert_eq!(
            hosts.installed()[&default],
            RaRoute::Routers {
                distance: DEFAULT_DISTANCE,
                legs: vec![(ll("fe80::1"), WAN), (ll("fe80::2"), WAN2)],
            }
        );
    }

    #[test]
    fn no_default_route_lists_the_router_but_installs_nothing() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.update_config("wan0", now, |cfg| cfg.no_default_route = true);
        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(1800, vec![pio("2001:db8:1::/64", la(), 3600, 1800)]),
            now,
        );
        assert_eq!(hosts.host(WAN).unwrap().routers.len(), 1);
        assert_eq!(
            hosts.installed().keys().cloned().collect::<Vec<_>>(),
            vec![(None, net("2001:db8:1::/64"))]
        );
    }

    #[test]
    fn a_pio_gives_the_on_link_route_and_a_slaac_address() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.take_actions();
        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(0, vec![pio("2001:db8:1::/64", la(), 3600, 1800)]),
            now,
        );
        let actions = hosts.take_actions();
        assert!(actions.contains(&HostAction::AddrAdd {
            ifindex: WAN,
            addr: net("2001:db8:1:0:5054:ff:fe12:3456/64"),
            valid: 3600,
            preferred: 1800,
        }));
        assert_eq!(
            routes(&actions),
            vec![(
                net("2001:db8:1::/64"),
                Some(RaRoute::OnLink {
                    distance: DEFAULT_DISTANCE,
                    ifindex: WAN
                })
            )]
        );
        // Valid lifetime 0 takes the on-link prefix away at once.
        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(0, vec![pio("2001:db8:1::/64", PrefixInfoFlags::L, 0, 0)]),
            now + secs(5),
        );
        assert_eq!(
            routes(&hosts.take_actions()),
            vec![(net("2001:db8:1::/64"), None)]
        );
    }

    #[test]
    fn only_a_valid_autonomous_slash_64_forms_an_address() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.take_actions();
        let addr_adds = |hosts: &mut RaHosts, opt| {
            hosts.on_ra(WAN, ll("fe80::1"), &ra(0, vec![opt]), now);
            hosts
                .take_actions()
                .into_iter()
                .filter(|a| matches!(a, HostAction::AddrAdd { .. }))
                .count()
        };
        // L only; a /56; preferred beyond valid (still on-link: RFC 4862
        // §5.5.3 (c) concerns the address only); a link-local prefix; and
        // a new prefix with valid lifetime 0.
        assert_eq!(
            addr_adds(
                &mut hosts,
                pio("2001:db8:2::/64", PrefixInfoFlags::L, 3600, 1800)
            ),
            0
        );
        assert_eq!(
            addr_adds(&mut hosts, pio("2001:db8:3::/56", la(), 3600, 1800)),
            0
        );
        assert_eq!(
            addr_adds(&mut hosts, pio("2001:db8:4::/64", la(), 1800, 3600)),
            0
        );
        assert_eq!(addr_adds(&mut hosts, pio("fe80::/64", la(), 3600, 1800)), 0);
        assert_eq!(addr_adds(&mut hosts, pio("2001:db8:5::/64", la(), 0, 0)), 0);
        assert!(hosts.host(WAN).unwrap().slaac.is_empty());
        assert_eq!(
            hosts.installed().keys().cloned().collect::<Vec<_>>(),
            vec![
                (None, net("2001:db8:2::/64")),
                (None, net("2001:db8:3::/56")),
                (None, net("2001:db8:4::/64")),
            ]
        );
        // Without `autoconf` there is no address either.
        hosts.update_config("wan0", now, |cfg| cfg.autoconf = false);
        assert!(hosts.host(WAN).is_none());
    }

    /// `address dhcpv6` runs the RA host for the default route and the
    /// on-link prefixes, and forms no SLAAC address: the lease is the
    /// address. `autoconf` beside it adds the SLAAC address.
    #[test]
    fn dhcpv6_runs_the_host_without_forming_addresses() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.update_config("wan0", now, |cfg| {
            cfg.autoconf = false;
            cfg.dhcpv6 = true;
        });
        assert!(hosts.host(WAN).is_some());
        hosts.take_actions();
        let prefix = pio("2001:db8:2::/64", la(), 3600, 1800);
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![prefix.clone()]), now);
        let actions = hosts.take_actions();
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, HostAction::AddrAdd { .. })),
            "{actions:?}"
        );
        // The default route and the on-link prefix are there all the same.
        let installed: Vec<_> = hosts.installed().keys().cloned().collect();
        assert_eq!(
            installed,
            vec![(None, net("::/0")), (None, net("2001:db8:2::/64"))]
        );
        assert!(hosts.host(WAN).unwrap().slaac.is_empty());

        // With `autoconf` as well, the routers are asked again, and the
        // RA that answers forms the address.
        assert_eq!(hosts.host(WAN).unwrap().rs_next, None);
        hosts.update_config("wan0", now, |cfg| cfg.autoconf = true);
        assert!(hosts.host(WAN).unwrap().rs_next.is_some());
        hosts.take_actions();
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![prefix]), now);
        let actions = hosts.take_actions();
        let formed: Vec<Ipv6Net> = actions
            .iter()
            .filter_map(|a| match a {
                HostAction::AddrAdd { addr, .. } => Some(*addr),
                _ => None,
            })
            .collect();
        assert_eq!(formed.len(), 1, "{actions:?}");
        // `autoconf` gone again: its address is given up, and the host
        // stays for the lease with its routes.
        hosts.update_config("wan0", now, |cfg| cfg.autoconf = false);
        assert_eq!(
            hosts.take_actions(),
            vec![HostAction::AddrDel {
                ifindex: WAN,
                addr: formed[0]
            }]
        );
        let host = hosts.host(WAN).expect("the host stays");
        assert!(host.slaac.is_empty());
        assert_eq!(hosts.installed().len(), 2);
        // An option that is not `autoconf` gives up nothing.
        hosts.update_config("wan0", now, |cfg| cfg.distance = 220);
        assert!(
            !hosts
                .take_actions()
                .iter()
                .any(|a| matches!(a, HostAction::AddrDel { .. }))
        );
        // With neither, there is no host.
        hosts.update_config("wan0", now, |cfg| cfg.dhcpv6 = false);
        assert!(hosts.host(WAN).is_none());
    }

    #[test]
    fn the_two_hour_rule_bounds_how_far_an_ra_shortens_an_address() {
        assert_eq!(refreshed_valid(86400, 600), 86400); // longer: taken
        assert_eq!(refreshed_valid(7201, 86400), 7201); // over two hours: taken
        assert_eq!(refreshed_valid(600, 86400), TWO_HOURS); // cut to two hours
        assert_eq!(refreshed_valid(0, 86400), TWO_HOURS);
        assert_eq!(refreshed_valid(600, 3600), 3600); // two hours or less left: kept
        assert_eq!(refreshed_valid(0, INFINITY), TWO_HOURS);
        assert_eq!(refreshed_valid(INFINITY, 600), INFINITY);

        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        let prefix = "2001:db8:1::/64";
        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(0, vec![pio(prefix, la(), 86400, 86400)]),
            now,
        );
        hosts.take_actions();
        // An RA saying 0 cuts the address to two hours, not to nothing.
        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(0, vec![pio(prefix, la(), 0, 0)]),
            now + secs(10),
        );
        let actions = hosts.take_actions();
        assert!(actions.contains(&HostAction::AddrAdd {
            ifindex: WAN,
            addr: net("2001:db8:1:0:5054:ff:fe12:3456/64"),
            valid: TWO_HOURS,
            preferred: 0,
        }));
    }

    #[test]
    fn a_dad_failure_gives_the_address_up_for_good() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        let opt = || pio("2001:db8:1::/64", la(), 3600, 1800);
        hosts.on_ra(WAN, ll("fe80::1"), &ra(0, vec![opt()]), now);
        hosts.take_actions();
        let addr = net("2001:db8:1:0:5054:ff:fe12:3456/64");
        hosts.addr_event(WAN, addr, true, true);
        assert_eq!(
            hosts.take_actions(),
            vec![HostAction::AddrDel { ifindex: WAN, addr }]
        );
        hosts.on_ra(WAN, ll("fe80::1"), &ra(0, vec![opt()]), now + secs(10));
        assert!(
            !hosts
                .take_actions()
                .iter()
                .any(|a| matches!(a, HostAction::AddrAdd { .. }))
        );
    }

    #[test]
    fn an_address_the_kernel_removed_is_formed_again() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        let opt = || pio("2001:db8:1::/64", la(), 3600, 1800);
        hosts.on_ra(WAN, ll("fe80::1"), &ra(0, vec![opt()]), now);
        hosts.take_actions();
        let addr = net("2001:db8:1:0:5054:ff:fe12:3456/64");
        hosts.addr_event(WAN, addr, false, false);
        assert!(hosts.host(WAN).unwrap().slaac.is_empty());
        hosts.on_ra(WAN, ll("fe80::1"), &ra(0, vec![opt()]), now + secs(10));
        assert!(hosts.take_actions().contains(&HostAction::AddrAdd {
            ifindex: WAN,
            addr,
            valid: 3600,
            preferred: 1800,
        }));
    }

    #[test]
    fn stopping_gives_up_addresses_and_routes() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(1800, vec![pio("2001:db8:1::/64", la(), 3600, 1800)]),
            now,
        );
        hosts.take_actions();
        hosts.update_config("wan0", now, |cfg| cfg.autoconf = false);
        let actions = hosts.take_actions();
        assert!(actions.contains(&HostAction::AddrDel {
            ifindex: WAN,
            addr: net("2001:db8:1:0:5054:ff:fe12:3456/64"),
        }));
        let mut withdrawn = routes(&actions);
        withdrawn.sort_by_key(|(prefix, _)| *prefix);
        assert_eq!(
            withdrawn,
            vec![(Ipv6Net::default(), None), (net("2001:db8:1::/64"), None)]
        );
        assert!(hosts.installed().is_empty());
    }

    #[test]
    fn a_vrf_move_starts_over_in_the_new_vrf() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.link_add(
            VRF,
            HostLink {
                name: "red".into(),
                is_vrf: true,
                up: true,
                ..Default::default()
            },
            now,
        );
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![]), now);
        hosts.take_actions();
        // The RIB announces the move as a delete and an add.
        hosts.link_del(WAN);
        hosts.link_add(
            WAN,
            HostLink {
                master: Some(VRF),
                ..link("wan0", true)
            },
            now + secs(1),
        );
        let actions = hosts.take_actions();
        assert_eq!(routes(&actions), vec![(Ipv6Net::default(), None)]);
        assert!(actions.contains(&HostAction::DisableKernelRa {
            ifname: "wan0".into()
        }));
        let host = hosts.host(WAN).unwrap();
        assert_eq!(host.vrf.as_deref(), Some("red"));
        assert!(host.routers.is_empty());
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![]), now + secs(2));
        assert_eq!(
            hosts.installed().keys().cloned().collect::<Vec<_>>(),
            vec![(Some("red".to_string()), Ipv6Net::default())]
        );
    }

    #[test]
    fn config_before_the_link_applies_when_it_appears() {
        let now = t0();
        let mut hosts = RaHosts::new();
        hosts.set_rng(Box::new(Fixed));
        hosts.update_config("wan0", now, |cfg| cfg.autoconf = true);
        assert!(hosts.hosts().is_empty());
        hosts.link_add(WAN, link("wan0", true), now);
        assert!(hosts.host(WAN).is_some());
    }

    #[test]
    fn what_ras_can_add_is_bounded() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        for n in 0..(MAX_ROUTERS as u16 + 4) {
            let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n + 1);
            let prefix = format!("2001:db8:{:x}::/64", n + 1);
            hosts.on_ra(
                WAN,
                src,
                &ra(1800, vec![pio(&prefix, la(), 3600, 1800)]),
                now,
            );
        }
        let host = hosts.host(WAN).unwrap();
        assert_eq!(host.routers.len(), MAX_ROUTERS);
        assert_eq!(host.slaac.len(), MAX_SLAAC);
        // One already held is still refreshed, and lifetime 0 still
        // takes it away.
        let first = ll("fe80::1");
        hosts.on_ra(WAN, first, &ra(600, vec![]), now + secs(1));
        assert_eq!(hosts.host(WAN).unwrap().routers[&first].lifetime, 600);
        hosts.on_ra(WAN, first, &ra(0, vec![]), now + secs(2));
        assert_eq!(hosts.host(WAN).unwrap().routers.len(), MAX_ROUTERS - 1);
    }

    #[test]
    fn dns_options_are_kept_until_their_lifetime_runs_out() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        let options = vec![
            NdOption::Rdnss(Rdnss {
                lifetime: 600,
                servers: vec![ll("2001:db8::53")],
            }),
            NdOption::Dnssl(Dnssl {
                lifetime: 300,
                domains: vec!["example.com".into()],
            }),
            NdOption::Mtu(1492),
        ];
        hosts.on_ra(WAN, ll("fe80::1"), &ra(0, options), now);
        let host = hosts.host(WAN).unwrap();
        assert!(host.dns.iter().any(|(a, _)| *a == ll("2001:db8::53")));
        assert!(host.search.iter().any(|(d, _)| d == "example.com"));
        assert_eq!(host.mtu, Some(1492));
        hosts.expire(now + secs(300));
        let host = hosts.host(WAN).unwrap();
        assert!(host.search.is_empty());
        assert_eq!(host.dns.len(), 1);
    }

    fn rdnss(lifetime: u32, servers: &[&str]) -> NdOption {
        NdOption::Rdnss(Rdnss {
            lifetime,
            servers: servers.iter().map(|s| ll(s)).collect(),
        })
    }

    fn dnssl(lifetime: u32, domains: &[&str]) -> NdOption {
        NdOption::Dnssl(Dnssl {
            lifetime,
            domains: domains.iter().map(|d| d.to_string()).collect(),
        })
    }

    fn link_dns(servers: &[&str], domains: &[&str]) -> LinkDns {
        LinkDns {
            servers: servers.iter().map(|s| IpAddr::V6(ll(s))).collect(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// What the host reported of name resolution since the last call,
    /// by interface name.
    fn reported(hosts: &mut RaHosts) -> Vec<(String, Option<LinkDns>)> {
        hosts
            .take_actions()
            .into_iter()
            .filter_map(|action| match action {
                HostAction::Dns { ifname, dns } => Some((ifname, dns)),
                _ => None,
            })
            .collect()
    }

    fn wan0(dns: Option<LinkDns>) -> Vec<(String, Option<LinkDns>)> {
        vec![("wan0".to_string(), dns)]
    }

    /// The resolver hears of every change in what RAs say of name
    /// resolution, once: a server or a domain coming, and going by a
    /// lifetime of zero.
    #[test]
    fn what_ras_say_of_name_servers_is_reported_as_it_changes() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        // A host that has heard of none says nothing.
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, vec![]), now);
        assert_eq!(reported(&mut hosts), []);

        let options = vec![rdnss(600, &["2001:db8::53"]), dnssl(600, &["example.com"])];
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, options.clone()), now);
        assert_eq!(
            reported(&mut hosts),
            wan0(Some(link_dns(&["2001:db8::53"], &["example.com"])))
        );
        // The same again only moves the lifetimes.
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, options), now + secs(60));
        assert_eq!(reported(&mut hosts), []);

        // Another server, from another router: heard of last, used
        // first.
        hosts.on_ra(
            WAN,
            ll("fe80::2"),
            &ra(1800, vec![rdnss(600, &["2001:db8::54"])]),
            now + secs(61),
        );
        assert_eq!(
            reported(&mut hosts),
            wan0(Some(link_dns(
                &["2001:db8::54", "2001:db8::53"],
                &["example.com"]
            )))
        );

        // A lifetime of zero takes the first away, and then the rest.
        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(1800, vec![rdnss(0, &["2001:db8::53"])]),
            now + secs(62),
        );
        assert_eq!(
            reported(&mut hosts),
            wan0(Some(link_dns(&["2001:db8::54"], &["example.com"])))
        );
        let options = vec![rdnss(0, &["2001:db8::54"]), dnssl(0, &["example.com"])];
        hosts.on_ra(WAN, ll("fe80::2"), &ra(1800, options), now + secs(63));
        assert_eq!(reported(&mut hosts), wan0(None));
        hosts.on_ra(WAN, ll("fe80::2"), &ra(1800, vec![]), now + secs(64));
        assert_eq!(reported(&mut hosts), []);
    }

    /// RFC 8106 §6.2 (§6.3 for domains): a server heard of for the
    /// first time goes in first, those of one option in the option's
    /// order, and one that is only refreshed stays where it is. Neither
    /// is the order of the addresses.
    #[test]
    fn a_new_name_server_goes_first_and_an_option_keeps_its_order() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        let options = vec![
            rdnss(600, &["2001:db8::99", "2001:db8::11"]),
            dnssl(600, &["zeta.example", "alpha.example"]),
        ];
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, options), now);
        assert_eq!(
            reported(&mut hosts),
            wan0(Some(link_dns(
                &["2001:db8::99", "2001:db8::11"],
                &["zeta.example", "alpha.example"],
            )))
        );

        // The last of each alone, again: not moved to the front, and
        // nothing new to report.
        let options = vec![
            rdnss(900, &["2001:db8::11"]),
            dnssl(900, &["alpha.example"]),
        ];
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, options), now + secs(1));
        assert_eq!(reported(&mut hosts), []);
        let host = hosts.host(WAN).unwrap();
        assert_eq!(host.dns[0], (ll("2001:db8::99"), Some(now + secs(600))));
        assert_eq!(host.dns[1], (ll("2001:db8::11"), Some(now + secs(901))));
        assert_eq!(host.search[1].0, "alpha.example");

        // An option naming one that is held between two that are new:
        // the new ones go ahead of everything held, in their own order,
        // and the held one stays.
        let options = vec![
            rdnss(600, &["2001:db8::77", "2001:db8::11", "2001:db8::55"]),
            dnssl(600, &["new.example", "alpha.example", "more.example"]),
        ];
        hosts.on_ra(WAN, ll("fe80::2"), &ra(1800, options), now + secs(2));
        assert_eq!(
            reported(&mut hosts),
            wan0(Some(link_dns(
                &[
                    "2001:db8::77",
                    "2001:db8::55",
                    "2001:db8::99",
                    "2001:db8::11"
                ],
                &[
                    "new.example",
                    "more.example",
                    "zeta.example",
                    "alpha.example"
                ],
            )))
        );

        // Two options in one advertisement are taken in one after the
        // other, so what the second one brings is ahead of the first's.
        let options = vec![rdnss(600, &["2001:db8::33"]), rdnss(600, &["2001:db8::22"])];
        hosts.on_ra(WAN, ll("fe80::2"), &ra(1800, options), now + secs(3));
        let servers = reported(&mut hosts).pop().unwrap().1.unwrap().servers;
        assert_eq!(
            servers[..3],
            link_dns(&["2001:db8::22", "2001:db8::33", "2001:db8::77"], &[]).servers[..]
        );
    }

    /// A lifetime that runs out is a change like any other, also when
    /// no route changes with it.
    #[test]
    fn name_servers_whose_lifetime_runs_out_are_reported_gone() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        let options = vec![
            rdnss(300, &["2001:db8::53"]),
            rdnss(600, &["2001:db8::54"]),
            dnssl(600, &["example.com"]),
        ];
        // No router and no prefix: nothing but the options times out.
        hosts.on_ra(WAN, ll("fe80::1"), &ra(0, options), now);
        reported(&mut hosts);
        assert_eq!(hosts.next_wakeup(|_| None), Some(now + secs(300)));
        hosts.expire(now + secs(299));
        assert_eq!(reported(&mut hosts), []);
        hosts.expire(now + secs(300));
        assert_eq!(
            reported(&mut hosts),
            wan0(Some(link_dns(&["2001:db8::54"], &["example.com"])))
        );
        hosts.expire(now + secs(600));
        assert_eq!(reported(&mut hosts), wan0(None));
        hosts.expire(now + secs(601));
        assert_eq!(reported(&mut hosts), []);
    }

    /// A host that stops, by its configuration or with its link, has no
    /// name servers to give any more. One that goes down keeps them: a
    /// link without carrier is the resolver's to leave alone.
    #[test]
    fn a_host_that_stops_takes_its_name_servers_back() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0"), (WAN2, "wan1")], now);
        let options = vec![rdnss(600, &["2001:db8::53"])];
        hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, options.clone()), now);
        hosts.on_ra(WAN2, ll("fe80::1"), &ra(1800, options), now);
        let servers = Some(link_dns(&["2001:db8::53"], &[]));
        assert_eq!(
            reported(&mut hosts),
            [
                ("wan0".to_string(), servers.clone()),
                ("wan1".to_string(), servers)
            ]
        );

        hosts.link_state(WAN, false, now + secs(1));
        hosts.link_state(WAN, true, now + secs(2));
        assert_eq!(reported(&mut hosts), []);

        hosts.update_config("wan0", now + secs(3), |cfg| cfg.autoconf = false);
        assert_eq!(reported(&mut hosts), wan0(None));
        hosts.link_del(WAN2);
        assert_eq!(reported(&mut hosts), [("wan1".to_string(), None)]);
    }

    /// The name is what the resolver knows an interface by: a renamed
    /// one gives its servers under the new name and none under the old.
    #[test]
    fn a_renamed_interface_reports_under_its_new_name() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        hosts.update_config("uplink", now, |cfg| cfg.autoconf = true);
        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(1800, vec![rdnss(600, &["2001:db8::53"])]),
            now,
        );
        reported(&mut hosts);
        hosts.link_add(WAN, link("uplink", true), now + secs(1));
        assert_eq!(
            reported(&mut hosts),
            [
                ("wan0".to_string(), None),
                ("uplink".to_string(), Some(link_dns(&["2001:db8::53"], &[]))),
            ]
        );
    }

    /// No more than `MAX_DNS` of each are held, and so reported; one
    /// held is still refreshed and still taken away.
    #[test]
    fn the_name_servers_ras_can_add_are_bounded() {
        let now = t0();
        let mut hosts = hosts_with(&[(WAN, "wan0")], now);
        for n in 0..(MAX_DNS as u16 + 3) {
            let server = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n + 1);
            let options = vec![
                NdOption::Rdnss(Rdnss {
                    lifetime: 600,
                    servers: vec![server],
                }),
                dnssl(600, &[&format!("d{n}.example")]),
            ];
            hosts.on_ra(WAN, ll("fe80::1"), &ra(1800, options), now);
        }
        let host = hosts.host(WAN).unwrap();
        assert_eq!((host.dns.len(), host.search.len()), (MAX_DNS, MAX_DNS));
        let last = reported(&mut hosts).pop().unwrap().1.unwrap();
        assert_eq!((last.servers.len(), last.domains.len()), (MAX_DNS, MAX_DNS));

        hosts.on_ra(
            WAN,
            ll("fe80::1"),
            &ra(1800, vec![rdnss(0, &["2001:db8::1"])]),
            now + secs(1),
        );
        assert_eq!(hosts.host(WAN).unwrap().dns.len(), MAX_DNS - 1);
    }

    #[test]
    fn actions_become_rib_messages() {
        let route = RaRoute::OnLink {
            distance: 210,
            ifindex: WAN,
        };
        let entry = route.entry();
        assert_eq!(entry.rtype, RibType::Ra);
        assert_eq!(entry.distance, 210);
        let Nexthop::Uni(uni) = &entry.nexthop else {
            panic!("not uni");
        };
        assert!(uni.addr.is_unspecified());
        assert_eq!(uni.ifindex_origin, Some(WAN));
        let msg = HostAction::AddrAdd {
            ifindex: WAN,
            addr: net("2001:db8:1::1/64"),
            valid: 3600,
            preferred: 1800,
        }
        .into_message();
        let Some(Message::AddrDynAdd { origin, opts, .. }) = msg else {
            panic!("not an AddrDynAdd");
        };
        assert_eq!(origin, AddrOrigin::Slaac);
        assert!(opts.noprefixroute);
        assert!(
            HostAction::DisableKernelRa {
                ifname: "wan0".into()
            }
            .into_message()
            .is_none()
        );
    }
}
