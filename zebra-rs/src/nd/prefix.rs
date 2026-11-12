//! The prefixes an advertising interface names in its Router
//! Advertisements (the Prefix Information option, RFC 4861 §4.6.2).
//!
//! RFC 4861 §6.2.1 has a router advertise, unless told otherwise, the
//! prefixes it holds as on-link on the interface (`AdvPrefixList`).
//! Here that is the /64 of each global address of the interface that
//! brings its connected route: one the operator configured, and one
//! taken from a delegated prefix (`dhcpv6-options pd <id> interface`),
//! which is how a CE router gets the hosts behind it their addresses
//! (RFC 7084 L-2). A /64, because that is what a host forms an address
//! from (RFC 4862).
//!
//! - **Lifetimes.** A prefix whose address never ends is advertised
//!   with RFC 4861's defaults, the same in every advertisement. One
//!   whose address has lifetimes (a delegated prefix's are the lease's)
//!   is advertised with what is left of them, counted down to the
//!   second: a host must not keep the prefix longer than this router
//!   holds it.
//! - **A prefix that goes** is not just left out, which would have the
//!   hosts go on using it for as long as they last heard. It is
//!   advertised with both lifetimes zero, and its flags as they were,
//!   until the longest valid lifetime it was ever advertised with is
//!   over (RFC 9096 §3.5, which replaces RFC 7084's L-13). A host that
//!   hears it starts no new connection from its address in the prefix,
//!   no longer takes the prefix for on-link, and keeps the address for
//!   two hours at most (RFC 4862 §5.5.3); and a host that was away for
//!   a while still hears it when it is back.
//!
//!   The longest ever, not the last: a host does not take a valid
//!   lifetime that an advertisement shortens to under two hours, and
//!   one that missed the advertisement knows nothing of it. And only a
//!   prefix that was advertised: of one no advertisement named, no
//!   host knows.
//! - **When a lifetime ends** is worked out from when the RIB noted it
//!   (`LinkAddr::ends`), not from when the RIB says so again: a link
//!   described anew (a move to another VRF) names the numbers it noted
//!   then.
//!
//! Pure bookkeeping, with the clock handed in: the engine feeds it the
//! RIB's address events and asks it for the options when an
//! advertisement is built.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv6Net};
use nd_packet::{PrefixInfo, PrefixInfoFlags};

use crate::rib::link::{AddrScope, LinkAddr};

/// RFC 4861 §6.2.1 `AdvValidLifetime`: 30 days.
pub const DEFAULT_VALID: u32 = 2_592_000;
/// RFC 4861 §6.2.1 `AdvPreferredLifetime`: 7 days.
pub const DEFAULT_PREFERRED: u32 = 604_800;
/// The length a host forms an address from.
const PREFIX_LEN: u8 = 64;
/// Lifetimes are whole seconds, noted when an event is handled: two
/// notes of one deadline can be this far apart.
const SAME: Duration = Duration::from_secs(2);

/// When an address's lifetimes end; `None` is never.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ends {
    valid: Option<Instant>,
    preferred: Option<Instant>,
}

impl Ends {
    fn of(addr: &LinkAddr, now: Instant) -> Ends {
        let (valid, preferred) = addr.ends(now);
        Ends { valid, preferred }
    }

    /// Whether `other` says something else, beyond the same deadline
    /// read a second apart.
    fn differs(&self, other: &Ends) -> bool {
        let moved = |a: Option<Instant>, b: Option<Instant>| match (a, b) {
            (None, None) => false,
            (Some(a), Some(b)) => {
                a.saturating_duration_since(b) > SAME || b.saturating_duration_since(a) > SAME
            }
            _ => true,
        };
        moved(self.valid, other.valid) || moved(self.preferred, other.preferred)
    }
}

/// What an event did to what a link advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    /// Nothing an advertisement would say differently.
    None,
    /// A lifetime moved: the hosts are to hear of it soon, since the
    /// old one may run out before the next advertisement is due.
    Lifetime,
    /// A prefix came or went.
    Prefixes,
}

/// One prefix as an advertisement names it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advertised {
    pub prefix: Ipv6Net,
    /// Seconds.
    pub valid: u32,
    pub preferred: u32,
    /// No address of the link is in it any more: it is named with both
    /// lifetimes zero, for this many seconds more.
    pub gone: Option<u32>,
}

impl Advertised {
    pub fn option(&self) -> PrefixInfo {
        PrefixInfo {
            prefix_length: self.prefix.prefix_len(),
            flags: PrefixInfoFlags::L | PrefixInfoFlags::A,
            valid_lifetime: self.valid,
            preferred_lifetime: self.preferred,
            prefix: self.prefix.network(),
        }
    }
}

/// Seconds from `now` to `at`, rounded up, so that a lifetime counted
/// down from a whole number of seconds reads back the same.
fn left(now: Instant, at: Instant) -> u32 {
    let left = at.saturating_duration_since(now);
    let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
    u32::try_from(secs)
        .unwrap_or(u32::MAX - 1)
        .min(u32::MAX - 1)
}

/// The address `addr` gives a prefix to advertise from, if it does: a
/// global IPv6 address under a /64, in the kernel, that brings its
/// connected route.
///
/// Not a SLAAC or a leased address, which went in without one
/// (`noprefixroute`): its prefix is another router's to advertise. Nor
/// one that failed duplicate address detection, which this router does
/// not hold.
fn advertised(addr: &LinkAddr) -> Option<Ipv6Net> {
    let IpNet::V6(net) = addr.addr else {
        return None;
    };
    let global = addr.scope == AddrScope::Universe
        && !net.addr().is_unicast_link_local()
        && !net.addr().is_loopback()
        && !net.addr().is_multicast()
        && !net.addr().is_unspecified();
    let usable = addr.fib && !addr.flags.dadfailed && addr.has_connected_route();
    (global && usable && net.prefix_len() == PREFIX_LEN).then_some(net)
}

/// Every link's prefixes to advertise.
#[derive(Debug, Default)]
pub struct Prefixes {
    /// By link: each address that gives a prefix, with when its
    /// lifetimes end.
    held: BTreeMap<u32, BTreeMap<Ipv6Net, Ends>>,
    /// By link: the prefixes no address is in any more, each with when
    /// it is over.
    gone: BTreeMap<u32, BTreeMap<Ipv6Net, Instant>>,
    /// By link: until when a host may hold each prefix, by what the
    /// advertisements that went out said of it. The latest of them all.
    told: BTreeMap<u32, BTreeMap<Ipv6Net, Instant>>,
}

impl Prefixes {
    /// An address of `ifindex` appeared, or is described anew.
    pub fn addr_add(&mut self, addr: &LinkAddr, now: Instant) -> Change {
        let Some(net) = advertised(addr) else {
            // Described anew as one that gives no prefix (it has failed
            // duplicate address detection, say).
            return match addr.addr {
                IpNet::V6(net) => self.remove(addr.ifindex, net, now),
                IpNet::V4(_) => Change::None,
            };
        };
        let ends = Ends::of(addr, now);
        let prefix = net.trunc();
        let held = self.held.entry(addr.ifindex).or_default();
        let had_prefix = held.keys().any(|other| other.trunc() == prefix);
        let old = held.insert(net, ends);
        // Back before it was over: what the hosts were told of it then
        // still holds for them.
        if let Some(until) = self
            .gone
            .get_mut(&addr.ifindex)
            .and_then(|gone| gone.remove(&prefix))
        {
            self.note_told(addr.ifindex, prefix, until);
        }
        match old {
            _ if !had_prefix => Change::Prefixes,
            Some(old) if !old.differs(&ends) => Change::None,
            _ => Change::Lifetime,
        }
    }

    /// An address of `ifindex` went.
    pub fn addr_del(&mut self, addr: &LinkAddr, now: Instant) -> Change {
        match addr.addr {
            IpNet::V6(net) => self.remove(addr.ifindex, net, now),
            IpNet::V4(_) => Change::None,
        }
    }

    fn remove(&mut self, ifindex: u32, net: Ipv6Net, now: Instant) -> Change {
        let Some(held) = self.held.get_mut(&ifindex) else {
            return Change::None;
        };
        if held.remove(&net).is_none() {
            return Change::None;
        }
        let prefix = net.trunc();
        if held.keys().any(|other| other.trunc() == prefix) {
            // Another address of the link is still in it.
            return Change::Lifetime;
        }
        // For as long as a host may still hold it: until the longest
        // valid lifetime an advertisement gave it is over. One that no
        // advertisement named, no host holds.
        let told = self.told.get_mut(&ifindex);
        if let Some(until) = told.and_then(|told| told.remove(&prefix))
            && until > now
        {
            let gone = self.gone.entry(ifindex).or_default();
            gone.insert(prefix, until);
        }
        Change::Prefixes
    }

    fn note_told(&mut self, ifindex: u32, prefix: Ipv6Net, until: Instant) {
        let told = self.told.entry(ifindex).or_default();
        let known = told.entry(prefix).or_insert(until);
        *known = (*known).max(until);
    }

    /// An advertisement of `ifindex` went out at `now` naming
    /// `advertised` (what [`Self::advertised`] gave for it): the hosts
    /// that heard it hold each prefix for the valid lifetime it said.
    pub fn sent(&mut self, ifindex: u32, advertised: &[Advertised], now: Instant) {
        for prefix in advertised.iter().filter(|p| p.gone.is_none()) {
            let until = now + Duration::from_secs(prefix.valid.into());
            self.note_told(ifindex, prefix.prefix, until);
        }
    }

    /// The link is described anew, with every address it has: one that
    /// is not among them went.
    pub fn link_set(&mut self, ifindex: u32, addrs: &[LinkAddr], now: Instant) -> Change {
        let listed: Vec<Ipv6Net> = addrs.iter().filter_map(advertised).collect();
        let stale: Vec<Ipv6Net> = self
            .held
            .get(&ifindex)
            .into_iter()
            .flat_map(|held| held.keys())
            .filter(|net| !listed.contains(net))
            .copied()
            .collect();
        let mut change = Change::None;
        for net in stale {
            change = change.max(self.remove(ifindex, net, now));
        }
        for addr in addrs {
            change = change.max(self.addr_add(addr, now));
        }
        change
    }

    /// The link is gone, and its addresses with it. What its hosts were
    /// told is kept until it is over: a link that moves to another VRF
    /// is reported gone and back, with the hosts where they were, and a
    /// prefix it does not come back with is to be named as gone.
    pub fn link_del(&mut self, ifindex: u32, now: Instant) {
        let held = self.held.get(&ifindex).into_iter().flatten();
        let nets: Vec<Ipv6Net> = held.map(|(net, _)| *net).collect();
        for net in nets {
            self.remove(ifindex, net, now);
        }
        self.held.remove(&ifindex);
    }

    /// Forget what is over by `now`: the prefixes that went, and what
    /// the hosts were told of the others.
    pub fn expire(&mut self, now: Instant) {
        for timed in [&mut self.gone, &mut self.told] {
            timed.retain(|_, prefixes| {
                prefixes.retain(|_, until| *until > now);
                !prefixes.is_empty()
            });
        }
    }

    /// What an advertisement of `ifindex` names at `now`: its prefixes
    /// in order, each once. A prefix several addresses are in lasts as
    /// long as the longest of them.
    pub fn advertised(&self, ifindex: u32, now: Instant) -> Vec<Advertised> {
        let mut out: BTreeMap<Ipv6Net, Advertised> = BTreeMap::new();
        for (net, ends) in self.held.get(&ifindex).into_iter().flatten() {
            let valid = ends.valid.map_or(DEFAULT_VALID, |at| left(now, at));
            let preferred = ends.preferred.map_or(DEFAULT_PREFERRED, |at| left(now, at));
            let prefix = net.trunc();
            let entry = out.entry(prefix).or_insert(Advertised {
                prefix,
                valid: 0,
                preferred: 0,
                gone: None,
            });
            entry.valid = entry.valid.max(valid);
            entry.preferred = entry.preferred.max(preferred.min(valid));
        }
        // One whose time is up says nothing any more: the kernel takes
        // the address away at that moment, and the event follows.
        out.retain(|_, held| held.valid > 0);
        for (prefix, until) in self.gone.get(&ifindex).into_iter().flatten() {
            let named = left(now, *until);
            if named > 0 {
                out.entry(*prefix).or_insert(Advertised {
                    prefix: *prefix,
                    valid: 0,
                    preferred: 0,
                    gone: Some(named),
                });
            }
        }
        out.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::link::{AddrFlags, AddrOrigin, NotedAt};

    const IF: u32 = 7;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn net(text: &str) -> Ipv6Net {
        text.parse().unwrap()
    }

    /// An address the kernel holds on `IF`, with these lifetimes.
    fn addr(text: &str, lifetimes: Option<(u32, u32)>) -> LinkAddr {
        LinkAddr {
            addr: IpNet::V6(net(text)),
            ifindex: IF,
            fib: true,
            scope: AddrScope::Universe,
            valid_lft: lifetimes.map(|(_, valid)| valid),
            preferred_lft: lifetimes.map(|(preferred, _)| preferred),
            ..Default::default()
        }
    }

    /// An advertisement of `IF` goes out at `now`.
    fn advertise(prefixes: &mut Prefixes, now: Instant) {
        let named = prefixes.advertised(IF, now);
        prefixes.sent(IF, &named, now);
    }

    /// What `IF` advertises at `now`, as text.
    fn told(prefixes: &Prefixes, now: Instant) -> Vec<String> {
        let all = prefixes.advertised(IF, now);
        all.iter()
            .map(|p| {
                let gone = p.gone.map(|left| format!(" gone, for {left}"));
                let gone = gone.unwrap_or_default();
                format!("{} {}/{}{gone}", p.prefix, p.preferred, p.valid)
            })
            .collect()
    }

    #[test]
    fn a_configured_address_gives_its_prefix_with_the_default_lifetimes() {
        let t0 = Instant::now();
        let mut prefixes = Prefixes::default();
        let configured = addr("2001:db8:1::1/64", None);
        assert_eq!(prefixes.addr_add(&configured, t0), Change::Prefixes);
        let want = [format!(
            "2001:db8:1::/64 {DEFAULT_PREFERRED}/{DEFAULT_VALID}"
        )];
        assert_eq!(told(&prefixes, t0), want);
        // The same in every advertisement, and for the kernel's word
        // "forever" too.
        assert_eq!(told(&prefixes, t0 + secs(86_400)), want);
        let forever = addr("2001:db8:1::1/64", Some((u32::MAX, u32::MAX)));
        assert_eq!(prefixes.addr_add(&forever, t0), Change::None);
        assert_eq!(told(&prefixes, t0), want);
        // The option: on-link, and for forming addresses from.
        let option = prefixes.advertised(IF, t0)[0].option();
        assert_eq!(option.prefix, net("2001:db8:1::/64").addr());
        assert_eq!(option.prefix_length, 64);
        assert_eq!(option.flags, PrefixInfoFlags::L | PrefixInfoFlags::A);
        assert_eq!(
            (option.preferred_lifetime, option.valid_lifetime),
            (DEFAULT_PREFERRED, DEFAULT_VALID)
        );
        // Another link has none of it.
        assert!(prefixes.advertised(IF + 1, t0).is_empty());
    }

    #[test]
    fn lifetimes_of_an_address_are_counted_down_and_follow_a_renewal() {
        let t0 = Instant::now();
        let mut prefixes = Prefixes::default();
        let leased = addr("2001:db8:100:1::1/64", Some((3600, 7200)));
        assert_eq!(prefixes.addr_add(&leased, t0), Change::Prefixes);
        assert_eq!(told(&prefixes, t0), ["2001:db8:100:1::/64 3600/7200"]);
        assert_eq!(
            told(&prefixes, t0 + secs(600)),
            ["2001:db8:100:1::/64 3000/6600"]
        );
        // Past the preferred lifetime it is named for what is open
        // only, and past the valid one not at all.
        assert_eq!(
            told(&prefixes, t0 + secs(4000)),
            ["2001:db8:100:1::/64 0/3200"]
        );
        assert!(told(&prefixes, t0 + secs(7200)).is_empty());

        // The kernel says the same a second later: nothing new.
        let again = addr("2001:db8:100:1::1/64", Some((3599, 7199)));
        assert_eq!(prefixes.addr_add(&again, t0 + secs(1)), Change::None);
        // A renewal moves both deadlines.
        let renewed = addr("2001:db8:100:1::1/64", Some((3600, 7200)));
        let t1 = t0 + secs(1800);
        assert_eq!(prefixes.addr_add(&renewed, t1), Change::Lifetime);
        assert_eq!(told(&prefixes, t1), ["2001:db8:100:1::/64 3600/7200"]);
        // So does a lifetime that comes to an address that had none,
        // and one that is taken off it.
        let configured = addr("2001:db8:100:1::1/64", None);
        assert_eq!(prefixes.addr_add(&configured, t1), Change::Lifetime);
        assert_eq!(prefixes.addr_add(&renewed, t1), Change::Lifetime);
        // A preferred lifetime never reads longer than the valid one.
        let odd = addr("2001:db8:100:1::1/64", Some((900, 600)));
        assert_eq!(prefixes.addr_add(&odd, t1), Change::Lifetime);
        assert_eq!(told(&prefixes, t1), ["2001:db8:100:1::/64 600/600"]);
    }

    #[test]
    fn only_a_global_slash_64_that_brings_its_route_is_advertised() {
        let t0 = Instant::now();
        let mut prefixes = Prefixes::default();
        let mut link_local = addr("fe80::1/64", None);
        link_local.scope = AddrScope::Link;
        let longer = addr("2001:db8:1::1/126", None);
        let shorter = addr("2001:db8:2::1/48", None);
        let host = addr("2001:db8:3::1/128", None);
        // A SLAAC address: its prefix is the advertising router's.
        let mut slaac = addr("2001:db8:4::5054:ff:fe12:3456/64", Some((1800, 3600)));
        slaac.dynamic = Some(AddrOrigin::Slaac);
        slaac.flags.noprefixroute = true;
        // Configured, and not in the kernel (the link is down).
        let mut absent = addr("2001:db8:5::1/64", None);
        absent.fib = false;
        let mut duplicate = addr("2001:db8:6::1/64", None);
        duplicate.flags = AddrFlags {
            dadfailed: true,
            tentative: true,
            ..AddrFlags::default()
        };
        let v4 = LinkAddr {
            addr: "192.0.2.1/24".parse().unwrap(),
            ifindex: IF,
            fib: true,
            ..Default::default()
        };
        for other in [
            &link_local,
            &longer,
            &shorter,
            &host,
            &slaac,
            &absent,
            &duplicate,
            &v4,
        ] {
            assert_eq!(prefixes.addr_add(other, t0), Change::None, "{}", other.addr);
            assert_eq!(prefixes.addr_del(other, t0), Change::None, "{}", other.addr);
        }
        assert!(told(&prefixes, t0).is_empty());

        // Still in duplicate address detection, it is this router's
        // all the same; a unique local address is a global one; and so
        // is one taken from a delegated prefix, which brings its route.
        let mut tentative = addr("2001:db8:7::1/64", None);
        tentative.flags.tentative = true;
        let unique_local = addr("fd00:1:2:3::1/64", None);
        let mut delegated = addr("2001:db8:8::1/64", Some((1800, 3600)));
        delegated.dynamic = Some(AddrOrigin::Pd);
        for mine in [&tentative, &unique_local, &delegated] {
            assert_eq!(
                prefixes.addr_add(mine, t0),
                Change::Prefixes,
                "{}",
                mine.addr
            );
        }
        assert_eq!(told(&prefixes, t0).len(), 3);

        // One that fails duplicate address detection after all is no
        // longer this router's: its prefix goes.
        advertise(&mut prefixes, t0);
        let mut failed = tentative.clone();
        failed.flags.dadfailed = true;
        assert_eq!(prefixes.addr_add(&failed, t0), Change::Prefixes);
        let now = told(&prefixes, t0);
        let gone = format!("2001:db8:7::/64 0/0 gone, for {DEFAULT_VALID}");
        assert!(now.contains(&gone), "{now:?}");
    }

    #[test]
    fn a_prefix_that_goes_is_named_on_its_way_out() {
        let t0 = Instant::now();
        let mut prefixes = Prefixes::default();
        let long = addr("2001:db8:100:1::1/64", Some((30_000, 60_000)));
        let short = addr("2001:db8:100:2::1/64", Some((300, 600)));
        let configured = addr("2001:db8:1::1/64", None);
        for held in [&long, &short, &configured] {
            prefixes.addr_add(held, t0);
        }
        advertise(&mut prefixes, t0);
        let t1 = t0 + secs(100);
        advertise(&mut prefixes, t1);
        for held in [&long, &short, &configured] {
            assert_eq!(
                prefixes.addr_del(held, t1),
                Change::Prefixes,
                "{}",
                held.addr
            );
        }
        // Both lifetimes zero at once, each until the valid lifetime
        // an advertisement gave it is over: what was left of an
        // address's, and RFC 4861's 30 days from the last one for an
        // address that never ended.
        assert_eq!(
            told(&prefixes, t1),
            [
                format!("2001:db8:1::/64 0/0 gone, for {DEFAULT_VALID}"),
                "2001:db8:100:1::/64 0/0 gone, for 59900".to_string(),
                "2001:db8:100:2::/64 0/0 gone, for 500".to_string(),
            ]
        );
        // Each until that is over, and not a second longer.
        assert_eq!(told(&prefixes, t1 + secs(499)).len(), 3);
        assert_eq!(told(&prefixes, t1 + secs(500)).len(), 2);
        prefixes.expire(t1 + secs(500));
        assert_eq!(told(&prefixes, t1 + secs(500)).len(), 2);
        // Gone a second time is nothing new.
        assert_eq!(prefixes.addr_del(&long, t1), Change::None);

        // One that comes back is itself again.
        let t2 = t1 + secs(600);
        assert_eq!(prefixes.addr_add(&long, t2), Change::Prefixes);
        assert_eq!(
            told(&prefixes, t2),
            [
                format!("2001:db8:1::/64 0/0 gone, for {}", DEFAULT_VALID - 600),
                "2001:db8:100:1::/64 30000/60000".to_string(),
            ]
        );
        // The option of one that went: both lifetimes zero, and the
        // flags it had.
        let option = prefixes.advertised(IF, t2)[0].option();
        assert_eq!(option.flags, PrefixInfoFlags::L | PrefixInfoFlags::A);
        assert_eq!((option.preferred_lifetime, option.valid_lifetime), (0, 0));
        // When its time is over it is forgotten.
        let over = t1 + secs(DEFAULT_VALID.into());
        assert_eq!(told(&prefixes, over).len(), 0);
        prefixes.expire(over);
        assert!(prefixes.gone.is_empty());

        // One whose time was up when it went leaves nothing to say.
        let mut prefixes = Prefixes::default();
        prefixes.addr_add(&short, t0);
        advertise(&mut prefixes, t0);
        assert_eq!(prefixes.addr_del(&short, t0 + secs(600)), Change::Prefixes);
        assert!(told(&prefixes, t0 + secs(600)).is_empty());
        // Nor does one that no advertisement named: no host holds it.
        prefixes.addr_add(&long, t0);
        assert_eq!(prefixes.addr_del(&long, t0 + secs(1)), Change::Prefixes);
        assert!(told(&prefixes, t0 + secs(1)).is_empty());
    }

    /// Until the longest valid lifetime an advertisement gave the
    /// prefix is over, not the last: a host takes no valid lifetime
    /// that is shortened to under two hours, and one that missed the
    /// advertisement which shortened it knows nothing of it.
    #[test]
    fn a_withdrawal_lasts_as_long_as_the_longest_lifetime_told() {
        let t0 = Instant::now();
        let mut prefixes = Prefixes::default();
        let leased = addr("2001:db8:100:1::1/64", Some((3600, 7200)));
        prefixes.addr_add(&leased, t0);
        advertise(&mut prefixes, t0);
        // The lease is cut to a minute, which is advertised too, and
        // then the prefix is taken away.
        let cut = addr("2001:db8:100:1::1/64", Some((60, 60)));
        assert_eq!(prefixes.addr_add(&cut, t0 + secs(10)), Change::Lifetime);
        advertise(&mut prefixes, t0 + secs(10));
        assert_eq!(
            told(&prefixes, t0 + secs(10)),
            ["2001:db8:100:1::/64 60/60"]
        );
        assert_eq!(prefixes.addr_del(&cut, t0 + secs(20)), Change::Prefixes);
        assert_eq!(
            told(&prefixes, t0 + secs(20)),
            ["2001:db8:100:1::/64 0/0 gone, for 7180"]
        );
        // Still named when the minute is long over.
        assert_eq!(told(&prefixes, t0 + secs(7199)).len(), 1);
        assert!(told(&prefixes, t0 + secs(7200)).is_empty());

        // A prefix that came back and goes again: what the hosts were
        // told the first time still holds for them.
        let mut prefixes = Prefixes::default();
        prefixes.addr_add(&leased, t0);
        advertise(&mut prefixes, t0);
        prefixes.addr_del(&leased, t0 + secs(100));
        prefixes.addr_add(&cut, t0 + secs(200));
        assert_eq!(prefixes.addr_del(&cut, t0 + secs(210)), Change::Prefixes);
        assert_eq!(
            told(&prefixes, t0 + secs(210)),
            ["2001:db8:100:1::/64 0/0 gone, for 6990"]
        );
        prefixes.expire(t0 + secs(7200));
        assert!(prefixes.gone.is_empty() && prefixes.told.is_empty());
    }

    /// A lifetime ends when the RIB noted it would, whenever the RIB
    /// says so again: a link described anew names the numbers it noted
    /// at the time.
    #[test]
    fn lifetimes_count_from_when_they_were_noted() {
        let t0 = Instant::now();
        let mut prefixes = Prefixes::default();
        let mut leased = addr("2001:db8:100:1::1/64", Some((3600, 7200)));
        leased.lft_noted = NotedAt(Some(t0));
        // Half an hour on, the link is described anew with what was
        // noted then.
        let later = t0 + secs(1800);
        let listed = [leased.clone()];
        assert_eq!(prefixes.link_set(IF, &listed, later), Change::Prefixes);
        assert_eq!(told(&prefixes, later), ["2001:db8:100:1::/64 1800/5400"]);
        // And again: the same end, so nothing new.
        let again = later + secs(600);
        assert_eq!(prefixes.link_set(IF, &listed, again), Change::None);
        assert_eq!(told(&prefixes, again), ["2001:db8:100:1::/64 1200/4800"]);
        // The same numbers noted now are a renewal.
        leased.lft_noted = NotedAt(Some(again));
        assert_eq!(prefixes.addr_add(&leased, again), Change::Lifetime);
        assert_eq!(told(&prefixes, again), ["2001:db8:100:1::/64 3600/7200"]);
    }

    #[test]
    fn a_prefix_lasts_as_long_as_the_longest_of_its_addresses() {
        let t0 = Instant::now();
        let mut prefixes = Prefixes::default();
        let leased = addr("2001:db8:100:1::1/64", Some((300, 600)));
        let longer = addr("2001:db8:100:1::2/64", Some((3600, 7200)));
        assert_eq!(prefixes.addr_add(&leased, t0), Change::Prefixes);
        // A second address in the prefix is no new prefix.
        assert_eq!(prefixes.addr_add(&longer, t0), Change::Lifetime);
        assert_eq!(told(&prefixes, t0), ["2001:db8:100:1::/64 3600/7200"]);
        // Nor is one of them leaving the end of it.
        assert_eq!(prefixes.addr_del(&longer, t0), Change::Lifetime);
        assert_eq!(told(&prefixes, t0), ["2001:db8:100:1::/64 300/600"]);
        // A configured one beside it never ends.
        let configured = addr("2001:db8:100:1::3/64", None);
        prefixes.addr_add(&configured, t0);
        let want = [format!(
            "2001:db8:100:1::/64 {DEFAULT_PREFERRED}/{DEFAULT_VALID}"
        )];
        assert_eq!(told(&prefixes, t0 + secs(900)), want);
    }

    #[test]
    fn a_link_described_anew_drops_what_it_no_longer_lists() {
        let t0 = Instant::now();
        let mut prefixes = Prefixes::default();
        let first = addr("2001:db8:1::1/64", None);
        let second = addr("2001:db8:2::1/64", None);
        let listed = [first.clone(), second.clone()];
        assert_eq!(prefixes.link_set(IF, &listed, t0), Change::Prefixes);
        assert_eq!(told(&prefixes, t0).len(), 2);
        // The same list again says nothing.
        assert_eq!(prefixes.link_set(IF, &listed, t0), Change::None);
        // One is no longer among them.
        advertise(&mut prefixes, t0);
        assert_eq!(prefixes.link_set(IF, &listed[..1], t0), Change::Prefixes);
        assert_eq!(
            told(&prefixes, t0),
            [
                format!("2001:db8:1::/64 {DEFAULT_PREFERRED}/{DEFAULT_VALID}"),
                format!("2001:db8:2::/64 0/0 gone, for {DEFAULT_VALID}"),
            ]
        );
        // A link reported gone before any advertisement went out:
        // nothing was told, and nothing is left of it.
        let mut prefixes = Prefixes::default();
        prefixes.link_set(IF, &listed, t0);
        prefixes.link_del(IF, t0);
        assert!(told(&prefixes, t0).is_empty());
        assert_eq!(prefixes.addr_del(&first, t0), Change::None);

        // Reported gone after its hosts were told (a move to another
        // VRF is that, and the link back at once): its prefixes are on
        // their way out, until it is back with them.
        prefixes.link_set(IF, &listed, t0);
        advertise(&mut prefixes, t0);
        prefixes.link_del(IF, t0);
        let both_gone = [
            format!("2001:db8:1::/64 0/0 gone, for {DEFAULT_VALID}"),
            format!("2001:db8:2::/64 0/0 gone, for {DEFAULT_VALID}"),
        ];
        assert_eq!(told(&prefixes, t0), both_gone);
        assert_eq!(prefixes.link_set(IF, &listed[..1], t0), Change::Prefixes);
        assert_eq!(
            told(&prefixes, t0),
            [
                format!("2001:db8:1::/64 {DEFAULT_PREFERRED}/{DEFAULT_VALID}"),
                format!("2001:db8:2::/64 0/0 gone, for {DEFAULT_VALID}"),
            ]
        );
    }
}
