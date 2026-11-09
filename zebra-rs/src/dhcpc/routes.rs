//! The routes leases give, as RIB entries.
//!
//! The RIB keeps one entry per protocol for a prefix, so the routes of
//! every interface's lease are gathered here first: each lease contributes
//! *legs* (a gateway on an interface, at that interface's
//! `default-route-distance`), and the legs for one prefix in one VRF become
//! one `RibType::DhcpClient` entry:
//!
//! - only the legs at the lowest distance are used; the others are
//!   backups, and take over when the better ones go (a lease ends, or its
//!   link goes down and the task leaves its legs out);
//! - one such leg is a plain route, several are ECMP (what VyOS gets from
//!   FRR for two DHCP uplinks left at the default distance).
//!
//! The backups are not handed to the RIB as a multi-metric (floating)
//! entry: the kernel flushes a leg's route when its link loses carrier,
//! and the RIB does not put that one leg back while another keeps the
//! entry installed. Choosing here, on every link event, uses only the
//! plain and ECMP shapes every protocol exercises.
//!
//! [`Routes::sync`] compares what is wanted with what was last handed to
//! the RIB and returns only the messages that change something.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;

use super::v4::client::Lease;
use crate::rib::entry::RibEntry;
use crate::rib::{Message, Nexthop, NexthopMulti, NexthopUni, RibType};

/// One interface's way to a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leg {
    pub distance: u8,
    pub ifindex: u32,
    pub gateway: Ipv4Addr,
}

/// A prefix in a VRF's table; `None` is the default table.
pub type Key = (Option<String>, Ipv4Net);

pub type Wanted = BTreeMap<Key, Vec<Leg>>;

/// What a lease routes, and through which gateway: its classless routes
/// when it has any (RFC 3442 has the client ignore the Router option
/// then), else a default route through the first router. On-link
/// destinations (router `0.0.0.0`) come back in the second list: the RIB
/// has no protocol route without a gateway, so they are not installed.
pub fn lease_routes(
    lease: &Lease,
    no_default_route: bool,
) -> (Vec<(Ipv4Net, Ipv4Addr)>, Vec<Ipv4Net>) {
    let default = Ipv4Net::default();
    let candidates: Vec<(Ipv4Net, Ipv4Addr)> = if lease.classless_routes.is_empty() {
        lease
            .routers
            .first()
            .map(|&router| (default, router))
            .into_iter()
            .collect()
    } else {
        lease.classless_routes.clone()
    };
    let mut routes = Vec::new();
    let mut on_link = Vec::new();
    for (prefix, router) in candidates {
        let prefix = prefix.trunc();
        if no_default_route && prefix == default {
            continue;
        }
        if router.is_unspecified() {
            on_link.push(prefix);
        } else if !routes.iter().any(|&(p, _)| p == prefix) {
            routes.push((prefix, router));
        }
    }
    (routes, on_link)
}

/// The legs that carry traffic: those at the lowest distance.
pub fn best(legs: &[Leg]) -> Vec<Leg> {
    let lowest = legs.iter().map(|leg| leg.distance).min();
    let mut best: Vec<Leg> = legs
        .iter()
        .filter(|leg| Some(leg.distance) == lowest)
        .copied()
        .collect();
    best.sort();
    best.dedup();
    best
}

/// The RIB entry for `legs` (not empty, all at one distance: see
/// [`best`]).
pub fn entry(legs: &[Leg]) -> RibEntry {
    let uni = |leg: &Leg| NexthopUni {
        addr: IpAddr::V4(leg.gateway),
        metric: 0,
        weight: 1,
        // The interface the lease is on: the gateway is reached there
        // and nowhere else, also when it lies outside the leased subnet
        // (a /32 lease).
        ifindex_origin: Some(leg.ifindex),
        ..Default::default()
    };
    let mut entry = RibEntry::new(RibType::DhcpClient);
    entry.distance = legs.first().map_or(0, |leg| leg.distance);
    entry.nexthop = match legs {
        [leg] => Nexthop::Uni(uni(leg)),
        legs => Nexthop::Multi(NexthopMulti {
            metric: 0,
            nexthops: legs.iter().map(uni).collect(),
            ..Default::default()
        }),
    };
    entry
}

/// What the RIB was last told.
#[derive(Default)]
pub struct Routes {
    installed: Wanted,
}

impl Routes {
    /// The messages that take the RIB from the last `sync` to `wanted`.
    pub fn sync(&mut self, mut wanted: Wanted) -> Vec<Message> {
        for legs in wanted.values_mut() {
            *legs = best(legs);
        }
        wanted.retain(|_, legs| !legs.is_empty());
        let mut out = Vec::new();
        for (vrf, prefix) in self.installed.keys() {
            if wanted.contains_key(&(vrf.clone(), *prefix)) {
                continue;
            }
            let rib = RibEntry::new(RibType::DhcpClient);
            out.push(match vrf {
                Some(vrf) => Message::Ipv4DelVrf {
                    vrf: vrf.clone(),
                    prefix: *prefix,
                    rib,
                },
                None => Message::Ipv4Del {
                    prefix: *prefix,
                    rib,
                },
            });
        }
        for ((vrf, prefix), legs) in &wanted {
            if self.installed.get(&(vrf.clone(), *prefix)) == Some(legs) {
                continue;
            }
            let rib = entry(legs);
            out.push(match vrf {
                Some(vrf) => Message::Ipv4AddVrf {
                    vrf: vrf.clone(),
                    prefix: *prefix,
                    rib,
                },
                None => Message::Ipv4Add {
                    prefix: *prefix,
                    rib,
                },
            });
        }
        self.installed = wanted;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(routers: &[&str], classless: &[(&str, &str)]) -> Lease {
        Lease {
            address: "192.0.2.100".parse().unwrap(),
            prefix_len: 24,
            server_id: "192.0.2.1".parse().unwrap(),
            broadcast: None,
            routers: routers.iter().map(|r| r.parse().unwrap()).collect(),
            classless_routes: classless
                .iter()
                .map(|(p, r)| (p.parse().unwrap(), r.parse().unwrap()))
                .collect(),
            dns_servers: vec![],
            domain_name: None,
            domain_search: vec![],
            ntp_servers: vec![],
            mtu: None,
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
        }
    }

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn lease_routes_follow_rfc3442() {
        // The Router option: a default through the first router.
        let (routes, on_link) = lease_routes(&lease(&["192.0.2.1", "192.0.2.2"], &[]), false);
        assert_eq!(routes, [(net("0.0.0.0/0"), addr("192.0.2.1"))]);
        assert!(on_link.is_empty());
        assert!(lease_routes(&lease(&["192.0.2.1"], &[]), true).0.is_empty());
        assert!(lease_routes(&lease(&[], &[]), false).0.is_empty());

        // Classless routes replace it, default included.
        let with_classless = lease(
            &["192.0.2.1"],
            &[
                ("0.0.0.0/0", "192.0.2.9"),
                ("10.0.0.0/8", "192.0.2.8"),
                ("172.16.0.0/12", "0.0.0.0"),
            ],
        );
        let (routes, on_link) = lease_routes(&with_classless, false);
        assert_eq!(
            routes,
            [
                (net("0.0.0.0/0"), addr("192.0.2.9")),
                (net("10.0.0.0/8"), addr("192.0.2.8")),
            ]
        );
        assert_eq!(on_link, [net("172.16.0.0/12")]);
        // `no-default-route` drops the default wherever it came from, and
        // the Router option stays ignored.
        let (routes, _) = lease_routes(&with_classless, true);
        assert_eq!(routes, [(net("10.0.0.0/8"), addr("192.0.2.8"))]);
    }

    fn leg(distance: u8, ifindex: u32, gateway: &str) -> Leg {
        Leg {
            distance,
            ifindex,
            gateway: addr(gateway),
        }
    }

    #[test]
    fn entry_shapes() {
        let one = entry(&[leg(210, 3, "192.0.2.1")]);
        assert_eq!(one.rtype, RibType::DhcpClient);
        assert_eq!(one.distance, 210);
        assert!(one.is_protocol());
        let Nexthop::Uni(uni) = &one.nexthop else {
            panic!("{:?}", one.nexthop)
        };
        assert_eq!(uni.addr, IpAddr::V4(addr("192.0.2.1")));
        assert_eq!((uni.ifindex_origin, uni.metric), (Some(3), 0));

        // Two uplinks at one distance: ECMP.
        let ecmp = entry(&[leg(210, 3, "192.0.2.1"), leg(210, 4, "198.51.100.1")]);
        let Nexthop::Multi(multi) = &ecmp.nexthop else {
            panic!("{:?}", ecmp.nexthop)
        };
        assert_eq!(multi.nexthops.len(), 2);
        assert_eq!(ecmp.distance, 210);

        // Different distances: only the better one carries traffic; the
        // other is a backup that `best` leaves out.
        let legs = [leg(220, 4, "198.51.100.1"), leg(210, 3, "192.0.2.1")];
        assert_eq!(best(&legs), [leg(210, 3, "192.0.2.1")]);
        assert_eq!(best(&legs[..1]), [leg(220, 4, "198.51.100.1")]);
        assert!(best(&[]).is_empty());
    }

    fn describe(messages: &[Message]) -> Vec<String> {
        messages
            .iter()
            .map(|m| match m {
                Message::Ipv4Add { prefix, rib } => format!("add {prefix} d{}", rib.distance),
                Message::Ipv4Del { prefix, .. } => format!("del {prefix}"),
                Message::Ipv4AddVrf { vrf, prefix, .. } => format!("add {vrf} {prefix}"),
                Message::Ipv4DelVrf { vrf, prefix, .. } => format!("del {vrf} {prefix}"),
                _ => "other".into(),
            })
            .collect()
    }

    #[test]
    fn sync_sends_only_what_changed() {
        let default = net("0.0.0.0/0");
        let mut routes = Routes::default();
        let one: Wanted = [((None, default), vec![leg(210, 3, "192.0.2.1")])].into();
        assert_eq!(describe(&routes.sync(one.clone())), ["add 0.0.0.0/0 d210"]);
        // The same again, in any order and with repeats: nothing to say.
        assert!(routes.sync(one.clone()).is_empty());

        // A backup uplink at a higher distance changes nothing the RIB
        // sees.
        let mut backup = one.clone();
        backup
            .get_mut(&(None, default))
            .unwrap()
            .push(leg(220, 6, "203.0.113.9"));
        assert!(routes.sync(backup.clone()).is_empty());

        // A better uplink joins, and another in a VRF.
        let mut two = backup.clone();
        two.get_mut(&(None, default))
            .unwrap()
            .insert(0, leg(200, 4, "198.51.100.1"));
        two.insert(
            (Some("red".into()), default),
            vec![leg(210, 5, "203.0.113.1")],
        );
        assert_eq!(
            describe(&routes.sync(two)),
            ["add 0.0.0.0/0 d200", "add red 0.0.0.0/0"]
        );

        // The better uplink goes (its lease ends or its link drops): the
        // next distance takes over; the VRF's route is withdrawn.
        assert_eq!(
            describe(&routes.sync(backup)),
            ["del red 0.0.0.0/0", "add 0.0.0.0/0 d210"]
        );
        let last: Wanted = [((None, default), vec![leg(220, 6, "203.0.113.9")])].into();
        assert_eq!(describe(&routes.sync(last)), ["add 0.0.0.0/0 d220"]);
        routes.sync(one.clone());
        assert_eq!(describe(&routes.sync(Wanted::new())), ["del 0.0.0.0/0"]);
        // An empty list of legs wants nothing.
        let empty: Wanted = [((None, default), vec![])].into();
        assert!(routes.sync(empty).is_empty());
    }
}
