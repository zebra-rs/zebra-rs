//! IPv6 unicast from an interface neighbor carries the peer's link-local
//! as next-hop. The Loc-RIB row pins it to the receiving interface (the
//! peer's `scope_id`) so the RIB does not resolve fe80::/64 to whichever
//! connected interface it finds first, and the pinned row is not tracked,
//! like an RFC 8950 ENHE row. Every check runs with next-hop tracking on
//! (the global instance's cache), so a tracked next-hop shows up as a
//! `register` and holds the route out of the FIB until the RIB answers.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::peer_key::PeerOrigin;
use crate::bgp::route::route_from_peer;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapMultiProtocol, Ipv6Nlri, Med, MpReachAttr,
    MpUnreachAttr, Origin, Safi, UpdatePacket,
};
use ipnet::Ipv6Net;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const IFINDEX: u32 = 7;
/// The neighbor's link-local: the session address and the next-hop.
const LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
/// A second neighbor, on its own link.
const IFINDEX2: u32 = 8;
const LL2: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
const GLOBAL: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
const SID: Ipv6Addr = Ipv6Addr::new(0xfc00, 0, 1, 0, 0, 0, 0, 0);
const V6: AfiSafi = AfiSafi {
    afi: Afi::Ip6,
    safi: Safi::Unicast,
};
const PREFIX: &str = "2001:db8:99::/64";

type RibRx = mpsc::UnboundedReceiver<crate::rib::client::RibInbound>;

/// A `Bgp` whose RIB messages the test reads.
fn bgp() -> (Bgp, RibRx) {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
    let client =
        crate::rib::client::RibClient::new(inbound_tx, crate::rib::client::ProtoId::from_raw(0));
    let ctx = crate::context::ProtoContext::default_table(client);
    let (rib_tx, rib_out_rx) = mpsc::unbounded_channel();
    let (rib_inbound_tx, sub_inbound_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(rib_out_rx));
    Box::leak(Box::new(sub_inbound_rx));
    let subscriber = crate::config::RibSubscriber::for_test(
        rib_tx,
        rib_inbound_tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    );
    let (policy_tx, policy_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(policy_rx));
    let mut bgp = Bgp::new(
        ctx,
        rib_rx,
        subscriber,
        policy_tx,
        None,
        None,
        mpsc::channel(1).0,
    );
    bgp.asn = 65000;
    bgp.router_id = ROUTER_ID;
    (bgp, inbound_rx)
}

/// An Established unnumbered eBGP neighbor on interface [`IFINDEX`] with
/// IPv6 unicast negotiated.
fn add_unnumbered(bgp: &mut Bgp) -> usize {
    add_unnumbered_on(bgp, LL, IFINDEX)
}

/// The same neighbor with link-local `ll` on interface `ifindex`.
fn add_unnumbered_on(bgp: &mut Bgp, ll: Ipv6Addr, ifindex: u32) -> usize {
    add_neighbor(bgp, ll, |peer| {
        peer.origin = PeerOrigin::Interface { ifindex };
        peer.scope_id = Some(ifindex);
    })
}

/// An Established eBGP neighbor configured by its link-local address
/// [`LL`]. It has no scope of its own; `session_ifindex` is the interface
/// its session was pinned to when it established, if any.
fn add_addressed(bgp: &mut Bgp, session_ifindex: Option<u32>) -> usize {
    add_neighbor(bgp, LL, |peer| peer.session_ifindex = session_ifindex)
}

fn add_neighbor(bgp: &mut Bgp, ll: Ipv6Addr, setup: impl FnOnce(&mut Peer)) -> usize {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip = IpAddr::V6(ll);
    let mut peer = Peer::new(
        0,
        65000,
        ROUTER_ID,
        65002,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = PeerType::EBGP;
    setup(&mut peer);
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&V6.afi, &V6.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    let (ptx, prx) = mpsc::unbounded_channel();
    Box::leak(Box::new(prx));
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    bgp.peers.get(&ip).unwrap().ident
}

/// Run one UPDATE through the ingest, as the peer's FSM does, with
/// next-hop tracking on.
fn ingest(bgp: &mut Bgp, id: usize, packet: UpdatePacket) {
    let mut top = BgpTop {
        router_id: &bgp.router_id,
        srv6_ipv6_export: None,
        local_rib: &mut bgp.local_rib,
        shard: &mut bgp.shard,
        tx: &bgp.tx,
        rib_client: &bgp.ctx.rib,
        attr_store: &mut bgp.attr_store,
        update_groups: &mut bgp.update_groups,
        interface_addrs: &bgp.interface_addrs,
        vrf_export: None,
        color_policy: None,
        flex_algo_routes: None,
        flex_algo_srv6_routes: None,
        vrf_import: None,
        nexthop_cache: Some(&mut bgp.nexthop_cache),
        vrf_transport_v4: None,
        vrf_transport_v6: None,
        as_sets_withdraw: bgp.as_sets_withdraw,
    };
    route_from_peer(id, packet, &mut top, &mut bgp.peers, bgp.shards.as_ref());
}

fn prefix() -> Ipv6Net {
    PREFIX.parse().unwrap()
}

/// The neighbor announces [`PREFIX`] via `nhop` (the 16-octet MP_REACH
/// next-hop), with `sid` as an SRv6 L3 service SID when given.
fn announce(bgp: &mut Bgp, id: usize, nhop: Ipv6Addr, sid: Option<Ipv6Addr>) {
    let mut attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65002").unwrap()),
        ..Default::default()
    };
    if let Some(sid) = sid {
        attr.prefix_sid = Some(bgp_packet::PrefixSid {
            tlvs: vec![bgp_packet::PrefixSidTlv::Srv6L3Service(
                bgp_packet::Srv6ServiceTlv {
                    sids: vec![bgp_packet::Srv6SidInfo::new(
                        sid,
                        0,
                        bgp_packet::SRV6_BEHAVIOR_END_DT46,
                        None,
                    )],
                    ..Default::default()
                },
            )],
        });
    }
    announce_attr(bgp, id, nhop, attr);
}

/// The neighbor announces [`PREFIX`] via `nhop` with `attr`.
fn announce_attr(bgp: &mut Bgp, id: usize, nhop: Ipv6Addr, attr: BgpAttr) {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(attr);
    packet.mp_update = Some(MpReachAttr::Ipv6 {
        snpa: 0,
        nhop: IpAddr::V6(nhop),
        updates: vec![Ipv6Nlri {
            id: 0,
            prefix: prefix(),
        }],
    });
    ingest(bgp, id, packet);
}

fn withdraw(bgp: &mut Bgp, id: usize) {
    let mut packet = UpdatePacket::new();
    packet.mp_withdraw = Some(MpUnreachAttr::Ipv6Nlri(vec![Ipv6Nlri {
        id: 0,
        prefix: prefix(),
    }]));
    ingest(bgp, id, packet);
}

/// The FIB and next-hop-tracking messages sent to the RIB since the last
/// call, sorted.
fn rib_msgs(rx: &mut RibRx) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(inbound) = rx.try_recv() {
        match inbound.msg {
            crate::rib::Message::Ipv6Add { prefix, rib } => out.push(match rib.nexthop {
                crate::rib::Nexthop::Uni(uni) => format!(
                    "add {prefix} via {} ifindex {:?}",
                    uni.addr, uni.ifindex_origin
                ),
                _ => format!("add {prefix} via a non-unicast next-hop"),
            }),
            crate::rib::Message::Ipv6Del { prefix, .. } => out.push(format!("del {prefix}")),
            crate::rib::Message::NexthopRegister { nh, .. } => out.push(format!("register {nh}")),
            crate::rib::Message::NexthopUnregister { nh, .. } => {
                out.push(format!("unregister {nh}"))
            }
            _ => {}
        }
    }
    out.sort();
    out
}

fn pinned() -> String {
    format!("add {PREFIX} via {LL} ifindex Some({IFINDEX})")
}

fn best_egress(bgp: &Bgp) -> Option<(Ipv6Addr, u32)> {
    bgp.shard.v6.candidates(prefix())[0].enhe_egress
}

#[tokio::test]
async fn a_link_local_next_hop_is_pinned_to_the_receiving_interface_and_not_tracked() {
    let (mut bgp, mut rx) = bgp();
    let id = add_unnumbered(&mut bgp);
    announce(&mut bgp, id, LL, None);
    assert_eq!(rib_msgs(&mut rx), vec![pinned()]);
    assert_eq!(best_egress(&bgp), Some((LL, IFINDEX)));
}

/// A neighbor configured by its link-local address is on one link too:
/// the one its session rides.
#[tokio::test]
async fn a_neighbor_configured_by_link_local_address_is_pinned_to_its_session_interface() {
    let (mut bgp, mut rx) = bgp();
    let id = add_addressed(&mut bgp, Some(IFINDEX));
    assert_eq!(bgp.peers.get_by_idx(id).unwrap().scope_id, None);
    announce(&mut bgp, id, LL, None);
    assert_eq!(rib_msgs(&mut rx), vec![pinned()]);
    assert_eq!(best_egress(&bgp), Some((LL, IFINDEX)));
}

/// With no interface known for the session there is nothing to pin to:
/// the link-local is tracked and left to the resolver, as before.
#[tokio::test]
async fn a_link_local_next_hop_with_no_known_interface_is_tracked() {
    let (mut bgp, mut rx) = bgp();
    let id = add_addressed(&mut bgp, None);
    announce(&mut bgp, id, LL, None);
    assert_eq!(
        rib_msgs(&mut rx),
        vec![format!("del {PREFIX}"), format!("register {LL}")]
    );
    assert_eq!(best_egress(&bgp), None);
}

#[tokio::test]
async fn a_global_next_hop_from_the_same_neighbor_is_tracked_and_not_pinned() {
    let (mut bgp, mut rx) = bgp();
    let id = add_unnumbered(&mut bgp);
    announce(&mut bgp, id, GLOBAL, None);
    // Pending in the RIB, so not installed yet (the delete is the ingest
    // clearing a prefix whose best is not installable).
    assert_eq!(
        rib_msgs(&mut rx),
        vec![format!("del {PREFIX}"), format!("register {GLOBAL}")]
    );
    assert_eq!(best_egress(&bgp), None);
}

#[tokio::test]
async fn the_next_hop_moving_between_link_local_and_global_tracks_only_the_global() {
    let (mut bgp, mut rx) = bgp();
    let id = add_unnumbered(&mut bgp);
    announce(&mut bgp, id, LL, None);
    assert_eq!(rib_msgs(&mut rx), vec![pinned()]);

    announce(&mut bgp, id, GLOBAL, None);
    assert_eq!(
        rib_msgs(&mut rx),
        vec![format!("del {PREFIX}"), format!("register {GLOBAL}")]
    );
    assert_eq!(best_egress(&bgp), None);

    announce(&mut bgp, id, LL, None);
    assert_eq!(
        rib_msgs(&mut rx),
        vec![pinned(), format!("unregister {GLOBAL}")]
    );
    assert_eq!(best_egress(&bgp), Some((LL, IFINDEX)));
}

#[tokio::test]
async fn a_withdrawn_pinned_route_leaves_the_fib_and_unregisters_nothing() {
    let (mut bgp, mut rx) = bgp();
    let id = add_unnumbered(&mut bgp);
    announce(&mut bgp, id, LL, None);
    assert_eq!(rib_msgs(&mut rx), vec![pinned()]);
    withdraw(&mut bgp, id);
    assert_eq!(rib_msgs(&mut rx), vec![format!("del {PREFIX}")]);
}

#[tokio::test]
async fn a_link_local_route_with_an_srv6_sid_keeps_tracking_the_sid() {
    let (mut bgp, mut rx) = bgp();
    let id = add_unnumbered(&mut bgp);
    announce(&mut bgp, id, LL, Some(SID));
    // The SID's locator is the forwarding dependency (`nht_target`): the
    // route waits for it like any SRv6 service route, unpinned.
    assert_eq!(
        rib_msgs(&mut rx),
        vec![format!("del {PREFIX}"), format!("register {SID}")]
    );
    assert_eq!(best_egress(&bgp), None);
}

/// A service SID that cannot serve an IPv6 destination (an End.DT4 alone)
/// is not installed: the route goes in as a plain one via its link-local,
/// so it is pinned like any other and waits for nothing.
#[tokio::test]
async fn a_link_local_route_whose_only_sid_is_end_dt4_is_pinned() {
    let (mut bgp, mut rx) = bgp();
    let id = add_unnumbered(&mut bgp);
    let attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65002").unwrap()),
        prefix_sid: Some(bgp_packet::PrefixSid {
            tlvs: vec![bgp_packet::PrefixSidTlv::Srv6L3Service(
                bgp_packet::Srv6ServiceTlv {
                    sids: vec![bgp_packet::Srv6SidInfo::new(
                        SID,
                        0,
                        bgp_packet::SRV6_BEHAVIOR_END_DT4,
                        None,
                    )],
                    ..Default::default()
                },
            )],
        }),
        ..Default::default()
    };
    announce_attr(&mut bgp, id, LL, attr);
    assert_eq!(rib_msgs(&mut rx), vec![pinned()]);
    assert_eq!(best_egress(&bgp), Some((LL, IFINDEX)));
}

/// A MED knob change re-runs best-path (`Bgp::bestpath_recompute_all`),
/// and that finds the prefixes to re-run by their tracked next-hops. A
/// prefix learned only over pinned link-locals has none and must be
/// re-run all the same. The knobs are process-wide, so this sets none:
/// it records as the winner the path `med missing-as-worst` would have
/// chosen, then runs the recompute that deleting the knob runs.
#[tokio::test]
async fn a_best_path_recompute_reaches_a_prefix_with_only_pinned_paths() {
    let (mut bgp, mut rx) = bgp();
    let first = add_unnumbered(&mut bgp);
    let second = add_unnumbered_on(&mut bgp, LL2, IFINDEX2);
    let attr = |med: Option<u32>| BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65002").unwrap()),
        med: med.map(Med::new),
        ..Default::default()
    };
    // Same neighboring AS, so MED decides: a missing MED reads as 0 and
    // beats 5, unless it is read as the worst value.
    announce_attr(&mut bgp, first, LL, attr(None));
    announce_attr(&mut bgp, second, LL2, attr(Some(5)));
    let winner = |bgp: &Bgp| bgp.shard.v6.1.get(&prefix()).map(|rib| rib.ident);
    assert_eq!(winner(&bgp), Some(first));
    assert!(
        bgp.nexthop_cache.entries.is_empty(),
        "neither path is tracked"
    );
    rib_msgs(&mut rx);

    let other = bgp
        .shard
        .v6
        .candidates(prefix())
        .iter()
        .find(|rib| rib.ident == second)
        .expect("the second path is a candidate")
        .clone();
    bgp.shard.v6.1.insert(prefix(), other);
    bgp.bestpath_recompute_all();

    assert_eq!(winner(&bgp), Some(first));
    assert_eq!(rib_msgs(&mut rx), vec![pinned()]);
}

/// A row for the same prefix with the same link-local but no scope is
/// tracked. The pinned row stays out of every match on that address: it
/// does not flip when the address does, and it does not keep the other
/// row's registration alive once that row leaves.
#[test]
fn a_pinned_row_is_not_matched_against_its_tracked_link_local() {
    use crate::bgp::route::{BgpRib, BgpRibType};
    let row = |ident: usize, pinned: bool| {
        let attr = BgpAttr {
            nexthop: Some(BgpNexthop::Ipv6(LL)),
            ..BgpAttr::default()
        };
        let mut rib = BgpRib::new(
            ident,
            ROUTER_ID,
            BgpRibType::EBGP,
            0,
            0,
            &attr,
            None,
            None,
            false,
        );
        if pinned {
            rib.enhe_egress = Some((LL, IFINDEX));
        }
        rib
    };
    let ll = IpAddr::V6(LL);
    let mut shard = crate::bgp::shard::BgpShard::default();
    shard.update_v6(prefix(), row(1, true));
    shard.update_v6(prefix(), row(2, false));

    assert!(shard.v6.set_nexthop_reachable(prefix(), ll, false));
    let mut reachable: Vec<_> = shard
        .v6
        .candidates(prefix())
        .iter()
        .map(|r| (r.ident, r.nexthop_reachable))
        .collect();
    reachable.sort();
    assert_eq!(reachable, vec![(1, true), (2, false)]);

    assert_eq!(
        shard.candidate_nexthops_v6(None, prefix()),
        BTreeSet::from([ll])
    );
    shard.remove_v6(prefix(), 0, 2);
    assert!(shard.candidate_nexthops_v6(None, prefix()).is_empty());
}

/// An RFC 8950 ENHE row from a zebra-rs neighbor still carries the
/// sender's v4 NEXT_HOP, which the receiver ignores. When a plain row for
/// the same prefix tracks that address, a reachability flip re-evaluates
/// only the plain row, and once it leaves nothing holds the address.
#[test]
fn an_enhe_row_is_not_matched_against_its_ignored_v4_next_hop() {
    use crate::bgp::route::{BgpRib, BgpRibType};
    use crate::bgp::shard::{BgpShard, ShardMsg, ShardOut};
    use bgp_packet::Ipv4Nlri;
    use ipnet::Ipv4Net;
    const NH4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
    let prefix = Ipv4Net::from_str("198.51.100.0/24").unwrap();
    let row = |ident: usize, enhe: bool| {
        let attr = BgpAttr {
            nexthop: Some(BgpNexthop::Ipv4(NH4)),
            ..BgpAttr::default()
        };
        let mut rib = BgpRib::new(
            ident,
            ROUTER_ID,
            BgpRibType::EBGP,
            0,
            0,
            &attr,
            None,
            None,
            false,
        );
        if enhe {
            rib.enhe_egress = Some((LL, IFINDEX));
        }
        rib
    };
    let nh = IpAddr::V4(NH4);
    let mut shard = BgpShard::default();
    shard.update(None, prefix, row(1, true));
    shard.update(None, prefix, row(2, false));

    let out = shard.handle(ShardMsg::NexthopReachableBatchV4 {
        nlris: vec![Ipv4Nlri { id: 0, prefix }],
        nh,
        reachable: false,
    });
    let [
        ShardOut::BestPathV4 {
            survivor_nexthops,
            nexthop_flipped,
            ..
        },
    ] = out.as_slice()
    else {
        panic!("expected one BestPathV4");
    };
    let flipped: Vec<_> = nexthop_flipped.iter().map(|r| r.ident).collect();
    assert_eq!(flipped, vec![2]);
    assert_eq!(survivor_nexthops, &BTreeSet::from([nh]));
    let mut reachable: Vec<_> = shard
        .v4
        .candidates(prefix)
        .iter()
        .map(|r| (r.ident, r.nexthop_reachable))
        .collect();
    reachable.sort();
    assert_eq!(reachable, vec![(1, true), (2, false)]);

    shard.remove(None, prefix, 0, 2);
    assert!(shard.candidate_nexthops_v4(None, prefix).is_empty());
}

/// A pinned route is installed on its interface also when another path
/// tracks the same link-local and the cache holds a resolution with an
/// SRv6 segment list for it: that transport is the other path's. A
/// tracked next-hop with such a resolution does inherit it.
#[tokio::test]
async fn a_pinned_route_does_not_inherit_the_transport_tracked_under_its_link_local() {
    let (mut bgp, mut rx) = bgp();
    let id = add_unnumbered(&mut bgp);
    // Another path tracks `nh`, and the RIB resolved it through an
    // SRv6-encapsulated route.
    let resolved_over_srv6 = |bgp: &mut Bgp, nh: Ipv6Addr| {
        let other = crate::bgp::nht::NhtDep::V6("2001:db8:77::/64".parse().unwrap());
        bgp.nexthop_cache.track(0, IpAddr::V6(nh), other);
        let entry = bgp
            .nexthop_cache
            .entries
            .get_mut(&(0, IpAddr::V6(nh)))
            .unwrap();
        entry.reachable = true;
        entry.nexthops = vec![crate::rib::nht::ResolvedNexthop {
            addr: "2001:db8::1".parse().unwrap(),
            ifindex: 3,
            labels: Vec::new(),
            segs: vec!["fc00:0:9::".parse().unwrap()],
            seg_encap: None,
        }];
    };
    resolved_over_srv6(&mut bgp, LL);
    resolved_over_srv6(&mut bgp, GLOBAL);

    announce(&mut bgp, id, LL, None);
    assert_eq!(rib_msgs(&mut rx), vec![pinned()]);

    announce(&mut bgp, id, GLOBAL, None);
    assert_eq!(
        rib_msgs(&mut rx),
        vec![format!("add {PREFIX} via 2001:db8::1 ifindex Some(3)")],
        "a tracked next-hop inherits its resolution's egress"
    );
}
