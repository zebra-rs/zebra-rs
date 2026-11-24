//! A family that a session did not negotiate is not ours to take, and is
//! ignored: the rule the send side follows. Negotiated means both OPENs
//! carried the family, or ours did and the neighbor sent no Multiprotocol
//! capability at all. FRR's `bgp_update_receive()` tests our side alone
//! (`peer->afc`); this is stricter. Most of these tests use IPv4 unicast,
//! which has the most forms on the wire; the rule is the same for every
//! family.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::route_from_peer;
use crate::test_log::logs;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapMultiProtocol, EvpnMulticast, EvpnRoute,
    Ipv4Nlri, Ipv6Nlri, MpReachAttr, MpUnreachAttr, Origin, Safi, UpdatePacket,
};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const P: &str = "10.50.0.0/24";

/// A `Bgp` with an `n`-shard pool when `n > 1`.
fn bgp_with(n: usize) -> Bgp {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(inbound_rx));
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
    if n > 1 {
        let (tx, rx) = mpsc::unbounded_channel();
        bgp.shards = Some(crate::bgp::shard::pool::ShardPool::spawn(
            (0..n).map(|_| Default::default()).collect(),
            tx,
        ));
        bgp.shard_results_rx = rx;
    }
    bgp
}

/// An Established eBGP neighbor at 10.0.0.2: each family with whether we
/// sent its capability and whether the neighbor did.
fn add_peer(bgp: &mut Bgp, caps: &[(Afi, Safi, bool, bool)]) -> usize {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = "10.0.0.2".parse().unwrap();
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
    peer.remote_id = Ipv4Addr::new(10, 0, 0, 2);
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    for (afi, safi, send, recv) in caps {
        let entry = peer
            .cap_map
            .entries
            .entry(CapMultiProtocol::new(afi, safi))
            .or_default();
        entry.send = *send;
        entry.recv = *recv;
    }
    let (ptx, prx) = mpsc::unbounded_channel();
    Box::leak(Box::new(prx));
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    bgp.peers.get(&ip).unwrap().ident
}

fn attr() -> BgpAttr {
    BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65002").unwrap()),
        nexthop: Some(BgpNexthop::Ipv4(Ipv4Addr::new(10, 0, 0, 2))),
        ..Default::default()
    }
}

fn nlri() -> Ipv4Nlri {
    Ipv4Nlri {
        id: 0,
        prefix: P.parse().unwrap(),
    }
}

/// [`P`] in the NLRI field of the UPDATE.
fn plain() -> UpdatePacket {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(attr());
    packet.ipv4_update.push(nlri());
    packet
}

/// [`P`] in an IPv4-unicast MP_REACH_NLRI (RFC 4760).
fn mp_reach() -> UpdatePacket {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(attr());
    packet.mp_update = Some(MpReachAttr::Ipv4 {
        snpa: 0,
        nhop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        updates: vec![nlri()],
    });
    packet
}

/// Run one UPDATE through `route_from_peer()`, as the peer's FSM does.
fn from_peer(bgp: &mut Bgp, id: usize, packet: UpdatePacket) {
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
        nexthop_cache: None,
        vrf_transport_v4: None,
        vrf_transport_v6: None,
        as_sets_withdraw: bgp.as_sets_withdraw,
    };
    route_from_peer(id, packet, &mut top, &mut bgp.peers, bgp.shards.as_ref());
}

/// Run one UPDATE through the ingest and let the pool (if any) finish
/// with it.
async fn ingest(bgp: &mut Bgp, id: usize, packet: UpdatePacket) {
    from_peer(bgp, id, packet);
    let Some(pool) = bgp.shards.as_ref() else {
        return;
    };
    let mut barriers = Vec::new();
    pool.broadcast(|| {
        let (reply, rx) = tokio::sync::oneshot::channel();
        barriers.push(rx);
        crate::bgp::shard::ShardMsg::CountAdjInV4All { reply }
    });
    for rx in barriers {
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
    }
    while let Ok(result) = bgp.shard_results_rx.try_recv() {
        bgp.process_shard_result(result);
    }
}

/// Whether [`P`] has a path in the IPv4-unicast table (main's replica of
/// the pool at N>1).
fn learned(bgp: &Bgp) -> bool {
    bgp.shard
        .v4
        .0
        .get(&P.parse().unwrap())
        .is_some_and(|c| !c.is_empty())
}

const EVPN_ONLY: &[(Afi, Safi, bool, bool)] = &[(Afi::L2vpn, Safi::Evpn, true, true)];

#[tokio::test]
async fn ipv4_unicast_from_a_session_without_it_is_ignored() {
    for n in [1, 2] {
        for (form, packet) in [("NLRI field", plain()), ("MP_REACH", mp_reach())] {
            let mut bgp = bgp_with(n);
            let id = add_peer(&mut bgp, EVPN_ONLY);
            ingest(&mut bgp, id, packet).await;
            assert!(!learned(&bgp), "{form} at N={n}: the route is ignored");
        }
    }
}

/// IPv4 unicast is ours to take when the session negotiated it: both
/// OPENs carried it, or ours did and the neighbor sent no Multiprotocol
/// capability at all, in which case it is taken to speak IPv4 unicast
/// (`cap_register_recv`). A neighbor whose OPEN had Multiprotocol
/// capabilities and left IPv4 unicast out did not negotiate it, though we
/// offered it: the EVPN-only neighbor of a session that keeps our default.
#[tokio::test]
async fn ipv4_unicast_is_taken_when_negotiated() {
    for n in [1, 2] {
        for (who, recv, assumed, taken) in [
            ("both OPENs carried it", true, false, true),
            (
                "no Multiprotocol capability from the neighbor",
                false,
                true,
                true,
            ),
            ("the neighbor's OPEN left it out", false, false, false),
        ] {
            for (form, packet) in [("NLRI field", plain()), ("MP_REACH", mp_reach())] {
                let mut bgp = bgp_with(n);
                let id = add_peer(
                    &mut bgp,
                    &[
                        (Afi::Ip, Safi::Unicast, true, recv),
                        (Afi::L2vpn, Safi::Evpn, true, !assumed),
                    ],
                );
                bgp.peers
                    .get_mut_by_idx(id)
                    .unwrap()
                    .cap_map
                    .get_mut(&CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast))
                    .unwrap()
                    .assumed = assumed;
                ingest(&mut bgp, id, packet).await;
                assert_eq!(learned(&bgp), taken, "{who}, {form} at N={n}");
            }
        }
    }
}

/// The NLRI and Withdrawn Routes fields, IPv4-unicast MP_REACH and
/// MP_UNREACH (End-of-RIB included) are IPv4 unicast; other families'
/// MP attributes are not.
#[test]
fn strip_takes_every_ipv4_unicast_form_and_nothing_else() {
    use crate::bgp::route::strip_families;
    let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
    let all_but_v4 = |afi, safi| AfiSafi::new(afi, safi) != v4;
    let forms: [(&str, fn(&mut UpdatePacket)); 5] = [
        ("NLRI field", |p| p.ipv4_update.push(nlri())),
        ("Withdrawn Routes", |p| p.ipv4_withdraw.push(nlri())),
        ("MP_REACH", |p| p.mp_update = mp_reach().mp_update),
        ("MP_UNREACH", |p| {
            p.mp_withdraw = Some(MpUnreachAttr::Ipv4Nlri(vec![nlri()]))
        }),
        ("End-of-RIB", |p| {
            p.mp_withdraw = Some(MpUnreachAttr::Ipv4Eor)
        }),
    ];
    for (form, fill) in forms {
        let mut packet = UpdatePacket::new();
        fill(&mut packet);
        assert_eq!(
            strip_families(&mut packet, all_but_v4),
            vec![v4],
            "{form}: stripped"
        );
        assert!(
            packet.ipv4_update.is_empty()
                && packet.ipv4_withdraw.is_empty()
                && packet.mp_update.is_none()
                && packet.mp_withdraw.is_none(),
            "{form}: nothing left"
        );
    }

    let mut packet = UpdatePacket::new();
    packet.mp_update = evpn_reach();
    packet.mp_withdraw = Some(MpUnreachAttr::Ipv6Eor);
    assert!(
        strip_families(&mut packet, all_but_v4).is_empty(),
        "no IPv4 unicast to strip"
    );
    assert!(
        matches!(packet.mp_update, Some(MpReachAttr::Evpn { .. }))
            && matches!(packet.mp_withdraw, Some(MpUnreachAttr::Ipv6Eor)),
        "the other families stay"
    );
}

/// Every family the predicate turns down goes, whichever attribute carries
/// it, and is reported once; an enabled family in the same UPDATE stays.
#[test]
fn strip_takes_each_family_not_enabled() {
    use crate::bgp::route::strip_families;
    let evpn_only = |afi, safi| (afi, safi) == (Afi::L2vpn, Safi::Evpn);

    let mut packet = plain();
    packet.ipv4_withdraw.push(nlri());
    packet.mp_update = evpn_reach();
    packet.mp_withdraw = Some(MpUnreachAttr::Ipv6Eor);
    assert_eq!(
        strip_families(&mut packet, evpn_only),
        vec![
            AfiSafi::new(Afi::Ip, Safi::Unicast),
            AfiSafi::new(Afi::Ip6, Safi::Unicast)
        ],
    );
    assert!(packet.ipv4_update.is_empty() && packet.ipv4_withdraw.is_empty());
    assert!(packet.mp_withdraw.is_none(), "the IPv6 End-of-RIB goes");
    assert!(
        matches!(packet.mp_update, Some(MpReachAttr::Evpn { .. })),
        "EVPN stays"
    );

    // An MP_REACH and an MP_UNREACH of one family count once.
    let mut packet = UpdatePacket::new();
    packet.mp_update = v6_reach().mp_update;
    packet.mp_withdraw = Some(MpUnreachAttr::Ipv6Nlri(vec![v6_nlri()]));
    assert_eq!(
        strip_families(&mut packet, evpn_only),
        vec![AfiSafi::new(Afi::Ip6, Safi::Unicast)],
    );
    assert!(packet.mp_update.is_none() && packet.mp_withdraw.is_none());
}

const P6: &str = "2001:db8:50::/64";

fn v6_nlri() -> Ipv6Nlri {
    Ipv6Nlri {
        id: 0,
        prefix: P6.parse().unwrap(),
    }
}

/// [`P6`] in an IPv6-unicast MP_REACH_NLRI.
fn v6_reach() -> UpdatePacket {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(attr());
    packet.mp_update = Some(MpReachAttr::Ipv6 {
        snpa: 0,
        nhop: IpAddr::V6("2001:db8::2".parse().unwrap()),
        updates: vec![v6_nlri()],
    });
    packet
}

/// The rule is not IPv4 unicast's alone: IPv6 unicast and EVPN from a
/// session that did not negotiate them are ignored too, and taken from one
/// that did.
#[tokio::test]
async fn other_families_follow_the_same_rule() {
    const V4_ONLY: &[(Afi, Safi, bool, bool)] = &[(Afi::Ip, Safi::Unicast, true, true)];
    let v6_rows = |bgp: &Bgp| bgp.shard.v6.candidates(P6.parse().unwrap()).len();
    let evpn_rows = |bgp: &Bgp| {
        bgp.local_rib
            .evpn
            .values()
            .filter(|t| !t.selected.is_empty())
            .count()
    };
    let evpn = || {
        let mut packet = UpdatePacket::new();
        packet.bgp_attr = Some(attr());
        packet.mp_update = evpn_reach();
        packet
    };

    let mut bgp = bgp_with(1);
    let id = add_peer(&mut bgp, V4_ONLY);
    ingest(&mut bgp, id, v6_reach()).await;
    ingest(&mut bgp, id, evpn()).await;
    assert_eq!(
        (v6_rows(&bgp), evpn_rows(&bgp)),
        (0, 0),
        "not negotiated: ignored"
    );
    ingest(&mut bgp, id, plain()).await;
    assert!(learned(&bgp), "the family the session did enable is taken");

    let mut bgp = bgp_with(1);
    let id = add_peer(
        &mut bgp,
        &[
            (Afi::Ip6, Safi::Unicast, true, true),
            (Afi::L2vpn, Safi::Evpn, true, true),
        ],
    );
    ingest(&mut bgp, id, v6_reach()).await;
    ingest(&mut bgp, id, evpn()).await;
    assert_eq!(
        (v6_rows(&bgp), evpn_rows(&bgp)),
        (1, 1),
        "negotiated: taken"
    );
}

/// An EVPN MP_REACH (an inclusive-multicast route) from 10.0.0.2.
fn evpn_reach() -> Option<MpReachAttr> {
    let pe: Ipv4Addr = "10.0.0.2".parse().unwrap();
    Some(MpReachAttr::Evpn {
        snpa: 0,
        nhop: IpAddr::V4(pe),
        updates: vec![EvpnRoute::Multicast(EvpnMulticast {
            id: 0,
            rd: crate::bgp::route::rd_from_router_id_vni(pe, 100).unwrap(),
            ether_tag: 0,
            addr: IpAddr::V4(pe),
        })],
    })
}

/// The EVPN in the same UPDATE is taken: only IPv4 unicast is dropped.
#[tokio::test]
async fn evpn_next_to_ipv4_in_one_update_is_still_taken() {
    for n in [1, 2] {
        let mut bgp = bgp_with(n);
        let id = add_peer(&mut bgp, EVPN_ONLY);
        let mut packet = plain();
        packet.mp_update = evpn_reach();
        ingest(&mut bgp, id, packet).await;
        assert!(!learned(&bgp), "N={n}: the IPv4 route is ignored");
        assert!(
            bgp.local_rib.evpn.values().any(|t| !t.selected.is_empty()),
            "N={n}: the EVPN route is taken"
        );
    }
}

/// The once-per-session info lines in captured log output.
fn info(out: &str) -> usize {
    out.lines()
        .filter(|l| l.starts_with("INFO ") && l.contains("(logged once per session)"))
        .count()
}

/// The drop is logged at info once per session, not once per UPDATE. With
/// `tracing adj-in` on, every drop, the first included, is also on the
/// adj-in trace.
#[tokio::test]
async fn the_drop_is_logged_once_per_session() {
    let traced = |out: &str| {
        out.lines()
            .filter(|l| {
                l.contains("did not negotiate; ignored") && l.contains("category=\"adj-in\"")
            })
            .count()
    };
    for adj_in in [false, true] {
        let mut bgp = bgp_with(1);
        let id = add_peer(&mut bgp, EVPN_ONLY);
        bgp.peers.get_mut_by_idx(id).unwrap().tracing.adj_in = adj_in;
        let first = logs(|| from_peer(&mut bgp, id, plain()));
        let second = logs(|| from_peer(&mut bgp, id, mp_reach()));
        let expect = if adj_in { 1 } else { 0 };
        assert_eq!(
            [info(&first), info(&second), traced(&first), traced(&second)],
            [1, 0, expect, expect],
            "adj-in={adj_in}:\n{first}{second}"
        );
        // The mark is per family: another one has its own first drop.
        let third = logs(|| from_peer(&mut bgp, id, v6_reach()));
        let fourth = logs(|| from_peer(&mut bgp, id, v6_reach()));
        assert_eq!(
            [info(&third), info(&fourth)],
            [1, 0],
            "adj-in={adj_in}:\n{third}{fourth}"
        );
    }
}

/// The mark is per session: `route_clean()` clears it, so the next
/// session logs its first drop at info again.
#[tokio::test]
async fn the_next_session_logs_its_first_drop_again() {
    let mut bgp = bgp_with(1);
    let id = add_peer(&mut bgp, EVPN_ONLY);
    ingest(&mut bgp, id, plain()).await;
    let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
    assert!(
        bgp.peers
            .get_by_idx(id)
            .unwrap()
            .ignored_family_logged
            .contains(&v4)
    );

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
        nexthop_cache: None,
        vrf_transport_v4: None,
        vrf_transport_v6: None,
        as_sets_withdraw: bgp.as_sets_withdraw,
    };
    crate::bgp::route::route_clean(id, &mut top, &mut bgp.peers, None);
    assert!(
        bgp.peers
            .get_by_idx(id)
            .unwrap()
            .ignored_family_logged
            .is_empty(),
        "the session that ended takes its marks with it"
    );

    let first = logs(|| from_peer(&mut bgp, id, plain()));
    let second = logs(|| from_peer(&mut bgp, id, plain()));
    assert_eq!(
        [info(&first), info(&second)],
        [1, 0],
        "the next session's first drop is at info, and only that one:\n{first}{second}"
    );
}
