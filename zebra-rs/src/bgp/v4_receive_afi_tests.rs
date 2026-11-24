//! IPv4 unicast from a session that did not enable it on our side is not
//! ours to take, and is ignored; FRR's `bgp_update_receive()` skips a
//! family not enabled on the peer (`peer->afc`) the same way. A neighbor
//! that sent no Multiprotocol capability still has IPv4 unicast enabled on
//! our side, so its routes are taken.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::route_from_peer;
use crate::test_log::logs;
use bgp_packet::{
    Afi, As4Path, BgpAttr, BgpNexthop, CapMultiProtocol, EvpnMulticast, EvpnRoute, Ipv4Nlri,
    MpReachAttr, MpUnreachAttr, Origin, Safi, UpdatePacket,
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

/// IPv4 unicast is ours to take when we enabled it, whatever the neighbor
/// advertised: one that sent no Multiprotocol capability at all speaks
/// IPv4 unicast (FRR assumes the configured families for it).
#[tokio::test]
async fn ipv4_unicast_enabled_on_our_side_is_taken() {
    for n in [1, 2] {
        for (who, caps) in [
            ("negotiated", &[(Afi::Ip, Safi::Unicast, true, true)][..]),
            (
                "no capability from the neighbor",
                &[(Afi::Ip, Safi::Unicast, true, false)][..],
            ),
        ] {
            for (form, packet) in [("NLRI field", plain()), ("MP_REACH", mp_reach())] {
                let mut bgp = bgp_with(n);
                let id = add_peer(&mut bgp, caps);
                ingest(&mut bgp, id, packet).await;
                assert!(learned(&bgp), "{who}, {form} at N={n}: the route is taken");
            }
        }
    }
}

/// The NLRI and Withdrawn Routes fields, IPv4-unicast MP_REACH and
/// MP_UNREACH (End-of-RIB included) are IPv4 unicast; other families'
/// MP attributes are not.
#[test]
fn strip_takes_every_ipv4_unicast_form_and_nothing_else() {
    use crate::bgp::route::strip_ipv4_unicast;
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
        assert!(strip_ipv4_unicast(&mut packet), "{form}: stripped");
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
    assert!(!strip_ipv4_unicast(&mut packet), "no IPv4 unicast to strip");
    assert!(
        matches!(packet.mp_update, Some(MpReachAttr::Evpn { .. }))
            && matches!(packet.mp_withdraw, Some(MpUnreachAttr::Ipv6Eor)),
        "the other families stay"
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
            .filter(|l| l.contains("did not enable; ignored") && l.contains("category=\"adj-in\""))
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
    }
}

/// The mark is per session: `route_clean()` clears it, so the next
/// session logs its first drop at info again.
#[tokio::test]
async fn the_next_session_logs_its_first_drop_again() {
    let mut bgp = bgp_with(1);
    let id = add_peer(&mut bgp, EVPN_ONLY);
    ingest(&mut bgp, id, plain()).await;
    assert!(bgp.peers.get_by_idx(id).unwrap().v4_not_enabled_logged);

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
        !bgp.peers.get_by_idx(id).unwrap().v4_not_enabled_logged,
        "the session that ended takes its mark with it"
    );

    let first = logs(|| from_peer(&mut bgp, id, plain()));
    let second = logs(|| from_peer(&mut bgp, id, plain()));
    assert_eq!(
        [info(&first), info(&second)],
        [1, 0],
        "the next session's first drop is at info, and only that one:\n{first}{second}"
    );
}
