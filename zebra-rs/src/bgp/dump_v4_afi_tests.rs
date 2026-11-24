//! At N>1 the session-up IPv4-unicast dump runs in the pool
//! (`broadcast_dump_v4`), not in `route_sync`. `route_sync` sends IPv4
//! unicast only to a peer that negotiated it; the pool dump sent the IPv4
//! table, and its End-of-RIB, to every peer — an EVPN-only overlay session
//! included.

use super::*;
use crate::bgp::cap::{CapAfiMap, cap_register_recv, cap_register_send};
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::route_sync;
use crate::rib::RibType;
use bgp_packet::{
    Afi, AfiSafi, BgpCap, BgpPacket, CapMultiProtocol, MpReachAttr, ParseOption, Safi,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
/// A redistributed prefix: something in the pool to dump.
const PREFIX: &str = "10.40.1.0/24";

type Rx = mpsc::UnboundedReceiver<bytes::BytesMut>;

/// A `Bgp` with a two-shard pool.
fn sharded_bgp() -> Bgp {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
    let client =
        crate::rib::client::RibClient::new(inbound_tx, crate::rib::client::ProtoId::from_raw(0));
    Box::leak(Box::new(inbound_rx));
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
    let (tx, rx) = mpsc::unbounded_channel();
    bgp.shards = Some(crate::bgp::shard::pool::ShardPool::spawn(
        vec![Default::default(), Default::default()],
        tx,
    ));
    bgp.shard_results_rx = rx;
    bgp
}

/// An Established eBGP neighbor at `addr` that negotiated `families`.
fn add_peer(bgp: &mut Bgp, addr: &str, families: &[(Afi, Safi)]) -> (usize, Rx) {
    let caps: Vec<_> = families.iter().map(|&(a, s)| (a, s, true, true)).collect();
    add_peer_with(bgp, addr, &caps)
}

/// An Established eBGP neighbor at `addr`: each family with whether we
/// sent its capability and whether the neighbor did.
fn add_peer_with(bgp: &mut Bgp, addr: &str, caps: &[(Afi, Safi, bool, bool)]) -> (usize, Rx) {
    add_peer_cap_map(bgp, addr, |cap_map| {
        for (afi, safi, send, recv) in caps {
            let entry = cap_map
                .entries
                .entry(CapMultiProtocol::new(afi, safi))
                .or_default();
            entry.send = *send;
            entry.recv = *recv;
        }
    })
}

/// An Established eBGP neighbor at `addr` whose `cap_map` is set by `caps`.
fn add_peer_cap_map(bgp: &mut Bgp, addr: &str, caps: impl FnOnce(&mut CapAfiMap)) -> (usize, Rx) {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = addr.parse().unwrap();
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
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    caps(&mut peer.cap_map);
    let (ptx, prx) = mpsc::unbounded_channel();
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    bgp.peers.membership_enroll(id);
    crate::bgp::update_group::attach(&mut bgp.update_groups, &mut bgp.peers, id, ROUTER_ID, false);
    (id, prx)
}

/// Main reduces every pool result for the work dispatched so far. Each
/// shard handles its messages in order and answers a barrier only after the
/// results of everything before it are on the channel.
async fn settle(bgp: &mut Bgp) {
    let mut barriers = Vec::new();
    bgp.shards.as_ref().unwrap().broadcast(|| {
        let (reply, rx) = tokio::sync::oneshot::channel();
        barriers.push(rx);
        crate::bgp::shard::ShardMsg::CountAdjInV4All { reply }
    });
    for rx in barriers {
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("the pool answers")
            .unwrap();
    }
    while let Ok(result) = bgp.shard_results_rx.try_recv() {
        bgp.process_shard_result(result);
    }
}

/// The session-up dump, as the transition to Established runs it: the FSM's
/// `route_sync`, then the pool's broadcast, its acks reduced. Returns
/// whether the pool dumped.
async fn dump(bgp: &mut Bgp, c: usize) -> bool {
    {
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
        route_sync(bgp.peers.get_mut_by_idx(c).unwrap(), &mut top, true);
    }
    let dumped = bgp.broadcast_dump_v4(c).is_some();
    settle(bgp).await;
    dumped
}

/// The session ends, as the FSM ends it on leaving Established.
fn end_session(bgp: &mut Bgp, c: usize) {
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
    crate::bgp::route::route_clean(c, &mut top, &mut bgp.peers, bgp.shards.as_ref());
}

/// What the neighbor was sent in IPv4 unicast: the prefixes, sorted, and
/// the number of IPv4 End-of-RIB markers (the bare empty UPDATE).
fn sent_v4(rx: &mut Rx) -> (Vec<String>, usize) {
    let mut prefixes = Vec::new();
    let mut eor = 0;
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, true, Some(ParseOption::default()))
            .expect("a well-formed UPDATE");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        if update.ipv4_update.is_empty()
            && update.ipv4_withdraw.is_empty()
            && update.mp_update.is_none()
            && update.mp_withdraw.is_none()
        {
            eor += 1;
        }
        if let Some(MpReachAttr::Ipv4 { updates, .. }) = &update.mp_update {
            prefixes.extend(updates.iter().map(|n| n.prefix.to_string()));
        }
        prefixes.extend(update.ipv4_update.iter().map(|n| n.prefix.to_string()));
    }
    prefixes.sort();
    (prefixes, eor)
}

#[tokio::test]
async fn an_evpn_only_neighbor_is_not_sent_the_ipv4_table() {
    let mut bgp = sharded_bgp();
    bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
    settle(&mut bgp).await;

    let (c, mut rx) = add_peer(&mut bgp, "10.0.0.2", &[(Afi::L2vpn, Safi::Evpn)]);
    assert!(
        !dump(&mut bgp, c).await,
        "the pool does not dump IPv4 unicast"
    );
    assert_eq!(
        sent_v4(&mut rx),
        (vec![], 0),
        "no IPv4 route and no IPv4 End-of-RIB on a session without IPv4 unicast"
    );
}

#[tokio::test]
async fn a_neighbor_with_ipv4_and_evpn_is_sent_the_ipv4_table() {
    let mut bgp = sharded_bgp();
    bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
    settle(&mut bgp).await;

    let (c, mut rx) = add_peer(
        &mut bgp,
        "10.0.0.2",
        &[(Afi::Ip, Safi::Unicast), (Afi::L2vpn, Safi::Evpn)],
    );
    assert!(dump(&mut bgp, c).await, "the pool dumps IPv4 unicast");
    assert_eq!(
        sent_v4(&mut rx),
        (vec![PREFIX.to_string()], 1),
        "the route, then one IPv4 End-of-RIB"
    );
}

/// IPv4 unicast is on by default on our side, so an EVPN-only neighbor is
/// usually one that did not send the IPv4 capability while we did.
#[tokio::test]
async fn ipv4_unicast_offered_by_one_side_only_is_not_negotiated() {
    for (send, recv) in [(true, false), (false, true)] {
        let mut bgp = sharded_bgp();
        bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
        settle(&mut bgp).await;

        let (c, mut rx) = add_peer_with(
            &mut bgp,
            "10.0.0.2",
            &[
                (Afi::Ip, Safi::Unicast, send, recv),
                (Afi::L2vpn, Safi::Evpn, true, true),
            ],
        );
        assert!(
            !dump(&mut bgp, c).await,
            "no IPv4 dump with send={send} recv={recv}"
        );
        assert_eq!(
            sent_v4(&mut rx),
            (vec![], 0),
            "nothing in IPv4 unicast with send={send} recv={recv}"
        );
    }
}

/// A neighbor whose OPEN carried no Multiprotocol capability did not
/// negotiate, and is taken to support IPv4 unicast, as FRR does. Its IPv4
/// routes are taken, so it is sent ours.
#[tokio::test]
async fn a_neighbor_without_multiprotocol_capability_is_sent_the_ipv4_table() {
    let mut bgp = sharded_bgp();
    bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
    settle(&mut bgp).await;

    let (c, mut rx) = add_peer_cap_map(&mut bgp, "10.0.0.2", |cap_map| {
        let mut ours = BgpCap::default();
        for (afi, safi) in [(Afi::Ip, Safi::Unicast), (Afi::L2vpn, Safi::Evpn)] {
            ours.mp
                .insert(AfiSafi::new(afi, safi), CapMultiProtocol::new(&afi, &safi));
        }
        cap_register_send(&ours, cap_map);
        cap_register_recv(&BgpCap::default(), cap_map);
    });
    assert!(dump(&mut bgp, c).await, "the pool dumps IPv4 unicast");
    assert_eq!(
        sent_v4(&mut rx),
        (vec![PREFIX.to_string()], 1),
        "the route, then one IPv4 End-of-RIB"
    );
}

/// Under `suppress-fib-pending` main's cursor takes the dump from the pool
/// for a peer with IPv4 unicast. A peer without it gets neither.
#[tokio::test]
async fn an_evpn_only_neighbor_gets_no_cursor_under_suppress_fib_pending() {
    let mut bgp = sharded_bgp();
    bgp.local_rib.suppress_fib_pending = true;
    bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
    settle(&mut bgp).await;

    let (c, mut rx) = add_peer(&mut bgp, "10.0.0.2", &[(Afi::L2vpn, Safi::Evpn)]);
    assert!(!dump(&mut bgp, c).await, "the pool does not dump");
    assert!(
        bgp.peers.get_by_idx(c).unwrap().sync_v4.is_none(),
        "main's cursor does not either"
    );
    assert_eq!(sent_v4(&mut rx), (vec![], 0), "nothing in IPv4 unicast");
}

/// A dump still in the pool when its session ends is not completed: its
/// rows are not recorded and no End-of-RIB is sent. The acks are matched
/// to the session that started the dump, not to the peer alone, which may
/// be down, in a handshake or in its next session by then.
#[tokio::test]
async fn a_dump_whose_session_ended_is_not_completed() {
    let mut bgp = sharded_bgp();
    bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
    settle(&mut bgp).await;

    let (c, mut rx) = add_peer(&mut bgp, "10.0.0.2", &[(Afi::Ip, Safi::Unicast)]);
    assert!(bgp.broadcast_dump_v4(c).is_some(), "the pool dumps");
    end_session(&mut bgp, c);
    settle(&mut bgp).await;

    let peer = bgp.peers.get_by_idx(c).unwrap();
    assert_eq!(
        peer.adj_out.count(Afi::Ip, Safi::Unicast),
        0,
        "nothing is recorded for the session that ended"
    );
    assert_eq!(sent_v4(&mut rx).1, 0, "no End-of-RIB");
    assert!(
        bgp.pending_dumps_v4.inflight.is_empty(),
        "the acks are still counted down"
    );
}

/// The next session's dump is its own: the acks of the dump the ended
/// session left in the pool do not send an End-of-RIB on it.
#[tokio::test]
async fn the_next_session_runs_its_own_dump() {
    let mut bgp = sharded_bgp();
    bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
    settle(&mut bgp).await;

    let (c, mut rx) = add_peer(&mut bgp, "10.0.0.2", &[(Afi::Ip, Safi::Unicast)]);
    let first = bgp.broadcast_dump_v4(c).expect("the pool dumps");
    end_session(&mut bgp, c);

    // The neighbor is back before the first dump's acks are reduced.
    {
        let peer = bgp.peers.get_mut_by_idx(c).unwrap();
        let entry = peer
            .cap_map
            .entries
            .entry(CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast))
            .or_default();
        entry.send = true;
        entry.recv = true;
    }
    let second = bgp.broadcast_dump_v4(c).expect("the pool dumps again");
    assert_ne!(first, second);
    settle(&mut bgp).await;

    let peer = bgp.peers.get_by_idx(c).unwrap();
    assert_eq!(
        peer.adj_out.count(Afi::Ip, Safi::Unicast),
        1,
        "the second dump's row"
    );
    assert_eq!(peer.dump_v4_req, None, "the second dump completed");
    assert_eq!(sent_v4(&mut rx).1, 1, "one End-of-RIB, the second dump's");
}
