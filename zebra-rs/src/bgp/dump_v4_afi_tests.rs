//! At N>1 the session-up IPv4-unicast dump runs in the pool
//! (`broadcast_dump_v4`), not in `route_sync`. `route_sync` sends IPv4
//! unicast only to a peer that negotiated it; the pool dump sent the IPv4
//! table, and its End-of-RIB, to every peer — an EVPN-only overlay session
//! included.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::route_sync;
use crate::rib::RibType;
use bgp_packet::{Afi, BgpPacket, CapMultiProtocol, MpReachAttr, ParseOption, Safi};
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
