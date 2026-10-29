//! At N>1 the worker pool owns the IPv4-unicast Loc-RIB and main's shard
//! is only its read replica. A redistributed IPv4 route was written to the
//! replica, as `network` was before `OriginateV4`: the pool's session-up
//! dump never sent it to a neighbor that came up later, and the pool picked
//! a peer's path over it, as if it were not there.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{BgpRib, BgpRibType, ORIGINATED_PEER, route_sync};
use crate::rib::RibType;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, MpReachAttr, Origin,
    ParseOption, Safi,
};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
/// The redistributed prefix.
const PREFIX: &str = "10.40.1.0/24";
/// The source of a peer-learned path: not a configured neighbor.
const SOURCE: usize = 1000;

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

/// An Established eBGP neighbor at `addr`, in its update group.
fn add_peer(bgp: &mut Bgp, addr: &str) -> (usize, Rx) {
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
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&V4.afi, &V4.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
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
/// `route_sync`, then the pool's broadcast, its acks reduced.
async fn dump(bgp: &mut Bgp, c: usize) {
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
    bgp.broadcast_dump_v4(c)
        .expect("the pool dumps IPv4 unicast");
    let mut acks = bgp.shards.as_ref().unwrap().n();
    while acks > 0 {
        let result = tokio::time::timeout(Duration::from_secs(5), bgp.shard_results_rx.recv())
            .await
            .expect("the pool acks the dump")
            .unwrap();
        acks -= result
            .out
            .iter()
            .filter(|o| matches!(o, crate::bgp::shard::ShardOut::DumpDoneV4 { .. }))
            .count();
        bgp.process_shard_result(result);
    }
}

/// The IPv4 prefixes the neighbor was sent, sorted.
fn sent(rx: &mut Rx) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, true, Some(ParseOption::default()))
            .expect("a well-formed UPDATE");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        if let Some(MpReachAttr::Ipv4 { updates, .. }) = &update.mp_update {
            out.extend(updates.iter().map(|n| n.prefix.to_string()));
        }
        out.extend(update.ipv4_update.iter().map(|n| n.prefix.to_string()));
    }
    out.sort();
    out
}

/// [`SOURCE`]'s UPDATE for [`PREFIX`], ingested by the pool shard that owns
/// it, as the N>1 ingest sends it.
fn learn_in_pool(bgp: &Bgp) {
    use crate::bgp::shard::msg::ShardUpdateV4;
    let prefix: Ipv4Net = PREFIX.parse().unwrap();
    let attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65100").unwrap()),
        nexthop: Some(BgpNexthop::Ipv4(Ipv4Addr::new(10, 0, 0, 100))),
        ..Default::default()
    };
    let pool = bgp.shards.as_ref().unwrap();
    pool.dispatch(
        pool.shard_of(IpAddr::V4(prefix.addr())),
        crate::bgp::shard::ShardMsg::UpdateV4(ShardUpdateV4 {
            ident: SOURCE,
            rd: None,
            nlri: bgp_packet::Ipv4Nlri { id: 0, prefix },
            peer_router_id: Ipv4Addr::new(10, 0, 0, 100),
            typ: BgpRibType::EBGP,
            from_client: false,
            attr,
            label: None,
            nexthop: None,
            enhe_egress: None,
            stale: false,
            nexthop_reachable: true,
            vrf_transit_only: false,
            decision: None,
            compute_policy: true,
        }),
    );
}

/// The best path main's replica holds for [`PREFIX`].
fn best(bgp: &Bgp) -> Option<BgpRib> {
    bgp.shard.v4.1.get(&PREFIX.parse().unwrap()).cloned()
}

#[tokio::test]
async fn a_neighbor_that_comes_up_later_learns_a_redistributed_route() {
    let mut bgp = sharded_bgp();
    bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
    settle(&mut bgp).await;
    assert!(
        best(&bgp).is_some_and(|b| b.ident == ORIGINATED_PEER),
        "the replica shows the redistributed route"
    );

    let (c, mut rx) = add_peer(&mut bgp, "10.0.0.2");
    dump(&mut bgp, c).await;
    assert_eq!(
        sent(&mut rx),
        vec![PREFIX.to_string()],
        "the session-up dump sends the redistributed route"
    );
}

#[tokio::test]
async fn a_redistributed_route_outranks_a_peer_path_learned_later() {
    let mut bgp = sharded_bgp();
    bgp.route_redist_inject(RibType::Static, PREFIX.parse().unwrap(), 10);
    settle(&mut bgp).await;
    learn_in_pool(&bgp);
    settle(&mut bgp).await;
    let best = best(&bgp).expect("a best path");
    assert_eq!(
        (best.ident, best.typ),
        (ORIGINATED_PEER, BgpRibType::Originated),
        "the redistributed route (weight 32768) stays best"
    );
    assert_eq!(
        best.attr.med.as_ref().map(|m| m.med),
        Some(10),
        "the route carries the redistributed metric as its MED"
    );
}

#[tokio::test]
async fn a_withdrawn_redistributed_route_is_not_sent_to_a_neighbor_that_comes_up_later() {
    let mut bgp = sharded_bgp();
    let prefix: Ipv4Net = PREFIX.parse().unwrap();
    bgp.route_redist_inject(RibType::Static, prefix, 10);
    settle(&mut bgp).await;
    bgp.route_redist_withdraw(RibType::Static, prefix);
    settle(&mut bgp).await;
    assert!(best(&bgp).is_none(), "the replica drops the route");

    let (c, mut rx) = add_peer(&mut bgp, "10.0.0.2");
    dump(&mut bgp, c).await;
    assert!(
        sent(&mut rx).is_empty(),
        "the session-up dump has nothing to send"
    );
}

#[tokio::test]
async fn a_withdraw_of_another_source_leaves_the_redistributed_route() {
    let mut bgp = sharded_bgp();
    let prefix: Ipv4Net = PREFIX.parse().unwrap();
    bgp.route_redist_inject(RibType::Static, prefix, 10);
    settle(&mut bgp).await;
    // `route_redist_del` withdraws each RouteDel from every family; this
    // source was never redistributed into this one.
    bgp.route_redist_withdraw(RibType::Connected, prefix);
    settle(&mut bgp).await;

    let (c, mut rx) = add_peer(&mut bgp, "10.0.0.2");
    dump(&mut bgp, c).await;
    assert_eq!(
        sent(&mut rx),
        vec![PREFIX.to_string()],
        "the static route is still there to send"
    );
}
