//! RFC 8950 IPv4 routes (an IPv6 next-hop, from an unnumbered neighbor)
//! were ingested on main even at N>1, where the worker pool owns IPv4
//! unicast. Withdraws, a session loss and a soft-in replay go to the pool,
//! which had none of these routes: a withdrawn route, every route of a
//! neighbor whose session went down, and a route the inbound policy now
//! denies all stayed in the Loc-RIB and the FIB. Every check runs at N=1
//! and N=2 and expects the same result.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::peer_key::PeerOrigin;
use crate::bgp::route::{route_clean, route_from_peer};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapExtendedNextHop, CapMultiProtocol,
    ExtendedNextHopValue, Ipv4Nlri, MpReachAttr, MpUnreachAttr, Origin, Safi, UpdatePacket,
};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const IFINDEX: u32 = 7;
/// The neighbor's link-local: the session address and the MP_REACH
/// next-hop.
const LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
/// Spread over both shards of the two-shard pool (checked by `prefixes`).
const PREFIXES: [&str; 4] = ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24"];

type RibRx = mpsc::UnboundedReceiver<crate::rib::client::RibInbound>;

/// A `Bgp` whose RIB messages the test reads, with an `n`-shard pool when
/// `n > 1`.
fn bgp_with(n: usize) -> (Bgp, RibRx) {
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
    if n > 1 {
        let (tx, rx) = mpsc::unbounded_channel();
        bgp.shards = Some(crate::bgp::shard::pool::ShardPool::spawn(
            (0..n).map(|_| Default::default()).collect(),
            tx,
        ));
        bgp.shard_results_rx = rx;
    }
    (bgp, inbound_rx)
}

fn enhe_cap() -> CapExtendedNextHop {
    CapExtendedNextHop::new(vec![ExtendedNextHopValue::new(
        Afi::Ip,
        Safi::Unicast,
        Afi::Ip6,
    )])
}

/// An Established unnumbered eBGP neighbor on interface [`IFINDEX`], with
/// the extended next-hop negotiated and soft-reconfiguration inbound on.
fn add_unnumbered(bgp: &mut Bgp) -> usize {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip = IpAddr::V6(LL);
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
    peer.origin = PeerOrigin::Interface { ifindex: IFINDEX };
    peer.scope_id = Some(IFINDEX);
    peer.cap_send.extended_nexthop = Some(enhe_cap());
    peer.cap_recv.extended_nexthop = Some(enhe_cap());
    peer.config.soft_reconfig_in = true;
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&V4.afi, &V4.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    let (ptx, prx) = mpsc::unbounded_channel();
    Box::leak(Box::new(prx));
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    assert!(bgp.peers.get_by_idx(id).unwrap().is_enhe_v4_negotiated());
    id
}

fn prefixes(bgp: &Bgp) -> Vec<Ipv4Net> {
    let p: Vec<Ipv4Net> = PREFIXES.iter().map(|s| s.parse().unwrap()).collect();
    if let Some(pool) = bgp.shards.as_ref() {
        let mut shards: Vec<usize> = p
            .iter()
            .map(|p| pool.shard_of(IpAddr::V4(p.addr())))
            .collect();
        shards.sort();
        shards.dedup();
        assert_eq!(shards.len(), pool.n(), "the prefixes reach every shard");
    }
    p
}

/// Run one UPDATE through the ingest, as the peer's FSM does, with
/// next-hop tracking on (the global instance's cache).
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

/// The neighbor announces `prefixes` over the extended next-hop. The
/// UPDATE also carries an IPv4 NEXT_HOP, which RFC 8950 §4 says to ignore:
/// tracked, it would be a fresh, unresolved next-hop that keeps the routes
/// out of the FIB.
fn announce(bgp: &mut Bgp, id: usize, prefixes: &[Ipv4Net]) {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65002").unwrap()),
        nexthop: Some(BgpNexthop::Ipv4(Ipv4Addr::new(10, 0, 0, 2))),
        ..Default::default()
    });
    packet.mp_update = Some(MpReachAttr::Ipv4 {
        snpa: 0,
        nhop: IpAddr::V6(LL),
        updates: prefixes
            .iter()
            .map(|p| Ipv4Nlri { id: 0, prefix: *p })
            .collect(),
    });
    ingest(bgp, id, packet);
}

/// The neighbor withdraws `prefix` in MP_UNREACH, as it does for a family
/// it announces in MP_REACH.
fn withdraw(bgp: &mut Bgp, id: usize, prefix: Ipv4Net) {
    let mut packet = UpdatePacket::new();
    packet.mp_withdraw = Some(MpUnreachAttr::Ipv4Nlri(vec![Ipv4Nlri { id: 0, prefix }]));
    ingest(bgp, id, packet);
}

/// The session leaves Established: the FSM's route clean-up.
fn session_down(bgp: &mut Bgp, id: usize) {
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
    route_clean(id, &mut top, &mut bgp.peers, bgp.shards.as_ref());
}

/// Main reduces every pool result for the work dispatched so far. Each
/// shard handles its messages in order and answers a barrier only after
/// the results of everything before it are on the channel. A no-op at N=1.
/// Returns the IPv4-unicast Adj-RIB-In rows the pool holds for `id`.
async fn settle(bgp: &mut Bgp, id: usize) -> usize {
    let Some(pool) = bgp.shards.as_ref() else {
        return 0;
    };
    let mut barriers = Vec::new();
    pool.broadcast(|| {
        let (reply, rx) = tokio::sync::oneshot::channel();
        barriers.push(rx);
        crate::bgp::shard::ShardMsg::CountAdjInV4All { reply }
    });
    let mut held = 0;
    for rx in barriers {
        let counts = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("the pool answers")
            .unwrap();
        held += counts.get(&id).copied().unwrap_or(0);
    }
    while let Ok(result) = bgp.shard_results_rx.try_recv() {
        bgp.process_shard_result(result);
    }
    held
}

/// The FIB and next-hop-tracking messages sent to the RIB since the last
/// call, sorted (the pool's shards reply in any order).
fn rib_msgs(rx: &mut RibRx) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(inbound) = rx.try_recv() {
        match inbound.msg {
            crate::rib::Message::Ipv4Add { prefix, rib } => out.push(match rib.nexthop {
                crate::rib::Nexthop::Uni(uni) => format!(
                    "add {prefix} via {} ifindex {:?}",
                    uni.addr, uni.ifindex_origin
                ),
                _ => format!("add {prefix} via a non-unicast next-hop"),
            }),
            crate::rib::Message::Ipv4Del { prefix, .. } => out.push(format!("del {prefix}")),
            crate::rib::Message::NexthopRegister { nh, .. } => out.push(format!("register {nh}")),
            _ => {}
        }
    }
    out.sort();
    out
}

fn installed(prefixes: &[Ipv4Net]) -> Vec<String> {
    prefixes
        .iter()
        .map(|p| format!("add {p} via {LL} ifindex Some({IFINDEX})"))
        .collect()
}

fn deleted(prefixes: &[Ipv4Net]) -> Vec<String> {
    prefixes.iter().map(|p| format!("del {p}")).collect()
}

/// The prefixes main's table (the read replica at N>1) has a best path
/// for, sorted.
fn selected(bgp: &Bgp) -> Vec<Ipv4Net> {
    bgp.shard.v4.1.iter().map(|(p, _)| p).collect()
}

/// An unnumbered neighbor's routes, learned and in the FIB.
async fn learned(n: usize) -> (Bgp, RibRx, usize, Vec<Ipv4Net>) {
    let (mut bgp, mut rx) = bgp_with(n);
    let id = add_unnumbered(&mut bgp);
    let p = prefixes(&bgp);
    announce(&mut bgp, id, &p);
    let held = settle(&mut bgp, id).await;
    assert_eq!(
        rib_msgs(&mut rx),
        installed(&p),
        "N={n}: each route is installed via the link-local, its IPv4 NEXT_HOP untracked"
    );
    if n > 1 {
        assert_eq!(held, p.len(), "N={n}: the pool holds the routes");
    }
    for prefix in &p {
        assert_eq!(
            bgp.shard.v4.1.get(prefix).and_then(|b| b.enhe_egress),
            Some((LL, IFINDEX)),
            "N={n}: {prefix}'s best path keeps the link-local egress"
        );
    }
    (bgp, rx, id, p)
}

#[tokio::test]
async fn unnumbered_routes_are_installed_via_the_link_local() {
    for n in [1, 2] {
        learned(n).await;
    }
}

#[tokio::test]
async fn a_withdrawn_unnumbered_route_leaves_the_fib() {
    for n in [1, 2] {
        let (mut bgp, mut rx, id, p) = learned(n).await;
        withdraw(&mut bgp, id, p[0]);
        let held = settle(&mut bgp, id).await;
        assert_eq!(
            rib_msgs(&mut rx),
            deleted(&p[..1]),
            "N={n}: the withdrawn route leaves the FIB"
        );
        assert_eq!(selected(&bgp), p[1..], "N={n}: the others stay selected");
        if n > 1 {
            assert_eq!(held, p.len() - 1, "N={n}: the pool drops the row");
        }
    }
}

#[tokio::test]
async fn a_session_loss_removes_the_unnumbered_routes() {
    for n in [1, 2] {
        let (mut bgp, mut rx, id, p) = learned(n).await;
        session_down(&mut bgp, id);
        let held = settle(&mut bgp, id).await;
        assert_eq!(
            rib_msgs(&mut rx),
            deleted(&p),
            "N={n}: every route leaves the FIB"
        );
        assert!(selected(&bgp).is_empty(), "N={n}: nothing stays selected");
        assert_eq!(held, 0, "N={n}: the pool drops the Adj-RIB-In");
    }
}

#[tokio::test]
async fn an_inbound_deny_removes_the_unnumbered_routes() {
    use crate::policy::{PolicyAction, PolicyList};
    for n in [1, 2] {
        let (mut bgp, mut rx, id, p) = learned(n).await;
        let mut deny = PolicyList::default();
        deny.entry(10).action = PolicyAction::Deny;
        let slot = bgp
            .peers
            .get_mut_by_idx(id)
            .unwrap()
            .policy_list_slot(V4, InOut::Input);
        slot.name = Some("IN".into());
        slot.policy_list = Some(deny);
        // A policy resolve: replicate the snapshot, then replay Adj-RIB-In.
        bgp.shard_replace_in_policy(id);
        crate::bgp::peer::apply_soft_in_peer(&mut bgp, id);
        settle(&mut bgp, id).await;
        assert_eq!(
            rib_msgs(&mut rx),
            deleted(&p),
            "N={n}: the denied routes leave the FIB"
        );
        assert!(selected(&bgp).is_empty(), "N={n}: nothing stays selected");
    }
}
