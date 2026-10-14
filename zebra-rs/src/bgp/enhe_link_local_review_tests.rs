//! Review finding #29: an unnumbered (interface) neighbor that negotiated
//! the RFC 8950 extended next-hop for IPv4 unicast is sent IPv4 routes with
//! our IPv6 link-local on its interface as the next-hop — which BGP knows
//! only once the RIB has reported that address.
//!
//! Until then the update-group flush skips the member (no garbage next-hop)
//! but the advertise path has already recorded the route as sent, and the
//! address arriving later (`RibRx::AddrAdd`) only updated the address
//! table: the member never got the route until it changed again. The
//! direct sends — the session-up dump and its chunked form — fell back to
//! the legacy encoding instead, with our router-id as the IPv4 NEXT_HOP,
//! which an unnumbered neighbor cannot reach.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::peer_key::PeerOrigin;
use crate::bgp::route::{
    BgpRib, BgpRibType, Ipv4SyncCursor, route_advertise_to_peers, route_sync_ipv4,
    route_sync_v4_chunk,
};
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapExtendedNextHop, CapMultiProtocol,
    ExtendedNextHopValue, MpReachAttr, Origin, ParseOption, Safi,
};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const IFINDEX: u32 = 7;
const OUR_LL: &str = "fe80::1";
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
const P: &str = "10.29.1.0/24";
/// The source of the Loc-RIB route: not the peer under test.
const SOURCE: usize = 1000;

type Rx = mpsc::UnboundedReceiver<bytes::BytesMut>;

fn fresh_bgp() -> Bgp {
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
    bgp
}

/// A reachable eBGP route learned from [`SOURCE`].
fn source_rib() -> BgpRib {
    let attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65100").unwrap()),
        nexthop: Some(BgpNexthop::Ipv4(Ipv4Addr::new(10, 0, 0, 100))),
        ..Default::default()
    };
    let mut rib = BgpRib::new(
        SOURCE,
        Ipv4Addr::new(10, 0, 0, 100),
        BgpRibType::EBGP,
        0,
        0,
        &attr,
        None,
        None,
        false,
    );
    rib.nexthop_reachable = true;
    rib
}

/// Put `P` in the IPv4-unicast Loc-RIB, learned from [`SOURCE`].
fn put(bgp: &mut Bgp) {
    bgp.shard.v4.update(P.parse().unwrap(), source_rib());
}

fn enhe_cap() -> CapExtendedNextHop {
    CapExtendedNextHop::new(vec![ExtendedNextHopValue::new(
        Afi::Ip,
        Safi::Unicast,
        Afi::Ip6,
    )])
}

/// An Established eBGP neighbor in its update group: an unnumbered one on
/// interface [`IFINDEX`] with the extended next-hop negotiated when `enhe`,
/// a numbered IPv4 one otherwise.
fn add_peer(bgp: &mut Bgp, enhe: bool) -> (usize, Rx) {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = if enhe {
        "fe80::2".parse().unwrap()
    } else {
        "10.0.0.2".parse().unwrap()
    };
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
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&V4.afi, &V4.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    if enhe {
        peer.origin = PeerOrigin::Interface { ifindex: IFINDEX };
        peer.scope_id = Some(IFINDEX);
        peer.cap_send.extended_nexthop = Some(enhe_cap());
        peer.cap_recv.extended_nexthop = Some(enhe_cap());
    } else {
        peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    }
    let (ptx, prx) = mpsc::unbounded_channel();
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    bgp.peers.membership_enroll(id);
    crate::bgp::update_group::attach(&mut bgp.update_groups, &mut bgp.peers, id, ROUTER_ID, false);
    assert_eq!(
        bgp.peers.get_by_idx(id).unwrap().is_enhe_v4_negotiated(),
        enhe
    );
    (id, prx)
}

/// The RIB reports our link-local on [`IFINDEX`].
fn link_local_appears(bgp: &mut Bgp) {
    bgp.process_rib_msg(RibRx::AddrAdd(LinkAddr {
        addr: format!("{OUR_LL}/64").parse().unwrap(),
        ifindex: IFINDEX,
        ..Default::default()
    }));
}

fn split(bgp: &mut Bgp) -> (BgpTop<'_>, &mut PeerMap) {
    (
        BgpTop {
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
        },
        &mut bgp.peers,
    )
}

/// The event-driven advertise of `P`, then the update group's flush, run
/// to completion.
fn advertise_and_flush(bgp: &mut Bgp, c: usize) {
    let prefix: Ipv4Net = P.parse().unwrap();
    let selected = vec![bgp.shard.v4.1.get(&prefix).unwrap().clone()];
    {
        let (mut top, peers) = split(bgp);
        route_advertise_to_peers(None, prefix, &selected, SOURCE, &mut top, peers);
    }
    let gid = bgp.peers.get_by_idx(c).unwrap().update_group_id[&V4].clone();
    let group = bgp
        .update_groups
        .get_mut(&V4)
        .unwrap()
        .group_by_id_mut(&gid)
        .unwrap();
    if let Some(job) =
        crate::bgp::update_group::build_flush_job_ipv4(group, &bgp.peers, &bgp.interface_addrs)
    {
        job.run();
    }
}

/// How each IPv4 route reached the neighbor.
#[derive(Debug, PartialEq)]
enum Sent {
    /// MP_REACH (RFC 8950) with this IPv6 next-hop.
    Enhe(String, IpAddr),
    /// The legacy NLRI field with this IPv4 NEXT_HOP.
    Legacy(String, Option<Ipv4Addr>),
}

fn sent(rx: &mut Rx) -> Vec<Sent> {
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, true, Some(ParseOption::default()))
            .expect("a well-formed UPDATE");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        if let Some(MpReachAttr::Ipv4 { nhop, updates, .. }) = &update.mp_update {
            out.extend(
                updates
                    .iter()
                    .map(|n| Sent::Enhe(n.prefix.to_string(), *nhop)),
            );
        }
        let legacy_nh = update.bgp_attr.as_ref().and_then(|a| match a.nexthop {
            Some(BgpNexthop::Ipv4(v4)) => Some(v4),
            _ => None,
        });
        out.extend(
            update
                .ipv4_update
                .iter()
                .map(|n| Sent::Legacy(n.prefix.to_string(), legacy_nh)),
        );
    }
    out
}

fn enhe_sent() -> Vec<Sent> {
    vec![Sent::Enhe(
        P.to_string(),
        IpAddr::V6(Ipv6Addr::from_str(OUR_LL).unwrap()),
    )]
}

/// The flush skips the member while our link-local on its interface is
/// unknown; once the RIB reports it, the member is sent the route it was
/// skipped for, with that next-hop. It was not: the route stayed recorded
/// as sent.
#[tokio::test]
async fn a_member_skipped_for_want_of_a_link_local_is_sent_the_route_once_one_appears() {
    let mut bgp = fresh_bgp();
    put(&mut bgp);
    let (c, mut rx) = add_peer(&mut bgp, true);
    advertise_and_flush(&mut bgp, c);
    assert_eq!(sent(&mut rx), vec![], "no link-local yet: nothing sent");

    link_local_appears(&mut bgp);
    assert_eq!(sent(&mut rx), enhe_sent());
}

/// The session-up dump to an extended-next-hop neighbor with no link-local
/// known sends no route with an IPv4 NEXT_HOP — our router-id, which an
/// unnumbered neighbor cannot reach — and the route goes out once the
/// link-local is reported.
#[tokio::test]
async fn the_session_up_dump_waits_for_the_link_local() {
    let mut bgp = fresh_bgp();
    put(&mut bgp);
    let (c, mut rx) = add_peer(&mut bgp, true);
    {
        let (mut top, peers) = split(&mut bgp);
        route_sync_ipv4(peers.get_mut_by_idx(c).unwrap(), &mut top);
    }
    assert_eq!(sent(&mut rx), vec![], "no route with a legacy next-hop");

    link_local_appears(&mut bgp);
    assert_eq!(sent(&mut rx), enhe_sent());
}

/// The same for the chunked session-up dump (`ZEBRA_BGP_SYNC_CHUNK`).
#[tokio::test]
async fn the_chunked_session_up_dump_waits_for_the_link_local() {
    let mut bgp = fresh_bgp();
    put(&mut bgp);
    let (c, mut rx) = add_peer(&mut bgp, true);
    bgp.peers.get_mut_by_idx(c).unwrap().sync_v4 =
        Some(Ipv4SyncCursor::new(vec![P.parse().unwrap()], false));
    loop {
        let (mut top, peers) = split(&mut bgp);
        if route_sync_v4_chunk(peers.get_mut_by_idx(c).unwrap(), &mut top, 1) {
            break;
        }
    }
    assert_eq!(sent(&mut rx), vec![], "no route with a legacy next-hop");

    link_local_appears(&mut bgp);
    assert_eq!(sent(&mut rx), enhe_sent());
}

/// Control: with the link-local already known, the flush sends the route
/// with it as the next-hop, and a later address event re-sends nothing.
#[tokio::test]
async fn with_the_link_local_known_the_route_goes_out_once() {
    let mut bgp = fresh_bgp();
    put(&mut bgp);
    let (c, mut rx) = add_peer(&mut bgp, true);
    link_local_appears(&mut bgp);
    advertise_and_flush(&mut bgp, c);
    assert_eq!(sent(&mut rx), enhe_sent());

    link_local_appears(&mut bgp);
    assert_eq!(sent(&mut rx), vec![], "the next-hop did not change");
}

/// Control: a numbered IPv4 neighbor is untouched by IPv6 address events.
#[tokio::test]
async fn a_numbered_neighbor_ignores_link_local_events() {
    let mut bgp = fresh_bgp();
    put(&mut bgp);
    let (c, mut rx) = add_peer(&mut bgp, false);
    advertise_and_flush(&mut bgp, c);
    assert_eq!(
        sent(&mut rx),
        vec![Sent::Legacy(
            P.to_string(),
            Some(Ipv4Addr::new(10, 0, 0, 99))
        )]
    );
    link_local_appears(&mut bgp);
    assert_eq!(sent(&mut rx), vec![]);
}

// -------------------------------------------------------------------------
// The gate-on egress engines (`ZEBRA_BGP_PEER_TASK`, the per-peer egress
// task; `ZEBRA_BGP_EGRESS_GROUP_TASK`, the per-group engine). Each gate
// switches one on in a child test process — the switches are process-wide
// and read once — and brings the session up through the real Established
// transition, so the engine is spawned and fed as in a running daemon.
// -------------------------------------------------------------------------

/// Run the calling test's body in a child process with `env` set; returns
/// true in the child (run the body), false in the parent once the child
/// passed.
fn in_child(name: &str, env: (&str, &str)) -> bool {
    if std::env::var_os("ENHE_REVIEW_CHILD").is_some() {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("bgp::inst::enhe_link_local_review_tests::{name}"),
            "--nocapture",
        ])
        .env("ENHE_REVIEW_CHILD", "1")
        .env(env.0, env.1)
        .env_remove("ZEBRA_BGP_SYNC_CHUNK")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

const P2: &str = "10.29.2.0/24";

/// Put `prefix` in the Loc-RIB from [`SOURCE`] and run the event-driven
/// advertise for it — which, with an engine on, is a delta to the engine.
fn announce(bgp: &mut Bgp, prefix: &str) {
    let prefix: Ipv4Net = prefix.parse().unwrap();
    bgp.shard.v4.update(prefix, source_rib());
    let selected = vec![bgp.shard.v4.1.get(&prefix).unwrap().clone()];
    let (mut top, peers) = split(bgp);
    route_advertise_to_peers(None, prefix, &selected, SOURCE, &mut top, peers);
}

/// The unnumbered neighbor's session comes up through the FSM (from
/// OpenConfirm), as in a running daemon: the engine is spawned or joined,
/// and the session-up dump runs.
fn session_comes_up(bgp: &mut Bgp) -> (usize, Rx) {
    let (c, rx) = add_peer(bgp, true);
    crate::bgp::update_group::detach(&mut bgp.update_groups, &mut bgp.peers, c);
    bgp.peers.membership_withdraw(c);
    let peer = bgp.peers.get_mut_by_idx(c).unwrap();
    peer.state = State::OpenConfirm;
    peer.primary_conn_id = Some(29);
    let (mut top, peers) = split(bgp);
    crate::bgp::peer::fsm(
        &mut top,
        peers,
        c,
        crate::bgp::peer::Event::KeepAliveMsg(29),
        None,
    );
    assert_eq!(bgp.peers.get_by_idx(c).unwrap().state, State::Established);
    (c, rx)
}

/// Wait until neighbor `c`'s engine has handled every delta sent so far.
async fn engine_settled(bgp: &Bgp, c: usize) {
    let peer = bgp.peers.get_by_idx(c).unwrap();
    if let Some(pet) = peer.pet.as_ref() {
        let (reply, rx) = tokio::sync::oneshot::channel();
        pet.delta_tx
            .send(crate::bgp::peer_egress::EgressDeltaV4::DumpAdjOut { reply })
            .unwrap();
        rx.await.unwrap();
    }
    if let Some(gid) = peer.update_group_id.get(&V4)
        && let Some(task) = bgp.update_groups[&V4]
            .group_by_id(gid)
            .and_then(|g| g.task.as_ref())
    {
        task.request_adj_out().await.unwrap();
    }
}

fn enhe_of(prefix: &str) -> Sent {
    Sent::Enhe(
        prefix.to_string(),
        IpAddr::V6(Ipv6Addr::from_str(OUR_LL).unwrap()),
    )
}

/// With the link-local known, the engine sends the unnumbered neighbor the
/// route with it as the next-hop. The engines never built an extended
/// next-hop: the route went out with our router-id as the IPv4 NEXT_HOP.
async fn check_engine_sends_the_link_local(name: &str, env: (&str, &str)) {
    if !in_child(name, env) {
        return;
    }
    let mut bgp = fresh_bgp();
    link_local_appears(&mut bgp);
    let (c, mut rx) = session_comes_up(&mut bgp);
    engine_settled(&bgp, c).await;
    sent(&mut rx);
    announce(&mut bgp, P2);
    engine_settled(&bgp, c).await;
    assert_eq!(sent(&mut rx), vec![enhe_of(P2)]);
}

/// With no link-local known when the session comes up, the engine sends
/// nothing (no IPv4 NEXT_HOP); once the link-local is reported, it sends
/// what it held back — the session-up route and the one announced since.
async fn check_engine_catches_up(name: &str, env: (&str, &str)) {
    if !in_child(name, env) {
        return;
    }
    let mut bgp = fresh_bgp();
    put(&mut bgp);
    let (c, mut rx) = session_comes_up(&mut bgp);
    announce(&mut bgp, P2);
    engine_settled(&bgp, c).await;
    assert_eq!(sent(&mut rx), vec![], "no link-local yet: nothing sent");

    link_local_appears(&mut bgp);
    engine_settled(&bgp, c).await;
    let mut got = sent(&mut rx);
    got.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(got, vec![enhe_of(P), enhe_of(P2)]);
}

#[tokio::test]
async fn the_peer_egress_task_sends_the_link_local_next_hop() {
    check_engine_sends_the_link_local(
        "the_peer_egress_task_sends_the_link_local_next_hop",
        ("ZEBRA_BGP_PEER_TASK", "1"),
    )
    .await;
}

#[tokio::test]
async fn the_peer_egress_task_catches_up_once_the_link_local_appears() {
    check_engine_catches_up(
        "the_peer_egress_task_catches_up_once_the_link_local_appears",
        ("ZEBRA_BGP_PEER_TASK", "1"),
    )
    .await;
}

#[tokio::test]
async fn the_group_engine_sends_the_link_local_next_hop() {
    check_engine_sends_the_link_local(
        "the_group_engine_sends_the_link_local_next_hop",
        ("ZEBRA_BGP_EGRESS_GROUP_TASK", "1"),
    )
    .await;
}

#[tokio::test]
async fn the_group_engine_catches_up_once_the_link_local_appears() {
    check_engine_catches_up(
        "the_group_engine_catches_up_once_the_link_local_appears",
        ("ZEBRA_BGP_EGRESS_GROUP_TASK", "1"),
    )
    .await;
}

// -------------------------------------------------------------------------
// The sharded session-up dump (`DumpV4`, N>1 pool shards) is built with the
// extended next-hop main resolved when it broadcast the dump. An address
// event while the dump is in flight re-sends the Adj-RIB-Out as it stands,
// which lacks the dump's rows: main records them only as the shards' acks
// arrive (reviewer follow-up on #29).
// -------------------------------------------------------------------------

/// A two-shard pool with `P` in the first shard's slice of the Loc-RIB.
fn sharded(bgp: &mut Bgp) {
    let mut shard = crate::bgp::shard::BgpShard::default();
    shard.v4.update(P.parse().unwrap(), source_rib());
    let (tx, rx) = mpsc::unbounded_channel();
    bgp.shards = Some(crate::bgp::shard::pool::ShardPool::spawn(
        vec![shard, Default::default()],
        tx,
    ));
    bgp.shard_results_rx = rx;
}

/// Main takes both shards' acks of the dump.
async fn dump_completes(bgp: &mut Bgp) {
    for _ in 0..2 {
        let result = bgp.shard_results_rx.recv().await.unwrap();
        bgp.process_shard_result(result);
    }
}

/// The link-local is reported while the dump, held back for want of it, is
/// in flight: the dump's route goes out once the dump completes. It was
/// only recorded — the address event had already re-sent an Adj-RIB-Out
/// without it, and a later event finds the next-hop unchanged.
#[tokio::test]
async fn a_sharded_dump_in_flight_when_the_link_local_appears_is_sent() {
    let mut bgp = fresh_bgp();
    let (c, mut rx) = add_peer(&mut bgp, true);
    sharded(&mut bgp);
    bgp.broadcast_dump_v4(c).unwrap();
    link_local_appears(&mut bgp);
    dump_completes(&mut bgp).await;
    assert_eq!(sent(&mut rx), enhe_sent());
}

/// Control: with the link-local known before the dump, the shard sends the
/// route with it and the dump's completion sends nothing more.
#[tokio::test]
async fn a_sharded_dump_with_the_link_local_known_sends_once() {
    let mut bgp = fresh_bgp();
    let (c, mut rx) = add_peer(&mut bgp, true);
    link_local_appears(&mut bgp);
    sharded(&mut bgp);
    bgp.broadcast_dump_v4(c).unwrap();
    dump_completes(&mut bgp).await;
    assert_eq!(sent(&mut rx), enhe_sent());
}

/// The same race with the egress engine on: the dump's rows reach the
/// engine as record-only after it re-sent its Adj-RIB-Out for the address
/// event.
async fn check_engine_sends_a_sharded_dump_in_flight(name: &str, env: (&str, &str)) {
    if !in_child(name, env) {
        return;
    }
    let mut bgp = fresh_bgp();
    let (c, mut rx) = session_comes_up(&mut bgp);
    engine_settled(&bgp, c).await;
    sent(&mut rx);
    sharded(&mut bgp);
    bgp.broadcast_dump_v4(c).unwrap();
    link_local_appears(&mut bgp);
    dump_completes(&mut bgp).await;
    engine_settled(&bgp, c).await;
    assert_eq!(sent(&mut rx), vec![enhe_of(P)]);
}

#[tokio::test]
async fn the_peer_egress_task_sends_a_sharded_dump_in_flight() {
    check_engine_sends_a_sharded_dump_in_flight(
        "the_peer_egress_task_sends_a_sharded_dump_in_flight",
        ("ZEBRA_BGP_PEER_TASK", "1"),
    )
    .await;
}

#[tokio::test]
async fn the_group_engine_sends_a_sharded_dump_in_flight() {
    check_engine_sends_a_sharded_dump_in_flight(
        "the_group_engine_sends_a_sharded_dump_in_flight",
        ("ZEBRA_BGP_EGRESS_GROUP_TASK", "1"),
    )
    .await;
}
