//! Review finding #25: with an egress engine running — the per-peer egress
//! task (PET, `router bgp sharding peer-sharding true`) or the per-group
//! engine (`ZEBRA_BGP_EGRESS_GROUP_TASK=1`) — a route a peer learned from
//! the session-up dump must be recorded in that engine's Adj-RIB-Out.
//!
//! At that point every IPv4-unicast withdraw for the peer goes through the
//! engine, which sends one only for a route it recorded. The N=1 dump
//! (`route_sync_ipv4`) recorded the group engine and the peer's own
//! Adj-RIB-Out but never the PET, so with the PET every route the peer
//! learned from the dump could never be withdrawn (and `advertised-routes`
//! did not list it). The chunked dump (`ZEBRA_BGP_SYNC_CHUNK`,
//! `route_sync_v4_chunk`) recorded neither engine. The N>1 dump (`DumpV4`)
//! records whichever engine runs.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::peer_egress::{EgressDeltaV4, PeerEgressTask};
use crate::bgp::route::{BgpRib, BgpRibType, Ipv4SyncCursor, route_sync_ipv4, route_sync_v4_chunk};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, Origin, ParseOption,
    Safi,
};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::sync::{mpsc, oneshot};

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
const P1: &str = "10.25.1.0/24";
const P2: &str = "10.25.2.0/24";
/// The source of the Loc-RIB routes: not the peer under test (split
/// horizon would keep them from it).
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
    bgp.router_id = ROUTER_ID;
    bgp
}

/// Put `prefix` in the IPv4-unicast Loc-RIB, learned from [`SOURCE`].
fn put(bgp: &mut Bgp, prefix: &str) {
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
    let prefix: Ipv4Net = prefix.parse().unwrap();
    bgp.shard.v4.update(prefix, rib);
    assert!(bgp.shard.v4.1.contains_key(&prefix), "setup: selected");
}

/// An Established eBGP peer with IPv4 unicast, in its update group, whose
/// packets land on the returned receiver.
fn add_peer(bgp: &mut Bgp) -> (usize, Rx) {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = "10.0.0.4".parse().unwrap();
    let mut peer = Peer::new(
        0,
        65000,
        ROUTER_ID,
        65004,
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
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    let (ptx, prx) = mpsc::unbounded_channel();
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    bgp.peers.membership_enroll(id);
    crate::bgp::update_group::attach(&mut bgp.update_groups, &mut bgp.peers, id, ROUTER_ID, false);
    (id, prx)
}

/// Give peer `c` its per-peer egress task, as the FSM does at Established
/// with `peer-sharding` on.
fn spawn_pet(bgp: &mut Bgp, c: usize) {
    let peer = bgp.peers.get_mut_by_idx(c).unwrap();
    let ctx = peer.sync_ctx(ROUTER_ID, false);
    peer.pet = Some(PeerEgressTask::spawn(ctx, false));
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
            central_label_alloc: None,
            as_sets_withdraw: bgp.as_sets_withdraw,
        },
        &mut bgp.peers,
    )
}

/// The session-up dump, all at once.
fn dump(bgp: &mut Bgp, c: usize) {
    let (mut top, peers) = split(bgp);
    route_sync_ipv4(peers.get_mut_by_idx(c).unwrap(), &mut top);
}

/// The session-up dump through the resumable cursor, one prefix a chunk.
fn dump_chunked(bgp: &mut Bgp, c: usize) {
    let keys: Vec<Ipv4Net> = bgp.shard.v4.1.iter().map(|(p, _)| p).collect();
    bgp.peers.get_mut_by_idx(c).unwrap().sync_v4 = Some(Ipv4SyncCursor::new(keys, false));
    loop {
        let (mut top, peers) = split(bgp);
        if route_sync_v4_chunk(peers.get_mut_by_idx(c).unwrap(), &mut top, 1) {
            break;
        }
    }
}

/// The prefixes peer `c`'s egress task holds in its Adj-RIB-Out. Its
/// reply also means every delta sent before has been handled.
async fn pet_adj_out(bgp: &Bgp, c: usize) -> Vec<String> {
    let (reply, rx) = oneshot::channel();
    let pet = bgp.peers.get_by_idx(c).unwrap().pet.as_ref().unwrap();
    pet.delta_tx
        .send(EgressDeltaV4::DumpAdjOut { reply })
        .unwrap();
    rx.await
        .unwrap()
        .into_iter()
        .map(|(p, _)| p.to_string())
        .collect()
}

/// The prefixes peer `c`'s update group engine holds in its Adj-RIB-Out.
async fn group_adj_out(bgp: &Bgp, c: usize) -> Vec<String> {
    let gid = bgp.peers.get_by_idx(c).unwrap().update_group_id[&V4].clone();
    let rx = bgp.update_groups[&V4]
        .group_by_id(&gid)
        .unwrap()
        .task
        .as_ref()
        .unwrap()
        .request_adj_out();
    rx.await
        .unwrap()
        .into_iter()
        .map(|(p, _)| p.to_string())
        .collect()
}

/// Every IPv4 prefix withdrawn in the packets peer `c` was sent.
fn withdrawn(rx: &mut Rx) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, true, Some(ParseOption::default()))
            .expect("a well-formed UPDATE");
        if let BgpPacket::Update(update) = packet {
            out.extend(update.ipv4_withdraw.iter().map(|n| n.prefix.to_string()));
        }
    }
    out
}

fn both() -> Vec<String> {
    vec![P1.to_string(), P2.to_string()]
}

/// Review follow-up: the real Established transition runs the session-up
/// dump before the peer joins its update group, so the dump could not
/// record into the group's engine — the first member of a new group was
/// never withdrawn a route it learned from the dump. The rows are recorded
/// when the peer joins; the group's later withdraw reaches it. The group
/// engine's gate is process-wide and read once, so this runs in a child
/// test process with `ZEBRA_BGP_EGRESS_GROUP_TASK=1`.
#[tokio::test]
async fn the_session_up_dump_is_recorded_in_the_group_engine_the_peer_joins() {
    const NAME: &str = "bgp::inst::pet_sync_review_tests::the_session_up_dump_is_recorded_in_the_group_engine_the_peer_joins";
    if std::env::var_os("PET_SYNC_REVIEW_GROUP_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("PET_SYNC_REVIEW_GROUP_CHILD", "1")
            .env("ZEBRA_BGP_EGRESS_GROUP_TASK", "1")
            .env_remove("ZEBRA_BGP_SYNC_CHUNK")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut bgp = fresh_bgp();
    put(&mut bgp, P1);
    let (c, mut rx) = add_peer(&mut bgp);
    // Back to OpenConfirm, out of its group, as a session about to come up.
    crate::bgp::update_group::detach(&mut bgp.update_groups, &mut bgp.peers, c);
    bgp.peers.membership_withdraw(c);
    let peer = bgp.peers.get_mut_by_idx(c).unwrap();
    peer.state = State::OpenConfirm;
    peer.primary_conn_id = Some(25);
    let (mut top, peers) = split(&mut bgp);
    crate::bgp::peer::fsm(
        &mut top,
        peers,
        c,
        crate::bgp::peer::Event::KeepAliveMsg(25),
        None,
    );
    assert_eq!(bgp.peers.get_by_idx(c).unwrap().state, State::Established);
    assert_eq!(group_adj_out(&bgp, c).await, vec![P1.to_string()]);
    while rx.try_recv().is_ok() {}

    let gid = bgp.peers.get_by_idx(c).unwrap().update_group_id[&V4].clone();
    bgp.update_groups[&V4]
        .group_by_id(&gid)
        .unwrap()
        .task
        .as_ref()
        .unwrap()
        .send(crate::bgp::group_egress::GroupEgressDeltaV4::Withdraw {
            prefix: P1.parse().unwrap(),
            id: 0,
        });
    assert_eq!(group_adj_out(&bgp, c).await, Vec::<String>::new());
    // Packed withdrawals flush a moment after the burst settles.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(withdrawn(&mut rx), vec![P1.to_string()]);
}

/// The session-up dump records the routes it sends in the peer's egress
/// task — the Adj-RIB-Out every later withdraw and `advertised-routes`
/// read. It recorded none.
#[tokio::test]
async fn the_session_up_dump_records_its_routes_in_the_peer_egress_task() {
    let mut bgp = fresh_bgp();
    put(&mut bgp, P1);
    put(&mut bgp, P2);
    let (c, _rx) = add_peer(&mut bgp);
    spawn_pet(&mut bgp, c);
    dump(&mut bgp, c);
    assert_eq!(pet_adj_out(&bgp, c).await, both());
}

/// The consequence: a route the peer learned from the dump is withdrawn
/// when its task is told the route is gone. It sent nothing.
#[tokio::test]
async fn a_route_from_the_session_up_dump_is_withdrawn_through_the_peer_egress_task() {
    let mut bgp = fresh_bgp();
    put(&mut bgp, P1);
    put(&mut bgp, P2);
    let (c, mut rx) = add_peer(&mut bgp);
    spawn_pet(&mut bgp, c);
    dump(&mut bgp, c);
    pet_adj_out(&bgp, c).await;
    assert_eq!(withdrawn(&mut rx), Vec::<String>::new(), "setup");

    let pet = bgp.peers.get_by_idx(c).unwrap().pet.as_ref().unwrap();
    pet.delta_tx
        .send(EgressDeltaV4::Withdraw {
            prefix: P1.parse().unwrap(),
            id: 0,
        })
        .unwrap();
    let held = pet_adj_out(&bgp, c).await;
    // The engine packs withdrawals and flushes them a moment after the
    // burst settles (`WITHDRAW_FLUSH_DELAY`); wait it out before reading.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(withdrawn(&mut rx), vec![P1.to_string()]);
    assert_eq!(held, vec![P2.to_string()]);
}

/// The chunked dump records its routes in the peer's egress task too.
#[tokio::test]
async fn the_chunked_session_up_dump_records_its_routes_in_the_peer_egress_task() {
    let mut bgp = fresh_bgp();
    put(&mut bgp, P1);
    put(&mut bgp, P2);
    let (c, _rx) = add_peer(&mut bgp);
    spawn_pet(&mut bgp, c);
    dump_chunked(&mut bgp, c);
    assert_eq!(pet_adj_out(&bgp, c).await, both());
}

/// And in the update group engine, when that one runs: the all-at-once
/// dump did, the chunked one did not.
#[tokio::test]
async fn the_chunked_session_up_dump_records_its_routes_in_the_group_engine() {
    let mut bgp = fresh_bgp();
    put(&mut bgp, P1);
    put(&mut bgp, P2);
    let (c, _rx) = add_peer(&mut bgp);
    let gid = bgp.peers.get_by_idx(c).unwrap().update_group_id[&V4].clone();
    let group = bgp
        .update_groups
        .get_mut(&V4)
        .unwrap()
        .group_by_id_mut(&gid)
        .unwrap();
    group.task = Some(crate::bgp::group_egress::GroupEgressTask::spawn(
        gid.clone(),
    ));
    dump_chunked(&mut bgp, c);
    assert_eq!(group_adj_out(&bgp, c).await, both());
}

/// Control: a peer with no egress engine records the dump in its own
/// Adj-RIB-Out, whichever way it runs.
#[tokio::test]
async fn without_an_egress_engine_the_dump_is_recorded_on_the_peer() {
    for chunked in [false, true] {
        let mut bgp = fresh_bgp();
        put(&mut bgp, P1);
        put(&mut bgp, P2);
        let (c, _rx) = add_peer(&mut bgp);
        if chunked {
            dump_chunked(&mut bgp, c);
        } else {
            dump(&mut bgp, c);
        }
        let held: Vec<String> = bgp
            .peers
            .get_by_idx(c)
            .unwrap()
            .adj_out
            .v4
            .0
            .keys()
            .map(|p| p.to_string())
            .collect();
        assert_eq!(held, both(), "chunked: {chunked}");
    }
}
