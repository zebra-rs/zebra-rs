//! Review finding #30: with `suppress-fib-pending` a prefix's advertisement
//! waits for the forwarding plane to confirm the install (or for the
//! deadline). The session-up dumps on main skip a held prefix
//! (`fib_pending_blocks_sync`) and leave it to the release, which fans it to
//! every Established neighbor, the new one included. The N>1 dump — each
//! pool shard sending its own slice of the Loc-RIB (`DumpV4`) — had no such
//! gate: a new neighbor learned a prefix the dataplane had not confirmed.
//! Nor could the shards be handed main's holds: a hold for a best path a
//! shard has just picked does not exist until main reduces that delta
//! (reviewer follow-up). Nor may the dump stop parking on a backed-up
//! neighbor wherever it runs (second reviewer follow-up).
//!
//! Every gate drives the session-up dump the way the transition to
//! Established does, so it holds whichever path the dump takes.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{BgpRib, BgpRibType, FibPending, route_sync};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, MpReachAttr, Origin,
    ParseOption, Safi,
};
use ipnet::{IpNet, Ipv4Net};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
/// The prefix awaiting the forwarding plane.
const HELD: &str = "10.30.1.0/24";
/// A prefix with no hold.
const FREE: &str = "10.30.2.0/24";
/// The source of the Loc-RIB routes: not the peer under test.
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

/// `ps` in a two-shard pool, in the first shard's slice (what the dump
/// walks), and in main's Loc-RIB replica (what the release re-selects
/// from, as the reduce keeps it at N>1).
fn sharded(bgp: &mut Bgp, ps: &[&str]) {
    let mut shard = crate::bgp::shard::BgpShard::default();
    for p in ps {
        shard.v4.update(p.parse().unwrap(), source_rib());
        bgp.shard.v4.update(p.parse().unwrap(), source_rib());
    }
    let (tx, rx) = mpsc::unbounded_channel();
    bgp.shards = Some(crate::bgp::shard::pool::ShardPool::spawn(
        vec![shard, Default::default()],
        tx,
    ));
    bgp.shard_results_rx = rx;
}

/// An Established eBGP neighbor in its update group, AddPath-send for IPv4
/// unicast when `add_path`.
fn add_peer(bgp: &mut Bgp, add_path: bool) -> (usize, Rx) {
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
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&V4.afi, &V4.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    if add_path {
        peer.opt.add_path.entry(V4).or_default().send = true;
    }
    let (ptx, prx) = mpsc::unbounded_channel();
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    bgp.peers.membership_enroll(id);
    crate::bgp::update_group::attach(&mut bgp.update_groups, &mut bgp.peers, id, ROUTER_ID, false);
    (id, prx)
}

/// `suppress-fib-pending` is on and [`HELD`]'s install has waited `ago`
/// for the forwarding plane's ack.
fn hold(bgp: &mut Bgp, ago: Duration) {
    bgp.local_rib.suppress_fib_pending = true;
    let since = Instant::now().checked_sub(ago).expect("uptime > ago");
    bgp.local_rib
        .fib_pending
        .insert(IpNet::V4(HELD.parse().unwrap()), FibPending::Waiting(since));
}

/// Main takes the pool's next `n` results, in order.
async fn reduce(bgp: &mut Bgp, n: usize) {
    for _ in 0..n {
        let result = bgp.shard_results_rx.recv().await.unwrap();
        bgp.process_shard_result(result);
    }
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

/// What the transition to Established starts: `route_sync` in the FSM,
/// then the pool's broadcast. Returns the number of pool acks to take.
fn start_dump(bgp: &mut Bgp, c: usize) -> usize {
    let pool = bgp.shards.is_some();
    {
        let (mut top, peers) = split(bgp);
        route_sync(peers.get_mut_by_idx(c).unwrap(), &mut top, pool);
    }
    match bgp.broadcast_dump_v4(c) {
        Some(_) => bgp.shards.as_ref().unwrap().n(),
        None => 0,
    }
}

/// Up to `ticks` ticks of main's resumable dump cursor, if the peer has one.
fn tick(bgp: &mut Bgp, c: usize, ticks: usize) {
    for _ in 0..ticks {
        if bgp.peers.get_by_idx(c).unwrap().sync_v4.is_none() {
            return;
        }
        bgp.drive_sync_v4(c);
    }
}

/// The session-up dump run to completion: main takes `pending` results
/// already on their way, then the dump's acks, then runs its cursor out.
async fn dump(bgp: &mut Bgp, c: usize, pending: usize) {
    let acks = start_dump(bgp, c);
    reduce(bgp, pending + acks).await;
    tick(bgp, c, 16);
    assert!(
        bgp.peers.get_by_idx(c).unwrap().sync_v4.is_none(),
        "the dump ran to completion"
    );
}

/// [`SOURCE`]'s UPDATE for [`HELD`], ingested in the pool shard that owns
/// it, as the N>1 ingest sends it: its best-path delta is then on its way
/// to main.
fn learn_in_pool(bgp: &Bgp) {
    use crate::bgp::shard::msg::ShardUpdateV4;
    let prefix: Ipv4Net = HELD.parse().unwrap();
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
            attr: (*source_rib().attr).clone(),
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

/// The forwarding plane confirms [`HELD`]: the release, as the RIB reply
/// handler runs it, then the update group's flush.
fn fib_ack(bgp: &mut Bgp, c: usize) {
    let prefix = IpNet::V4(HELD.parse().unwrap());
    bgp.local_rib
        .fib_pending
        .insert(prefix, FibPending::Confirmed);
    bgp.fib_pending_release(prefix);
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

/// The IPv4 prefixes the neighbor was sent, in order (a path-id-bearing
/// encoding when `add_path`).
fn sent(rx: &mut Rx, add_path: bool) -> Vec<String> {
    let mut opt = ParseOption::default();
    if add_path {
        opt.add_path.entry(V4).or_default().recv = true;
    }
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) =
            BgpPacket::parse_packet(&bytes, true, Some(opt.clone())).expect("a well-formed UPDATE");
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

/// `ps` as [`sent`] reports them.
fn prefixes(ps: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = ps
        .iter()
        .map(|p| Ipv4Net::from_str(p).unwrap().to_string())
        .collect();
    out.sort();
    out
}

async fn check_dump_holds_back(add_path: bool) {
    let mut bgp = fresh_bgp();
    let (c, mut rx) = add_peer(&mut bgp, add_path);
    sharded(&mut bgp, &[HELD, FREE]);
    hold(&mut bgp, Duration::ZERO);
    dump(&mut bgp, c, 0).await;
    assert_eq!(
        sent(&mut rx, add_path),
        prefixes(&[FREE]),
        "the held prefix waits for the forwarding plane"
    );

    fib_ack(&mut bgp, c);
    assert_eq!(
        sent(&mut rx, add_path),
        prefixes(&[HELD]),
        "the release sends it"
    );
}

/// The N>1 session-up dump sends a new neighbor the prefix with no hold
/// and holds back the one the forwarding plane has not confirmed; the
/// release sends that. On `main` the dump sent both.
#[tokio::test]
async fn a_sharded_dump_holds_back_a_prefix_awaiting_the_fib() {
    check_dump_holds_back(false).await;
}

/// The same toward an AddPath neighbor, which the shard sends every path.
#[tokio::test]
async fn a_sharded_addpath_dump_holds_back_a_prefix_awaiting_the_fib() {
    check_dump_holds_back(true).await;
}

/// Control: a hold past its deadline is not skipped — the sweep releases
/// it anyway — as on main's dumps.
#[tokio::test]
async fn a_sharded_dump_sends_a_prefix_whose_hold_expired() {
    let mut bgp = fresh_bgp();
    let (c, mut rx) = add_peer(&mut bgp, false);
    sharded(&mut bgp, &[HELD, FREE]);
    hold(
        &mut bgp,
        crate::bgp::route::FIB_PENDING_TIMEOUT + Duration::from_secs(1),
    );
    dump(&mut bgp, c, 0).await;
    assert_eq!(sent(&mut rx, false), prefixes(&[FREE, HELD]));
}

async fn check_dump_holds_back_an_unreduced_best_path(add_path: bool) {
    let mut bgp = fresh_bgp();
    let (c, mut rx) = add_peer(&mut bgp, add_path);
    sharded(&mut bgp, &[FREE]);
    bgp.local_rib.suppress_fib_pending = true;
    learn_in_pool(&bgp);
    // The new best path's delta is still on its way to main.
    dump(&mut bgp, c, 1).await;
    assert!(
        crate::bgp::route::fib_pending_blocks_sync(
            &bgp.local_rib,
            IpNet::V4(HELD.parse().unwrap())
        ),
        "the reduce armed the hold"
    );
    assert_eq!(
        sent(&mut rx, add_path),
        prefixes(&[FREE]),
        "the held prefix waits for the forwarding plane"
    );

    fib_ack(&mut bgp, c);
    assert_eq!(
        sent(&mut rx, add_path),
        prefixes(&[HELD]),
        "the release sends it"
    );
}

/// Reviewer follow-up: the dump is broadcast while a pool shard's new
/// best path for [`HELD`] is still on its way to main, so main has no hold
/// for it yet; the reduce then arms one. The neighbor still gets only
/// [`FREE`] from the dump, and [`HELD`] from the release.
#[tokio::test]
async fn a_sharded_dump_holds_back_a_best_path_main_has_not_reduced() {
    check_dump_holds_back_an_unreduced_best_path(false).await;
}

/// The same toward an AddPath neighbor.
#[tokio::test]
async fn a_sharded_addpath_dump_holds_back_a_best_path_main_has_not_reduced() {
    check_dump_holds_back_an_unreduced_best_path(true).await;
}

/// Control (second reviewer follow-up): the dump parks while the
/// neighbor's egress queue is over the high-water mark and resumes once
/// it drains — wherever it runs under `suppress-fib-pending`. A send from
/// main that ignored the backlog could queue the whole table toward a slow
/// neighbor. While the neighbor is backed up, main's cursor ticks and main
/// takes whatever the pool has finished (the shard with an empty slice acks
/// at once); nothing may go out.
#[tokio::test]
async fn a_sharded_dump_under_suppress_fib_pending_parks_on_a_backed_up_neighbor() {
    use std::sync::atomic::Ordering;
    let mut bgp = fresh_bgp();
    let (c, mut rx) = add_peer(&mut bgp, false);
    sharded(&mut bgp, &[FREE]);
    bgp.local_rib.suppress_fib_pending = true;
    let depth = bgp.peers.get_by_idx(c).unwrap().egress_depth.clone();
    depth.store(sync_egress_high_water() + 1, Ordering::Relaxed);
    let acks = start_dump(&mut bgp, c);
    tick(&mut bgp, c, 4);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut taken = 0;
    while let Ok(result) = bgp.shard_results_rx.try_recv() {
        bgp.process_shard_result(result);
        taken += 1;
    }
    assert!(
        sent(&mut rx, false).is_empty(),
        "nothing goes out while the neighbor is backed up"
    );

    depth.store(0, Ordering::Relaxed);
    reduce(&mut bgp, acks - taken).await;
    tick(&mut bgp, c, 16);
    assert_eq!(
        sent(&mut rx, false),
        prefixes(&[FREE]),
        "the dump resumes once it drains"
    );
}
