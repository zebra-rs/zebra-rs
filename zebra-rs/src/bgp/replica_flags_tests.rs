//! At N>1 main's IPv4-unicast table is a read replica of the pool, and
//! `show bgp ipv4` renders its candidates' `best_path` / `multipath`
//! flags as `>` / `=`. The replica took each pool row as it was before
//! selection and never updated the other candidates, so at N>1 no route
//! ever showed `>` or `=`. Each step here must flag the candidates as N=1
//! does.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{MultipathCfg, route_from_peer};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapMultiProtocol, Ipv4Nlri, Origin, Safi,
    UpdatePacket,
};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
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

/// An Established eBGP neighbor at `addr` in AS `asn`.
fn add_peer(bgp: &mut Bgp, addr: &str, asn: u32) -> usize {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = addr.parse().unwrap();
    let mut peer = Peer::new(
        0,
        65000,
        ROUTER_ID,
        asn,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = PeerType::EBGP;
    peer.remote_id = match ip {
        IpAddr::V4(a) => a,
        _ => unreachable!(),
    };
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
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
    bgp.peers.get(&ip).unwrap().ident
}

/// The neighbor announces [`P`].
fn announce(bgp: &mut Bgp, id: usize, as_path: &str, nh: &str) {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str(as_path).unwrap()),
        nexthop: Some(BgpNexthop::Ipv4(nh.parse().unwrap())),
        ..Default::default()
    });
    packet.ipv4_update.push(Ipv4Nlri {
        id: 0,
        prefix: P.parse().unwrap(),
    });
    ingest(bgp, id, packet);
}

/// Run one UPDATE through the ingest, as the peer's FSM does.
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
        nexthop_cache: None,
        vrf_transport_v4: None,
        vrf_transport_v6: None,
        as_sets_withdraw: bgp.as_sets_withdraw,
    };
    route_from_peer(id, packet, &mut top, &mut bgp.peers, bgp.shards.as_ref());
}

/// The neighbor withdraws [`P`].
fn withdraw(bgp: &mut Bgp, id: usize) {
    let mut packet = UpdatePacket::new();
    packet.ipv4_withdraw.push(Ipv4Nlri {
        id: 0,
        prefix: P.parse().unwrap(),
    });
    ingest(bgp, id, packet);
}

/// Main reduces every pool result for the work dispatched so far (a
/// no-op at N=1): each shard answers the barrier only after the results
/// of everything before it are on the channel.
async fn settle(bgp: &mut Bgp) {
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

/// The candidates of [`P`] as `show bgp ipv4` marks them, with the reason
/// the best path won, sorted by router-id.
fn flags(bgp: &Bgp) -> Vec<String> {
    let p = P.parse().unwrap();
    let mut out: Vec<String> = bgp
        .shard
        .v4
        .0
        .get(&p)
        .map(|c| {
            c.iter()
                .map(|r| {
                    let marker = if r.best_path {
                        ">"
                    } else if r.multipath {
                        "="
                    } else {
                        " "
                    };
                    format!("{marker} {} {:?}", r.router_id, r.best_reason)
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a[2..].cmp(&b[2..]));
    out
}

/// The flags of [`P`]'s candidates after each step, at `n` shards.
async fn run(n: usize) -> Vec<Vec<String>> {
    let mut bgp = bgp_with(n);
    let a = add_peer(&mut bgp, "10.0.0.2", 65002);
    let b = add_peer(&mut bgp, "10.0.0.3", 65003);
    let mut steps = Vec::new();
    // 1. one path: A
    announce(&mut bgp, a, "65002 65100", "10.0.0.2");
    settle(&mut bgp).await;
    steps.push(flags(&bgp));
    // 2. a shorter AS path from B wins
    announce(&mut bgp, b, "65003", "10.0.0.3");
    settle(&mut bgp).await;
    steps.push(flags(&bgp));
    // 3. multipath with relax, and B equal to A again: A wins on router-id
    bgp.shard.v4.2 = MultipathCfg {
        max_paths: 8,
        max_paths_ibgp: None,
        relax: true,
    };
    bgp.multipath_resync(V4);
    settle(&mut bgp).await;
    announce(&mut bgp, b, "65003 65100", "10.0.0.3");
    settle(&mut bgp).await;
    steps.push(flags(&bgp));
    // 4. maximum-paths 1, a resync alone: B leaves the set
    bgp.shard.v4.2 = MultipathCfg {
        max_paths: 1,
        max_paths_ibgp: None,
        relax: true,
    };
    bgp.multipath_resync(V4);
    settle(&mut bgp).await;
    steps.push(flags(&bgp));
    // 5. maximum-paths 8 again, a resync alone: B rejoins
    bgp.shard.v4.2 = MultipathCfg {
        max_paths: 8,
        max_paths_ibgp: None,
        relax: true,
    };
    bgp.multipath_resync(V4);
    settle(&mut bgp).await;
    steps.push(flags(&bgp));
    // 6. the best path is withdrawn
    withdraw(&mut bgp, a);
    settle(&mut bgp).await;
    steps.push(flags(&bgp));
    steps
}

#[tokio::test]
async fn the_replica_marks_best_and_multipath_as_n1_does() {
    let markers = |steps: &[Vec<String>]| -> Vec<Vec<String>> {
        steps
            .iter()
            .map(|s| s.iter().map(|l| l[..10].to_string()).collect())
            .collect()
    };
    let expected = vec![
        vec!["> 10.0.0.2"],
        vec!["  10.0.0.2", "> 10.0.0.3"],
        vec!["> 10.0.0.2", "= 10.0.0.3"],
        vec!["> 10.0.0.2", "  10.0.0.3"],
        vec!["> 10.0.0.2", "= 10.0.0.3"],
        vec!["> 10.0.0.3"],
    ];
    let n1 = run(1).await;
    assert_eq!(markers(&n1), expected, "N=1");
    let n2 = run(2).await;
    assert_eq!(n2, n1, "N=2 flags its candidates as N=1 does");
}
