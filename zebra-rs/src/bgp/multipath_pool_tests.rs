//! At N>1 the worker pool owns IPv4-unicast selection, but the multipath
//! policy (`maximum-paths`, `maximum-paths-ibgp`, `multipath-relax`) was
//! written to main's read replica alone. Every pool shard kept the
//! single-path default, so the next pool re-selection of a prefix (an
//! UPDATE, a new leg, a session loss) installed one leg.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{BgpRibType, MultipathCfg};
use crate::bgp::shard::ShardMsg;
use crate::bgp::shard::msg::ShardUpdateV4;
use crate::rib::client::RibInbound;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapMultiProtocol, Ipv4Nlri, Origin, Safi,
};
use ipnet::Ipv4Net;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
/// Path sources, none a configured neighbor (the shard applies
/// default-permit). Source `s` has next-hop and router-id 10.0.0.(s - 900).
const A: usize = 1000;
const B: usize = 1001;
const C: usize = 1002;

/// A `Bgp` with a two-shard pool, and the channel its FIB installs reach.
fn sharded_bgp() -> (Bgp, Fib) {
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
    let (tx, rx) = mpsc::unbounded_channel();
    bgp.shards = Some(crate::bgp::shard::pool::ShardPool::spawn(
        vec![Default::default(), Default::default()],
        tx,
    ));
    bgp.shard_results_rx = rx;
    (
        bgp,
        Fib {
            rx: inbound_rx,
            legs: BTreeMap::new(),
        },
    )
}

/// The kernel's view: the number of next-hops installed per prefix.
struct Fib {
    rx: mpsc::UnboundedReceiver<RibInbound>,
    legs: BTreeMap<Ipv4Net, usize>,
}

impl Fib {
    /// Apply every install / delete sent since the last call; returns how
    /// many there were.
    fn sync(&mut self) -> usize {
        let mut n = 0;
        while let Ok(m) = self.rx.try_recv() {
            match m.msg {
                crate::rib::Message::Ipv4Add { prefix, rib } => {
                    let legs = match rib.nexthop {
                        crate::rib::Nexthop::Multi(multi) => multi.nexthops.len(),
                        _ => 1,
                    };
                    self.legs.insert(prefix, legs);
                    n += 1;
                }
                crate::rib::Message::Ipv4Del { prefix, .. } => {
                    self.legs.insert(prefix, 0);
                    n += 1;
                }
                _ => {}
            }
        }
        n
    }

    /// Asserts that every prefix has `want` legs installed.
    fn expect(&mut self, prefixes: &[Ipv4Net], want: usize, when: &str) {
        self.sync();
        for prefix in prefixes {
            assert_eq!(
                self.legs.get(prefix).copied(),
                Some(want),
                "{prefix}: legs installed {when}"
            );
        }
    }
}

/// Prefixes that hash onto both shards of the pool.
fn prefixes(bgp: &Bgp) -> Vec<Ipv4Net> {
    let pool = bgp.shards.as_ref().unwrap();
    let all: Vec<Ipv4Net> = (0..16)
        .map(|i| Ipv4Net::new(Ipv4Addr::new(10, 40, i, 0), 24).unwrap())
        .collect();
    let shards: BTreeSet<usize> = all
        .iter()
        .map(|p| pool.shard_of(IpAddr::V4(p.addr())))
        .collect();
    assert_eq!(shards.len(), 2, "the prefixes cover both shards");
    all
}

/// `source`'s UPDATE for `prefixes`, ingested by the owning pool shards as
/// the N>1 ingest sends it. A second call refreshes the same path.
fn announce(bgp: &Bgp, source: usize, typ: BgpRibType, as_path: &str, prefixes: &[Ipv4Net]) {
    let addr = Ipv4Addr::new(10, 0, 0, (source - 900) as u8);
    let pool = bgp.shards.as_ref().unwrap();
    for prefix in prefixes {
        let attr = BgpAttr {
            origin: Some(Origin::Igp),
            aspath: Some(As4Path::from_str(as_path).unwrap()),
            nexthop: Some(BgpNexthop::Ipv4(addr)),
            ..Default::default()
        };
        pool.dispatch(
            pool.shard_of(IpAddr::V4(prefix.addr())),
            ShardMsg::UpdateV4(ShardUpdateV4 {
                ident: source,
                rd: None,
                nlri: Ipv4Nlri {
                    id: 0,
                    prefix: *prefix,
                },
                peer_router_id: addr,
                typ,
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
}

fn ebgp(bgp: &Bgp, source: usize, as_path: &str, prefixes: &[Ipv4Net]) {
    announce(bgp, source, BgpRibType::EBGP, as_path, prefixes);
}

/// `source`'s session goes down: every shard sweeps its paths.
fn peer_down(bgp: &Bgp, source: usize) {
    bgp.shards
        .as_ref()
        .unwrap()
        .broadcast(|| ShardMsg::PeerDown { ident: source });
}

/// An Established eBGP neighbor at `addr`, in its update group.
fn add_peer(bgp: &mut Bgp, addr: &str) -> usize {
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
    Box::leak(Box::new(prx));
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    bgp.peers.membership_enroll(id);
    crate::bgp::update_group::attach(&mut bgp.update_groups, &mut bgp.peers, id, ROUTER_ID, false);
    id
}

/// The prefixes queued in `peer`'s update-group cache for the wire.
fn queued(bgp: &Bgp, peer: usize, prefixes: &[Ipv4Net]) -> usize {
    let gid = bgp.peers.get_by_idx(peer).unwrap().update_group_id[&V4].clone();
    let group = bgp.update_groups[&V4].group_by_id(&gid).unwrap();
    prefixes
        .iter()
        .filter(|p| {
            group
                .cache_ipv4_rev
                .contains_key(&Ipv4Nlri { id: 0, prefix: **p })
        })
        .count()
}

fn clear_queued(bgp: &mut Bgp, peer: usize) {
    let gid = bgp.peers.get_by_idx(peer).unwrap().update_group_id[&V4].clone();
    let group = bgp
        .update_groups
        .get_mut(&V4)
        .unwrap()
        .group_by_id_mut(&gid)
        .unwrap();
    group.cache_ipv4.clear();
    group.cache_ipv4_rev.clear();
}

/// What the config handlers do: write main's policy, then resync.
fn set_multipath(bgp: &mut Bgp, max_paths: u32, max_paths_ibgp: Option<u32>, relax: bool) {
    bgp.shard.v4.2 = MultipathCfg {
        max_paths,
        max_paths_ibgp,
        relax,
    };
    bgp.multipath_resync(V4);
}

/// Main reduces every pool result for the work dispatched so far. Each
/// shard handles its messages in order and answers a barrier only after the
/// results of everything before it are on the channel.
async fn settle(bgp: &mut Bgp) {
    let mut barriers = Vec::new();
    bgp.shards.as_ref().unwrap().broadcast(|| {
        let (reply, rx) = tokio::sync::oneshot::channel();
        barriers.push(rx);
        ShardMsg::CountAdjInV4All { reply }
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

#[tokio::test]
async fn raising_maximum_paths_keeps_every_leg_through_a_refresh() {
    let (mut bgp, mut fib) = sharded_bgp();
    let p = prefixes(&bgp);
    ebgp(&bgp, A, "65100", &p);
    ebgp(&bgp, B, "65100", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 1, "at the single-path default");

    set_multipath(&mut bgp, 8, None, false);
    settle(&mut bgp).await;
    fib.expect(&p, 2, "after raising maximum-paths");

    // A refresh re-runs selection on the pool shard that owns the prefix.
    ebgp(&bgp, A, "65100", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 2, "after a refresh of one leg");
}

#[tokio::test]
async fn a_leg_learned_after_maximum_paths_is_set_joins_the_set() {
    let (mut bgp, mut fib) = sharded_bgp();
    let p = prefixes(&bgp);
    // Startup order: the config is applied before any route arrives.
    set_multipath(&mut bgp, 8, None, false);
    settle(&mut bgp).await;
    ebgp(&bgp, A, "65100", &p);
    ebgp(&bgp, B, "65100", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 2, "with maximum-paths set before the routes");

    ebgp(&bgp, C, "65100", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 3, "after a third leg");

    peer_down(&bgp, C);
    settle(&mut bgp).await;
    fib.expect(&p, 2, "after the third leg's session goes down");
}

#[tokio::test]
async fn lowering_maximum_paths_drops_the_extra_legs() {
    let (mut bgp, mut fib) = sharded_bgp();
    let p = prefixes(&bgp);
    set_multipath(&mut bgp, 8, None, false);
    ebgp(&bgp, A, "65100", &p);
    ebgp(&bgp, B, "65100", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 2, "at maximum-paths 8");

    set_multipath(&mut bgp, 1, None, false);
    settle(&mut bgp).await;
    fib.expect(&p, 1, "after lowering maximum-paths to 1");

    ebgp(&bgp, B, "65100", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 1, "after a refresh at maximum-paths 1");
}

#[tokio::test]
async fn maximum_paths_ibgp_reaches_the_pool() {
    let (mut bgp, mut fib) = sharded_bgp();
    let p = prefixes(&bgp);
    // The eBGP cap stays 1: only the iBGP cap can widen an iBGP set.
    set_multipath(&mut bgp, 1, Some(8), false);
    announce(&bgp, A, BgpRibType::IBGP, "65100", &p);
    announce(&bgp, B, BgpRibType::IBGP, "65100", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 2, "for an iBGP set under maximum-paths-ibgp 8");
}

#[tokio::test]
async fn multipath_relax_reaches_the_pool() {
    let (mut bgp, mut fib) = sharded_bgp();
    let p = prefixes(&bgp);
    // Two neighboring ASes: only multipath-relax admits both.
    set_multipath(&mut bgp, 8, None, false);
    ebgp(&bgp, A, "65100", &p);
    ebgp(&bgp, B, "65200", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 1, "without multipath-relax");

    set_multipath(&mut bgp, 8, None, true);
    settle(&mut bgp).await;
    ebgp(&bgp, A, "65100", &p);
    settle(&mut bgp).await;
    fib.expect(&p, 2, "with multipath-relax, after a refresh");
}

#[tokio::test]
async fn a_resync_leaves_the_install_to_the_pool() {
    let (mut bgp, mut fib) = sharded_bgp();
    let p = prefixes(&bgp);
    ebgp(&bgp, A, "65100", &p);
    ebgp(&bgp, B, "65100", &p);
    settle(&mut bgp).await;
    fib.sync();

    // Main's table is a read replica: installing from it would race the
    // pool, whose next re-selection of the prefix overwrites it.
    set_multipath(&mut bgp, 8, None, false);
    assert_eq!(fib.sync(), 0, "main installs nothing from its replica");
    settle(&mut bgp).await;
    fib.expect(&p, 2, "once the pool has re-run selection");
}

#[tokio::test]
async fn a_resync_advertises_nothing() {
    let (mut bgp, mut fib) = sharded_bgp();
    let p = prefixes(&bgp);
    let c = add_peer(&mut bgp, "10.0.0.2");
    ebgp(&bgp, A, "65100", &p);
    ebgp(&bgp, B, "65100", &p);
    settle(&mut bgp).await;
    assert_eq!(
        queued(&bgp, c, &p),
        p.len(),
        "the neighbor is sent every prefix"
    );
    clear_queued(&mut bgp, c);

    // The multipath set is installed, not advertised: the winner a plain
    // neighbor is sent does not change.
    set_multipath(&mut bgp, 8, None, false);
    settle(&mut bgp).await;
    fib.expect(&p, 2, "after raising maximum-paths");
    assert_eq!(queued(&bgp, c, &p), 0, "nothing is re-advertised");
}
