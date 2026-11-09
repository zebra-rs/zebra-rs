//! A multipath knob changed at runtime (`maximum-paths`,
//! `maximum-paths-ibgp`, `multipath-relax`) re-runs best-path over every
//! prefix (`multipath_resync`) and installs the sets that changed, with
//! nothing advertised. Every check runs at N=1 and N=2 and expects the
//! same FIB: at N>1 the pool shards re-run selection and main installs
//! their `MultipathV4` replies.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::peer_key::PeerOrigin;
use crate::bgp::route::{MultipathCfg, route_from_peer};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapExtendedNextHop, CapMultiProtocol,
    ExtendedNextHopValue, Ipv4Nlri, MpReachAttr, Origin, Safi, UpdatePacket,
};
use ipnet::Ipv4Net;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const LOCAL_AS: u32 = 65000;
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
/// Spread over both shards of the two-shard pool (checked by `prefixes`).
const PREFIXES: [&str; 4] = ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24"];

type RibRx = mpsc::UnboundedReceiver<crate::rib::client::RibInbound>;

/// A `Bgp` whose RIB messages the test reads, with an `n`-shard pool when
/// `n > 1`.
fn bgp_with(n: usize) -> (Bgp, Fib) {
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
    bgp.asn = LOCAL_AS;
    bgp.router_id = ROUTER_ID;
    if n > 1 {
        let (tx, rx) = mpsc::unbounded_channel();
        bgp.shards = Some(crate::bgp::shard::pool::ShardPool::spawn(
            (0..n).map(|_| Default::default()).collect(),
            tx,
        ));
        bgp.shard_results_rx = rx;
    }
    (
        bgp,
        Fib {
            rx: inbound_rx,
            legs: BTreeMap::new(),
        },
    )
}

/// The kernel's view: each prefix's installed gateways.
struct Fib {
    rx: RibRx,
    legs: BTreeMap<Ipv4Net, Vec<IpAddr>>,
}

impl Fib {
    /// Apply every install and delete sent since the last call; returns
    /// how many there were.
    fn sync(&mut self) -> usize {
        let mut n = 0;
        while let Ok(m) = self.rx.try_recv() {
            match m.msg {
                crate::rib::Message::Ipv4Add { prefix, rib } => {
                    let mut gws: Vec<IpAddr> = match rib.nexthop {
                        crate::rib::Nexthop::Uni(uni) => vec![uni.addr],
                        crate::rib::Nexthop::Multi(multi) => {
                            multi.nexthops.iter().map(|u| u.addr).collect()
                        }
                        _ => Vec::new(),
                    };
                    gws.sort();
                    self.legs.insert(prefix, gws);
                    n += 1;
                }
                crate::rib::Message::Ipv4Del { prefix, .. } => {
                    self.legs.insert(prefix, Vec::new());
                    n += 1;
                }
                _ => {}
            }
        }
        n
    }

    /// Asserts that every prefix is installed via exactly `want`.
    fn expect(&mut self, prefixes: &[Ipv4Net], want: &[&str], when: &str) {
        self.sync();
        let mut want: Vec<IpAddr> = want.iter().map(|a| a.parse().unwrap()).collect();
        want.sort();
        for prefix in prefixes {
            assert_eq!(
                self.legs.get(prefix),
                Some(&want),
                "{prefix}: installed gateways {when}"
            );
        }
    }
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

/// An Established neighbor at `addr` in AS `asn` (iBGP when it is ours).
/// A link-local `addr` makes it unnumbered on interface `ifindex`, with the
/// extended next-hop negotiated.
fn add_peer(bgp: &mut Bgp, addr: &str, asn: u32, ifindex: u32) -> usize {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = addr.parse().unwrap();
    let mut peer = Peer::new(
        0,
        LOCAL_AS,
        ROUTER_ID,
        asn,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = if asn == LOCAL_AS {
        PeerType::IBGP
    } else {
        PeerType::EBGP
    };
    if ip.is_ipv6() {
        let cap = || {
            CapExtendedNextHop::new(vec![ExtendedNextHopValue::new(
                Afi::Ip,
                Safi::Unicast,
                Afi::Ip6,
            )])
        };
        peer.origin = PeerOrigin::Interface { ifindex };
        peer.scope_id = Some(ifindex);
        peer.cap_send.extended_nexthop = Some(cap());
        peer.cap_recv.extended_nexthop = Some(cap());
    }
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

/// The neighbor announces `prefixes` with `as_path` via next-hop `nh`: an
/// IPv4 next-hop in the NEXT_HOP attribute, an IPv6 one (RFC 8950) in
/// MP_REACH.
fn announce(bgp: &mut Bgp, id: usize, as_path: &str, nh: &str, prefixes: &[Ipv4Net]) {
    let nlris: Vec<Ipv4Nlri> = prefixes
        .iter()
        .map(|p| Ipv4Nlri { id: 0, prefix: *p })
        .collect();
    let mut attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str(as_path).unwrap()),
        ..Default::default()
    };
    let mut packet = UpdatePacket::new();
    match nh.parse::<IpAddr>().unwrap() {
        IpAddr::V4(v4) => {
            attr.nexthop = Some(BgpNexthop::Ipv4(v4));
            packet.ipv4_update = nlris;
        }
        IpAddr::V6(v6) => {
            packet.mp_update = Some(MpReachAttr::Ipv4 {
                snpa: 0,
                nhop: IpAddr::V6(v6),
                updates: nlris,
            });
        }
    }
    packet.bgp_attr = Some(attr);
    ingest(bgp, id, packet);
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

/// Main reduces every pool result for the work dispatched so far (a no-op
/// at N=1): each shard answers the barrier only after the results of
/// everything before it are on the channel.
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
            .expect("the pool answers")
            .unwrap();
    }
    while let Ok(result) = bgp.shard_results_rx.try_recv() {
        bgp.process_shard_result(result);
    }
}

#[tokio::test]
async fn multipath_relax_takes_effect_on_the_resync_alone() {
    for n in [1, 2] {
        let (mut bgp, mut fib) = bgp_with(n);
        let p = prefixes(&bgp);
        let a = add_peer(&mut bgp, "10.0.0.2", 65002, 0);
        let b = add_peer(&mut bgp, "10.0.0.3", 65003, 0);
        set_multipath(&mut bgp, 8, None, false);
        settle(&mut bgp).await;
        announce(&mut bgp, a, "65002 65100", "10.0.0.2", &p);
        announce(&mut bgp, b, "65003 65100", "10.0.0.3", &p);
        settle(&mut bgp).await;
        fib.expect(&p, &["10.0.0.2"], &format!("N={n}: neighbor ASes differ"));

        // No UPDATE follows: the resync alone must widen the set, and
        // narrow it again.
        set_multipath(&mut bgp, 8, None, true);
        settle(&mut bgp).await;
        fib.expect(
            &p,
            &["10.0.0.2", "10.0.0.3"],
            &format!("N={n}: after multipath-relax"),
        );
        set_multipath(&mut bgp, 8, None, false);
        settle(&mut bgp).await;
        fib.expect(
            &p,
            &["10.0.0.2"],
            &format!("N={n}: after multipath-relax is removed"),
        );
    }
}

#[tokio::test]
async fn a_runtime_maximum_paths_ibgp_change_reaches_the_set() {
    for n in [1, 2] {
        let (mut bgp, mut fib) = bgp_with(n);
        let p = prefixes(&bgp);
        let a = add_peer(&mut bgp, "10.0.0.2", LOCAL_AS, 0);
        let b = add_peer(&mut bgp, "10.0.0.3", LOCAL_AS, 0);
        announce(&mut bgp, a, "65100", "10.0.0.2", &p);
        announce(&mut bgp, b, "65100", "10.0.0.3", &p);
        settle(&mut bgp).await;
        fib.expect(&p, &["10.0.0.2"], &format!("N={n}: single path"));

        // `maximum-paths 1` stays; only the iBGP cap moves.
        set_multipath(&mut bgp, 1, Some(8), false);
        settle(&mut bgp).await;
        fib.expect(
            &p,
            &["10.0.0.2", "10.0.0.3"],
            &format!("N={n}: after maximum-paths-ibgp 8"),
        );
        set_multipath(&mut bgp, 1, Some(1), false);
        settle(&mut bgp).await;
        fib.expect(
            &p,
            &["10.0.0.2"],
            &format!("N={n}: after maximum-paths-ibgp 1"),
        );
    }
}

#[tokio::test]
async fn unnumbered_paths_form_a_multipath_set() {
    for n in [1, 2] {
        let (mut bgp, mut fib) = bgp_with(n);
        let p = prefixes(&bgp);
        let a = add_peer(&mut bgp, "fe80::2", 65002, 7);
        let b = add_peer(&mut bgp, "fe80::3", 65003, 8);
        announce(&mut bgp, a, "65002 65100", "fe80::2", &p);
        announce(&mut bgp, b, "65003 65100", "fe80::3", &p);
        settle(&mut bgp).await;
        fib.expect(&p, &["fe80::2"], &format!("N={n}: single path"));

        set_multipath(&mut bgp, 8, None, true);
        settle(&mut bgp).await;
        fib.expect(
            &p,
            &["fe80::2", "fe80::3"],
            &format!("N={n}: after maximum-paths 8"),
        );

        // A refresh re-selects with the policy the routes' owner holds.
        announce(&mut bgp, b, "65003 65100", "fe80::3", &p);
        settle(&mut bgp).await;
        fib.expect(
            &p,
            &["fe80::2", "fe80::3"],
            &format!("N={n}: after a refresh"),
        );
    }
}

#[tokio::test]
async fn a_resync_installs_only_the_sets_it_changes() {
    for n in [1, 2] {
        let (mut bgp, mut fib) = bgp_with(n);
        let p = prefixes(&bgp);
        let a = add_peer(&mut bgp, "10.0.0.2", 65002, 0);
        let b = add_peer(&mut bgp, "10.0.0.3", 65003, 0);
        announce(&mut bgp, a, "65002 65100", "10.0.0.2", &p);
        // One prefix only from B: the others have a single path.
        announce(&mut bgp, b, "65003 65100", "10.0.0.3", &p[..1]);
        settle(&mut bgp).await;
        fib.sync();

        // The paths come from different ASes: without multipath-relax a
        // higher cap selects nothing new.
        set_multipath(&mut bgp, 8, None, false);
        settle(&mut bgp).await;
        assert_eq!(fib.sync(), 0, "N={n}: no set changed, nothing installed");

        set_multipath(&mut bgp, 8, None, true);
        settle(&mut bgp).await;
        assert_eq!(fib.sync(), 1, "N={n}: the one prefix with two paths");
        fib.expect(&p[..1], &["10.0.0.2", "10.0.0.3"], &format!("N={n}"));
        fib.expect(&p[1..], &["10.0.0.2"], &format!("N={n}"));
    }
}
