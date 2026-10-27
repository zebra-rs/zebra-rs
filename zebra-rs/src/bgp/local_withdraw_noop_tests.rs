//! A local withdraw — a `network` removal or a redistributed route's
//! RouteDel — that removes nothing leaves the selection alone.
//! `route_redist_del` withdraws each RouteDel from both the unicast and
//! the labeled-unicast family, so one of the two usually holds nothing of
//! that source. With a peer-learned best for the prefix, that withdraw
//! reinstalled the peer's route in the FIB and re-sent it to every peer.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{BgpRib, BgpRibType};
use crate::rib::RibType;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapMultiProtocol, Ipv4Nlri, Ipv6Nlri, Label,
    Origin, Safi,
};
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
/// The source of the peer-learned best: not a configured neighbor.
const SOURCE: usize = 1000;
const V4U: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
const V6U: AfiSafi = AfiSafi {
    afi: Afi::Ip6,
    safi: Safi::Unicast,
};
const V4LU: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::MplsLabel,
};
const V6LU: AfiSafi = AfiSafi {
    afi: Afi::Ip6,
    safi: Safi::MplsLabel,
};

type RibRx = mpsc::UnboundedReceiver<crate::rib::client::RibInbound>;

/// A `Bgp` whose RIB messages the test counts.
fn fresh_bgp() -> (Bgp, RibRx) {
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
    (bgp, inbound_rx)
}

fn drain(rx: &mut RibRx) -> usize {
    let mut n = 0;
    while rx.try_recv().is_ok() {
        n += 1;
    }
    n
}

/// An Established eBGP neighbor C for `family`, in its update group.
fn add_peer(bgp: &mut Bgp, addr: &str, family: AfiSafi) -> usize {
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
    peer.param.local_addr = Some(if ip.is_ipv4() {
        "10.0.0.99:179".parse().unwrap()
    } else {
        "[2001:db8::99]:179".parse().unwrap()
    });
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&family.afi, &family.safi))
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

/// A reachable eBGP path from [`SOURCE`] via `nh`, labeled when `label`.
fn source_rib(nh: IpAddr, label: bool) -> BgpRib {
    let attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65100").unwrap()),
        nexthop: Some(match nh {
            IpAddr::V4(a) => BgpNexthop::Ipv4(a),
            IpAddr::V6(a) => BgpNexthop::Ipv6(a),
        }),
        ..Default::default()
    };
    let mut rib = BgpRib::new(
        SOURCE,
        Ipv4Addr::new(10, 0, 0, 100),
        BgpRibType::EBGP,
        0,
        0,
        &attr,
        label.then(|| Label::new(16000, 0, true)),
        None,
        false,
    );
    rib.nexthop_reachable = true;
    rib
}

/// C's update-group cache: is `prefix` queued for the wire?
fn queued_v4(bgp: &Bgp, c: usize, prefix: Ipv4Net) -> bool {
    let gid = bgp.peers.get_by_idx(c).unwrap().update_group_id[&V4U].clone();
    let group = bgp.update_groups[&V4U].group_by_id(&gid).unwrap();
    group
        .cache_ipv4_rev
        .contains_key(&Ipv4Nlri { id: 0, prefix })
}

fn queued_v6(bgp: &Bgp, c: usize, prefix: Ipv6Net) -> bool {
    let gid = bgp.peers.get_by_idx(c).unwrap().update_group_id[&V6U].clone();
    let group = bgp.update_groups[&V6U].group_by_id(&gid).unwrap();
    group
        .cache_ipv6_rev
        .contains_key(&Ipv6Nlri { id: 0, prefix })
}

fn clear_queued(bgp: &mut Bgp, c: usize, family: AfiSafi) {
    let gid = bgp.peers.get_by_idx(c).unwrap().update_group_id[&family].clone();
    let group = bgp
        .update_groups
        .get_mut(&family)
        .unwrap()
        .group_by_id_mut(&gid)
        .unwrap();
    group.cache_ipv4.clear();
    group.cache_ipv4_rev.clear();
    group.cache_ipv6.clear();
    group.cache_ipv6_rev.clear();
}

#[tokio::test]
async fn local_withdraw_that_removes_nothing_changes_nothing_v4() {
    let (mut bgp, mut rib) = fresh_bgp();
    let c = add_peer(&mut bgp, "10.0.0.2", V4U);
    let prefix: Ipv4Net = "10.31.1.0/24".parse().unwrap();
    bgp.shard
        .v4
        .update(prefix, source_rib("10.0.0.100".parse().unwrap(), false));
    drain(&mut rib); // the fixture's own setup messages

    bgp.route_redist_withdraw(RibType::Connected, prefix);
    assert_eq!(drain(&mut rib), 0, "redistribute: no FIB reinstall");
    assert!(!queued_v4(&bgp, c, prefix), "redistribute: no re-advertise");
    bgp.route_del(prefix);
    assert_eq!(drain(&mut rib), 0, "network: no FIB reinstall");
    assert!(!queued_v4(&bgp, c, prefix), "network: no re-advertise");
    assert_eq!(bgp.shard.v4.candidates(prefix).len(), 1);

    // Control: withdrawing a route that was injected still hands the
    // prefix back to the peer's path.
    bgp.route_redist_inject(RibType::Connected, prefix, 0);
    drain(&mut rib);
    clear_queued(&mut bgp, c, V4U);
    bgp.route_redist_withdraw(RibType::Connected, prefix);
    assert!(drain(&mut rib) > 0, "the peer's path is reinstalled");
    assert!(queued_v4(&bgp, c, prefix), "and re-advertised");
}

#[tokio::test]
async fn local_withdraw_that_removes_nothing_changes_nothing_v6() {
    let (mut bgp, mut rib) = fresh_bgp();
    let c = add_peer(&mut bgp, "2001:db8::2", V6U);
    let prefix: Ipv6Net = "2001:db8:31::/64".parse().unwrap();
    bgp.shard
        .v6
        .update(prefix, source_rib("2001:db8::100".parse().unwrap(), false));
    drain(&mut rib); // the fixture's own setup messages

    bgp.route_redist_withdraw_v6(RibType::Connected, prefix);
    assert_eq!(drain(&mut rib), 0, "redistribute: no FIB reinstall");
    assert!(!queued_v6(&bgp, c, prefix), "redistribute: no re-advertise");
    bgp.route_del_v6(prefix);
    assert_eq!(drain(&mut rib), 0, "network: no FIB reinstall");
    assert!(!queued_v6(&bgp, c, prefix), "network: no re-advertise");
    assert_eq!(bgp.shard.v6.candidates(prefix).len(), 1);

    bgp.route_redist_inject_v6(RibType::Connected, prefix, 0);
    drain(&mut rib);
    clear_queued(&mut bgp, c, V6U);
    bgp.route_redist_withdraw_v6(RibType::Connected, prefix);
    assert!(drain(&mut rib) > 0, "the peer's path is reinstalled");
    assert!(queued_v6(&bgp, c, prefix), "and re-advertised");
}

/// Labeled unicast sends straight to the wire; C's Adj-RIB-Out records
/// what it was sent.
#[tokio::test]
async fn local_withdraw_that_removes_nothing_changes_nothing_v4lu() {
    let (mut bgp, mut rib) = fresh_bgp();
    let c = add_peer(&mut bgp, "10.0.0.2", V4LU);
    let prefix: Ipv4Net = "10.31.2.0/24".parse().unwrap();
    bgp.shard
        .v4lu
        .update(prefix, source_rib("10.0.0.100".parse().unwrap(), true));
    drain(&mut rib); // the fixture's own setup messages
    let sent = |bgp: &Bgp| {
        let peer = bgp.peers.get_by_idx(c).unwrap();
        peer.adj_out.v4lu.0.contains_key(&prefix)
    };

    bgp.route_redist_withdraw_labelv4(RibType::Connected, prefix);
    assert_eq!(drain(&mut rib), 0, "redistribute: no FIB reinstall");
    assert!(!sent(&bgp), "redistribute: no re-advertise");
    bgp.route_del_label_v4(prefix);
    assert_eq!(drain(&mut rib), 0, "network: no FIB reinstall");
    assert!(!sent(&bgp), "network: no re-advertise");
    assert_eq!(bgp.shard.v4lu.candidates(prefix).len(), 1);

    bgp.route_redist_inject_labelv4(RibType::Connected, prefix, 0);
    drain(&mut rib);
    bgp.route_redist_withdraw_labelv4(RibType::Connected, prefix);
    assert!(drain(&mut rib) > 0, "the peer's path is reinstalled");
}

#[tokio::test]
async fn local_withdraw_that_removes_nothing_changes_nothing_v6lu() {
    let (mut bgp, mut rib) = fresh_bgp();
    let c = add_peer(&mut bgp, "2001:db8::2", V6LU);
    let prefix: Ipv6Net = "2001:db8:32::/64".parse().unwrap();
    bgp.shard
        .v6lu
        .update(prefix, source_rib("2001:db8::100".parse().unwrap(), true));
    drain(&mut rib); // the fixture's own setup messages
    let sent = |bgp: &Bgp| {
        let peer = bgp.peers.get_by_idx(c).unwrap();
        peer.adj_out.v6lu.0.contains_key(&prefix)
    };

    bgp.route_redist_withdraw_labelv6(RibType::Connected, prefix);
    assert_eq!(drain(&mut rib), 0, "redistribute: no FIB reinstall");
    assert!(!sent(&bgp), "redistribute: no re-advertise");
    bgp.route_del_label_v6(prefix);
    assert_eq!(drain(&mut rib), 0, "network: no FIB reinstall");
    assert!(!sent(&bgp), "network: no re-advertise");
    assert_eq!(bgp.shard.v6lu.candidates(prefix).len(), 1);

    bgp.route_redist_inject_labelv6(RibType::Connected, prefix, 0);
    drain(&mut rib);
    bgp.route_redist_withdraw_labelv6(RibType::Connected, prefix);
    assert!(drain(&mut rib) > 0, "the peer's path is reinstalled");
}
