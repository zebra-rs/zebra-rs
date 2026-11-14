//! Review follow-up (maximum-prefix, finding #7): an UPDATE that arrives while
//! a KEEPALIVE is held completes the handshake, and the same UPDATE can take
//! the peer past its limit. `fsm` then tears the session down from inside and
//! returns before the Established entry block. These tests drive that path
//! through `fsm` and check what the peer is left with: the teardown runs from
//! Established, and the skipped entry must leave nothing half done.

use super::*;
use crate::bgp::max_prefix::MaxPrefixConfig;
use crate::bgp::peer::{Event, Peer, PeerDownReason, PeerType, State};
use crate::bgp::route::{BgpRib, BgpRibType};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, Ipv4Nlri, Origin,
    ParseOption, Safi, UpdatePacket,
};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
/// A Loc-RIB route from another peer: a session-up dump would send it.
const DUMPED: &str = "10.7.0.0/24";
const SENT: [&str; 2] = ["10.7.1.0/24", "10.7.2.0/24"];
const SOURCE: usize = 1000;
const CONN: u64 = 25;

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

fn put_from_source(bgp: &mut Bgp, prefix: &str) {
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

/// An eBGP peer in OpenConfirm with a KEEPALIVE held on its primary conn, an
/// IPv4-unicast limit of 1 and a cause parked before the session came up. Not
/// in the membership index or any update group, as before Established.
fn held_peer(bgp: &mut Bgp) -> (usize, Rx) {
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
    peer.state = State::OpenConfirm;
    peer.peer_type = PeerType::EBGP;
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&V4.afi, &V4.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    peer.primary_conn_id = Some(CONN);
    peer.held_keepalive = Some(CONN);
    peer.down_reason = Some(PeerDownReason::AdminReset);
    peer.config.max_prefix.insert(
        V4,
        MaxPrefixConfig {
            limit: Some(1),
            ..Default::default()
        },
    );
    let (ptx, prx) = mpsc::unbounded_channel();
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    (id, prx)
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

fn over_limit_update() -> UpdatePacket {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("65004").unwrap()),
        nexthop: Some(BgpNexthop::Ipv4(Ipv4Addr::new(10, 0, 0, 4))),
        ..Default::default()
    });
    for prefix in SENT {
        packet.ipv4_update.push(Ipv4Nlri {
            id: 0,
            prefix: prefix.parse().unwrap(),
        });
    }
    packet
}

/// The packets sent to the peer, as (UPDATE prefixes announced, whether a
/// Cease NOTIFICATION was among them).
fn sent(rx: &mut Rx) -> (Vec<String>, bool) {
    let mut announced = Vec::new();
    let mut cease = false;
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, true, Some(ParseOption::default()))
            .expect("a well-formed packet");
        match packet {
            BgpPacket::Update(update) => {
                announced.extend(update.ipv4_update.iter().map(|n| n.prefix.to_string()));
            }
            BgpPacket::Notification(notification) => {
                cease |= notification.code == bgp_packet::NotifyCode::Cease;
            }
            _ => {}
        }
    }
    (announced, cease)
}

#[tokio::test]
async fn an_update_that_completes_the_handshake_and_trips_the_limit_leaves_nothing_behind() {
    let mut bgp = fresh_bgp();
    put_from_source(&mut bgp, DUMPED);
    let (c, mut rx) = held_peer(&mut bgp);

    let (mut top, peers) = split(&mut bgp);
    crate::bgp::peer::fsm(
        &mut top,
        peers,
        c,
        Event::UpdateMsg(over_limit_update()),
        None,
    );

    let peer = bgp.peers.get_by_idx(c).unwrap();
    assert_eq!(peer.state, State::Idle);
    assert!(peer.max_prefix.overflow.is_some(), "held past the limit");
    assert!(
        matches!(peer.last_reset, Some((PeerDownReason::MaximumPrefix, _))),
        "the parked AdminReset must not label this teardown: {:?}",
        peer.last_reset
    );
    assert!(peer.down_reason.is_none());

    // Update groups and the membership index: never joined, nothing left.
    assert!(peer.update_group_id.is_empty());
    assert!(
        bgp.update_groups
            .values()
            .flat_map(|af| af.groups.values())
            .all(|group| !group.members.contains(&c)),
        "no update group lists the peer"
    );
    assert!(
        bgp.peers
            .membership()
            .iter()
            .all(|(_, family)| family.iter_all().all(|ident| ident != c)),
        "the membership index does not list the peer"
    );

    // Egress state of the session that never came up.
    assert!(peer.pet.is_none());
    assert!(peer.sync_v4.is_none());

    // Timers: none of the session's; Idle holds without a restart.
    assert!(peer.timer.keepalive.is_none());
    assert!(peer.timer.hold_timer.is_none());
    assert!(peer.timer.max_prefix_restart.is_none());

    // The UPDATE's routes are gone again; the other peer's route stays.
    assert_eq!(bgp.shard.accepted_paths(c, Afi::Ip, Safi::Unicast), 0);
    assert_eq!(bgp.shard.adj_in_count(c, Afi::Ip, Safi::Unicast), 0);
    for prefix in SENT {
        let prefix: Ipv4Net = prefix.parse().unwrap();
        assert!(!bgp.shard.v4.1.contains_key(&prefix), "{prefix} cleaned");
    }
    let dumped: Ipv4Net = DUMPED.parse().unwrap();
    assert!(bgp.shard.v4.1.contains_key(&dumped));

    // The peer was told Cease and sent no session-up dump.
    let (announced, cease) = sent(&mut rx);
    assert!(cease, "a Cease NOTIFICATION was sent");
    assert!(announced.is_empty(), "no session-up dump: {announced:?}");
}
