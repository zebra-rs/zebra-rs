//! Review finding #21, the `bgp router-id` item: a change of the effective
//! BGP Identifier must reach every session.
//!
//! A peer learns our BGP Identifier only from our OPEN, so a session that
//! sent one keeps the old identifier until it is re-established. Nothing
//! re-established it: `set_router_id` only rewrote the peers' snapshots
//! ("the next OPEN picks up the new one"). Meanwhile our own checks moved
//! to the new identifier: a route of ours an RR reflects back carries the
//! old one as ORIGINATOR_ID (the RR stamps it from our OPEN) and passes the
//! inbound loop check; routes we already reflected carry the old one in
//! CLUSTER_LIST, which our loop check no longer recognises; and the gate-on
//! engines keep the old identifier in the `SyncCtx` each member captured
//! when it joined. FRR, IOS and Junos reset every session on a router-id
//! change.
//!
//! The per-VRF tasks capture the effective router-id at spawn and are
//! respawned when it changes — but only at `CommitEnd`. A RIB-derived
//! router-id (`system router-id`, or the automatic pick) arrives outside
//! any commit, so a VRF on the global router-id kept the old one until the
//! next commit, whatever it changed, respawned it (and bounced its CE
//! sessions).

use super::*;
use crate::bgp::peer::{Event as PeerEvent, Peer, PeerDownReason, State};
use crate::bgp::vrf_config::BgpVrfConfig;
use crate::config::{ConfigOp, ConfigRequest};
use crate::rib::api::RibRx;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;

const OLD: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const NEW: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
const VRF_OWN_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 77);

/// A BGP instance whose effective router-id is [`OLD`], learned from the
/// RIB (no `router bgp global router-id`).
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
    bgp.process_rib_msg(RibRx::RouterIdUpdate(OLD));
    assert_eq!(bgp.router_id, OLD);
    bgp
}

/// An iBGP neighbor at `addr` whose session is in `state` — put back in
/// it when the neighbor exists.
fn add_peer(bgp: &mut Bgp, addr: &str, state: State) -> usize {
    let ip: IpAddr = addr.parse().unwrap();
    if let Some(peer) = bgp.peers.get_mut(&ip) {
        peer.state = state;
        return peer.ident;
    }
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let mut peer = Peer::new(
        0,
        65000,
        bgp.router_id,
        65000,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = state;
    bgp.peers.insert(ip, peer);
    bgp.peers.get(&ip).unwrap().ident
}

/// Every neighbor's session state.
fn states(bgp: &mut Bgp) -> BTreeMap<usize, State> {
    bgp.peers
        .iter_mut_all()
        .map(|(_, peer)| (peer.ident, peer.state))
        .collect()
}

/// Run `change` and return the neighbors whose session it reset (left the
/// state it was in).
fn resets(bgp: &mut Bgp, change: impl FnOnce(&mut Bgp)) -> BTreeSet<usize> {
    let before = states(bgp);
    change(bgp);
    let after = states(bgp);
    before
        .into_iter()
        .filter(|(ident, state)| after.get(ident) != Some(state))
        .map(|(ident, _)| ident)
        .collect()
}

/// The reason recorded for the neighbor's last reset.
fn last_reset(bgp: &Bgp, addr: &str) -> Option<PeerDownReason> {
    bgp.peers
        .get(&addr.parse().unwrap())
        .unwrap()
        .last_reset
        .as_ref()
        .map(|(reason, _)| *reason)
}

/// One neighbor in each FSM state (put back in it on a later call);
/// returns the ones that have sent an OPEN (OpenSent, OpenConfirm,
/// Established).
fn peers_in_every_state(bgp: &mut Bgp) -> BTreeSet<usize> {
    add_peer(bgp, "10.0.0.1", State::Idle);
    add_peer(bgp, "10.0.0.2", State::Connect);
    add_peer(bgp, "10.0.0.3", State::Active);
    [
        add_peer(bgp, "10.0.0.4", State::OpenSent),
        add_peer(bgp, "10.0.0.5", State::OpenConfirm),
        add_peer(bgp, "10.0.0.6", State::Established),
    ]
    .into_iter()
    .collect()
}

/// `set router bgp global router-id` as the config callback applies it.
fn configure_router_id(bgp: &mut Bgp, id: Option<Ipv4Addr>) {
    bgp.router_id_config = id;
    bgp.refresh_router_id();
}

/// A configured router-id change bounces every session that has sent an
/// OPEN, so the next one carries the new identifier; a session that has
/// not sent one yet picks it up on its own.
#[tokio::test]
async fn a_configured_router_id_change_bounces_every_session_that_sent_an_open() {
    let mut bgp = fresh_bgp();
    let sent_open = peers_in_every_state(&mut bgp);
    let reset = resets(&mut bgp, |bgp| configure_router_id(bgp, Some(NEW)));
    assert_eq!(bgp.router_id, NEW);
    assert_eq!(reset, sent_open);
    for (_, peer) in bgp.peers.iter_mut_all() {
        assert_eq!(
            peer.router_id, NEW,
            "the next OPEN carries the new identifier"
        );
    }
    // The Established session's reset says why.
    assert_eq!(
        last_reset(&bgp, "10.0.0.6"),
        Some(PeerDownReason::RouterIdChange)
    );
}

/// The reset does not travel through the bounded event queue: a router-id
/// change that finds the queue full still resets the session. A queued
/// `Event::Stop` was dropped silently, leaving the neighbor on the old
/// identifier with nothing to retry it.
#[tokio::test]
async fn a_router_id_change_resets_the_session_with_the_event_queue_full() {
    let mut bgp = fresh_bgp();
    let ident = add_peer(&mut bgp, "10.0.0.4", State::Established);
    while bgp.tx.capacity() > 0 {
        bgp.tx
            .try_send(Message::Event(ident, PeerEvent::ConfigUpdate))
            .unwrap();
    }
    bgp.process_rib_msg(RibRx::RouterIdUpdate(NEW));
    assert_eq!(bgp.router_id, NEW);
    assert_ne!(
        bgp.peers.get_by_idx(ident).unwrap().state,
        State::Established,
        "the router-id changed but the session was not reset"
    );
    assert_eq!(
        last_reset(&bgp, "10.0.0.4"),
        Some(PeerDownReason::RouterIdChange)
    );
}

/// The same for a RIB-derived change (`system router-id`, or the
/// automatic pick), and for deleting the configured router-id, which
/// falls back to the RIB-derived one.
#[tokio::test]
async fn a_rib_router_id_change_bounces_the_sessions() {
    let mut bgp = fresh_bgp();
    let sent_open = peers_in_every_state(&mut bgp);
    let reset = resets(&mut bgp, |bgp| {
        bgp.process_rib_msg(RibRx::RouterIdUpdate(NEW))
    });
    assert_eq!(bgp.router_id, NEW);
    assert_eq!(reset, sent_open);

    peers_in_every_state(&mut bgp);
    let reset = resets(&mut bgp, |bgp| configure_router_id(bgp, Some(OLD)));
    assert_eq!(reset, sent_open);
    peers_in_every_state(&mut bgp);
    let reset = resets(&mut bgp, |bgp| configure_router_id(bgp, None));
    assert_eq!(bgp.router_id, NEW, "back to the RIB-derived router-id");
    assert_eq!(reset, sent_open);
}

/// Control: a RIB-derived change under a configured router-id leaves the
/// effective one as it is, and re-setting the router-id in force changes
/// nothing — neither bounces a session.
#[tokio::test]
async fn a_change_that_leaves_the_effective_router_id_bounces_nothing() {
    let mut bgp = fresh_bgp();
    configure_router_id(&mut bgp, Some(OLD));
    peers_in_every_state(&mut bgp);
    let reset = resets(&mut bgp, |bgp| {
        bgp.process_rib_msg(RibRx::RouterIdUpdate(NEW));
        configure_router_id(bgp, Some(OLD));
    });
    assert_eq!(bgp.router_id, OLD);
    assert_eq!(reset, BTreeSet::new());
}

/// Commit `vrfs` (added to the desired config) as the config manager does:
/// the per-VRF tasks spawn at `CommitEnd`.
fn commit(bgp: &mut Bgp, vrfs: &[(&str, Option<Ipv4Addr>)]) {
    bgp.process_cm_msg(ConfigRequest::new(vec![], ConfigOp::CommitStart));
    for (name, router_id) in vrfs {
        bgp.vrfs.insert(
            name.to_string(),
            BgpVrfConfig {
                router_id: *router_id,
                ..Default::default()
            },
        );
    }
    bgp.process_cm_msg(ConfigRequest::new(vec![], ConfigOp::CommitEnd));
}

/// The running VRF task's show channel: a new one means a respawn.
fn vrf_task(bgp: &Bgp, name: &str) -> mpsc::UnboundedSender<crate::config::DisplayRequest> {
    bgp.vrf_registry[name].show_tx.clone()
}

/// A RIB-derived router-id change reaches the VRF on the global router-id
/// at once — it is respawned with the new one — while the VRF with a
/// router-id of its own keeps running.
#[tokio::test]
async fn a_rib_router_id_change_respawns_the_vrfs_on_the_global_router_id() {
    let mut bgp = fresh_bgp();
    commit(&mut bgp, &[("red", None), ("blue", Some(VRF_OWN_ID))]);
    assert_eq!(bgp.vrf_registry["red"].router_id, OLD);
    assert_eq!(bgp.vrf_registry["blue"].router_id, VRF_OWN_ID);
    let blue = vrf_task(&bgp, "blue");

    bgp.process_rib_msg(RibRx::RouterIdUpdate(NEW));
    assert_eq!(bgp.vrf_registry["red"].router_id, NEW);
    assert!(
        vrf_task(&bgp, "blue").same_channel(&blue),
        "blue keeps running"
    );
}

/// A commit after a RIB-derived router-id change respawns no VRF: the
/// change was applied when it arrived. (It used to respawn every VRF on
/// the global router-id, whatever the commit changed.)
#[tokio::test]
async fn a_commit_after_a_rib_router_id_change_respawns_nothing() {
    let mut bgp = fresh_bgp();
    commit(&mut bgp, &[("red", None), ("blue", Some(VRF_OWN_ID))]);
    bgp.process_rib_msg(RibRx::RouterIdUpdate(NEW));
    let (red, blue) = (vrf_task(&bgp, "red"), vrf_task(&bgp, "blue"));

    commit(&mut bgp, &[]);
    assert!(
        vrf_task(&bgp, "red").same_channel(&red),
        "red is not respawned"
    );
    assert!(vrf_task(&bgp, "blue").same_channel(&blue));
}

/// Control: a configured router-id change inside a commit respawns the VRF
/// on the global router-id once, at that commit's end — as before — and
/// not mid-transaction, where the rest of the commit (the VRF's own config,
/// say) may not be applied yet.
#[tokio::test]
async fn a_configured_router_id_change_respawns_the_vrf_at_commit_end() {
    let mut bgp = fresh_bgp();
    commit(&mut bgp, &[("red", None)]);
    let red = vrf_task(&bgp, "red");

    bgp.process_cm_msg(ConfigRequest::new(vec![], ConfigOp::CommitStart));
    configure_router_id(&mut bgp, Some(NEW));
    assert!(
        vrf_task(&bgp, "red").same_channel(&red),
        "not respawned before CommitEnd"
    );
    bgp.process_cm_msg(ConfigRequest::new(vec![], ConfigOp::CommitEnd));
    assert_eq!(bgp.vrf_registry["red"].router_id, NEW);
    let respawned = vrf_task(&bgp, "red");
    assert!(!respawned.same_channel(&red));

    commit(&mut bgp, &[]);
    assert!(vrf_task(&bgp, "red").same_channel(&respawned));
}
