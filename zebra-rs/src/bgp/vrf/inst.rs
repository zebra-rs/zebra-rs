//! Per-VRF BGP task — owns the runtime state for one
//! `router bgp vrf X` block.
//!
//! Mirrors the global [`crate::bgp::Bgp`] structure on a smaller
//! surface: a [`PeerMap`] for CE peers (populated in step 15),
//! a per-VRF [`LocalRib`] for the IPv4/IPv6 unicast Loc-RIB
//! (populated by best-path / import in step 17 / 18), and the
//! identity (`name`, `rd`, `router_id`) the global task supplies
//! at spawn time.
//!
//! Step 13 ships the type and the lifecycle (`event_loop`,
//! `serve_vrf`, `Shutdown` handling); step 14's `spawn_bgp_vrf`
//! is the first production consumer.

use std::net::Ipv4Addr;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use bgp_packet::RouteDistinguisher;

use crate::config::{ConfigChannel, ShowChannel};
use crate::context::{ProtoContext, Task};

use super::super::Message;
use super::super::peer_map::PeerMap;
use super::super::route::LocalRib;
use super::msg::{BgpGlobalMsg, BgpVrfMsg};

/// Per-VRF BGP runtime. One task per `router bgp vrf X` block.
///
/// Most fields are written by `BgpVrf::new` at spawn time but
/// don't gain a reader until later steps (15-18). The
/// `dead_code` allow goes away as each consumer site lands.
#[allow(dead_code)]
pub struct BgpVrf {
    /// VRF name (matches the YANG list key under
    /// `/router/bgp/vrf/<name>`). Used in log lines, `show bgp vrf
    /// <name> ...` dispatch, and as the `BgpGlobalMsg::Export` /
    /// `RegisterPeer` payload so the global task can attribute
    /// cross-task messages back to a VRF.
    pub name: String,
    /// Spawn-time runtime context built by step 14 via
    /// [`ProtoContext::for_vrf`]. Every socket the per-VRF runtime
    /// opens flows through `ctx.tcp_socket_v*` / `ctx.tcp_listen`
    /// and therefore inherits the `SO_BINDTODEVICE` binding step 8
    /// installed.
    pub ctx: ProtoContext,
    /// Per-VRF peer table — CE peers configured under
    /// `/router/bgp/vrf/<name>/neighbor/...`. Populated in step 15.
    pub peers: PeerMap,
    /// IPv4/IPv6 unicast Loc-RIB scoped to this VRF. VPNv4/v6 /
    /// EVPN stay anchored on the global Loc-RIB; the per-VRF Loc-
    /// RIB holds only the CE-facing surface plus routes imported
    /// from the global Loc-RIB via [`BgpVrfMsg::ImportV4`] /
    /// [`BgpVrfMsg::ImportV6`] (step 18).
    pub local_rib: LocalRib,
    /// Route Distinguisher prepended to VPNv4/v6 advertisements
    /// originated from this VRF. `None` until the operator has
    /// committed `set router bgp vrf <name> rd <RD>`; export to
    /// the global Loc-RIB (step 17) is gated on `rd.is_some()`.
    pub rd: Option<RouteDistinguisher>,
    /// Per-VRF BGP router-id. Defaults to the global router-id at
    /// spawn time (passed through by step 14); the operator may
    /// override via `set router bgp vrf <name> router-id <addr>`,
    /// in which case step 14 respawns the VRF with the new value.
    pub router_id: Ipv4Addr,
    /// Config-manager subscription. Path-dispatch by step 14
    /// routes `/router/bgp/vrf/<name>/...` callbacks here so the
    /// per-VRF runtime owns its own commit sequencing.
    pub cm: ConfigChannel,
    /// Show-command subscription. Step 20 wires `show bgp vrf
    /// <name> ...` to dispatch through this channel.
    pub show: ShowChannel,
    /// Outbound channel to the global `Bgp` task. Used for peer
    /// registration (step 16) and per-VRF best-path exports
    /// (step 17 / 18).
    pub global_tx: UnboundedSender<BgpGlobalMsg>,
    /// Inbound channel from the global `Bgp` task. The accept
    /// dispatcher (step 16) and the import pipeline (step 18) push
    /// here. `Shutdown` from `despawn_bgp_vrf` (step 14) also
    /// arrives on this channel.
    pub global_rx: UnboundedReceiver<BgpVrfMsg>,
    /// FSM event channel. Per-VRF peers send `Event(ident, ...)`
    /// here when their timers expire or their TCP state changes;
    /// the per-VRF event loop drives the FSM from these. Bounded
    /// (8192) to match the global `Bgp::tx/rx`. Step 15c lands the
    /// channel so peers can be materialized at spawn time; the
    /// loop drains it as a no-op until step 15d wires the FSM
    /// driver.
    pub tx: tokio::sync::mpsc::Sender<Message>,
    pub rx: tokio::sync::mpsc::Receiver<Message>,
    /// Local AS number. Threaded in from the global `Bgp::asn` at
    /// spawn time so per-VRF peers `Peer::new` can fill
    /// `local_as`. The per-VRF runtime does not maintain a
    /// separate ASN today; if a future spec requires one this is
    /// where it lives.
    pub asn: u32,
}

/// Sender side of the per-VRF inbound channel — handed back to
/// the global task at spawn time so `despawn_bgp_vrf` can send
/// `BgpVrfMsg::Shutdown`, and so the accept / import dispatchers
/// (step 16 / 18) can locate the matching VRF's queue.
pub type BgpVrfInbox = UnboundedSender<BgpVrfMsg>;

impl BgpVrf {
    /// Build a `BgpVrf` and the matching inbound sender. The
    /// caller (step 14's `spawn_bgp_vrf`) keeps the
    /// `BgpVrfInbox`, hands the `BgpVrf` to [`serve_vrf`], and
    /// stashes the inbox in a per-VRF registry so cross-task
    /// messages can locate this task.
    pub fn new(
        name: String,
        ctx: ProtoContext,
        rd: Option<RouteDistinguisher>,
        router_id: Ipv4Addr,
        asn: u32,
        global_tx: UnboundedSender<BgpGlobalMsg>,
    ) -> (Self, BgpVrfInbox) {
        let (inbox_tx, global_rx) = mpsc::unbounded_channel();
        let (tx, rx) = mpsc::channel(8192);
        let vrf = Self {
            name,
            ctx,
            peers: PeerMap::new(),
            local_rib: LocalRib::default(),
            rd,
            router_id,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            global_tx,
            global_rx,
            tx,
            rx,
            asn,
        };
        (vrf, inbox_tx)
    }

    /// Drive the per-VRF task. The loop exits cleanly when the
    /// global task sends [`BgpVrfMsg::Shutdown`] or when the
    /// inbound channel is closed (i.e. every sender — the global
    /// task plus any per-peer holds — has dropped).
    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                msg = self.global_rx.recv() => {
                    match msg {
                        Some(BgpVrfMsg::Shutdown) => {
                            tracing::info!(vrf = %self.name, "bgp vrf: shutdown");
                            break;
                        }
                        Some(other) => self.process_global_msg(other),
                        None => {
                            // All senders dropped — the global task
                            // exited without sending Shutdown.
                            tracing::info!(
                                vrf = %self.name,
                                "bgp vrf: inbound channel closed; exiting",
                            );
                            break;
                        }
                    }
                }
                _msg = self.cm.rx.recv() => {
                    // CM dispatch from /router/bgp/vrf/<name>/...
                    // arrives in step 14 once `spawn_bgp_vrf`
                    // registers the path handler. Step 13 drops it
                    // on the floor — no consumer has been wired
                    // yet, and the channel staying drained keeps
                    // the select! arm from livelocking.
                }
                _msg = self.show.rx.recv() => {
                    // `show bgp vrf <name> ...` dispatch lands in
                    // step 20. Same drain rationale as above.
                }
                Some(msg) = self.rx.recv() => {
                    // Per-VRF FSM event channel. Step 15c lands the
                    // channel so peers materialised at spawn time
                    // (also step 15c) have somewhere to send their
                    // timer events; step 15d wires the actual FSM
                    // driver. Until then, drain at debug — without
                    // this arm the materialised peer's `start()`
                    // timer would fill the bounded queue and stall
                    // the per-VRF runtime.
                    tracing::debug!(
                        vrf = %self.name,
                        msg = ?msg,
                        "bgp vrf: drained FSM event (step 15d wires the handler)",
                    );
                }
            }
        }
    }

    /// Per-task handling of cross-task messages that aren't
    /// `Shutdown`. Step 13 is intentionally a no-op match — every
    /// non-`Shutdown` variant is a stub for later steps.
    fn process_global_msg(&mut self, msg: BgpVrfMsg) {
        match msg {
            BgpVrfMsg::Accept(_, sockaddr) => {
                // Step 16 lands the global accept dispatcher that
                // routes us here; step 15d will pick up the
                // `TcpStream` and continue the FSM. Until then the
                // stream drops at the end of this arm and the TCP
                // connection closes.
                tracing::debug!(
                    vrf = %self.name,
                    peer = %sockaddr.ip(),
                    "bgp vrf: received inbound Accept (FSM driver lands in step 15d)",
                );
            }
            BgpVrfMsg::ImportV4 { .. } | BgpVrfMsg::ImportV6 { .. } => {
                // Step 18 wires the import insert + best-path.
            }
            BgpVrfMsg::WithdrawImport { .. } => {
                // Step 18.
            }
            BgpVrfMsg::Shutdown => unreachable!("handled in event_loop"),
        }
    }
}

/// Spawn the per-VRF event loop on its own tokio task. Mirrors
/// [`crate::bgp::inst::serve`] / [`crate::nd::inst::serve`].
pub fn serve_vrf(mut vrf: BgpVrf) -> Task<()> {
    Task::spawn(async move {
        vrf.event_loop().await;
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc::unbounded_channel;

    use crate::rib::client::{ProtoId, RibClient, RibInbound};

    use super::*;

    fn test_ctx_for_vrf(table_id: u32, ifname: &str) -> ProtoContext {
        // Parked RibClient — the test doesn't exercise rib.send().
        let (inbound_tx, inbound_rx) = unbounded_channel::<RibInbound>();
        Box::leak(Box::new(inbound_rx));
        let rib = RibClient::new(inbound_tx, ProtoId::from_raw(0));
        ProtoContext::for_vrf(rib, table_id, ifname.to_string())
    }

    #[tokio::test]
    async fn shutdown_message_exits_event_loop_within_timeout() {
        // Step 13's lifecycle invariant: `Shutdown` on the inbound
        // channel makes `event_loop` return — without that
        // contract, `despawn_bgp_vrf` (step 14) wouldn't be able
        // to tear a VRF task down cleanly.
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(10, "vrf-test");
        let (mut vrf, inbox) = BgpVrf::new(
            "vrf-test".to_string(),
            ctx,
            None,
            Ipv4Addr::UNSPECIFIED,
            65000,
            global_tx,
        );

        inbox.send(BgpVrfMsg::Shutdown).expect("inbound rx alive");

        // Two-second timeout: the loop should exit on the very
        // next `recv` call; a slow exit would indicate a deadlock
        // on the inbound channel.
        tokio::time::timeout(Duration::from_secs(2), vrf.event_loop())
            .await
            .expect("event_loop returns after Shutdown");
    }

    #[tokio::test]
    async fn inbox_drop_closes_event_loop() {
        // If every sender to the inbound channel is dropped, the
        // VRF task exits anyway — defensive cleanup so a buggy
        // step-14 caller that forgets to send `Shutdown` still
        // doesn't leak the task.
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(11, "vrf-test2");
        let (mut vrf, inbox) = BgpVrf::new(
            "vrf-test2".to_string(),
            ctx,
            None,
            Ipv4Addr::UNSPECIFIED,
            65000,
            global_tx,
        );

        drop(inbox);

        tokio::time::timeout(Duration::from_secs(2), vrf.event_loop())
            .await
            .expect("event_loop exits when inbox is dropped");
    }
}
