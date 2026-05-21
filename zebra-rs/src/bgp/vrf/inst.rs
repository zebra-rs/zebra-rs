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
use super::super::interface_addrs::InterfaceAddrs;
use super::super::peer_map::PeerMap;
use super::super::route::LocalRib;
use super::super::store::BgpAttrStore;
use super::super::update_group::UpdateGroupMap;
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
    /// Dedup pool for `BgpAttr` instances seen by this VRF's
    /// peers. Step 15d gives every per-VRF runtime its own pool
    /// (cheaper than threading a shared lock across the `!Send`
    /// boundary, and the attribute populations are largely
    /// disjoint between VRFs in practice).
    pub attr_store: BgpAttrStore,
    /// IOS-XR-style update-groups scoped to this VRF. Same
    /// rationale as `attr_store`: per-VRF copy avoids cross-task
    /// sharing.
    pub update_groups: UpdateGroupMap,
    /// Per-link IPv6 link-local cache for RFC 8950 next-hop
    /// resolution. The per-VRF runtime starts with an empty
    /// cache; BGP unnumbered (interface-neighbor) lives on the
    /// global instance and isn't yet exposed at the VRF surface.
    /// Step 15d threads this through `BgpTop` so the FSM driver
    /// compiles even though no path here populates it today.
    pub interface_addrs: InterfaceAddrs,
}

/// Sender side of the per-VRF inbound channel — handed back to
/// the global task at spawn time so `despawn_bgp_vrf` can send
/// `BgpVrfMsg::Shutdown`, and so the accept / import dispatchers
/// (step 16 / 18) can locate the matching VRF's queue.
pub type BgpVrfInbox = UnboundedSender<BgpVrfMsg>;

/// Hook handed to the shared `route_update_ipv4` path so a
/// per-VRF best-path winner gets pushed up to the global Bgp
/// task as a VPNv4 export candidate. Carries the VRF name (so
/// the global side can look up RD + RT) and the per-VRF
/// `global_tx` channel.
///
/// The global `Bgp` task constructs its own `BgpTop` with
/// `vrf_export = None`, so the shared route pipeline doesn't
/// fire any export for default-VRF traffic. Per-VRF tasks build
/// a `BgpTop` with `Some(VrfExporter { ... })` and the same
/// code path emits exports as a side-effect.
pub struct VrfExporter {
    pub name: String,
    pub tx: UnboundedSender<BgpGlobalMsg>,
}

/// Send a `BgpGlobalMsg::Export` for `prefix` carrying the
/// winner's `BgpAttr` (cloned out of the `Arc` so the global
/// task can re-intern). Step 17b-iii's hook calls this from
/// `route_update_ipv4` after best-path returns a non-empty
/// `selected`. `label = 0` is the step-19 stub — the global
/// handler treats that as "skip the per-route install" rather
/// than emit an explicit-null label.
pub fn vrf_emit_export(
    exporter: &VrfExporter,
    prefix: ipnet::Ipv4Net,
    attr: &bgp_packet::BgpAttr,
    label: u32,
) {
    let _ = exporter.tx.send(BgpGlobalMsg::Export {
        vrf: exporter.name.clone(),
        prefix,
        attr: attr.clone(),
        label,
    });
}

/// Send a `BgpGlobalMsg::WithdrawExport` for `prefix`. Step
/// 17b-iii calls this when `route_update_ipv4` / withdraw path
/// observes the per-VRF best-path go from "has a winner" to
/// "empty" — the global instance drops the matching VPNv4 row.
pub fn vrf_emit_withdraw(exporter: &VrfExporter, prefix: ipnet::Ipv4Net) {
    let _ = exporter.tx.send(BgpGlobalMsg::WithdrawExport {
        vrf: exporter.name.clone(),
        prefix,
    });
}

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
            attr_store: BgpAttrStore::new(),
            update_groups: super::super::update_group::empty_map(),
            interface_addrs: InterfaceAddrs::new(),
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
                    self.process_msg(msg);
                }
            }
        }
    }

    /// Step 17b-i hook: push a freshly-elected best-path winner to
    /// the global Bgp task as a VPNv4 export candidate. The global
    /// side prepends the VRF's RD and tags the configured
    /// export-RT set before inserting into `LocalRib.v4vpn`.
    ///
    /// Caller hands over `attr` by value — the global task
    /// re-interns into its own `BgpAttrStore`. `label` is a per-VRF
    /// MPLS label allocated by step 19; until that lands, callers
    /// pass `0` and the global side logs / skips the install.
    ///
    /// Not yet wired into the per-VRF FSM. Step 17b-ii hooks it
    /// to the post-best-path notification in
    /// [`Self::process_msg`].
    #[allow(dead_code)] // first caller lands in step 17b-ii.
    pub fn export_best_path(&self, prefix: ipnet::Ipv4Net, attr: bgp_packet::BgpAttr, label: u32) {
        let _ = self.global_tx.send(BgpGlobalMsg::Export {
            vrf: self.name.clone(),
            prefix,
            attr,
            label,
        });
    }

    /// Inverse of [`Self::export_best_path`]. Tells the global
    /// task to withdraw the matching VPNv4 advertisement.
    #[allow(dead_code)] // first caller lands in step 17b-ii.
    pub fn withdraw_exported(&self, prefix: ipnet::Ipv4Net) {
        let _ = self.global_tx.send(BgpGlobalMsg::WithdrawExport {
            vrf: self.name.clone(),
            prefix,
        });
    }

    /// Handle a per-VRF FSM event off `self.rx`. Step 15d wires
    /// the same set the global `Bgp::process_msg` handles —
    /// minus `Accept` (passive accept lives at the global task
    /// and is forwarded via `BgpVrfMsg::Accept`; step 15d doesn't
    /// yet drive that path because `peer::accept` is tied to the
    /// global `Bgp`).
    fn process_msg(&mut self, msg: Message) {
        use super::super::peer::{BgpTop, fsm};
        match msg {
            Message::Event(ident, event) => {
                // Build a fresh `VrfExporter` per call so the
                // shared `route_update_ipv4` path emits Export to
                // the global Bgp instance when this VRF's
                // best-path changes. The handle is the same
                // `global_tx` the per-VRF runtime already holds;
                // we wrap it with the VRF name so the receiver
                // can resolve RD/RT.
                let exporter = VrfExporter {
                    name: self.name.clone(),
                    tx: self.global_tx.clone(),
                };
                let mut top = BgpTop {
                    router_id: &self.router_id,
                    local_rib: &mut self.local_rib,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    vrf_export: Some(&exporter),
                    // Color → Flex-Algo binding is a default-VRF
                    // concept today; per-VRF support is a follow-up.
                    color_policy: None,
                    flex_algo_routes: None,
                };
                fsm(&mut top, &mut self.peers, ident, event);
            }
            Message::Accept(_, _) => {
                // Active-connect path is driven by `Event(...)` from
                // peer-side timers; the global Bgp's accept
                // dispatcher routes passive connections to a VRF
                // via `BgpVrfMsg::Accept`, but `peer::accept` is
                // tied to `&mut Bgp` — refactoring it for per-VRF
                // is a follow-up. Drop here so the channel doesn't
                // accumulate stale Accepts if `peer.rs::accept`
                // ever gains a path that sends into `vrf.tx`.
                tracing::debug!(
                    vrf = %self.name,
                    "bgp vrf: ignored Accept on vrf.tx (active-only path in step 15d)",
                );
            }
            Message::Show(tx) => {
                // Re-route to the global show subsystem by echoing
                // the request back through the bounded tx. Step
                // 20 wires `show bgp vrf <name>` properly.
                let _ = self.tx.try_send(Message::Show(tx));
            }
            Message::FlushUpdateGroupIpv4(group_id) => {
                super::super::update_group::flush_ipv4(
                    &mut self.update_groups,
                    &mut self.peers,
                    &mut self.attr_store,
                    &group_id,
                    &self.interface_addrs,
                );
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

    #[tokio::test]
    async fn export_best_path_sends_global_msg_with_payload() {
        // Step 17b-i invariant: `export_best_path` pushes a
        // `BgpGlobalMsg::Export` carrying the VRF name, prefix,
        // attr (by value), and label stub. The global instance's
        // handler is exercised separately; here we only verify
        // the producer side.
        let (global_tx, mut global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(20, "vrf-export");
        let (vrf, _inbox) = BgpVrf::new(
            "vrf-export".to_string(),
            ctx,
            None,
            Ipv4Addr::UNSPECIFIED,
            65000,
            global_tx,
        );

        let prefix: ipnet::Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let attr = bgp_packet::BgpAttr::default();
        vrf.export_best_path(prefix, attr.clone(), 0);

        let msg = global_rx
            .try_recv()
            .expect("Export pushed onto global channel");
        match msg {
            BgpGlobalMsg::Export {
                vrf: v,
                prefix: p,
                attr: a,
                label,
            } => {
                assert_eq!(v, "vrf-export");
                assert_eq!(p, prefix);
                assert_eq!(a, attr);
                assert_eq!(label, 0);
            }
            other => panic!("expected Export, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn withdraw_exported_sends_global_msg() {
        let (global_tx, mut global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(21, "vrf-withdraw");
        let (vrf, _inbox) = BgpVrf::new(
            "vrf-withdraw".to_string(),
            ctx,
            None,
            Ipv4Addr::UNSPECIFIED,
            65000,
            global_tx,
        );

        let prefix: ipnet::Ipv4Net = "10.0.0.0/24".parse().unwrap();
        vrf.withdraw_exported(prefix);

        let msg = global_rx
            .try_recv()
            .expect("WithdrawExport pushed onto global channel");
        match msg {
            BgpGlobalMsg::WithdrawExport { vrf: v, prefix: p } => {
                assert_eq!(v, "vrf-withdraw");
                assert_eq!(p, prefix);
            }
            other => panic!("expected WithdrawExport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn vrf_emit_export_sends_export_msg_via_exporter() {
        // Step 17b-iii: the free-function hook called from
        // `route_update_ipv4`'s post-best-path arm pushes an
        // Export with the winner's prefix + attr + label stub.
        let (tx, mut rx) = unbounded_channel::<BgpGlobalMsg>();
        let exporter = VrfExporter {
            name: "vrf-hook".to_string(),
            tx,
        };
        let prefix: ipnet::Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let attr = bgp_packet::BgpAttr::default();

        vrf_emit_export(&exporter, prefix, &attr, 0);

        let msg = rx.try_recv().expect("Export pushed");
        match msg {
            BgpGlobalMsg::Export {
                vrf,
                prefix: p,
                attr: a,
                label,
            } => {
                assert_eq!(vrf, "vrf-hook");
                assert_eq!(p, prefix);
                assert_eq!(a, attr);
                assert_eq!(label, 0);
            }
            other => panic!("expected Export, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn vrf_emit_withdraw_sends_withdraw_export_msg() {
        let (tx, mut rx) = unbounded_channel::<BgpGlobalMsg>();
        let exporter = VrfExporter {
            name: "vrf-hook2".to_string(),
            tx,
        };
        let prefix: ipnet::Ipv4Net = "10.0.0.0/24".parse().unwrap();

        vrf_emit_withdraw(&exporter, prefix);

        let msg = rx.try_recv().expect("WithdrawExport pushed");
        match msg {
            BgpGlobalMsg::WithdrawExport { vrf, prefix: p } => {
                assert_eq!(vrf, "vrf-hook2");
                assert_eq!(p, prefix);
            }
            other => panic!("expected WithdrawExport, got {other:?}"),
        }
    }
}
