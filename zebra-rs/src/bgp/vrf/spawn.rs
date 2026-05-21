//! Spawn / despawn of [`BgpVrf`] tasks driven by the global Bgp's
//! `CommitEnd` diff (step 14 of the BGP MPLS/VPN refactor).
//!
//! The committed intent lives in [`crate::bgp::Bgp::vrfs`] (a
//! `BTreeMap<String, BgpVrfConfig>` populated by step 12's
//! callbacks). The running task set lives in
//! [`crate::bgp::Bgp::vrf_registry`]. After every commit the
//! diff between the two maps is computed, new VRF names get a
//! fresh [`BgpVrf`] + [`serve_vrf`], deleted names get a
//! [`BgpVrfMsg::Shutdown`].
//!
//! The current cut deliberately uses a placeholder
//! [`ProtoContext::default_table_no_rib`] for the per-VRF runtime:
//! step 14 doesn't open any per-VRF sockets, and the
//! `SO_BINDTODEVICE` plumbing only matters once peers exist
//! (step 15). The same step 15 lifts the placeholder to a real
//! [`ProtoContext::for_vrf`] built from a fresh per-VRF
//! `RibClient` subscription that carries the kernel `table_id`
//! through to [`crate::rib::client::ClientRegistry`].

use std::collections::BTreeMap;

use tokio::sync::mpsc::UnboundedSender;

use crate::context::{ProtoContext, Task};

use super::super::inst::RibKnownVrf;
use super::super::vrf_config::BgpVrfConfig;
use super::inst::{BgpVrf, BgpVrfInbox, serve_vrf};
use super::msg::{BgpGlobalMsg, BgpVrfMsg};

use crate::config::RibSubscriber;

/// Per-VRF task handle stashed on [`crate::bgp::Bgp::vrf_registry`].
/// Holds the inbound sender so the global task can dispatch
/// `Shutdown` / `Accept` / import deliveries, plus the spawned
/// [`Task`] so dropping the handle aborts the runtime cleanly.
pub struct BgpVrfHandle {
    pub inbox: BgpVrfInbox,
    /// Held so dropping the handle aborts the spawned event loop
    /// even if `despawn_bgp_vrf` was never called (defence in
    /// depth — a clean teardown sends `Shutdown` first). Not
    /// read directly anywhere; `Task` already runs its
    /// `AbortHandle` via `Drop`.
    #[allow(dead_code)]
    pub task: Task<()>,
    /// MPLS label allocated for this VRF by `Bgp::vrf_label_alloc`
    /// at spawn time. Mirrored back onto the handle so the global
    /// `Bgp` can reclaim it on despawn and reuse it on
    /// respawn-with-kernel-ctx — a respawn must keep the same
    /// label, otherwise a brief outage would invalidate PE-side
    /// FIB entries that already point at this VRF's old label.
    pub label: u32,
    /// VRF master ifindex used in the AF_MPLS DecapVrf ILM, when
    /// step 19b's spawn site successfully installed one. `None`
    /// when the spawn ran with no kernel info (placeholder ctx);
    /// the next `maybe_respawn_vrf_with_kernel_ctx` after the
    /// kernel VRF appears installs the ILM.
    pub ilm_decap_ifindex: Option<u32>,
}

/// Pure diff: which VRF names need to be spawned (in `desired`
/// but not `running`) and which need to be despawned (in
/// `running` but not `desired`). Names that appear in both are
/// considered unchanged at this step — step 14 doesn't yet detect
/// edits to `rd` / `router-id` / `label-mode`; step 15 layers
/// edit detection on top by hashing the cfg.
pub fn compute_vrf_diff(
    desired: &BTreeMap<String, BgpVrfConfig>,
    running: &BTreeMap<String, BgpVrfHandle>,
) -> (Vec<String>, Vec<String>) {
    let to_spawn: Vec<String> = desired
        .keys()
        .filter(|name| !running.contains_key(*name))
        .cloned()
        .collect();
    let to_despawn: Vec<String> = running
        .keys()
        .filter(|name| !desired.contains_key(*name))
        .cloned()
        .collect();
    (to_spawn, to_despawn)
}

/// Build + spawn a per-VRF task. Returns the handle the caller
/// stashes on `vrf_registry`. `kernel` carries the matching
/// kernel VRF master info if RIB has already told us about it;
/// when `None`, the spawn falls back to a placeholder
/// `ProtoContext::default_table_no_rib()` and the per-VRF runtime
/// won't bind sockets to a VRF master until the global Bgp task
/// re-spawns via
/// [`super::super::inst::Bgp::maybe_respawn_vrf_with_kernel_ctx`].
///
/// `rib_subscriber` mints the per-VRF [`RibClient`] when kernel
/// info is present — route installs from this task flow through
/// the matching `vrf_tables[table_id]` via step 9's inbound
/// dispatcher. With no kernel info, the spawn uses a parked
/// `RibClient`; routes sent through it land in the global table
/// until the respawn happens.
///
/// `global_tx` is the shared sender every VRF task uses to push
/// back to the global runtime (one channel, fanned in from every
/// VRF).
pub fn spawn_bgp_vrf(
    name: String,
    cfg: &BgpVrfConfig,
    router_id: std::net::Ipv4Addr,
    asn: u32,
    label: u32,
    kernel: Option<RibKnownVrf>,
    rib_subscriber: &RibSubscriber,
    global_tx: UnboundedSender<BgpGlobalMsg>,
) -> BgpVrfHandle {
    // Snapshot for logging + ILM install so we can move
    // `kernel` into the ctx-building arm without re-borrowing
    // later.
    let kernel_table_id = kernel.as_ref().map(|k| k.table_id);
    let kernel_ifindex = kernel.as_ref().map(|k| k.ifindex);
    let ctx = match kernel {
        Some(k) => {
            // Mint a fresh `RibClient` for this VRF. The
            // subscription's `vrf_id` tells RIB to route the
            // task's route installs into `vrf_tables[table_id]`
            // (step 9's inbound dispatcher). The `RibRx` half is
            // leaked — per-VRF subscribers don't yet consume RIB
            // outbound notifications; that's a future step.
            let proto = format!("bgp:vrf:{name}");
            let (rib_client, rib_rx) = rib_subscriber.subscribe_for_vrf(&proto, k.table_id);
            Box::leak(Box::new(rib_rx));
            ProtoContext::for_vrf(rib_client, k.table_id, name.clone())
        }
        None => {
            tracing::debug!(
                vrf = %name,
                "bgp: spawning per-VRF task with placeholder context (kernel VRF not yet known)",
            );
            ProtoContext::default_table_no_rib()
        }
    };
    // Per-VRF override on router-id wins over the global one. An
    // operator edit to router-id post-spawn doesn't bubble through
    // yet — a follow-up adds the respawn-on-edit detection.
    let effective_router_id = cfg.router_id.unwrap_or(router_id);
    let (mut vrf, inbox) = BgpVrf::new(
        name.clone(),
        ctx,
        cfg.rd,
        effective_router_id,
        asn,
        label,
        global_tx,
    );

    // Materialise per-VRF peers from the BgpVrfConfig snapshot.
    // Step 15c is scaffolding — the per-VRF FSM driver lands in
    // step 15d, and until then `peer.start()`'s timer events get
    // logged at debug and dropped by `BgpVrf::event_loop`. Peers
    // without a `remote_as` are skipped: `Peer::start` gates on
    // `remote_as != 0`, so inserting them would only litter the
    // map with permanently-Idle entries.
    let peer_count = materialize_peers(&mut vrf, cfg);

    // Step 16: register each materialised peer with the global
    // accept dispatcher so an inbound `:179` from that IP lands
    // on this VRF task via `BgpVrfMsg::Accept` instead of the
    // global instance.
    for addr in vrf.peers.keys().copied().collect::<Vec<_>>() {
        let _ = vrf.global_tx.send(BgpGlobalMsg::RegisterPeer {
            vrf: name.clone(),
            addr,
        });
    }

    // Step 19b: install the AF_MPLS DecapVrf ILM at the
    // allocated label so a remote PE's VPNv4 packet with this
    // label pops + lands in `vrf_tables[table_id]`. Only when
    // we have kernel info — a placeholder-ctx spawn skips the
    // install; the `maybe_respawn_vrf_with_kernel_ctx` path
    // re-runs with kernel info and installs the ILM then.
    let ilm_decap_ifindex = match (kernel_table_id, kernel_ifindex) {
        (Some(table_id), Some(vrf_ifindex)) if label != 0 => {
            let entry = crate::rib::inst::IlmEntry {
                rtype: crate::rib::RibType::Bgp,
                ilm_type: crate::rib::inst::IlmType::DecapVrf {
                    table_id,
                    vrf_ifindex,
                },
                nexthop: crate::rib::Nexthop::default(),
            };
            rib_subscriber.send_ilm_add(label, entry);
            Some(vrf_ifindex)
        }
        _ => None,
    };

    let task = serve_vrf(vrf);
    tracing::info!(
        vrf = %name,
        rd = ?cfg.rd,
        router_id = %effective_router_id,
        table_id = ?kernel_table_id,
        label,
        ilm_installed = ilm_decap_ifindex.is_some(),
        peers = peer_count,
        "bgp: spawned per-VRF task",
    );
    BgpVrfHandle {
        inbox,
        task,
        label,
        ilm_decap_ifindex,
    }
}

/// Build `Peer` objects from `cfg.neighbors` and insert them into
/// `vrf.peers`. Calls `peer.start()` on each — that arms the
/// idle-hold timer; once it fires the FSM event lands on
/// `vrf.tx`, which step 15c only drains at debug.
fn materialize_peers(vrf: &mut BgpVrf, cfg: &BgpVrfConfig) -> usize {
    use super::super::peer::Peer;
    use super::super::peer_key::PeerKey;

    let mut count = 0usize;
    for (addr, nbr_cfg) in &cfg.neighbors {
        // `Peer::start()` gates on `remote_as != 0` already, but
        // skipping the insert entirely keeps the per-VRF peer map
        // free of dormant rows the show path would have to render
        // as "remote-as: unset". When the operator later types
        // the missing leaf the follow-up commit re-runs
        // `materialize_peers` (step 15d hooks the per-VRF CM
        // dispatch) and the peer arrives.
        let Some(remote_as) = nbr_cfg.remote_as else {
            tracing::debug!(
                vrf = %vrf.name,
                peer = %addr,
                "bgp vrf: skip peer without remote-as",
            );
            continue;
        };
        let mut peer = Peer::new(
            0,
            vrf.asn,
            vrf.router_id,
            remote_as,
            *addr,
            // Per-VRF hostnames aren't a thing today; the global
            // hostname / OS hostname applies to every session.
            None,
            vrf.tx.clone(),
            vrf.ctx.clone(),
        );
        peer.start();
        vrf.peers.insert_with_key(PeerKey::Addr(*addr), peer);
        count += 1;
    }
    count
}

/// Send `Shutdown` to the per-VRF task. Caller drops the handle
/// from `vrf_registry` *after* this returns; dropping the handle
/// without sending `Shutdown` first would leak a final
/// `BgpVrfMsg` send window — the FSM might miss state it needs to
/// flush. The handle's `Task` aborts on drop regardless, so a
/// failure path here doesn't strand the runtime.
pub fn despawn_bgp_vrf(name: &str, handle: &BgpVrfHandle) {
    if handle.inbox.send(BgpVrfMsg::Shutdown).is_err() {
        // Receiver already gone — the task exited on its own
        // (e.g. inbox-drop path). Nothing left to do.
        tracing::debug!(
            vrf = %name,
            "bgp: despawn target already exited; cleanup is a no-op",
        );
        return;
    }
    tracing::info!(vrf = %name, "bgp: sent Shutdown to per-VRF task");
}

#[cfg(test)]
mod tests {
    //! Pure-function tests on [`compute_vrf_diff`]. Spawn /
    //! despawn themselves need a `Bgp` to drive end-to-end, which
    //! is exercised by the BDD scenarios in step 14's follow-up;
    //! the diff function is the part that's worth unit-testing in
    //! isolation because it's where the spawn / despawn decision
    //! actually lives.
    use std::net::Ipv4Addr;

    use tokio::sync::mpsc::unbounded_channel;

    use super::*;

    fn handle(name: &str) -> BgpVrfHandle {
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let cfg = BgpVrfConfig::default();
        // Pass `None` for the kernel info — the diff tests don't
        // need the per-VRF `SO_BINDTODEVICE` binding; the
        // placeholder context is enough for lifecycle testing.
        let subscriber = test_rib_subscriber();
        spawn_bgp_vrf(
            name.to_string(),
            &cfg,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            None,
            &subscriber,
            global_tx,
        )
    }

    fn test_rib_subscriber() -> RibSubscriber {
        let (rib_tx, rib_rx) = unbounded_channel();
        let (rib_inbound_tx, inbound_rx) = unbounded_channel();
        Box::leak(Box::new(rib_rx));
        Box::leak(Box::new(inbound_rx));
        RibSubscriber::for_test(
            rib_tx,
            rib_inbound_tx,
            std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
        )
    }

    #[tokio::test]
    async fn materialize_peers_inserts_neighbors_with_remote_as() {
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;

        // Construct a BgpVrf directly (no spawn) so we can inspect
        // `vrf.peers` after `materialize_peers` runs. Per-VRF FSM
        // events go through `vrf.tx`, which we drain via the rx in
        // step 15c's event loop — but the loop isn't running in
        // this test, so the timer events `peer.start()` arms stay
        // queued until the rx is dropped at end of scope.
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            None,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
        );

        let mut cfg = BgpVrfConfig::default();
        let with_as: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let no_as: std::net::IpAddr = "192.0.2.2".parse().unwrap();
        cfg.neighbors.insert(
            with_as,
            BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            },
        );
        cfg.neighbors.insert(no_as, BgpVrfNeighborConfig::default());

        let count = materialize_peers(&mut vrf, &cfg);

        // Only the neighbor with `remote-as` set is materialised —
        // `Peer::start()` gates on `remote_as != 0`, and inserting
        // a dormant entry would clutter `show bgp vrf v1 summary`
        // output until the operator filled the leaf in.
        assert_eq!(count, 1);
        assert!(
            vrf.peers.get(&with_as).is_some(),
            "peer with remote-as inserted"
        );
        assert!(
            vrf.peers.get(&no_as).is_none(),
            "neighbor without remote-as skipped"
        );
    }

    #[tokio::test]
    async fn materialize_peers_with_no_neighbors_returns_zero() {
        use super::super::super::vrf_config::BgpVrfConfig;
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v0".to_string(),
            ctx,
            None,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
        );

        let cfg = BgpVrfConfig::default();
        assert_eq!(materialize_peers(&mut vrf, &cfg), 0);
    }

    #[tokio::test]
    async fn diff_with_no_running_yields_all_as_spawn() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        desired.insert("v2".to_string(), BgpVrfConfig::default());
        let running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert_eq!(to_spawn, vec!["v1".to_string(), "v2".to_string()]);
        assert!(to_despawn.is_empty());
    }

    #[tokio::test]
    async fn diff_with_no_desired_yields_all_as_despawn() {
        let desired: BTreeMap<String, BgpVrfConfig> = BTreeMap::new();
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1"));
        running.insert("v2".to_string(), handle("v2"));

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert!(to_spawn.is_empty());
        assert_eq!(to_despawn, vec!["v1".to_string(), "v2".to_string()]);
    }

    #[tokio::test]
    async fn diff_mixed_returns_only_deltas() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        desired.insert("v3".to_string(), BgpVrfConfig::default()); // new
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1")); // unchanged
        running.insert("v2".to_string(), handle("v2")); // removed

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert_eq!(to_spawn, vec!["v3".to_string()]);
        assert_eq!(to_despawn, vec!["v2".to_string()]);
    }

    #[tokio::test]
    async fn diff_with_matching_sets_is_empty() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1"));

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert!(to_spawn.is_empty());
        assert!(to_despawn.is_empty());
    }
}
