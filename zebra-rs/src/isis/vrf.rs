//! Per-VRF IS-IS instance spawn / despawn.
//!
//! Unlike BGP — which stages a small typed `BgpVrfConfig` and
//! materializes a subset at spawn — IS-IS reuses the **whole**
//! [`Isis`] instance per VRF. The default `router isis` task acts as a
//! thin parent: it forwards every `/router/isis/vrf/<name>/…` config
//! line, rewritten to strip the `vrf <name>` prefix (see
//! [`crate::config::vrf_redirect_split`]), into a full per-VRF `Isis`
//! whose existing callbacks / SPF / RIB / show paths run unchanged.
//!
//! VRF isolation for IS-IS needs exactly one binding: the per-VRF
//! [`RibClient`](crate::rib::client::RibClient) is subscribed at the
//! VRF's kernel `table_id`, so SPF routes install into the VRF table.
//! IS-IS PDUs are L2 (`AF_PACKET` bound to the physical ifindex in
//! [`super::socket::isis_socket`]), so no `SO_BINDTODEVICE` is needed.
//!
//! A child is spawned only once **both** config intent exists (the
//! parent's `vrf_log`) **and** the kernel VRF master has been created
//! (`RibRx::VrfAdd` delivered the `table_id`). The buffered config is
//! replayed into the fresh child, followed by one synthetic
//! `CommitEnd` so the child runs its commit-time reconcile.

use tokio::sync::mpsc::{Sender, UnboundedSender};

use crate::config::{CommandPath, ConfigOp, ConfigRequest, Message, RibSubscriber};
use crate::context::{ProtoContext, Task};

use super::inst::{self, Isis};

/// Handle to one running per-VRF IS-IS task, stashed on the parent's
/// `vrf_registry`.
pub struct IsisVrfHandle {
    /// Config inbox of the child. The parent forwards rewritten
    /// `/router/isis/…` `ConfigRequest`s here (and the per-commit
    /// `CommitEnd`).
    pub cm_tx: UnboundedSender<ConfigRequest>,
    /// Spawned event loop. Dropping the handle aborts it (the `Task`
    /// runs its `AbortHandle` on `Drop`), so removing a handle from
    /// `vrf_registry` tears the child down.
    #[allow(dead_code)]
    pub task: Task<()>,
}

/// Per-VRF instance proto label. Distinct from the default `"isis"` so
/// the child's name-keyed RIB / policy / SR registrations don't clobber
/// the parent's. Route-install attribution is by numeric `ProtoId`, so
/// it is unaffected.
pub fn vrf_proto_label(name: &str) -> String {
    format!("isis:vrf:{name}")
}

/// Manager show-channel registry key for a per-VRF instance — must
/// match what the manager's `DisplayTx` handler computes from
/// `show isis vrf <name> …` (`"<proto>:vrf:<name>"`).
pub fn vrf_show_key(name: &str) -> String {
    format!("isis:vrf:{name}")
}

/// True if the buffered config log still has at least one net-effect
/// `Set` item. The parent uses this at `CommitEnd` to detect a fully
/// deleted `router isis vrf <name>` block (→ tear the child down).
/// Set/Delete are folded by a path+values key (joined `CommandPath`
/// names), so a `Set` later cancelled by a matching `Delete` drops out.
pub fn vrf_log_active(log: &[(Vec<CommandPath>, ConfigOp)]) -> bool {
    let mut active: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (paths, op) in log {
        let key = paths
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join("/");
        match op {
            ConfigOp::Set => {
                active.insert(key);
            }
            ConfigOp::Delete => {
                active.remove(&key);
            }
            _ => {}
        }
    }
    !active.is_empty()
}

/// Build + spawn a per-VRF IS-IS task and return its handle.
///
/// `table_id` is the kernel routing table id RIB allocated for the VRF
/// master (from `RibRx::VrfAdd`); the per-VRF `RibClient` is subscribed
/// at it so route installs land in `vrf_tables[table_id]`. `buffered`
/// is the parent's replay log for this VRF — every rewritten config
/// line in commit order; it is replayed, then a synthetic `CommitEnd`
/// is sent so the child reconciles.
pub fn spawn_isis_vrf(
    name: &str,
    table_id: u32,
    rib_subscriber: &RibSubscriber,
    config_tx: &Sender<Message>,
    policy_tx: &UnboundedSender<crate::policy::Message>,
    buffered: &[(Vec<CommandPath>, ConfigOp)],
) -> IsisVrfHandle {
    let proto = vrf_proto_label(name);
    // Per-VRF RIB subscription bound to the kernel table_id. Consume
    // (don't leak) `rib_rx` — the child's event loop needs LinkAdd /
    // AddrAdd to manage its interfaces.
    let (rib_client, rib_rx) = rib_subscriber.subscribe_for_vrf(&proto, table_id);
    let ctx = ProtoContext::for_vrf(rib_client, table_id, name.to_string());

    let isis = Isis::new(
        ctx,
        rib_rx,
        /* bfd_client_tx */ None,
        /* stamp_client_tx (default-VRF only in Phase 1) */ None,
        /* bgp_tx */ None,
        policy_tx.clone(),
        proto.clone(),
        rib_subscriber.clone(),
        config_tx.clone(),
    );
    let cm_tx = isis.cm.tx.clone();

    // Register the child's show channel so `show isis vrf <name> …`
    // redirects into it (manager strips the `vrf <name>` selector).
    let _ = config_tx.try_send(Message::SubscribeShowVrf {
        key: vrf_show_key(name),
        tx: isis.show.tx.clone(),
    });

    // Replay buffered config in commit order, then one synthetic
    // CommitEnd so the child runs `commit_srlg` / reconcile once.
    for (paths, op) in buffered {
        let _ = cm_tx.send(ConfigRequest::new(paths.clone(), *op));
    }
    let _ = cm_tx.send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));

    let task = inst::serve(isis);
    tracing::info!(vrf = %name, table_id, "isis: spawned per-VRF instance");

    IsisVrfHandle { cm_tx, task }
}

/// Tear down a per-VRF instance's manager + RIB registrations.
///
/// The caller removes the [`IsisVrfHandle`] from `vrf_registry`
/// separately, which drops the `Task` and aborts the event loop. This
/// drops the manager show channel and the RIB client / SR / redist
/// rows (via `ProtoCleanup`). The VRF's FIB routes are reclaimed by
/// RIB's own `VrfDel` handling when the master device disappears.
pub fn despawn_isis_vrf(name: &str, config_tx: &Sender<Message>, rib_subscriber: &RibSubscriber) {
    let _ = config_tx.try_send(Message::UnsubscribeShowVrf {
        key: vrf_show_key(name),
    });
    rib_subscriber.send_proto_cleanup(&vrf_proto_label(name));
    tracing::info!(vrf = %name, "isis: despawned per-VRF instance");
}
