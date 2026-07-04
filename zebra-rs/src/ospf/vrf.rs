//! Per-VRF OSPF instance spawn / despawn (OSPFv2 + OSPFv3).
//!
//! Mirrors `crate::isis::vrf`: the default `router ospf` /
//! `router ospfv3` task acts as a thin parent that forwards each
//! `/router/ospf{,v3}/vrf/<name>/…` config line — rewritten to strip
//! the `vrf <name>` prefix (see [`crate::config::vrf_redirect_split`])
//! — into a full per-VRF [`Ospf`] whose existing callbacks / SPF /
//! RIB / show paths run unchanged.
//!
//! Unlike IS-IS, OSPF is L3 (raw IP protocol 89) and opens its socket
//! through [`crate::context::ProtoContext`] (`ospf_socket_ipv4/6` →
//! `ctx.raw_socket`). So a child built with `ProtoContext::for_vrf`
//! gets `SO_BINDTODEVICE` to the VRF master for free, and its
//! `RibClient` is subscribed at the VRF's kernel `table_id` — that is
//! all VRF isolation needs.
//!
//! `Ospf<V>` is generic over the version, but `Ospf::<V>::new` is a
//! concrete (per-version) constructor, so the spawn is dispatched via
//! [`crate::ospf::version::OspfVersion::spawn_vrf`] into the two
//! concrete helpers here. A child is spawned only once both config
//! intent (the parent's `vrf_log`) and the kernel VRF master
//! (`RibRx::VrfAdd` → `table_id`) exist; the buffered config is
//! replayed, then a synthetic `CommitEnd` triggers the child's
//! commit-time reconcile.

use tokio::sync::mpsc::{Sender, UnboundedSender};

use crate::config::{CommandPath, ConfigOp, ConfigRequest, DisplayRequest, Message, RibSubscriber};
use crate::context::{ProtoContext, Task};

use super::inst::{self, Ospf};
use super::version::{OspfVersion, Ospfv2, Ospfv3};

/// Handle to one running per-VRF OSPF task, stashed on the parent's
/// `vrf_registry`. Version-agnostic — only the config inbox and the
/// task are kept.
pub struct OspfVrfHandle {
    /// Config inbox of the child. The parent forwards rewritten
    /// `/router/ospf{,v3}/…` `ConfigRequest`s here (and the per-commit
    /// `CommitEnd`).
    pub cm_tx: UnboundedSender<ConfigRequest>,
    /// Spawned event loop. Dropping the handle aborts it (the `Task`
    /// runs its `AbortHandle` on `Drop`), so removing a handle from
    /// `vrf_registry` tears the child down.
    #[allow(dead_code)]
    pub task: Task<()>,
}

/// True if the buffered config log still has at least one net-effect
/// `Set` item. The parent uses this at `CommitEnd` to detect a fully
/// deleted `router ospf{,v3} vrf <name>` block (→ tear the child
/// down). Set/Delete are folded by a path+values key (joined
/// `CommandPath` names), so a `Set` later cancelled by a matching
/// `Delete` drops out.
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

/// Shared tail of both version spawns: register the child's show
/// channel (`"<proto>:vrf:<name>"`, matching the manager's
/// `DisplayTx` key), replay the buffered config in commit order, then
/// send one synthetic `CommitEnd` so the child reconciles once.
fn finish_spawn(
    proto: &str,
    cm_tx: UnboundedSender<ConfigRequest>,
    show_tx: UnboundedSender<DisplayRequest>,
    task: Task<()>,
    config_tx: &Sender<Message>,
    buffered: &[(Vec<CommandPath>, ConfigOp)],
) -> OspfVrfHandle {
    let _ = config_tx.try_send(Message::SubscribeShowVrf {
        key: proto.to_string(),
        tx: show_tx,
    });
    for (paths, op) in buffered {
        let _ = cm_tx.send(ConfigRequest::new(paths.clone(), *op));
    }
    let _ = cm_tx.send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
    OspfVrfHandle { cm_tx, task }
}

/// Spawn a per-VRF `Ospf<Ospfv2>` bound to the VRF's kernel `table_id`.
pub fn spawn_ospf_vrf_v2(
    name: &str,
    table_id: u32,
    rib_subscriber: &RibSubscriber,
    config_tx: &Sender<Message>,
    policy_tx: &UnboundedSender<crate::policy::Message>,
    buffered: &[(Vec<CommandPath>, ConfigOp)],
) -> OspfVrfHandle {
    let proto = format!("{}:vrf:{}", Ospfv2::PROTO, name);
    // Consume (don't leak) `rib_rx` — the child's event loop needs
    // LinkAdd / AddrAdd to manage its interfaces.
    let (rib_client, rib_rx) = rib_subscriber.subscribe_for_vrf(&proto, table_id);
    let ctx = ProtoContext::for_vrf(rib_client, table_id, name.to_string());
    let ospf = Ospf::<Ospfv2>::new(
        ctx,
        rib_rx,
        policy_tx.clone(),
        proto.clone(),
        rib_subscriber.clone(),
        config_tx.clone(),
        // Per-VRF OSPF BFD is deferred (the BFD instance is default-table
        // only); `None` makes per-interface `bfd` inert in a VRF for now.
        None,
        // Per-VRF STAMP likewise (sessions are default-VRF only).
        None,
    );
    let cm_tx = ospf.cm.tx.clone();
    let show_tx = ospf.show.tx.clone();
    let task = inst::serve(ospf);
    tracing::info!(vrf = %name, table_id, "ospf: spawned per-VRF instance");
    finish_spawn(&proto, cm_tx, show_tx, task, config_tx, buffered)
}

/// Spawn a per-VRF `Ospf<Ospfv3>` bound to the VRF's kernel `table_id`.
pub fn spawn_ospf_vrf_v3(
    name: &str,
    table_id: u32,
    rib_subscriber: &RibSubscriber,
    config_tx: &Sender<Message>,
    policy_tx: &UnboundedSender<crate::policy::Message>,
    buffered: &[(Vec<CommandPath>, ConfigOp)],
) -> OspfVrfHandle {
    let proto = format!("{}:vrf:{}", Ospfv3::PROTO, name);
    let (rib_client, rib_rx) = rib_subscriber.subscribe_for_vrf(&proto, table_id);
    let ctx = ProtoContext::for_vrf(rib_client, table_id, name.to_string());
    let ospf = Ospf::<Ospfv3>::new(
        ctx,
        rib_rx,
        policy_tx.clone(),
        proto.clone(),
        rib_subscriber.clone(),
        config_tx.clone(),
        // Per-VRF OSPFv3 BFD deferred (see `spawn_ospf_vrf_v2`).
        None,
        // Per-VRF STAMP likewise.
        None,
    );
    let cm_tx = ospf.cm.tx.clone();
    let show_tx = ospf.show.tx.clone();
    let task = inst::serve_v3(ospf);
    tracing::info!(vrf = %name, table_id, "ospfv3: spawned per-VRF instance");
    finish_spawn(&proto, cm_tx, show_tx, task, config_tx, buffered)
}

/// Tear down a per-VRF instance's manager + RIB registrations.
/// `proto_base` is `V::PROTO` (`"ospf"` / `"ospfv3"`). The caller
/// removes the [`OspfVrfHandle`] from `vrf_registry` separately, which
/// drops the `Task` and aborts the event loop. The VRF's FIB routes
/// are reclaimed by RIB's own `VrfDel` handling.
pub fn despawn_ospf_vrf(
    proto_base: &str,
    name: &str,
    config_tx: &Sender<Message>,
    rib_subscriber: &RibSubscriber,
) {
    let proto = format!("{proto_base}:vrf:{name}");
    let _ = config_tx.try_send(Message::UnsubscribeShowVrf { key: proto.clone() });
    rib_subscriber.send_proto_cleanup(&proto);
    tracing::info!(vrf = %name, proto = %proto, "ospf: despawned per-VRF instance");
}
