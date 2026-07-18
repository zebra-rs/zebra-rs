//! Per-VRF PIM instance spawn / despawn, mirroring `crate::isis::vrf`.
//!
//! The default `router pim` task acts as a thin parent: it forwards
//! every `/router/pim/vrf/<name>/…` config line — rewritten to strip
//! the `vrf <name>` selector (see `crate::config::vrf_config_split`)
//! — into a full per-VRF [`Pim`] whose callbacks / TIB / show paths
//! run unchanged.
//!
//! Unlike IS-IS (L2 PDUs, RIB binding only), PIM's isolation needs
//! all three sockets rebuilt inside the VRF: the protocol-103 and
//! IGMP sockets get `SO_BINDTODEVICE` via
//! [`ProtoContext::for_vrf`]'s socket factory, and the mroute socket
//! selects the VRF's kernel multicast table with `MRT_TABLE` before
//! `MRT_INIT`.
//!
//! A child is spawned only once **both** config intent exists (the
//! parent's `vrf_log`) **and** the kernel VRF master has been created
//! (`RibRx::VrfAdd` delivered the `table_id`). The buffered config is
//! replayed into the fresh child, followed by one synthetic
//! `CommitEnd`.

use tokio::sync::mpsc::{Sender, UnboundedSender};

use crate::config::{CommandPath, ConfigOp, ConfigRequest, Message, RibSubscriber};
use crate::context::{ProtoContext, Task};

use super::inst::{self, Pim};
use super::mroute::{Mrt4, PimForwardingPlane};
use super::socket::{igmp_socket, pim_socket};

/// Handle to one running per-VRF PIM task, stashed on the parent's
/// `vrf_registry`. Dropping it aborts the child's event loop.
pub struct PimVrfHandle {
    pub cm_tx: UnboundedSender<ConfigRequest>,
    #[allow(dead_code)]
    pub task: Task<()>,
}

/// Per-VRF instance proto label — namespaces the child's name-keyed
/// RIB registrations away from the parent's.
pub fn vrf_proto_label(name: &str) -> String {
    format!("pim:vrf:{name}")
}

/// Manager show-channel registry key — must match what the manager's
/// `DisplayTx` handler computes from `show pim vrf <name> …`.
pub fn vrf_show_key(name: &str) -> String {
    format!("pim:vrf:{name}")
}

/// True if the buffered config log still has at least one net-effect
/// `Set` item (a `Set` cancelled by a matching `Delete` drops out).
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

/// Build + spawn a per-VRF PIM task. Returns `None` when the VRF's
/// sockets cannot be opened (missing kernel support, another
/// multicast daemon owning the table) — the caller leaves the
/// registry empty so a later event retries.
pub fn spawn_pim_vrf(
    name: &str,
    table_id: u32,
    rib_subscriber: &RibSubscriber,
    config_tx: &Sender<Message>,
    buffered: &[(Vec<CommandPath>, ConfigOp)],
) -> Option<PimVrfHandle> {
    let proto = vrf_proto_label(name);

    // All three sockets live inside the VRF. Open them BEFORE the RIB
    // subscription so a failure doesn't leave a dead RibRx receiver
    // queued in RIB's inbox (same contract as the default spawn).
    let probe = ProtoContext::for_vrf_no_rib(table_id, name.to_string());
    let sock = match pim_socket(&probe) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::warn!(vrf = %name, "pim: vrf instance not started ({e})");
            return None;
        }
    };
    let igmp_sock = match igmp_socket(&probe) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::warn!(vrf = %name, "pim: vrf instance not started (igmp socket: {e})");
            return None;
        }
    };
    let fp = match Mrt4::new(&probe, table_id) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::warn!(vrf = %name, "pim: vrf instance not started (mroute socket: {e})");
            return None;
        }
    };

    let (rib_client, rib_rx) = rib_subscriber.subscribe_for_vrf(&proto, table_id);
    let ctx = ProtoContext::for_vrf(rib_client, table_id, name.to_string());

    let pim = Pim::new(
        ctx,
        sock,
        igmp_sock,
        fp,
        rib_rx,
        proto.clone(),
        rib_subscriber.clone(),
        config_tx.clone(),
    );
    let cm_tx = pim.cm.tx.clone();

    let _ = config_tx.try_send(Message::SubscribeShowVrf {
        key: vrf_show_key(name),
        tx: pim.show.tx.clone(),
    });

    // Replay buffered config in commit order, then one synthetic
    // CommitEnd so the child reconciles.
    for (paths, op) in buffered {
        let _ = cm_tx.send(ConfigRequest::new(paths.clone(), *op));
    }
    let _ = cm_tx.send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));

    let task = inst::serve(pim);
    tracing::info!(vrf = %name, table_id, "pim: spawned per-VRF instance");

    Some(PimVrfHandle { cm_tx, task })
}

/// Tear down a per-VRF instance's manager + RIB registrations. The
/// caller removes the handle from `vrf_registry`, which drops the
/// `Task` and aborts the event loop — closing the sockets runs the
/// kernel's implicit MRT_DONE cleanup for the VRF table.
pub fn despawn_pim_vrf(name: &str, config_tx: &Sender<Message>, rib_subscriber: &RibSubscriber) {
    let _ = config_tx.try_send(Message::UnsubscribeShowVrf {
        key: vrf_show_key(name),
    });
    rib_subscriber.send_proto_cleanup(&vrf_proto_label(name));
    tracing::info!(vrf = %name, "pim: despawned per-VRF instance");
}
