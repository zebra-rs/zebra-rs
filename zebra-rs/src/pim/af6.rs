//! Default-table IPv6 child spawn / routing. Until the standalone
//! `PimSupervisor` arrives (Phase 7, when per-VRF × AF needs a flat
//! matrix), the default `Pim<Ipv4>` instance parents the default-table
//! `Pim<Ipv6>` instance exactly as it parents its per-VRF children: the
//! manager routes every `router pim …` / `show pim …` line to the one
//! `"pim"` channel, and the parent strips a leading `ipv6` container
//! (see `inst::af6_split`) and forwards to this child.

use tokio::sync::mpsc::{Sender, UnboundedSender};

use crate::config::{ConfigRequest, DisplayRequest, Message, RibSubscriber};
use crate::context::{ProtoContext, Task};

use super::inst::{self, Pim};
use super::ipv6::Ipv6;
use super::mroute::{Mrt6, PimForwardingPlane};
use super::socket::{mld_socket, pim_socket_v6};

/// Handle to the running default-table `Pim<Ipv6>` task, stashed on the
/// parent. Dropping it aborts the child's event loop.
pub struct PimAf6Handle {
    pub cm_tx: UnboundedSender<ConfigRequest>,
    pub show_tx: UnboundedSender<DisplayRequest>,
    #[allow(dead_code)]
    pub task: Task<()>,
}

/// Namespaces the IPv6 child's name-keyed RIB registrations away from
/// the parent's `"pim"` / `"pim:vrf:<name>"`: `"pim:ipv6"` for the
/// default table, `"pim:vrf:<name>:ipv6"` for a per-VRF IPv6 child.
pub fn af6_proto_label(vrf_ifname: Option<&str>) -> String {
    match vrf_ifname {
        None => "pim:ipv6".to_string(),
        Some(name) => format!("pim:vrf:{name}:ipv6"),
    }
}

/// Build + spawn a `Pim<Ipv6>` task, either default-table
/// (`vrf_ifname == None`, `vrf_id == 0`) or per-VRF (the child of a
/// per-VRF `Pim<Ipv4>`). The sockets and the MRT6 instance are scoped to
/// the VRF exactly as `spawn_pim_vrf` scopes the IPv4 ones. Returns
/// `None` when the v6 socket cannot be opened (missing kernel support),
/// so the caller leaves the slot empty and a later event retries.
pub fn spawn_pim_v6(
    rib_subscriber: &RibSubscriber,
    config_tx: &Sender<Message>,
    vrf_id: u32,
    vrf_ifname: Option<String>,
    trace: bool,
) -> Option<PimAf6Handle> {
    let proto = af6_proto_label(vrf_ifname.as_deref());
    let scope = match &vrf_ifname {
        None => "default-table".to_string(),
        Some(name) => format!("VRF {name}"),
    };

    // Open the sockets — inside the VRF when scoped — before subscribing
    // so a failure can't leave a dead RibRx receiver queued in RIB's
    // inbox (same contract as the IPv4 spawn).
    let probe = match &vrf_ifname {
        None => ProtoContext::default_table_no_rib(),
        Some(name) => ProtoContext::for_vrf_no_rib(vrf_id, name.clone()),
    };
    let sock = match pim_socket_v6(&probe) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::warn!("pim6: {scope} instance not started ({e})");
            return None;
        }
    };
    let mld_sock = match mld_socket(&probe) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::warn!("pim6: {scope} instance not started (mld socket: {e})");
            return None;
        }
    };
    let fp = match Mrt6::new(&probe, vrf_id) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::warn!("pim6: {scope} instance not started (mroute6: {e})");
            return None;
        }
    };

    let (rib_client, rib_rx) = rib_subscriber.subscribe_for_vrf(&proto, vrf_id);
    let ctx = match &vrf_ifname {
        None => ProtoContext::default_table(rib_client),
        Some(name) => ProtoContext::for_vrf(rib_client, vrf_id, name.clone()),
    };

    let pim = Pim::<Ipv6>::new(
        ctx,
        sock,
        mld_sock,
        fp,
        rib_rx,
        proto,
        rib_subscriber.clone(),
        config_tx.clone(),
    );
    let cm_tx = pim.cm.tx.clone();
    let show_tx = pim.show.tx.clone();
    let task = inst::serve(pim);
    if trace {
        tracing::info!(
            proto = "pim",
            category = "event",
            "pim6: spawned {scope} IPv6 instance"
        );
    }

    Some(PimAf6Handle {
        cm_tx,
        show_tx,
        task,
    })
}
