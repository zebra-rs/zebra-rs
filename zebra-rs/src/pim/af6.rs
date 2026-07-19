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
/// the parent's `"pim"`.
pub fn af6_proto_label() -> String {
    "pim:ipv6".to_string()
}

/// Build + spawn the default-table `Pim<Ipv6>` task. Returns `None`
/// when the v6 socket cannot be opened (missing kernel support), so the
/// caller leaves the slot empty and a later event retries.
pub fn spawn_pim_v6(
    rib_subscriber: &RibSubscriber,
    config_tx: &Sender<Message>,
) -> Option<PimAf6Handle> {
    let proto = af6_proto_label();

    // Open the socket before subscribing so a failure can't leave a
    // dead RibRx receiver queued in RIB's inbox (same contract as the
    // IPv4 spawn).
    let probe = ProtoContext::default_table_no_rib();
    let sock = match pim_socket_v6(&probe) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::warn!("pim6: default-table instance not started ({e})");
            return None;
        }
    };
    let mld_sock = match mld_socket(&probe) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::warn!("pim6: default-table instance not started (mld socket: {e})");
            return None;
        }
    };
    let fp = match Mrt6::new(&probe, 0) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::warn!("pim6: default-table instance not started (mroute6: {e})");
            return None;
        }
    };

    let (rib_client, rib_rx) = rib_subscriber.subscribe_for_vrf(&proto, 0);
    let ctx = ProtoContext::default_table(rib_client);

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
    tracing::info!("pim6: spawned default-table IPv6 instance");

    Some(PimAf6Handle {
        cm_tx,
        show_tx,
        task,
    })
}
