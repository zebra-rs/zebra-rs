//! Client API — how the IGPs attach to STAMP sessions.
//!
//! Modelled on BFD's client registry: a protocol module obtains the
//! instance's [`ClientReq`] sender from the ConfigManager at spawn
//! time and submits `Subscribe` / `Unsubscribe` keyed by
//! [`SessionKey`]. Sessions are shared — IS-IS and OSPF measuring the
//! same link drive one prober and both receive every
//! [`StampEvent::MetricUpdate`]. A `Subscribe` against an existing
//! session whose params differ retunes the live session
//! (last-writer-wins; cheaper than a BFD-style Poll Sequence since
//! nothing is negotiated with the peer).

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::session::{SessionKey, SessionParams};
use super::stats::MetricSnapshot;

/// Identifier for a STAMP subscriber — conventionally the proto name
/// ("isis", "ospf").
pub type ClientId = String;

/// Sender/receiver pair for the inbound client-request channel.
/// Mirrors [`crate::bfd::inst::ClientReqChannel`].
#[derive(Debug)]
pub struct ClientReqChannel {
    pub tx: UnboundedSender<ClientReq>,
    pub rx: UnboundedReceiver<ClientReq>,
}

impl ClientReqChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

impl Default for ClientReqChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Requests sent to the STAMP instance by protocol modules.
#[derive(Debug)]
pub enum ClientReq {
    /// Register interest in measuring `key`. The first subscriber
    /// creates the session with `params`; later subscribers reuse it,
    /// retuning the live probe/export timers when their `params`
    /// differ (last-writer-wins). `MetricUpdate`s flow to `notifier`
    /// until the matching `Unsubscribe`; if the session has already
    /// exported a value, it is mirrored to the new subscriber
    /// immediately.
    Subscribe {
        client: ClientId,
        key: SessionKey,
        params: SessionParams,
        notifier: UnboundedSender<StampEvent>,
    },
    /// Drop `client`'s interest in `key`. The last unsubscribe tears
    /// the session (prober, sockets, read task) down.
    Unsubscribe { client: ClientId, key: SessionKey },
}

/// Events emitted to subscribers.
#[derive(Debug, Clone, Copy)]
pub enum StampEvent {
    /// A damped export: the link's measured delay changed enough to
    /// re-advertise. `None` clears — the measurement went stale (no
    /// replies for a whole export period); the IGP must withdraw the
    /// measured sub-TLVs (falling back to static config where present,
    /// else pruning the link from delay-metric topologies).
    MetricUpdate {
        key: SessionKey,
        snapshot: Option<MetricSnapshot>,
    },
}
