//! Client API — how the IGPs attach to STAMP sessions.
//!
//! Modelled on BFD's client registry: a protocol module obtains the
//! instance's [`ClientReq`] sender from the ConfigManager at spawn
//! time and submits `Subscribe` / `Unsubscribe` keyed by
//! [`SessionKey`]. Sessions are shared — IS-IS and OSPF measuring the
//! same link drive one prober and both receive every
//! [`StampEvent::MetricUpdate`]. A `Subscribe` against an existing
//! session whose *timing* params differ retunes the live session
//! (last-writer-wins; cheaper than a BFD-style Poll Sequence since
//! nothing is negotiated with the peer).
//!
//! Anomaly thresholds are the exception, and deliberately so. They are
//! not a property of the probe stream but of what each IGP advertises,
//! and each IGP configures them under its own `te-metric measurement`
//! block. Retuning them last-writer-wins would let OSPF subscribing
//! with no threshold silently disable the anomaly IS-IS was configured
//! to report — an advertisement neither config asked for. They are
//! therefore kept per subscriber in [`Subscriber`], alongside that
//! subscriber's hysteresis state.

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::anomaly::{AnomalyFlags, AnomalyThresholds, DelayAnomaly};
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
    /// differ (last-writer-wins) — except for `params.anomaly`, which
    /// stays this subscriber's alone. `MetricUpdate`s flow to `notifier`
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

/// One IGP's registration on a session: where to deliver updates, the
/// anomaly policy it configured, and the hysteresis that policy has
/// accumulated. Held per client so two IGPs measuring one link can
/// advertise different bits from the same samples.
#[derive(Debug)]
pub struct Subscriber {
    pub notifier: UnboundedSender<StampEvent>,
    pub thresholds: AnomalyThresholds,
    pub anomaly: DelayAnomaly,
    /// Last flags delivered to this subscriber, so a transition can
    /// force an export the shared value filter would have damped.
    pub last_flags: AnomalyFlags,
}

impl Subscriber {
    pub fn new(notifier: UnboundedSender<StampEvent>, thresholds: AnomalyThresholds) -> Self {
        Self {
            notifier,
            thresholds,
            anomaly: DelayAnomaly::default(),
            last_flags: AnomalyFlags::default(),
        }
    }

    /// Evaluate `snapshot` against this subscriber's own bounds and
    /// stamp the resulting flags into the copy it will receive. An
    /// empty window (`None`) resets the hysteresis: the export that
    /// follows withdraws the sub-TLVs the bits would have qualified.
    pub fn apply(&mut self, snapshot: Option<MetricSnapshot>) -> Option<MetricSnapshot> {
        match snapshot {
            Some(mut snap) => {
                snap.anomaly = self.anomaly.evaluate(&snap, self.thresholds);
                Some(snap)
            }
            None => {
                self.anomaly.reset();
                None
            }
        }
    }
}
