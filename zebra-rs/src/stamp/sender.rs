//! Per-session prober task.
//!
//! One task per session drives two periodic timers and reports the
//! ticks to the event loop, which owns all session state (mirroring
//! the BFD `session_timer` split):
//!
//!   * the **probe** timer fires every `interval_ms` →
//!     [`Message::TxTick`] → the event loop builds and sends one
//!     Session-Sender packet;
//!   * the **export** timer fires every `damping_secs` →
//!     [`Message::ExportTick`] → the event loop snapshots the stats
//!     window, runs the damping gate, and fans `MetricUpdate`s out.
//!
//! [`ProberCmd::Retune`] re-arms both timers — the runtime path for a
//! `Subscribe` carrying changed params (shared sessions are
//! last-writer-wins, plan D11).

use std::time::Duration;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::{Instant, interval_at};

use crate::context::Task;

use super::inst::Message;
use super::session::{SessionKey, SessionParams};

/// Commands the event loop sends to a session's prober task.
#[derive(Debug, Clone, Copy)]
pub enum ProberCmd {
    /// Params changed (a later `Subscribe` with a different tuple);
    /// re-arm both timers at the new rates.
    Retune(SessionParams),
    /// Shut the task down. Equivalent to dropping the cmd channel.
    Shutdown,
}

/// Holds one session's prober task and its command channel. Dropping
/// the [`Task`] aborts the loop.
#[derive(Debug)]
pub struct ProberHandle {
    pub cmd_tx: UnboundedSender<ProberCmd>,
    pub _task: Task<()>,
}

/// Prober task body. Runs until the cmd channel closes or
/// [`ProberCmd::Shutdown`] arrives.
pub async fn session_prober(
    key: SessionKey,
    params: SessionParams,
    mut cmd_rx: UnboundedReceiver<ProberCmd>,
    event_tx: UnboundedSender<Message>,
) {
    let (mut probe, mut export) = arm(params);

    loop {
        tokio::select! {
            _ = probe.tick() => {
                if event_tx.send(Message::TxTick { key }).is_err() {
                    return; // event loop gone
                }
            }
            _ = export.tick() => {
                if event_tx.send(Message::ExportTick { key }).is_err() {
                    return;
                }
            }
            cmd = cmd_rx.recv() => match cmd {
                None | Some(ProberCmd::Shutdown) => return,
                Some(ProberCmd::Retune(p)) => (probe, export) = arm(p),
            }
        }
    }
}

/// Build both interval timers. `interval_at` with a one-period initial
/// delay: an immediate first probe would race link bring-up for
/// nothing, and an immediate first export would always be an empty
/// window. Missed ticks (event-loop stall) are skipped, not bursted —
/// a burst of back-to-back probes measures the daemon, not the link.
fn arm(params: SessionParams) -> (tokio::time::Interval, tokio::time::Interval) {
    let probe_period = Duration::from_millis(params.interval_ms.max(1) as u64);
    let export_period = Duration::from_secs(params.damping_secs.max(1) as u64);
    let mut probe = interval_at(Instant::now() + probe_period, probe_period);
    let mut export = interval_at(Instant::now() + export_period, export_period);
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    export.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    (probe, export)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::sync::mpsc;

    use super::*;

    fn key() -> SessionKey {
        SessionKey {
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            ifindex: 0,
        }
    }

    /// Probe ticks arrive at roughly the configured interval, and the
    /// export tick fires once per damping period.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ticks_fire_at_configured_rates() {
        let params = SessionParams {
            interval_ms: 10,
            damping_secs: 1,
            ..SessionParams::default()
        };
        let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(session_prober(key(), params, cmd_rx, event_tx));

        tokio::time::sleep(Duration::from_millis(250)).await;
        let (mut tx_ticks, mut export_ticks) = (0u32, 0u32);
        while let Ok(msg) = event_rx.try_recv() {
            match msg {
                Message::TxTick { .. } => tx_ticks += 1,
                Message::ExportTick { .. } => export_ticks += 1,
                _ => {}
            }
        }
        assert!(tx_ticks >= 10, "expected ≥10 probe ticks, got {tx_ticks}");
        assert_eq!(export_ticks, 0, "export period (1s) not yet reached");
        task.abort();
    }

    /// Retune takes effect: after switching from a slow to a fast
    /// probe interval, ticks speed up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retune_changes_rate() {
        let params = SessionParams {
            interval_ms: 10_000,
            damping_secs: 3600,
            ..SessionParams::default()
        };
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(session_prober(key(), params, cmd_rx, event_tx));

        cmd_tx
            .send(ProberCmd::Retune(SessionParams {
                interval_ms: 10,
                damping_secs: 3600,
                ..SessionParams::default()
            }))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let tx_ticks = std::iter::from_fn(|| event_rx.try_recv().ok())
            .filter(|m| matches!(m, Message::TxTick { .. }))
            .count();
        assert!(tx_ticks >= 5, "retuned rate not applied: {tx_ticks} ticks");
        task.abort();
    }
}
