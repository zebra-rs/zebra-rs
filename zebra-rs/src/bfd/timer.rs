//! Per-session timer task.
//!
//! Each [`Session`](super::session::Session) gets exactly one
//! [`session_timer`] task. The task owns two timers:
//!
//!   * a periodic **TX scheduler** that fires at a jittered fraction
//!     of the negotiated `tx_interval` (RFC 5880 §6.8.7); each fire
//!     sends a [`TimerEvent::TxTick`] to the main event loop, which
//!     builds the packet from the live session state and dispatches
//!     it via the write task;
//!   * a **detection timer** that fires once when no valid packet
//!     has arrived in `detection_time` (RFC 5880 §6.8.4); the event
//!     loop drives the FSM with [`super::fsm::Event::DetectExpired`]
//!     in response.
//!
//! Both intervals can be adjusted at runtime by sending [`TimerCmd::Update`]
//! (whenever negotiation changes the effective rates).
//! [`TimerCmd::ResetDetect`] is sent on every valid receive so the
//! detection timer rearms.

use std::time::Duration;

use rand::RngExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::{Instant, sleep_until};

use super::inst::Message;
use super::session::SessionKey;

/// Commands the event loop sends to a session's timer task.
#[derive(Debug, Clone, Copy)]
pub enum TimerCmd {
    /// Negotiation result changed; recompute deadlines.
    /// `detect_mult` is the *local* multiplier and is only used to
    /// cap the per-TX jitter envelope per RFC 5880 §6.8.7.
    Update {
        tx_interval_us: u32,
        detection_time_us: u32,
        detect_mult: u8,
    },
    /// A valid packet just arrived; reset the detection timer.
    ResetDetect,
    /// Shut the task down. Equivalent to dropping the cmd channel.
    Shutdown,
}

/// Initial timer parameters supplied when the task is spawned.
#[derive(Debug, Clone, Copy)]
pub struct InitialParams {
    pub tx_interval_us: u32,
    pub detection_time_us: u32,
    pub detect_mult: u8,
}

/// Per-session timer task body. Runs until the cmd channel closes
/// (the [`crate::context::Task`] handle is dropped) or [`TimerCmd::Shutdown`]
/// arrives.
pub async fn session_timer(
    key: SessionKey,
    initial: InitialParams,
    mut cmd_rx: UnboundedReceiver<TimerCmd>,
    event_tx: UnboundedSender<Message>,
) {
    let mut tx_us = initial.tx_interval_us;
    let mut detect_us = initial.detection_time_us;
    let mut detect_mult = initial.detect_mult.max(1);

    let mut next_tx = arm_tx(tx_us, detect_mult);
    let mut detect_at = arm_detect(detect_us);

    loop {
        // tokio::select! cannot match on Option<Sleep>, so we always
        // build a sleep and use the `if` guard to gate the arm.
        let tx_at = next_tx.unwrap_or_else(far_future);
        let detect_at_or_far = detect_at.unwrap_or_else(far_future);
        let tx_sleep = sleep_until(tx_at);
        let det_sleep = sleep_until(detect_at_or_far);
        tokio::pin!(tx_sleep, det_sleep);

        tokio::select! {
            _ = &mut tx_sleep, if next_tx.is_some() => {
                if event_tx.send(Message::TxTick { key }).is_err() {
                    return; // event loop gone
                }
                next_tx = arm_tx(tx_us, detect_mult);
            }
            _ = &mut det_sleep, if detect_at.is_some() => {
                if event_tx.send(Message::DetectExpired { key }).is_err() {
                    return;
                }
                // Don't rearm — the FSM transition to Down means there
                // is no detection timer until the peer comes back.
                detect_at = None;
            }
            cmd = cmd_rx.recv() => match cmd {
                None | Some(TimerCmd::Shutdown) => return,
                Some(TimerCmd::Update {
                    tx_interval_us,
                    detection_time_us,
                    detect_mult: mult,
                }) => {
                    tx_us = tx_interval_us;
                    detect_us = detection_time_us;
                    detect_mult = mult.max(1);
                    next_tx = arm_tx(tx_us, detect_mult);
                    detect_at = arm_detect(detect_us);
                }
                Some(TimerCmd::ResetDetect) => {
                    detect_at = arm_detect(detect_us);
                }
            }
        }
    }
}

/// Pick the next TX deadline, applying RFC 5880 §6.8.7 jitter. Zero
/// transmission interval means the peer has suspended async transmit
/// (`Required Min RX Interval = 0`) and we mustn't send.
fn arm_tx(tx_us: u32, detect_mult: u8) -> Option<Instant> {
    if tx_us == 0 {
        return None;
    }
    Some(Instant::now() + Duration::from_micros(jittered_tx_us(tx_us, detect_mult) as u64))
}

/// Pick the next detection-time deadline. Zero means we haven't
/// heard from the peer yet (RFC 5880 §6.8.4 initial condition).
fn arm_detect(detect_us: u32) -> Option<Instant> {
    if detect_us == 0 {
        return None;
    }
    Some(Instant::now() + Duration::from_micros(detect_us as u64))
}

/// Compute a single jittered transmit interval per RFC 5880 §6.8.7:
///
///   * normally the actual interval is 75–100% of the negotiated value;
///   * when `detect_mult == 1`, the upper bound drops to 90% so a
///     single missed packet cannot exceed the detection time.
fn jittered_tx_us(tx_us: u32, detect_mult: u8) -> u32 {
    let upper: u32 = if detect_mult <= 1 { 90 } else { 100 };
    let lower: u32 = 75;
    let pct: u32 = rand::rng().random_range(lower..=upper);
    // Multiply in u64 to avoid overflow at the u32 upper end.
    ((u64::from(tx_us) * u64::from(pct)) / 100) as u32
}

fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Jitter must stay within the RFC 5880 §6.8.7 envelope at every
    /// detect-multiplier setting; a few hundred draws is enough to
    /// catch off-by-one mistakes on the bound clamping.
    #[test]
    fn jitter_envelope() {
        let tx_us: u32 = 1_000_000;
        for &mult in &[1u8, 2, 3, 5, 100] {
            let upper_pct: u32 = if mult == 1 { 90 } else { 100 };
            for _ in 0..500 {
                let j = jittered_tx_us(tx_us, mult);
                let pct = (u64::from(j) * 100) / u64::from(tx_us);
                assert!(
                    (75..=u64::from(upper_pct)).contains(&pct),
                    "mult={mult} pct={pct} (j={j})",
                );
            }
        }
    }

    /// Zero TX interval suppresses transmission per RFC 5880 §6.8.7
    /// (peer's Required Min RX Interval = 0).
    #[test]
    fn zero_tx_disables_arm() {
        assert!(arm_tx(0, 3).is_none());
        assert!(arm_tx(50_000, 3).is_some());
    }

    /// Zero detection time leaves the detect arm un-set (no peer
    /// data yet, so nothing to time out against).
    #[test]
    fn zero_detect_disables_arm() {
        assert!(arm_detect(0).is_none());
        assert!(arm_detect(150_000).is_some());
    }
}
