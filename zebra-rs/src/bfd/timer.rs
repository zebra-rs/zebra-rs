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

    let (mut next_tx, _) = arm_tx(tx_us, detect_mult);
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
                // Re-arm first so the tick carries the jitter of the interval
                // we are now counting down — that is the value `show bfd peers`
                // reports as "actual with jitter" (matches FRR).
                let (deadline, actual_tx_us) = arm_tx(tx_us, detect_mult);
                next_tx = deadline;
                if event_tx.send(Message::TxTick { key, actual_tx_us }).is_err() {
                    return; // event loop gone
                }
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
                    detect_mult = mult.max(1);
                    detect_us = detection_time_us;
                    // Every valid Rx funnels an Update here to reset the
                    // detection timer (RFC 5880 §6.8.4) — so re-arm the
                    // detection deadline unconditionally.
                    detect_at = arm_detect(detect_us);
                    // The TX timer, however, free-runs at the negotiated
                    // interval (RFC 5880 §6.8.7) and must be reset ONLY
                    // when that interval actually changes. Re-arming it on
                    // every Rx starves transmission: when the peer sends
                    // at ~our TX interval, each received packet postpones
                    // our next TxTick before it can fire, so we transmit
                    // far too rarely and the peer hits its detection
                    // timeout (ControlDetectionTimeExpired). The
                    // comparison also covers the suspend/resume edges
                    // (0 ⇄ non-zero), since `arm_tx(0)` yields `None`.
                    if tx_interval_us != tx_us {
                        tx_us = tx_interval_us;
                        // Jitter for the new interval is reported on the next tick.
                        next_tx = arm_tx(tx_us, detect_mult).0;
                    }
                }
                Some(TimerCmd::ResetDetect) => {
                    detect_at = arm_detect(detect_us);
                }
            }
        }
    }
}

/// Pick the next TX deadline, applying RFC 5880 §6.8.7 jitter. Returns the
/// deadline together with the jittered interval in microseconds (so the caller
/// can report it as "actual with jitter"). Zero transmission interval means the
/// peer has suspended async transmit (`Required Min RX Interval = 0`) and we
/// mustn't send — yielding `(None, 0)`.
fn arm_tx(tx_us: u32, detect_mult: u8) -> (Option<Instant>, u32) {
    if tx_us == 0 {
        return (None, 0);
    }
    let jitter_us = jittered_tx_us(tx_us, detect_mult);
    (
        Some(Instant::now() + Duration::from_micros(jitter_us as u64)),
        jitter_us,
    )
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
        // Suspended transmit yields no deadline and zero reported jitter.
        let (deadline, jitter) = arm_tx(0, 3);
        assert!(deadline.is_none());
        assert_eq!(jitter, 0);
        // A live interval yields a deadline and an in-envelope jitter.
        let (deadline, jitter) = arm_tx(50_000, 3);
        assert!(deadline.is_some());
        assert!((37_500..=50_000).contains(&jitter), "jitter={jitter}");
    }

    /// Zero detection time leaves the detect arm un-set (no peer
    /// data yet, so nothing to time out against).
    #[test]
    fn zero_detect_disables_arm() {
        assert!(arm_detect(0).is_none());
        assert!(arm_detect(150_000).is_some());
    }

    /// Regression: a steady stream of received packets (each funnelling
    /// a `TimerCmd::Update` with the *same* negotiated intervals to reset
    /// the detection timer) must NOT keep re-arming — and thereby starve
    /// — the transmit timer. The peer sends at ~our TX interval, so if
    /// each Rx postponed our next TxTick we would transmit far too rarely
    /// and the peer would hit its detection timeout
    /// (ControlDetectionTimeExpired) — the BGP/FRR BFD flap.
    ///
    /// Drives the real `session_timer` task with short wall-clock
    /// intervals (TX 15 ms): an Update arrives every 10 ms — shorter than
    /// the 11.25–15 ms jittered TX window — so before the fix the TX
    /// timer was reset before it could ever fire and zero TxTicks were
    /// emitted. With the free-running TX timer we expect a tick roughly
    /// every ~13 ms, i.e. many over the run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tx_not_starved_by_received_updates() {
        use super::super::session::SessionKey;
        use std::net::{IpAddr, Ipv4Addr};

        let key = SessionKey {
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            ifindex: 0,
            multihop: false,
        };
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let initial = InitialParams {
            tx_interval_us: 15_000,
            detection_time_us: 45_000,
            detect_mult: 3,
        };
        let task = tokio::spawn(session_timer(key, initial, cmd_rx, event_tx));

        let mut tx_ticks = 0u32;
        for _ in 0..30 {
            // Simulate a received packet: reset detection via Update with
            // unchanged intervals.
            cmd_tx
                .send(TimerCmd::Update {
                    tx_interval_us: 15_000,
                    detection_time_us: 45_000,
                    detect_mult: 3,
                })
                .unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            while let Ok(msg) = event_rx.try_recv() {
                if matches!(msg, Message::TxTick { .. }) {
                    tx_ticks += 1;
                }
            }
        }

        assert!(
            tx_ticks >= 5,
            "TX starved by received Updates: only {tx_ticks} TxTicks over ~300ms",
        );
        task.abort();
    }
}
