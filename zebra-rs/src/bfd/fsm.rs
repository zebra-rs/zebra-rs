//! BFD session finite-state machine.
//!
//! Pure transition table from RFC 5880 §6.2 (state diagram) and §6.8.6
//! (reception logic). [`transition`] is a free function — it has no
//! side effects and does not touch session data, so it can be unit
//! tested exhaustively against the spec. The caller (in
//! [`super::session::Session::handle_event`]) is responsible for the
//! side effects: updating its own state, resetting the detection
//! timer, notifying clients, and so on.

// PR 3a stages the full Event surface (`DetectExpired`, `AdminDown`,
// `AdminUp`); the production wiring that constructs the non-`Rx`
// variants arrives in PR 3b (timer expiry) and PR 4 (admin shutdown).
#![allow(dead_code)]

use bfd_packet::{Diag, State};

/// External events that can drive a state change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A valid BFD control packet was received. `remote_state` is the
    /// State field carried by that packet.
    Rx { remote_state: State },
    /// The session's detection timer expired without a valid packet
    /// arriving in time (RFC 5880 §6.8.4).
    DetectExpired,
    /// Administrative shutdown requested (e.g. `shutdown` under a
    /// `bfd peer` block).
    AdminDown,
    /// Administrative shutdown rescinded.
    AdminUp,
}

/// Result of applying an [`Event`] to the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// The state the session should hold after the event.
    pub new_state: State,
    /// If the transition was caused by a condition that should update
    /// the local diagnostic (RFC 5880 §4.1), this is the new diag
    /// value to record. `None` means leave the existing diag untouched.
    pub new_diag: Option<Diag>,
}

/// Apply `event` to a session in `local` state and return the new
/// state and diagnostic per RFC 5880 §6.2 / §6.8.6.
///
/// AdminDown is sticky: only [`Event::AdminUp`] can lift it. While in
/// AdminDown, received packets and detection-timer expiries are
/// ignored.
pub fn transition(local: State, event: Event) -> Transition {
    if local == State::AdminDown {
        return match event {
            Event::AdminUp => stay(State::Down, None),
            _ => stay(State::AdminDown, None),
        };
    }

    match event {
        Event::AdminDown => stay(State::AdminDown, Some(Diag::AdministrativelyDown)),
        Event::AdminUp => stay(local, None),
        Event::DetectExpired => match local {
            State::Down => stay(State::Down, None),
            _ => stay(State::Down, Some(Diag::ControlDetectionTimeExpired)),
        },
        Event::Rx { remote_state } => rx_transition(local, remote_state),
    }
}

fn rx_transition(local: State, remote: State) -> Transition {
    use State::*;
    // RFC 5880 §6.8.6 — Reception of BFD Control Packets.
    // The two-axis match expresses the spec's nested if/else exactly.
    match (local, remote) {
        // Remote AdminDown — tear down unless we're already Down.
        (Down, AdminDown) => stay(Down, None),
        (Init, AdminDown) | (Up, AdminDown) => stay(Down, Some(Diag::NeighborSignaledSessionDown)),

        // Local Down — only Down/Init from peer makes us move.
        (Down, Down) => stay(Init, None),
        (Down, Init) => stay(Up, None),
        (Down, Up) => stay(Down, None),

        // Local Init — Init or Up from peer brings us Up; Down keeps us.
        (Init, Down) => stay(Init, None),
        (Init, Init) | (Init, Up) => stay(Up, None),

        // Local Up — only Down from peer tears us down.
        (Up, Down) => stay(Down, Some(Diag::NeighborSignaledSessionDown)),
        (Up, Init) | (Up, Up) => stay(Up, None),

        // Local AdminDown handled in the caller's early-return.
        (AdminDown, _) => unreachable!("AdminDown handled before rx_transition"),
    }
}

#[inline]
fn stay(new_state: State, new_diag: Option<Diag>) -> Transition {
    Transition {
        new_state,
        new_diag,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use State::*;

    /// Exhaustive RFC 5880 §6.8.6 truth table for received packets.
    /// 16 cases — all 4 local × 4 remote pairs.
    #[test]
    fn rx_transition_table() {
        let cases: &[(State, State, State, Option<Diag>)] = &[
            // (local, remote_in_rx, expected_new_state, expected_new_diag)

            // Remote AdminDown
            (Down, AdminDown, Down, None),
            (
                Init,
                AdminDown,
                Down,
                Some(Diag::NeighborSignaledSessionDown),
            ),
            (Up, AdminDown, Down, Some(Diag::NeighborSignaledSessionDown)),
            // Local Down
            (Down, Down, Init, None),
            (Down, Init, Up, None),
            (Down, Up, Down, None),
            // Local Init
            (Init, Down, Init, None),
            (Init, Init, Up, None),
            (Init, Up, Up, None),
            // Local Up
            (Up, Down, Down, Some(Diag::NeighborSignaledSessionDown)),
            (Up, Init, Up, None),
            (Up, Up, Up, None),
        ];
        for &(local, remote_state, expected_state, expected_diag) in cases {
            let t = transition(local, Event::Rx { remote_state });
            assert_eq!(
                t.new_state, expected_state,
                "Rx case ({local:?}, {remote_state:?}) new_state",
            );
            assert_eq!(
                t.new_diag, expected_diag,
                "Rx case ({local:?}, {remote_state:?}) new_diag",
            );
        }
    }

    /// AdminDown ignores every Rx (the local state stays AdminDown
    /// and no diag is updated).
    #[test]
    fn rx_into_admin_down_is_noop() {
        for &remote_state in &[Down, Init, Up, AdminDown] {
            let t = transition(AdminDown, Event::Rx { remote_state });
            assert_eq!(t.new_state, AdminDown);
            assert_eq!(t.new_diag, None);
        }
    }

    /// RFC 5880 §6.8.4 — Detection Time expiry from Init/Up drives
    /// Down with ControlDetectionTimeExpired; from Down it's a no-op;
    /// from AdminDown it's ignored.
    #[test]
    fn detect_expired() {
        let t = transition(Down, Event::DetectExpired);
        assert_eq!(t.new_state, Down);
        assert_eq!(t.new_diag, None);

        for &s in &[Init, Up] {
            let t = transition(s, Event::DetectExpired);
            assert_eq!(t.new_state, Down, "from {s:?}");
            assert_eq!(
                t.new_diag,
                Some(Diag::ControlDetectionTimeExpired),
                "from {s:?}",
            );
        }

        let t = transition(AdminDown, Event::DetectExpired);
        assert_eq!(t.new_state, AdminDown);
        assert_eq!(t.new_diag, None);
    }

    /// AdminDown event drives every non-AdminDown state to AdminDown
    /// and records the AdministrativelyDown diag. From AdminDown
    /// itself it's a no-op.
    #[test]
    fn admin_down_event() {
        for &s in &[Down, Init, Up] {
            let t = transition(s, Event::AdminDown);
            assert_eq!(t.new_state, AdminDown);
            assert_eq!(t.new_diag, Some(Diag::AdministrativelyDown));
        }
        let t = transition(AdminDown, Event::AdminDown);
        assert_eq!(t.new_state, AdminDown);
        assert_eq!(t.new_diag, None);
    }

    /// AdminUp lifts AdminDown back to Down (fresh start). From any
    /// other state it's a no-op (you can't "AdminUp" a session that
    /// isn't administratively down).
    #[test]
    fn admin_up_event() {
        let t = transition(AdminDown, Event::AdminUp);
        assert_eq!(t.new_state, Down);
        assert_eq!(t.new_diag, None);

        for &s in &[Down, Init, Up] {
            let t = transition(s, Event::AdminUp);
            assert_eq!(t.new_state, s, "AdminUp from {s:?} must be no-op");
            assert_eq!(t.new_diag, None);
        }
    }
}
