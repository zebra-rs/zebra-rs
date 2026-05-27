use isis_packet::IsisTlvRestart;
use serde::Serialize;

/// Per-adjacency Graceful Restart observation + helper-mode state
/// (RFC 5306).
///
/// Phase 2 recorded the peer's Restart TLV passively. Phase 3a adds
/// the helper-mode flag — `helper_active` flips on the first IIH that
/// carries RR=1 and clears on the first IIH with RR=0 — and the
/// `observe()` method returns a [`HelperEdge`] so the caller can
/// (a) suppress the per-IIH hold-timer refresh while the peer keeps
/// retransmitting RR (RFC 5306 §3.2(a) — "otherwise, the holding time
/// is not refreshed"), and (b) trigger an immediate IIH to deliver the
/// RA reply without waiting for the next periodic hello.
#[derive(Debug, Default, Clone, Serialize)]
pub struct AdjGrState {
    /// Most recent Restart TLV (type 211) received from the peer.
    /// `None` until the peer sends an IIH that carries one.
    pub last_seen: Option<IsisTlvRestart>,
    /// Number of distinct restart attempts the peer has signaled with
    /// RR=1. Edge-triggered on the 0→1 transition so the typical
    /// 3-IIH RR retransmission burst counts once, not three times.
    pub restart_count: u32,
    /// Set while the peer is mid-restart from our point of view: we've
    /// seen RR=1 and have not yet seen RR=0. The IIH send path emits a
    /// Restart TLV with RA=1 for every neighbor in this state; the
    /// IIH receive path uses it to gate the hold-timer refresh.
    pub helper_active: bool,
}

/// Edge classification returned by [`AdjGrState::observe`] so the
/// IIH receive path knows what to do.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HelperEdge {
    /// No GR signaling on this IIH (no TLV 211 or RR=0 outside helper
    /// mode). Treat the IIH normally — refresh hold timer, no RA.
    None,
    /// First IIH with RR=1 since helper mode last cleared. Helper
    /// state has just been armed; the caller should refresh the hold
    /// timer using the IIH's hold_time (already happens today) and
    /// trigger an immediate IIH origination so RA reaches the
    /// restarter without waiting for the periodic hello.
    Enter,
    /// Peer keeps retransmitting RR=1; helper mode was already armed.
    /// RFC 5306 §3.2(a) — caller MUST NOT refresh the hold timer
    /// (otherwise a misbehaving peer can pin the adjacency forever).
    Stay,
    /// Peer cleared RR — restart is complete (or peer gave up). Helper
    /// state cleared; treat the IIH as a normal hello.
    Exit,
}

impl AdjGrState {
    /// Fold a fresh Restart TLV from the peer's IIH into the
    /// observation, return the [`HelperEdge`] for this transition.
    pub fn observe(&mut self, tlv: &IsisTlvRestart) -> HelperEdge {
        let prev_rr = self.last_seen.as_ref().map(|t| t.rr()).unwrap_or(false);
        self.last_seen = Some(tlv.clone());
        match (prev_rr, tlv.rr()) {
            (false, true) => {
                self.restart_count = self.restart_count.saturating_add(1);
                self.helper_active = true;
                HelperEdge::Enter
            }
            (true, true) => HelperEdge::Stay,
            (true, false) => {
                self.helper_active = false;
                HelperEdge::Exit
            }
            (false, false) => {
                // Could be a peer that simply included an empty
                // Restart TLV (e.g. SA-only "starting router"). Make
                // sure helper_active is consistent — clear it if it
                // was somehow left set from a prior race.
                self.helper_active = false;
                HelperEdge::None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First observation of RR=1 bumps the counter; a retransmitted RR
    /// without an intervening RR=0 must not double-count it.
    #[test]
    fn restart_count_edge_triggers_on_rr() {
        let mut gr = AdjGrState::default();
        let mut tlv = IsisTlvRestart::default();
        tlv.set_rr(true);

        assert_eq!(gr.observe(&tlv), HelperEdge::Enter);
        assert_eq!(gr.restart_count, 1);

        // Same RR still set on the next IIH — no edge, no bump.
        assert_eq!(gr.observe(&tlv), HelperEdge::Stay);
        assert_eq!(gr.restart_count, 1);

        // Peer clears RR (normal IIH), then signals a new restart.
        let cleared = IsisTlvRestart::default();
        assert_eq!(gr.observe(&cleared), HelperEdge::Exit);
        assert_eq!(gr.restart_count, 1);
        assert_eq!(gr.observe(&tlv), HelperEdge::Enter);
        assert_eq!(gr.restart_count, 2);
    }

    /// last_seen reflects the most recent TLV verbatim, including
    /// fields populated only when RA=1.
    #[test]
    fn last_seen_records_latest_tlv() {
        let mut gr = AdjGrState::default();
        let mut ra = IsisTlvRestart::default();
        ra.set_ra(true);
        ra.remaining_time = Some(27);

        assert_eq!(gr.observe(&ra), HelperEdge::None);
        let seen = gr.last_seen.expect("must record observation");
        assert!(seen.ra());
        assert!(!seen.rr());
        assert_eq!(seen.remaining_time, Some(27));
    }

    /// Helper-mode flag tracks the RR edge: armed on first RR, stays
    /// armed through retransmissions, clears on RR=0.
    #[test]
    fn helper_active_tracks_rr() {
        let mut gr = AdjGrState::default();
        let mut rr = IsisTlvRestart::default();
        rr.set_rr(true);
        let cleared = IsisTlvRestart::default();

        assert!(!gr.helper_active);
        gr.observe(&rr);
        assert!(gr.helper_active);
        gr.observe(&rr);
        assert!(gr.helper_active, "still active during retransmit");
        gr.observe(&cleared);
        assert!(!gr.helper_active, "cleared on RR=0");
    }

    /// SA-only IIH from a starting router (RFC 5306 §3.4) doesn't
    /// trigger helper mode — that path uses RR=0 + SA=1, and the
    /// helper-mode state machine is keyed off RR.
    #[test]
    fn sa_only_starting_router_is_none() {
        let mut gr = AdjGrState::default();
        let mut sa = IsisTlvRestart::default();
        sa.set_sa(true);

        assert_eq!(gr.observe(&sa), HelperEdge::None);
        assert!(!gr.helper_active);
        assert_eq!(gr.restart_count, 0);
    }
}
