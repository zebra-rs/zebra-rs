use isis_packet::IsisTlvRestart;
use serde::Serialize;

/// Per-adjacency Graceful Restart observation (RFC 5306).
///
/// Phase 2 is read-only — we record the most recent Restart TLV the
/// peer included in its IIH so an operator can confirm GR signaling
/// over the wire, but we take no action on it. Helper-side state
/// machine (refresh hold once, send RA, suppress adjacency teardown)
/// arrives in Phase 3 and will extend this struct.
#[derive(Debug, Default, Clone, Serialize)]
pub struct AdjGrState {
    /// Most recent Restart TLV (type 211) received from the peer.
    /// `None` until the peer sends an IIH that carries one.
    pub last_seen: Option<IsisTlvRestart>,
    /// Number of distinct restart attempts the peer has signaled with
    /// RR=1. Edge-triggered on the 0→1 transition so the typical
    /// 3-IIH RR retransmission burst counts once, not three times.
    pub restart_count: u32,
}

impl AdjGrState {
    /// Fold a fresh Restart TLV from the peer's IIH into the
    /// observation. Increments `restart_count` only on the 0→1 RR
    /// edge, then stores the new TLV so the next call can see the
    /// previous state.
    pub fn observe(&mut self, tlv: &IsisTlvRestart) {
        let prev_rr = self.last_seen.as_ref().map(|t| t.rr()).unwrap_or(false);
        if tlv.rr() && !prev_rr {
            self.restart_count = self.restart_count.saturating_add(1);
        }
        self.last_seen = Some(tlv.clone());
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

        gr.observe(&tlv);
        assert_eq!(gr.restart_count, 1);

        // Same RR still set on the next IIH — no edge, no bump.
        gr.observe(&tlv);
        assert_eq!(gr.restart_count, 1);

        // Peer clears RR (normal IIH), then signals a new restart.
        let cleared = IsisTlvRestart::default();
        gr.observe(&cleared);
        assert_eq!(gr.restart_count, 1);
        gr.observe(&tlv);
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

        gr.observe(&ra);
        let seen = gr.last_seen.expect("must record observation");
        assert!(seen.ra());
        assert!(!seen.rr());
        assert_eq!(seen.remaining_time, Some(27));
    }
}
