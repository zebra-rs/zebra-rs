//! EVPN Ethernet Segment (RFC 7432) configuration state.
//!
//! Phase 2 of the ES foundation (see `docs/design/bgp-evpn-ethernet-segment.md`):
//! the `router bgp afi-safi evpn ethernet-segment <name>` config surface and
//! the per-ES state it populates. No routes / DF election / data plane yet —
//! those are later phases. The config handlers live in `config.rs` alongside
//! the other EVPN afi-safi knobs; this module owns the state types.

use bgp_packet::ExtCommunityValue;

/// All-active vs single-active multihoming redundancy mode (RFC 7432 §14.1).
/// Carried in the ESI Label EC's flag on the per-ES A-D route.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EsRedundancyMode {
    /// All PEs on the ES forward to/from the CE (load-balanced, RFC 7432).
    /// The default and the common data-center case.
    #[default]
    AllActive,
    /// Exactly one PE (the DF) forwards per service; the rest are backup.
    SingleActive,
}

impl EsRedundancyMode {
    /// Parse the YANG `redundancy-mode` enum keyword (defaults to all-active).
    pub fn from_keyword(s: &str) -> Self {
        match s {
            "single-active" => EsRedundancyMode::SingleActive,
            _ => EsRedundancyMode::AllActive,
        }
    }

    /// The YANG keyword for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            EsRedundancyMode::AllActive => "all-active",
            EsRedundancyMode::SingleActive => "single-active",
        }
    }
}

/// A locally-configured Ethernet Segment: an ESI, a redundancy mode, and the
/// access interface it is bound to. Keyed by an operator-chosen name in
/// `Bgp::ethernet_segments`. DF state and the per-ES PE membership set are
/// added in later phases (Type-4 discovery + DF election).
#[derive(Debug, Clone, Default)]
pub struct EthernetSegment {
    /// 10-octet ESI (manual Type-0 in this phase). `None` until configured.
    pub esi: Option<[u8; 10]>,
    /// All-active (default) or single-active.
    pub redundancy_mode: EsRedundancyMode,
    /// Access interface bound to this ES (the multihomed CE-facing port).
    pub interface: Option<String>,
}

impl EthernetSegment {
    /// Auto-derive the ES-Import Route Target (RFC 7432 §7.6) from the ESI —
    /// the high-order 6 octets of the ESI value. `None` until the ESI is set.
    /// Used (in a later phase) to scope the Type-4 ES route to the PEs on this
    /// segment.
    pub fn es_import_rt(&self) -> Option<ExtCommunityValue> {
        self.esi.map(|esi| ExtCommunityValue::es_import_rt(&esi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redundancy_mode_keyword_round_trip() {
        assert_eq!(
            EsRedundancyMode::from_keyword("single-active"),
            EsRedundancyMode::SingleActive
        );
        assert_eq!(
            EsRedundancyMode::from_keyword("all-active"),
            EsRedundancyMode::AllActive
        );
        // Default / unknown keyword falls back to all-active.
        assert_eq!(
            EsRedundancyMode::from_keyword("bogus"),
            EsRedundancyMode::AllActive
        );
        assert_eq!(EsRedundancyMode::default(), EsRedundancyMode::AllActive);
        assert_eq!(EsRedundancyMode::SingleActive.as_str(), "single-active");
    }

    #[test]
    fn es_import_rt_derives_from_esi() {
        // No ESI yet → no RT.
        let es = EthernetSegment::default();
        assert!(es.es_import_rt().is_none());
        // ESI set → ES-Import RT auto-derived from the high-order 6 octets of
        // the ESI value (esi[1..7]).
        let es = EthernetSegment {
            esi: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03]),
            ..Default::default()
        };
        let rt = es.es_import_rt().expect("RT derived");
        assert!(rt.is_es_import_rt());
        assert_eq!(
            rt.as_es_import_rt(),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }
}
