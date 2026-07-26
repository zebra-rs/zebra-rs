//! EVPN Ethernet Segment (RFC 7432) configuration state.
//!
//! Part of the ES foundation (see `docs/design/bgp-evpn-ethernet-segment.md`):
//! the `router bgp afi-safi evpn ethernet-segment <name>` config surface and
//! the per-ES state it populates. No routes / DF election / data plane yet —
//! those are later phases. The config handlers live in `config.rs` alongside
//! the other EVPN afi-safi knobs; this module owns the state types.

use std::net::IpAddr;

use bgp_packet::{DfElectionEc, ExtCommunityValue};

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

    /// The ESI Label EC Single-Active flag value (RFC 7432 §7.5) for this mode.
    pub fn single_active(&self) -> bool {
        matches!(self, EsRedundancyMode::SingleActive)
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
    /// DF Preference (draft-ietf-bess-evpn-pref-df). `Some` switches this
    /// segment to Alg 2, where the highest preference wins and ties break on
    /// the lowest address, instead of the RFC 7432 §8.5 carving modulus.
    /// `None` = service carving (Alg 0), the default.
    pub df_preference: Option<u16>,
    /// Advertise the RFC 8584 §2.2 AC-DF (AC-Influenced DF election)
    /// capability on this segment's Type-4.
    pub ac_df: bool,
}

impl EthernetSegment {
    /// The DF Election extended community this segment advertises on its
    /// Type-4: Alg 2 with the configured preference when one is set,
    /// otherwise the default carving algorithm.
    pub fn df_election_ec(&self) -> DfElectionEc {
        let mut ec = match self.df_preference {
            Some(pref) => DfElectionEc {
                df_alg: DfElectionEc::ALG_PREF,
                bitmap: 0,
                pref,
            },
            None => DfElectionEc {
                df_alg: DfElectionEc::ALG_DEFAULT,
                bitmap: 0,
                pref: 0,
            },
        };
        ec.set_ac_df(self.ac_df);
        ec
    }

    /// Auto-derive the ES-Import Route Target (RFC 7432 §7.6) from the ESI —
    /// the high-order 6 octets of the ESI value. `None` until the ESI is set.
    /// Used (in a later phase) to scope the Type-4 ES route to the PEs on this
    /// segment.
    pub fn es_import_rt(&self) -> Option<ExtCommunityValue> {
        self.esi.map(|esi| ExtCommunityValue::es_import_rt(&esi))
    }
}

/// RFC 8584 DF Election algorithm negotiation across the PEs on an Ethernet
/// Segment: if every PE advertised the same algorithm (in its Type-4 DF
/// Election EC), that algorithm is used; otherwise the Default algorithm
/// (Alg 0, service-carving / modulus) is used as the fallback. An empty set
/// yields the default.
pub fn negotiate_df_alg(algs: &[u8]) -> u8 {
    match algs.split_first() {
        Some((first, rest)) if rest.iter().all(|a| a == first) => *first,
        _ => DfElectionEc::ALG_DEFAULT,
    }
}

/// Designated-Forwarder election via service carving (RFC 7432 §8.5 /
/// RFC 8584 Alg 0): the candidate VTEPs are ordered by ascending IP, given
/// ordinals 0..N, and the DF for a given Ethernet Tag / VLAN `tag` is the
/// candidate at ordinal `tag mod N`. `candidates` MUST already be sorted
/// ascending. `None` for an empty candidate set. (HRW, Alg 1, is a follow-up;
/// callers fall back to this carving for any non-zero negotiated algorithm.)
pub fn designated_forwarder(candidates: &[IpAddr], tag: u32) -> Option<IpAddr> {
    if candidates.is_empty() {
        return None;
    }
    let idx = (tag as usize) % candidates.len();
    Some(candidates[idx])
}

/// The backup Designated Forwarder for `tag` — the candidate one ordinal
/// past the DF, wrapping (RFC 8584 §2: the DF's successor in the carving
/// order takes over when the DF's routes are withdrawn). `None` for fewer
/// than two candidates: a lone PE is the DF with nobody to back it up.
pub fn backup_forwarder(candidates: &[IpAddr], tag: u32) -> Option<IpAddr> {
    if candidates.len() < 2 {
        return None;
    }
    let idx = (tag as usize).wrapping_add(1) % candidates.len();
    Some(candidates[idx])
}

/// One PE's advertised DF-election parameters, read off its Type-4's DF
/// Election extended community: `(VTEP, algorithm, preference)`.
pub type DfCandidate = (IpAddr, u8, u16);

/// Order two preference-based candidates by who wins
/// (draft-ietf-bess-evpn-pref-df): the higher preference, and on a tie the
/// **lower** IP address. Matches FRR's comparison in
/// `zebra_evpn_es_run_df_election`, so the two agree on a shared segment —
/// disagreement here means two PEs both forward and the CE sees duplicates.
fn pref_wins(a: &DfCandidate, b: &DfCandidate) -> std::cmp::Ordering {
    // Higher pref first, then lower IP first.
    b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0))
}

/// The candidates ordered best-DF-first under preference-based election.
fn pref_ranked(candidates: &[DfCandidate]) -> Vec<IpAddr> {
    let mut ranked = candidates.to_vec();
    ranked.sort_by(pref_wins);
    ranked.into_iter().map(|(ip, _, _)| ip).collect()
}

/// Elect the Designated Forwarder and its backup for one service instance,
/// dispatching on the algorithm the segment's PEs agreed on.
///
/// Alg 2 (preference) ranks by preference then address, so the DF is the
/// winner and the backup is the runner-up. Anything else falls back to
/// service carving, where the ordinal is `tag mod N` and the backup is the
/// next ordinal — the RFC 8584 fallback for a disagreed algorithm, which
/// [`negotiate_df_alg`] already resolves to Alg 0.
///
/// `candidates` need not be sorted; carving sorts by address internally so
/// the ordinal is stable across PEs.
pub fn elect_forwarders(candidates: &[DfCandidate], tag: u32) -> (Option<IpAddr>, Option<IpAddr>) {
    let algs: Vec<u8> = candidates.iter().map(|(_, alg, _)| *alg).collect();
    if negotiate_df_alg(&algs) == DfElectionEc::ALG_PREF {
        let ranked = pref_ranked(candidates);
        return (ranked.first().copied(), ranked.get(1).copied());
    }
    let mut vteps: Vec<IpAddr> = candidates.iter().map(|(ip, _, _)| *ip).collect();
    vteps.sort();
    vteps.dedup();
    (
        designated_forwarder(&vteps, tag),
        backup_forwarder(&vteps, tag),
    )
}

/// The role a PE advertises for one VPWS service instance on an Ethernet
/// Segment — the RFC 8214 §3.1 P and B bits of the Layer-2 Attributes
/// extended community.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VpwsRole {
    /// P=1, B=0. The PE forwards for this service instance: the DF under
    /// single-active, *every* attached PE under all-active, and the sole
    /// advertiser of a single-homed service.
    #[default]
    Primary,
    /// P=0, B=1. Single-active standby — the remote PE switches to this SID
    /// when the primary's Type-1 is withdrawn.
    Backup,
    /// P=0, B=0. On the segment but neither DF nor its backup; the remote
    /// PE must not use this PE for the service instance.
    NonDesignated,
}

impl VpwsRole {
    /// The `(P, B)` bit pair this role puts in the Layer-2 Attributes EC.
    pub fn bits(&self) -> (bool, bool) {
        match self {
            VpwsRole::Primary => (true, false),
            VpwsRole::Backup => (false, true),
            VpwsRole::NonDesignated => (false, false),
        }
    }

    /// Short display form for `show bgp evpn vpws`.
    pub fn as_str(&self) -> &'static str {
        match self {
            VpwsRole::Primary => "primary",
            VpwsRole::Backup => "backup",
            VpwsRole::NonDesignated => "non-designated",
        }
    }
}

/// RFC 8214 §5 role election for one VPWS service instance: `candidates` are
/// the VTEPs advertising the segment's Type-4 (ascending, as
/// `Bgp::es_df_candidates` returns them), `me` is this PE, and `service_id`
/// is the VPWS service instance id — the Ethernet Tag of the Type-1, and the
/// carving key that spreads service instances across the attached PEs.
///
/// All-active makes every attached PE primary (§5: all PEs can forward, and
/// the remote load-balances). Single-active gives the carved DF the P bit and
/// its successor the B bit, leaving any further PE with neither. A candidate
/// set that does not (yet) list `me` — our own Type-4 not selected, or no
/// segment at all — falls back to primary rather than blackholing the
/// service while the segment converges.
pub fn vpws_role(
    mode: EsRedundancyMode,
    candidates: &[DfCandidate],
    me: IpAddr,
    service_id: u32,
) -> VpwsRole {
    let on_segment = candidates.iter().any(|(ip, _, _)| *ip == me);
    if !matches!(mode, EsRedundancyMode::SingleActive) || !on_segment {
        return VpwsRole::Primary;
    }
    let (df, backup) = elect_forwarders(candidates, service_id);
    if df == Some(me) {
        VpwsRole::Primary
    } else if backup == Some(me) {
        VpwsRole::Backup
    } else {
        VpwsRole::NonDesignated
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

    #[test]
    fn df_alg_negotiation() {
        // All agree → that algorithm.
        assert_eq!(negotiate_df_alg(&[0, 0, 0]), 0);
        assert_eq!(negotiate_df_alg(&[1, 1]), 1);
        // Disagreement → Default (0).
        assert_eq!(negotiate_df_alg(&[0, 1]), 0);
        assert_eq!(negotiate_df_alg(&[1, 1, 0]), 0);
        // Empty → Default.
        assert_eq!(negotiate_df_alg(&[]), 0);
        // Single PE → its own algorithm.
        assert_eq!(negotiate_df_alg(&[1]), 1);
    }

    #[test]
    fn service_carving_df() {
        use std::net::Ipv4Addr;
        let a = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2));
        let cands = [a, b]; // sorted ascending
        // tag 0 -> ordinal 0 (a); tag 1 -> ordinal 1 (b); tag 2 -> 0 (a).
        assert_eq!(designated_forwarder(&cands, 0), Some(a));
        assert_eq!(designated_forwarder(&cands, 1), Some(b));
        assert_eq!(designated_forwarder(&cands, 2), Some(a));
        assert_eq!(designated_forwarder(&cands, 3), Some(b));
        // Single candidate is DF for every tag.
        assert_eq!(designated_forwarder(&[a], 7), Some(a));
        // Empty → none.
        assert_eq!(designated_forwarder(&[], 0), None);
    }

    /// Three PEs to make "DF", "backup" and "neither" distinguishable.
    fn pes() -> [IpAddr; 3] {
        use std::net::Ipv4Addr;
        [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        ]
    }

    #[test]
    fn backup_is_the_df_successor() {
        let [a, b, c] = pes();
        let cands = [a, b, c];
        // tag 0: DF = a (ordinal 0), backup = b (ordinal 1).
        assert_eq!(designated_forwarder(&cands, 0), Some(a));
        assert_eq!(backup_forwarder(&cands, 0), Some(b));
        // tag 2: DF = c (ordinal 2), backup wraps to a (ordinal 0).
        assert_eq!(designated_forwarder(&cands, 2), Some(c));
        assert_eq!(backup_forwarder(&cands, 2), Some(a));
        // A lone PE is the DF with nobody behind it.
        assert_eq!(backup_forwarder(&[a], 0), None);
        assert_eq!(backup_forwarder(&[], 0), None);
    }

    /// Carving candidates: every PE advertising Alg 0 with no preference.
    fn carving(ips: &[IpAddr]) -> Vec<DfCandidate> {
        ips.iter()
            .map(|ip| (*ip, DfElectionEc::ALG_DEFAULT, 0))
            .collect()
    }

    /// Preference candidates: every PE advertising Alg 2 with its own value.
    fn prefs(entries: &[(IpAddr, u16)]) -> Vec<DfCandidate> {
        entries
            .iter()
            .map(|(ip, p)| (*ip, DfElectionEc::ALG_PREF, *p))
            .collect()
    }

    #[test]
    fn all_active_makes_every_pe_primary() {
        let [a, b, c] = pes();
        let cands = carving(&[a, b, c]);
        // RFC 8214 §5: under all-active every attached PE forwards, so each
        // advertises P=1 regardless of its carving ordinal.
        for me in [a, b, c] {
            for service_id in 0..4u32 {
                assert_eq!(
                    vpws_role(EsRedundancyMode::AllActive, &cands, me, service_id),
                    VpwsRole::Primary
                );
            }
        }
    }

    #[test]
    fn single_active_carves_one_primary_and_one_backup() {
        let [a, b, c] = pes();
        let cands = carving(&[a, b, c]);
        let mode = EsRedundancyMode::SingleActive;
        // Service instance 0 carves to ordinal 0: a is DF, b backs it up,
        // c must not be used for this instance.
        assert_eq!(vpws_role(mode, &cands, a, 0), VpwsRole::Primary);
        assert_eq!(vpws_role(mode, &cands, b, 0), VpwsRole::Backup);
        assert_eq!(vpws_role(mode, &cands, c, 0), VpwsRole::NonDesignated);
        // Instance 1 shifts the whole assignment by one — that spread is the
        // point of carving per <ESI, service instance>.
        assert_eq!(vpws_role(mode, &cands, b, 1), VpwsRole::Primary);
        assert_eq!(vpws_role(mode, &cands, c, 1), VpwsRole::Backup);
        assert_eq!(vpws_role(mode, &cands, a, 1), VpwsRole::NonDesignated);
    }

    #[test]
    fn single_active_pe_not_yet_in_candidates_stays_primary() {
        let [a, b, c] = pes();
        let mode = EsRedundancyMode::SingleActive;
        // Our own Type-4 not selected yet (or no segment at all): advertise
        // primary rather than blackhole the service while it converges.
        assert_eq!(vpws_role(mode, &carving(&[a, b]), c, 0), VpwsRole::Primary);
        assert_eq!(vpws_role(mode, &[], a, 0), VpwsRole::Primary);
        // Sole PE on the segment is the DF.
        assert_eq!(vpws_role(mode, &carving(&[a]), a, 3), VpwsRole::Primary);
    }

    #[test]
    fn preference_beats_address_order() {
        let [a, b, c] = pes();
        // a is the lowest address but the lowest preference, so under Alg 2
        // it loses to both — the whole point of preference over carving.
        let cands = prefs(&[(a, 10), (b, 300), (c, 200)]);
        assert_eq!(elect_forwarders(&cands, 0), (Some(b), Some(c)));
        // ... and the service instance no longer shifts the winner, unlike
        // carving: preference is per-segment, not per-service.
        for tag in 0..5u32 {
            assert_eq!(elect_forwarders(&cands, tag).0, Some(b));
        }
    }

    #[test]
    fn equal_preference_breaks_on_lowest_address() {
        let [a, b, c] = pes();
        // draft-ietf-bess-evpn-pref-df, and FRR's comparison: equal pref ->
        // lowest IP wins. Both PEs must agree or they both forward.
        let cands = prefs(&[(c, 100), (a, 100), (b, 100)]);
        assert_eq!(elect_forwarders(&cands, 0), (Some(a), Some(b)));
    }

    #[test]
    fn mixed_algorithms_fall_back_to_carving() {
        let [a, b, c] = pes();
        // One PE still on Alg 0 means the segment cannot agree, so RFC 8584
        // negotiation drops everyone to carving — preference is ignored even
        // though two PEs advertised it.
        let mut cands = prefs(&[(a, 10), (b, 300)]);
        cands.push((c, DfElectionEc::ALG_DEFAULT, 0));
        // Carving on the address-sorted list [a, b, c], tag 1 -> ordinal 1.
        assert_eq!(elect_forwarders(&cands, 1), (Some(b), Some(c)));
        // Whereas all-Alg-2 would have given b (highest pref) for every tag.
        let agreed = prefs(&[(a, 10), (b, 300), (c, 0)]);
        assert_eq!(elect_forwarders(&agreed, 1).0, Some(b));
    }

    #[test]
    fn preference_drives_the_vpws_role() {
        let [a, b, c] = pes();
        let mode = EsRedundancyMode::SingleActive;
        let cands = prefs(&[(a, 10), (b, 300), (c, 200)]);
        // Highest preference is primary, runner-up is the backup, the rest
        // must not be used — and unlike carving this holds for every
        // service instance.
        for tag in 0..4u32 {
            assert_eq!(vpws_role(mode, &cands, b, tag), VpwsRole::Primary);
            assert_eq!(vpws_role(mode, &cands, c, tag), VpwsRole::Backup);
            assert_eq!(vpws_role(mode, &cands, a, tag), VpwsRole::NonDesignated);
        }
        // All-active still overrides the election entirely.
        for me in [a, b, c] {
            assert_eq!(
                vpws_role(EsRedundancyMode::AllActive, &cands, me, 0),
                VpwsRole::Primary
            );
        }
    }

    #[test]
    fn single_pe_wins_and_empty_elects_nobody() {
        let [a, _, _] = pes();
        assert_eq!(elect_forwarders(&prefs(&[(a, 1)]), 0), (Some(a), None));
        assert_eq!(elect_forwarders(&[], 0), (None, None));
    }

    #[test]
    fn segment_advertises_the_configured_algorithm() {
        // No preference configured: Alg 0, byte-identical to what the
        // segment advertised before preference existed.
        let carving_es = EthernetSegment::default();
        let ec = carving_es.df_election_ec();
        assert_eq!(ec.df_alg, DfElectionEc::ALG_DEFAULT);
        assert_eq!(ec.pref, 0);
        assert!(!ec.ac_df());
        // A preference switches the segment to Alg 2 and carries the value.
        let pref_es = EthernetSegment {
            df_preference: Some(200),
            ac_df: true,
            ..Default::default()
        };
        let ec = pref_es.df_election_ec();
        assert_eq!(ec.df_alg, DfElectionEc::ALG_PREF);
        assert_eq!(ec.pref, 200);
        assert!(ec.ac_df());
    }

    #[test]
    fn role_maps_to_l2_attr_bits() {
        assert_eq!(VpwsRole::Primary.bits(), (true, false));
        assert_eq!(VpwsRole::Backup.bits(), (false, true));
        assert_eq!(VpwsRole::NonDesignated.bits(), (false, false));
        // The single-homed default must stay P=1/B=0 — that is the
        // pre-multihoming behavior every existing service relies on.
        assert_eq!(VpwsRole::default(), VpwsRole::Primary);
    }
}
