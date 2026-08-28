//! EVPN Ethernet Segment (RFC 7432) configuration state.
//!
//! Part of the ES foundation (see `docs/design/bgp-evpn-ethernet-segment.md`):
//! the `router bgp afi-safi evpn ethernet-segment <name>` config surface and
//! the per-ES state it populates. No routes / DF election / data plane yet —
//! those are later phases. The config handlers live in `config.rs` alongside
//! the other EVPN afi-safi knobs; this module owns the state types.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use bgp_packet::{DfElectionEc, ExtCommunityValue};

use super::vpws::{EsBinding, bind_es};

/// The interface name for `ifindex`, from the `if-name` → `ifindex` mirror
/// BGP keeps off `RibRx::LinkAdd`.
///
/// `ifindex == 0` is "no port", not a lookup miss, and never matches: an FDB
/// learn that carries no interface must not be attributed to whichever link
/// happens to sit at index 0. Both learn sources normally carry a port — the
/// kernel bridge always, cradle via `FdbEvent.port` — so 0 now means only
/// that the source could not attribute the learn.
pub fn ac_name_for_ifindex(ifindex: u32, links: &BTreeMap<String, u32>) -> Option<String> {
    if ifindex == 0 {
        return None;
    }
    links
        .iter()
        .find_map(|(name, &idx)| (idx == ifindex).then(|| name.clone()))
}

/// The ESI a route learned on access port `ac` should carry, or `None` for
/// single-homed.
///
/// The learning port *is* the attachment circuit, so this reuses the same
/// [`bind_es`] inference VPWS does — with no explicit leaf to honour, because
/// a MAC learn carries no operator intent to override. Two segments claiming
/// one port resolves to single-homed rather than a tie-break: the wrong ESI
/// is a silent blackhole once a remote PE starts aliasing (RFC 7432 §8.4)
/// toward the segment we misnamed. `Err` returns the competing names so the
/// caller can say so.
pub fn esi_for_ac(
    ac: &str,
    segments: &BTreeMap<String, EthernetSegment>,
) -> Result<Option<[u8; 10]>, Vec<String>> {
    // `bind_es` keys on the same `Option<&String>` the VPWS `interface` leaf
    // hands it; the temporary is one allocation per MAC learn.
    let ac = ac.to_string();
    match bind_es(None, Some(&ac), segments) {
        EsBinding::Derived(name) | EsBinding::Explicit(name) => {
            Ok(segments.get(&name).and_then(|es| es.esi))
        }
        EsBinding::Ambiguous(claims) => Err(claims),
        EsBinding::None | EsBinding::Unresolved(_) => Ok(None),
    }
}

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
    /// Elect with the RFC 8584 §3 Highest Random Weight algorithm (Alg 1)
    /// instead of service carving; a configured `df_preference` (Alg 2)
    /// takes precedence.
    pub hrw: bool,
    /// Seconds to stay out of this segment's DF election after joining it
    /// (IOS-XR `timers peering`, Junos
    /// `designated-forwarder-election-hold-time`, FRR
    /// `evpn mh startup-delay`). `None` = participate immediately, the
    /// pre-existing behaviour.
    pub startup_delay: Option<u16>,
    /// When the current hold ends. `Some` only while a `startup_delay` is
    /// running; cleared when the timer fires. Runtime state kept beside the
    /// config it derives from, as [`super::vpws::VpwsService`] already does
    /// for its own derived state.
    pub hold_until: Option<Instant>,
}

impl EthernetSegment {
    /// True while this segment is still inside its startup hold at `now`.
    ///
    /// A PE that has just booted has not yet learned the other PEs' Type-4
    /// routes, so an election run immediately would see an empty segment and
    /// elect this PE the Designated Forwarder — duplicating traffic toward a
    /// CE the incumbent DF is already serving. The hold keeps this PE out of
    /// the segment until BGP has had time to converge.
    pub fn is_holding_at(&self, now: Instant) -> bool {
        self.hold_until.is_some_and(|until| now < until)
    }

    /// Seconds left in the hold at `now`, rounded up; `None` once it has
    /// elapsed. Display only. Rounding up rather than truncating means a hold
    /// that is genuinely still running never reads as `0s`.
    pub fn hold_remaining_at(&self, now: Instant) -> Option<u64> {
        self.hold_until
            .filter(|until| now < *until)
            .map(|until| until - now)
            .map(|left| left.as_secs() + u64::from(left.subsec_nanos() > 0))
    }

    /// Arm the startup hold, if one is configured and is not already
    /// running. Returns the deadline so the caller can schedule the wake-up,
    /// or `None` when there is nothing to arm.
    ///
    /// Re-arming is deliberately a no-op: a single commit that sets both the
    /// ESI and the delay reaches here twice, and restarting the countdown on
    /// the second edit would extend the outage and leave two timers racing
    /// to end the same hold.
    pub fn arm_hold(&mut self, now: Instant) -> Option<Instant> {
        let secs = self.startup_delay.filter(|s| *s > 0)?;
        if self.is_holding_at(now) {
            return None;
        }
        let until = now + Duration::from_secs(secs as u64);
        self.hold_until = Some(until);
        Some(until)
    }

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
                df_alg: if self.hrw {
                    DfElectionEc::ALG_HRW
                } else {
                    DfElectionEc::ALG_DEFAULT
                },
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

/// CRC-32 (IEEE 802.3 / ISO 3309: polynomial 0x04C11DB7 reflected, initial
/// and final XOR all-ones — the CRC of zlib and Ethernet), as RFC 8584 §3.2
/// uses for the HRW digest. Bitwise; the inputs are 14 bytes.
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// RFC 8584 §3.2 `D(V, Es)`: the 31-bit digest of the 14-octet stream
/// `Ethernet Tag (4, network order) || ESI (10)` — CRC-32 with the top bit
/// discarded.
pub fn hrw_digest(esi: &[u8; 10], tag: u32) -> u32 {
    let mut stream = [0u8; 14];
    stream[..4].copy_from_slice(&tag.to_be_bytes());
    stream[4..].copy_from_slice(esi);
    crc32_ieee(&stream) & 0x7fff_ffff
}

/// RFC 8584 §3.2 `Wrand(V, Es, Si)`:
/// `(1103515245 · ((1103515245 · Si + 12345) ⊕ D) + 12345) mod 2^31`, with
/// `Si` the PE's address as a 32-bit integer — an IPv4 address whole, an
/// IPv6 address by its low-order 32 bits (the RFC notes only the low 31
/// bits are significant). Computed in wrapping 32-bit arithmetic, which
/// preserves the residue mod 2^31 the RFC defines.
pub fn hrw_weight(addr: IpAddr, digest: u32) -> u32 {
    let si: u32 = match addr {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            u32::from_be_bytes([o[12], o[13], o[14], o[15]])
        }
    };
    let a = 1_103_515_245u32.wrapping_mul(si).wrapping_add(12_345);
    1_103_515_245u32
        .wrapping_mul(a ^ digest)
        .wrapping_add(12_345)
        & 0x7fff_ffff
}

/// The candidates ordered best-DF-first under HRW (RFC 8584 §3.2): highest
/// weight wins, a tie goes to the numerically lowest address; the runner-up
/// is the backup DF. Deterministic and order-independent, so every PE on
/// the segment computes the same ranking from the same Type-4 set.
fn hrw_ranked(candidates: &[DfCandidate], esi: &[u8; 10], tag: u32) -> Vec<IpAddr> {
    let d = hrw_digest(esi, tag);
    let mut ranked: Vec<(u32, IpAddr)> = candidates
        .iter()
        .map(|(ip, _, _)| (hrw_weight(*ip, d), *ip))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    ranked.dedup_by_key(|(_, ip)| *ip);
    ranked.into_iter().map(|(_, ip)| ip).collect()
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
pub fn elect_forwarders(
    candidates: &[DfCandidate],
    esi: &[u8; 10],
    tag: u32,
) -> (Option<IpAddr>, Option<IpAddr>) {
    let algs: Vec<u8> = candidates.iter().map(|(_, alg, _)| *alg).collect();
    match negotiate_df_alg(&algs) {
        DfElectionEc::ALG_PREF => {
            let ranked = pref_ranked(candidates);
            return (ranked.first().copied(), ranked.get(1).copied());
        }
        DfElectionEc::ALG_HRW => {
            let ranked = hrw_ranked(candidates, esi, tag);
            return (ranked.first().copied(), ranked.get(1).copied());
        }
        _ => {}
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
    esi: &[u8; 10],
    service_id: u32,
) -> VpwsRole {
    let on_segment = candidates.iter().any(|(ip, _, _)| *ip == me);
    if !matches!(mode, EsRedundancyMode::SingleActive) || !on_segment {
        return VpwsRole::Primary;
    }
    let (df, backup) = elect_forwarders(candidates, esi, service_id);
    if df == Some(me) {
        VpwsRole::Primary
    } else if backup == Some(me) {
        VpwsRole::Backup
    } else {
        VpwsRole::NonDesignated
    }
}

/// The E-LAN DF verdict for this PE on a segment in one bridge domain
/// (RFC 7432 §8.5): service carving over the segment's Type-4 candidates
/// with the VNI as the Ethernet Tag — `elect_forwarders` honours the
/// negotiated algorithm, so a unanimous preference-based segment elects by
/// preference instead. A holding PE (startup delay) is never DF: its own
/// Type-4 is withheld, so it must not forward BUM before it has joined the
/// election. A PE absent from the candidates (its Type-4 not selected yet)
/// is not DF either — unlike `vpws_role`'s primary fallback, a BUM copy
/// delivered by a not-yet-elected PE is exactly the duplicate the filter
/// exists to stop, while known unicast keeps flowing regardless.
pub fn elan_df(
    candidates: &[DfCandidate],
    me: IpAddr,
    esi: &[u8; 10],
    vni: u32,
    holding: bool,
) -> bool {
    !holding && elect_forwarders(candidates, esi, vni).0 == Some(me)
}

/// RFC 8584 §4 AC-Influenced DF election is in effect on a segment only
/// when **every** PE on it advertises the capability (§4: a PE that does
/// not support it would keep electing over the full Type-4 set, and the
/// two views of the DF would diverge). `advertising` of `total` Type-4s
/// carry the bit; an empty segment is not in effect.
pub fn ac_df_in_effect(advertising: usize, total: usize) -> bool {
    total > 0 && advertising == total
}

/// The AC-DF candidate list for one `(ES, EVI, Ethernet Tag)` (RFC 8584
/// §4.1): of the segment's Type-4 `candidates`, a PE stays only if its
/// per-ES A-D is `live` and it has a per-EVI A-D for this EVI/tag
/// (`ad_evi`) — a PE that withdrew that route has the attachment circuit
/// down. `me` always stays: the callers elect for EVIs this PE is itself
/// advertising for, and our own routes are not in the sets (they are
/// originated, not received). The relative order — and so the carving
/// ordinals — is preserved.
pub fn ac_df_filter(
    candidates: &[DfCandidate],
    me: IpAddr,
    live: &std::collections::BTreeSet<IpAddr>,
    ad_evi: &std::collections::BTreeSet<IpAddr>,
) -> Vec<DfCandidate> {
    candidates
        .iter()
        .filter(|(ip, _, _)| *ip == me || (live.contains(ip) && ad_evi.contains(ip)))
        .copied()
        .collect()
}

/// What the E-LAN DF tee last told the cradle datapath about one segment
/// (`Bgp::es_df_sent`), so a re-sync emits only the deltas: the access port
/// sent as the segment's port list (`None` = not sent, or must be re-sent
/// because the link reappeared) and the per-bridge-domain DF verdicts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EsTeeState {
    pub port: Option<String>,
    /// Bridge domain → `(DF?, single-active?)`.
    pub roles: std::collections::BTreeMap<u32, (bool, bool)>,
    /// The peer PEs sent as the segment's split-horizon list (the Type-4
    /// candidates other than this PE).
    pub peers: std::collections::BTreeSet<IpAddr>,
}

#[cfg(test)]
mod ac_esi_tests {
    use super::*;

    const ESI_A: [u8; 10] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
    const ESI_B: [u8; 10] = [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03];

    fn links(entries: &[(&str, u32)]) -> BTreeMap<String, u32> {
        entries
            .iter()
            .map(|(name, idx)| (name.to_string(), *idx))
            .collect()
    }

    fn segments(
        entries: &[(&str, Option<&str>, Option<[u8; 10]>)],
    ) -> BTreeMap<String, EthernetSegment> {
        entries
            .iter()
            .map(|(name, iface, esi)| {
                (
                    name.to_string(),
                    EthernetSegment {
                        esi: *esi,
                        interface: iface.map(str::to_string),
                        ..Default::default()
                    },
                )
            })
            .collect()
    }

    #[test]
    fn ifindex_resolves_to_its_link_name() {
        let links = links(&[("eth0", 2), ("eth1", 3)]);
        assert_eq!(ac_name_for_ifindex(3, &links).as_deref(), Some("eth1"));
        // An index no link claims is a miss, not a wrong answer.
        assert_eq!(ac_name_for_ifindex(9, &links), None);
    }

    /// A learn whose source could not attribute a port arrives with
    /// `ifindex: 0`. That must never be attributed to a link — including one
    /// that somehow sits at index 0 — or every such MAC would inherit that
    /// link's segment.
    #[test]
    fn ifindex_zero_never_resolves() {
        assert_eq!(ac_name_for_ifindex(0, &links(&[("eth0", 0)])), None);
        assert_eq!(ac_name_for_ifindex(0, &links(&[("eth0", 2)])), None);
    }

    #[test]
    fn port_on_one_segment_takes_its_esi() {
        let segs = segments(&[("es1", Some("eth0"), Some(ESI_A))]);
        assert_eq!(esi_for_ac("eth0", &segs), Ok(Some(ESI_A)));
    }

    #[test]
    fn port_on_no_segment_is_single_homed() {
        let segs = segments(&[("es1", Some("eth0"), Some(ESI_A))]);
        assert_eq!(esi_for_ac("eth1", &segs), Ok(None));
        // A segment that claims the port but has no ESI configured yet is
        // still single-homed — there is nothing to advertise.
        let pending = segments(&[("es1", Some("eth0"), None)]);
        assert_eq!(esi_for_ac("eth0", &pending), Ok(None));
    }

    /// Two segments claiming one port must not tie-break: picking the wrong
    /// ESI blackholes traffic a remote PE aliases toward that segment.
    #[test]
    fn port_claimed_twice_is_ambiguous_not_arbitrary() {
        let segs = segments(&[
            ("es1", Some("eth0"), Some(ESI_A)),
            ("es2", Some("eth0"), Some(ESI_B)),
        ]);
        assert_eq!(
            esi_for_ac("eth0", &segs),
            Err(vec!["es1".to_string(), "es2".to_string()])
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The segment the election tests run on (its ESI is HRW's salt).
    const ESI_T: [u8; 10] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];

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
                    vpws_role(EsRedundancyMode::AllActive, &cands, me, &ESI_T, service_id),
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
        assert_eq!(vpws_role(mode, &cands, a, &ESI_T, 0), VpwsRole::Primary);
        assert_eq!(vpws_role(mode, &cands, b, &ESI_T, 0), VpwsRole::Backup);
        assert_eq!(
            vpws_role(mode, &cands, c, &ESI_T, 0),
            VpwsRole::NonDesignated
        );
        // Instance 1 shifts the whole assignment by one — that spread is the
        // point of carving per <ESI, service instance>.
        assert_eq!(vpws_role(mode, &cands, b, &ESI_T, 1), VpwsRole::Primary);
        assert_eq!(vpws_role(mode, &cands, c, &ESI_T, 1), VpwsRole::Backup);
        assert_eq!(
            vpws_role(mode, &cands, a, &ESI_T, 1),
            VpwsRole::NonDesignated
        );
    }

    #[test]
    fn single_active_pe_not_yet_in_candidates_stays_primary() {
        let [a, b, c] = pes();
        let mode = EsRedundancyMode::SingleActive;
        // Our own Type-4 not selected yet (or no segment at all): advertise
        // primary rather than blackhole the service while it converges.
        assert_eq!(
            vpws_role(mode, &carving(&[a, b]), c, &ESI_T, 0),
            VpwsRole::Primary
        );
        assert_eq!(vpws_role(mode, &[], a, &ESI_T, 0), VpwsRole::Primary);
        // Sole PE on the segment is the DF.
        assert_eq!(
            vpws_role(mode, &carving(&[a]), a, &ESI_T, 3),
            VpwsRole::Primary
        );
    }

    #[test]
    fn preference_beats_address_order() {
        let [a, b, c] = pes();
        // a is the lowest address but the lowest preference, so under Alg 2
        // it loses to both — the whole point of preference over carving.
        let cands = prefs(&[(a, 10), (b, 300), (c, 200)]);
        assert_eq!(elect_forwarders(&cands, &ESI_T, 0), (Some(b), Some(c)));
        // ... and the service instance no longer shifts the winner, unlike
        // carving: preference is per-segment, not per-service.
        for tag in 0..5u32 {
            assert_eq!(elect_forwarders(&cands, &ESI_T, tag).0, Some(b));
        }
    }

    #[test]
    fn equal_preference_breaks_on_lowest_address() {
        let [a, b, c] = pes();
        // draft-ietf-bess-evpn-pref-df, and FRR's comparison: equal pref ->
        // lowest IP wins. Both PEs must agree or they both forward.
        let cands = prefs(&[(c, 100), (a, 100), (b, 100)]);
        assert_eq!(elect_forwarders(&cands, &ESI_T, 0), (Some(a), Some(b)));
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
        assert_eq!(elect_forwarders(&cands, &ESI_T, 1), (Some(b), Some(c)));
        // Whereas all-Alg-2 would have given b (highest pref) for every tag.
        let agreed = prefs(&[(a, 10), (b, 300), (c, 0)]);
        assert_eq!(elect_forwarders(&agreed, &ESI_T, 1).0, Some(b));
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
            assert_eq!(vpws_role(mode, &cands, b, &ESI_T, tag), VpwsRole::Primary);
            assert_eq!(vpws_role(mode, &cands, c, &ESI_T, tag), VpwsRole::Backup);
            assert_eq!(
                vpws_role(mode, &cands, a, &ESI_T, tag),
                VpwsRole::NonDesignated
            );
        }
        // All-active still overrides the election entirely.
        for me in [a, b, c] {
            assert_eq!(
                vpws_role(EsRedundancyMode::AllActive, &cands, me, &ESI_T, 0),
                VpwsRole::Primary
            );
        }
    }

    /// The CRC-32 the HRW digest is built on is the IEEE/zlib one: its
    /// standard check value.
    #[test]
    fn crc32_is_the_ieee_crc() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }

    /// RFC 8584 §3.2 vectors, computed independently from the formula
    /// (`zlib.crc32` over `tag || ESI`, then the LCG in 32-bit wrapping
    /// arithmetic, mod 2^31): for ESI 00:11:…:99 and tag 0 the digest is
    /// 0x19981279, and 192.168.0.1 outweighs 192.168.0.2; for tag 100 the
    /// order flips. Any implementation on the far end of the segment that
    /// follows the RFC must agree on these, or two DFs forward.
    #[test]
    fn hrw_matches_the_rfc_8584_formula() {
        use std::net::Ipv4Addr;
        let a = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2));
        assert_eq!(hrw_digest(&ESI_T, 0), 0x1998_1279);
        assert_eq!(hrw_weight(a, 0x1998_1279), 1_676_836_140);
        assert_eq!(hrw_weight(b, 0x1998_1279), 1_477_024_859);
        assert_eq!(hrw_digest(&ESI_T, 100), 0x7995_f7c3);
        assert_eq!(hrw_weight(a, 0x7995_f7c3), 712_275_514);
        assert_eq!(hrw_weight(b, 0x7995_f7c3), 2_110_888_649);
        let cands: Vec<DfCandidate> =
            vec![(a, DfElectionEc::ALG_HRW, 0), (b, DfElectionEc::ALG_HRW, 0)];
        assert_eq!(elect_forwarders(&cands, &ESI_T, 0), (Some(a), Some(b)));
        assert_eq!(elect_forwarders(&cands, &ESI_T, 100), (Some(b), Some(a)));
        // Order-independent: every PE ranks the same set the same way.
        let rev: Vec<DfCandidate> = cands.iter().rev().copied().collect();
        assert_eq!(elect_forwarders(&rev, &ESI_T, 0), (Some(a), Some(b)));
        // A single candidate is DF with nobody to back it up; none elects nobody.
        assert_eq!(elect_forwarders(&cands[..1], &ESI_T, 0), (Some(a), None));
        assert_eq!(elect_forwarders(&[], &ESI_T, 0), (None, None));
    }

    /// One PE asking for HRW while another asks for carving is a disagreed
    /// segment: RFC 8584 negotiation falls back to carving, whose tag-0 DF
    /// is the lowest address regardless of weights.
    #[test]
    fn hrw_needs_unanimity() {
        let [a, b, _] = pes();
        let mixed: Vec<DfCandidate> = vec![
            (a, DfElectionEc::ALG_HRW, 0),
            (b, DfElectionEc::ALG_DEFAULT, 0),
        ];
        assert_eq!(elect_forwarders(&mixed, &ESI_T, 0).0, Some(a));
        assert_eq!(elect_forwarders(&mixed, &ESI_T, 1).0, Some(b));
    }

    /// The election the segment advertises follows the config: HRW when
    /// asked for, but a preference still wins over it.
    #[test]
    fn segment_advertises_hrw_when_configured() {
        let es = EthernetSegment {
            hrw: true,
            ..Default::default()
        };
        assert_eq!(es.df_election_ec().df_alg, DfElectionEc::ALG_HRW);
        let es = EthernetSegment {
            hrw: true,
            df_preference: Some(7),
            ..Default::default()
        };
        assert_eq!(es.df_election_ec().df_alg, DfElectionEc::ALG_PREF);
    }

    /// AC-DF is a unanimous capability: any PE without the bit keeps the
    /// segment on the plain Type-4 election, and nobody is not a segment.
    #[test]
    fn ac_df_needs_every_pe() {
        assert!(ac_df_in_effect(2, 2));
        assert!(ac_df_in_effect(1, 1));
        assert!(!ac_df_in_effect(1, 2));
        assert!(!ac_df_in_effect(0, 1));
        assert!(!ac_df_in_effect(0, 0));
    }

    /// RFC 8584 §4.1: a PE whose per-EVI A-D for the EVI is missing — its
    /// attachment circuit is down — drops out of that EVI's candidate list,
    /// and so does one whose per-ES A-D is gone; the local PE stays. The
    /// election then runs over what is left: with the carved DF gone, the
    /// survivor is DF for the service.
    #[test]
    fn ac_df_drops_the_pe_with_the_ac_down() {
        use std::collections::BTreeSet;
        let [a, b, c] = pes();
        let cands: Vec<DfCandidate> = vec![
            (a, DfElectionEc::ALG_DEFAULT, 0),
            (b, DfElectionEc::ALG_DEFAULT, 0),
            (c, DfElectionEc::ALG_DEFAULT, 0),
        ];
        // Tag 1 carves to ordinal 1 = b over the full set.
        assert_eq!(elect_forwarders(&cands, &ESI_T, 1).0, Some(b));
        let live: BTreeSet<IpAddr> = [b, c].into_iter().collect();
        // b's per-EVI A-D for this EVI is gone; c's is up.
        let ad_evi: BTreeSet<IpAddr> = [c].into_iter().collect();
        let narrowed = ac_df_filter(&cands, a, &live, &ad_evi);
        assert_eq!(
            narrowed.iter().map(|(ip, _, _)| *ip).collect::<Vec<_>>(),
            vec![a, c]
        );
        // Tag 1 now carves to ordinal 1 of [a, c] = c.
        assert_eq!(elect_forwarders(&narrowed, &ESI_T, 1).0, Some(c));
        // c's per-ES A-D withdrawn (mass withdraw) removes it even with the
        // per-EVI A-D still selected.
        let live: BTreeSet<IpAddr> = [b].into_iter().collect();
        let ad_evi: BTreeSet<IpAddr> = [b, c].into_iter().collect();
        let narrowed = ac_df_filter(&cands, a, &live, &ad_evi);
        assert_eq!(
            narrowed.iter().map(|(ip, _, _)| *ip).collect::<Vec<_>>(),
            vec![a, b]
        );
        // The local PE is never filtered by its own (originated) routes.
        let narrowed = ac_df_filter(&cands, a, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(
            narrowed.iter().map(|(ip, _, _)| *ip).collect::<Vec<_>>(),
            vec![a]
        );
    }

    #[test]
    fn single_pe_wins_and_empty_elects_nobody() {
        let [a, _, _] = pes();
        assert_eq!(
            elect_forwarders(&prefs(&[(a, 1)]), &ESI_T, 0),
            (Some(a), None)
        );
        assert_eq!(elect_forwarders(&[], &ESI_T, 0), (None, None));
    }

    /// E-LAN DF per bridge domain: carving spreads consecutive VNIs across
    /// the segment's PEs, a holding PE never forwards BUM, and a PE that
    /// is not (yet) a candidate is non-DF rather than primary.
    #[test]
    fn elan_df_carves_by_vni_and_holds() {
        let [a, b, c] = pes();
        let cands: Vec<DfCandidate> = vec![(a, 0, 0), (b, 0, 0)];
        // VNI 100 % 2 == 0 → a; VNI 101 % 2 == 1 → b.
        assert!(elan_df(&cands, a, &ESI_T, 100, false));
        assert!(!elan_df(&cands, b, &ESI_T, 100, false));
        assert!(!elan_df(&cands, a, &ESI_T, 101, false));
        assert!(elan_df(&cands, b, &ESI_T, 101, false));
        // Holding trumps winning.
        assert!(!elan_df(&cands, a, &ESI_T, 100, true));
        // Not a candidate: never DF.
        assert!(!elan_df(&cands, c, &ESI_T, 100, false));
        assert!(!elan_df(&[], a, &ESI_T, 100, false));
        // Unanimous preference: the preferred PE is DF in every domain.
        let pref = prefs(&[(a, 10), (b, 200)]);
        assert!(elan_df(&pref, b, &ESI_T, 100, false));
        assert!(elan_df(&pref, b, &ESI_T, 101, false));
        assert!(!elan_df(&pref, a, &ESI_T, 100, false));
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
    fn startup_hold_arms_once_and_elapses() {
        let now = Instant::now();
        // No delay configured: nothing to arm, and the segment is never
        // holding — the pre-existing behaviour every current ES relies on.
        let mut es = EthernetSegment::default();
        assert_eq!(es.arm_hold(now), None);
        assert!(!es.is_holding_at(now));
        assert_eq!(es.hold_remaining_at(now), None);

        let mut es = EthernetSegment {
            startup_delay: Some(30),
            ..Default::default()
        };
        let until = es.arm_hold(now).expect("armed");
        assert_eq!(until, now + Duration::from_secs(30));
        assert!(es.is_holding_at(now));
        assert!(es.is_holding_at(now + Duration::from_secs(29)));
        // The deadline itself is already out of the hold, so the timer
        // firing exactly on time finds the segment free to rejoin.
        assert!(!es.is_holding_at(until));

        // Re-arming mid-hold keeps the original deadline: one commit reaches
        // `arm_hold` from both the `esi` and the `startup-delay` leaf, and
        // restarting the countdown on the second would extend the outage and
        // leave two timers racing to end the same hold.
        assert_eq!(es.arm_hold(now + Duration::from_secs(10)), None);
        assert_eq!(es.hold_until, Some(until));
        // Once it has elapsed the segment can be held again — leaving and
        // rejoining a segment is a fresh hold, not a spent one.
        es.hold_until = None;
        assert_eq!(es.arm_hold(until), Some(until + Duration::from_secs(30)));
    }

    #[test]
    fn hold_remaining_rounds_up_for_display() {
        let now = Instant::now();
        let mut es = EthernetSegment {
            startup_delay: Some(10),
            ..Default::default()
        };
        es.arm_hold(now);
        // Exactly the full delay, not one more: "11s of 10s remaining" the
        // instant it arms would be nonsense.
        assert_eq!(es.hold_remaining_at(now), Some(10));
        // Part-way through the last second still reads as 1s — while the
        // hold is genuinely running it must never display as 0.
        assert_eq!(
            es.hold_remaining_at(now + Duration::from_millis(9_500)),
            Some(1)
        );
        assert_eq!(es.hold_remaining_at(now + Duration::from_secs(10)), None);
    }

    #[test]
    fn zero_startup_delay_never_holds() {
        // The YANG range starts at 1, but a 0 reaching the type must not arm
        // a hold no timer would ever come back to end.
        let now = Instant::now();
        let mut es = EthernetSegment {
            startup_delay: Some(0),
            ..Default::default()
        };
        assert_eq!(es.arm_hold(now), None);
        assert!(!es.is_holding_at(now));
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
