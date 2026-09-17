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

/// How a remote PE is told which PE forwards a single-active segment's
/// known unicast (`docs/design/bgp-evpn-single-active-plan.md` §4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RoleSignaling {
    /// Advertise nothing; a remote PE infers the forwarder from which PE
    /// advertised the segment's MACs (`Bgp::es_sa_primary`). The
    /// pre-existing behaviour, and the default.
    #[default]
    Inferred,
    /// Advertise the elected role in the Layer-2 Attributes extended
    /// community of the per-EVI Ethernet A-D (draft-ietf-bess-rfc7432bis
    /// §7.11.1), so a remote PE reads the forwarder instead of guessing it
    /// from MAC counts.
    L2Attr,
}

impl RoleSignaling {
    /// Parse the YANG `role-signaling` keyword.
    pub fn from_keyword(s: &str) -> Self {
        match s {
            "l2-attr" => RoleSignaling::L2Attr,
            _ => RoleSignaling::Inferred,
        }
    }

    /// The YANG keyword for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            RoleSignaling::Inferred => "inferred",
            RoleSignaling::L2Attr => "l2-attr",
        }
    }

    /// Whether the role rides the per-EVI A-D.
    pub fn signals(&self) -> bool {
        matches!(self, RoleSignaling::L2Attr)
    }
}

/// The DF election algorithm a segment advertises and runs (RFC 8584 §2.2
/// DF Alg values; RFC 9785 adds the two preference-based ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfAlgorithm {
    /// Alg 0 — RFC 7432 §8.5 service carving (the modulus).
    Default,
    /// Alg 1 — RFC 8584 §3 Highest Random Weight.
    Hrw,
    /// Alg 2 — RFC 9785 Highest-Preference.
    Preference,
    /// Alg 3 — RFC 9785 Lowest-Preference.
    LowestPreference,
}

impl DfAlgorithm {
    /// Parse the YANG `df-election algorithm` keyword; `None` for anything
    /// else, which leaves the segment on whatever the preference leaf implies.
    pub fn from_keyword(s: &str) -> Option<Self> {
        match s {
            "default" => Some(DfAlgorithm::Default),
            "hrw" => Some(DfAlgorithm::Hrw),
            "preference" => Some(DfAlgorithm::Preference),
            "lowest-preference" => Some(DfAlgorithm::LowestPreference),
            _ => None,
        }
    }

    /// The YANG keyword for this algorithm.
    pub fn as_str(&self) -> &'static str {
        match self {
            DfAlgorithm::Default => "default",
            DfAlgorithm::Hrw => "hrw",
            DfAlgorithm::Preference => "preference",
            DfAlgorithm::LowestPreference => "lowest-preference",
        }
    }

    /// The 5-bit DF Alg value this algorithm puts on the wire.
    pub fn wire(&self) -> u8 {
        match self {
            DfAlgorithm::Default => DfElectionEc::ALG_DEFAULT,
            DfAlgorithm::Hrw => DfElectionEc::ALG_HRW,
            DfAlgorithm::Preference => DfElectionEc::ALG_PREF,
            DfAlgorithm::LowestPreference => DfElectionEc::ALG_PREF_LOWEST,
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
    /// DF Preference (RFC 9785 §3). Under a preference-based algorithm this
    /// is what the segment bids; `None` there means the RFC's mandatory
    /// default of 32767. With no `df_algorithm` configured at all, `Some`
    /// still selects Alg 2 on its own — the spelling that shipped before the
    /// `algorithm` leaf grew its preference arms.
    pub df_preference: Option<u16>,
    /// Advertise the RFC 8584 §2.2 AC-DF (AC-Influenced DF election)
    /// capability on this segment's Type-4.
    pub ac_df: bool,
    /// The configured DF election algorithm. `None` = not configured, which
    /// means carving unless `df_preference` is set (see that field).
    pub df_algorithm: Option<DfAlgorithm>,
    /// Advertise the RFC 9785 "Don't Preempt" (DP) capability: on a
    /// preference tie this PE is ranked ahead of one that does **not** set
    /// the bit. Only meaningful — and only advertised — under a
    /// preference-based algorithm.
    ///
    /// This is the tie-break input alone. It is not RFC 9785 §4.3
    /// non-revertive operation, which additionally has a recovering PE
    /// advertise an *operational* `(Pref, DP)` inherited from the incumbent
    /// DF; without that, two PEs that both set the bit at equal preference
    /// still fall through to the address comparison, and the lower-address
    /// one reclaims the role when it comes back.
    pub dont_preempt: bool,
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
    /// How this segment tells remote PEs which PE forwards its known
    /// unicast. Default `Inferred` — the pre-existing MAC-count inference.
    pub role_signaling: RoleSignaling,
    /// RFC 7432 §8.3: this PE's ESI label for the segment under
    /// `encapsulation mpls` — drawn from the dynamic label block
    /// (`Bgp::es_label_reconcile`), advertised in the per-ES A-D's ESI
    /// Label EC, and teed to cradle so a peer's BUM carrying it is kept
    /// off the segment. `None` under any other encapsulation, or until the
    /// block arrives.
    pub esi_label: Option<u32>,
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
    /// Type-4: the configured algorithm, the preference it bids under a
    /// preference-based one, and the capability bits.
    ///
    /// A preference-based algorithm with no configured value bids RFC 9785
    /// §3's mandatory default of 32767 rather than 0 — a PE that bid 0 would
    /// silently rank below every peer that took the default. The DP bit is
    /// advertised only under those algorithms, since it is defined as a
    /// preference tie-break.
    /// **Precedence, and why it is not simply "the explicit leaf wins".**
    /// Before the `algorithm` leaf had preference arms, its only values were
    /// `default` and `hrw`, and a `preference` value selected Alg 2 over
    /// either of them. Configurations spelled that way exist, so they keep
    /// that meaning: a preference value still beats `algorithm default` and
    /// `algorithm hrw`. Making the algorithm leaf win instead would change
    /// what such a PE advertises across an upgrade — and a PE that starts
    /// advertising Alg 1 to peers still on Alg 2 does not merely differ, it
    /// breaks the RFC 8584 unanimity check and drops the **whole segment**
    /// to carving, moving the DF as it goes. The new arms are how an
    /// operator now says which preference algorithm they mean; `algorithm
    /// hrw` plus a preference stays the legacy spelling of Alg 2, which
    /// `show bgp evpn ethernet-segment` calls out rather than leaving to be
    /// discovered.
    pub fn df_election_ec(&self) -> DfElectionEc {
        let alg = match (self.df_algorithm, self.df_preference) {
            // The preference arms name the algorithm themselves, so a value
            // beside them selects between Alg 2 and Alg 3 rather than
            // overriding anything.
            (Some(alg @ (DfAlgorithm::Preference | DfAlgorithm::LowestPreference)), _) => {
                alg.wire()
            }
            // Legacy precedence, preserved for configurations written before
            // those arms existed.
            (_, Some(_)) => DfElectionEc::ALG_PREF,
            (Some(alg), None) => alg.wire(),
            (None, None) => DfElectionEc::ALG_DEFAULT,
        };
        let preference_based = DfElectionEc::is_preference_alg(alg);
        let mut ec = DfElectionEc {
            df_alg: alg,
            bitmap: 0,
            pref: if preference_based {
                self.df_preference.unwrap_or(DfElectionEc::PREF_DEFAULT)
            } else {
                0
            },
        };
        ec.set_ac_df(self.ac_df);
        ec.set_dont_preempt(preference_based && self.dont_preempt);
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
/// Election extended community: the VTEP, the algorithm, the preference and
/// the capability bitmap (RFC 9785 DP, RFC 8584 AC-DF).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DfCandidate {
    /// The PE's Originating Router IP — the Type-4 NLRI key, and the
    /// identity every PE on the segment ranks by.
    pub addr: IpAddr,
    /// DF Alg this PE advertises (RFC 8584 §2.2 / RFC 9785 §3).
    pub alg: u8,
    /// Its DF Preference; meaningful under the preference-based algorithms.
    pub pref: u16,
    /// Its capability bitmap, kept whole so a bit this version does not act
    /// on is still visible in `show` rather than dropped at parse time.
    pub caps: u16,
}

impl DfCandidate {
    /// A candidate with no capability bits — the common case in tests and
    /// for a Type-4 carrying no DF Election EC at all.
    pub fn new(addr: IpAddr, alg: u8, pref: u16) -> Self {
        Self {
            addr,
            alg,
            pref,
            caps: 0,
        }
    }

    /// Builder: attach the advertised capability bitmap.
    pub fn with_caps(mut self, caps: u16) -> Self {
        self.caps = caps;
        self
    }

    /// Whether this PE asked not to be preempted (RFC 9785 §3, D bit).
    pub fn dont_preempt(&self) -> bool {
        self.caps & DfElectionEc::CAP_DONT_PREEMPT != 0
    }
}

/// Order two preference-based candidates by who wins (RFC 9785 §4.1): the
/// better preference — highest under Alg 2, `lowest` under Alg 3 — then the
/// PE that asked not to be preempted, then the **lower** IP address.
///
/// The address step matches FRR's comparison in
/// `zebra_evpn_es_run_df_election`, so the two agree on a shared segment;
/// disagreement here means two PEs both forward and the CE sees duplicates.
/// The DP step sits between them because RFC 9785 §4.1 orders it that way —
/// ignoring a peer's bit would rank the segment differently at each end,
/// which is the same duplicate.
fn pref_wins(a: &DfCandidate, b: &DfCandidate, lowest: bool) -> std::cmp::Ordering {
    let by_pref = if lowest {
        a.pref.cmp(&b.pref)
    } else {
        b.pref.cmp(&a.pref)
    };
    by_pref
        // `false < true`, so comparing b to a puts DP=1 first.
        .then_with(|| b.dont_preempt().cmp(&a.dont_preempt()))
        .then_with(|| a.addr.cmp(&b.addr))
}

/// The candidates ordered best-DF-first under preference-based election.
fn pref_ranked(candidates: &[DfCandidate], lowest: bool) -> Vec<IpAddr> {
    let mut ranked = candidates.to_vec();
    ranked.sort_by(|a, b| pref_wins(a, b, lowest));
    ranked.into_iter().map(|c| c.addr).collect()
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
        .map(|c| (hrw_weight(c.addr, d), c.addr))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    ranked.dedup_by_key(|(_, ip)| *ip);
    ranked.into_iter().map(|(_, ip)| ip).collect()
}

/// Elect the Designated Forwarder and its backup for one service instance,
/// dispatching on the algorithm the segment's PEs agreed on.
///
/// Alg 2 / Alg 3 (RFC 9785 preference) rank by preference, then the DP bit,
/// then address, so the DF is the winner and the backup is the runner-up.
/// Anything else falls back to
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
    let algs: Vec<u8> = candidates.iter().map(|c| c.alg).collect();
    let alg = negotiate_df_alg(&algs);
    match alg {
        DfElectionEc::ALG_PREF | DfElectionEc::ALG_PREF_LOWEST => {
            let ranked = pref_ranked(candidates, alg == DfElectionEc::ALG_PREF_LOWEST);
            return (ranked.first().copied(), ranked.get(1).copied());
        }
        DfElectionEc::ALG_HRW => {
            let ranked = hrw_ranked(candidates, esi, tag);
            return (ranked.first().copied(), ranked.get(1).copied());
        }
        _ => {}
    }
    let mut vteps: Vec<IpAddr> = candidates.iter().map(|c| c.addr).collect();
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
    let on_segment = candidates.iter().any(|c| c.addr == me);
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

/// The role this PE advertises for a single-active segment in one bridge
/// domain — the P/B bits of the per-EVI Ethernet A-D's Layer-2 Attributes
/// extended community (draft-ietf-bess-rfc7432bis §7.11.1).
///
/// Elected exactly like [`elan_df`], over the same candidates and with the
/// VNI as the Ethernet Tag, so the bit a remote PE reads and the BUM filter
/// this PE enforces can never disagree: the DF is Primary, the election's
/// runner-up is Backup, anyone else is neither.
///
/// A PE that is `holding`, or that is not in the candidate set at all (its
/// own Type-4 not selected yet), advertises **neither** bit. That is the
/// opposite of [`vpws_role`]'s "stay primary while the segment converges"
/// fallback, and deliberately so: under single-active a non-DF blocks the
/// access port in both directions, so attracting unicast to a PE that has
/// not joined the election is a blackhole, not a duplicate.
pub fn elan_role(
    candidates: &[DfCandidate],
    me: IpAddr,
    esi: &[u8; 10],
    vni: u32,
    holding: bool,
) -> VpwsRole {
    if holding || !candidates.iter().any(|c| c.addr == me) {
        return VpwsRole::NonDesignated;
    }
    let (df, backup) = elect_forwarders(candidates, esi, vni);
    if df == Some(me) {
        VpwsRole::Primary
    } else if backup == Some(me) {
        VpwsRole::Backup
    } else {
        VpwsRole::NonDesignated
    }
}

/// Order an Ethernet Segment nexthop group's members for the datapath.
/// `pairs` are `(advertising PE, member)`; the result is sorted by PE then
/// member so it is stable across recomputes, except that a single-active
/// segment's `primary` — the Designated Forwarder, the PE the segment's
/// MACs were learned from — leads (RFC 7432 §14.1.1): the datapath
/// forwards to slot 0 alone and holds the rest as the pre-installed backup
/// path. `None` (no MAC advertised yet, or an all-active segment) leaves
/// the sorted order; on a single-active segment that is the lowest PE,
/// which is moot until a MAC exists to forward.
pub fn order_es_members(
    mut pairs: Vec<(IpAddr, crate::rib::EsNhgMember)>,
    primary: Option<IpAddr>,
    backup: Option<IpAddr>,
) -> Vec<crate::rib::EsNhgMember> {
    pairs.sort();
    // Applied backup-first then primary-first, so the primary ends up ahead
    // of the backup however the two were chosen. Each pass is stable, so a
    // PE contributing several members keeps their relative order.
    for lead in [backup, primary] {
        let Some(lead) = lead else {
            continue;
        };
        let (front, back): (Vec<_>, Vec<_>) = pairs.into_iter().partition(|(pe, _)| *pe == lead);
        pairs = front.into_iter().chain(back).collect();
    }
    pairs.into_iter().map(|(_, m)| m).collect()
}

/// Why a single-active group's forwarder was chosen the way it was —
/// rendered by `show`, so an operator can tell a signalled answer from a
/// guess without reading the routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaSelectReason {
    /// Exactly one member advertised P=1 (rfc7432bis §7.11.1).
    Signalled,
    /// More than one member claimed P=1; the lowest address broke the tie.
    /// Both PEs believe they forward, which this PE cannot repair — it can
    /// only avoid installing two forwarding members and say so.
    Conflict,
    /// Nobody claimed P=1 but exactly one member advertised B=1, so the
    /// segment's own runner-up leads.
    BackupOnly,
    /// No member signals a role at all; the caller falls back to inferring
    /// the forwarder from which PE advertised the segment's MACs.
    Unsignalled,
}

impl SaSelectReason {
    /// Short display form.
    pub fn as_str(&self) -> &'static str {
        match self {
            SaSelectReason::Signalled => "signalled",
            SaSelectReason::Conflict => "conflict",
            SaSelectReason::BackupOnly => "backup-only",
            SaSelectReason::Unsignalled => "inferred",
        }
    }
}

/// The forwarder a remote ingress PE should use for a single-active segment
/// in one bridge domain, from the roles its members advertise.
///
/// `signals` is one entry per **eligible** member — the caller has already
/// dropped PEs whose per-ES A-D is gone (RFC 7432 §8.2 mass withdraw) or
/// that have no per-EVI A-D for this bridge domain — as
/// `(PE, Some((P, B)))`, or `(PE, None)` for a member carrying no Layer-2
/// Attributes EC.
///
/// Returns `(primary, backup, reason)`. `Unsignalled` means nobody told us
/// anything and the caller should fall back to its own inference; every
/// other reason is an answer. Two PEs claiming P=1 is a segment-level
/// misconfiguration that no ingress PE can repair — this one at least
/// installs a single forwarder deterministically (the lowest address) and
/// names the condition instead of silently forwarding to both.
pub fn select_sa_forwarder(
    signals: &[(IpAddr, Option<(bool, bool)>)],
) -> (Option<IpAddr>, Option<IpAddr>, SaSelectReason) {
    if signals.iter().all(|(_, bits)| bits.is_none()) {
        return (None, None, SaSelectReason::Unsignalled);
    }
    let mut primaries: Vec<IpAddr> = signals
        .iter()
        .filter(|(_, bits)| matches!(bits, Some((true, _))))
        .map(|(pe, _)| *pe)
        .collect();
    let mut backups: Vec<IpAddr> = signals
        .iter()
        .filter(|(_, bits)| matches!(bits, Some((false, true))))
        .map(|(pe, _)| *pe)
        .collect();
    primaries.sort();
    backups.sort();
    // A single backup is the segment's own runner-up, so it leads when no
    // primary is present — the alternative is slot 0 by address order, which
    // is a worse guess, not a safer one.
    let backup = (backups.len() == 1).then(|| backups[0]);
    match primaries.len() {
        0 => match backup {
            Some(b) => (Some(b), None, SaSelectReason::BackupOnly),
            None => (None, None, SaSelectReason::Unsignalled),
        },
        1 => (Some(primaries[0]), backup, SaSelectReason::Signalled),
        _ => (
            Some(primaries[0]),
            backup.filter(|b| *b != primaries[0]),
            SaSelectReason::Conflict,
        ),
    }
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
        .filter(|c| c.addr == me || (live.contains(&c.addr) && ad_evi.contains(&c.addr)))
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
    /// RFC 7432 §8.3 (MPLS): our ESI label sent with the port list (0 =
    /// none).
    pub esi_label: u32,
    /// RFC 7432 §8.3 (MPLS): the ESI-label replication slots sent — per
    /// `(bridge domain, peer PE, its BUM label, its ESI label for us)`.
    pub slots: std::collections::BTreeSet<(u32, IpAddr, u32, u32)>,
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
            .map(|ip| DfCandidate::new(*ip, DfElectionEc::ALG_DEFAULT, 0))
            .collect()
    }

    /// Preference candidates: every PE advertising Alg 2 with its own value.
    fn prefs(entries: &[(IpAddr, u16)]) -> Vec<DfCandidate> {
        entries
            .iter()
            .map(|(ip, p)| DfCandidate::new(*ip, DfElectionEc::ALG_PREF, *p))
            .collect()
    }

    /// Lowest-Preference (Alg 3) candidates.
    fn prefs_low(entries: &[(IpAddr, u16)]) -> Vec<DfCandidate> {
        entries
            .iter()
            .map(|(ip, p)| DfCandidate::new(*ip, DfElectionEc::ALG_PREF_LOWEST, *p))
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
        cands.push(DfCandidate::new(c, DfElectionEc::ALG_DEFAULT, 0));
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
        let cands: Vec<DfCandidate> = vec![
            DfCandidate::new(a, DfElectionEc::ALG_HRW, 0),
            DfCandidate::new(b, DfElectionEc::ALG_HRW, 0),
        ];
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
            DfCandidate::new(a, DfElectionEc::ALG_HRW, 0),
            DfCandidate::new(b, DfElectionEc::ALG_DEFAULT, 0),
        ];
        assert_eq!(elect_forwarders(&mixed, &ESI_T, 0).0, Some(a));
        assert_eq!(elect_forwarders(&mixed, &ESI_T, 1).0, Some(b));
    }

    /// Upgrade safety: every spelling that existed before the `algorithm`
    /// leaf grew preference arms advertises exactly what it advertised then.
    /// A PE that changed algorithm across an upgrade would break the RFC
    /// 8584 unanimity check against its not-yet-upgraded peers and drop the
    /// whole segment to carving, moving the DF as it went.
    #[test]
    fn a_preference_value_still_overrides_the_legacy_algorithm_arms() {
        // `algorithm hrw` alone: Alg 1, unchanged.
        let hrw = EthernetSegment {
            df_algorithm: Some(DfAlgorithm::Hrw),
            ..Default::default()
        };
        assert_eq!(hrw.df_election_ec().df_alg, DfElectionEc::ALG_HRW);
        // `algorithm hrw` PLUS a preference: Alg 2 carrying that bid — the
        // pre-upgrade meaning of this combination.
        let hrw_with_pref = EthernetSegment {
            df_algorithm: Some(DfAlgorithm::Hrw),
            df_preference: Some(7),
            ..Default::default()
        };
        assert_eq!(
            hrw_with_pref.df_election_ec().df_alg,
            DfElectionEc::ALG_PREF
        );
        assert_eq!(hrw_with_pref.df_election_ec().pref, 7);
        // Same for the explicit `algorithm default` spelling.
        let carving_with_pref = EthernetSegment {
            df_algorithm: Some(DfAlgorithm::Default),
            df_preference: Some(9),
            ..Default::default()
        };
        assert_eq!(
            carving_with_pref.df_election_ec().df_alg,
            DfElectionEc::ALG_PREF
        );
        assert_eq!(carving_with_pref.df_election_ec().pref, 9);
        // Preference alone: Alg 2 with that bid.
        let bare = EthernetSegment {
            df_preference: Some(7),
            ..Default::default()
        };
        assert_eq!(bare.df_election_ec().df_alg, DfElectionEc::ALG_PREF);
        assert_eq!(bare.df_election_ec().pref, 7);
        // The new arms name the algorithm, so a value beside them selects
        // between Alg 2 and Alg 3 instead of overriding them.
        let lowest = EthernetSegment {
            df_algorithm: Some(DfAlgorithm::LowestPreference),
            df_preference: Some(100),
            ..Default::default()
        };
        assert_eq!(
            lowest.df_election_ec().df_alg,
            DfElectionEc::ALG_PREF_LOWEST
        );
        assert_eq!(lowest.df_election_ec().pref, 100);
        assert_eq!(
            DfAlgorithm::from_keyword("lowest-preference"),
            Some(DfAlgorithm::LowestPreference)
        );
        assert_eq!(DfAlgorithm::from_keyword("nonsense"), None);
    }

    /// The DP bit is a tie-break, not non-revertive operation: it ranks a PE
    /// ahead of one that does not set it, and two PEs that both set it at
    /// equal preference still fall through to the address — so the
    /// lower-address PE reclaims the role on recovery. RFC 9785 §4.3
    /// non-revertive behaviour needs the operational-preference adjustment
    /// this phase does not implement, and no documentation may read as if it
    /// did.
    #[test]
    fn dont_preempt_does_not_by_itself_make_the_election_non_revertive() {
        let [a, b, _] = pes();
        let dp = DfElectionEc::CAP_DONT_PREEMPT;
        // The incumbent keeps the role only while the returning PE leaves
        // the bit clear.
        let one_sided = vec![
            DfCandidate::new(a, DfElectionEc::ALG_PREF, 32767),
            DfCandidate::new(b, DfElectionEc::ALG_PREF, 32767).with_caps(dp),
        ];
        assert_eq!(elect_forwarders(&one_sided, &ESI_T, 0).0, Some(b));
        // Both configured the same way — the usual case — and the lower
        // address takes it back.
        let both = vec![
            DfCandidate::new(a, DfElectionEc::ALG_PREF, 32767).with_caps(dp),
            DfCandidate::new(b, DfElectionEc::ALG_PREF, 32767).with_caps(dp),
        ];
        assert_eq!(elect_forwarders(&both, &ESI_T, 0).0, Some(a));
    }

    /// RFC 9785 §3: a preference-based segment with no configured value bids
    /// the mandatory default of 32767, not 0 — bidding 0 would rank this PE
    /// below every peer that took the default. The DP bit rides only under
    /// those algorithms.
    #[test]
    fn preference_defaults_to_the_rfc_9785_midpoint() {
        let es = EthernetSegment {
            df_algorithm: Some(DfAlgorithm::Preference),
            ..Default::default()
        };
        let ec = es.df_election_ec();
        assert_eq!(ec.df_alg, DfElectionEc::ALG_PREF);
        assert_eq!(ec.pref, DfElectionEc::PREF_DEFAULT);
        assert!(!ec.dont_preempt());

        let low = EthernetSegment {
            df_algorithm: Some(DfAlgorithm::LowestPreference),
            dont_preempt: true,
            ac_df: true,
            ..Default::default()
        };
        let ec = low.df_election_ec();
        assert_eq!(ec.df_alg, DfElectionEc::ALG_PREF_LOWEST);
        assert_eq!(ec.pref, DfElectionEc::PREF_DEFAULT);
        assert!(ec.dont_preempt() && ec.ac_df());

        // Carving never advertises a preference or the DP bit — the bit is
        // defined as a preference tie-break, so it would mean nothing on the
        // wire here. (With a `preference` value this segment would not be
        // carving at all: see
        // `a_preference_value_still_overrides_the_legacy_algorithm_arms`.)
        let carving = EthernetSegment {
            df_algorithm: Some(DfAlgorithm::Default),
            dont_preempt: true,
            ..Default::default()
        };
        let ec = carving.df_election_ec();
        assert_eq!(ec.df_alg, DfElectionEc::ALG_DEFAULT);
        assert_eq!(ec.pref, 0);
        assert!(!ec.dont_preempt());
    }

    /// RFC 9785 §4.1 ranking, in order: preference, then the DP bit, then
    /// the lowest address. Each step is proven by a case the previous step
    /// cannot decide, and Alg 3 reverses only the first.
    #[test]
    fn preference_ranks_pref_then_dp_then_address() {
        let [a, b, c] = pes();
        // Preference beats address order: c bids highest despite the highest
        // address, and the runner-up (backup DF) is the next best bid.
        let cands = prefs(&[(a, 100), (b, 200), (c, 300)]);
        assert_eq!(elect_forwarders(&cands, &ESI_T, 0), (Some(c), Some(b)));
        // ... for every tag, unlike carving.
        assert_eq!(elect_forwarders(&cands, &ESI_T, 7).0, Some(c));
        // Alg 3 reverses the preference comparison alone.
        let low = prefs_low(&[(a, 100), (b, 200), (c, 300)]);
        assert_eq!(elect_forwarders(&low, &ESI_T, 0), (Some(a), Some(b)));
        // Equal preference: the PE asking not to be preempted wins, even
        // though its address is higher.
        let tie = vec![
            DfCandidate::new(a, DfElectionEc::ALG_PREF, 32767),
            DfCandidate::new(b, DfElectionEc::ALG_PREF, 32767)
                .with_caps(DfElectionEc::CAP_DONT_PREEMPT),
        ];
        assert_eq!(elect_forwarders(&tie, &ESI_T, 0), (Some(b), Some(a)));
        // Without the bit the same tie falls to the lowest address.
        let tie = prefs(&[(a, 32767), (b, 32767)]);
        assert_eq!(elect_forwarders(&tie, &ESI_T, 0), (Some(a), Some(b)));
        // An unrelated capability (AC-DF) is not a tie-break.
        let tie = vec![
            DfCandidate::new(a, DfElectionEc::ALG_PREF, 32767),
            DfCandidate::new(b, DfElectionEc::ALG_PREF, 32767).with_caps(DfElectionEc::CAP_AC_DF),
        ];
        assert_eq!(elect_forwarders(&tie, &ESI_T, 0).0, Some(a));
        // A segment split between Alg 2 and Alg 3 is a disagreed segment:
        // RFC 8584 negotiation drops the whole thing to carving, where tag 0
        // is the lowest address regardless of the bids.
        let mixed = vec![
            DfCandidate::new(a, DfElectionEc::ALG_PREF, 100),
            DfCandidate::new(b, DfElectionEc::ALG_PREF_LOWEST, 300),
        ];
        assert_eq!(elect_forwarders(&mixed, &ESI_T, 0).0, Some(a));
        assert_eq!(elect_forwarders(&mixed, &ESI_T, 1).0, Some(b));
    }

    /// The E-LAN role advertised on the per-EVI A-D is the same election the
    /// BUM filter uses, so the bit a remote reads and the filter this PE
    /// enforces cannot disagree: the DF is Primary, the runner-up is Backup,
    /// everyone else advertises neither bit.
    #[test]
    fn elan_role_tracks_the_same_election_as_the_bum_filter() {
        let [a, b, c] = pes();
        let cands = carving(&[a, b, c]);
        // Carving on tag 0 elects a, so b (ordinal 1) is its backup.
        assert_eq!(elan_role(&cands, a, &ESI_T, 0, false), VpwsRole::Primary);
        assert_eq!(elan_role(&cands, b, &ESI_T, 0, false), VpwsRole::Backup);
        assert_eq!(
            elan_role(&cands, c, &ESI_T, 0, false),
            VpwsRole::NonDesignated
        );
        // Whoever is Primary here is exactly who `elan_df` lets forward BUM.
        for (pe, role) in [
            (a, VpwsRole::Primary),
            (b, VpwsRole::Backup),
            (c, VpwsRole::NonDesignated),
        ] {
            assert_eq!(
                elan_df(&cands, pe, &ESI_T, 0, false),
                role == VpwsRole::Primary
            );
        }
        // A different bridge domain carves differently, and the role follows.
        assert_eq!(elan_role(&cands, b, &ESI_T, 1, false), VpwsRole::Primary);
        assert_eq!(elan_role(&cands, c, &ESI_T, 1, false), VpwsRole::Backup);
        // Preference pins one PE across every bridge domain.
        let pref = prefs(&[(a, 10), (b, 200), (c, 30)]);
        for vni in [0, 1, 4242] {
            assert_eq!(elan_role(&pref, b, &ESI_T, vni, false), VpwsRole::Primary);
            assert_eq!(elan_role(&pref, c, &ESI_T, vni, false), VpwsRole::Backup);
            assert_eq!(
                elan_role(&pref, a, &ESI_T, vni, false),
                VpwsRole::NonDesignated
            );
        }
    }

    /// A PE that has not joined the election advertises NEITHER bit — the
    /// opposite of `vpws_role`'s "stay primary while the segment converges"
    /// fallback. Under single-active a non-DF blocks its access port in both
    /// directions, so attracting a remote's unicast to a PE that is not
    /// forwarding is a blackhole, where the VPWS fallback would only risk a
    /// duplicate.
    #[test]
    fn elan_role_is_neither_bit_while_this_pe_is_out_of_the_election() {
        let [a, b, _] = pes();
        let cands = carving(&[a, b]);
        // Holding (startup delay): our Type-4 is suppressed, so we are in
        // nobody's candidate set and must not be used.
        assert_eq!(
            elan_role(&cands, a, &ESI_T, 0, true),
            VpwsRole::NonDesignated
        );
        assert_eq!(
            vpws_role(EsRedundancyMode::SingleActive, &cands, a, &ESI_T, 0),
            VpwsRole::Primary
        );
        // Not in the candidate set at all (our own Type-4 not selected yet).
        let others = carving(&[b]);
        assert_eq!(
            elan_role(&others, a, &ESI_T, 0, false),
            VpwsRole::NonDesignated
        );
        // An empty segment elects nobody.
        assert_eq!(elan_role(&[], a, &ESI_T, 0, false), VpwsRole::NonDesignated);
        // A lone PE is Primary with no backup behind it.
        let alone = carving(&[a]);
        assert_eq!(elan_role(&alone, a, &ESI_T, 0, false), VpwsRole::Primary);
    }

    /// The config keyword round-trips, and only `l2-attr` signals.
    #[test]
    fn role_signaling_keyword_round_trip() {
        assert_eq!(
            RoleSignaling::from_keyword("l2-attr"),
            RoleSignaling::L2Attr
        );
        assert_eq!(
            RoleSignaling::from_keyword("inferred"),
            RoleSignaling::Inferred
        );
        assert_eq!(
            RoleSignaling::from_keyword("nonsense"),
            RoleSignaling::Inferred
        );
        assert_eq!(RoleSignaling::default(), RoleSignaling::Inferred);
        assert!(RoleSignaling::L2Attr.signals());
        assert!(!RoleSignaling::Inferred.signals());
        assert_eq!(RoleSignaling::L2Attr.as_str(), "l2-attr");
        assert_eq!(RoleSignaling::Inferred.as_str(), "inferred");
        // The bits the two signalling roles put on the wire.
        assert_eq!(VpwsRole::Primary.bits(), (true, false));
        assert_eq!(VpwsRole::Backup.bits(), (false, true));
        assert_eq!(VpwsRole::NonDesignated.bits(), (false, false));
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
            DfCandidate::new(a, DfElectionEc::ALG_DEFAULT, 0),
            DfCandidate::new(b, DfElectionEc::ALG_DEFAULT, 0),
            DfCandidate::new(c, DfElectionEc::ALG_DEFAULT, 0),
        ];
        // Tag 1 carves to ordinal 1 = b over the full set.
        assert_eq!(elect_forwarders(&cands, &ESI_T, 1).0, Some(b));
        let live: BTreeSet<IpAddr> = [b, c].into_iter().collect();
        // b's per-EVI A-D for this EVI is gone; c's is up.
        let ad_evi: BTreeSet<IpAddr> = [c].into_iter().collect();
        let narrowed = ac_df_filter(&cands, a, &live, &ad_evi);
        assert_eq!(
            narrowed.iter().map(|c| c.addr).collect::<Vec<_>>(),
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
            narrowed.iter().map(|c| c.addr).collect::<Vec<_>>(),
            vec![a, b]
        );
        // The local PE is never filtered by its own (originated) routes.
        let narrowed = ac_df_filter(&cands, a, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(narrowed.iter().map(|c| c.addr).collect::<Vec<_>>(), vec![a]);
    }

    /// A remote ingress PE picks the forwarder from the roles the segment's
    /// PEs advertise: exactly one P=1 is the answer, the lone B=1 is the
    /// prepared standby, and nobody signalling means fall back to inference.
    #[test]
    fn remote_selects_the_signalled_forwarder() {
        use SaSelectReason::*;
        let [a, b, c] = pes();
        let p = Some((true, false));
        let bk = Some((false, true));
        let neither = Some((false, false));

        // The ordinary case: one primary, one backup, one neither.
        assert_eq!(
            select_sa_forwarder(&[(a, p), (b, bk), (c, neither)]),
            (Some(a), Some(b), Signalled)
        );
        // Order of the input does not matter.
        assert_eq!(
            select_sa_forwarder(&[(c, neither), (b, bk), (a, p)]),
            (Some(a), Some(b), Signalled)
        );
        // No backup advertised: a primary alone is still an answer.
        assert_eq!(
            select_sa_forwarder(&[(a, p), (b, neither)]),
            (Some(a), None, Signalled)
        );
        // Two PEs advertising B=1 is not a usable standby — it is ambiguous,
        // so no slot-1 preference is expressed.
        assert_eq!(
            select_sa_forwarder(&[(a, p), (b, bk), (c, bk)]),
            (Some(a), None, Signalled)
        );
    }

    /// Nobody claiming primary is not the same as nobody signalling: the
    /// segment's own runner-up leads, because the alternative is slot 0 by
    /// address order — a worse guess, not a safer one. With no signal at all
    /// the caller is told to fall back to its MAC-origination inference.
    #[test]
    fn remote_falls_back_only_when_nothing_is_signalled() {
        use SaSelectReason::*;
        let [a, b, c] = pes();
        let bk = Some((false, true));
        let neither = Some((false, false));

        assert_eq!(
            select_sa_forwarder(&[(a, neither), (b, bk)]),
            (Some(b), None, BackupOnly)
        );
        // Every member on the segment but none of them selectable: there is
        // nothing to forward to, and saying so beats picking one at random.
        assert_eq!(
            select_sa_forwarder(&[(a, neither), (b, neither)]),
            (None, None, Unsignalled)
        );
        // No Layer-2 Attributes EC anywhere — a segment whose PEs run
        // `role-signaling inferred`, or an older release.
        assert_eq!(
            select_sa_forwarder(&[(a, None), (b, None), (c, None)]),
            (None, None, Unsignalled)
        );
        assert_eq!(select_sa_forwarder(&[]), (None, None, Unsignalled));
        // A mixed segment (one PE upgraded, one not) still has an answer
        // from the PE that does signal.
        assert_eq!(
            select_sa_forwarder(&[(a, None), (b, Some((true, false)))]),
            (Some(b), None, Signalled)
        );
    }

    /// Two PEs both claiming primary is a segment-level misconfiguration no
    /// ingress PE can repair. This one installs a single forwarder
    /// deterministically — the lowest address, so every remote PE picks the
    /// same one — and reports the condition instead of forwarding to both.
    #[test]
    fn remote_tie_breaks_a_double_primary_and_says_so() {
        use SaSelectReason::*;
        let [a, b, c] = pes();
        let p = Some((true, false));
        assert_eq!(
            select_sa_forwarder(&[(b, p), (a, p), (c, Some((false, true)))]),
            (Some(a), Some(c), Conflict)
        );
        // A PE claiming both bits counts as a primary claim; it is never
        // also the backup.
        assert_eq!(
            select_sa_forwarder(&[(a, p), (b, Some((true, true)))]),
            (Some(a), None, Conflict)
        );
        assert_eq!(Conflict.as_str(), "conflict");
        assert_eq!(Signalled.as_str(), "signalled");
        assert_eq!(BackupOnly.as_str(), "backup-only");
        assert_eq!(Unsignalled.as_str(), "inferred");
    }

    /// The group is ordered primary, then backup, then the rest — the
    /// datapath forwards to slot 0 alone under single-active and holds the
    /// remainder as the pre-installed backup path, so slot 1 must be the PE
    /// the segment nominated rather than whichever address sorts next.
    #[test]
    fn group_orders_primary_then_backup_then_the_rest() {
        use crate::rib::EsNhgMember;
        let [a, b, c] = pes();
        let pairs = vec![
            (a, EsNhgMember::Vxlan(a)),
            (b, EsNhgMember::Vxlan(b)),
            (c, EsNhgMember::Vxlan(c)),
        ];
        assert_eq!(
            order_es_members(pairs.clone(), Some(c), Some(b)),
            vec![
                EsNhgMember::Vxlan(c),
                EsNhgMember::Vxlan(b),
                EsNhgMember::Vxlan(a)
            ]
        );
        // A backup with no primary still leads.
        assert_eq!(
            order_es_members(pairs.clone(), None, Some(c)),
            vec![
                EsNhgMember::Vxlan(c),
                EsNhgMember::Vxlan(a),
                EsNhgMember::Vxlan(b)
            ]
        );
        // A backup that is no longer a member changes nothing.
        let survivors: Vec<_> = pairs.into_iter().filter(|(pe, _)| *pe != b).collect();
        assert_eq!(
            order_es_members(survivors, Some(c), Some(b)),
            vec![EsNhgMember::Vxlan(c), EsNhgMember::Vxlan(a)]
        );
    }

    /// The single-active group leads with the MAC advertiser and keeps the
    /// rest, sorted, as the backup path; without a primary (all-active, or
    /// no MAC yet) the order is the sorted one.
    #[test]
    fn single_active_group_leads_with_the_primary() {
        use crate::rib::EsNhgMember;
        let [a, b, c] = pes();
        let pairs = vec![
            (c, EsNhgMember::Vxlan(c)),
            (a, EsNhgMember::Vxlan(a)),
            (b, EsNhgMember::Vxlan(b)),
        ];
        assert_eq!(
            order_es_members(pairs.clone(), None, None),
            vec![
                EsNhgMember::Vxlan(a),
                EsNhgMember::Vxlan(b),
                EsNhgMember::Vxlan(c)
            ]
        );
        assert_eq!(
            order_es_members(pairs.clone(), Some(b), None),
            vec![
                EsNhgMember::Vxlan(b),
                EsNhgMember::Vxlan(a),
                EsNhgMember::Vxlan(c)
            ]
        );
        // A primary that is not (any longer) a member — its per-ES A-D
        // withdrawn — changes nothing: the survivors lead in sorted order,
        // which is the failover.
        let survivors: Vec<_> = pairs.into_iter().filter(|(pe, _)| *pe != b).collect();
        assert_eq!(
            order_es_members(survivors, Some(b), None),
            vec![EsNhgMember::Vxlan(a), EsNhgMember::Vxlan(c)]
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
        let cands: Vec<DfCandidate> = vec![DfCandidate::new(a, 0, 0), DfCandidate::new(b, 0, 0)];
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
