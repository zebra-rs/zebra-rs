use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use ipnet::{Ipv4Net, Ipv6Net};

use super::Lsdb;
use super::version::{OspfVersion, Ospfv2};
use crate::context::Timer;

pub const AREA0: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

/// RFC 3101 §2.2 NSSA translator-role configuration knob for an
/// NSSA ABR. `Candidate` is the default and triggers election among
/// the area's ABRs via the Nt-bit. `Always` forces translation
/// unconditionally; `Never` disables it. Storage-only in phase 1.
#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum NssaTranslatorRole {
    #[default]
    Candidate,
    Always,
    Never,
}

impl NssaTranslatorRole {
    pub fn from_yang(s: &str) -> Option<Self> {
        match s {
            "candidate" => Some(Self::Candidate),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

/// Discriminant for [`AreaType`]. Drives the option-bit (N/E)
/// behavior on Hello/DBD; the sub-knobs in [`AreaType`] only matter
/// for `Stub` and `Nssa`.
#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum AreaTypeKind {
    #[default]
    Normal,
    Stub,
    Nssa,
}

impl AreaTypeKind {
    pub fn from_yang(s: &str) -> Option<Self> {
        match s {
            "normal" => Some(Self::Normal),
            "stub" => Some(Self::Stub),
            "nssa" => Some(Self::Nssa),
            _ => None,
        }
    }
}

/// Per-area type with its sub-knobs.
///
/// `kind` selects the area flavor; the remaining fields are
/// configuration leaves that only take effect for matching flavors:
/// - `no_summary` — totally-stubby / totally-NSSA: drop Type-3
///   Summary at the ABR. Applies to `Stub` and `Nssa`.
/// - `nssa_default_originate` — ABR originates a default Type-7
///   into the NSSA area. Applies to `Nssa` only.
/// - `nssa_suppress_fa` — zero the forwarding address when
///   translating Type-7 to Type-5 (RFC 3101 §2.6). Applies to
///   `Nssa` only.
/// - `nssa_translator_role` — RFC 3101 §2.2 election behavior.
///   Applies to `Nssa` only.
///
/// `kind` plus the N-bit / E-bit negotiation are wired up; the
/// remaining knobs are stored but not yet acted on.
#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub struct AreaType {
    pub kind: AreaTypeKind,
    pub no_summary: bool,
    pub nssa_default_originate: bool,
    pub nssa_suppress_fa: bool,
    pub nssa_translator_role: NssaTranslatorRole,
}

/// E1 vs E2 metric-type for AS-External / NSSA-AS-External LSAs.
/// E1 (Type 1): the receiver adds SPF(originator) cost to LSA metric.
/// E2 (Type 2, default): receiver uses LSA metric alone (SPF cost is
/// the tiebreak only). Encoded on the wire as the E-bit (0x80) of the
/// LSA body's `ext_and_resvd` / `ext_and_tos` byte.
#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum ExternalMetricType {
    Type1,
    #[default]
    Type2,
}

impl ExternalMetricType {
    /// `"type-1"` / `"type-2"` from the YANG enum.
    pub fn from_yang(s: &str) -> Option<Self> {
        match s {
            "type-1" => Some(Self::Type1),
            "type-2" => Some(Self::Type2),
            _ => None,
        }
    }

    pub fn is_type_2(self) -> bool {
        matches!(self, Self::Type2)
    }
}

/// Per-source-proto redistribution knobs. Today only `connected`
/// is wired (RIB subscription lives in `inst.rs`); extending to
/// `static` is just adding another `Option<RedistEntry>` field
/// here plus a matching YANG container + callback.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedistEntry {
    /// External metric to advertise. Default 20 (matches FRR).
    pub metric: u32,
    /// E1 (Type 1) vs E2 (Type 2). Default E2.
    pub metric_type: ExternalMetricType,
}

impl RedistEntry {
    pub const DEFAULT_METRIC: u32 = 20;
}

/// Per-area redistribute configuration. Sibling per source proto.
/// `Some(entry)` = redistribute that source into this area's
/// Type-7 LSAs; `None` = don't.
#[derive(Debug, Default, Clone, Copy)]
pub struct AreaRedistribute {
    pub connected: Option<RedistEntry>,
}

impl AreaType {
    /// True for any flavor of stub or NSSA — AS-External LSAs are
    /// dropped at the area boundary.
    pub fn is_stub_or_nssa(self) -> bool {
        !matches!(self.kind, AreaTypeKind::Normal)
    }

    /// True only for NSSA-flavored areas.
    pub fn is_nssa(self) -> bool {
        matches!(self.kind, AreaTypeKind::Nssa)
    }

    /// True when this area accepts and floods Type-5 AS-External
    /// LSAs (RFC 2328 §3.6). False for stub and NSSA.
    pub fn accepts_as_external(self) -> bool {
        matches!(self.kind, AreaTypeKind::Normal)
    }

    /// E-bit value advertised in the OSPF Options field. Per
    /// RFC 2328 §A.2 / RFC 3101 §2.5 the E-bit must be clear on
    /// stub and NSSA links and set on normal links. Hello/DBD
    /// emit reads this; recv compares against the neighbor's bit
    /// and drops mismatches.
    pub fn e_bit(self) -> bool {
        self.accepts_as_external()
    }

    /// N-bit value advertised in the OSPF Options field. Per
    /// RFC 3101 §2.5 the N-bit must be set on NSSA links and
    /// clear elsewhere. Mismatch with a neighbor's bit on Hello
    /// receipt drops the packet.
    pub fn n_bit(self) -> bool {
        self.is_nssa()
    }
}

/// Map of OSPF area-id → `OspfArea<V>`.
///
/// Generic over `V: OspfVersion` so v3's areas will carry
/// `Lsdb<Ospfv3>` when the v3 instance materializes. Default
/// `V = Ospfv2` keeps existing callers resolving to the v2 shape.
pub struct OspfAreaMap<V: OspfVersion = Ospfv2>(BTreeMap<Ipv4Addr, OspfArea<V>>);

impl<V: OspfVersion> OspfAreaMap<V> {
    pub fn new() -> Self {
        let mut areas = Self(BTreeMap::new());
        areas.fetch(Ipv4Addr::UNSPECIFIED);
        areas
    }

    pub fn get(&self, id: Ipv4Addr) -> Option<&OspfArea<V>> {
        self.0.get(&id)
    }

    pub fn get_mut(&mut self, id: Ipv4Addr) -> Option<&mut OspfArea<V>> {
        self.0.get_mut(&id)
    }

    pub fn fetch(&mut self, area_id: Ipv4Addr) -> &mut OspfArea<V> {
        self.0
            .entry(area_id)
            .or_insert_with(|| OspfArea::new(area_id))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Ipv4Addr, &OspfArea<V>)> {
        self.0.iter()
    }
}

impl<V: OspfVersion> Default for OspfAreaMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OspfArea<V: OspfVersion = Ospfv2> {
    // OSPF area id.  This value may be treated as IPv4 address.
    pub id: Ipv4Addr,

    // Area type (Normal, Stub, NSSA) and its sub-knobs.
    pub area_type: AreaType,

    // Set of interfaces belongs to this area.
    pub links: BTreeSet<u32>,

    // LSDB of this area.
    pub lsdb: Lsdb<V>,

    // SPF calculation timer.
    pub spf_timer: Option<Timer>,

    // Per-area adaptive SPF-throttle backoff state (IOS-XR style).
    // Fed the `spf-interval` bounds each time a run is scheduled; the
    // wait grows initial -> secondary -> ... -> maximum within a burst
    // and resets after a quiet period. Isolated per area so a churning
    // area backs off without slowing a stable one.
    pub spf_throttle: crate::throttle::Throttle,

    // SPF in-flight gate: true while a SPF run for this area is
    // executing. New `Message::SpfCalc(area_id)` events that arrive
    // during a run set `spf_pending` instead of starting a second
    // SPF; the completion path re-fires exactly one follow-up.
    pub spf_inflight: bool,
    pub spf_pending: bool,

    /// Per-area redistribute config (NSSA Type-7 source toggles).
    /// Only consulted when `area_type` is NSSA; storage is
    /// area-typeless because operators may toggle the redistribute
    /// knob before flipping `area-type` and the value should
    /// survive the order swap.
    pub redistribute: AreaRedistribute,

    /// Prefixes of redistributed connected routes that this router
    /// has originated as Type-7 LSAs into this area. Keyed by
    /// `prefix.network()`. Used to flush the matching Type-7s when
    /// the redistribute knob is removed or the area leaves NSSA.
    /// Populated/maintained by the RIB RouteAdd / RouteDel handlers
    /// in `inst.rs`.
    pub redist_connected_originated: BTreeSet<Ipv4Net>,

    /// v6 sibling of `redist_connected_originated`: prefixes of
    /// redistributed connected routes this router has originated as
    /// OSPFv3 NSSA-LSAs (Type-7) into this area. The generic
    /// `OspfArea<V>` carries both the v4 and v6 sets; a v2 instance
    /// only touches the v4 one and a v3 instance only the v6 one.
    pub redist_connected_originated_v6: BTreeSet<Ipv6Net>,

    /// RFC 3101 §3 NSSA Type-7→Type-5 translator state. ls_ids of
    /// Type-7 LSAs in this area for which we have translated a
    /// Type-5 into `lsdb_as`. The translated Type-5's adv_router is
    /// our router-id by construction, so ls_id alone is enough to
    /// identify the pair. Maintained by
    /// `Ospf::nssa_translate_resync` in `inst.rs`.
    pub nssa_translated: BTreeSet<Ipv4Addr>,

    /// Router-IDs of ASBRs for which this ABR has originated a
    /// Type-4 Summary-ASBR LSA into this area. Flushed when the
    /// ABR loses connectivity to the ASBR or the area.
    pub asbr_summaries_originated: BTreeSet<Ipv4Addr>,

    /// RFC 2328 §12.4.3 address ranges configured on this area
    /// (`area <id> range <prefix>`), consulted by the ABR summary
    /// desired-set computation: intra-area routes of this area that
    /// fall inside a range are folded into one aggregate (largest
    /// component metric, or the configured cost) or suppressed
    /// entirely (`not-advertise`). The generic `OspfArea<V>` carries
    /// both the v4 and v6 maps; each version touches its own.
    pub ranges: BTreeMap<Ipv4Net, AreaRange>,
    /// v6 sibling of `ranges` (OSPFv3 Inter-Area-Prefix aggregation).
    pub ranges_v6: BTreeMap<Ipv6Net, AreaRange>,

    /// RFC 2328 §15 virtual links configured *through* this area
    /// (`area <id> virtual-link <router-id>`) — this area is the
    /// transit area; the key is the remote ABR's router-id. The VL
    /// itself is a synthetic area-0 interface materialized by
    /// `Ospf::vl_reconcile` once the transit-area SPF finds the peer
    /// reachable. v2-only today.
    pub virtual_links: BTreeMap<Ipv4Addr, VirtualLinkConfig>,
}

/// Instance-level `default-information originate` configuration.
/// Without `always`, the Type-5 default is originated only while a
/// non-OSPF default route sits in the RIB (tracked via the RIB
/// default watch); `always` originates unconditionally. Metric
/// defaults to 10 (FRR parity) with E2 semantics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DefaultOriginate {
    pub always: bool,
    pub metric: u32,
    pub metric_type: ExternalMetricType,
}

impl Default for DefaultOriginate {
    fn default() -> Self {
        Self {
            always: false,
            metric: 10,
            metric_type: ExternalMetricType::default(),
        }
    }
}

/// One configured `area <id> range <prefix>` entry.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AreaRange {
    /// Suppress the aggregate as well — the whole range (components
    /// and summary) stays hidden from the other areas.
    pub not_advertise: bool,
    /// Advertise the aggregate at this fixed cost instead of the
    /// largest component metric.
    pub cost: Option<u32>,
}

/// One configured `area <id> virtual-link <router-id>` entry
/// (RFC 2328 §15). Interval and authentication overrides mirror the
/// per-interface leaves; `None`/empty falls back to the defaults the
/// synthetic link's `LinkConfig` already carries (hello 10s / dead
/// 40s / retransmit 5s, Null auth). Copied onto the synthetic link
/// by `Ospf::vl_reconcile` on every create/refresh.
#[derive(Debug, Default, Clone)]
pub struct VirtualLinkConfig {
    pub hello_interval: Option<u16>,
    pub dead_interval: Option<u32>,
    pub retransmit_interval: Option<u16>,
    /// RFC 2328 §D authentication mode (null / simple /
    /// message-digest), same semantics as the per-interface leaf.
    pub auth_mode: Option<super::link::OspfAuthMode>,
    /// Simple-password key, zero-padded to the 8-octet wire field.
    pub auth_key: Option<[u8; 8]>,
    /// MD5 keys keyed by key-id (`message-digest-key <id> md5 <key>`).
    pub crypto_keys: BTreeMap<u8, super::link::AuthKey>,
    /// RFC 8177 key-chain name; supersedes `crypto_keys` when set.
    pub key_chain: Option<String>,
}

impl<V: OspfVersion> OspfArea<V> {
    pub fn new(id: Ipv4Addr) -> Self {
        Self {
            id,
            area_type: AreaType::default(),
            links: BTreeSet::new(),
            lsdb: Lsdb::<V>::new(),
            spf_timer: None,
            spf_throttle: crate::throttle::Throttle::default(),
            spf_inflight: false,
            spf_pending: false,
            redistribute: AreaRedistribute::default(),
            redist_connected_originated: BTreeSet::new(),
            redist_connected_originated_v6: BTreeSet::new(),
            nssa_translated: BTreeSet::new(),
            asbr_summaries_originated: BTreeSet::new(),
            ranges: BTreeMap::new(),
            ranges_v6: BTreeMap::new(),
            virtual_links: BTreeMap::new(),
        }
    }
}
