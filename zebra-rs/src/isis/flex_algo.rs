use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use isis_packet::neigh::IsisSubTlv as NeighSubTlv;
use isis_packet::{
    Algo, ExtAdminGroup, FadSubTlv, IsisSubAdminGrp, IsisSubAsla, IsisSubFadExcludeAg,
    IsisSubFadExcludeSrlg, IsisSubFadFlags, IsisSubFadIncludeAllAg, IsisSubFadIncludeAnyAg,
    IsisSubFlexAlgoDef, IsisSubPrefixSid, SidLabelValue,
};

use crate::config::{Args, ConfigOp};

use super::Isis;
use super::affinity_map::AffinityMap;
use super::srlg::SrlgGroup;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FadMetricType {
    Igp,                // FAD Metric-Type 0
    MinUnidirLinkDelay, // FAD Metric-Type 1 (RFC 8570)
    TeDefault,          // FAD Metric-Type 2 (RFC 5305)
}

impl FadMetricType {
    /// FAD Sub-TLV Metric-Type code (RFC 9350 §5.1, IANA registry).
    /// Single source of truth for the on-the-wire byte, consumed by
    /// `build_fad_subs` at LSP-build time.
    pub fn wire(self) -> u8 {
        match self {
            Self::Igp => 0,
            Self::MinUnidirLinkDelay => 1,
            Self::TeDefault => 2,
        }
    }
}

impl FromStr for FadMetricType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "igp" => Ok(Self::Igp),
            "min-unidir-link-delay" => Ok(Self::MinUnidirLinkDelay),
            "te-default" => Ok(Self::TeDefault),
            _ => bail!("unknown flex-algo metric-type: {s}"),
        }
    }
}

/// One Flexible Algorithm Definition (RFC 9350) as configured on this
/// router. Mirrors the YANG schema under /router/isis/flex-algo.
#[derive(Debug, Default, Clone)]
pub struct FlexAlgoEntry {
    pub delete: bool,
    pub advertise_definition: Option<bool>,
    pub metric_type: Option<FadMetricType>,
    pub priority: Option<u8>,
    pub prefix_metric: Option<bool>,
    pub dataplane_sr_mpls: Option<bool>,
    pub dataplane_srv6: Option<bool>,
    pub dataplane_ip: Option<bool>,
    pub include_any: BTreeSet<String>,
    pub include_all: BTreeSet<String>,
    pub exclude_any: BTreeSet<String>,
    pub srlg_exclude: BTreeSet<String>,
    pub ti_lfa: bool,
}

pub struct FlexAlgoConfig {
    pub config: BTreeMap<u8, FlexAlgoEntry>,
    pub cache: BTreeMap<u8, FlexAlgoEntry>,
    builder: ConfigBuilder,
}

impl Default for FlexAlgoConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FlexAlgoConfig {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: config_builder(),
        }
    }

    /// Stage one leaf update into the pending cache. Mirrors
    /// `StaticConfig::exec` in rib/static/config.rs — pure staging,
    /// no side effects until `commit` is called.
    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing flex-algo config handler";
        const ALGO_ERR: &str = "missing flex-algo algorithm arg";

        let func = self.builder.map.get(&(path, op)).context(CONFIG_ERR)?;
        let algo = args.u8().context(ALGO_ERR)?;
        if !(128..=255).contains(&algo) {
            bail!("flex-algo identifier must be 128..=255 (got {algo})");
        }
        func(&mut self.config, &mut self.cache, algo, &mut args)
    }

    /// Drain the pending cache into the committed map. Apply / drop
    /// semantics match `StaticConfig::commit`. SPF gating and
    /// per-algo RIB install will be wired in follow-up PRs; LSP
    /// re-origination is triggered by the per-leaf shim callbacks
    /// (so a single config change that hits multiple leaves
    /// originates the LSP once per leaf — acceptable churn given the
    /// LSP-gen throttle).
    pub fn commit(&mut self) {
        while let Some((algo, entry)) = self.cache.pop_first() {
            if entry.delete {
                self.config.remove(&algo);
            } else {
                self.config.insert(algo, entry);
            }
        }
    }
}

/// Extract per-algorithm Prefix-SIDs from a peer-advertised Ext IP-
/// Reach entry. Yields one (algo, sid) pair for each Prefix-SID
/// sub-TLV (RFC 8667 §2.1) whose Algorithm field is in the
/// flex-algo range (128..=255); algo-0 / algo-1 / unknown algos
/// are skipped. Mirrors the producer-side `build_per_algo_prefix_sids`
/// so the bytes a sender packs are the bytes a receiver unpacks.
pub fn parse_per_algo_prefix_sids(
    entry: &isis_packet::IsisTlvExtIpReachEntry,
) -> impl Iterator<Item = (u8, isis_packet::SidLabelValue)> + '_ {
    entry.subs.iter().filter_map(|sub| match sub {
        isis_packet::prefix::IsisSubTlv::PrefixSid(s) => match s.algo {
            Algo::FlexAlgo(n) => Some((n, s.sid.clone())),
            _ => None,
        },
        _ => None,
    })
}

/// Extract the Extended Admin Group bitmap from a peer-advertised
/// ASLA sub-TLV iff the ASLA's SABM marks it as applying to the
/// Flex-Algorithm application (RFC 9479 §4.2 X-bit). Returns the
/// nested IsisSubAdminGrp's bitmap as an ExtAdminGroup; returns
/// `None` when the SABM byte 0 is missing, the X-bit is clear, or
/// no AdminGrp sub-sub-TLV is present. Mirrors the producer-side
/// `build_link_asla` so SPF gating sees the same bits a sender
/// sets.
pub fn parse_asla_flex_algo_bitmap(asla: &IsisSubAsla) -> Option<ExtAdminGroup> {
    let first = asla.sabm.first()?;
    if first & SABM_FLEX_ALGO == 0 {
        return None;
    }
    for sub in &asla.subs {
        if let NeighSubTlv::AdminGrp(g) = sub {
            return Some(ExtAdminGroup {
                words: g.groups.clone(),
            });
        }
    }
    None
}

/// SABM byte (RFC 9479 §4.2) with the Flex-Algorithm (X-bit) set.
/// Bit layout in the first SABM byte, MSB-first: R(7) S(6) F(5) X(4)
/// reserved(3..0). Used as the Selective Application-specific
/// Attribute Bitmap on a per-link ASLA sub-TLV so receivers know
/// these link attributes apply to flex-algo path computation.
const SABM_FLEX_ALGO: u8 = 0x10;

/// Build the per-link Extended Admin Group bitmap from a set of
/// affinity names by resolving each name to its bit position via the
/// affinity-map and packing the bits into RFC 7308 32-bit words.
/// Names with no matching `/router/isis/affinity-map/affinity` entry
/// are silently dropped (best-effort emit, matches `build_fad_subs`).
fn link_admin_group_words(affinity: &BTreeSet<String>, am: &AffinityMap) -> Vec<u32> {
    let mut g = ExtAdminGroup::default();
    for name in affinity {
        if let Some(bit) = am.bit(name) {
            g.set(bit);
        }
    }
    g.words
}

/// Build a per-link ASLA sub-TLV (RFC 9479) carrying the link's
/// affinity (Extended Admin Group, RFC 7308) for the Flex-Algorithm
/// application. Returns `None` when no affinity bits resolved — a
/// zero-byte AdminGrp inside an ASLA would be a meaningless wire
/// artifact.
///
/// SABM is set to a single byte with only the X-bit (Flex-Algorithm,
/// 0x10) — these link attributes apply to flex-algo SPF only. The
/// L-flag stays cleared (modern non-legacy interpretation per
/// RFC 9479 §4.2). UDABM is left empty: every receiver that
/// understands ASLA understands Flex-Algorithm.
pub fn build_link_asla(affinity: &BTreeSet<String>, am: &AffinityMap) -> Option<IsisSubAsla> {
    let words = link_admin_group_words(affinity, am);
    if words.is_empty() {
        return None;
    }
    Some(IsisSubAsla {
        l_flag: false,
        sabm: vec![SABM_FLEX_ALGO],
        udabm: Vec::new(),
        subs: vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp { groups: words })],
    })
}

/// Resolve a set of affinity names to an `ExtAdminGroup` bitmap via
/// the affinity-map. Names with no matching entry are silently
/// dropped (best-effort, matches `build_link_asla` semantics).
///
/// Used by per-algo SPF to derive the bitmap for our own ExtIsReach
/// edges, since peer-ingested `peer_link_affinity` deliberately
/// excludes the local sys-id (the rebuild skips self).
pub fn local_link_affinity(affinity: &BTreeSet<String>, am: &AffinityMap) -> ExtAdminGroup {
    let mut g = ExtAdminGroup::default();
    for name in affinity {
        if let Some(bit) = am.bit(name) {
            g.set(bit);
        }
    }
    g
}

/// Apply the RFC 9350 §6 link-attribute constraints from `entry`
/// against `affinity`. Returns true when the link is admissible for
/// the algorithm's SPF graph.
///
/// `affinity = None` means the source LSP did not advertise an ASLA
/// bitmap for this neighbor — treated as the empty bitmap (every bit
/// = 0). That's the right default for peers that simply haven't
/// configured admin-groups: include-any with a non-empty constraint
/// rejects them, which matches the §6 "no link attribute" reading.
///
/// Constraint semantics:
///   - **exclude-any**: link fails if any of the FAD's excluded bits
///     is set in `affinity` (intersection non-empty).
///   - **include-any**: when the FAD lists any bit here, the link
///     must have at least one of them set (intersection non-empty).
///     Empty constraint = no requirement.
///   - **include-all**: every bit in the FAD's constraint must be set
///     on the link.
///
/// Name resolution failures (a constraint name not in `am`) are
/// silently dropped, matching `build_fad_subs` — the wire form would
/// not have carried that bit anyway.
pub fn link_passes_fad(
    affinity: Option<&ExtAdminGroup>,
    entry: &FlexAlgoEntry,
    am: &AffinityMap,
) -> bool {
    let exclude = local_link_affinity(&entry.exclude_any, am);
    let include_any = local_link_affinity(&entry.include_any, am);
    let include_all = local_link_affinity(&entry.include_all, am);

    let empty = ExtAdminGroup::default();
    let bitmap = affinity.unwrap_or(&empty);

    if !ext_admin_group_intersection(&exclude, bitmap).is_empty() {
        return false;
    }
    if !include_any.words.iter().all(|w| *w == 0)
        && ext_admin_group_intersection(&include_any, bitmap).is_empty()
    {
        return false;
    }
    if !ext_admin_group_contains(bitmap, &include_all) {
        return false;
    }
    true
}

/// Bitwise AND of two `ExtAdminGroup` bitmaps. Returned bitmap is
/// length min(a, b) — trailing zero words from a longer operand do
/// not contribute set bits.
fn ext_admin_group_intersection(a: &ExtAdminGroup, b: &ExtAdminGroup) -> ExtAdminGroup {
    let len = a.words.len().min(b.words.len());
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(a.words[i] & b.words[i]);
    }
    ExtAdminGroup { words: out }
}

/// True iff every set bit in `needed` is also set in `bitmap`.
/// Trailing words past `bitmap.words.len()` in `needed` must be zero.
fn ext_admin_group_contains(bitmap: &ExtAdminGroup, needed: &ExtAdminGroup) -> bool {
    for (i, w) in needed.words.iter().enumerate() {
        let have = bitmap.words.get(i).copied().unwrap_or(0);
        if *w & !have != 0 {
            return false;
        }
    }
    true
}

/// True iff `g` has no set bits.
trait ExtAdminGroupExt {
    fn is_empty(&self) -> bool;
}

impl ExtAdminGroupExt for ExtAdminGroup {
    fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }
}

/// Build the per-algorithm Prefix-SID sub-TLVs (RFC 8667 §2.1 +
/// RFC 9350 §7) to attach to one prefix's IP-reach entry. Each map
/// entry produces one additional Prefix-SID sub-TLV with the
/// Algorithm field set to the flex-algo id. Iteration order matches
/// the BTreeMap (ascending algo id) so the wire byte sequence is
/// deterministic.
pub fn build_per_algo_prefix_sids(map: &BTreeMap<u8, SidLabelValue>) -> Vec<IsisSubPrefixSid> {
    map.iter()
        .map(|(&algo, sid)| IsisSubPrefixSid {
            flags: 0.into(),
            algo: Algo::FlexAlgo(algo),
            sid: sid.clone(),
        })
        .collect()
}

/// Algorithms this router advertises in the SR Algorithm sub-TLV
/// (RFC 8667 §3.2, sub-TLV 19). `Algo::Spf` (algo 0) is always
/// present; every flex-algo entry in `fa.config` is added as
/// `Algo::FlexAlgo(N)` in sorted order.
///
/// Required by RFC 9350 §5.2: a router that originates a FAD or
/// participates in a flex-algo MUST list that algo here. The
/// configuration model treats *any* entry in `flex_algo.config` as
/// participation — `advertise_definition` controls FAD origination,
/// not participation.
pub fn sr_algorithms(fa: &FlexAlgoConfig) -> Vec<Algo> {
    let mut algos = Vec::with_capacity(1 + fa.config.len());
    algos.push(Algo::Spf);
    for &n in fa.config.keys() {
        algos.push(Algo::FlexAlgo(n));
    }
    algos
}

/// Build the FAD sub-TLVs (RFC 9350 §5.1) this router will originate
/// inside Router Capability TLV 242. One FAD per
/// `FlexAlgoConfig.config` entry with `advertise_definition == true`;
/// entries with the flag absent or false stay purely local.
///
/// Affinity names are resolved against `affinity_map` to 256-bit
/// Extended Admin Group bit positions (RFC 7308) — names with no
/// matching entry are silently dropped (LSP-gen is best-effort, the
/// operator's mistake doesn't deserve a build failure). SRLG names
/// are resolved against the global SRLG map (`Isis::srlg_groups`)
/// to 32-bit identifiers the same way.
pub fn build_fad_subs(
    fa: &FlexAlgoConfig,
    am: &AffinityMap,
    srlg_groups: &BTreeMap<String, SrlgGroup>,
) -> Vec<IsisSubFlexAlgoDef> {
    fn group_from_names<I: IntoIterator<Item = S>, S: AsRef<str>>(
        am: &AffinityMap,
        names: I,
    ) -> ExtAdminGroup {
        let mut g = ExtAdminGroup::default();
        for n in names {
            if let Some(bit) = am.bit(n.as_ref()) {
                g.set(bit);
            }
        }
        g
    }

    let mut out = Vec::new();
    for (&algo, entry) in &fa.config {
        if entry.advertise_definition != Some(true) {
            continue;
        }
        let metric_type = entry.metric_type.unwrap_or(FadMetricType::Igp).wire();
        let priority = entry.priority.unwrap_or(128);

        let mut subs = Vec::new();

        if !entry.exclude_any.is_empty() {
            let group = group_from_names(am, entry.exclude_any.iter());
            if !group.words.is_empty() {
                subs.push(FadSubTlv::ExcludeAg(IsisSubFadExcludeAg { group }));
            }
        }
        if !entry.include_any.is_empty() {
            let group = group_from_names(am, entry.include_any.iter());
            if !group.words.is_empty() {
                subs.push(FadSubTlv::IncludeAnyAg(IsisSubFadIncludeAnyAg { group }));
            }
        }
        if !entry.include_all.is_empty() {
            let group = group_from_names(am, entry.include_all.iter());
            if !group.words.is_empty() {
                subs.push(FadSubTlv::IncludeAllAg(IsisSubFadIncludeAllAg { group }));
            }
        }
        if entry.prefix_metric == Some(true) {
            subs.push(FadSubTlv::Flags(IsisSubFadFlags {
                m_flag: true,
                trailing: Vec::new(),
            }));
        }
        if !entry.srlg_exclude.is_empty() {
            let mut ids: Vec<u32> = entry
                .srlg_exclude
                .iter()
                .filter_map(|n| srlg_groups.get(n).map(|g| g.value))
                .collect();
            ids.sort();
            ids.dedup();
            if !ids.is_empty() {
                subs.push(FadSubTlv::ExcludeSrlg(IsisSubFadExcludeSrlg { srlgs: ids }));
            }
        }

        out.push(IsisSubFlexAlgoDef {
            flex_algorithm: algo,
            metric_type,
            calc_type: 0, // Only SPF defined today (RFC 9350 §5.1).
            priority,
            subs,
        });
    }
    out
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    pub map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    config: &mut BTreeMap<u8, FlexAlgoEntry>,
    cache: &mut BTreeMap<u8, FlexAlgoEntry>,
    algo: u8,
    args: &mut Args,
) -> Result<()>;

impl ConfigBuilder {
    pub fn path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    pub fn set(mut self, func: Handler) -> Self {
        self.map.insert((self.path.clone(), ConfigOp::Set), func);
        self
    }

    pub fn del(mut self, func: Handler) -> Self {
        self.map.insert((self.path.clone(), ConfigOp::Delete), func);
        self
    }
}

fn config_get(config: &BTreeMap<u8, FlexAlgoEntry>, algo: u8) -> FlexAlgoEntry {
    config.get(&algo).cloned().unwrap_or_default()
}

fn config_lookup(config: &BTreeMap<u8, FlexAlgoEntry>, algo: u8) -> Option<FlexAlgoEntry> {
    config.get(&algo).cloned()
}

fn cache_get<'a>(
    config: &BTreeMap<u8, FlexAlgoEntry>,
    cache: &'a mut BTreeMap<u8, FlexAlgoEntry>,
    algo: u8,
) -> Option<&'a mut FlexAlgoEntry> {
    if cache.get(&algo).is_none() {
        cache.insert(algo, config_get(config, algo));
    }
    cache.get_mut(&algo)
}

fn cache_lookup<'a>(
    config: &BTreeMap<u8, FlexAlgoEntry>,
    cache: &'a mut BTreeMap<u8, FlexAlgoEntry>,
    algo: u8,
) -> Option<&'a mut FlexAlgoEntry> {
    if cache.get(&algo).is_none() {
        cache.insert(algo, config_lookup(config, algo)?);
    }
    let entry = cache.get_mut(&algo)?;
    if entry.delete { None } else { Some(entry) }
}

fn config_builder() -> ConfigBuilder {
    const CONFIG_ERR: &str = "flex-algo entry parse error";
    const BOOL_ERR: &str = "flex-algo boolean arg parse error";
    const U8_ERR: &str = "flex-algo u8 arg parse error";
    const ENUM_ERR: &str = "flex-algo enum arg parse error";
    const NAME_ERR: &str = "flex-algo name arg parse error";

    ConfigBuilder::default()
        .path("/router/isis/flex-algo")
        .set(|config, cache, algo, _args| {
            let _ = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            if let Some(e) = cache.get_mut(&algo) {
                e.delete = true;
            } else {
                let mut e = config_lookup(config, algo).context(CONFIG_ERR)?;
                e.delete = true;
                cache.insert(algo, e);
            }
            Ok(())
        })
        .path("/router/isis/flex-algo/advertise-definition")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.advertise_definition = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.advertise_definition = None;
            Ok(())
        })
        .path("/router/isis/flex-algo/metric-type")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.metric_type = Some(args.string().context(ENUM_ERR)?.parse()?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.metric_type = None;
            Ok(())
        })
        .path("/router/isis/flex-algo/priority")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.priority = Some(args.u8().context(U8_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.priority = None;
            Ok(())
        })
        .path("/router/isis/flex-algo/prefix-metric")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.prefix_metric = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.prefix_metric = None;
            Ok(())
        })
        .path("/router/isis/flex-algo/dataplane/sr-mpls")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_sr_mpls = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_sr_mpls = None;
            Ok(())
        })
        .path("/router/isis/flex-algo/dataplane/srv6")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_srv6 = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_srv6 = None;
            Ok(())
        })
        .path("/router/isis/flex-algo/dataplane/ip")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_ip = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_ip = None;
            Ok(())
        })
        .path("/router/isis/flex-algo/affinity/include-any")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.include_any.insert(name);
            Ok(())
        })
        .del(|config, cache, algo, args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.include_any.remove(&name);
            Ok(())
        })
        .path("/router/isis/flex-algo/affinity/include-all")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.include_all.insert(name);
            Ok(())
        })
        .del(|config, cache, algo, args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.include_all.remove(&name);
            Ok(())
        })
        .path("/router/isis/flex-algo/affinity/exclude-any")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.exclude_any.insert(name);
            Ok(())
        })
        .del(|config, cache, algo, args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.exclude_any.remove(&name);
            Ok(())
        })
        .path("/router/isis/flex-algo/srlg-exclude")
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.srlg_exclude.insert(name);
            Ok(())
        })
        .del(|config, cache, algo, args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.srlg_exclude.remove(&name);
            Ok(())
        })
        .path("/router/isis/flex-algo/fast-reroute/ti-lfa")
        .set(|config, cache, algo, _args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.ti_lfa = true;
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.ti_lfa = false;
            Ok(())
        })
}

// ── Wiring into the existing IS-IS callback dispatcher ────────────
//
// The IS-IS instance dispatches per-leaf via `Isis::callbacks`, with
// callback signature `fn(&mut Isis, Args, ConfigOp) -> Option<()>`. We
// register one shim per path here; each shim forwards into
// `isis.flex_algo.exec(path, ...)` and then `commit()` so the new value
// is visible synchronously, the way the rest of IS-IS expects.

macro_rules! flex_algo_cb {
    ($name:ident, $path:literal) => {
        fn $name(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
            isis.flex_algo.exec($path.to_string(), args, op).ok()?;
            isis.flex_algo.commit();
            // Re-originate both levels so FAD changes propagate to
            // peers without waiting for the refresh timer. The
            // process_lsp_originate path filters by `has_level` for
            // single-level instances, so unconditional send is safe.
            let _ = isis
                .tx
                .send(super::Message::LspOriginate(super::Level::L1, None));
            let _ = isis
                .tx
                .send(super::Message::LspOriginate(super::Level::L2, None));
            Some(())
        }
    };
}

flex_algo_cb!(cb_entry, "/router/isis/flex-algo");
flex_algo_cb!(
    cb_advertise_definition,
    "/router/isis/flex-algo/advertise-definition"
);
flex_algo_cb!(cb_metric_type, "/router/isis/flex-algo/metric-type");
flex_algo_cb!(cb_priority, "/router/isis/flex-algo/priority");
flex_algo_cb!(cb_prefix_metric, "/router/isis/flex-algo/prefix-metric");
flex_algo_cb!(cb_dp_sr_mpls, "/router/isis/flex-algo/dataplane/sr-mpls");
flex_algo_cb!(cb_dp_srv6, "/router/isis/flex-algo/dataplane/srv6");
flex_algo_cb!(cb_dp_ip, "/router/isis/flex-algo/dataplane/ip");
flex_algo_cb!(
    cb_affinity_include_any,
    "/router/isis/flex-algo/affinity/include-any"
);
flex_algo_cb!(
    cb_affinity_include_all,
    "/router/isis/flex-algo/affinity/include-all"
);
flex_algo_cb!(
    cb_affinity_exclude_any,
    "/router/isis/flex-algo/affinity/exclude-any"
);
flex_algo_cb!(cb_srlg_exclude, "/router/isis/flex-algo/srlg-exclude");
flex_algo_cb!(cb_ti_lfa, "/router/isis/flex-algo/fast-reroute/ti-lfa");

pub fn callback_register(isis: &mut Isis) {
    isis.callback_add("/router/isis/flex-algo", cb_entry);
    isis.callback_add(
        "/router/isis/flex-algo/advertise-definition",
        cb_advertise_definition,
    );
    isis.callback_add("/router/isis/flex-algo/metric-type", cb_metric_type);
    isis.callback_add("/router/isis/flex-algo/priority", cb_priority);
    isis.callback_add("/router/isis/flex-algo/prefix-metric", cb_prefix_metric);
    isis.callback_add("/router/isis/flex-algo/dataplane/sr-mpls", cb_dp_sr_mpls);
    isis.callback_add("/router/isis/flex-algo/dataplane/srv6", cb_dp_srv6);
    isis.callback_add("/router/isis/flex-algo/dataplane/ip", cb_dp_ip);
    isis.callback_add(
        "/router/isis/flex-algo/affinity/include-any",
        cb_affinity_include_any,
    );
    isis.callback_add(
        "/router/isis/flex-algo/affinity/include-all",
        cb_affinity_include_all,
    );
    isis.callback_add(
        "/router/isis/flex-algo/affinity/exclude-any",
        cb_affinity_exclude_any,
    );
    isis.callback_add("/router/isis/flex-algo/srlg-exclude", cb_srlg_exclude);
    isis.callback_add("/router/isis/flex-algo/fast-reroute/ti-lfa", cb_ti_lfa);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect::<VecDeque<_>>())
    }

    #[test]
    fn set_advertise_definition_then_commit_persists() {
        let mut fa = FlexAlgoConfig::new();
        fa.exec(
            "/router/isis/flex-algo/advertise-definition".into(),
            args(&["128", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        let e = fa.config.get(&128).unwrap();
        assert_eq!(e.advertise_definition, Some(true));
    }

    #[test]
    fn set_metric_type_then_priority_share_entry() {
        let mut fa = FlexAlgoConfig::new();
        fa.exec(
            "/router/isis/flex-algo/metric-type".into(),
            args(&["128", "min-unidir-link-delay"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        fa.exec(
            "/router/isis/flex-algo/priority".into(),
            args(&["128", "200"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        let e = fa.config.get(&128).unwrap();
        assert_eq!(e.metric_type, Some(FadMetricType::MinUnidirLinkDelay));
        assert_eq!(e.priority, Some(200));
    }

    #[test]
    fn affinity_exclude_any_is_a_set() {
        let mut fa = FlexAlgoConfig::new();
        for color in ["blue", "red", "blue"] {
            fa.exec(
                "/router/isis/flex-algo/affinity/exclude-any".into(),
                args(&["129", color]),
                ConfigOp::Set,
            )
            .unwrap();
            fa.commit();
        }
        let e = fa.config.get(&129).unwrap();
        assert_eq!(e.exclude_any.len(), 2);
        assert!(e.exclude_any.contains("blue"));
        assert!(e.exclude_any.contains("red"));
    }

    #[test]
    fn delete_entry_removes_it() {
        let mut fa = FlexAlgoConfig::new();
        fa.exec(
            "/router/isis/flex-algo/priority".into(),
            args(&["128", "100"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        assert!(fa.config.contains_key(&128));

        fa.exec(
            "/router/isis/flex-algo".into(),
            args(&["128"]),
            ConfigOp::Delete,
        )
        .unwrap();
        fa.commit();
        assert!(!fa.config.contains_key(&128));
    }

    #[test]
    fn build_per_algo_prefix_sids_empty_map_yields_empty_vec() {
        let map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        assert!(build_per_algo_prefix_sids(&map).is_empty());
    }

    #[test]
    fn build_per_algo_prefix_sids_emits_one_per_algo_in_sorted_order() {
        let mut map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        map.insert(129, SidLabelValue::Index(1129));
        map.insert(128, SidLabelValue::Index(1128));
        let sids = build_per_algo_prefix_sids(&map);
        assert_eq!(sids.len(), 2);
        // BTreeMap iterates ascending → algo 128 first, 129 second.
        assert_eq!(sids[0].algo, Algo::FlexAlgo(128));
        assert_eq!(sids[0].sid, SidLabelValue::Index(1128));
        assert_eq!(sids[1].algo, Algo::FlexAlgo(129));
        assert_eq!(sids[1].sid, SidLabelValue::Index(1129));
    }

    #[test]
    fn build_per_algo_prefix_sids_preserves_label_vs_index_form() {
        let mut map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        map.insert(128, SidLabelValue::Index(42));
        map.insert(129, SidLabelValue::Label(20128));
        let sids = build_per_algo_prefix_sids(&map);
        assert_eq!(sids[0].sid, SidLabelValue::Index(42));
        assert_eq!(sids[1].sid, SidLabelValue::Label(20128));
    }

    fn affinity_set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parse_per_algo_prefix_sids_filters_to_flex_algo_range() {
        use ipnet::Ipv4Net;
        use isis_packet::PrefixSidFlags;
        use isis_packet::prefix::{Ipv4ControlInfo, IsisSubTlv as PrefixSubTlv};
        let entry = isis_packet::IsisTlvExtIpReachEntry {
            metric: 10,
            flags: Ipv4ControlInfo::new(),
            prefix: "10.0.0.1/32".parse::<Ipv4Net>().unwrap(),
            subs: vec![
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::Spf,
                    sid: SidLabelValue::Index(1),
                }),
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::FlexAlgo(128),
                    sid: SidLabelValue::Index(1128),
                }),
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::FlexAlgo(129),
                    sid: SidLabelValue::Label(20129),
                }),
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::StrictSpf,
                    sid: SidLabelValue::Index(2),
                }),
            ],
        };
        let out: Vec<_> = parse_per_algo_prefix_sids(&entry).collect();
        // Algo::Spf and Algo::StrictSpf must be skipped.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (128, SidLabelValue::Index(1128)));
        assert_eq!(out[1], (129, SidLabelValue::Label(20129)));
    }

    #[test]
    fn parse_per_algo_prefix_sids_round_trips_through_build_per_algo_prefix_sids() {
        use ipnet::Ipv4Net;
        use isis_packet::prefix::{Ipv4ControlInfo, IsisSubTlv as PrefixSubTlv};
        let mut map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        map.insert(128, SidLabelValue::Index(1128));
        map.insert(129, SidLabelValue::Label(20129));
        let sids = build_per_algo_prefix_sids(&map);
        // Wrap each into the entry, then pull back via the parser.
        let entry = isis_packet::IsisTlvExtIpReachEntry {
            metric: 10,
            flags: Ipv4ControlInfo::new(),
            prefix: "10.0.0.1/32".parse::<Ipv4Net>().unwrap(),
            subs: sids.into_iter().map(PrefixSubTlv::PrefixSid).collect(),
        };
        let out: Vec<_> = parse_per_algo_prefix_sids(&entry).collect();
        assert_eq!(
            out,
            vec![
                (128, SidLabelValue::Index(1128)),
                (129, SidLabelValue::Label(20129)),
            ]
        );
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_returns_none_without_x_bit() {
        // SABM = [0x80] sets R-bit (RSVP-TE) but not X-bit.
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![0x80],
            udabm: vec![],
            subs: vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0xFF],
            })],
        };
        assert!(parse_asla_flex_algo_bitmap(&asla).is_none());
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_returns_none_with_empty_sabm() {
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![],
            udabm: vec![],
            subs: vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0xFF],
            })],
        };
        assert!(parse_asla_flex_algo_bitmap(&asla).is_none());
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_returns_none_when_no_admin_grp_nested() {
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![SABM_FLEX_ALGO],
            udabm: vec![],
            subs: vec![],
        };
        assert!(parse_asla_flex_algo_bitmap(&asla).is_none());
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_extracts_admin_grp_when_x_bit_set() {
        // SABM = [0x90] sets R-bit AND X-bit — both are honored; X
        // alone is enough to surface the bitmap.
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![0x90],
            udabm: vec![],
            subs: vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0x11, 0x80000000],
            })],
        };
        let bitmap = parse_asla_flex_algo_bitmap(&asla).expect("bitmap");
        assert_eq!(bitmap.words, vec![0x11, 0x80000000]);
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_round_trips_through_build_link_asla() {
        // Build an ASLA on the producer side, parse it on the
        // consumer side — the bitmap must round-trip bit-for-bit.
        let mut am = AffinityMap::new();
        for (name, bit) in [("blue", "0"), ("red", "200")] {
            am.exec(
                "/router/isis/affinity-map/affinity/bit-position".into(),
                args(&[name, bit]),
                ConfigOp::Set,
            )
            .unwrap();
            am.commit();
        }
        let asla = build_link_asla(&affinity_set(&["blue", "red"]), &am).expect("ASLA");
        let parsed = parse_asla_flex_algo_bitmap(&asla).expect("bitmap");
        // bit 0 in word 0, bit (200 - 6*32 = 8) in word 6.
        assert_eq!(parsed.words.len(), 7);
        assert!(parsed.get(0));
        assert!(parsed.get(200));
        assert!(!parsed.get(1));
    }

    #[test]
    fn build_link_asla_returns_none_for_empty_affinity() {
        let am = AffinityMap::new();
        assert!(build_link_asla(&BTreeSet::new(), &am).is_none());
    }

    #[test]
    fn build_link_asla_returns_none_when_all_names_unresolved() {
        let am = AffinityMap::new();
        // `blue` is referenced but the affinity-map is empty.
        assert!(build_link_asla(&affinity_set(&["blue"]), &am).is_none());
    }

    #[test]
    fn build_link_asla_emits_sabm_flex_algo_and_admin_grp() {
        let mut am = AffinityMap::new();
        for (name, bit) in [("blue", "0"), ("low-lat", "4"), ("red", "31")] {
            am.exec(
                "/router/isis/affinity-map/affinity/bit-position".into(),
                args(&[name, bit]),
                ConfigOp::Set,
            )
            .unwrap();
            am.commit();
        }
        let asla = build_link_asla(&affinity_set(&["blue", "low-lat", "red"]), &am)
            .expect("ASLA expected");
        // L-flag clear, SABM = [0x10] (X-bit only), UDABM empty.
        assert!(!asla.l_flag);
        assert_eq!(asla.sabm, vec![SABM_FLEX_ALGO]);
        assert!(asla.udabm.is_empty());
        // One nested sub-TLV: AdminGrp with bits 0, 4, 31 packed into
        // the first 32-bit word.
        assert_eq!(asla.subs.len(), 1);
        match &asla.subs[0] {
            NeighSubTlv::AdminGrp(ag) => {
                assert_eq!(ag.groups.len(), 1);
                let w = ag.groups[0];
                assert!(w & (1 << 0) != 0, "bit 0 (blue) missing");
                assert!(w & (1 << 4) != 0, "bit 4 (low-lat) missing");
                assert!(w & (1 << 31) != 0, "bit 31 (red) missing");
                // No unexpected bits.
                let expected = (1u32 << 0) | (1u32 << 4) | (1u32 << 31);
                assert_eq!(w, expected);
            }
            other => panic!("expected AdminGrp, got {other:?}"),
        }
    }

    #[test]
    fn build_link_asla_grows_bitmap_to_multiple_words() {
        let mut am = AffinityMap::new();
        for (name, bit) in [("a", "0"), ("b", "32"), ("c", "200")] {
            am.exec(
                "/router/isis/affinity-map/affinity/bit-position".into(),
                args(&[name, bit]),
                ConfigOp::Set,
            )
            .unwrap();
            am.commit();
        }
        let asla = build_link_asla(&affinity_set(&["a", "b", "c"]), &am).expect("ASLA");
        match &asla.subs[0] {
            NeighSubTlv::AdminGrp(ag) => {
                // bit 200 lives in word 6 (200/32=6), so we need
                // at least 7 words.
                assert_eq!(ag.groups.len(), 7);
            }
            _ => panic!("expected AdminGrp"),
        }
    }

    #[test]
    fn sr_algorithms_lists_spf_plus_every_configured_algo() {
        let mut fa = FlexAlgoConfig::new();
        // No flex-algos yet — should yield exactly Algo::Spf.
        assert_eq!(sr_algorithms(&fa), vec![Algo::Spf]);

        // Add two flex-algos via any leaf write (priority is fine —
        // participation is implied by the entry existing, not by
        // advertise_definition).
        for algo in ["129", "128"] {
            fa.exec(
                "/router/isis/flex-algo/priority".into(),
                args(&[algo, "200"]),
                ConfigOp::Set,
            )
            .unwrap();
            fa.commit();
        }
        // BTreeMap iterates sorted, so flex-algos appear in 128, 129
        // order after Spf.
        assert_eq!(
            sr_algorithms(&fa),
            vec![Algo::Spf, Algo::FlexAlgo(128), Algo::FlexAlgo(129)]
        );
    }

    #[test]
    fn build_fad_subs_skips_entries_without_advertise_flag() {
        let mut fa = FlexAlgoConfig::new();
        // Algo 128 — advertise-definition NOT set, so should be skipped.
        fa.exec(
            "/router/isis/flex-algo/priority".into(),
            args(&["128", "200"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        // Algo 129 — advertise-definition set, should be emitted.
        fa.exec(
            "/router/isis/flex-algo/advertise-definition".into(),
            args(&["129", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();

        let am = AffinityMap::new();
        let srlg = BTreeMap::new();
        let subs = build_fad_subs(&fa, &am, &srlg);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].flex_algorithm, 129);
        // Defaults: igp metric type, priority 128, no nested subs.
        assert_eq!(subs[0].metric_type, FadMetricType::Igp.wire());
        assert_eq!(subs[0].priority, 128);
        assert!(subs[0].subs.is_empty());
    }

    #[test]
    fn build_fad_subs_emits_exclude_ag_and_srlg() {
        let mut fa = FlexAlgoConfig::new();
        for (path, args_) in [
            (
                "/router/isis/flex-algo/advertise-definition",
                &["128", "true"][..],
            ),
            (
                "/router/isis/flex-algo/affinity/exclude-any",
                &["128", "blue"],
            ),
            ("/router/isis/flex-algo/srlg-exclude", &["128", "risk-A"]),
            ("/router/isis/flex-algo/prefix-metric", &["128", "true"]),
        ] {
            fa.exec(path.into(), args(args_), ConfigOp::Set).unwrap();
            fa.commit();
        }

        let mut am = AffinityMap::new();
        am.exec(
            "/router/isis/affinity-map/affinity/bit-position".into(),
            args(&["blue", "4"]),
            ConfigOp::Set,
        )
        .unwrap();
        am.commit();

        let mut srlg = BTreeMap::new();
        srlg.insert(
            "risk-A".to_string(),
            SrlgGroup {
                name: "risk-A".into(),
                value: 100,
            },
        );

        let subs = build_fad_subs(&fa, &am, &srlg);
        assert_eq!(subs.len(), 1);
        let fad = &subs[0];
        assert_eq!(fad.flex_algorithm, 128);
        // Exactly three nested sub-TLVs: ExcludeAg, Flags (M=1), ExcludeSrlg.
        assert_eq!(fad.subs.len(), 3);
        let mut has_excl = false;
        let mut has_flags = false;
        let mut has_srlg = false;
        for sub in &fad.subs {
            match sub {
                FadSubTlv::ExcludeAg(v) => {
                    has_excl = true;
                    assert!(v.group.get(4));
                }
                FadSubTlv::Flags(v) => {
                    has_flags = true;
                    assert!(v.m_flag);
                }
                FadSubTlv::ExcludeSrlg(v) => {
                    has_srlg = true;
                    assert_eq!(v.srlgs, vec![100]);
                }
                _ => panic!("unexpected sub: {sub:?}"),
            }
        }
        assert!(has_excl && has_flags && has_srlg);
    }

    #[test]
    fn build_fad_subs_drops_unresolved_affinity_names() {
        let mut fa = FlexAlgoConfig::new();
        fa.exec(
            "/router/isis/flex-algo/advertise-definition".into(),
            args(&["128", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.exec(
            "/router/isis/flex-algo/affinity/exclude-any".into(),
            args(&["128", "ghost"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();

        // Empty affinity map — `ghost` is referenced but not defined.
        let am = AffinityMap::new();
        let subs = build_fad_subs(&fa, &am, &BTreeMap::new());
        assert_eq!(subs.len(), 1);
        // No ExcludeAg sub-TLV emitted because the bitmap would be
        // empty — a 0-byte sub-TLV is meaningless on the wire.
        assert!(subs[0].subs.is_empty(), "got subs: {:?}", subs[0].subs);
    }

    #[test]
    fn algo_outside_user_range_rejected() {
        let mut fa = FlexAlgoConfig::new();
        let err = fa
            .exec(
                "/router/isis/flex-algo/priority".into(),
                args(&["127", "100"]),
                ConfigOp::Set,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("128..=255"), "unexpected err: {err}");
    }

    /// Build a synthetic affinity-map with the requested name → bit
    /// assignments. Each name gets its own slot starting at bit 0.
    fn affinity_map(names: &[&str]) -> AffinityMap {
        let mut am = AffinityMap::new();
        for (i, name) in names.iter().enumerate() {
            am.config.insert(
                (*name).to_string(),
                super::super::affinity_map::AffinityEntry {
                    delete: false,
                    bit_position: Some(i as u16),
                },
            );
        }
        am
    }

    /// Build an `ExtAdminGroup` from a list of bit positions.
    fn admin_group(bits: &[u16]) -> ExtAdminGroup {
        let mut g = ExtAdminGroup::default();
        for b in bits {
            g.set(*b);
        }
        g
    }

    fn fad_entry(
        exclude_any: &[&str],
        include_any: &[&str],
        include_all: &[&str],
    ) -> FlexAlgoEntry {
        FlexAlgoEntry {
            exclude_any: affinity_set(exclude_any),
            include_any: affinity_set(include_any),
            include_all: affinity_set(include_all),
            ..Default::default()
        }
    }

    #[test]
    fn link_passes_fad_no_constraints_accepts_anything() {
        let am = affinity_map(&["red"]);
        let entry = fad_entry(&[], &[], &[]);
        assert!(link_passes_fad(None, &entry, &am));
        let g = admin_group(&[0]);
        assert!(link_passes_fad(Some(&g), &entry, &am));
    }

    #[test]
    fn link_passes_fad_exclude_any_drops_link_with_excluded_bit() {
        let am = affinity_map(&["red", "blue"]);
        let entry = fad_entry(&["red"], &[], &[]);
        let red = admin_group(&[0]);
        let blue = admin_group(&[1]);
        assert!(!link_passes_fad(Some(&red), &entry, &am));
        assert!(link_passes_fad(Some(&blue), &entry, &am));
        // Missing affinity = empty bitmap = no excluded bit set.
        assert!(link_passes_fad(None, &entry, &am));
    }

    #[test]
    fn link_passes_fad_include_any_requires_at_least_one_bit() {
        let am = affinity_map(&["red", "blue", "green"]);
        let entry = fad_entry(&[], &["red", "blue"], &[]);
        // No bits set → fails include-any when constraint is non-empty.
        assert!(!link_passes_fad(None, &entry, &am));
        // Unrelated bit only → still fails.
        let green = admin_group(&[2]);
        assert!(!link_passes_fad(Some(&green), &entry, &am));
        // One of the required bits → passes.
        let red = admin_group(&[0]);
        assert!(link_passes_fad(Some(&red), &entry, &am));
        // Both required bits → passes.
        let red_blue = admin_group(&[0, 1]);
        assert!(link_passes_fad(Some(&red_blue), &entry, &am));
    }

    #[test]
    fn link_passes_fad_include_all_requires_every_bit() {
        let am = affinity_map(&["red", "blue", "green"]);
        let entry = fad_entry(&[], &[], &["red", "blue"]);
        // Empty bitmap → missing both → fails.
        assert!(!link_passes_fad(None, &entry, &am));
        // Only one of the required bits → fails.
        let red = admin_group(&[0]);
        assert!(!link_passes_fad(Some(&red), &entry, &am));
        // Both required bits → passes.
        let red_blue = admin_group(&[0, 1]);
        assert!(link_passes_fad(Some(&red_blue), &entry, &am));
        // Superset (all required + extra) → still passes.
        let red_blue_green = admin_group(&[0, 1, 2]);
        assert!(link_passes_fad(Some(&red_blue_green), &entry, &am));
    }

    #[test]
    fn link_passes_fad_combined_constraints_all_must_pass() {
        // exclude red, include-any {blue, green}, include-all {blue}
        let am = affinity_map(&["red", "blue", "green"]);
        let entry = fad_entry(&["red"], &["blue", "green"], &["blue"]);
        // red present → exclude trips first.
        let red_blue = admin_group(&[0, 1]);
        assert!(!link_passes_fad(Some(&red_blue), &entry, &am));
        // blue alone → satisfies include-any (blue ∈ {blue, green}) and
        // include-all ({blue} ⊆ {blue}).
        let blue = admin_group(&[1]);
        assert!(link_passes_fad(Some(&blue), &entry, &am));
        // green alone → satisfies include-any but not include-all.
        let green = admin_group(&[2]);
        assert!(!link_passes_fad(Some(&green), &entry, &am));
    }

    #[test]
    fn link_passes_fad_unresolved_constraint_names_silently_drop() {
        // FAD references "purple" which isn't in the affinity-map; the
        // bit cannot be encoded into the local bitmap, so an include-
        // all on it alone reduces to an empty requirement → passes.
        let am = affinity_map(&["red"]);
        let entry = fad_entry(&[], &[], &["purple"]);
        assert!(link_passes_fad(None, &entry, &am));
        let red = admin_group(&[0]);
        assert!(link_passes_fad(Some(&red), &entry, &am));
    }
}
