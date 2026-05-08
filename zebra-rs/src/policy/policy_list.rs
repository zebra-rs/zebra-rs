use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Error, Result};
use bgp_packet::Origin;
use strum_macros::{Display, EnumString};

use crate::config::{Args, ConfigOp};

use super::{
    AsPathSet, AsPathSetConfig, CommunitySet, CommunitySetConfig, ExtCommunitySet,
    ExtCommunitySetConfig, LargeCommunitySet, LargeCommunitySetConfig, Policy, PrefixSet,
    PrefixSetConfig,
};

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PolicyList {
    pub entry: BTreeMap<u32, PolicyEntry>,
    pub delete: bool,
}

impl PolicyList {
    pub fn entry(&mut self, seq: u32) -> &mut PolicyEntry {
        self.entry.entry(seq).or_default()
    }

    pub fn lookup(&mut self, seq: &u32) -> Option<&mut PolicyEntry> {
        self.entry.get_mut(seq)
    }
}

/// Per-entry terminal action. `permit` accepts the route and stops
/// scanning. `deny` rejects the route. `next` falls through to the
/// next entry (after applying any `set`).
///
/// `Default` returns `Permit` so a partially-constructed
/// `PolicyEntry` (e.g. mid config commit, before the YANG callback
/// has fired) doesn't silently flip semantics. The YANG schema
/// requires `action` to be explicitly set on every entry, so the
/// default is only ever observed transiently.
#[derive(EnumString, Display, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PolicyAction {
    #[default]
    #[strum(serialize = "permit")]
    Permit,
    #[strum(serialize = "next")]
    Next,
    #[strum(serialize = "deny")]
    Deny,
}

fn parse_origin(s: &str) -> Result<Origin> {
    match s {
        "igp" => Ok(Origin::Igp),
        "egp" => Ok(Origin::Egp),
        "incomplete" => Ok(Origin::Incomplete),
        other => Err(anyhow::anyhow!("invalid origin: {}", other)),
    }
}

/// Set-action config for `set as-path-prepend ASN repeat NUM`.
/// At apply time the same ASN is prepended `repeat` times onto
/// AS_PATH — equivalent to IOS-XR's `prepend as-path NUM repeats N`.
#[derive(Clone, Debug, PartialEq)]
pub struct AsPathPrependConfig {
    pub asn: u32,
    pub repeat: u8,
}

impl AsPathPrependConfig {
    pub fn new(asn: u32) -> Self {
        Self { asn, repeat: 1 }
    }
}

/// Operator for numeric match clauses (`match med`,
/// `match as-path-len`, `match as-path-len-uniq`,
/// `match local-preference`, `match weight`) of shape
/// `{eq|le|ge} NUM`. The operand is bundled into the variant so
/// the type itself encodes "exactly one operator with its value".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumericMatch {
    Eq(u32),
    Le(u32),
    Ge(u32),
}

impl NumericMatch {
    pub fn op_str(&self) -> &'static str {
        match self {
            NumericMatch::Eq(_) => "eq",
            NumericMatch::Le(_) => "le",
            NumericMatch::Ge(_) => "ge",
        }
    }

    pub fn value(&self) -> u32 {
        match self {
            NumericMatch::Eq(v) | NumericMatch::Le(v) | NumericMatch::Ge(v) => *v,
        }
    }

    pub fn matches(&self, v: u32) -> bool {
        match self {
            NumericMatch::Eq(target) => v == *target,
            NumericMatch::Le(target) => v <= *target,
            NumericMatch::Ge(target) => v >= *target,
        }
    }
}

/// Operator for numeric set actions (`set local-preference`,
/// `set med`) of shape `{set NUM | add NUM | sub NUM}`.
/// `Set` overwrites the attribute; `Add` and `Sub` mutate the
/// route's current value (treating absence as 0). Underflow on
/// `Sub` and overflow on `Add` saturate; arithmetic never drops
/// the route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumericSet {
    Set(u32),
    Add(u32),
    Sub(u32),
}

impl NumericSet {
    pub fn op_str(&self) -> &'static str {
        match self {
            NumericSet::Set(_) => "set",
            NumericSet::Add(_) => "add",
            NumericSet::Sub(_) => "sub",
        }
    }

    pub fn value(&self) -> u32 {
        match self {
            NumericSet::Set(v) | NumericSet::Add(v) | NumericSet::Sub(v) => *v,
        }
    }

    /// Apply the action to the route's current value, treating
    /// absence as 0 and saturating on overflow / underflow.
    pub fn apply(&self, current: u32) -> u32 {
        match self {
            NumericSet::Set(v) => *v,
            NumericSet::Add(v) => current.saturating_add(*v),
            NumericSet::Sub(v) => current.saturating_sub(*v),
        }
    }
}

/// Operation applied by `set community NAME {|additive|delete}`.
/// `Replace` overwrites the COMMUNITIES attribute with the set's
/// members; `Additive` merges them in; `Delete` removes them
/// (set difference).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SetCommunityMode {
    #[default]
    Replace,
    Additive,
    Delete,
}

/// Set-action config for `set community NAME {|additive|delete}`.
/// `name` references a community-set; `resolved` is populated by
/// `policy_entry_sync` from the community-set registry.
#[derive(Clone, Debug, PartialEq)]
pub struct SetCommunityConfig {
    pub name: String,
    pub mode: SetCommunityMode,
    pub resolved: Option<CommunitySet>,
}

impl SetCommunityConfig {
    pub fn new(name: String) -> Self {
        Self {
            name,
            mode: SetCommunityMode::Replace,
            resolved: None,
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PolicyEntry {
    // Match.
    pub prefix_set_name: Option<String>,
    pub prefix_set: Option<PrefixSet>,
    pub community_set_name: Option<String>,
    pub community_set: Option<CommunitySet>,
    pub ext_community_set_name: Option<String>,
    pub ext_community_set: Option<ExtCommunitySet>,
    pub large_community_set_name: Option<String>,
    pub large_community_set: Option<LargeCommunitySet>,
    pub as_path_set_name: Option<String>,
    pub as_path_set: Option<AsPathSet>,
    pub match_next_hop: Option<IpAddr>,
    pub match_med: Option<NumericMatch>,
    pub match_as_path_len: Option<NumericMatch>,
    pub match_as_path_len_uniq: Option<NumericMatch>,
    pub match_local_pref: Option<NumericMatch>,
    pub match_weight: Option<NumericMatch>,
    pub match_origin: Option<Origin>,
    // Set.
    pub local_pref: Option<NumericSet>,
    pub med: Option<NumericSet>,
    pub weight: Option<u32>,
    pub set_community: Option<SetCommunityConfig>,
    pub set_as_path_prepend: Option<AsPathPrependConfig>,
    pub set_next_hop: Option<Ipv4Addr>,
    pub set_origin: Option<Origin>,
    // Action.
    pub action: PolicyAction,
}

pub fn policy_entry_sync(
    policy_list: &mut PolicyList,
    prefix_set: &PrefixSetConfig,
    community_set: &CommunitySetConfig,
    ext_community_set: &ExtCommunitySetConfig,
    large_community_set: &LargeCommunitySetConfig,
    as_path_set: &AsPathSetConfig,
) {
    for (_, policy) in policy_list.entry.iter_mut() {
        if let Some(name) = &policy.prefix_set_name {
            if let Some(prefix_set) = prefix_set.config.get(name) {
                policy.prefix_set = Some(prefix_set.clone());
            } else {
                policy.prefix_set = None;
            }
        }
        if let Some(name) = &policy.community_set_name {
            if let Some(community_set) = community_set.config.get(name) {
                policy.community_set = Some(community_set.clone());
            } else {
                policy.community_set = None;
            }
        }
        if let Some(name) = &policy.ext_community_set_name {
            policy.ext_community_set = ext_community_set.config.get(name).cloned();
        }
        if let Some(name) = &policy.large_community_set_name {
            policy.large_community_set = large_community_set.config.get(name).cloned();
        }
        if let Some(name) = &policy.as_path_set_name {
            if let Some(as_path_set) = as_path_set.config.get(name) {
                policy.as_path_set = Some(as_path_set.clone());
            } else {
                policy.as_path_set = None;
            }
        }
        if let Some(cfg) = policy.set_community.as_mut() {
            cfg.resolved = community_set.config.get(&cfg.name).cloned();
        }
    }
}

pub struct PolicyConfig {
    pub config: BTreeMap<String, PolicyList>,
    pub cache: BTreeMap<String, PolicyList>,
    builder: ConfigBuilder,
}

impl PolicyConfig {
    pub fn new() -> Self {
        PolicyConfig {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const POLICY_NAME_ERR: &str = "missing policy name arg";
        const ENTRY_SEQ_ERR: &str = "missing entry sequence number arg";

        let handler = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name = args.string().context(POLICY_NAME_ERR)?;
        if !path.starts_with("/policy/entry") {
            handler(&mut self.config, &mut self.cache, name, 0, &mut args)
        } else {
            let seq = args.u32().context(ENTRY_SEQ_ERR)?;
            handler(&mut self.config, &mut self.cache, name, seq, &mut args)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit<S: crate::policy::Syncer>(
        config: &mut BTreeMap<String, PolicyList>,
        cache: &mut BTreeMap<String, PolicyList>,
        prefix_config: &PrefixSetConfig,
        community_config: &CommunitySetConfig,
        ext_community_config: &ExtCommunitySetConfig,
        large_community_config: &LargeCommunitySetConfig,
        as_path_config: &AsPathSetConfig,
        syncer: S,
    ) {
        while let Some((name, mut s)) = cache.pop_first() {
            if s.delete {
                syncer.policy_list_remove(&name);
                config.remove(&name);
            } else {
                policy_entry_sync(
                    &mut s,
                    prefix_config,
                    community_config,
                    ext_community_config,
                    large_community_config,
                    as_path_config,
                );
                syncer.policy_list_update(&name, &s);
                config.insert(name, s);
            }
        }
    }
}

type Handler = fn(
    policy: &mut BTreeMap<String, PolicyList>,
    cache: &mut BTreeMap<String, PolicyList>,
    name: String,
    seq: u32,
    args: &mut Args,
) -> Result<()>;

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

fn config_get(config: &BTreeMap<String, PolicyList>, name: &String) -> PolicyList {
    let Some(list) = config.get(name) else {
        return PolicyList::default();
    };
    list.clone()
}

fn config_lookup(config: &BTreeMap<String, PolicyList>, name: &String) -> Option<PolicyList> {
    let list = config.get(name)?;
    Some(list.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, PolicyList>,
    cache: &'a mut BTreeMap<String, PolicyList>,
    name: &'a String,
) -> Option<&'a mut PolicyList> {
    if cache.get(name).is_none() {
        cache.insert(name.clone(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, PolicyList>,
    cache: &'a mut BTreeMap<String, PolicyList>,
    name: &'a String,
) -> Option<&'a mut PolicyList> {
    if cache.get(name).is_none() {
        cache.insert(name.clone(), config_lookup(config, name)?);
    }
    let cache = cache.get_mut(name)?;
    if cache.delete { None } else { Some(cache) }
}

impl ConfigBuilder {
    pub fn new() -> Self {
        const ARG_ERR: &str = "missing argument";

        ConfigBuilder::default()
            .path("")
            .set(|policy, cache, name, _seq, _args| {
                let _ = cache_get(policy, cache, &name).context(ARG_ERR)?;
                Ok(())
            })
            .del(|policy, cache, name, _seq, _args| {
                if let Some(list) = cache.get_mut(&name) {
                    list.delete = true;
                } else {
                    let mut list = config_lookup(policy, &name).context(ARG_ERR)?;
                    list.delete = true;
                    cache.insert(name, list);
                }
                Ok(())
            })
            .path("/entry")
            .set(|policy, cache, name, seq, _args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let _ = list.entry(seq);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                list.entry.remove(&seq).context(ARG_ERR)?;
                Ok(())
            })
            .path("/entry/match/prefix")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let prefix_set = args.string().context(ARG_ERR)?;
                entry.prefix_set_name = Some(prefix_set);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.prefix_set_name = None;
                Ok(())
            })
            .path("/entry/match/community")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let community_set = args.string().context(ARG_ERR)?;
                entry.community_set_name = Some(community_set);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.community_set_name = None;
                Ok(())
            })
            .path("/entry/match/ext-community")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.ext_community_set_name = Some(args.string().context(ARG_ERR)?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.ext_community_set_name = None;
                Ok(())
            })
            .path("/entry/match/large-community")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.large_community_set_name = Some(args.string().context(ARG_ERR)?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.large_community_set_name = None;
                Ok(())
            })
            .path("/entry/match/as-path")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let as_path_set = args.string().context(ARG_ERR)?;
                entry.as_path_set_name = Some(as_path_set);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.as_path_set_name = None;
                Ok(())
            })
            // `match next-hop ADDR` — direct IPv4/IPv6 address
            // compared for exact equality against the route's
            // BGP NEXT_HOP attribute.
            .path("/entry/match/next-hop")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                let s = args.string().context(ARG_ERR)?;
                entry.match_next_hop = Some(s.parse::<IpAddr>()?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_next_hop = None;
                Ok(())
            })
            // `match med {eq|le|ge} NUM` — presence container with
            // a `choice op` enforcing exactly-one operator. Each
            // case carries a mandatory uint32 operand; setting any
            // case writes the variant; deleting it (or the
            // container) clears the whole match.
            .path("/entry/match/med/eq")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_med = Some(NumericMatch::Eq(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_med, Some(NumericMatch::Eq(_))) {
                    entry.match_med = None;
                }
                Ok(())
            })
            .path("/entry/match/med/le")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_med = Some(NumericMatch::Le(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_med, Some(NumericMatch::Le(_))) {
                    entry.match_med = None;
                }
                Ok(())
            })
            .path("/entry/match/med/ge")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_med = Some(NumericMatch::Ge(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_med, Some(NumericMatch::Ge(_))) {
                    entry.match_med = None;
                }
                Ok(())
            })
            .path("/entry/match/med")
            .del(|policy, cache, name, seq, _args| {
                // Container-level delete clears the whole match.
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_med = None;
                Ok(())
            })
            // `match as-path-len {eq|le|ge} NUM` — same shape as med.
            .path("/entry/match/as-path-len/eq")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_as_path_len = Some(NumericMatch::Eq(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_as_path_len, Some(NumericMatch::Eq(_))) {
                    entry.match_as_path_len = None;
                }
                Ok(())
            })
            .path("/entry/match/as-path-len/le")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_as_path_len = Some(NumericMatch::Le(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_as_path_len, Some(NumericMatch::Le(_))) {
                    entry.match_as_path_len = None;
                }
                Ok(())
            })
            .path("/entry/match/as-path-len/ge")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_as_path_len = Some(NumericMatch::Ge(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_as_path_len, Some(NumericMatch::Ge(_))) {
                    entry.match_as_path_len = None;
                }
                Ok(())
            })
            .path("/entry/match/as-path-len")
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_as_path_len = None;
                Ok(())
            })
            // `match as-path-len-uniq {eq|le|ge} NUM` — same shape.
            .path("/entry/match/as-path-len-uniq/eq")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_as_path_len_uniq = Some(NumericMatch::Eq(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_as_path_len_uniq, Some(NumericMatch::Eq(_))) {
                    entry.match_as_path_len_uniq = None;
                }
                Ok(())
            })
            .path("/entry/match/as-path-len-uniq/le")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_as_path_len_uniq = Some(NumericMatch::Le(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_as_path_len_uniq, Some(NumericMatch::Le(_))) {
                    entry.match_as_path_len_uniq = None;
                }
                Ok(())
            })
            .path("/entry/match/as-path-len-uniq/ge")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_as_path_len_uniq = Some(NumericMatch::Ge(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_as_path_len_uniq, Some(NumericMatch::Ge(_))) {
                    entry.match_as_path_len_uniq = None;
                }
                Ok(())
            })
            .path("/entry/match/as-path-len-uniq")
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_as_path_len_uniq = None;
                Ok(())
            })
            // `match local-preference {eq|le|ge} NUM` — same shape.
            .path("/entry/match/local-preference/eq")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_local_pref = Some(NumericMatch::Eq(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_local_pref, Some(NumericMatch::Eq(_))) {
                    entry.match_local_pref = None;
                }
                Ok(())
            })
            .path("/entry/match/local-preference/le")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_local_pref = Some(NumericMatch::Le(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_local_pref, Some(NumericMatch::Le(_))) {
                    entry.match_local_pref = None;
                }
                Ok(())
            })
            .path("/entry/match/local-preference/ge")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_local_pref = Some(NumericMatch::Ge(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_local_pref, Some(NumericMatch::Ge(_))) {
                    entry.match_local_pref = None;
                }
                Ok(())
            })
            .path("/entry/match/local-preference")
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_local_pref = None;
                Ok(())
            })
            // `match weight {eq|le|ge} NUM` — same shape.
            .path("/entry/match/weight/eq")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_weight = Some(NumericMatch::Eq(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_weight, Some(NumericMatch::Eq(_))) {
                    entry.match_weight = None;
                }
                Ok(())
            })
            .path("/entry/match/weight/le")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_weight = Some(NumericMatch::Le(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_weight, Some(NumericMatch::Le(_))) {
                    entry.match_weight = None;
                }
                Ok(())
            })
            .path("/entry/match/weight/ge")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_weight = Some(NumericMatch::Ge(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.match_weight, Some(NumericMatch::Ge(_))) {
                    entry.match_weight = None;
                }
                Ok(())
            })
            .path("/entry/match/weight")
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_weight = None;
                Ok(())
            })
            .path("/entry/match/origin")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                let origin_str = args.string().context(ARG_ERR)?;
                entry.match_origin = Some(parse_origin(&origin_str).context(ARG_ERR)?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_origin = None;
                Ok(())
            })
            // `set local-preference {set|add|sub} NUM` — presence
            // container with mandatory choice; `set` overwrites,
            // `add`/`sub` mutate the route's current value with
            // saturating arithmetic.
            .path("/entry/set/local-preference/set")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.local_pref = Some(NumericSet::Set(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.local_pref, Some(NumericSet::Set(_))) {
                    entry.local_pref = None;
                }
                Ok(())
            })
            .path("/entry/set/local-preference/add")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.local_pref = Some(NumericSet::Add(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.local_pref, Some(NumericSet::Add(_))) {
                    entry.local_pref = None;
                }
                Ok(())
            })
            .path("/entry/set/local-preference/sub")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.local_pref = Some(NumericSet::Sub(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.local_pref, Some(NumericSet::Sub(_))) {
                    entry.local_pref = None;
                }
                Ok(())
            })
            .path("/entry/set/local-preference")
            .del(|policy, cache, name, seq, _args| {
                // Container-level delete clears the whole action.
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.local_pref = None;
                Ok(())
            })
            // `set med {set|add|sub} NUM` — same shape.
            .path("/entry/set/med/set")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.med = Some(NumericSet::Set(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.med, Some(NumericSet::Set(_))) {
                    entry.med = None;
                }
                Ok(())
            })
            .path("/entry/set/med/add")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.med = Some(NumericSet::Add(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.med, Some(NumericSet::Add(_))) {
                    entry.med = None;
                }
                Ok(())
            })
            .path("/entry/set/med/sub")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.med = Some(NumericSet::Sub(args.u32().context(ARG_ERR)?));
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if matches!(entry.med, Some(NumericSet::Sub(_))) {
                    entry.med = None;
                }
                Ok(())
            })
            .path("/entry/set/med")
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.med = None;
                Ok(())
            })
            .path("/entry/set/weight")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.weight = Some(args.u32().context(ARG_ERR)?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.weight = None;
                Ok(())
            })
            // `set community NAME {|additive|delete}` — presence
            // container with a mandatory `name` and a `choice mode`
            // whose three cases are bare keywords (or empty for
            // replace). YANG fires per-leaf callbacks; we maintain a
            // single `SetCommunityConfig` and patch in/out the mode.
            .path("/entry/set/community/name")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                let community_name = args.string().context(ARG_ERR)?;
                match entry.set_community.as_mut() {
                    Some(cfg) => cfg.name = community_name,
                    None => entry.set_community = Some(SetCommunityConfig::new(community_name)),
                }
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                // `name` is mandatory; deleting it invalidates the
                // whole config.
                entry.set_community = None;
                Ok(())
            })
            .path("/entry/set/community/additive")
            .set(|policy, cache, name, seq, _args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                if let Some(cfg) = entry.set_community.as_mut() {
                    cfg.mode = SetCommunityMode::Additive;
                }
                // No-op if name not yet set; the YANG choice ensures
                // additive and delete are mutually exclusive at the
                // schema level.
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if let Some(cfg) = entry.set_community.as_mut()
                    && cfg.mode == SetCommunityMode::Additive
                {
                    cfg.mode = SetCommunityMode::Replace;
                }
                Ok(())
            })
            .path("/entry/set/community/delete")
            .set(|policy, cache, name, seq, _args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                if let Some(cfg) = entry.set_community.as_mut() {
                    cfg.mode = SetCommunityMode::Delete;
                }
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if let Some(cfg) = entry.set_community.as_mut()
                    && cfg.mode == SetCommunityMode::Delete
                {
                    cfg.mode = SetCommunityMode::Replace;
                }
                Ok(())
            })
            .path("/entry/set/community")
            .del(|policy, cache, name, seq, _args| {
                // Container-level delete clears the whole config.
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.set_community = None;
                Ok(())
            })
            // `set as-path-prepend ASN [repeat NUM]` is modeled as
            // a presence container with two leaves. YANG fires
            // callbacks per leaf, so we patch the partial config
            // incrementally; a missing `repeat` defaults to 1
            // (matches the YANG default).
            .path("/entry/set/as-path-prepend/asn")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                let asn = args.u32().context("as-path-prepend asn: parse")?;
                match entry.set_as_path_prepend.as_mut() {
                    Some(cfg) => cfg.asn = asn,
                    None => entry.set_as_path_prepend = Some(AsPathPrependConfig::new(asn)),
                }
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                // `asn` is mandatory; deleting it invalidates the
                // whole config.
                entry.set_as_path_prepend = None;
                Ok(())
            })
            .path("/entry/set/as-path-prepend/repeat")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                let repeat = args.u8().context("as-path-prepend repeat: parse")?;
                if repeat == 0 {
                    anyhow::bail!("as-path-prepend repeat: must be >= 1");
                }
                if let Some(cfg) = entry.set_as_path_prepend.as_mut() {
                    cfg.repeat = repeat;
                }
                // If asn isn't set yet the leaf order is unusual but
                // valid (commit will fire the asn callback next);
                // silently no-op rather than synthesizing an invalid
                // config.
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                if let Some(cfg) = entry.set_as_path_prepend.as_mut() {
                    cfg.repeat = 1;
                }
                Ok(())
            })
            .path("/entry/set/as-path-prepend")
            .del(|policy, cache, name, seq, _args| {
                // Container-level delete clears the whole config.
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.set_as_path_prepend = None;
                Ok(())
            })
            .path("/entry/set/next-hop")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let addr = args.v4addr().context(ARG_ERR)?;
                entry.set_next_hop = Some(addr);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.set_next_hop = None;
                Ok(())
            })
            .path("/entry/set/origin")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                let s = args.string().context(ARG_ERR)?;
                entry.set_origin = Some(parse_origin(&s).context(ARG_ERR)?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.set_origin = None;
                Ok(())
            })
            .path("/entry/action")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.action = args.string().context(ARG_ERR)?.parse()?;
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                // YANG marks `action` mandatory; deleting just the
                // leaf reverts to the default (Permit). The whole
                // entry should be deleted to remove the policy line.
                entry.action = PolicyAction::default();
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/policy";
        self.path = format!("{prefix}{path}");
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

pub fn show(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();
    for (name, policy) in policy.policy_config.config.iter() {
        let _ = writeln!(buf, "policy-list: {}", name);
        for (seq, entry) in policy.entry.iter() {
            let _ = writeln!(buf, " entry: {}", seq);
            if let Some(prefix_set) = &entry.prefix_set_name {
                let _ = writeln!(buf, "  match: prefix_set {}", prefix_set);
            }
            if let Some(community_set) = &entry.community_set_name {
                let _ = writeln!(buf, "  match: community_set {}", community_set);
            }
            if let Some(name) = &entry.ext_community_set_name {
                let _ = writeln!(buf, "  match: ext-community {}", name);
            }
            if let Some(name) = &entry.large_community_set_name {
                let _ = writeln!(buf, "  match: large-community {}", name);
            }
            if let Some(as_path_set) = &entry.as_path_set_name {
                let _ = writeln!(buf, "  match: as_path_set {}", as_path_set);
            }
            if let Some(addr) = &entry.match_next_hop {
                let _ = writeln!(buf, "  match: next-hop {}", addr);
            }
            if let Some(m) = &entry.match_med {
                let _ = writeln!(buf, "  match: med {} {}", m.op_str(), m.value());
            }
            if let Some(m) = &entry.match_as_path_len {
                let _ = writeln!(buf, "  match: as-path-len {} {}", m.op_str(), m.value());
            }
            if let Some(m) = &entry.match_as_path_len_uniq {
                let _ = writeln!(
                    buf,
                    "  match: as-path-len-uniq {} {}",
                    m.op_str(),
                    m.value()
                );
            }
            if let Some(m) = &entry.match_local_pref {
                let _ = writeln!(
                    buf,
                    "  match: local-preference {} {}",
                    m.op_str(),
                    m.value()
                );
            }
            if let Some(m) = &entry.match_weight {
                let _ = writeln!(buf, "  match: weight {} {}", m.op_str(), m.value());
            }
            if let Some(origin) = &entry.match_origin {
                let _ = writeln!(buf, "  match: origin {:?}", origin);
            }
            if let Some(s) = &entry.local_pref {
                let _ = writeln!(buf, "  set: local-preference {} {}", s.op_str(), s.value());
            }
            if let Some(s) = &entry.med {
                let _ = writeln!(buf, "  set: med {} {}", s.op_str(), s.value());
            }
            if let Some(w) = &entry.weight {
                let _ = writeln!(buf, "  set: weight {}", w);
            }
            if let Some(cfg) = &entry.set_community {
                let suffix = match cfg.mode {
                    SetCommunityMode::Replace => "",
                    SetCommunityMode::Additive => " additive",
                    SetCommunityMode::Delete => " delete",
                };
                let _ = writeln!(buf, "  set: community {}{}", cfg.name, suffix);
            }
            if let Some(prepend) = &entry.set_as_path_prepend {
                let _ = writeln!(
                    buf,
                    "  set: as-path-prepend {} repeat {}",
                    prepend.asn, prepend.repeat
                );
            }
            if let Some(nh) = &entry.set_next_hop {
                let _ = writeln!(buf, "  set: next-hop {}", nh);
            }
            if let Some(o) = &entry.set_origin {
                let _ = writeln!(buf, "  set: origin {:?}", o);
            }
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use crate::policy::prefix::set::{PrefixSet, PrefixSetEntry};

    use super::*;

    #[test]
    fn policy_list() {
        use ipnet::Ipv4Net;
        use std::str::FromStr;

        // Create a prefix-set named "pset" with prefix 1.1.1.1/32
        let mut prefix_set = PrefixSet::default();
        let prefix = Ipv4Net::from_str("1.1.1.1/32").unwrap();
        prefix_set.insert(prefix.into(), PrefixSetEntry::default());

        // Create a policy-list with an entry that matches "pset" and permits.
        let mut plist = PolicyList::default();

        // Entry 10: match prefix-set "pset" and action permit.
        let entry = plist.entry(10);
        entry.prefix_set_name = Some("pset".to_string());
        entry.action = PolicyAction::Permit;

        // Verify the policy list configuration
        assert_eq!(plist.entry.len(), 1);
        let entry = plist.entry.get(&10).unwrap();
        assert_eq!(entry.prefix_set_name, Some("pset".to_string()));
        assert_eq!(entry.action, PolicyAction::Permit);

        // Verify prefix-set contains the correct prefix
        assert_eq!(prefix_set.len(), 1);
        assert!(prefix_set.contains_prefix(&prefix.into()));

        // Note: Default deny behavior is implicit - if no entry matches,
        // the policy should deny by default (this would be implemented
        // in the actual policy evaluation logic)
    }
}
