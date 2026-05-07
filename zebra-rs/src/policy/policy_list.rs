use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::Ipv4Addr;

use anyhow::{Context, Error, Result};
use bgp_packet::Origin;
use strum_macros::{Display, EnumString};

use crate::config::{Args, ConfigOp};

use super::{
    AsPathSet, AsPathSetConfig, CommunitySet, CommunitySetConfig, Policy, PrefixSet,
    PrefixSetConfig,
};

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PolicyList {
    pub entry: BTreeMap<u32, PolicyEntry>,
    pub default_action: Option<PolicyAction>,
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

#[derive(EnumString, Display, Clone, Debug, PartialEq)]
pub enum PolicyAction {
    #[strum(serialize = "accept")]
    Accept,
    #[strum(serialize = "pass")]
    Pass,
    #[strum(serialize = "reject")]
    Reject,
}

fn parse_origin(s: &str) -> Result<Origin> {
    match s {
        "igp" => Ok(Origin::Igp),
        "egp" => Ok(Origin::Egp),
        "incomplete" => Ok(Origin::Incomplete),
        other => Err(anyhow::anyhow!("invalid origin: {}", other)),
    }
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PolicyEntry {
    // Match.
    pub prefix_set_name: Option<String>,
    pub prefix_set: Option<PrefixSet>,
    pub community_set_name: Option<String>,
    pub community_set: Option<CommunitySet>,
    pub as_path_set_name: Option<String>,
    pub as_path_set: Option<AsPathSet>,
    pub next_hop_set_name: Option<String>,
    pub next_hop_set: Option<PrefixSet>,
    pub match_med_eq: Option<u32>,
    pub match_med_ge: Option<u32>,
    pub match_med_le: Option<u32>,
    pub match_origin: Option<Origin>,
    // Set.
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub set_community_name: Option<String>,
    pub set_community: Option<CommunitySet>,
    pub set_community_additive: bool,
    pub set_as_path_prepend: Option<Vec<u32>>,
    pub set_next_hop: Option<Ipv4Addr>,
    // Action.
    pub action: Option<PolicyAction>,
}

pub fn policy_entry_sync(
    policy_list: &mut PolicyList,
    prefix_set: &PrefixSetConfig,
    community_set: &CommunitySetConfig,
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
        if let Some(name) = &policy.as_path_set_name {
            if let Some(as_path_set) = as_path_set.config.get(name) {
                policy.as_path_set = Some(as_path_set.clone());
            } else {
                policy.as_path_set = None;
            }
        }
        if let Some(name) = &policy.next_hop_set_name {
            if let Some(prefix_set) = prefix_set.config.get(name) {
                policy.next_hop_set = Some(prefix_set.clone());
            } else {
                policy.next_hop_set = None;
            }
        }
        if let Some(name) = &policy.set_community_name {
            if let Some(community_set) = community_set.config.get(name) {
                policy.set_community = Some(community_set.clone());
            } else {
                policy.set_community = None;
            }
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

    pub fn commit<S: crate::policy::Syncer>(
        config: &mut BTreeMap<String, PolicyList>,
        cache: &mut BTreeMap<String, PolicyList>,
        prefix_config: &PrefixSetConfig,
        community_config: &CommunitySetConfig,
        as_path_config: &AsPathSetConfig,
        syncer: S,
    ) {
        while let Some((name, mut s)) = cache.pop_first() {
            if s.delete {
                syncer.policy_list_remove(&name);
                config.remove(&name);
            } else {
                policy_entry_sync(&mut s, prefix_config, community_config, as_path_config);
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
            .path("/entry/match/prefix-set")
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
            .path("/entry/match/community-set")
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
            .path("/entry/match/as-path-set")
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
            .path("/entry/match/next-hop-set")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let next_hop_set = args.string().context(ARG_ERR)?;
                entry.next_hop_set_name = Some(next_hop_set);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.next_hop_set_name = None;
                Ok(())
            })
            .path("/entry/match/med-eq")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_med_eq = Some(args.u32().context(ARG_ERR)?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_med_eq = None;
                Ok(())
            })
            .path("/entry/match/med-ge")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_med_ge = Some(args.u32().context(ARG_ERR)?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_med_ge = None;
                Ok(())
            })
            .path("/entry/match/med-le")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);
                entry.match_med_le = Some(args.u32().context(ARG_ERR)?);
                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.match_med_le = None;
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
            .path("/entry/set/local-preference")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let local_pref = args.u32().context(ARG_ERR)?;
                entry.local_pref = Some(local_pref);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.local_pref = None;
                Ok(())
            })
            .path("/entry/set/med")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let med = args.u32().context(ARG_ERR)?;
                entry.med = Some(med);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.med = None;
                Ok(())
            })
            .path("/entry/set/community-set")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let community_set = args.string().context(ARG_ERR)?;
                entry.set_community_name = Some(community_set);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.set_community_name = None;
                entry.set_community = None;
                Ok(())
            })
            .path("/entry/set/community-additive")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let additive = args.boolean().context(ARG_ERR)?;
                entry.set_community_additive = additive;

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.set_community_additive = false;
                Ok(())
            })
            .path("/entry/set/as-path-prepend")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let raw = args.string().context(ARG_ERR)?;
                let asns: Vec<u32> = raw
                    .split_whitespace()
                    .map(|s| s.parse::<u32>())
                    .collect::<Result<Vec<_>, _>>()
                    .context("as-path-prepend: invalid AS number")?;
                if asns.is_empty() {
                    anyhow::bail!("as-path-prepend: empty AS list");
                }
                entry.set_as_path_prepend = Some(asns);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
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
            .path("/entry/action")
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.entry(seq);

                let action: PolicyAction = args.string().context(ARG_ERR)?.parse()?;
                entry.action = Some(action);

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.action = None;
                Ok(())
            })
            .path("/default-action")
            .set(|policy, cache, name, _seq, args| {
                let _list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let _default_action = args.string().context(ARG_ERR)?;

                Ok(())
            })
            .del(|policy, cache, name, seq, _args| {
                let list = cache_lookup(policy, cache, &name).context(ARG_ERR)?;
                let entry = list.lookup(&seq).context(ARG_ERR)?;
                entry.action = None;
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
            if let Some(as_path_set) = &entry.as_path_set_name {
                let _ = writeln!(buf, "  match: as_path_set {}", as_path_set);
            }
            if let Some(next_hop_set) = &entry.next_hop_set_name {
                let _ = writeln!(buf, "  match: next_hop_set {}", next_hop_set);
            }
            if let Some(med) = &entry.match_med_eq {
                let _ = writeln!(buf, "  match: med eq {}", med);
            }
            if let Some(med) = &entry.match_med_ge {
                let _ = writeln!(buf, "  match: med ge {}", med);
            }
            if let Some(med) = &entry.match_med_le {
                let _ = writeln!(buf, "  match: med le {}", med);
            }
            if let Some(origin) = &entry.match_origin {
                let _ = writeln!(buf, "  match: origin {:?}", origin);
            }
            if let Some(local_pref) = &entry.local_pref {
                let _ = writeln!(buf, "  set: local-pref {}", local_pref);
            }
            if let Some(med) = &entry.med {
                let _ = writeln!(buf, "  set: med {}", med);
            }
            if let Some(set_community) = &entry.set_community_name {
                let suffix = if entry.set_community_additive {
                    " additive"
                } else {
                    ""
                };
                let _ = writeln!(buf, "  set: community {}{}", set_community, suffix);
            }
            if let Some(prepend) = &entry.set_as_path_prepend {
                let s = prepend
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                let _ = writeln!(buf, "  set: as-path-prepend {}", s);
            }
            if let Some(nh) = &entry.set_next_hop {
                let _ = writeln!(buf, "  set: next-hop {}", nh);
            }
        }
        if let Some(default_action) = &policy.default_action {
            let _ = writeln!(buf, " default-action: {}", default_action);
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
        prefix_set
            .prefixes
            .insert(prefix.into(), PrefixSetEntry::default());

        // Create a policy-list with entry that matches "pset" and has action accept (permit)
        let mut plist = PolicyList::default();

        // Entry 10: match prefix-set "pset" and action accept
        let entry = plist.entry(10);
        entry.prefix_set_name = Some("pset".to_string());
        entry.action = Some(PolicyAction::Accept);

        // Verify the policy list configuration
        assert_eq!(plist.entry.len(), 1);
        let entry = plist.entry.get(&10).unwrap();
        assert_eq!(entry.prefix_set_name, Some("pset".to_string()));

        match &entry.action {
            Some(PolicyAction::Accept) => {
                // Test passes - action is Accept (permit)
            }
            _ => panic!("Expected PolicyAction::Accept"),
        }

        // Verify prefix-set contains the correct prefix
        assert_eq!(prefix_set.prefixes.len(), 1);
        assert!(prefix_set.prefixes.contains_key(&prefix.into()));

        // Note: Default deny behavior is implicit - if no entry matches,
        // the policy should deny by default (this would be implemented
        // in the actual policy evaluation logic)
    }
}
