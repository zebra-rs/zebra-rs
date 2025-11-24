use std::collections::BTreeMap;
use std::fmt::Write;

use anyhow::{Context, Error, Result};
use strum_macros::{Display, EnumString};

use crate::config::{Args, ConfigOp};

use super::{Policy, PrefixSet};

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

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PolicyEntry {
    // Match.
    pub prefix_set_name: Option<String>,
    pub prefix_set: Option<PrefixSet>,
    pub community_set_name: Option<String>,
    // Set.
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    // Action.
    pub action: Option<PolicyAction>,
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
        if !path.starts_with("/policy-options/policy/entry") {
            handler(&mut self.config, &mut self.cache, name, 0, &mut args)
        } else {
            let seq = args.u32().context(ENTRY_SEQ_ERR)?;
            handler(&mut self.config, &mut self.cache, name, seq, &mut args)
        }
    }

    pub fn commit(&mut self) {
        while let Some((name, s)) = self.cache.pop_first() {
            if s.delete {
                self.config.remove(&name);
            } else {
                self.config.insert(name, s);
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
            .set(|policy, cache, name, seq, args| {
                let list = cache_get(policy, cache, &name).context(ARG_ERR)?;
                let default_action = args.string().context(ARG_ERR)?;

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
        let prefix = "/policy-options/policy";
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
        writeln!(buf, "policy-list: {}", name);
        for (seq, entry) in policy.entry.iter() {
            writeln!(buf, " entry: {}", seq);
            if let Some(prefix_set) = &entry.prefix_set_name {
                writeln!(buf, "  match: prefix_set {}", prefix_set);
            }
            if let Some(local_pref) = &entry.local_pref {
                writeln!(buf, "  set: local-pref {}", local_pref);
            }
            if let Some(med) = &entry.med {
                writeln!(buf, "  set: med {}", med);
            }
        }
        if let Some(default_action) = &policy.default_action {
            writeln!(buf, " default-action: {}", default_action);
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use crate::policy::set::{PrefixSet, PrefixSetEntry};

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
