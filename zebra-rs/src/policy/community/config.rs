use std::collections::BTreeMap;

use anyhow::{Context, Result};

use crate::config::{Args, ConfigOp};

use super::{CommunitySet, parse_community_set};

#[derive(Default)]
pub struct CommunitySetConfig {
    pub config: BTreeMap<String, CommunitySet>,
    pub cache: BTreeMap<String, CommunitySet>,
    builder: ConfigBuilder,
}

impl CommunitySetConfig {
    pub fn new() -> Self {
        CommunitySetConfig {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const COMMUNITY_SET_NAME_ERR: &str = "missing community set name arg";

        let handler = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name = args.string().context(COMMUNITY_SET_NAME_ERR)?;

        handler(&mut self.config, &mut self.cache, &name, &mut args)
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

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    config: &mut BTreeMap<String, CommunitySet>,
    cache: &mut BTreeMap<String, CommunitySet>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(clist: &BTreeMap<String, CommunitySet>, name: &String) -> CommunitySet {
    let Some(entry) = clist.get(name) else {
        return CommunitySet {
            vals: Vec::new(),
            delete: false,
        };
    };
    CommunitySet {
        vals: entry.vals.clone(),
        delete: entry.delete,
    }
}

fn config_lookup(clist: &BTreeMap<String, CommunitySet>, name: &String) -> Option<CommunitySet> {
    let entry = clist.get(name)?;
    Some(CommunitySet {
        vals: entry.vals.clone(),
        delete: entry.delete,
    })
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, CommunitySet>,
    cache: &'a mut BTreeMap<String, CommunitySet>,
    name: &'a String,
) -> Option<&'a mut CommunitySet> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, CommunitySet>,
    cache: &'a mut BTreeMap<String, CommunitySet>,
    name: &'a String,
) -> Option<&'a mut CommunitySet> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_lookup(config, name)?);
    }
    let cache = cache.get_mut(name)?;
    if cache.delete { None } else { Some(cache) }
}

impl ConfigBuilder {
    pub fn new() -> Self {
        const CONFIG_ERR: &str = "missing config";
        const MEMBER_ERR: &str = "missing member";

        ConfigBuilder::default()
            .path("")
            .set(|config, cache, name, _args| {
                let _ = cache_get(config, cache, name).context(CONFIG_ERR)?;
                Ok(())
            })
            .del(|config, cache, name, _args| {
                if let Some(list) = cache.get_mut(name) {
                    list.delete = true;
                } else {
                    let mut list = config_lookup(config, name).context(CONFIG_ERR)?;
                    list.delete = true;
                    cache.insert(name.to_string(), list);
                }
                Ok(())
            })
            .path("/member")
            .set(|config, cache, name, args| {
                let member_str = args.string().context(MEMBER_ERR)?;
                let set = cache_get(config, cache, name).context(CONFIG_ERR)?;

                // Parse the community member string (e.g., "rt:100:200", "no-export", etc.)
                let matcher = parse_community_set(&member_str).context(MEMBER_ERR)?;
                set.vals.push(matcher);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let member_str = args.string().context(MEMBER_ERR)?;
                let set = cache_lookup(config, cache, name).context(CONFIG_ERR)?;

                // Parse the community member to find and remove it
                if let Some(matcher) = parse_community_set(&member_str) {
                    // Find and remove the matching member
                    // Note: We need to compare by debug representation since CommunityMatcher
                    // doesn't implement PartialEq
                    let matcher_debug = format!("{:?}", matcher);
                    set.vals.retain(|x| format!("{:?}", x) != matcher_debug);
                }
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/community-set";
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
