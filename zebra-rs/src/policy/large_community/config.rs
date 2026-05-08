use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::config::{Args, ConfigOp};

use super::{LargeCommunityMatcher, LargeCommunitySet};

#[derive(Default)]
pub struct LargeCommunitySetConfig {
    pub config: BTreeMap<String, LargeCommunitySet>,
    pub cache: BTreeMap<String, LargeCommunitySet>,
    builder: ConfigBuilder,
}

impl LargeCommunitySetConfig {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const NAME_ERR: &str = "missing large-community-set name arg";

        let handler = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;
        let name = args.string().context(NAME_ERR)?;
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
    config: &mut BTreeMap<String, LargeCommunitySet>,
    cache: &mut BTreeMap<String, LargeCommunitySet>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(clist: &BTreeMap<String, LargeCommunitySet>, name: &String) -> LargeCommunitySet {
    let Some(entry) = clist.get(name) else {
        return LargeCommunitySet {
            vals: BTreeSet::new(),
            delete: false,
        };
    };
    LargeCommunitySet {
        vals: entry.vals.clone(),
        delete: entry.delete,
    }
}

fn config_lookup(
    clist: &BTreeMap<String, LargeCommunitySet>,
    name: &String,
) -> Option<LargeCommunitySet> {
    let entry = clist.get(name)?;
    Some(LargeCommunitySet {
        vals: entry.vals.clone(),
        delete: entry.delete,
    })
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, LargeCommunitySet>,
    cache: &'a mut BTreeMap<String, LargeCommunitySet>,
    name: &'a String,
) -> Option<&'a mut LargeCommunitySet> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, LargeCommunitySet>,
    cache: &'a mut BTreeMap<String, LargeCommunitySet>,
    name: &'a String,
) -> Option<&'a mut LargeCommunitySet> {
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
            .path("/members")
            .set(|config, cache, name, args| {
                let set = cache_get(config, cache, name).context(CONFIG_ERR)?;
                while let Some(member_str) = args.string() {
                    if let Ok(matcher) = LargeCommunityMatcher::from_str(&member_str) {
                        set.vals.insert(matcher);
                    }
                }
                Ok(())
            })
            .del(|config, cache, name, args| {
                let member_str = args.string().context(MEMBER_ERR)?;
                let set = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Ok(matcher) = LargeCommunityMatcher::from_str(&member_str) {
                    let key = format!("{:?}", matcher);
                    set.vals.retain(|x| format!("{:?}", x) != key);
                }
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/large-community-set";
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
