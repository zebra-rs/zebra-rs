use std::collections::BTreeMap;

use anyhow::{Context, Result};

use crate::config::{Args, ConfigOp};

use super::PrefixSet;

#[derive(Default)]
pub struct PrefixSetConfig {
    pub config: BTreeMap<String, PrefixSet>,
    pub cache: BTreeMap<String, PrefixSet>,
    builder: ConfigBuilder,
}

impl PrefixSetConfig {
    pub fn new() -> Self {
        PrefixSetConfig {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const PREFIX_SET_NAME_ERR: &str = "missing prefix set name arg";

        let handler = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name = args.string().context(PREFIX_SET_NAME_ERR)?;

        handler(&mut self.config, &mut self.cache, &name, &mut args)
    }

    // TODO: can we move the code to here?
    // pub fn commit(&mut self, syncer: impl Syncer) {
    //     while let Some((name, s)) = self.cache.pop_first() {
    //         if s.delete {
    //             // Notify subscribed entity for prefix-set.
    //             syncer.prefix_set_remove(&name);
    //             self.config.remove(&name);
    //         } else {
    //             self.config.insert(name, s);
    //         }
    //     }
    // }
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    config: &mut BTreeMap<String, PrefixSet>,
    cache: &mut BTreeMap<String, PrefixSet>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(plist: &BTreeMap<String, PrefixSet>, name: &String) -> PrefixSet {
    let Some(entry) = plist.get(name) else {
        return PrefixSet::default();
    };
    entry.clone()
}

fn config_lookup(plist: &BTreeMap<String, PrefixSet>, name: &String) -> Option<PrefixSet> {
    let entry = plist.get(name)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, PrefixSet>,
    cache: &'a mut BTreeMap<String, PrefixSet>,
    name: &'a String,
) -> Option<&'a mut PrefixSet> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, PrefixSet>,
    cache: &'a mut BTreeMap<String, PrefixSet>,
    name: &'a String,
) -> Option<&'a mut PrefixSet> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_lookup(config, name)?);
    }
    let cache = cache.get_mut(name)?;
    if cache.delete { None } else { Some(cache) }
}

impl ConfigBuilder {
    pub fn new() -> Self {
        const CONFIG_ERR: &str = "missing config";
        const PREFIX_ERR: &str = "missing prefix";
        const LE_ERR: &str = "missing le";
        const EQ_ERR: &str = "missing eq";
        const GE_ERR: &str = "missing ge";

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
            .path("/prefixes")
            .set(|config, cache, name, args| {
                let prefix = args.net().context(PREFIX_ERR)?;
                let set = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let _entry = set.prefixes.entry(prefix).or_default();
                Ok(())
            })
            .del(|config, cache, name, args| {
                let prefix = args.net().context(PREFIX_ERR)?;
                let set = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                set.prefixes.remove(&prefix).context(CONFIG_ERR)?;
                Ok(())
            })
            .path("/prefixes/le")
            .set(|config, cache, name, args| {
                let prefix = args.net().context(PREFIX_ERR)?;
                let le = args.u8().context(LE_ERR)?;

                let set = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let entry = set.prefixes.entry(prefix).or_default();
                entry.le = Some(le);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let prefix = args.net().context(PREFIX_ERR)?;

                let set = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                let entry = set.prefixes.get_mut(&prefix).context(LE_ERR)?;
                entry.le = None;
                Ok(())
            })
            .path("/prefixes/eq")
            .set(|config, cache, name, args| {
                let prefix = args.net().context(PREFIX_ERR)?;
                let eq = args.u8().context(EQ_ERR)?;

                let set = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let entry = set.prefixes.entry(prefix).or_default();
                entry.eq = Some(eq);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let prefix = args.net().context(PREFIX_ERR)?;

                let set = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                let entry = set.prefixes.get_mut(&prefix).context(EQ_ERR)?;
                entry.eq = None;
                Ok(())
            })
            .path("/prefixes/ge")
            .set(|config, cache, name, args| {
                let prefix = args.net().context(PREFIX_ERR)?;
                let ge = args.u8().context(GE_ERR)?;

                let set = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let entry = set.prefixes.entry(prefix).or_default();
                entry.ge = Some(ge);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let prefix = args.net().context(PREFIX_ERR)?;

                let set = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                let entry = set.prefixes.get_mut(&prefix).context(GE_ERR)?;
                entry.ge = None;
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/prefix-set";
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
