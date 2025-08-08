use anyhow::{Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::{Action, Policy};

use crate::config::{Args, ConfigOp};

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

    pub fn commit(&mut self) {
        while let Some((name, s)) = self.cache.pop_first() {
            if s.delete {
                self.config.remove(&name);
            } else {
                //
            }
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct PrefixSet {
    pub entry: BTreeMap<u32, PrefixListEntry>,
    pub delete: bool,
}

#[derive(Clone, Debug)]
pub struct PrefixListEntry {
    pub prefix: Ipv4Net,
    pub le: Option<u8>,
    pub eq: Option<u8>,
    pub ge: Option<u8>,
}

impl PrefixListEntry {
    pub fn apply(&self, prefix: &Ipv4Net) -> bool {
        if self.prefix.contains(prefix) {
            if let Some(le) = self.le {
                return prefix.prefix_len() <= le;
            }
            if let Some(eq) = self.eq {
                return prefix.prefix_len() == eq;
            }
            if let Some(ge) = self.ge {
                return prefix.prefix_len() >= ge;
            }
            self.prefix.prefix_len() == prefix.prefix_len()
        } else {
            false
        }
    }
}

impl Default for PrefixListEntry {
    fn default() -> Self {
        Self {
            prefix: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
            le: None,
            eq: None,
            ge: None,
        }
    }
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
    plist: &'a BTreeMap<String, PrefixSet>,
    cache: &'a mut BTreeMap<String, PrefixSet>,
    name: &'a String,
) -> Option<&'a mut PrefixSet> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(plist, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    plist: &'a BTreeMap<String, PrefixSet>,
    cache: &'a mut BTreeMap<String, PrefixSet>,
    name: &'a String,
) -> Option<&'a mut PrefixSet> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_lookup(plist, name)?);
    }
    let cache = cache.get_mut(name)?;
    if cache.delete { None } else { Some(cache) }
}

pub fn prefix_ipv4_commit(
    plist: &mut BTreeMap<String, PrefixSet>,
    cache: &mut BTreeMap<String, PrefixSet>,
) {
    while let Some((n, s)) = cache.pop_first() {
        if s.delete {
            plist.remove(&n);
        } else {
            plist.insert(n, s);
        }
    }
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
                let prefix = args.v4net().context(PREFIX_ERR)?;
                // let config = cache_get(config, cache, name).context(CONFIG_ERR)?;
                // let seq = config.entry.entry(seq).or_default();
                // seq.prefix = prefix;
                Ok(())
            })
            .del(|config, cache, name, _args| {
                // let config = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                // let seq = config.entry.get_mut(&seq).context(PREFIX_ERR)?;
                // seq.prefix = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
                Ok(())
            })
            .path("/prefixes/le")
            .set(|config, cache, name, args| {
                // let le = args.u8().context(LE_ERR)?;
                // let config = cache_get(config, cache, name).context(CONFIG_ERR)?;
                // let seq = config.entry.entry(seq).or_default();
                // seq.le = Some(le);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                // let config = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                // let seq = config.entry.get_mut(&seq).context(LE_ERR)?;
                // seq.le = None;
                Ok(())
            })
            .path("/prefixes/eq")
            .set(|config, cache, name, args| {
                // let eq = args.u8().context(EQ_ERR)?;
                // let config = cache_get(config, cache, name).context(CONFIG_ERR)?;
                // let seq = config.entry.entry(seq).or_default();
                // seq.eq = Some(eq);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                // let config = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                // let seq = config.entry.get_mut(&seq).context(EQ_ERR)?;
                // seq.eq = None;
                Ok(())
            })
            .path("/prefixes/ge")
            .set(|config, cache, name, args| {
                // let ge = args.u8().context(GE_ERR)?;
                // let config = cache_get(config, cache, name).context(CONFIG_ERR)?;
                // let seq = config.entry.entry(seq).or_default();
                // seq.ge = Some(ge);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                // let config = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                // let seq = config.entry.get_mut(&seq).context(GE_ERR)?;
                // seq.ge = None;
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

pub fn plist_ipv4_show(plist: &BTreeMap<String, PrefixSet>) {
    for (n, p) in plist.iter() {
        println!("name: {}", n);
        for (seq, e) in p.entry.iter() {
            println!(
                " seq: {} prefix: {} le: {} eq: {} ge: {}",
                seq,
                e.prefix,
                e.le.unwrap_or(0),
                e.eq.unwrap_or(0),
                e.ge.unwrap_or(0)
            );
        }
    }
}
