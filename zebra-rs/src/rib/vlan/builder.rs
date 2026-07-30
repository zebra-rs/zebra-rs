use std::collections::BTreeMap;

use anyhow::{Context, Result};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::Message;

use super::VlanConfig;

pub struct VlanBuilder {
    pub config: BTreeMap<String, VlanConfig>,
    pub cache: BTreeMap<String, VlanConfig>,
    builder: ConfigBuilder,
}

impl VlanBuilder {
    pub fn new() -> Self {
        VlanBuilder {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const VLAN_ERR: &str = "missing vlan name argument";

        let func = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name: String = args.string().context(VLAN_ERR)?;

        func(&mut self.config, &mut self.cache, &name, &mut args)
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        while let Some((name, config)) = self.cache.pop_first() {
            if config.delete {
                self.config.remove(&name);
                let _ = tx.send(Message::VlanDel { name });
            } else {
                self.config.insert(name.clone(), config.clone());
                let _ = tx.send(Message::VlanAdd { name, config });
            }
        }
    }
}

type Handler = fn(
    config: &mut BTreeMap<String, VlanConfig>,
    cache: &mut BTreeMap<String, VlanConfig>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(config: &BTreeMap<String, VlanConfig>, name: &String) -> VlanConfig {
    let Some(entry) = config.get(name) else {
        return VlanConfig::default();
    };
    entry.clone()
}

fn config_lookup(config: &BTreeMap<String, VlanConfig>, name: &String) -> Option<VlanConfig> {
    let entry = config.get(name)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, VlanConfig>,
    cache: &'a mut BTreeMap<String, VlanConfig>,
    name: &'a String,
) -> Option<&'a mut VlanConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, VlanConfig>,
    cache: &'a mut BTreeMap<String, VlanConfig>,
    name: &'a String,
) -> Option<&'a mut VlanConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.clone(), config_lookup(config, name)?);
    }
    let cache = cache.get_mut(name)?;
    if cache.delete { None } else { Some(cache) }
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        const CONFIG_ERR: &str = "missing config";
        const INTERFACE_ERR: &str = "parent interface format error";
        const VLAN_ID_ERR: &str = "vlan-id format error";

        ConfigBuilder::default()
            .path("")
            .set(|config, cache, name, _args| {
                let _ = cache_get(config, cache, name).context(CONFIG_ERR)?;
                Ok(())
            })
            .del(|config, cache, name, _args| {
                if let Some(s) = cache.get_mut(name) {
                    s.delete = true;
                } else {
                    let mut s = config_lookup(config, name).context(CONFIG_ERR)?;
                    s.delete = true;
                    cache.insert(name.clone(), s);
                }
                Ok(())
            })
            .path("/interface")
            .set(|config, cache, name, args| {
                let interface = args.string().context(INTERFACE_ERR)?;

                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.interface = Some(interface);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.interface = None;
                Ok(())
            })
            .path("/vlan-id")
            .set(|config, cache, name, args| {
                let vlan_id = args.u16().context(VLAN_ID_ERR)?;

                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.vlan_id = Some(vlan_id);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.vlan_id = None;
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/vlan";
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
