use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::{AddrGenMode, Message};

use super::VxlanConfig;

pub struct VxlanBuilder {
    pub config: BTreeMap<String, VxlanConfig>,
    pub cache: BTreeMap<String, VxlanConfig>,
    builder: ConfigBuilder,
}

impl VxlanBuilder {
    pub fn new() -> Self {
        VxlanBuilder {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const BRIDGE_ERR: &str = "missing bridge name argument";

        let func = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name: String = args.string().context(BRIDGE_ERR)?;

        func(&mut self.config, &mut self.cache, &name, &mut args)
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        while let Some((name, config)) = self.cache.pop_first() {
            if config.delete {
                self.config.remove(&name);
                let _ = tx.send(Message::VxlanDel { name });
            } else {
                self.config.insert(name.clone(), config.clone());
                let _ = tx.send(Message::VxlanAdd { name, config });
            }
        }
    }
}

type Handler = fn(
    config: &mut BTreeMap<String, VxlanConfig>,
    cache: &mut BTreeMap<String, VxlanConfig>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(config: &BTreeMap<String, VxlanConfig>, name: &String) -> VxlanConfig {
    let Some(entry) = config.get(name) else {
        return VxlanConfig::default();
    };
    entry.clone()
}

fn config_lookup(config: &BTreeMap<String, VxlanConfig>, name: &String) -> Option<VxlanConfig> {
    let entry = config.get(name)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, VxlanConfig>,
    cache: &'a mut BTreeMap<String, VxlanConfig>,
    name: &'a String,
) -> Option<&'a mut VxlanConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, VxlanConfig>,
    cache: &'a mut BTreeMap<String, VxlanConfig>,
    name: &'a String,
) -> Option<&'a mut VxlanConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.clone(), config_lookup(config, name)?);
    }
    let cache = cache.get_mut(name)?;
    if cache.delete { None } else { Some(cache) }
}

fn parse_addr_gen_mode(mode: &String) -> Option<AddrGenMode> {
    match mode.as_str() {
        "none" => Some(AddrGenMode::None),
        "eui64" => Some(AddrGenMode::Eui64),
        "stable-secret" => Some(AddrGenMode::StableSecret),
        "random" => Some(AddrGenMode::Random),
        _ => None,
    }
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        const CONFIG_ERR: &str = "missing config";
        const VNI_ERR: &str = "VNI format error";
        const DPORT_ERR: &str = "destination port format error";
        const ADDR_ERR: &str = "local address format error";
        const ADDR_GEN_MODE_ERR: &str = "address gen mode format error";

        ConfigBuilder::default()
            .path("")
            .set(|config, cache, name, args| {
                let _ = cache_get(config, cache, name).context(CONFIG_ERR)?;
                Ok(())
            })
            .del(|config, cache, name, args| {
                if let Some(s) = cache.get_mut(name) {
                    s.delete = true;
                } else {
                    let mut s = config_lookup(config, name).context(CONFIG_ERR)?;
                    s.delete = true;
                    cache.insert(name.clone(), s);
                }
                Ok(())
            })
            .path("/vni")
            .set(|config, cache, name, args| {
                let vni = args.u32().context(VNI_ERR)?;

                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.vni = Some(vni);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.vni = None;
                Ok(())
            })
            .path("/dest-port")
            .set(|config, cache, name, args| {
                let dport = args.u16().context(DPORT_ERR)?;

                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.dport = Some(dport);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.dport = None;
                Ok(())
            })
            .path("/local-address")
            .set(|config, cache, name, args| {
                let addr = if let Some(addr) = args.v4addr() {
                    IpAddr::V4(addr)
                } else if let Some(addr) = args.v6addr() {
                    IpAddr::V6(addr)
                } else {
                    anyhow::bail!(ADDR_ERR);
                };

                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.local_addr = Some(addr);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.local_addr = None;
                Ok(())
            })
            .path("/address-gen-mode")
            .set(|config, cache, name, args| {
                let mode = args.string().context(ADDR_GEN_MODE_ERR)?;
                let mode = parse_addr_gen_mode(&mode).context(ADDR_GEN_MODE_ERR)?;

                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.addr_gen_mode = Some(mode);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.addr_gen_mode = None;
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/vxlan";
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
