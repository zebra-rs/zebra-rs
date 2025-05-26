use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::entry::RibEntry;
use crate::rib::{Message, RibType};

use super::MplsRoute;

pub struct MplsConfig {
    pub config: MplsConfigMap,
    pub cache: MplsConfigMap,
    builder: ConfigBuilder,
}

impl MplsConfig {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: config_builder(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const PREFIX_ERR: &str = "missing prefix arg";

        let func = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;
        let label: u32 = args.u32().context(PREFIX_ERR)?;

        func(&mut self.config, &mut self.cache, label, &mut args)
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        while let Some((p, s)) = self.cache.pop_first() {
            {
                if s.delete {
                    // self.config.remove(&p);
                    // let msg = Message::Ipv4Del {
                    //     prefix: p,
                    //     rib: RibEntry::new(RibType::Static),
                    // };
                    // let _ = tx.send(msg);
                } else {
                    // let entry = s.to_entry();
                    // self.config.insert(p, s);
                    // if let Some(rib) = entry {
                    //     let msg = Message::Ipv4Add { prefix: p, rib };
                    //     let _ = tx.send(msg);
                    // }
                }
            }
        }
    }
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    pub map: BTreeMap<(String, ConfigOp), Handler>,
}

type MplsConfigMap = BTreeMap<u32, MplsRoute>;

type Handler = fn(
    config: &mut MplsConfigMap,
    cache: &mut MplsConfigMap,
    label: u32,
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

fn config_get(config: &MplsConfigMap, label: u32) -> MplsRoute {
    let Some(entry) = config.get(&label) else {
        return MplsRoute::default();
    };
    entry.clone()
}

fn config_lookup(config: &MplsConfigMap, label: u32) -> Option<MplsRoute> {
    let entry = config.get(&label)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a MplsConfigMap,
    cache: &'a mut MplsConfigMap,
    label: &'a u32,
) -> Option<&'a mut MplsRoute> {
    if cache.get(label).is_none() {
        cache.insert(*label, config_get(config, *label));
    }
    cache.get_mut(label)
}

fn cache_lookup<'a>(
    config: &'a MplsConfigMap,
    cache: &'a mut MplsConfigMap,
    label: &'a u32,
) -> Option<&'a mut MplsRoute> {
    if cache.get(label).is_none() {
        cache.insert(*label, config_lookup(config, *label)?);
    }
    let cache = cache.get_mut(label)?;
    if cache.delete {
        None
    } else {
        Some(cache)
    }
}

fn config_builder() -> ConfigBuilder {
    const CONFIG_ERR: &str = "missing config";
    const NEXTHOP_ERR: &str = "missing nexthop address";
    const METRIC_ERR: &str = "missing metric arg";
    const DISTANCE_ERR: &str = "missing distance arg";
    const WEIGHT_ERR: &str = "missing weight arg";

    ConfigBuilder::default()
        .path("/routing/static/mpls/label")
        .set(|config, cache, label, _| {
            let _ = cache_get(config, cache, &label).context(CONFIG_ERR)?;
            Ok(())
        })
        .del(|config, cache, label, _| {
            if let Some(st) = cache.get_mut(&label) {
                st.delete = true;
            } else {
                let mut st = config_lookup(config, label).context(CONFIG_ERR)?;
                st.delete = true;
                cache.insert(label, st);
            }
            Ok(())
        })
        .path("/routing/static/mpls/label/nexthop")
        .set(|config, cache, label, args| {
            let s = cache_get(config, cache, &label).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let _ = s.nexthops.entry(naddr).or_default();
            Ok(())
        })
        .del(|config, cache, label, args| {
            let s = cache_lookup(config, cache, &label).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            s.nexthops.remove(&naddr).context(CONFIG_ERR)?;
            Ok(())
        })
        .path("/routing/static/mpls/label/nexthop/outgoing-label")
        .set(|config, cache, label, args| {
            let s = cache_get(config, cache, &label).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            Ok(())
        })
        .del(|config, cache, label, args| {
            let s = cache_lookup(config, cache, &label).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            Ok(())
        })
}
