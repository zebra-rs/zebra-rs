use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::entry::RibEntry;
use crate::rib::{Message, RibType};

use super::StaticRoute;

pub struct StaticConfig {
    pub config: BTreeMap<Ipv4Net, StaticRoute>,
    pub cache: BTreeMap<Ipv4Net, StaticRoute>,
    builder: ConfigBuilder,
}

impl StaticConfig {
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
        let prefix: Ipv4Net = args.v4net().context(PREFIX_ERR)?;

        func(&mut self.config, &mut self.cache, &prefix, &mut args)
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        while let Some((p, s)) = self.cache.pop_first() {
            if s.delete {
                self.config.remove(&p);
                let msg = Message::Ipv4Del {
                    prefix: p,
                    rib: RibEntry::new(RibType::Static),
                };
                let _ = tx.send(msg);
            } else {
                let entry = s.to_entry();
                self.config.insert(p, s);
                if let Some(rib) = entry {
                    let msg = Message::Ipv4Add { prefix: p, rib };
                    let _ = tx.send(msg);
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

type Handler = fn(
    config: &mut BTreeMap<Ipv4Net, StaticRoute>,
    cache: &mut BTreeMap<Ipv4Net, StaticRoute>,
    prefix: &Ipv4Net,
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

fn config_get(config: &BTreeMap<Ipv4Net, StaticRoute>, prefix: &Ipv4Net) -> StaticRoute {
    let Some(entry) = config.get(prefix) else {
        return StaticRoute::default();
    };
    entry.clone()
}

fn config_lookup(config: &BTreeMap<Ipv4Net, StaticRoute>, prefix: &Ipv4Net) -> Option<StaticRoute> {
    let entry = config.get(prefix)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<Ipv4Net, StaticRoute>,
    cache: &'a mut BTreeMap<Ipv4Net, StaticRoute>,
    prefix: &'a Ipv4Net,
) -> Option<&'a mut StaticRoute> {
    if cache.get(prefix).is_none() {
        cache.insert(*prefix, config_get(config, prefix));
    }
    cache.get_mut(prefix)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<Ipv4Net, StaticRoute>,
    cache: &'a mut BTreeMap<Ipv4Net, StaticRoute>,
    prefix: &'a Ipv4Net,
) -> Option<&'a mut StaticRoute> {
    if cache.get(prefix).is_none() {
        cache.insert(*prefix, config_lookup(config, prefix)?);
    }
    let cache = cache.get_mut(prefix)?;
    if cache.delete { None } else { Some(cache) }
}

fn config_builder() -> ConfigBuilder {
    const CONFIG_ERR: &str = "missing config";
    const NEXTHOP_ERR: &str = "missing nexthop address";
    const METRIC_ERR: &str = "missing metric arg";
    const DISTANCE_ERR: &str = "missing distance arg";
    const WEIGHT_ERR: &str = "missing weight arg";

    ConfigBuilder::default()
        .path("/routing/static/ipv4/route")
        .set(|config, cache, prefix, _args| {
            let _ = cache_get(config, cache, prefix).context(CONFIG_ERR)?;
            Ok(())
        })
        .del(|config, cache, prefix, _args| {
            if let Some(st) = cache.get_mut(prefix) {
                st.delete = true;
            } else {
                let mut st = config_lookup(config, prefix).context(CONFIG_ERR)?;
                st.delete = true;
                cache.insert(*prefix, st);
            }
            Ok(())
        })
        .path("/routing/static/ipv4/route/metric")
        .set(|config, cache, prefix, args| {
            let s = cache_get(config, cache, prefix).context(CONFIG_ERR)?;
            s.metric = Some(args.u32().context(METRIC_ERR)?);
            Ok(())
        })
        .del(|config, cache, prefix, _args| {
            let s = cache_lookup(config, cache, prefix).context(CONFIG_ERR)?;
            s.metric = None;
            Ok(())
        })
        .path("/routing/static/ipv4/route/distance")
        .set(|config, cache, prefix, args| {
            let s = cache_get(config, cache, prefix).context(CONFIG_ERR)?;
            s.distance = Some(args.u8().context(DISTANCE_ERR)?);
            Ok(())
        })
        .del(|config, cache, prefix, _args| {
            let s = cache_lookup(config, cache, prefix).context(CONFIG_ERR)?;
            s.distance = None;
            Ok(())
        })
        .path("/routing/static/ipv4/route/nexthop")
        .set(|config, cache, prefix, args| {
            let s = cache_get(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let _ = s.nexthops.entry(naddr).or_default();
            Ok(())
        })
        .del(|config, cache, prefix, args| {
            let s = cache_lookup(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            s.nexthops.remove(&naddr).context(CONFIG_ERR)?;
            Ok(())
        })
        .path("/routing/static/ipv4/route/nexthop/metric")
        .set(|config, cache, prefix, args| {
            let s = cache_get(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            n.metric = Some(args.u32().context(METRIC_ERR)?);
            Ok(())
        })
        .del(|config, cache, prefix, args| {
            let s = cache_lookup(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            n.metric = None;
            Ok(())
        })
        .path("/routing/static/ipv4/route/nexthop/weight")
        .set(|config, cache, prefix, args| {
            let s = cache_get(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            n.weight = Some(args.u8().context(WEIGHT_ERR)?);
            Ok(())
        })
        .del(|config, cache, prefix, args| {
            let s = cache_lookup(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            n.weight = None;
            Ok(())
        })
}
