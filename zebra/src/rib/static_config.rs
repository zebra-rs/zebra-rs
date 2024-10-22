use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use super::fib::FibHandle;
use super::Rib;
use super::RibEntries;
use crate::config::{Args, ConfigOp};
use crate::rib::StaticRoute;

fn static_get(rib: &PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net) -> StaticRoute {
    let Some(entry) = rib.get(prefix) else {
        return StaticRoute::default();
    };
    let Some(st) = &entry.st else {
        return StaticRoute::default();
    };
    st.clone()
}

fn static_lookup(rib: &PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net) -> Option<StaticRoute> {
    let entry = rib.get(prefix)?;
    let Some(st) = &entry.st else {
        return None;
    };
    Some(st.clone())
}

fn cache_get<'a>(
    rib: &'a PrefixMap<Ipv4Net, RibEntries>,
    cache: &'a mut BTreeMap<Ipv4Net, StaticRoute>,
    prefix: &'a Ipv4Net,
) -> Option<&'a mut StaticRoute> {
    if cache.get(prefix).is_none() {
        cache.insert(*prefix, static_get(rib, prefix));
    }
    cache.get_mut(prefix)
}

fn cache_lookup<'a>(
    rib: &'a PrefixMap<Ipv4Net, RibEntries>,
    cache: &'a mut BTreeMap<Ipv4Net, StaticRoute>,
    prefix: &'a Ipv4Net,
) -> Option<&'a mut StaticRoute> {
    if cache.get(prefix).is_none() {
        cache.insert(*prefix, static_lookup(rib, prefix)?);
    }
    let Some(cache) = cache.get_mut(prefix) else {
        return None;
    };
    if cache.delete {
        None
    } else {
        Some(cache)
    }
}
#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
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

    pub fn exec(&self, path: &str, op: ConfigOp, rib: &mut Rib, mut args: Args) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const PREFIX_ERR: &str = "missing prefix arg";

        let func = self.map.get(&(path.to_string(), op)).context(CONFIG_ERR)?;
        let prefix: Ipv4Net = args.v4net().context(PREFIX_ERR)?;
        func(&mut rib.rib, &mut rib.cache, &prefix, &mut args)
    }
}

fn static_config_builder() -> ConfigBuilder {
    const CONFIG_ERR: &str = "missing config";
    const NEXTHOP_ERR: &str = "missing nexthop address";
    const METRIC_ERR: &str = "missing metric arg";
    const DISTANCE_ERR: &str = "missing distance arg";
    const WEIGHT_ERR: &str = "missing weight arg";

    ConfigBuilder::default()
        .path("/routing/static/route")
        .set(|rib, cache, prefix, _| {
            let _ = cache_get(rib, cache, &prefix).context(CONFIG_ERR)?;
            Ok(())
        })
        .del(|rib, cache, prefix, _| {
            if let Some(st) = cache.get_mut(&prefix) {
                st.delete = true;
            } else {
                let mut st = static_lookup(rib, &prefix).context(CONFIG_ERR)?;
                st.delete = true;
                cache.insert(*prefix, st);
            }
            Ok(())
        })
        .path("/routing/static/route/metric")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context(CONFIG_ERR)?;
            s.metric = Some(args.u32().context(METRIC_ERR)?);
            Ok(())
        })
        .del(|rib, cache, prefix, _| {
            let s = cache_lookup(rib, cache, &prefix).context(CONFIG_ERR)?;
            s.metric = None;
            Ok(())
        })
        .path("/routing/static/route/distance")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context(CONFIG_ERR)?;
            s.distance = Some(args.u8().context(DISTANCE_ERR)?);
            Ok(())
        })
        .del(|rib, cache, prefix, _| {
            let s = cache_lookup(rib, cache, &prefix).context(CONFIG_ERR)?;
            s.distance = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let _ = s.nexthops.entry(naddr).or_default();
            Ok(())
        })
        .del(|rib, cache, prefix, args| {
            let s = cache_lookup(rib, cache, &prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            s.nexthops.remove(&naddr).context(CONFIG_ERR)?;
            Ok(())
        })
        .path("/routing/static/route/nexthop/metric")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            n.metric = Some(args.u32().context(METRIC_ERR)?);
            Ok(())
        })
        .del(|rib, cache, prefix, args| {
            let s = cache_lookup(rib, cache, &prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            n.metric = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop/distance")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            n.distance = Some(args.u8().context(DISTANCE_ERR)?);
            Ok(())
        })
        .del(|rib, cache, prefix, args| {
            let s = cache_lookup(rib, cache, &prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            n.distance = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop/weight")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            n.weight = Some(args.u32().context(WEIGHT_ERR)?);
            Ok(())
        })
        .del(|rib, cache, prefix, args| {
            let s = cache_lookup(rib, cache, &prefix).context(CONFIG_ERR)?;
            let naddr = args.v4addr().context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            n.weight = None;
            Ok(())
        })
}

pub fn static_config_exec(rib: &mut Rib, path: String, args: Args, op: ConfigOp) {
    let builder = static_config_builder();
    let _ = builder.exec(path.as_str(), op, rib, args);
}

pub async fn static_config_commit(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    cache: &mut BTreeMap<Ipv4Net, StaticRoute>,
    fib_handle: &FibHandle,
) {
    while let Some((p, s)) = cache.pop_first() {
        let entry = rib.entry(p).or_default();
        if s.delete {
            entry.st = None;
        } else {
            entry.st = Some(s);
        }
        entry.static_process(&p, fib_handle).await;
    }
}
