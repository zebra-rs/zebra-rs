use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use super::instance::RibEntries;
use super::Rib;
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
struct StaticConfigRunner {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    cache: &mut BTreeMap<Ipv4Net, StaticRoute>,
    prefix: &Ipv4Net,
    args: &mut Args,
) -> Result<()>;

impl StaticConfigRunner {
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
        let func = self
            .map
            .get(&(path.to_string(), op))
            .context("missing config handler")?;
        let prefix: Ipv4Net = args.v4net().context("missing prefix arg")?;
        func(&mut rib.rib, &mut rib.cache, &prefix, &mut args)
    }
}

fn static_config_runner() -> StaticConfigRunner {
    StaticConfigRunner::default()
        .path("/routing/static/route")
        .set(|rib, cache, prefix, _| {
            let _ = cache_get(rib, cache, &prefix).context("missing config")?;
            Ok(())
        })
        .del(|rib, cache, prefix, _| {
            if let Some(st) = cache.get_mut(&prefix) {
                st.delete = true;
            } else {
                let mut st = static_lookup(rib, &prefix).context("missing config")?;
                st.delete = true;
                cache.insert(*prefix, st);
            }
            Ok(())
        })
        .path("/routing/static/route/metric")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context("missing config")?;
            s.metric = Some(args.u32().context("missing metric arg")?);
            Ok(())
        })
        .del(|rib, cache, prefix, _| {
            let s = cache_lookup(rib, cache, &prefix).context("missing config")?;
            s.metric = None;
            Ok(())
        })
        .path("/routing/static/route/distance")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context("missing config")?;
            s.distance = Some(args.u8().context("missing distance arg")?);
            Ok(())
        })
        .del(|rib, cache, prefix, _| {
            let s = cache_lookup(rib, cache, &prefix).context("missing config")?;
            s.distance = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context("missing config")?;
            let naddr = args.v4addr().context("missing nexthop address")?;
            let _ = s.nexthops.entry(naddr).or_default();
            Ok(())
        })
        .del(|rib, cache, prefix, args| {
            let s = cache_lookup(rib, cache, &prefix).context("missing config")?;
            let naddr = args.v4addr().context("missing nexthop address")?;
            s.nexthops.remove(&naddr).context("missing config")?;
            Ok(())
        })
        .path("/routing/static/route/nexthop/metric")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context("missing config")?;
            let naddr = args.v4addr().context("missing nexthop address")?;
            let n = s.nexthops.entry(naddr).or_default();
            n.metric = Some(args.u32().context("missing metric arg")?);
            Ok(())
        })
        .del(|rib, cache, prefix, args| {
            let s = cache_lookup(rib, cache, &prefix).context("missing config")?;
            let naddr = args.v4addr().context("missing nexthop address")?;
            let n = s.nexthops.get_mut(&naddr).context("missing config")?;
            n.metric = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop/distance")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context("missing config")?;
            let naddr = args.v4addr().context("missing nexthop address")?;
            let n = s.nexthops.entry(naddr).or_default();
            n.distance = Some(args.u8().context("missing distance arg")?);
            Ok(())
        })
        .del(|rib, cache, prefix, args| {
            let s = cache_lookup(rib, cache, &prefix).context("missing config")?;
            let naddr = args.v4addr().context("missing nexthop address")?;
            let n = s.nexthops.get_mut(&naddr).context("missing config")?;
            n.distance = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop/weight")
        .set(|rib, cache, prefix, args| {
            let s = cache_get(rib, cache, &prefix).context("missing config")?;
            let naddr = args.v4addr().context("missing nexthop address")?;
            let n = s.nexthops.entry(naddr).or_default();
            n.weight = Some(args.u32().context("missing weight arg")?);
            Ok(())
        })
        .del(|rib, cache, prefix, args| {
            let s = cache_lookup(rib, cache, &prefix).context("missing config")?;
            let naddr = args.v4addr().context("missing nexthop address")?;
            let n = s.nexthops.get_mut(&naddr).context("missing config")?;
            n.weight = None;
            Ok(())
        })
}

pub fn static_config_exec(rib: &mut Rib, path: String, args: Args, op: ConfigOp) {
    let runner = static_config_runner();
    let _ = runner.exec(path.as_str(), op, rib, args);
}

pub fn static_config_commit(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    cache: &mut BTreeMap<Ipv4Net, StaticRoute>,
) {
    for (p, s) in cache.into_iter() {
        let entry = rib.entry(*p).or_default();
        if s.delete {
            entry.st = None;
        } else {
            entry.st = Some(s.clone());
        }
    }
    cache.clear();
}
