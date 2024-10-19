use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use super::instance::RibEntries;
use super::Rib;
use crate::config::{Args, ConfigOp};
use crate::rib::StaticRoute;

fn static_route_get(rib: &PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net) -> StaticRoute {
    let Some(entry) = rib.get(prefix) else {
        return StaticRoute::default();
    };
    let Some(st) = &entry.st else {
        return StaticRoute::default();
    };
    st.clone()
}

fn static_route_lookup(
    rib: &PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
) -> Option<StaticRoute> {
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
        cache.insert(*prefix, static_route_get(rib, prefix));
    }
    cache.get_mut(prefix)
}

fn static_cache_lookup<'a>(
    rib: &'a PrefixMap<Ipv4Net, RibEntries>,
    cache: &'a mut BTreeMap<Ipv4Net, StaticRoute>,
    prefix: &'a Ipv4Net,
) -> Option<&'a mut StaticRoute> {
    if cache.get(prefix).is_none() {
        cache.insert(*prefix, static_route_lookup(rib, prefix)?);
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

type ConfigFunc = fn(rib: &mut Rib, prefix: &Ipv4Net, args: &mut Args) -> Result<()>;

#[derive(Default)]
struct StaticConfigRunner {
    path: String,
    map: BTreeMap<(String, ConfigOp), ConfigFunc>,
}

impl StaticConfigRunner {
    pub fn path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    pub fn set(mut self, func: ConfigFunc) -> Self {
        self.map.insert((self.path.clone(), ConfigOp::Set), func);
        self
    }

    pub fn del(mut self, func: ConfigFunc) -> Self {
        self.map.insert((self.path.clone(), ConfigOp::Delete), func);
        self
    }

    pub fn exec(&self, path: &str, op: ConfigOp, rib: &mut Rib, mut args: Args) -> Result<()> {
        let func = self.map.get(&(path.to_string(), op)).context("")?;
        let prefix: Ipv4Net = args.v4net().context("")?;
        func(rib, &prefix, &mut args)
    }
}

pub fn static_config_exec(rib: &mut Rib, path: String, args: Args, op: ConfigOp) {
    let runner = StaticConfigRunner::default()
        .path("/routing/static/route")
        .set(|rib, prefix, _| {
            let _ = cache_get(&rib.rib, &mut rib.cache, &prefix).context("")?;
            Ok(())
        })
        .del(|rib, prefix, _| {
            if let Some(st) = rib.cache.get_mut(&prefix) {
                st.delete = true;
            } else {
                let mut st = static_route_lookup(&rib.rib, &prefix).context("")?;
                st.delete = true;
                rib.cache.insert(*prefix, st);
            }
            Ok(())
        })
        .path("/routing/static/route/metric")
        .set(|rib, prefix, args| {
            let s = cache_get(&rib.rib, &mut rib.cache, &prefix).context("")?;
            s.metric = Some(args.u32().context("")?);
            Ok(())
        })
        .del(|rib, prefix, args| {
            let s = static_cache_lookup(&rib.rib, &mut rib.cache, &prefix).context("")?;
            s.metric = None;
            Ok(())
        })
        .path("/routing/static/route/distance")
        .set(|rib, prefix, args| {
            let s = cache_get(&rib.rib, &mut rib.cache, &prefix).context("")?;
            s.distance = Some(args.u8().context("")?);
            Ok(())
        })
        .del(|rib, prefix, _| {
            let s = static_cache_lookup(&rib.rib, &mut rib.cache, &prefix).context("")?;
            s.distance = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop")
        .set(|rib, prefix, args| {
            let s = cache_get(&rib.rib, &mut rib.cache, &prefix).context("")?;
            let _ = s.nexthops.entry(args.v4addr().context("")?).or_default();
            Ok(())
        })
        .del(|rib, prefix, args| {
            let s = static_cache_lookup(&rib.rib, &mut rib.cache, &prefix).context("")?;
            s.nexthops.remove(&args.v4addr().context("")?).context("")?;
            Ok(())
        })
        .path("/routing/static/route/nexthop/metric")
        .set(|rib, prefix, args| {
            let s = cache_get(&rib.rib, &mut rib.cache, &prefix).context("")?;
            let n = s.nexthops.entry(args.v4addr().context("")?).or_default();
            n.metric = Some(args.u32().context("")?);
            Ok(())
        })
        .del(|rib, prefix, args| {
            let s = static_cache_lookup(&rib.rib, &mut rib.cache, &prefix).context("")?;
            let n = s
                .nexthops
                .get_mut(&args.v4addr().context("")?)
                .context("")?;
            n.metric = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop/distance")
        .set(|rib, prefix, args| {
            let s = cache_get(&rib.rib, &mut rib.cache, &prefix).context("")?;
            let n = s.nexthops.entry(args.v4addr().context("")?).or_default();
            n.distance = Some(args.u8().context("")?);
            Ok(())
        })
        .del(|rib, prefix, args| {
            let s = static_cache_lookup(&rib.rib, &mut rib.cache, &prefix).context("")?;
            let n = s
                .nexthops
                .get_mut(&args.v4addr().context("")?)
                .context("")?;
            n.distance = None;
            Ok(())
        })
        .path("/routing/static/route/nexthop/weight")
        .set(|rib, prefix, args| {
            let s = cache_get(&rib.rib, &mut rib.cache, &prefix).context("")?;
            let n = s.nexthops.entry(args.v4addr().context("")?).or_default();
            n.weight = Some(args.u32().context("")?);
            Ok(())
        })
        .del(|rib, prefix, args| {
            let s = static_cache_lookup(&rib.rib, &mut rib.cache, &prefix).context("")?;
            let n = s
                .nexthops
                .get_mut(&args.v4addr().context("")?)
                .context("")?;
            n.weight = None;
            Ok(())
        });

    println!("P: {:?} {}", op, path);
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
