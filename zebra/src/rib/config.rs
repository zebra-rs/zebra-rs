use super::{
    entry::{RibEntry, RibType},
    instance::{Rib, RibEntries},
};
use crate::{
    config::{Args, ConfigOp},
    rib::{nexthop::Nexthop, route::StaticRoute},
};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::{
    collections::{BTreeMap, HashMap},
    net::Ipv4Addr,
};

use anyhow::{Context, Result};

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

pub fn routing_static_commit(
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

type ConfigFunc = fn(rib: &mut Rib, prefix: &Ipv4Net, args: &mut Args) -> Result<()>;

#[derive(Default)]
struct StaticConfigRunner {
    path: String,
    map: HashMap<(String, ConfigOp), ConfigFunc>,
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

pub async fn config_dispatch(rib: &mut Rib, path: String, args: Args, op: ConfigOp) {
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

async fn static_route_nexthop(rib: &mut Rib, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set && args.len() > 1 {
        let dest: Ipv4Net = args.v4net()?;
        let gateway: Ipv4Addr = args.v4addr()?;

        println!("addr {} nexthop {}", dest, gateway);

        let mut entry = RibEntry::new(RibType::Static);
        entry.distance = 1;
        let mut nexthop = Nexthop::builder().addr(gateway).build();
        let found = resolve(rib, &mut nexthop);
        if let Some(ifc) = found {
            println!("XX Found {}", ifc.link_index);
        } else {
            println!("XX Not Found");
        }
        entry.nexthops.push(nexthop);
        // entry.gateway = IpAddr::V4(gateway);
        // XXX rib.rib.insert(dest, entry);

        rib.ipv4_add(dest, entry.clone());
        rib.ipv4_add(dest, entry);

        rib.fib_handle.route_ipv4_add(dest, gateway).await;
        // if let Some(handle) = rib.handle.as_ref() {
        //     route_add(handle.clone(), dest, gateway).await;
        // }
    }
    Some(())
}

trait Ipv4AddrEx {
    fn to_prefix(&self) -> Ipv4Net;
}

impl Ipv4AddrEx for Ipv4Addr {
    fn to_prefix(&self) -> Ipv4Net {
        Ipv4Net::new(*self, Ipv4Addr::BITS as u8).unwrap()
    }
}

fn resolve<'a>(rib: &'a Rib, nexthop: &'a mut Nexthop) -> Option<&'a RibEntry> {
    let Some(addr) = nexthop.addr else {
        return None;
    };
    let addr = addr.to_prefix();
    let (_, entry) = rib.rib.get_lpm(&addr)?;
    for e in entry.ribs.iter() {
        if e.rtype == RibType::Connected {
            return Some(e);
        }
    }
    None
}
