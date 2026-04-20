// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::entry::RibEntry;
use crate::rib::{Message, RibType};

use super::StaticRoute;

pub trait StaticFamily: Sized + 'static {
    type Prefix: Ord + Copy;
    type Addr: Ord + Copy;

    const FAMILY: &'static str;

    fn parse_prefix(args: &mut Args) -> Option<Self::Prefix>;
    fn parse_addr(args: &mut Args) -> Option<Self::Addr>;
    fn to_ip_addr(addr: Self::Addr) -> IpAddr;
    fn add_msg(prefix: Self::Prefix, rib: RibEntry) -> Message;
    fn del_msg(prefix: Self::Prefix, rib: RibEntry) -> Message;
}

pub struct V4;
impl StaticFamily for V4 {
    type Prefix = Ipv4Net;
    type Addr = Ipv4Addr;
    const FAMILY: &'static str = "ipv4";

    fn parse_prefix(args: &mut Args) -> Option<Self::Prefix> {
        args.v4net()
    }
    fn parse_addr(args: &mut Args) -> Option<Self::Addr> {
        args.v4addr()
    }
    fn to_ip_addr(addr: Self::Addr) -> IpAddr {
        IpAddr::V4(addr)
    }
    fn add_msg(prefix: Self::Prefix, rib: RibEntry) -> Message {
        Message::Ipv4Add { prefix, rib }
    }
    fn del_msg(prefix: Self::Prefix, rib: RibEntry) -> Message {
        Message::Ipv4Del { prefix, rib }
    }
}

pub struct V6;
impl StaticFamily for V6 {
    type Prefix = Ipv6Net;
    type Addr = Ipv6Addr;
    const FAMILY: &'static str = "ipv6";

    fn parse_prefix(args: &mut Args) -> Option<Self::Prefix> {
        args.v6net()
    }
    fn parse_addr(args: &mut Args) -> Option<Self::Addr> {
        args.v6addr()
    }
    fn to_ip_addr(addr: Self::Addr) -> IpAddr {
        IpAddr::V6(addr)
    }
    fn add_msg(prefix: Self::Prefix, rib: RibEntry) -> Message {
        Message::Ipv6Add { prefix, rib }
    }
    fn del_msg(prefix: Self::Prefix, rib: RibEntry) -> Message {
        Message::Ipv6Del { prefix, rib }
    }
}

pub struct StaticConfig<F: StaticFamily> {
    pub config: BTreeMap<F::Prefix, StaticRoute<F>>,
    pub cache: BTreeMap<F::Prefix, StaticRoute<F>>,
    builder: ConfigBuilder<F>,
}

impl<F: StaticFamily> StaticConfig<F> {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: config_builder::<F>(),
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
        let prefix = F::parse_prefix(&mut args).context(PREFIX_ERR)?;

        func(&mut self.config, &mut self.cache, &prefix, &mut args)
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        while let Some((p, s)) = self.cache.pop_first() {
            if s.delete {
                self.config.remove(&p);
                let _ = tx.send(F::del_msg(p, RibEntry::new(RibType::Static)));
            } else {
                let entry = s.to_entry();
                self.config.insert(p, s);
                if let Some(rib) = entry {
                    let _ = tx.send(F::add_msg(p, rib));
                }
            }
        }
    }
}

struct ConfigBuilder<F: StaticFamily> {
    path: String,
    pub map: BTreeMap<(String, ConfigOp), Handler<F>>,
}

impl<F: StaticFamily> Default for ConfigBuilder<F> {
    fn default() -> Self {
        Self {
            path: String::new(),
            map: BTreeMap::new(),
        }
    }
}

type Handler<F> = fn(
    config: &mut BTreeMap<<F as StaticFamily>::Prefix, StaticRoute<F>>,
    cache: &mut BTreeMap<<F as StaticFamily>::Prefix, StaticRoute<F>>,
    prefix: &<F as StaticFamily>::Prefix,
    args: &mut Args,
) -> Result<()>;

impl<F: StaticFamily> ConfigBuilder<F> {
    pub fn path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    pub fn set(mut self, func: Handler<F>) -> Self {
        self.map.insert((self.path.clone(), ConfigOp::Set), func);
        self
    }

    pub fn del(mut self, func: Handler<F>) -> Self {
        self.map.insert((self.path.clone(), ConfigOp::Delete), func);
        self
    }
}

fn config_get<F: StaticFamily>(
    config: &BTreeMap<F::Prefix, StaticRoute<F>>,
    prefix: &F::Prefix,
) -> StaticRoute<F> {
    let Some(entry) = config.get(prefix) else {
        return StaticRoute::default();
    };
    entry.clone()
}

fn config_lookup<F: StaticFamily>(
    config: &BTreeMap<F::Prefix, StaticRoute<F>>,
    prefix: &F::Prefix,
) -> Option<StaticRoute<F>> {
    let entry = config.get(prefix)?;
    Some(entry.clone())
}

fn cache_get<'a, F: StaticFamily>(
    config: &'a BTreeMap<F::Prefix, StaticRoute<F>>,
    cache: &'a mut BTreeMap<F::Prefix, StaticRoute<F>>,
    prefix: &'a F::Prefix,
) -> Option<&'a mut StaticRoute<F>> {
    if cache.get(prefix).is_none() {
        cache.insert(*prefix, config_get::<F>(config, prefix));
    }
    cache.get_mut(prefix)
}

fn cache_lookup<'a, F: StaticFamily>(
    config: &'a BTreeMap<F::Prefix, StaticRoute<F>>,
    cache: &'a mut BTreeMap<F::Prefix, StaticRoute<F>>,
    prefix: &'a F::Prefix,
) -> Option<&'a mut StaticRoute<F>> {
    if cache.get(prefix).is_none() {
        cache.insert(*prefix, config_lookup::<F>(config, prefix)?);
    }
    let cache = cache.get_mut(prefix)?;
    if cache.delete { None } else { Some(cache) }
}

fn config_builder<F: StaticFamily>() -> ConfigBuilder<F> {
    const CONFIG_ERR: &str = "missing config";
    const NEXTHOP_ERR: &str = "missing nexthop address";
    const METRIC_ERR: &str = "missing metric arg";
    const DISTANCE_ERR: &str = "missing distance arg";
    const WEIGHT_ERR: &str = "missing weight arg";

    ConfigBuilder::<F>::default()
        .path(&format!("/routing/static/{}/route", F::FAMILY))
        .set(|config, cache, prefix, _args| {
            let _ = cache_get::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            Ok(())
        })
        .del(|config, cache, prefix, _args| {
            if let Some(st) = cache.get_mut(prefix) {
                st.delete = true;
            } else {
                let mut st = config_lookup::<F>(config, prefix).context(CONFIG_ERR)?;
                st.delete = true;
                cache.insert(*prefix, st);
            }
            Ok(())
        })
        .path(&format!("/routing/static/{}/route/metric", F::FAMILY))
        .set(|config, cache, prefix, args| {
            let s = cache_get::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            s.metric = Some(args.u32().context(METRIC_ERR)?);
            Ok(())
        })
        .del(|config, cache, prefix, _args| {
            let s = cache_lookup::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            s.metric = None;
            Ok(())
        })
        .path(&format!("/routing/static/{}/route/distance", F::FAMILY))
        .set(|config, cache, prefix, args| {
            let s = cache_get::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            s.distance = Some(args.u8().context(DISTANCE_ERR)?);
            Ok(())
        })
        .del(|config, cache, prefix, _args| {
            let s = cache_lookup::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            s.distance = None;
            Ok(())
        })
        .path(&format!("/routing/static/{}/route/nexthop", F::FAMILY))
        .set(|config, cache, prefix, args| {
            let s = cache_get::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = F::parse_addr(args).context(NEXTHOP_ERR)?;
            let _ = s.nexthops.entry(naddr).or_default();
            Ok(())
        })
        .del(|config, cache, prefix, args| {
            let s = cache_lookup::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = F::parse_addr(args).context(NEXTHOP_ERR)?;
            s.nexthops.remove(&naddr).context(CONFIG_ERR)?;
            Ok(())
        })
        .path(&format!(
            "/routing/static/{}/route/nexthop/metric",
            F::FAMILY
        ))
        .set(|config, cache, prefix, args| {
            let s = cache_get::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = F::parse_addr(args).context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            n.metric = Some(args.u32().context(METRIC_ERR)?);
            Ok(())
        })
        .del(|config, cache, prefix, args| {
            let s = cache_lookup::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = F::parse_addr(args).context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            n.metric = None;
            Ok(())
        })
        .path(&format!(
            "/routing/static/{}/route/nexthop/weight",
            F::FAMILY
        ))
        .set(|config, cache, prefix, args| {
            let s = cache_get::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = F::parse_addr(args).context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            n.weight = Some(args.u8().context(WEIGHT_ERR)?);
            Ok(())
        })
        .del(|config, cache, prefix, args| {
            let s = cache_lookup::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = F::parse_addr(args).context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            n.weight = None;
            Ok(())
        })
        .path(&format!(
            "/routing/static/{}/route/nexthop/label",
            F::FAMILY
        ))
        .set(|config, cache, prefix, args| {
            let s = cache_get::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = F::parse_addr(args).context(NEXTHOP_ERR)?;
            let n = s.nexthops.entry(naddr).or_default();
            n.labels.clear();
            while let Some(label) = args.u32() {
                n.labels.push(label);
            }
            Ok(())
        })
        .del(|config, cache, prefix, args| {
            let s = cache_lookup::<F>(config, cache, prefix).context(CONFIG_ERR)?;
            let naddr = F::parse_addr(args).context(NEXTHOP_ERR)?;
            let n = s.nexthops.get_mut(&naddr).context(CONFIG_ERR)?;
            n.labels.clear();
            Ok(())
        })
}
