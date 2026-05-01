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
            // self.config holds the last-committed snapshot, and commit() is
            // the only path that emits add/del_msg for static routes — so
            // "was this prefix previously installed?" is exactly
            // "does the previous StaticRoute produce Some(to_entry())?".
            let prev_installed = self
                .config
                .get(&p)
                .and_then(StaticRoute::to_entry)
                .is_some();

            if s.delete {
                self.config.remove(&p);
                if prev_installed {
                    let _ = tx.send(F::del_msg(p, RibEntry::new(RibType::Static)));
                }
            } else {
                let new_entry = s.to_entry();
                self.config.insert(p, s);
                match (prev_installed, new_entry) {
                    (_, Some(rib)) => {
                        let _ = tx.send(F::add_msg(p, rib));
                    }
                    (true, None) => {
                        let _ = tx.send(F::del_msg(p, RibEntry::new(RibType::Static)));
                    }
                    (false, None) => {}
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
    const CONFIG_ERR: &str = "config parse error";
    const NEXTHOP_ERR: &str = "nexthop address parse error";
    const METRIC_ERR: &str = "metric arg parse error";
    const DISTANCE_ERR: &str = "distance arg parse error";
    const WEIGHT_ERR: &str = "weight arg parse error";

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

#[cfg(test)]
mod tests {
    use super::super::route::StaticNexthop;
    use super::*;
    use crate::rib::Nexthop;
    use std::str::FromStr;
    use tokio::sync::mpsc::{self, UnboundedReceiver};

    fn prefix() -> Ipv4Net {
        Ipv4Net::from_str("10.0.0.0/24").unwrap()
    }

    fn nexthop_addr() -> Ipv4Addr {
        "192.0.2.1".parse().unwrap()
    }

    fn other_nexthop_addr() -> Ipv4Addr {
        "192.0.2.2".parse().unwrap()
    }

    fn route_with_nexthop(addr: Ipv4Addr) -> StaticRoute<V4> {
        let mut r = StaticRoute::<V4>::default();
        r.nexthops.insert(addr, StaticNexthop::default());
        r
    }

    fn drain(rx: &mut UnboundedReceiver<Message>) -> Vec<Message> {
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            out.push(msg);
        }
        out
    }

    fn assert_ipv4_add(msg: &Message, expected_prefix: Ipv4Net) -> &RibEntry {
        match msg {
            Message::Ipv4Add { prefix, rib } => {
                assert_eq!(*prefix, expected_prefix);
                rib
            }
            _ => panic!("expected Ipv4Add"),
        }
    }

    fn assert_ipv4_del(msg: &Message, expected_prefix: Ipv4Net) {
        match msg {
            Message::Ipv4Del { prefix, .. } => assert_eq!(*prefix, expected_prefix),
            _ => panic!("expected Ipv4Del"),
        }
    }

    #[test]
    fn add_with_nexthop_sends_add_msg() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sc = StaticConfig::<V4>::new();
        sc.cache
            .insert(prefix(), route_with_nexthop(nexthop_addr()));

        sc.commit(tx);

        let msgs = drain(&mut rx);
        assert_eq!(msgs.len(), 1);
        assert_ipv4_add(&msgs[0], prefix());
        assert!(sc.config.contains_key(&prefix()));
    }

    #[test]
    fn add_without_nexthop_sends_nothing() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sc = StaticConfig::<V4>::new();
        sc.cache.insert(prefix(), StaticRoute::<V4>::default());

        sc.commit(tx);

        assert!(drain(&mut rx).is_empty());
        assert!(sc.config.contains_key(&prefix()));
    }

    #[test]
    fn remove_only_nexthop_sends_del_msg() {
        // Reproduces the original TODO scenario: route was previously
        // installed with a nexthop, the user removed the only nexthop
        // without deleting the route. RIB must withdraw it.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sc = StaticConfig::<V4>::new();
        sc.config
            .insert(prefix(), route_with_nexthop(nexthop_addr()));
        sc.cache.insert(prefix(), StaticRoute::<V4>::default());

        sc.commit(tx);

        let msgs = drain(&mut rx);
        assert_eq!(msgs.len(), 1);
        assert_ipv4_del(&msgs[0], prefix());
    }

    #[test]
    fn delete_uninstalled_route_sends_nothing() {
        // Symmetric fix: deleting a route that was never installed
        // (no nexthops) must not emit a spurious del_msg.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sc = StaticConfig::<V4>::new();
        sc.config.insert(prefix(), StaticRoute::<V4>::default());
        sc.cache.insert(
            prefix(),
            StaticRoute::<V4> {
                delete: true,
                ..Default::default()
            },
        );

        sc.commit(tx);

        assert!(drain(&mut rx).is_empty());
        assert!(!sc.config.contains_key(&prefix()));
    }

    #[test]
    fn delete_installed_route_sends_del_msg() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sc = StaticConfig::<V4>::new();
        sc.config
            .insert(prefix(), route_with_nexthop(nexthop_addr()));
        let pending = StaticRoute::<V4> {
            delete: true,
            ..route_with_nexthop(nexthop_addr())
        };
        sc.cache.insert(prefix(), pending);

        sc.commit(tx);

        let msgs = drain(&mut rx);
        assert_eq!(msgs.len(), 1);
        assert_ipv4_del(&msgs[0], prefix());
        assert!(!sc.config.contains_key(&prefix()));
    }

    #[test]
    fn mutate_nexthop_sends_add_msg_with_new_content() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sc = StaticConfig::<V4>::new();
        sc.config
            .insert(prefix(), route_with_nexthop(nexthop_addr()));
        sc.cache
            .insert(prefix(), route_with_nexthop(other_nexthop_addr()));

        sc.commit(tx);

        let msgs = drain(&mut rx);
        assert_eq!(msgs.len(), 1);
        let rib = assert_ipv4_add(&msgs[0], prefix());
        match &rib.nexthop {
            Nexthop::Uni(uni) => assert_eq!(uni.addr, IpAddr::V4(other_nexthop_addr())),
            _ => panic!("expected Nexthop::Uni"),
        }
    }
}
