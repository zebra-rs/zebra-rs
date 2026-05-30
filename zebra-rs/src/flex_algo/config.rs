use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use crate::config::{Args, ConfigOp};

use super::entry::FlexAlgoEntry;

/// Staged Flexible Algorithm Definitions (RFC 9350) for one IGP
/// instance, keyed by algorithm id (128..=255). Protocol-neutral: the
/// config path prefix is supplied at construction so IS-IS
/// (`/router/isis/flex-algo`) and OSPF (`/router/ospf/flex-algo`,
/// `/router/ospfv3/flex-algo`) share one staging engine. The wire
/// builders that turn the committed `config` into FAD sub-TLVs stay in
/// each protocol module (isis-packet / ospf-packet types differ).
pub struct FlexAlgoConfig {
    pub config: BTreeMap<u8, FlexAlgoEntry>,
    pub cache: BTreeMap<u8, FlexAlgoEntry>,
    builder: ConfigBuilder,
}

impl FlexAlgoConfig {
    /// `prefix` is the config subtree these leaves hang under, e.g.
    /// `/router/ospf/flex-algo`. Leaf paths are `{prefix}/...`.
    pub fn new(prefix: &str) -> Self {
        Self {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: config_builder(prefix),
        }
    }

    /// Stage one leaf update into the pending cache. Pure staging — no
    /// side effects until `commit` is called.
    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing flex-algo config handler";
        const ALGO_ERR: &str = "missing flex-algo algorithm arg";

        let func = self.builder.map.get(&(path, op)).context(CONFIG_ERR)?;
        let algo = args.u8().context(ALGO_ERR)?;
        if !(128..=255).contains(&algo) {
            bail!("flex-algo identifier must be 128..=255 (got {algo})");
        }
        func(&mut self.config, &mut self.cache, algo, &mut args)
    }

    /// Drain the pending cache into the committed map. LSP/LSA
    /// re-origination is triggered by the per-leaf shim callbacks in
    /// each protocol module.
    pub fn commit(&mut self) {
        while let Some((algo, entry)) = self.cache.pop_first() {
            if entry.delete {
                self.config.remove(&algo);
            } else {
                self.config.insert(algo, entry);
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
    config: &mut BTreeMap<u8, FlexAlgoEntry>,
    cache: &mut BTreeMap<u8, FlexAlgoEntry>,
    algo: u8,
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

fn config_get(config: &BTreeMap<u8, FlexAlgoEntry>, algo: u8) -> FlexAlgoEntry {
    config.get(&algo).cloned().unwrap_or_default()
}

fn config_lookup(config: &BTreeMap<u8, FlexAlgoEntry>, algo: u8) -> Option<FlexAlgoEntry> {
    config.get(&algo).cloned()
}

fn cache_get<'a>(
    config: &BTreeMap<u8, FlexAlgoEntry>,
    cache: &'a mut BTreeMap<u8, FlexAlgoEntry>,
    algo: u8,
) -> Option<&'a mut FlexAlgoEntry> {
    if cache.get(&algo).is_none() {
        cache.insert(algo, config_get(config, algo));
    }
    cache.get_mut(&algo)
}

fn cache_lookup<'a>(
    config: &BTreeMap<u8, FlexAlgoEntry>,
    cache: &'a mut BTreeMap<u8, FlexAlgoEntry>,
    algo: u8,
) -> Option<&'a mut FlexAlgoEntry> {
    if cache.get(&algo).is_none() {
        cache.insert(algo, config_lookup(config, algo)?);
    }
    let entry = cache.get_mut(&algo)?;
    if entry.delete { None } else { Some(entry) }
}

fn config_builder(prefix: &str) -> ConfigBuilder {
    const CONFIG_ERR: &str = "flex-algo entry parse error";
    const BOOL_ERR: &str = "flex-algo boolean arg parse error";
    const U8_ERR: &str = "flex-algo u8 arg parse error";
    const ENUM_ERR: &str = "flex-algo enum arg parse error";
    const NAME_ERR: &str = "flex-algo name arg parse error";

    ConfigBuilder::default()
        .path(prefix)
        .set(|config, cache, algo, _args| {
            let _ = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            if let Some(e) = cache.get_mut(&algo) {
                e.delete = true;
            } else {
                let mut e = config_lookup(config, algo).context(CONFIG_ERR)?;
                e.delete = true;
                cache.insert(algo, e);
            }
            Ok(())
        })
        .path(&format!("{prefix}/advertise-definition"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.advertise_definition = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.advertise_definition = None;
            Ok(())
        })
        .path(&format!("{prefix}/metric-type"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.metric_type = Some(args.string().context(ENUM_ERR)?.parse()?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.metric_type = None;
            Ok(())
        })
        .path(&format!("{prefix}/priority"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.priority = Some(args.u8().context(U8_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.priority = None;
            Ok(())
        })
        .path(&format!("{prefix}/prefix-metric"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.prefix_metric = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.prefix_metric = None;
            Ok(())
        })
        .path(&format!("{prefix}/dataplane/sr-mpls"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_sr_mpls = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_sr_mpls = None;
            Ok(())
        })
        .path(&format!("{prefix}/dataplane/srv6"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_srv6 = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_srv6 = None;
            Ok(())
        })
        .path(&format!("{prefix}/dataplane/ip"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_ip = Some(args.boolean().context(BOOL_ERR)?);
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.dataplane_ip = None;
            Ok(())
        })
        .path(&format!("{prefix}/affinity/include-any"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.include_any.insert(name);
            Ok(())
        })
        .del(|config, cache, algo, args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.include_any.remove(&name);
            Ok(())
        })
        .path(&format!("{prefix}/affinity/include-all"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.include_all.insert(name);
            Ok(())
        })
        .del(|config, cache, algo, args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.include_all.remove(&name);
            Ok(())
        })
        .path(&format!("{prefix}/affinity/exclude-any"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.exclude_any.insert(name);
            Ok(())
        })
        .del(|config, cache, algo, args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.exclude_any.remove(&name);
            Ok(())
        })
        .path(&format!("{prefix}/srlg-exclude"))
        .set(|config, cache, algo, args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.srlg_exclude.insert(name);
            Ok(())
        })
        .del(|config, cache, algo, args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            let name = args.string().context(NAME_ERR)?;
            e.srlg_exclude.remove(&name);
            Ok(())
        })
        .path(&format!("{prefix}/fast-reroute/ti-lfa"))
        .set(|config, cache, algo, _args| {
            let e = cache_get(config, cache, algo).context(CONFIG_ERR)?;
            e.ti_lfa = true;
            Ok(())
        })
        .del(|config, cache, algo, _args| {
            let e = cache_lookup(config, cache, algo).context(CONFIG_ERR)?;
            e.ti_lfa = false;
            Ok(())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flex_algo::FadMetricType;
    use std::collections::VecDeque;

    const P: &str = "/router/ospf/flex-algo";

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect::<VecDeque<_>>())
    }

    #[test]
    fn set_advertise_definition_then_commit_persists() {
        let mut fa = FlexAlgoConfig::new(P);
        fa.exec(
            format!("{P}/advertise-definition"),
            args(&["128", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        assert_eq!(
            fa.config.get(&128).unwrap().advertise_definition,
            Some(true)
        );
    }

    #[test]
    fn set_metric_type_then_priority_share_entry() {
        let mut fa = FlexAlgoConfig::new(P);
        fa.exec(
            format!("{P}/metric-type"),
            args(&["128", "min-unidir-link-delay"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        fa.exec(
            format!("{P}/priority"),
            args(&["128", "200"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        let e = fa.config.get(&128).unwrap();
        assert_eq!(e.metric_type, Some(FadMetricType::MinUnidirLinkDelay));
        assert_eq!(e.priority, Some(200));
    }

    #[test]
    fn affinity_exclude_any_is_a_set() {
        let mut fa = FlexAlgoConfig::new(P);
        for color in ["blue", "red", "blue"] {
            fa.exec(
                format!("{P}/affinity/exclude-any"),
                args(&["129", color]),
                ConfigOp::Set,
            )
            .unwrap();
            fa.commit();
        }
        let e = fa.config.get(&129).unwrap();
        assert_eq!(e.exclude_any.len(), 2);
        assert!(e.exclude_any.contains("blue"));
        assert!(e.exclude_any.contains("red"));
    }

    #[test]
    fn delete_entry_removes_it() {
        let mut fa = FlexAlgoConfig::new(P);
        fa.exec(
            format!("{P}/priority"),
            args(&["128", "100"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        assert!(fa.config.contains_key(&128));

        fa.exec(P.to_string(), args(&["128"]), ConfigOp::Delete)
            .unwrap();
        fa.commit();
        assert!(!fa.config.contains_key(&128));
    }

    #[test]
    fn algo_outside_user_range_rejected() {
        let mut fa = FlexAlgoConfig::new(P);
        let err = fa
            .exec(
                format!("{P}/priority"),
                args(&["127", "100"]),
                ConfigOp::Set,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("128..=255"), "unexpected err: {err}");
    }
}
