use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::{Context, Result, bail};

use crate::config::{Args, ConfigOp};

use super::Isis;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FadMetricType {
    Igp,                // FAD Metric-Type 0
    MinUnidirLinkDelay, // FAD Metric-Type 1 (RFC 8570)
    TeDefault,          // FAD Metric-Type 2 (RFC 5305)
}

impl FadMetricType {
    /// FAD Sub-TLV Metric-Type code (RFC 9350 §5.1, IANA registry).
    /// Held here so the LSP-emit follow-up has a single source of
    /// truth for the on-the-wire byte.
    #[allow(dead_code)]
    pub fn wire(self) -> u8 {
        match self {
            Self::Igp => 0,
            Self::MinUnidirLinkDelay => 1,
            Self::TeDefault => 2,
        }
    }
}

impl FromStr for FadMetricType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "igp" => Ok(Self::Igp),
            "min-unidir-link-delay" => Ok(Self::MinUnidirLinkDelay),
            "te-default" => Ok(Self::TeDefault),
            _ => bail!("unknown flex-algo metric-type: {s}"),
        }
    }
}

/// One Flexible Algorithm Definition (RFC 9350) as configured on this
/// router. Mirrors the YANG schema under /router/isis/flex-algo.
#[derive(Debug, Default, Clone)]
pub struct FlexAlgoEntry {
    pub delete: bool,
    pub advertise_definition: Option<bool>,
    pub metric_type: Option<FadMetricType>,
    pub priority: Option<u8>,
    pub prefix_metric: Option<bool>,
    pub dataplane_sr_mpls: Option<bool>,
    pub dataplane_srv6: Option<bool>,
    pub dataplane_ip: Option<bool>,
    pub include_any: BTreeSet<String>,
    pub include_all: BTreeSet<String>,
    pub exclude_any: BTreeSet<String>,
    pub srlg_exclude: BTreeSet<String>,
    pub ti_lfa: bool,
}

pub struct FlexAlgoConfig {
    pub config: BTreeMap<u8, FlexAlgoEntry>,
    pub cache: BTreeMap<u8, FlexAlgoEntry>,
    builder: ConfigBuilder,
}

impl Default for FlexAlgoConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FlexAlgoConfig {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: config_builder(),
        }
    }

    /// Stage one leaf update into the pending cache. Mirrors
    /// `StaticConfig::exec` in rib/static/config.rs — pure staging,
    /// no side effects until `commit` is called.
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

    /// Drain the pending cache into the committed map. Apply / drop
    /// semantics match `StaticConfig::commit`. Side-effects driven by
    /// definition changes (LSP re-origination, SPF schedule, dataplane
    /// install) will be wired in follow-up PRs — for now this is a pure
    /// in-memory commit.
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

fn config_builder() -> ConfigBuilder {
    const CONFIG_ERR: &str = "flex-algo entry parse error";
    const BOOL_ERR: &str = "flex-algo boolean arg parse error";
    const U8_ERR: &str = "flex-algo u8 arg parse error";
    const ENUM_ERR: &str = "flex-algo enum arg parse error";
    const NAME_ERR: &str = "flex-algo name arg parse error";

    ConfigBuilder::default()
        .path("/router/isis/flex-algo")
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
        .path("/router/isis/flex-algo/advertise-definition")
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
        .path("/router/isis/flex-algo/metric-type")
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
        .path("/router/isis/flex-algo/priority")
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
        .path("/router/isis/flex-algo/prefix-metric")
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
        .path("/router/isis/flex-algo/dataplane/sr-mpls")
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
        .path("/router/isis/flex-algo/dataplane/srv6")
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
        .path("/router/isis/flex-algo/dataplane/ip")
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
        .path("/router/isis/flex-algo/affinity/include-any")
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
        .path("/router/isis/flex-algo/affinity/include-all")
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
        .path("/router/isis/flex-algo/affinity/exclude-any")
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
        .path("/router/isis/flex-algo/srlg-exclude")
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
        .path("/router/isis/flex-algo/fast-reroute/ti-lfa")
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

// ── Wiring into the existing IS-IS callback dispatcher ────────────
//
// The IS-IS instance dispatches per-leaf via `Isis::callbacks`, with
// callback signature `fn(&mut Isis, Args, ConfigOp) -> Option<()>`. We
// register one shim per path here; each shim forwards into
// `isis.flex_algo.exec(path, ...)` and then `commit()` so the new value
// is visible synchronously, the way the rest of IS-IS expects.

macro_rules! flex_algo_cb {
    ($name:ident, $path:literal) => {
        fn $name(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
            isis.flex_algo.exec($path.to_string(), args, op).ok()?;
            isis.flex_algo.commit();
            Some(())
        }
    };
}

flex_algo_cb!(cb_entry, "/router/isis/flex-algo");
flex_algo_cb!(
    cb_advertise_definition,
    "/router/isis/flex-algo/advertise-definition"
);
flex_algo_cb!(cb_metric_type, "/router/isis/flex-algo/metric-type");
flex_algo_cb!(cb_priority, "/router/isis/flex-algo/priority");
flex_algo_cb!(cb_prefix_metric, "/router/isis/flex-algo/prefix-metric");
flex_algo_cb!(cb_dp_sr_mpls, "/router/isis/flex-algo/dataplane/sr-mpls");
flex_algo_cb!(cb_dp_srv6, "/router/isis/flex-algo/dataplane/srv6");
flex_algo_cb!(cb_dp_ip, "/router/isis/flex-algo/dataplane/ip");
flex_algo_cb!(
    cb_affinity_include_any,
    "/router/isis/flex-algo/affinity/include-any"
);
flex_algo_cb!(
    cb_affinity_include_all,
    "/router/isis/flex-algo/affinity/include-all"
);
flex_algo_cb!(
    cb_affinity_exclude_any,
    "/router/isis/flex-algo/affinity/exclude-any"
);
flex_algo_cb!(cb_srlg_exclude, "/router/isis/flex-algo/srlg-exclude");
flex_algo_cb!(cb_ti_lfa, "/router/isis/flex-algo/fast-reroute/ti-lfa");

pub fn callback_register(isis: &mut Isis) {
    isis.callback_add("/router/isis/flex-algo", cb_entry);
    isis.callback_add(
        "/router/isis/flex-algo/advertise-definition",
        cb_advertise_definition,
    );
    isis.callback_add("/router/isis/flex-algo/metric-type", cb_metric_type);
    isis.callback_add("/router/isis/flex-algo/priority", cb_priority);
    isis.callback_add("/router/isis/flex-algo/prefix-metric", cb_prefix_metric);
    isis.callback_add("/router/isis/flex-algo/dataplane/sr-mpls", cb_dp_sr_mpls);
    isis.callback_add("/router/isis/flex-algo/dataplane/srv6", cb_dp_srv6);
    isis.callback_add("/router/isis/flex-algo/dataplane/ip", cb_dp_ip);
    isis.callback_add(
        "/router/isis/flex-algo/affinity/include-any",
        cb_affinity_include_any,
    );
    isis.callback_add(
        "/router/isis/flex-algo/affinity/include-all",
        cb_affinity_include_all,
    );
    isis.callback_add(
        "/router/isis/flex-algo/affinity/exclude-any",
        cb_affinity_exclude_any,
    );
    isis.callback_add("/router/isis/flex-algo/srlg-exclude", cb_srlg_exclude);
    isis.callback_add("/router/isis/flex-algo/fast-reroute/ti-lfa", cb_ti_lfa);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect::<VecDeque<_>>())
    }

    #[test]
    fn set_advertise_definition_then_commit_persists() {
        let mut fa = FlexAlgoConfig::new();
        fa.exec(
            "/router/isis/flex-algo/advertise-definition".into(),
            args(&["128", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        let e = fa.config.get(&128).unwrap();
        assert_eq!(e.advertise_definition, Some(true));
    }

    #[test]
    fn set_metric_type_then_priority_share_entry() {
        let mut fa = FlexAlgoConfig::new();
        fa.exec(
            "/router/isis/flex-algo/metric-type".into(),
            args(&["128", "min-unidir-link-delay"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        fa.exec(
            "/router/isis/flex-algo/priority".into(),
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
        let mut fa = FlexAlgoConfig::new();
        for color in ["blue", "red", "blue"] {
            fa.exec(
                "/router/isis/flex-algo/affinity/exclude-any".into(),
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
        let mut fa = FlexAlgoConfig::new();
        fa.exec(
            "/router/isis/flex-algo/priority".into(),
            args(&["128", "100"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        assert!(fa.config.contains_key(&128));

        fa.exec(
            "/router/isis/flex-algo".into(),
            args(&["128"]),
            ConfigOp::Delete,
        )
        .unwrap();
        fa.commit();
        assert!(!fa.config.contains_key(&128));
    }

    #[test]
    fn algo_outside_user_range_rejected() {
        let mut fa = FlexAlgoConfig::new();
        let err = fa
            .exec(
                "/router/isis/flex-algo/priority".into(),
                args(&["127", "100"]),
                ConfigOp::Set,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("128..=255"), "unexpected err: {err}");
    }
}
