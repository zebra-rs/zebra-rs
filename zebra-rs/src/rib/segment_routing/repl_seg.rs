//! RFC 9524 SR-P2MP Replication segment configuration
//! (`segment-routing/replication-segment`). An operator declares a local
//! `End.Replicate` SID and its downstream branches; the RIB registers the SID
//! and tees the branch set to the cradle eBPF data plane (`REPL_SEG`). There
//! is no kernel seg6local action for replication — cradle is the data plane.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::Message;

/// In-flight Replication-segment configuration, mirroring the YANG list:
///
/// ```yang
/// list replication-segment {
///   key "name";
///   leaf name { type string; }
///   leaf sid  { type inet:ipv6-address; }        // the End.Replicate SID
///   leaf hop-limit-threshold { type uint8; }     // RFC 9524 (0 = disabled)
///   list branch {
///     key "sid";
///     leaf sid { type inet:ipv6-address; }        // downstream Replication-SID
///     leaf nexthop-id { type uint32; }            // 0 = FIB6-on-sid
///   }
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct ReplSegConfig {
    pub delete: bool,
    /// The local `End.Replicate` SID (the `REPL_SEG` map key).
    pub sid: Option<Ipv6Addr>,
    /// RFC 9524 Hop-Limit Threshold.
    pub hop_limit_threshold: u8,
    /// Downstream branches: branch (downstream Replication-)SID → nexthop id
    /// (0 = resolve by a FIB6 lookup on the branch SID).
    pub branches: BTreeMap<Ipv6Addr, u32>,
}

pub struct ReplSegBuilder {
    pub config: BTreeMap<String, ReplSegConfig>,
    pub cache: BTreeMap<String, ReplSegConfig>,
    builder: ConfigBuilder,
}

impl ReplSegBuilder {
    pub fn new() -> Self {
        ReplSegBuilder {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const NAME_ERR: &str = "missing replication-segment name argument";

        let func = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name: String = args.string().context(NAME_ERR)?;

        func(&mut self.config, &mut self.cache, &name, &mut args)
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        while let Some((name, config)) = self.cache.pop_first() {
            if config.delete {
                self.config.remove(&name);
                let _ = tx.send(Message::ReplSegDel { name });
            } else {
                self.config.insert(name.clone(), config.clone());
                let _ = tx.send(Message::ReplSegAdd { name, config });
            }
        }
    }
}

type Handler = fn(
    config: &mut BTreeMap<String, ReplSegConfig>,
    cache: &mut BTreeMap<String, ReplSegConfig>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(config: &BTreeMap<String, ReplSegConfig>, name: &String) -> ReplSegConfig {
    config.get(name).cloned().unwrap_or_default()
}

fn config_lookup(config: &BTreeMap<String, ReplSegConfig>, name: &String) -> Option<ReplSegConfig> {
    config.get(name).cloned()
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, ReplSegConfig>,
    cache: &'a mut BTreeMap<String, ReplSegConfig>,
    name: &'a String,
) -> Option<&'a mut ReplSegConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, ReplSegConfig>,
    cache: &'a mut BTreeMap<String, ReplSegConfig>,
    name: &'a String,
) -> Option<&'a mut ReplSegConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.clone(), config_lookup(config, name)?);
    }
    let cache = cache.get_mut(name)?;
    if cache.delete { None } else { Some(cache) }
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        const CONFIG_ERR: &str = "missing config";
        const SID_ERR: &str = "expected ipv6 address";
        const HLT_ERR: &str = "expected uint8 hop-limit-threshold";
        const BRANCH_ERR: &str = "expected ipv6 branch SID";
        const NH_ERR: &str = "expected uint32 nexthop-id";

        ConfigBuilder::default()
            .path("")
            .set(|config, cache, name, _args| {
                let _ = cache_get(config, cache, name).context(CONFIG_ERR)?;
                Ok(())
            })
            .del(|config, cache, name, _args| {
                if let Some(s) = cache.get_mut(name) {
                    s.delete = true;
                } else {
                    let mut s = config_lookup(config, name).context(CONFIG_ERR)?;
                    s.delete = true;
                    cache.insert(name.clone(), s);
                }
                Ok(())
            })
            .path("/sid")
            .set(|config, cache, name, args| {
                let sid = args.v6addr().context(SID_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.sid = Some(sid);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.sid = None;
                Ok(())
            })
            .path("/hop-limit-threshold")
            .set(|config, cache, name, args| {
                let hlt = args.u8().context(HLT_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.hop_limit_threshold = hlt;
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.hop_limit_threshold = 0;
                Ok(())
            })
            // Nested `branch` list, keyed by the branch SID (the second key
            // after the segment name, read from `args` here). The list-entry
            // set/del adds/removes the branch; `/branch/nexthop-id` sets its
            // explicit underlay nexthop (0 = FIB6-on-sid).
            .path("/branch")
            .set(|config, cache, name, args| {
                let bsid = args.v6addr().context(BRANCH_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.branches.entry(bsid).or_insert(0);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let bsid = args.v6addr().context(BRANCH_ERR)?;
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.branches.remove(&bsid);
                Ok(())
            })
            .path("/branch/nexthop-id")
            .set(|config, cache, name, args| {
                let bsid = args.v6addr().context(BRANCH_ERR)?;
                let nh = args.u32().context(NH_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.branches.insert(bsid, nh);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let bsid = args.v6addr().context(BRANCH_ERR)?;
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(v) = s.branches.get_mut(&bsid) {
                    *v = 0;
                }
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/segment-routing/replication-segment";
        self.path = format!("{prefix}{path}");
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
