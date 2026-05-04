//! SR-MPLS label block (SRGB + SRLB) configuration. Per-protocol modules
//! (IS-IS, OSPF, BGP-LU) reference a block by name from their
//! `segment-routing/mpls/block` leaf.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::Message;
use crate::spf::label_block::LabelBlock;

/// Applied snapshot of an SR-MPLS block, exported to the rest of the system
/// once a config commit lands. `global` and `local` are populated only when
/// both `start` and `range` were configured for the corresponding container.
///
/// Fields carry `#[allow(dead_code)]` until the IS-IS-side `mpls/block`
/// handler reads them by name from `Rib::blocks`.
#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct Block {
    pub name: String,
    /// SR Global Block (SRGB) — prefix-SID label range.
    pub global: Option<LabelBlock>,
    /// SR Local Block (SRLB) — adjacency-SID label range.
    pub local: Option<LabelBlock>,
}

/// Canonical name of the default block, always present in `Rib::blocks`.
/// Operators get this for free without explicit configuration; protocols
/// that subscribe to "default" without a custom block fall back to it.
pub const DEFAULT_BLOCK_NAME: &str = "default";

const DEFAULT_GLOBAL_START: u32 = 16000;
const DEFAULT_GLOBAL_RANGE: u32 = 8000;
const DEFAULT_LOCAL_START: u32 = 15000;
const DEFAULT_LOCAL_RANGE: u32 = 100;

impl Block {
    /// The default block — seeded into `Rib::blocks` at startup and re-seeded
    /// after a delete of the same name. SRGB 16000..23999 + SRLB 15000..15099.
    pub fn default_block() -> Self {
        Self {
            name: DEFAULT_BLOCK_NAME.to_string(),
            global: Some(LabelBlock::new(DEFAULT_GLOBAL_START, DEFAULT_GLOBAL_RANGE)),
            local: Some(LabelBlock::new(DEFAULT_LOCAL_START, DEFAULT_LOCAL_RANGE)),
        }
    }
}

/// In-flight Block configuration, mirroring the YANG list shape:
///
/// ```yang
/// list block {
///   key "name";
///   leaf name { type string; }
///   container global { leaf start; leaf range; }
///   container local  { leaf start; leaf range; }
/// }
/// ```
///
/// Each individual leaf can be set/cleared independently during a commit
/// cycle; conversion to the applied `Block` only emits a `LabelBlock` when
/// both `start` and `range` are present together.
#[derive(Debug, Default, Clone)]
pub struct BlockConfig {
    pub delete: bool,
    pub global_start: Option<u32>,
    pub global_range: Option<u32>,
    pub local_start: Option<u32>,
    pub local_range: Option<u32>,
}

impl BlockConfig {
    pub fn to_block(&self, name: &str) -> Block {
        let global = match (self.global_start, self.global_range) {
            (Some(start), Some(range)) => Some(LabelBlock::new(start, range)),
            _ => None,
        };
        let local = match (self.local_start, self.local_range) {
            (Some(start), Some(range)) => Some(LabelBlock::new(start, range)),
            _ => None,
        };
        Block {
            name: name.to_string(),
            global,
            local,
        }
    }
}

pub struct BlockBuilder {
    pub config: BTreeMap<String, BlockConfig>,
    pub cache: BTreeMap<String, BlockConfig>,
    builder: ConfigBuilder,
}

impl BlockBuilder {
    pub fn new() -> Self {
        BlockBuilder {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const NAME_ERR: &str = "missing block name argument";

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
                let _ = tx.send(Message::BlockDel { name });
            } else {
                self.config.insert(name.clone(), config.clone());
                let _ = tx.send(Message::BlockAdd { name, config });
            }
        }
    }
}

type Handler = fn(
    config: &mut BTreeMap<String, BlockConfig>,
    cache: &mut BTreeMap<String, BlockConfig>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(config: &BTreeMap<String, BlockConfig>, name: &String) -> BlockConfig {
    let Some(entry) = config.get(name) else {
        return BlockConfig::default();
    };
    entry.clone()
}

fn config_lookup(config: &BTreeMap<String, BlockConfig>, name: &String) -> Option<BlockConfig> {
    let entry = config.get(name)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, BlockConfig>,
    cache: &'a mut BTreeMap<String, BlockConfig>,
    name: &'a String,
) -> Option<&'a mut BlockConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, BlockConfig>,
    cache: &'a mut BTreeMap<String, BlockConfig>,
    name: &'a String,
) -> Option<&'a mut BlockConfig> {
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
        const VALUE_ERR: &str = "expected u32";

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
            .path("/global/start")
            .set(|config, cache, name, args| {
                let v = args.u32().context(VALUE_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.global_start = Some(v);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.global_start = None;
                Ok(())
            })
            .path("/global/range")
            .set(|config, cache, name, args| {
                let v = args.u32().context(VALUE_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.global_range = Some(v);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.global_range = None;
                Ok(())
            })
            .path("/local/start")
            .set(|config, cache, name, args| {
                let v = args.u32().context(VALUE_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.local_start = Some(v);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.local_start = None;
                Ok(())
            })
            .path("/local/range")
            .set(|config, cache, name, args| {
                let v = args.u32().context(VALUE_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.local_range = Some(v);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.local_range = None;
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/segment-routing/block";
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_block_has_canonical_values() {
        let b = Block::default_block();
        assert_eq!(b.name, DEFAULT_BLOCK_NAME);

        // LabelBlock stores (start, end = start + range), so verify the
        // pair through that derived shape.
        let global = b.global.expect("default block has SRGB");
        assert_eq!(global.start, DEFAULT_GLOBAL_START);
        assert_eq!(global.end, DEFAULT_GLOBAL_START + DEFAULT_GLOBAL_RANGE);

        let local = b.local.expect("default block has SRLB");
        assert_eq!(local.start, DEFAULT_LOCAL_START);
        assert_eq!(local.end, DEFAULT_LOCAL_START + DEFAULT_LOCAL_RANGE);
    }

    #[test]
    fn default_block_uses_canonical_name() {
        // The seeded default lives at the literal name "default" — that's
        // the name protocols watch when no explicit block is configured.
        assert_eq!(DEFAULT_BLOCK_NAME, "default");
    }
}
