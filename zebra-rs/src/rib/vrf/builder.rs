use std::collections::BTreeMap;

use anyhow::{Context, Result};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::Message;

use super::VrfConfig;

/// Stage `set vrf NAME` / `delete vrf NAME` calls and emit
/// `Message::VrfAdd` / `Message::VrfDel` on commit.
///
/// Layout matches `BridgeBuilder` / `VxlanBuilder` — `config` is the
/// committed map; `cache` is the in-flight edit set built up across an
/// entire commit batch and drained by `commit()`.
pub struct VrfBuilder {
    pub config: BTreeMap<String, VrfConfig>,
    pub cache: BTreeMap<String, VrfConfig>,
    builder: ConfigBuilder,
}

impl VrfBuilder {
    pub fn new() -> Self {
        VrfBuilder {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const VRF_ERR: &str = "missing vrf name argument";

        let func = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name: String = args.string().context(VRF_ERR)?;

        func(&mut self.config, &mut self.cache, &name, &mut args)
    }

    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        while let Some((name, config)) = self.cache.pop_first() {
            if config.delete {
                self.config.remove(&name);
                let _ = tx.send(Message::VrfDel { name });
            } else {
                self.config.insert(name.clone(), config);
                let _ = tx.send(Message::VrfAdd { name });
            }
        }
    }
}

impl Default for VrfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

type Handler = fn(
    config: &mut BTreeMap<String, VrfConfig>,
    cache: &mut BTreeMap<String, VrfConfig>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(config: &BTreeMap<String, VrfConfig>, name: &String) -> VrfConfig {
    let Some(entry) = config.get(name) else {
        return VrfConfig::default();
    };
    entry.clone()
}

fn config_lookup(config: &BTreeMap<String, VrfConfig>, name: &String) -> Option<VrfConfig> {
    let entry = config.get(name)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, VrfConfig>,
    cache: &'a mut BTreeMap<String, VrfConfig>,
    name: &'a String,
) -> Option<&'a mut VrfConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        const CONFIG_ERR: &str = "missing config";

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
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/vrf";
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
