use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use crate::config::{Args, ConfigOp};

use super::Isis;

/// IS-IS-local named affinity (admin-group) table. Each entry binds an
/// operator-friendly name to a bit position in the 256-bit Extended
/// Admin Group bitmap (RFC 7308). Mirrors the YANG list at
/// /router/isis/affinity-map/affinity.
///
/// Held inside the IS-IS instance to match IOS-XR placement; promotable
/// to a global sibling of /srlg once OSPF flex-algo arrives.
#[derive(Default)]
pub struct AffinityMap {
    pub config: BTreeMap<String, AffinityEntry>,
    pub cache: BTreeMap<String, AffinityEntry>,
    builder: ConfigBuilder,
}

#[derive(Debug, Default, Clone)]
pub struct AffinityEntry {
    pub delete: bool,
    pub bit_position: Option<u16>,
}

impl AffinityMap {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: config_builder(),
        }
    }

    /// Stage one leaf update into the pending cache. Mirrors
    /// `FlexAlgoConfig::exec` / `StaticConfig::exec`.
    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing affinity-map config handler";
        const NAME_ERR: &str = "missing affinity name arg";

        let func = self.builder.map.get(&(path, op)).context(CONFIG_ERR)?;
        let name = args.string().context(NAME_ERR)?;
        func(&mut self.config, &mut self.cache, name, &mut args)
    }

    pub fn commit(&mut self) {
        while let Some((name, entry)) = self.cache.pop_first() {
            if entry.delete {
                self.config.remove(&name);
            } else {
                self.config.insert(name, entry);
            }
        }
    }

    /// Bit position currently committed for `name`, if any. Used at
    /// LSP-build time to assemble the per-link 256-bit Extended Admin
    /// Group bitmap from the names attached to each link.
    #[allow(dead_code)]
    pub fn bit(&self, name: &str) -> Option<u16> {
        self.config.get(name).and_then(|e| e.bit_position)
    }
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    pub map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    config: &mut BTreeMap<String, AffinityEntry>,
    cache: &mut BTreeMap<String, AffinityEntry>,
    name: String,
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

fn config_get(config: &BTreeMap<String, AffinityEntry>, name: &str) -> AffinityEntry {
    config.get(name).cloned().unwrap_or_default()
}

fn config_lookup(config: &BTreeMap<String, AffinityEntry>, name: &str) -> Option<AffinityEntry> {
    config.get(name).cloned()
}

fn cache_get<'a>(
    config: &BTreeMap<String, AffinityEntry>,
    cache: &'a mut BTreeMap<String, AffinityEntry>,
    name: String,
) -> Option<&'a mut AffinityEntry> {
    if !cache.contains_key(&name) {
        cache.insert(name.clone(), config_get(config, &name));
    }
    cache.get_mut(&name)
}

fn cache_lookup<'a>(
    config: &BTreeMap<String, AffinityEntry>,
    cache: &'a mut BTreeMap<String, AffinityEntry>,
    name: String,
) -> Option<&'a mut AffinityEntry> {
    if !cache.contains_key(&name) {
        cache.insert(name.clone(), config_lookup(config, &name)?);
    }
    let entry = cache.get_mut(&name)?;
    if entry.delete { None } else { Some(entry) }
}

fn config_builder() -> ConfigBuilder {
    const CONFIG_ERR: &str = "affinity entry parse error";
    const BIT_ERR: &str = "affinity bit-position parse error";

    ConfigBuilder::default()
        .path("/router/isis/affinity-map/affinity")
        .set(|config, cache, name, _args| {
            let _ = cache_get(config, cache, name).context(CONFIG_ERR)?;
            Ok(())
        })
        .del(|config, cache, name, _args| {
            if let Some(e) = cache.get_mut(&name) {
                e.delete = true;
            } else {
                let mut e = config_lookup(config, &name).context(CONFIG_ERR)?;
                e.delete = true;
                cache.insert(name, e);
            }
            Ok(())
        })
        .path("/router/isis/affinity-map/affinity/bit-position")
        .set(|config, cache, name, args| {
            let bit = args.u16().context(BIT_ERR)?;
            if bit > 255 {
                bail!("affinity bit-position must be 0..=255 (got {bit})");
            }
            let e = cache_get(config, cache, name).context(CONFIG_ERR)?;
            e.bit_position = Some(bit);
            Ok(())
        })
        .del(|config, cache, name, _args| {
            let e = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
            e.bit_position = None;
            Ok(())
        })
}

macro_rules! affinity_cb {
    ($name:ident, $path:literal) => {
        fn $name(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
            isis.affinity_map.exec($path.to_string(), args, op).ok()?;
            isis.affinity_map.commit();
            // Affinity-name → bit changes feed straight into the
            // Extended Admin Group bitmaps inside originated FADs;
            // re-originate both levels so peers see the new bits
            // without waiting for the refresh timer.
            let _ = isis
                .tx
                .send(super::Message::LspOriginate(super::Level::L1, None));
            let _ = isis
                .tx
                .send(super::Message::LspOriginate(super::Level::L2, None));
            Some(())
        }
    };
}

affinity_cb!(cb_entry, "/router/isis/affinity-map/affinity");
affinity_cb!(
    cb_bit_position,
    "/router/isis/affinity-map/affinity/bit-position"
);

pub fn callback_register(isis: &mut Isis) {
    isis.callback_add("/router/isis/affinity-map/affinity", cb_entry);
    isis.callback_add(
        "/router/isis/affinity-map/affinity/bit-position",
        cb_bit_position,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect::<VecDeque<_>>())
    }

    #[test]
    fn set_then_commit_persists_bit() {
        let mut am = AffinityMap::new();
        am.exec(
            "/router/isis/affinity-map/affinity/bit-position".into(),
            args(&["blue", "4"]),
            ConfigOp::Set,
        )
        .unwrap();
        am.commit();
        assert_eq!(am.bit("blue"), Some(4));
    }

    #[test]
    fn delete_removes_entry() {
        let mut am = AffinityMap::new();
        am.exec(
            "/router/isis/affinity-map/affinity/bit-position".into(),
            args(&["blue", "4"]),
            ConfigOp::Set,
        )
        .unwrap();
        am.commit();
        am.exec(
            "/router/isis/affinity-map/affinity".into(),
            args(&["blue"]),
            ConfigOp::Delete,
        )
        .unwrap();
        am.commit();
        assert_eq!(am.bit("blue"), None);
        assert!(!am.config.contains_key("blue"));
    }

    #[test]
    fn bit_out_of_range_rejected() {
        let mut am = AffinityMap::new();
        let err = am
            .exec(
                "/router/isis/affinity-map/affinity/bit-position".into(),
                args(&["blue", "256"]),
                ConfigOp::Set,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("0..=255"), "unexpected err: {err}");
    }
}
