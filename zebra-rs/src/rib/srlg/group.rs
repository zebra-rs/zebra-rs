//! Shared Risk Link Group (SRLG) configuration. Per-protocol modules
//! (IS-IS, OSPF) read this table by name from their per-interface
//! `srlg` leaf-list and emit the resolved 32-bit value in their TE
//! extensions (IS-IS top-level TLV 138 for IPv4 / TLV 139 for IPv6,
//! RFC 5307 / RFC 6119; OSPF-TE SRLG sub-TLV, RFC 4203).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::Message;

/// Applied snapshot of a named SRLG group, exported via the RIB's
/// `srlg_groups` table. `value` is the 32-bit identifier advertised on
/// the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrlgGroup {
    pub name: String,
    pub value: u32,
}

/// In-flight SRLG group configuration, mirroring the YANG list shape:
///
/// ```yang
/// list group {
///   key "name";
///   leaf name  { type string; }
///   leaf value { type uint32; mandatory true; }
/// }
/// ```
///
/// `value` is `Option<u32>` because the leaf can be set/cleared
/// independently during a commit cycle. The applied snapshot only
/// reaches `Rib::srlg_groups` once a value is present — a group with
/// no value is dropped from the table.
#[derive(Debug, Default, Clone)]
pub struct SrlgGroupConfig {
    pub delete: bool,
    pub value: Option<u32>,
}

pub struct SrlgGroupBuilder {
    pub config: BTreeMap<String, SrlgGroupConfig>,
    pub cache: BTreeMap<String, SrlgGroupConfig>,
    builder: ConfigBuilder,
}

impl SrlgGroupBuilder {
    pub fn new() -> Self {
        SrlgGroupBuilder {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const NAME_ERR: &str = "missing srlg group name argument";

        let func = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name: String = args.string().context(NAME_ERR)?;

        func(&mut self.config, &mut self.cache, &name, &mut args)
    }

    /// Fold the staging `cache` into `config`, then push a single full
    /// snapshot via `Message::SrlgUpdate`. The full-snapshot push
    /// matches the design contract: subscribers always receive the
    /// entire SRLG table on every change, not deltas.
    pub fn commit(&mut self, tx: UnboundedSender<Message>) {
        let mut changed = false;
        while let Some((name, config)) = self.cache.pop_first() {
            changed = true;
            if config.delete {
                self.config.remove(&name);
            } else {
                self.config.insert(name, config);
            }
        }
        if !changed {
            return;
        }
        let groups: BTreeMap<String, SrlgGroup> = self
            .config
            .iter()
            .filter_map(|(name, c)| {
                c.value.map(|v| {
                    (
                        name.clone(),
                        SrlgGroup {
                            name: name.clone(),
                            value: v,
                        },
                    )
                })
            })
            .collect();
        let _ = tx.send(Message::SrlgUpdate { groups });
    }
}

type Handler = fn(
    config: &mut BTreeMap<String, SrlgGroupConfig>,
    cache: &mut BTreeMap<String, SrlgGroupConfig>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(config: &BTreeMap<String, SrlgGroupConfig>, name: &String) -> SrlgGroupConfig {
    let Some(entry) = config.get(name) else {
        return SrlgGroupConfig::default();
    };
    entry.clone()
}

fn config_lookup(
    config: &BTreeMap<String, SrlgGroupConfig>,
    name: &String,
) -> Option<SrlgGroupConfig> {
    let entry = config.get(name)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, SrlgGroupConfig>,
    cache: &'a mut BTreeMap<String, SrlgGroupConfig>,
    name: &'a String,
) -> Option<&'a mut SrlgGroupConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, SrlgGroupConfig>,
    cache: &'a mut BTreeMap<String, SrlgGroupConfig>,
    name: &'a String,
) -> Option<&'a mut SrlgGroupConfig> {
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
            .path("/value")
            .set(|config, cache, name, args| {
                let v = args.u32().context(VALUE_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.value = Some(v);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.value = None;
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/srlg/group";
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
    fn group_without_value_is_dropped_from_snapshot() {
        // YANG marks `value` mandatory, so this state shouldn't reach
        // commit in practice — but `commit()` must still skip such
        // entries rather than emit a placeholder. Verifies the
        // filter_map in commit().
        let mut b = SrlgGroupBuilder::new();
        b.config.insert(
            "ghost".into(),
            SrlgGroupConfig {
                delete: false,
                value: None,
            },
        );
        // Manually seed a "changed" entry so commit() runs the snapshot
        // build (cache must be non-empty for the early-return guard).
        b.cache.insert(
            "real".into(),
            SrlgGroupConfig {
                delete: false,
                value: Some(42),
            },
        );

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        b.commit(tx);

        match rx.try_recv().expect("SrlgUpdate emitted") {
            Message::SrlgUpdate { groups } => {
                assert!(groups.contains_key("real"));
                assert!(!groups.contains_key("ghost"));
                assert_eq!(groups["real"].value, 42);
            }
            _ => panic!("expected SrlgUpdate"),
        }
    }

    #[test]
    fn no_message_when_nothing_changed() {
        // commit() with empty cache should be a no-op — protocols
        // shouldn't see a spurious push when an unrelated commit fires.
        let mut b = SrlgGroupBuilder::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        b.commit(tx);
        assert!(rx.try_recv().is_err());
    }
}
