use std::collections::BTreeMap;

use anyhow::{Context, Result};

use crate::config::{Args, ConfigOp};

use super::{CryptoAlgorithm, Key, KeyChain, Lifetime, LifetimeEnd};

#[derive(Default)]
pub struct KeyChainSetConfig {
    pub config: BTreeMap<String, KeyChain>,
    pub cache: BTreeMap<String, KeyChain>,
    builder: ConfigBuilder,
}

impl KeyChainSetConfig {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const KEY_CHAIN_NAME_ERR: &str = "missing key-chain name arg";

        let handler = self
            .builder
            .map
            .get(&(path.to_string(), op))
            .context(CONFIG_ERR)?;

        let name = args.string().context(KEY_CHAIN_NAME_ERR)?;

        handler(&mut self.config, &mut self.cache, &name, &mut args)
    }

    /// Drain the per-commit cache into the canonical map, firing
    /// `key_chain_update` / `key_chain_remove` on the supplied
    /// `Syncer`. Mirrors `PrefixSetConfig::commit`.
    pub fn commit<S: crate::policy::Syncer>(
        config: &mut BTreeMap<String, KeyChain>,
        cache: &mut BTreeMap<String, KeyChain>,
        syncer: S,
    ) {
        while let Some((name, kc)) = cache.pop_first() {
            if kc.delete {
                syncer.key_chain_remove(&name);
                config.remove(&name);
            } else {
                syncer.key_chain_update(&name, &kc);
                config.insert(name, kc);
            }
        }
    }
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    config: &mut BTreeMap<String, KeyChain>,
    cache: &mut BTreeMap<String, KeyChain>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(map: &BTreeMap<String, KeyChain>, name: &String) -> KeyChain {
    map.get(name).cloned().unwrap_or_default()
}

fn config_lookup(map: &BTreeMap<String, KeyChain>, name: &String) -> Option<KeyChain> {
    map.get(name).cloned()
}

/// Fetch-or-create the cache entry, seeded from the canonical map.
/// Used for SET handlers: a new chain or a new leaf inside an existing
/// chain both want a writeable entry.
fn cache_get<'a>(
    config: &'a BTreeMap<String, KeyChain>,
    cache: &'a mut BTreeMap<String, KeyChain>,
    name: &'a String,
) -> Option<&'a mut KeyChain> {
    if !cache.contains_key(name) {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

/// Fetch the cache entry, seeded from the canonical map *only if*
/// it already exists there. Used for DELETE handlers — deleting a
/// child of a chain that never existed should fail loudly rather
/// than implicitly resurrect it.
fn cache_lookup<'a>(
    config: &'a BTreeMap<String, KeyChain>,
    cache: &'a mut BTreeMap<String, KeyChain>,
    name: &'a String,
) -> Option<&'a mut KeyChain> {
    if !cache.contains_key(name) {
        cache.insert(name.to_string(), config_lookup(config, name)?);
    }
    let entry = cache.get_mut(name)?;
    if entry.delete { None } else { Some(entry) }
}

fn parse_yang_datetime(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// Replace the end-time half of both send + accept lifetime with
/// `new_end`. Mirrors the OSPF helper this PR will eventually
/// supersede: the YANG `case start-end-time` lets `start-date-time`
/// and one of `no-end-time` / `duration` / `end-date-time` arrive in
/// any order; if `Always` is still in place we default the start to
/// UNIX_EPOCH so the bound is well-defined.
fn set_send_accept_end(key: &mut Key, new_end: LifetimeEnd) {
    let start = match key.send_lifetime {
        Lifetime::Window { start, .. } => start,
        Lifetime::Always => chrono::DateTime::UNIX_EPOCH,
    };
    let lt = Lifetime::Window {
        start,
        end: new_end,
    };
    key.send_lifetime = lt.clone();
    key.accept_lifetime = lt;
}

impl ConfigBuilder {
    pub fn new() -> Self {
        const CONFIG_ERR: &str = "missing config";
        const KEY_ID_ERR: &str = "missing key-id";
        const VALUE_ERR: &str = "missing value";

        ConfigBuilder::default()
            // /key-chains/key-chain {name}
            .path("/key-chain")
            .set(|config, cache, name, _args| {
                let _ = cache_get(config, cache, name).context(CONFIG_ERR)?;
                Ok(())
            })
            .del(|config, cache, name, _args| {
                if let Some(kc) = cache.get_mut(name) {
                    kc.delete = true;
                } else {
                    let mut kc = config_lookup(config, name).context(CONFIG_ERR)?;
                    kc.delete = true;
                    cache.insert(name.to_string(), kc);
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/description
            .path("/key-chain/description")
            .set(|config, cache, name, args| {
                let desc = args.string().context(VALUE_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                kc.description = Some(desc);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                kc.description = None;
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}
            .path("/key-chain/key")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                kc.keys.entry(key_id).or_default();
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                kc.keys.remove(&key_id);
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/crypto-algorithm
            .path("/key-chain/key/crypto-algorithm")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let algo_name = args.string().context(VALUE_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                key.algo = CryptoAlgorithm::from_identity(&algo_name);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    k.algo = None;
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/key-string/keystring
            .path("/key-chain/key/key-string/keystring")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let s = args.string().context(VALUE_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                key.key_material = s.into_bytes();
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    k.key_material.clear();
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/key-string/hexadecimal-string
            .path("/key-chain/key/key-string/hexadecimal-string")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let hex_in = args.string().context(VALUE_ERR)?;
                let cleaned: String = hex_in
                    .chars()
                    .filter(|c| !c.is_whitespace() && *c != ':')
                    .collect();
                // Mirror BGP's existing behavior: a malformed hex
                // string drops silently so the rest of the commit
                // still applies. The YANG layer is expected to do
                // the strict validation.
                let Ok(decoded) = hex::decode(&cleaned) else {
                    return Ok(());
                };
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                key.key_material = decoded;
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    k.key_material.clear();
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/send-id
            .path("/key-chain/key/send-id")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let v = args.u8().context(VALUE_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                key.send_id = Some(v);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    k.send_id = None;
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/recv-id
            .path("/key-chain/key/recv-id")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let v = args.u8().context(VALUE_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                key.recv_id = Some(v);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    k.recv_id = None;
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/lifetime/send-accept-lifetime/always
            .path("/key-chain/key/lifetime/send-accept-lifetime/always")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                key.send_lifetime = Lifetime::Always;
                key.accept_lifetime = Lifetime::Always;
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    k.send_lifetime = Lifetime::Always;
                    k.accept_lifetime = Lifetime::Always;
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/lifetime/send-accept-lifetime/start-date-time
            .path("/key-chain/key/lifetime/send-accept-lifetime/start-date-time")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let ts = args.string().context(VALUE_ERR)?;
                let start = parse_yang_datetime(&ts).context(VALUE_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                let preserved_end = match &key.send_lifetime {
                    Lifetime::Window { end, .. } => end.clone(),
                    Lifetime::Always => LifetimeEnd::NoEnd,
                };
                let lt = Lifetime::Window {
                    start,
                    end: preserved_end,
                };
                key.send_lifetime = lt.clone();
                key.accept_lifetime = lt;
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    k.send_lifetime = Lifetime::Always;
                    k.accept_lifetime = Lifetime::Always;
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/lifetime/send-accept-lifetime/no-end-time
            .path("/key-chain/key/lifetime/send-accept-lifetime/no-end-time")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                set_send_accept_end(key, LifetimeEnd::NoEnd);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    set_send_accept_end(k, LifetimeEnd::NoEnd);
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/lifetime/send-accept-lifetime/end-date-time
            .path("/key-chain/key/lifetime/send-accept-lifetime/end-date-time")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let ts = args.string().context(VALUE_ERR)?;
                let end = parse_yang_datetime(&ts).context(VALUE_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                set_send_accept_end(key, LifetimeEnd::EndAt(end));
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    set_send_accept_end(k, LifetimeEnd::NoEnd);
                }
                Ok(())
            })
            // /key-chains/key-chain {name}/key {key-id}/lifetime/send-accept-lifetime/duration
            .path("/key-chain/key/lifetime/send-accept-lifetime/duration")
            .set(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let secs = args.u32().context(VALUE_ERR)?;
                let kc = cache_get(config, cache, name).context(CONFIG_ERR)?;
                let key = kc.keys.entry(key_id).or_default();
                set_send_accept_end(key, LifetimeEnd::Duration(secs));
                Ok(())
            })
            .del(|config, cache, name, args| {
                let key_id = args.u64().context(KEY_ID_ERR)?;
                let kc = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                if let Some(k) = kc.keys.get_mut(&key_id) {
                    set_send_accept_end(k, LifetimeEnd::NoEnd);
                }
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/key-chains";
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
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::policy::{KeyChain, PolicyList, PrefixSet, Syncer};

    fn args(parts: &[&str]) -> Args {
        Args(parts.iter().map(|s| s.to_string()).collect::<VecDeque<_>>())
    }

    #[derive(Default)]
    struct CollectingSyncer {
        updates: RefCell<Vec<(String, KeyChain)>>,
        removes: RefCell<Vec<String>>,
    }

    impl Syncer for CollectingSyncer {
        fn prefix_set_update(&self, _: &str, _: &PrefixSet) {}
        fn prefix_set_remove(&self, _: &str) {}
        fn policy_list_update(&self, _: &str, _: &PolicyList) {}
        fn policy_list_remove(&self, _: &str) {}
        fn key_chain_update(&self, name: &str, kc: &KeyChain) {
            self.updates
                .borrow_mut()
                .push((name.to_string(), kc.clone()));
        }
        fn key_chain_remove(&self, name: &str) {
            self.removes.borrow_mut().push(name.to_string());
        }
    }

    fn commit(cfg: &mut KeyChainSetConfig) -> CollectingSyncer {
        let syncer = CollectingSyncer::default();
        KeyChainSetConfig::commit(&mut cfg.config, &mut cfg.cache, &syncer);
        syncer
    }

    impl Syncer for &CollectingSyncer {
        fn key_chain_update(&self, name: &str, kc: &KeyChain) {
            (*self).key_chain_update(name, kc)
        }
        fn key_chain_remove(&self, name: &str) {
            (*self).key_chain_remove(name)
        }
    }

    /// Setting a `/key-chains/key-chain` root then a leaf
    /// underneath should land a single populated entry in the
    /// canonical map and fire one Syncer update.
    #[test]
    fn create_then_set_keystring_lands_one_update() {
        let mut cfg = KeyChainSetConfig::new();
        cfg.exec(
            "/key-chains/key-chain".into(),
            args(&["chain1"]),
            ConfigOp::Set,
        )
        .unwrap();
        cfg.exec(
            "/key-chains/key-chain/key".into(),
            args(&["chain1", "1"]),
            ConfigOp::Set,
        )
        .unwrap();
        cfg.exec(
            "/key-chains/key-chain/key/crypto-algorithm".into(),
            args(&["chain1", "1", "hmac-sha-256"]),
            ConfigOp::Set,
        )
        .unwrap();
        cfg.exec(
            "/key-chains/key-chain/key/key-string/keystring".into(),
            args(&["chain1", "1", "secret"]),
            ConfigOp::Set,
        )
        .unwrap();

        let s = commit(&mut cfg);
        assert!(s.removes.borrow().is_empty());
        let updates = s.updates.borrow();
        assert_eq!(updates.len(), 1);
        let (name, kc) = &updates[0];
        assert_eq!(name, "chain1");
        let key = kc.keys.get(&1).unwrap();
        assert_eq!(key.algo, Some(CryptoAlgorithm::HmacSha256));
        assert_eq!(key.key_material, b"secret");
        assert!(cfg.config.contains_key("chain1"));
        assert!(cfg.cache.is_empty(), "cache must drain on commit");
    }

    /// Deleting the chain root collapses cleanly into one
    /// Syncer remove notification, and removes the entry from
    /// the canonical map.
    #[test]
    fn delete_chain_fires_remove_and_drops_entry() {
        let mut cfg = KeyChainSetConfig::new();
        cfg.exec(
            "/key-chains/key-chain".into(),
            args(&["chain1"]),
            ConfigOp::Set,
        )
        .unwrap();
        let _ = commit(&mut cfg);
        assert!(cfg.config.contains_key("chain1"));

        cfg.exec(
            "/key-chains/key-chain".into(),
            args(&["chain1"]),
            ConfigOp::Delete,
        )
        .unwrap();
        let s = commit(&mut cfg);
        assert_eq!(*s.removes.borrow(), vec!["chain1".to_string()]);
        assert!(s.updates.borrow().is_empty());
        assert!(!cfg.config.contains_key("chain1"));
    }

    /// hexadecimal-string variant decodes hex into raw bytes.
    #[test]
    fn hex_string_decodes_into_key_material() {
        let mut cfg = KeyChainSetConfig::new();
        cfg.exec("/key-chains/key-chain".into(), args(&["c"]), ConfigOp::Set)
            .unwrap();
        cfg.exec(
            "/key-chains/key-chain/key".into(),
            args(&["c", "1"]),
            ConfigOp::Set,
        )
        .unwrap();
        cfg.exec(
            "/key-chains/key-chain/key/key-string/hexadecimal-string".into(),
            args(&["c", "1", "deadbeef"]),
            ConfigOp::Set,
        )
        .unwrap();
        let _ = commit(&mut cfg);
        let key = cfg.config.get("c").unwrap().keys.get(&1).unwrap();
        assert_eq!(key.key_material, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    /// start-date-time + duration arriving in two separate handler
    /// calls (the YANG callbacks fire independently) compose into a
    /// single Window lifetime — the `set_send_accept_end` helper
    /// must preserve the prior start when only the end changes.
    #[test]
    fn start_then_duration_compose_into_window() {
        let mut cfg = KeyChainSetConfig::new();
        cfg.exec("/key-chains/key-chain".into(), args(&["c"]), ConfigOp::Set)
            .unwrap();
        cfg.exec(
            "/key-chains/key-chain/key".into(),
            args(&["c", "1"]),
            ConfigOp::Set,
        )
        .unwrap();
        cfg.exec(
            "/key-chains/key-chain/key/lifetime/send-accept-lifetime/start-date-time".into(),
            args(&["c", "1", "2026-01-01T00:00:00Z"]),
            ConfigOp::Set,
        )
        .unwrap();
        cfg.exec(
            "/key-chains/key-chain/key/lifetime/send-accept-lifetime/duration".into(),
            args(&["c", "1", "3600"]),
            ConfigOp::Set,
        )
        .unwrap();
        let _ = commit(&mut cfg);
        let key = cfg.config.get("c").unwrap().keys.get(&1).unwrap();
        match &key.send_lifetime {
            Lifetime::Window {
                start,
                end: LifetimeEnd::Duration(secs),
            } => {
                assert_eq!(start.to_rfc3339(), "2026-01-01T00:00:00+00:00");
                assert_eq!(*secs, 3600);
            }
            other => panic!("expected Window+Duration, got {other:?}"),
        }
        // send and accept lifetimes are kept in lockstep by the
        // send-accept-lifetime YANG choice.
        assert_eq!(key.send_lifetime, key.accept_lifetime);
    }
}
