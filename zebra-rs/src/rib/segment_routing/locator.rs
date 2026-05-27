//! SRv6 locator configuration. Per-protocol modules (IS-IS, OSPF, BGP-LU)
//! reference a locator by name from their `segment-routing/srv6/locator`
//! leaf.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use ipnet::Ipv6Net;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::rib::Message;

/// Locator-wide endpoint behavior. The YANG enum currently lists only
/// `usid` (RFC 9800 NEXT-C-SID); the variant is `Option<...>` on Locator
/// because the absence of the leaf means the classic RFC 8986 full SID
/// layout, not "uSID".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocatorBehavior {
    /// RFC 9800 NEXT-C-SID (micro-SID) format.
    Usid,
}

impl LocatorBehavior {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "usid" => Some(Self::Usid),
            _ => None,
        }
    }
}

/// Applied snapshot of an SRv6 locator, exported to the rest of the system
/// once a config commit lands. Keyed by name in `Rib::locators`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Locator {
    pub prefix: Option<Ipv6Net>,
    pub behavior: Option<LocatorBehavior>,
}

impl Locator {
    /// First address of the locator prefix — the canonical Node SID for
    /// owners that need an End SID. Returns `None` when no prefix is
    /// configured yet (the locator exists in config but has nothing to
    /// allocate from). Always uses the network address so a locator
    /// configured with host bits set still produces the correct Node
    /// SID.
    pub fn node_sid_addr(&self) -> Option<Ipv6Addr> {
        self.prefix.map(|p| p.network())
    }

    /// Geometry of SIDs allocated under this locator (RFC 9352 §9 SID
    /// Structure). Returns `None` when the locator has no prefix yet.
    ///
    /// Single source of truth so the IS-IS LSP advertisement and the
    /// FIB install can't drift on LB/LN/Fun. uSID locators cap LB at
    /// 32 (the typical uSID block size); classic locators cap at 40
    /// (IPv6 DOC / SR block convention). Function is fixed at 16 bits
    /// — the width `function_addr()` actually places into the SID.
    /// Argument is 0; we don't allocate argument-bearing SIDs.
    pub fn sid_structure(&self) -> Option<crate::rib::SidStructure> {
        let prefix = self.prefix?;
        let plen = prefix.prefix_len();
        let lb_bits = match self.behavior {
            Some(LocatorBehavior::Usid) => plen.min(32),
            None => plen.min(40),
        };
        Some(crate::rib::SidStructure {
            lb_bits,
            ln_bits: plen.saturating_sub(lb_bits),
            fun_bits: 16,
            arg_bits: 0,
        })
    }
}

/// In-flight Locator configuration, mirroring the YANG list shape:
///
/// ```yang
/// list locator {
///   key "name";
///   leaf name     { type string; }
///   leaf prefix   { type inet:ipv6-prefix; }
///   leaf behavior { type enumeration { enum usid; } }
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct LocatorConfig {
    pub delete: bool,
    pub prefix: Option<Ipv6Net>,
    pub behavior: Option<LocatorBehavior>,
}

impl LocatorConfig {
    pub fn to_locator(&self) -> Locator {
        Locator {
            prefix: self.prefix,
            behavior: self.behavior.clone(),
        }
    }
}

pub struct LocatorBuilder {
    pub config: BTreeMap<String, LocatorConfig>,
    pub cache: BTreeMap<String, LocatorConfig>,
    builder: ConfigBuilder,
}

impl LocatorBuilder {
    pub fn new() -> Self {
        LocatorBuilder {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder::new(),
        }
    }

    pub fn exec(&mut self, path: String, mut args: Args, op: ConfigOp) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const NAME_ERR: &str = "missing locator name argument";

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
                let _ = tx.send(Message::LocatorDel { name });
            } else {
                self.config.insert(name.clone(), config.clone());
                let _ = tx.send(Message::LocatorAdd { name, config });
            }
        }
    }
}

type Handler = fn(
    config: &mut BTreeMap<String, LocatorConfig>,
    cache: &mut BTreeMap<String, LocatorConfig>,
    name: &String,
    args: &mut Args,
) -> Result<()>;

fn config_get(config: &BTreeMap<String, LocatorConfig>, name: &String) -> LocatorConfig {
    let Some(entry) = config.get(name) else {
        return LocatorConfig::default();
    };
    entry.clone()
}

fn config_lookup(config: &BTreeMap<String, LocatorConfig>, name: &String) -> Option<LocatorConfig> {
    let entry = config.get(name)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    config: &'a BTreeMap<String, LocatorConfig>,
    cache: &'a mut BTreeMap<String, LocatorConfig>,
    name: &'a String,
) -> Option<&'a mut LocatorConfig> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), config_get(config, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    config: &'a BTreeMap<String, LocatorConfig>,
    cache: &'a mut BTreeMap<String, LocatorConfig>,
    name: &'a String,
) -> Option<&'a mut LocatorConfig> {
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
        const PREFIX_ERR: &str = "expected ipv6 prefix";
        const BEHAVIOR_ERR: &str = "unknown locator behavior";

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
            .path("/prefix")
            .set(|config, cache, name, args| {
                let prefix = args.v6net().context(PREFIX_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.prefix = Some(prefix);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.prefix = None;
                Ok(())
            })
            .path("/behavior")
            .set(|config, cache, name, args| {
                let raw = args.string().context(BEHAVIOR_ERR)?;
                let b = LocatorBehavior::parse(&raw).context(BEHAVIOR_ERR)?;
                let s = cache_get(config, cache, name).context(CONFIG_ERR)?;
                s.behavior = Some(b);
                Ok(())
            })
            .del(|config, cache, name, _args| {
                let s = cache_lookup(config, cache, name).context(CONFIG_ERR)?;
                s.behavior = None;
                Ok(())
            })
    }

    pub fn path(mut self, path: &str) -> Self {
        let prefix = "/segment-routing/locator";
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
    fn node_sid_uses_prefix_network_address() {
        let loc = Locator {
            prefix: Some("2001:db8:a:2::/64".parse().unwrap()),
            behavior: None,
        };
        assert_eq!(loc.node_sid_addr(), Some("2001:db8:a:2::".parse().unwrap()));
    }

    #[test]
    fn node_sid_zeros_host_bits_when_prefix_has_them_set() {
        // An operator typo like ".../64 with ::5 host bits" should still
        // resolve to the canonical first address; protocols rely on
        // this to advertise a stable Node SID.
        let loc = Locator {
            prefix: Some("2001:db8:a:2::5/64".parse().unwrap()),
            behavior: None,
        };
        assert_eq!(loc.node_sid_addr(), Some("2001:db8:a:2::".parse().unwrap()));
    }

    #[test]
    fn node_sid_none_when_prefix_unset() {
        let loc = Locator {
            prefix: None,
            behavior: None,
        };
        assert_eq!(loc.node_sid_addr(), None);
    }
}
