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
                // Snapshot the RT sets before moving `config` into
                // `self.config`. The two sends order matters: the
                // receiving end relies on the `Vrf` row existing
                // before `VrfRouteTargets` arrives so the RT
                // update has a target to mutate.
                let ipv4_import_rts = config.ipv4_import_rts.clone();
                let ipv4_export_rts = config.ipv4_export_rts.clone();
                let ipv6_import_rts = config.ipv6_import_rts.clone();
                let ipv6_export_rts = config.ipv6_export_rts.clone();
                self.config.insert(name.clone(), config);
                let _ = tx.send(Message::VrfAdd { name: name.clone() });
                let _ = tx.send(Message::VrfRouteTargets {
                    name,
                    ipv4_import_rts,
                    ipv4_export_rts,
                    ipv6_import_rts,
                    ipv6_export_rts,
                });
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
        use std::str::FromStr;

        const CONFIG_ERR: &str = "missing config";
        const RT_ERR: &str = "missing route-target argument";
        const RT_PARSE_ERR: &str =
            "route-target must parse as ASN:value, IPv4:value, or 4byteASN:value";

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
            // /vrf/<name>/ipv4/route-target/import — leaf-list, one
            // RT value per callback. RT shares the on-wire 6-octet
            // encoding with RD, so we parse via the `bgp_packet`
            // `RouteDistinguisher::from_str` and store the same
            // `RouteDistinguisher` value. The YANG-layer label
            // distinguishes RT from RD at the user surface.
            .path("/ipv4/route-target/import")
            .set(|config, cache, name, args| {
                let raw = args.string().context(RT_ERR)?;
                let rt = bgp_packet::RouteDistinguisher::from_str(&raw)
                    .map_err(|_| anyhow::anyhow!(RT_PARSE_ERR))?;
                cache_get(config, cache, name)
                    .context(CONFIG_ERR)?
                    .ipv4_import_rts
                    .insert(rt);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let raw = args.string().context(RT_ERR)?;
                let rt = bgp_packet::RouteDistinguisher::from_str(&raw)
                    .map_err(|_| anyhow::anyhow!(RT_PARSE_ERR))?;
                cache_get(config, cache, name)
                    .context(CONFIG_ERR)?
                    .ipv4_import_rts
                    .remove(&rt);
                Ok(())
            })
            .path("/ipv4/route-target/export")
            .set(|config, cache, name, args| {
                let raw = args.string().context(RT_ERR)?;
                let rt = bgp_packet::RouteDistinguisher::from_str(&raw)
                    .map_err(|_| anyhow::anyhow!(RT_PARSE_ERR))?;
                cache_get(config, cache, name)
                    .context(CONFIG_ERR)?
                    .ipv4_export_rts
                    .insert(rt);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let raw = args.string().context(RT_ERR)?;
                let rt = bgp_packet::RouteDistinguisher::from_str(&raw)
                    .map_err(|_| anyhow::anyhow!(RT_PARSE_ERR))?;
                cache_get(config, cache, name)
                    .context(CONFIG_ERR)?
                    .ipv4_export_rts
                    .remove(&rt);
                Ok(())
            })
            .path("/ipv6/route-target/import")
            .set(|config, cache, name, args| {
                let raw = args.string().context(RT_ERR)?;
                let rt = bgp_packet::RouteDistinguisher::from_str(&raw)
                    .map_err(|_| anyhow::anyhow!(RT_PARSE_ERR))?;
                cache_get(config, cache, name)
                    .context(CONFIG_ERR)?
                    .ipv6_import_rts
                    .insert(rt);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let raw = args.string().context(RT_ERR)?;
                let rt = bgp_packet::RouteDistinguisher::from_str(&raw)
                    .map_err(|_| anyhow::anyhow!(RT_PARSE_ERR))?;
                cache_get(config, cache, name)
                    .context(CONFIG_ERR)?
                    .ipv6_import_rts
                    .remove(&rt);
                Ok(())
            })
            .path("/ipv6/route-target/export")
            .set(|config, cache, name, args| {
                let raw = args.string().context(RT_ERR)?;
                let rt = bgp_packet::RouteDistinguisher::from_str(&raw)
                    .map_err(|_| anyhow::anyhow!(RT_PARSE_ERR))?;
                cache_get(config, cache, name)
                    .context(CONFIG_ERR)?
                    .ipv6_export_rts
                    .insert(rt);
                Ok(())
            })
            .del(|config, cache, name, args| {
                let raw = args.string().context(RT_ERR)?;
                let rt = bgp_packet::RouteDistinguisher::from_str(&raw)
                    .map_err(|_| anyhow::anyhow!(RT_PARSE_ERR))?;
                cache_get(config, cache, name)
                    .context(CONFIG_ERR)?
                    .ipv6_export_rts
                    .remove(&rt);
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tokio::sync::mpsc;

    use crate::config::{Args, ConfigOp};

    use super::*;

    fn args(words: &[&str]) -> Args {
        Args(words.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn commit_emits_vrf_add_then_route_targets() {
        // Operator typed:
        //   set vrf v1 ipv4 route-target import 65000:1
        //   set vrf v1 ipv4 route-target export 65000:2
        //   commit
        // The receiving end should see `VrfAdd { v1 }` followed
        // by a `VrfRouteTargets { v1, ... }` carrying both RTs.
        let mut builder = VrfBuilder::new();
        builder
            .exec("/vrf".into(), args(&["v1"]), ConfigOp::Set)
            .expect("create vrf");
        builder
            .exec(
                "/vrf/ipv4/route-target/import".into(),
                args(&["v1", "65000:1"]),
                ConfigOp::Set,
            )
            .expect("add import RT");
        builder
            .exec(
                "/vrf/ipv4/route-target/export".into(),
                args(&["v1", "65000:2"]),
                ConfigOp::Set,
            )
            .expect("add export RT");

        let (tx, mut rx) = mpsc::unbounded_channel();
        builder.commit(tx);

        let first = rx.try_recv().expect("VrfAdd present");
        let Message::VrfAdd { name } = first else {
            panic!("first message is not VrfAdd");
        };
        assert_eq!(name, "v1");

        let second = rx.try_recv().expect("VrfRouteTargets present");
        let Message::VrfRouteTargets {
            name,
            ipv4_import_rts,
            ipv4_export_rts,
            ipv6_import_rts,
            ipv6_export_rts,
        } = second
        else {
            panic!("second message is not VrfRouteTargets");
        };
        assert_eq!(name, "v1");
        let imp = bgp_packet::RouteDistinguisher::from_str("65000:1").unwrap();
        let exp = bgp_packet::RouteDistinguisher::from_str("65000:2").unwrap();
        assert!(ipv4_import_rts.contains(&imp));
        assert!(ipv4_export_rts.contains(&exp));
        assert!(ipv6_import_rts.is_empty());
        assert!(ipv6_export_rts.is_empty());
        assert!(rx.try_recv().is_err(), "no third message expected");
    }

    #[test]
    fn invalid_rt_string_returns_an_error() {
        let mut builder = VrfBuilder::new();
        builder
            .exec("/vrf".into(), args(&["v1"]), ConfigOp::Set)
            .expect("create vrf");
        let err = builder
            .exec(
                "/vrf/ipv4/route-target/import".into(),
                args(&["v1", "not-an-rt"]),
                ConfigOp::Set,
            )
            .expect_err("garbage RT must be rejected");
        assert!(
            err.to_string().contains("route-target"),
            "expected RT-specific error, got: {err}",
        );
    }
}
