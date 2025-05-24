use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use std::{collections::BTreeMap, net::Ipv4Addr};

use crate::config::{Args, ConfigOp};

use super::{Action, Policy, PrefixListIpv4, PrefixListIpv4Map};

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    map: BTreeMap<(String, ConfigOp), Handler>,
}

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

    pub fn exec(
        &self,
        path: &str,
        op: ConfigOp,
        map: &mut PrefixListIpv4Map,
        mut args: Args,
    ) -> Result<()> {
        const CONFIG_ERR: &str = "missing config handler";
        const NAME_ERR: &str = "missing name arg";

        let func = self.map.get(&(path.to_string(), op)).context(CONFIG_ERR)?;
        let string: String = args.string().context(NAME_ERR)?;
        let seq: u32 = args.u32().unwrap_or(0);
        func(&mut map.plist, &mut map.cache, &string, seq, &mut args)
    }
}

type Handler = fn(
    plist: &mut BTreeMap<String, PrefixListIpv4>,
    cache: &mut BTreeMap<String, PrefixListIpv4>,
    name: &String,
    seq: u32,
    args: &mut Args,
) -> Result<()>;

fn plist_get(plist: &BTreeMap<String, PrefixListIpv4>, name: &String) -> PrefixListIpv4 {
    let Some(entry) = plist.get(name) else {
        return PrefixListIpv4::default();
    };
    entry.clone()
}

fn plist_lookup(plist: &BTreeMap<String, PrefixListIpv4>, name: &String) -> Option<PrefixListIpv4> {
    let entry = plist.get(name)?;
    Some(entry.clone())
}

fn cache_get<'a>(
    plist: &'a BTreeMap<String, PrefixListIpv4>,
    cache: &'a mut BTreeMap<String, PrefixListIpv4>,
    name: &'a String,
) -> Option<&'a mut PrefixListIpv4> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), plist_get(plist, name));
    }
    cache.get_mut(name)
}

fn cache_lookup<'a>(
    plist: &'a BTreeMap<String, PrefixListIpv4>,
    cache: &'a mut BTreeMap<String, PrefixListIpv4>,
    name: &'a String,
) -> Option<&'a mut PrefixListIpv4> {
    if cache.get(name).is_none() {
        cache.insert(name.to_string(), plist_lookup(plist, name)?);
    }
    let cache = cache.get_mut(name)?;
    if cache.delete {
        None
    } else {
        Some(cache)
    }
}

fn prefix_ipv4_config_builder() -> ConfigBuilder {
    const CONFIG_ERR: &str = "missing config";
    const ACTION_ERR: &str = "missing action";
    const PREFIX_ERR: &str = "missing prefix";
    const LE_ERR: &str = "missing le";
    const EQ_ERR: &str = "missing eq";
    const GE_ERR: &str = "missing ge";

    ConfigBuilder::default()
        .path("/prefix-list")
        .set(|plist, cache, name, _seq, _args| {
            let _ = cache_get(plist, cache, name).context(CONFIG_ERR)?;
            Ok(())
        })
        .del(|plist, cache, name, _seq, _args| {
            if let Some(plist) = cache.get_mut(name) {
                plist.delete = true;
            } else {
                let mut plist = plist_lookup(plist, name).context(CONFIG_ERR)?;
                plist.delete = true;
                cache.insert(name.to_string(), plist);
            }
            Ok(())
        })
        .path("/prefix-list/seq")
        .set(|plist, cache, name, seq, _| {
            let plist = cache_get(plist, cache, name).context(CONFIG_ERR)?;
            let _ = plist.seq.entry(seq).or_default();
            Ok(())
        })
        .del(|plist, cache, name, seq, _| {
            let plist = cache_lookup(plist, cache, name).context(CONFIG_ERR)?;
            plist.seq.remove(&seq).context(CONFIG_ERR)?;
            Ok(())
        })
        .path("/prefix-list/seq/action")
        .set(|plist, cache, name, seq, args| {
            let action_str = args.string().context(ACTION_ERR)?;
            let action = Action::try_from(&action_str)?;
            let plist = cache_get(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.entry(seq).or_default();
            seq.action = action;
            Ok(())
        })
        .del(|plist, cache, name, seq, _args| {
            let plist = cache_lookup(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.get_mut(&seq).context(ACTION_ERR)?;
            seq.action = Action::Permit;
            Ok(())
        })
        .path("/prefix-list/seq/prefix")
        .set(|plist, cache, name, seq, args| {
            let prefix = args.v4net().context(PREFIX_ERR)?;
            let plist = cache_get(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.entry(seq).or_default();
            seq.prefix = prefix;
            Ok(())
        })
        .del(|plist, cache, name, seq, _args| {
            let plist = cache_lookup(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.get_mut(&seq).context(PREFIX_ERR)?;
            seq.prefix = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
            Ok(())
        })
        .path("/prefix-list/seq/le")
        .set(|plist, cache, name, seq, args| {
            let le = args.u8().context(LE_ERR)?;
            let plist = cache_get(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.entry(seq).or_default();
            seq.le = Some(le);
            Ok(())
        })
        .del(|plist, cache, name, seq, _args| {
            let plist = cache_lookup(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.get_mut(&seq).context(LE_ERR)?;
            seq.le = None;
            Ok(())
        })
        .path("/prefix-list/seq/eq")
        .set(|plist, cache, name, seq, args| {
            let eq = args.u8().context(EQ_ERR)?;
            let plist = cache_get(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.entry(seq).or_default();
            seq.eq = Some(eq);
            Ok(())
        })
        .del(|plist, cache, name, seq, _args| {
            let plist = cache_lookup(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.get_mut(&seq).context(EQ_ERR)?;
            seq.eq = None;
            Ok(())
        })
        .path("/prefix-list/seq/ge")
        .set(|plist, cache, name, seq, args| {
            let ge = args.u8().context(GE_ERR)?;
            let plist = cache_get(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.entry(seq).or_default();
            seq.ge = Some(ge);
            Ok(())
        })
        .del(|plist, cache, name, seq, _args| {
            let plist = cache_lookup(plist, cache, name).context(CONFIG_ERR)?;
            let seq = plist.seq.get_mut(&seq).context(GE_ERR)?;
            seq.ge = None;
            Ok(())
        })
}

pub fn prefix_ipv4_exec(policy: &mut Policy, path: String, args: Args, op: ConfigOp) {
    let builder = prefix_ipv4_config_builder();
    let _ = builder.exec(path.as_str(), op, &mut policy.plist_v4, args);
}

pub fn prefix_ipv4_commit(
    plist: &mut BTreeMap<String, PrefixListIpv4>,
    cache: &mut BTreeMap<String, PrefixListIpv4>,
) {
    while let Some((n, s)) = cache.pop_first() {
        if s.delete {
            plist.remove(&n);
        } else {
            plist.insert(n, s);
        }
    }
}
