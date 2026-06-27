use std::fmt::Write;

use anyhow::{Context, Error};
use serde::Serialize;

use crate::config::Args;
use crate::policy::Policy;

use super::{CryptoAlgorithm, Lifetime, LifetimeEnd};

#[derive(Serialize)]
struct KeyJson {
    id: u64,
    algo: Option<String>,
    /// Length of the raw key material in bytes (the secret itself is
    /// never serialized).
    key_bytes: usize,
    send_id: Option<u8>,
    recv_id: Option<u8>,
    send_lifetime: String,
    accept_lifetime: String,
}

#[derive(Serialize)]
struct KeyChainJson {
    name: String,
    description: Option<String>,
    keys: Vec<KeyJson>,
}

fn to_json(name: &str, kc: &super::KeyChain) -> KeyChainJson {
    KeyChainJson {
        name: name.to_string(),
        description: kc.description.clone(),
        keys: kc
            .keys
            .iter()
            .map(|(id, key)| KeyJson {
                id: *id,
                algo: key.algo.map(|a| algo_name(a).to_string()),
                key_bytes: key.key_material.len(),
                send_id: key.send_id,
                recv_id: key.recv_id,
                send_lifetime: fmt_lifetime(&key.send_lifetime),
                accept_lifetime: fmt_lifetime(&key.accept_lifetime),
            })
            .collect(),
    }
}

pub fn key_chains(policy: &Policy, _args: Args, json: bool) -> Result<String, Error> {
    if json {
        let list: Vec<_> = policy
            .key_chain_config
            .config
            .iter()
            .map(|(name, kc)| to_json(name, kc))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)?);
    }
    let mut buf = String::new();
    for (name, kc) in policy.key_chain_config.config.iter() {
        write_chain(&mut buf, name, kc)?;
    }
    Ok(buf)
}

pub fn key_chain_name(policy: &Policy, mut args: Args, json: bool) -> Result<String, Error> {
    let name = args.string().context("missing key-chain name")?;
    let kc = policy
        .key_chain_config
        .config
        .get(&name)
        .context(format!("key-chain '{}' not found", name))?;
    if json {
        return Ok(serde_json::to_string_pretty(&to_json(&name, kc))?);
    }
    let mut buf = String::new();
    write_chain(&mut buf, &name, kc)?;
    Ok(buf)
}

fn write_chain(buf: &mut String, name: &str, kc: &super::KeyChain) -> Result<(), std::fmt::Error> {
    writeln!(buf, "key-chain: {}", name)?;
    if let Some(desc) = &kc.description {
        writeln!(buf, "  description: {}", desc)?;
    }
    for (id, key) in kc.keys.iter() {
        writeln!(buf, "  key {}:", id)?;
        if let Some(algo) = key.algo {
            writeln!(buf, "    algo: {}", algo_name(algo))?;
        }
        writeln!(buf, "    key-bytes: {}", key.key_material.len())?;
        if let Some(s) = key.send_id {
            writeln!(buf, "    send-id: {}", s)?;
        }
        if let Some(r) = key.recv_id {
            writeln!(buf, "    recv-id: {}", r)?;
        }
        writeln!(
            buf,
            "    send-lifetime: {}",
            fmt_lifetime(&key.send_lifetime)
        )?;
        writeln!(
            buf,
            "    accept-lifetime: {}",
            fmt_lifetime(&key.accept_lifetime)
        )?;
    }
    Ok(())
}

fn algo_name(a: CryptoAlgorithm) -> &'static str {
    match a {
        CryptoAlgorithm::Md5 => "md5",
        CryptoAlgorithm::HmacSha1 => "hmac-sha-1",
        CryptoAlgorithm::HmacSha256 => "hmac-sha-256",
        CryptoAlgorithm::HmacSha384 => "hmac-sha-384",
        CryptoAlgorithm::HmacSha512 => "hmac-sha-512",
        CryptoAlgorithm::AesCmacPrf128 => "aes-cmac-prf-128",
    }
}

fn fmt_lifetime(lt: &Lifetime) -> String {
    match lt {
        Lifetime::Always => "always".to_string(),
        Lifetime::Window { start, end } => match end {
            LifetimeEnd::NoEnd => format!("{} → no-end", start),
            LifetimeEnd::Duration(s) => format!("{} +{}s", start, s),
            LifetimeEnd::EndAt(t) => format!("{} → {}", start, t),
        },
    }
}
