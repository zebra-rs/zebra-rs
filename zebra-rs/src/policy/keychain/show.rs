use std::fmt::Write;

use anyhow::{Context, Error};

use crate::config::Args;
use crate::policy::Policy;

use super::{CryptoAlgorithm, Lifetime, LifetimeEnd};

pub fn key_chains(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();
    for (name, kc) in policy.key_chain_config.config.iter() {
        write_chain(&mut buf, name, kc)?;
    }
    Ok(buf)
}

pub fn key_chain_name(policy: &Policy, mut args: Args, _json: bool) -> Result<String, Error> {
    let name = args.string().context("missing key-chain name")?;
    let kc = policy
        .key_chain_config
        .config
        .get(&name)
        .context(format!("key-chain '{}' not found", name))?;
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
