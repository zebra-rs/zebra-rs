use anyhow::{Context, Error};
use serde::Serialize;
use std::fmt::Write;

use super::AsPathSet;
use crate::{config::Args, policy::Policy};

#[derive(Serialize)]
struct AsPathSetJson {
    name: String,
    members: Vec<String>,
}

fn to_json(name: &str, set: &AsPathSet) -> AsPathSetJson {
    AsPathSetJson {
        name: name.to_string(),
        members: set.vals.iter().map(|m| m.pattern().to_string()).collect(),
    }
}

pub fn as_path_set(policy: &Policy, _args: Args, json: bool) -> Result<String, Error> {
    if json {
        let list: Vec<_> = policy
            .as_path_config
            .config
            .iter()
            .map(|(name, set)| to_json(name, set))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)?);
    }

    let mut buf = String::new();
    for (name, set) in policy.as_path_config.config.iter() {
        writeln!(buf, "as-path-set: {} len: {}", name, set.vals.len())?;
        for matcher in &set.vals {
            writeln!(buf, "  {}", matcher.pattern())?;
        }
    }

    Ok(buf)
}

pub fn as_path_set_name(policy: &Policy, mut args: Args, json: bool) -> Result<String, Error> {
    let name = args.string().context("missing as-path-set name")?;
    let set = policy
        .as_path_config
        .config
        .get(&name)
        .context(format!("as-path-set '{}' not found", name))?;

    if json {
        return Ok(serde_json::to_string_pretty(&to_json(&name, set))?);
    }

    let mut buf = String::new();
    writeln!(buf, "as-path-set: {}", name)?;
    for matcher in &set.vals {
        writeln!(buf, "  {}", matcher.pattern())?;
    }

    Ok(buf)
}
