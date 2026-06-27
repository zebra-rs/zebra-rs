use std::fmt::Write;

use anyhow::{Context, Error};
use serde::Serialize;

use super::{ExtCommunityMatcher, ExtCommunitySet};
use crate::{config::Args, policy::Policy};

#[derive(Serialize)]
struct ExtCommunitySetJson {
    name: String,
    members: Vec<String>,
}

fn to_json(name: &str, set: &ExtCommunitySet) -> ExtCommunitySetJson {
    ExtCommunitySetJson {
        name: name.to_string(),
        members: set.vals.iter().map(format_matcher).collect(),
    }
}

pub fn ext_community_set(policy: &Policy, _args: Args, json: bool) -> Result<String, Error> {
    if json {
        let list: Vec<_> = policy
            .ext_community_config
            .config
            .iter()
            .map(|(name, set)| to_json(name, set))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)?);
    }
    let mut buf = String::new();
    for (name, set) in policy.ext_community_config.config.iter() {
        writeln!(buf, "ext-community-set: {} len: {}", name, set.vals.len())?;
        for matcher in &set.vals {
            writeln!(buf, "  {}", format_matcher(matcher))?;
        }
    }
    Ok(buf)
}

pub fn ext_community_set_name(
    policy: &Policy,
    mut args: Args,
    json: bool,
) -> Result<String, Error> {
    let name = args.string().context("missing ext-community-set name")?;
    let set = policy
        .ext_community_config
        .config
        .get(&name)
        .context(format!("ext-community-set '{}' not found", name))?;
    if json {
        return Ok(serde_json::to_string_pretty(&to_json(&name, set))?);
    }
    let mut buf = String::new();
    writeln!(buf, "ext-community-set: {}", name)?;
    for matcher in &set.vals {
        writeln!(buf, "  {}", format_matcher(matcher))?;
    }
    Ok(buf)
}

fn format_matcher(matcher: &ExtCommunityMatcher) -> String {
    match matcher {
        ExtCommunityMatcher::Exact(val) => val.to_string(),
        ExtCommunityMatcher::Regex(sub_type, compiled) => {
            format!("{}:{}", sub_type, compiled.pattern())
        }
    }
}
