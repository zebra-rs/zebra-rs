use std::fmt::Write;

use anyhow::{Context, Error};
use serde::Serialize;

use super::{LargeCommunityMatcher, LargeCommunitySet};
use crate::{config::Args, policy::Policy};

#[derive(Serialize)]
struct LargeCommunitySetJson {
    name: String,
    members: Vec<String>,
}

fn to_json(name: &str, set: &LargeCommunitySet) -> LargeCommunitySetJson {
    LargeCommunitySetJson {
        name: name.to_string(),
        members: set.vals.iter().map(format_matcher).collect(),
    }
}

pub fn large_community_set(policy: &Policy, _args: Args, json: bool) -> Result<String, Error> {
    if json {
        let list: Vec<_> = policy
            .large_community_config
            .config
            .iter()
            .map(|(name, set)| to_json(name, set))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)?);
    }
    let mut buf = String::new();
    for (name, set) in policy.large_community_config.config.iter() {
        writeln!(buf, "large-community-set: {} len: {}", name, set.vals.len())?;
        for matcher in &set.vals {
            writeln!(buf, "  {}", format_matcher(matcher))?;
        }
    }
    Ok(buf)
}

pub fn large_community_set_name(
    policy: &Policy,
    mut args: Args,
    json: bool,
) -> Result<String, Error> {
    let name = args.string().context("missing large-community-set name")?;
    let set = policy
        .large_community_config
        .config
        .get(&name)
        .context(format!("large-community-set '{}' not found", name))?;
    if json {
        return Ok(serde_json::to_string_pretty(&to_json(&name, set))?);
    }
    let mut buf = String::new();
    writeln!(buf, "large-community-set: {}", name)?;
    for matcher in &set.vals {
        writeln!(buf, "  {}", format_matcher(matcher))?;
    }
    Ok(buf)
}

fn format_matcher(matcher: &LargeCommunityMatcher) -> String {
    match matcher {
        LargeCommunityMatcher::Exact(val) => val.to_str(),
        LargeCommunityMatcher::Regex(compiled) => compiled.pattern().to_string(),
    }
}
