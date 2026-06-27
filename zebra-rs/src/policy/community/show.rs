use anyhow::{Context, Error};
use serde::Serialize;
use std::fmt::Write;

use super::{CommunityMatcher, CommunitySet, ExtendedMatcher, StandardMatcher};
use crate::{config::Args, policy::Policy};

#[derive(Serialize)]
struct CommunitySetJson {
    name: String,
    members: Vec<String>,
}

fn to_json(name: &str, set: &CommunitySet) -> CommunitySetJson {
    CommunitySetJson {
        name: name.to_string(),
        members: set.vals.iter().map(format_community_matcher).collect(),
    }
}

pub fn community_set(policy: &Policy, _args: Args, json: bool) -> Result<String, Error> {
    if json {
        let list: Vec<_> = policy
            .community_config
            .config
            .iter()
            .map(|(name, set)| to_json(name, set))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)?);
    }

    let mut buf = String::new();
    for (name, set) in policy.community_config.config.iter() {
        writeln!(buf, "community-set: {} len: {}", name, set.vals.len())?;
        for matcher in &set.vals {
            writeln!(buf, "  {}", format_community_matcher(matcher))?;
        }
    }

    Ok(buf)
}

pub fn community_set_name(policy: &Policy, mut args: Args, json: bool) -> Result<String, Error> {
    // get the community-set name from arguments
    let name = args.string().context("missing community-set name")?;

    // Look up the community-set by name
    let set = policy
        .community_config
        .config
        .get(&name)
        .context(format!("community-set '{}' not found", name))?;

    if json {
        return Ok(serde_json::to_string_pretty(&to_json(&name, set))?);
    }

    let mut buf = String::new();
    writeln!(buf, "community-set: {}", name)?;

    // Show all community matchers in this set
    for matcher in &set.vals {
        writeln!(buf, "  {}", format_community_matcher(matcher))?;
    }

    Ok(buf)
}

fn format_community_matcher(matcher: &CommunityMatcher) -> String {
    match matcher {
        CommunityMatcher::Standard(standard) => match standard {
            StandardMatcher::Exact(val) => val.to_str(),
            StandardMatcher::Regex(compiled) => compiled.pattern().to_string(),
        },
        CommunityMatcher::Extended(extended) => match extended {
            ExtendedMatcher::Exact(val) => val.to_string(),
            ExtendedMatcher::Regex(sub_type, compiled) => {
                format!("{}:{}", sub_type, compiled.pattern())
            }
        },
    }
}
