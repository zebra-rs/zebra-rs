use std::fmt::Write;

use anyhow::{Context, Error};

use super::LargeCommunityMatcher;
use crate::{config::Args, policy::Policy};

pub fn large_community_set(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
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
    _json: bool,
) -> Result<String, Error> {
    let mut buf = String::new();
    let name = args.string().context("missing large-community-set name")?;
    let set = policy
        .large_community_config
        .config
        .get(&name)
        .context(format!("large-community-set '{}' not found", name))?;
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
