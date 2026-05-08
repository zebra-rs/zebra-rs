use std::fmt::Write;

use anyhow::{Context, Error};

use super::ExtCommunityMatcher;
use crate::{config::Args, policy::Policy};

pub fn ext_community_set(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
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
    _json: bool,
) -> Result<String, Error> {
    let mut buf = String::new();
    let name = args.string().context("missing ext-community-set name")?;
    let set = policy
        .ext_community_config
        .config
        .get(&name)
        .context(format!("ext-community-set '{}' not found", name))?;
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
