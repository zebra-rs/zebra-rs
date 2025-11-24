use anyhow::{Context, Error};
use std::fmt::Write;

use crate::{config::Args, policy::Policy};
use super::{CommunityMatcher, StandardMatcher, ExtendedMatcher};

pub fn community_set(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();

    for (name, set) in policy.community_config.config.iter() {
        writeln!(buf, "community-set: {}", name)?;
        for matcher in &set.vals {
            writeln!(buf, "  {}", format_community_matcher(matcher))?;
        }
    }

    Ok(buf)
}

pub fn community_set_name(policy: &Policy, mut args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();

    // get the community-set name from arguments
    let name = args.string().context("missing community-set name")?;

    // Look up the community-set by name
    let set = policy
        .community_config
        .config
        .get(&name)
        .context(format!("community-set '{}' not found", name))?;

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
            StandardMatcher::Regex(pattern) => pattern.clone(),
        },
        CommunityMatcher::Extended(extended) => match extended {
            ExtendedMatcher::Exact(val) => val.to_string(),
            ExtendedMatcher::Regex(sub_type, pattern) => {
                format!("{}:{}", sub_type, pattern)
            }
        },
    }
}
