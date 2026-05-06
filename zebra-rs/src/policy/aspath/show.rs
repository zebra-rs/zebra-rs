use anyhow::{Context, Error};
use std::fmt::Write;

use crate::{config::Args, policy::Policy};

pub fn as_path_set(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();

    for (name, set) in policy.as_path_config.config.iter() {
        writeln!(buf, "as-path-set: {} len: {}", name, set.vals.len())?;
        for matcher in &set.vals {
            writeln!(buf, "  {}", matcher.pattern())?;
        }
    }

    Ok(buf)
}

pub fn as_path_set_name(policy: &Policy, mut args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();

    let name = args.string().context("missing as-path-set name")?;
    let set = policy
        .as_path_config
        .config
        .get(&name)
        .context(format!("as-path-set '{}' not found", name))?;

    writeln!(buf, "as-path-set: {}", name)?;
    for matcher in &set.vals {
        writeln!(buf, "  {}", matcher.pattern())?;
    }

    Ok(buf)
}
