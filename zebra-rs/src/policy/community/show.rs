use anyhow::{Context, Error};
use std::fmt::Write;

use crate::{config::Args, policy::Policy};

pub fn community_set(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();

    for (name, set) in policy.community_set.config.iter() {
        //
    }

    Ok(buf)
}

pub fn community_set_name(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();

    for (name, set) in policy.community_set.config.iter() {
        //
    }

    Ok(buf)
}
