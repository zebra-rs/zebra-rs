use anyhow::{Context, Error};
use serde::Serialize;
use std::fmt::Write;

use super::PrefixSet;
use crate::{config::Args, policy::Policy};

#[derive(Serialize)]
struct PrefixEntryJson {
    prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    le: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eq: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ge: Option<u8>,
}

#[derive(Serialize)]
struct PrefixSetJson {
    name: String,
    prefixes: Vec<PrefixEntryJson>,
}

fn to_json(name: &str, set: &PrefixSet) -> PrefixSetJson {
    PrefixSetJson {
        name: name.to_string(),
        prefixes: set
            .iter()
            .map(|(prefix, entry)| PrefixEntryJson {
                prefix: prefix.to_string(),
                le: entry.le,
                eq: entry.eq,
                ge: entry.ge,
            })
            .collect(),
    }
}

// Render one prefix-set the FRR-ish way (`  P/M le L eq E ge G`).
fn write_set(buf: &mut String, name: &str, set: &PrefixSet) -> Result<(), std::fmt::Error> {
    writeln!(buf, "prefix-set: {}", name)?;
    for (prefix, entry) in set.iter() {
        write!(buf, "  {}", prefix)?;
        if let Some(le) = entry.le {
            write!(buf, " le {}", le)?;
        }
        if let Some(eq) = entry.eq {
            write!(buf, " eq {}", eq)?;
        }
        if let Some(ge) = entry.ge {
            write!(buf, " ge {}", ge)?;
        }
        writeln!(buf)?;
    }
    Ok(())
}

// List all of prefix-set.
pub fn prefix_set(policy: &Policy, _args: Args, json: bool) -> Result<String, Error> {
    if json {
        let list: Vec<_> = policy
            .prefix_config
            .config
            .iter()
            .map(|(name, set)| to_json(name, set))
            .collect();
        return Ok(serde_json::to_string_pretty(&list)?);
    }

    let mut buf = String::new();
    for (name, set) in policy.prefix_config.config.iter() {
        write_set(&mut buf, name, set)?;
    }

    Ok(buf)
}

// Show prefix-set of the name.
pub fn prefix_set_name(policy: &Policy, mut args: Args, json: bool) -> Result<String, Error> {
    // get the prefix-set name from arguments
    let name = args.string().context("missing prefix-set name")?;

    // Look up the prefix-set by name
    let set = policy
        .prefix_config
        .config
        .get(&name)
        .context(format!("prefix-set '{}' not found", name))?;

    if json {
        return Ok(serde_json::to_string_pretty(&to_json(&name, set))?);
    }

    let mut buf = String::new();
    write_set(&mut buf, &name, set)?;

    Ok(buf)
}
