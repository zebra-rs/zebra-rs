use anyhow::{Context, Error};
use std::fmt::Write;

use crate::{config::Args, policy::Policy};

// List all of prefix-set.
pub fn prefix_set(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();

    // Iterate through all prefix-sets
    for (name, set) in policy.prefix_set.config.iter() {
        writeln!(buf, "prefix-set: {}", name)?;
        for (prefix, entry) in set.prefixes.iter() {
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
    }

    Ok(buf)
}

// Show prefix-set of the name.
pub fn prefix_set_name(policy: &Policy, mut args: Args, _json: bool) -> Result<String, Error> {
    let mut buf = String::new();

    // get the prefix-set name from arguments
    let name = args.string().context("missing prefix-set name")?;

    // Look up the prefix-set by name
    let set = policy
        .prefix_set
        .config
        .get(&name)
        .context(format!("prefix-set '{}' not found", name))?;

    writeln!(buf, "prefix-set: {}", name)?;

    // Show all prefixes in this set
    for (prefix, entry) in set.prefixes.iter() {
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

    Ok(buf)
}
