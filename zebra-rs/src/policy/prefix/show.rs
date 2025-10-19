use anyhow::Error;

use crate::{config::Args, policy::Policy};

// List all of prefix-set.
pub fn prefix_set(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    Ok(String::from("hoge"))
}

// Show prefix-set of the name.
pub fn prefix_set_name(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
    Ok(String::from("name"))
}

// pub fn show(policy: &Policy, _args: Args, _json: bool) -> Result<String, Error> {
//     let mut buf = String::new();
//     for (name, set) in policy.prefix_set.config.iter() {
//         writeln!(buf, "prefix-set: {}", name)?;
//         for (prefix, entry) in set.entry.iter() {
//             write!(buf, " {}", prefix,)?;
//             if let Some(le) = entry.le {
//                 write!(buf, " le: {}", le);
//             }
//             if let Some(eq) = entry.eq {
//                 write!(buf, " eq: {}", eq);
//             }
//             if let Some(ge) = entry.ge {
//                 write!(buf, " ge: {}", ge);
//             }
//             writeln!(buf, "");
//         }
//     }
//     Ok(buf)
// }
