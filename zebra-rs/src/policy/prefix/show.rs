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
