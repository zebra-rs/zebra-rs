//! FRR `vtysh` compatibility.
//!
//! SONiC's tooling talks to the routing stack by running `vtysh -c
//! '<FRR command>'` and reading what it prints — text for operators,
//! FRR's JSON for programs (bgpmon, `show ip bgp summary`, route_check).
//! This module takes that command line, asks zebra-rs the equivalent
//! question, and for the JSON forms answers in FRR's schema.
//!
//! It is reached two ways: `vtyctl vtysh …`, and by running the binary
//! under the name `vtysh`, which is how SONiC's bgp container installs it.
//!
//! It is compatibility for existing callers, not a second CLI: what it
//! cannot answer faithfully it refuses with a non-zero exit, the same way
//! FRR's vtysh fails a command it does not know.

pub mod command;
pub mod json;

use command::Action;

use crate::show::FetchError;

/// True when the program was started as `vtysh` (through a link or a
/// copy of that name).
pub fn is_vtysh_name(argv0: &str) -> bool {
    std::path::Path::new(argv0)
        .file_name()
        .is_some_and(|name| name == "vtysh")
}

/// The commands of an FRR vtysh command line, or why it cannot be run.
///
/// Options that select or tune FRR daemons mean nothing here and are
/// accepted and dropped: SONiC passes `-H /dev/null` (bgpmon) and `-n
/// <asic>` (multi-asic wrappers). Its host wrapper also passes the
/// caller's tty as a bare word, a tag for `pkill`; bare words are dropped.
fn parse_args(args: &[String]) -> Result<Vec<String>, String> {
    let mut commands = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-c" | "--command" => match it.next() {
                Some(c) => commands.push(c.clone()),
                None => return Err("option -c needs a command".to_string()),
            },
            "-H" | "--histfile" | "-n" | "-d" | "--daemon" | "-N" | "--pathspace"
            | "--vty_socket" | "--config_dir" | "-i" | "--inputfile" => {
                if it.next().is_none() {
                    return Err(format!("option {arg} needs a value"));
                }
            }
            "-f" | "--file" => {
                return Err(
                    "-f is not supported: zebra-rs configuration goes through `vtyctl apply -f`"
                        .to_string(),
                );
            }
            "-h" | "--help" => return Err(String::new()),
            _ => {}
        }
    }
    Ok(commands)
}

fn usage() {
    eprintln!("Usage: vtysh [-n ASIC] -c 'COMMAND' [-c 'COMMAND']...");
    eprintln!();
    eprintln!("FRR vtysh compatibility for zebra-rs. Takes FRR `show` and `clear bgp`");
    eprintln!("commands; the `json` forms SONiC's tooling reads are answered in FRR's");
    eprintln!("schema. There is no interactive mode: use `vtyctl show '<command>'`.");
}

/// Report a failed command the way FRR's vtysh does: a `% …` line on
/// standard output and a non-zero status. On standard output because
/// that is where callers look — sonic-utilities' `show ip route` prints
/// an answer that starts with `%` as the error it is.
fn report(command: &str, err: FetchError) -> i32 {
    match err {
        FetchError::Connect(why) => {
            eprintln!("Exiting: failed to connect to any daemons. ({why})");
        }
        FetchError::Rejected(why) => {
            println!("% Unknown command: {command} ({why})");
        }
        FetchError::Failed(why) => println!("% {command}: {why}"),
    }
    1
}

fn print_output(text: &str) {
    print!("{text}");
    if !text.is_empty() && !text.ends_with('\n') {
        println!();
    }
}

async fn fetch_json(host: &str, command: &str) -> Result<serde_json::Value, FetchError> {
    let text = crate::show::fetch(host, command, true).await?;
    serde_json::from_str(&text)
        .map_err(|e| FetchError::Failed(format!("zebra-rs did not answer in JSON: {e}")))
}

fn print_json(value: &serde_json::Value) {
    // serde_json cannot fail on a `Value`.
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
    );
}

async fn run_one(host: &str, line: &str) -> i32 {
    let result = match command::translate(line) {
        Action::SummaryJson { family, per_vrf } => {
            fetch_json(host, "show bgp summary").await.map(|src| {
                let out = json::summary(&src, family);
                if per_vrf {
                    print_json(&serde_json::json!({ "default": out }));
                } else {
                    print_json(&out);
                }
            })
        }
        Action::RouteJson {
            family,
            protocol,
            target,
        } => {
            let mut source = String::from(match family {
                command::Family::V4 => "show ip route",
                command::Family::V6 => "show ipv6 route",
            });
            if let Some(target) = &target {
                source.push(' ');
                source.push_str(target);
            }
            fetch_json(host, &source)
                .await
                .map(|src| print_json(&json::routes(&src, protocol.as_deref())))
        }
        Action::BgpHeaderJson => fetch_json(host, "show bgp summary")
            .await
            .map(|src| print_json(&json::bgp_header(&src))),
        Action::Show(cmd) => crate::show::fetch(host, &cmd, false)
            .await
            .map(|text| print_output(&text)),
        Action::Clear(cmd) => crate::clear::run(host, &cmd)
            .await
            .map(|text| print_output(&text)),
        Action::Unsupported(why) => {
            println!("% Unknown command: {line} (zebra-rs vtysh compatibility: {why})");
            return 1;
        }
    };
    match result {
        Ok(()) => 0,
        Err(e) => report(line, e),
    }
}

/// Run an FRR vtysh command line against the daemon at `host`. Returns
/// the process exit status: 0 when every command was answered.
pub async fn run(host: &str, args: Vec<String>) -> i32 {
    let commands = match parse_args(&args) {
        Ok(c) => c,
        Err(why) => {
            if !why.is_empty() {
                eprintln!("vtysh: {why}");
            }
            usage();
            return 1;
        }
    };
    if commands.is_empty() {
        usage();
        return 1;
    }
    // FRR runs every -c and exits with the first failure's status.
    let mut status = 0;
    for line in &commands {
        let code = run_one(host, line).await;
        if status == 0 {
            status = code;
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn started_as_vtysh() {
        assert!(is_vtysh_name("vtysh"));
        assert!(is_vtysh_name("/usr/bin/vtysh"));
        assert!(!is_vtysh_name("/usr/bin/vtyctl"));
        assert!(!is_vtysh_name(""));
    }

    /// The exact command lines SONiC runs: bgpmon, bgp_util through the
    /// host wrapper (which adds the tty tag), and a multi-asic `-n`.
    #[test]
    fn sonic_command_lines() {
        assert_eq!(
            parse_args(&args(&["-H", "/dev/null", "-c", "show bgp summary json"])).unwrap(),
            ["show bgp summary json"]
        );
        assert_eq!(
            parse_args(&args(&["/dev/pts/0", "-c", "show ip route"])).unwrap(),
            ["show ip route"]
        );
        assert_eq!(
            parse_args(&args(&["-n", "0", "-c", "show ip route json"])).unwrap(),
            ["show ip route json"]
        );
        assert_eq!(
            parse_args(&args(&["-c", "show version", "-c", "show ip route"])).unwrap(),
            ["show version", "show ip route"]
        );
    }

    #[test]
    fn bad_command_lines() {
        assert!(parse_args(&args(&["-c"])).is_err());
        assert!(parse_args(&args(&["-f", "/tmp/x.conf"])).is_err());
        assert!(parse_args(&args(&["-H"])).is_err());
        assert_eq!(parse_args(&args(&[])).unwrap(), Vec::<String>::new());
    }
}
