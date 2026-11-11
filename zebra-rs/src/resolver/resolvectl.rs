//! systemd-resolved, through `resolvectl`: an interface's name servers
//! and search domains become that link's DNS configuration (the bus
//! calls `SetLinkDNS`, `SetLinkDomains` and `RevertLink`, which is how
//! NetworkManager feeds it too).
//!
//! resolved keeps a link's configuration while the link exists, across
//! its own restart, and only uses it while the link is up with a
//! routable address. So a lease's servers go in when the lease is bound
//! and come out when it ends, and a link that loses its carrier in
//! between needs nothing from us.
//!
//! **The network namespace.** `resolvectl` takes an interface name,
//! turns it into an index where it runs, and sends that index over the
//! system bus. The bus is one per host, the indexes one set per network
//! namespace: run from another namespace, the command configures
//! whichever host interface happens to have that index. So it is only
//! run in the namespace of PID 1, where resolved is.
//!
//! `$ZEBRA_RESOLVECTL` names a program to run in `resolvectl`'s place,
//! with the same arguments. Whoever sets it answers for what that
//! program reaches, so the namespace is not looked at: it is how the BDD
//! suite, whose daemons all run in namespaces, sees the commands.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use super::inst::{Backend, Failure, Op};

/// The environment variable naming a stand-in for `resolvectl`.
pub const PROGRAM_ENV: &str = "ZEBRA_RESOLVECTL";

/// How long one command may take. With resolved running it answers in
/// milliseconds; started by the call, in a second or so. A caller the
/// bus does not authorise is not refused at once but kept waiting for a
/// password nobody will type.
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct Resolvectl {
    /// `$ZEBRA_RESOLVECTL`.
    named: Option<OsString>,
    timeout: Duration,
    /// Whether this is the host's network namespace, once looked at.
    host: Option<Result<(), String>>,
}

impl Resolvectl {
    pub fn from_env() -> Resolvectl {
        Resolvectl::new(std::env::var_os(PROGRAM_ENV))
    }

    fn new(named: Option<OsString>) -> Resolvectl {
        Resolvectl {
            // Set and empty is not set.
            named: named.filter(|program| !program.is_empty()),
            timeout: TIMEOUT,
            host: None,
        }
    }

    /// The program to run, or why none may be.
    fn program(&mut self) -> Result<OsString, String> {
        if let Some(program) = &self.named {
            return Ok(program.clone());
        }
        self.host
            .get_or_insert_with(|| {
                host_netns(Path::new("/proc/self/ns/net"), Path::new("/proc/1/ns/net"))
            })
            .clone()?;
        Ok(OsString::from("resolvectl"))
    }
}

impl Backend for Resolvectl {
    async fn run(&mut self, op: &Op) -> Result<(), Failure> {
        let program = self.program().map_err(Failure::Refused)?;
        exec(&program, &argv(op), self.timeout)
            .await
            .map_err(Failure::Failed)
    }

    fn link_exists(&self, ifname: &str) -> bool {
        nix::net::if_::if_nametoindex(ifname).is_ok()
    }
}

/// Whether `ours` and `init` are the same network namespace: this
/// process is where the host's resolved is. Reading PID 1's takes root,
/// and so does configuring resolved.
fn host_netns(ours: &Path, init: &Path) -> Result<(), String> {
    let read = |path: &Path| {
        std::fs::read_link(path).map_err(|e| {
            format!(
                "cannot tell whether this is the host's network namespace ({}: {e})",
                path.display()
            )
        })
    };
    if read(ours)? == read(init)? {
        Ok(())
    } else {
        Err("this is not the host's network namespace".to_string())
    }
}

/// `resolvectl`'s arguments for `op`, after a `--` that keeps an
/// interface named like an option from being read as one.
fn argv(op: &Op) -> Vec<String> {
    // One empty argument is how a list is cleared.
    let list = |items: Vec<String>| {
        if items.is_empty() {
            vec![String::new()]
        } else {
            items
        }
    };
    let (verb, name, values) = match op {
        Op::Dns(name, servers) => (
            "dns",
            name,
            list(servers.iter().map(ToString::to_string).collect()),
        ),
        Op::Domains(name, domains) => ("domain", name, list(domains.clone())),
        Op::Revert(name) => ("revert", name, Vec::new()),
    };
    let mut argv = vec!["--".to_string(), verb.to_string(), name.clone()];
    argv.extend(values);
    argv
}

/// Run `program` to its end, or for `limit`. The error is for the log:
/// how it ended and the first line it wrote to standard error.
async fn exec(program: &OsStr, argv: &[String], limit: Duration) -> Result<(), String> {
    let name = program.to_string_lossy();
    let child = Command::new(program)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        // Dropped at the time limit, which ends it.
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("{name}: {e}"))?;
    match tokio::time::timeout(limit, child.wait_with_output()).await {
        Err(_) => Err(format!("{name}: no answer in {} s", limit.as_secs_f32())),
        Ok(Err(e)) => Err(format!("{name}: {e}")),
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            match stderr.lines().find(|line| !line.trim().is_empty()) {
                Some(line) => Err(format!("{name}: {}", line.trim())),
                None => Err(format!("{name}: {}", output.status)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    use super::*;

    /// A scratch directory, gone when the test is.
    struct Dir(PathBuf);

    impl Dir {
        fn new(test: &str) -> Dir {
            let dir =
                std::env::temp_dir().join(format!("zebra-resolver-{}-{test}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Dir(dir)
        }

        /// An executable script.
        fn script(&self, name: &str, body: &str) -> OsString {
            let path = self.0.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.into_os_string()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_arguments_are_resolvectl_s() {
        let servers = vec![
            "198.51.100.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ];
        assert_eq!(
            argv(&Op::Dns("wan0".into(), servers)),
            strings(&["--", "dns", "wan0", "198.51.100.53", "2001:db8::53"])
        );
        assert_eq!(
            argv(&Op::Domains(
                "wan0".into(),
                strings(&["example.com", "example.net"])
            )),
            strings(&["--", "domain", "wan0", "example.com", "example.net"])
        );
        assert_eq!(
            argv(&Op::Revert("wan0".into())),
            strings(&["--", "revert", "wan0"])
        );
    }

    #[test]
    fn an_empty_list_is_one_empty_argument() {
        assert_eq!(
            argv(&Op::Domains("wan0".into(), vec![])),
            strings(&["--", "domain", "wan0", ""])
        );
        assert_eq!(
            argv(&Op::Dns("wan0".into(), vec![])),
            strings(&["--", "dns", "wan0", ""])
        );
    }

    #[test]
    fn only_the_namespace_of_pid_1_is_the_host_s() {
        let dir = Dir::new("netns");
        let link = |name: &str, target: &str| {
            let path = dir.0.join(name);
            symlink(target, &path).unwrap();
            path
        };
        let ours = link("ours", "net:[4026531840]");
        let same = link("same", "net:[4026531840]");
        let other = link("other", "net:[4026532528]");
        assert_eq!(host_netns(&ours, &same), Ok(()));
        assert_eq!(
            host_netns(&ours, &other),
            Err("this is not the host's network namespace".to_string())
        );
        // Not readable (not root): not known to be the host's, so not
        // taken for it.
        let unreadable = host_netns(&ours, &dir.0.join("absent")).unwrap_err();
        assert!(
            unreadable.starts_with("cannot tell whether this is the host's network namespace"),
            "{unreadable}"
        );
    }

    #[test]
    fn a_named_program_is_run_whatever_the_namespace() {
        let mut named = Resolvectl::new(Some("/opt/stand-in".into()));
        assert_eq!(named.program(), Ok(OsString::from("/opt/stand-in")));
        // Not looked at.
        assert_eq!(named.host, None);

        // Empty is not a name: the namespace decides, once.
        let mut system = Resolvectl::new(Some(OsString::new()));
        assert_eq!(system.named, None);
        system.host = Some(Err("this is not the host's network namespace".to_string()));
        assert_eq!(
            system.program(),
            Err("this is not the host's network namespace".to_string())
        );
        system.host = Some(Ok(()));
        assert_eq!(system.program(), Ok(OsString::from("resolvectl")));
    }

    #[tokio::test]
    async fn a_refusal_names_the_namespace_and_runs_nothing() {
        let mut system = Resolvectl::new(None);
        system.host = Some(Err("this is not the host's network namespace".to_string()));
        assert_eq!(
            system.run(&Op::Revert("wan0".into())).await,
            Err(Failure::Refused(
                "this is not the host's network namespace".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn the_program_gets_the_arguments_and_its_exit_decides() {
        let dir = Dir::new("exec");
        let seen = dir.0.join("seen");
        let record = dir.script(
            "record",
            &format!("printf '%s\\n' \"$@\" > {}", seen.display()),
        );
        let mut backend = Resolvectl::new(Some(record));
        assert_eq!(
            backend
                .run(&Op::Domains("wan0".into(), strings(&["example.com"])))
                .await,
            Ok(())
        );
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap(),
            "--\ndomain\nwan0\nexample.com\n"
        );

        let refuse = dir.script("refuse", "echo; echo 'Failed to set: no' >&2; exit 1");
        let mut backend = Resolvectl::new(Some(refuse.clone()));
        assert_eq!(
            backend.run(&Op::Revert("wan0".into())).await,
            Err(Failure::Failed(format!(
                "{}: Failed to set: no",
                refuse.to_string_lossy()
            )))
        );

        // Nothing on standard error: how it ended.
        let silent = dir.script("silent", "exit 3");
        let error = exec(&silent, &[], TIMEOUT).await.unwrap_err();
        assert!(error.ends_with("exit status: 3"), "{error}");
    }

    #[tokio::test]
    async fn a_program_that_is_not_there_is_a_failure() {
        let dir = Dir::new("absent");
        let absent = dir.0.join("absent").into_os_string();
        let error = exec(&absent, &[], TIMEOUT).await.unwrap_err();
        assert!(error.contains("No such file"), "{error}");
    }

    #[tokio::test]
    async fn a_program_that_does_not_answer_is_ended() {
        let dir = Dir::new("slow");
        let pid = dir.0.join("pid");
        let slow = dir.script(
            "slow",
            &format!("echo $$ > {}; exec sleep 600", pid.display()),
        );
        let mut backend = Resolvectl::new(Some(slow.clone()));
        backend.timeout = Duration::from_millis(300);
        assert_eq!(
            backend.run(&Op::Revert("wan0".into())).await,
            Err(Failure::Failed(format!(
                "{}: no answer in 0.3 s",
                slow.to_string_lossy()
            )))
        );
        // Killed, not left behind.
        let pid: i32 = std::fs::read_to_string(&pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // Gone, or dead and not yet collected (state `Z`).
        let gone = || match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat
                .rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
            Err(_) => true,
        };
        for _ in 0..50 {
            if gone() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(gone(), "the program outlived its time limit");
    }

    #[test]
    fn an_interface_exists_or_does_not() {
        let backend = Resolvectl::new(None);
        assert!(backend.link_exists("lo"));
        assert!(!backend.link_exists("zebra-absent0"));
    }

    /// Against the real `resolvectl` and a running systemd-resolved,
    /// which no other test reaches. It needs root and the host's network
    /// namespace, and makes and removes a dummy interface (left down, so
    /// resolved never asks the servers it is given):
    ///
    /// ```text
    /// sudo target/debug/deps/zebra_rs-<hash> --ignored --exact \
    ///     resolver::resolvectl::tests::resolved_takes_a_link_s_settings_and_gives_them_back
    /// ```
    #[tokio::test]
    #[ignore = "needs root, the host's network namespace and systemd-resolved"]
    async fn resolved_takes_a_link_s_settings_and_gives_them_back() {
        const IF: &str = "zrsvtest0";
        fn ip(args: &[&str]) -> bool {
            std::process::Command::new("ip")
                .args(args)
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        }
        struct Link;
        impl Drop for Link {
            fn drop(&mut self) {
                ip(&["link", "del", IF]);
            }
        }
        /// `resolvectl dns|domain IF`: `Link N (IF): …`.
        fn held(what: &str) -> String {
            let output = std::process::Command::new("resolvectl")
                .args([what, IF])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&output.stdout);
            let (_, values) = text.trim().split_once("):").expect("a link line");
            values.trim().to_string()
        }

        ip(&["link", "del", IF]);
        assert!(ip(&["link", "add", IF, "type", "dummy"]), "needs root");
        let link = Link;
        // No stand-in: the program is `resolvectl`, and this is the host.
        let mut backend = Resolvectl::new(None);
        assert_eq!(backend.program(), Ok(OsString::from("resolvectl")));
        assert!(backend.link_exists(IF));

        let servers = vec![
            "198.51.100.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ];
        assert_eq!(backend.run(&Op::Dns(IF.into(), servers)).await, Ok(()));
        let domains = strings(&["example.com", "corp.example"]);
        assert_eq!(backend.run(&Op::Domains(IF.into(), domains)).await, Ok(()));
        assert_eq!(held("dns"), "198.51.100.53 2001:db8::53");
        assert_eq!(held("domain"), "example.com corp.example");

        // No domains clears them and leaves the servers.
        assert_eq!(backend.run(&Op::Domains(IF.into(), vec![])).await, Ok(()));
        assert_eq!(held("domain"), "");
        assert_eq!(held("dns"), "198.51.100.53 2001:db8::53");

        assert_eq!(backend.run(&Op::Revert(IF.into())).await, Ok(()));
        assert_eq!(held("dns"), "");

        // An interface that is gone: the command fails, and there is
        // nothing left to take back.
        drop(link);
        assert!(matches!(
            backend.run(&Op::Revert(IF.into())).await,
            Err(Failure::Failed(_))
        ));
        assert!(!backend.link_exists(IF));
    }
}
