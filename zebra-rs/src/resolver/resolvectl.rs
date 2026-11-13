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
//! **The interface is said by its index.** `resolvectl` takes a number
//! in place of a name and sends it over the system bus as it is, with
//! no lookup of its own (every release since the first, systemd 239). A
//! name it would look up itself, when it comes to run, and the name can
//! be another interface's by then. The index is what resolved keeps a
//! link's settings by, also through a change of name: a command reaches
//! the interface it was started for, or resolved says that it knows no
//! such link.
//!
//! **The network namespace.** The bus is one per host, the indexes one
//! set per network namespace: sent from another namespace, an index is
//! whichever host interface happens to have it. So `resolvectl` is only
//! run in the namespace of PID 1, where resolved is.
//!
//! `$ZEBRA_RESOLVECTL` names a program to run in `resolvectl`'s place,
//! with the same arguments. Whoever sets it answers for what that
//! program reaches, so the namespace is not looked at: it is how the BDD
//! suite, whose daemons all run in namespaces, sees the commands.
//!
//! **The program is looked for before every command** ([`locate`]), and
//! the file found is the one run. A host without `resolvectl` is then
//! known to be one before anything is started, and each time anew: the
//! resolver task puts an interface on record before a command that may
//! give it something, and must know whether there is such a command
//! without taking it from how the last one went.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use nix::unistd::{AccessFlags, access};
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

    /// The name of the program to run, or why none may be.
    fn name(&mut self) -> Result<OsString, String> {
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
    type Program = PathBuf;

    fn program(&mut self) -> Result<PathBuf, Failure> {
        let name = self.name().map_err(Failure::Refused)?;
        locate(&name, std::env::var_os("PATH").as_deref())
            .ok_or_else(|| Failure::NotRun(format!("{}: no such program", name.to_string_lossy())))
    }

    async fn run(&mut self, program: &PathBuf, op: &Op) -> Result<(), Failure> {
        exec(program.as_os_str(), &argv(op), self.timeout).await
    }

    fn permitted(&mut self) -> Result<(), String> {
        self.name().map(|_| ())
    }

    fn ifname(&self, ifindex: u32) -> Option<String> {
        known_name(ifindex, ask_name(ifindex))
    }
}

/// What the system says the interface of that index is called, or the
/// error (`errno`) the question ended with.
///
/// Asked of libc itself. nix 0.31 takes the null pointer that says
/// "no name" for success and hands back an empty one, whatever the
/// reason was: no such interface, or no file descriptor left to ask
/// with.
fn ask_name(ifindex: u32) -> Result<String, i32> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `if_indextoname` writes at most `IF_NAMESIZE` bytes, the
    // closing nul among them, to the buffer it is given, which is that
    // long.
    let name = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if name.is_null() {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // SAFETY: not null, so the buffer holds a name and its closing nul.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    // A name is any bytes to the kernel. One that is not text is an
    // interface all the same.
    Ok(name.to_string_lossy().into_owned())
}

/// What the resolver task is told of an interface index
/// ([`Backend::ifname`]): `None` only where the system has said that
/// no interface has it (`ENXIO`, as POSIX has it; `ENODEV` is the
/// kernel's own word for the same).
///
/// Any other error is the question failing, not its answer: no file
/// descriptor or no memory to ask with. The interface is then taken to
/// be there, under a name that says only its index. To take it for gone
/// would be to forget what it holds, for good: nothing would ever be
/// taken back from it. Taken to be there, its command is made, and one
/// that fails is tried again.
fn known_name(ifindex: u32, asked: Result<String, i32>) -> Option<String> {
    match asked {
        Ok(name) => Some(name),
        Err(libc::ENXIO | libc::ENODEV) => None,
        Err(_) => Some(format!("link {ifindex}")),
    }
}

/// The file `name` is run from: itself when it says where it is (a `/`
/// in it), else the first directory of `path` (`$PATH`) that has it, as
/// `execvp` looks. Only a file this process may execute counts.
///
/// The spawn would look by itself, and say afterwards that it found
/// nothing. Looking here says so before, and the spawn is given the
/// file that was found, so the two cannot disagree: no program found is
/// no command started.
fn locate(name: &OsStr, path: Option<&OsStr>) -> Option<PathBuf> {
    let runnable = |file: &Path| file.is_file() && access(file, AccessFlags::X_OK).is_ok();
    if name.as_bytes().contains(&b'/') {
        let file = Path::new(name);
        return runnable(file).then(|| file.to_path_buf());
    }
    // What `execvp` searches without a `$PATH`.
    let path = path.unwrap_or(OsStr::new("/bin:/usr/bin"));
    std::env::split_paths(path)
        // An empty entry is the current directory to `execvp`, and a
        // relative one is under it. Neither is searched: a daemon does
        // not run what happens to lie where it was started.
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|file| runnable(file))
}

/// Whether `ours` and `init` are the same network namespace: this
/// process is where the host's resolved is. Reading PID 1's takes root,
/// and so does configuring resolved.
fn host_netns(ours: &Path, init: &Path) -> Result<(), String> {
    let root = nix::unistd::geteuid().is_root();
    let read = |path: &Path| std::fs::read_link(path).map_err(|e| unreadable(path, &e, root));
    if read(ours)? == read(init)? {
        Ok(())
    } else {
        Err("this is not the host's network namespace".to_string())
    }
}

/// Why a namespace could not be looked at.
///
/// A lease's name servers are the host's without a word of
/// configuration, so this is the one line that tells a zebra-rs that is
/// not root (started with file capabilities alone, as `make run` does)
/// why they were not set. It names the cause and not only the error.
fn unreadable(path: &Path, error: &std::io::Error, root: bool) -> String {
    let not_root = !root && error.kind() == std::io::ErrorKind::PermissionDenied;
    format!(
        "cannot tell whether this is the host's network namespace ({}: {error}{})",
        path.display(),
        if not_root {
            "; zebra-rs is not root"
        } else {
            ""
        }
    )
}

/// `resolvectl`'s arguments for `op`: the verb, the interface by its
/// index, and the list. Nothing after the `--` is read as an option,
/// whatever it is.
fn argv(op: &Op) -> Vec<String> {
    // One empty argument is how a list is cleared.
    let list = |items: Vec<String>| {
        if items.is_empty() {
            vec![String::new()]
        } else {
            items
        }
    };
    let (verb, ifindex, values) = match op {
        Op::Dns(ifindex, servers) => (
            "dns",
            ifindex,
            list(servers.iter().map(ToString::to_string).collect()),
        ),
        Op::Domains(ifindex, domains) => ("domain", ifindex, list(domains.clone())),
        Op::Revert(ifindex) => ("revert", ifindex, Vec::new()),
    };
    let mut argv = vec!["--".to_string(), verb.to_string(), ifindex.to_string()];
    argv.extend(values);
    argv
}

/// Run `program` to its end, or for `limit`. The text is for the log:
/// how it ended, or the first line it wrote to standard error.
///
/// Only a program that could not be started is known to have changed
/// nothing ([`Failure::NotRun`]). Once it has run, any end but success
/// leaves what the interface holds open ([`Failure::Uncertain`]):
///
/// - cut short, by the time limit or a signal, it may have made its
///   call to resolved first;
/// - and an error from resolved is no assurance either. Replacing a
///   list (`SetLinkDNS`, `SetLinkDomains`), resolved 255 drops the whole
///   list when it cannot add one of the new entries, and reports the
///   error after that. `RevertLink` reports a failure to send its reply
///   when the settings are already gone.
async fn exec(program: &OsStr, argv: &[String], limit: Duration) -> Result<(), Failure> {
    let name = program.to_string_lossy();
    let child = Command::new(program)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        // Dropped at the time limit, which ends it.
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Failure::NotRun(format!("{name}: {e}")))?;
    let how = match tokio::time::timeout(limit, child.wait_with_output()).await {
        Err(_) => format!("no answer in {} s", limit.as_secs_f32()),
        Ok(Err(e)) => e.to_string(),
        Ok(Ok(output)) if output.status.success() => return Ok(()),
        Ok(Ok(output)) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            match stderr.lines().find(|line| !line.trim().is_empty()) {
                Some(line) => line.trim().to_string(),
                None => output.status.to_string(),
            }
        }
    };
    Err(Failure::Uncertain(format!("{name}: {how}")))
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::symlink;
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
        ///
        /// Written by a child and not by this process. A file this
        /// process has open for writing is open in every child another
        /// test's thread forks at that moment, until that child calls
        /// exec, and the kernel refuses to run a file that anybody has
        /// open for writing (ETXTBSY, "Text file busy"). The tests here
        /// run side by side and all start programs.
        fn script(&self, name: &str, body: &str) -> OsString {
            let path = self.0.join(name);
            let mut writer = std::process::Command::new("sh")
                .args(["-c", r#"cat > "$0" && chmod 755 "$0""#])
                .arg(&path)
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = writer.stdin.take().unwrap();
            stdin
                .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
                .unwrap();
            drop(stdin);
            assert!(writer.wait().unwrap().success());
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
        // The interface is a number: its index, and never its name.
        assert_eq!(
            argv(&Op::Dns(7, servers)),
            strings(&["--", "dns", "7", "198.51.100.53", "2001:db8::53"])
        );
        assert_eq!(
            argv(&Op::Domains(7, strings(&["example.com", "example.net"]))),
            strings(&["--", "domain", "7", "example.com", "example.net"])
        );
        assert_eq!(argv(&Op::Revert(4021)), strings(&["--", "revert", "4021"]));
    }

    #[test]
    fn an_empty_list_is_one_empty_argument() {
        assert_eq!(
            argv(&Op::Domains(7, vec![])),
            strings(&["--", "domain", "7", ""])
        );
        assert_eq!(argv(&Op::Dns(7, vec![])), strings(&["--", "dns", "7", ""]));
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

    /// PID 1's namespace is not readable without root. Not being root
    /// is then named as the cause, and only then.
    #[test]
    fn a_namespace_that_takes_root_to_read_says_so() {
        let init = Path::new("/proc/1/ns/net");
        let denied = std::io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(
            unreadable(init, &denied, false),
            "cannot tell whether this is the host's network namespace \
             (/proc/1/ns/net: Permission denied (os error 13); zebra-rs is not root)"
        );
        // Root and refused all the same (a user namespace): not that.
        assert_eq!(
            unreadable(init, &denied, true),
            "cannot tell whether this is the host's network namespace \
             (/proc/1/ns/net: Permission denied (os error 13))"
        );
        // Nor when it is not there to read.
        let absent = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert!(
            unreadable(init, &absent, false).ends_with("(os error 2))"),
            "{}",
            unreadable(init, &absent, false)
        );
    }

    #[test]
    fn a_named_program_is_run_whatever_the_namespace() {
        let mut named = Resolvectl::new(Some("/opt/stand-in".into()));
        assert_eq!(named.name(), Ok(OsString::from("/opt/stand-in")));
        assert_eq!(named.permitted(), Ok(()));
        // Not looked at.
        assert_eq!(named.host, None);

        // Empty is not a name: the namespace decides, once.
        let mut system = Resolvectl::new(Some(OsString::new()));
        assert_eq!(system.named, None);
        system.host = Some(Err("this is not the host's network namespace".to_string()));
        assert_eq!(
            system.name(),
            Err("this is not the host's network namespace".to_string())
        );
        assert_eq!(
            system.permitted(),
            Err("this is not the host's network namespace".to_string())
        );
        system.host = Some(Ok(()));
        assert_eq!(system.name(), Ok(OsString::from("resolvectl")));
        assert_eq!(system.permitted(), Ok(()));
    }

    /// What the resolver task does with one command: the program is
    /// looked for, and what is found is run.
    async fn run(backend: &mut Resolvectl, op: Op) -> Result<(), Failure> {
        let program = backend.program()?;
        backend.run(&program, &op).await
    }

    #[tokio::test]
    async fn a_refusal_names_the_namespace_and_runs_nothing() {
        let mut system = Resolvectl::new(None);
        system.host = Some(Err("this is not the host's network namespace".to_string()));
        assert_eq!(
            run(&mut system, Op::Revert(7)).await,
            Err(Failure::Refused(
                "this is not the host's network namespace".to_string()
            ))
        );
    }

    /// The search is `execvp`'s: the directories of `$PATH` in their
    /// order, and a name with a `/` in it is where it says. What is
    /// found is a file this process may execute, and nothing else.
    #[test]
    fn the_program_is_looked_for_where_a_spawn_would_find_it() {
        let dir = Dir::new("locate");
        let sub = |name: &str| {
            let sub = dir.0.join(name);
            std::fs::create_dir_all(&sub).unwrap();
            Dir(sub)
        };
        let (empty, first, second) = (sub("empty"), sub("first"), sub("second"));
        let in_first = PathBuf::from(first.script("resolvectl", "exit 0"));
        let in_second = PathBuf::from(second.script("resolvectl", "exit 0"));
        let path =
            |dirs: &[&Dir]| std::env::join_paths(dirs.iter().map(|dir| dir.0.clone())).unwrap();
        let name = OsStr::new("resolvectl");

        assert_eq!(
            locate(name, Some(&path(&[&empty, &first, &second]))),
            Some(in_first.clone())
        );
        assert_eq!(
            locate(name, Some(&path(&[&second, &first]))),
            Some(in_second.clone())
        );
        assert_eq!(locate(name, Some(&path(&[&empty]))), None);
        assert_eq!(locate(name, Some(OsStr::new(""))), None);
        // Said with its place, the path is not asked.
        assert_eq!(
            locate(in_second.as_os_str(), Some(&path(&[&first]))),
            Some(in_second.clone())
        );
        assert_eq!(
            locate(
                empty.0.join("resolvectl").as_os_str(),
                Some(&path(&[&first]))
            ),
            None
        );
        // Also when the place is said from where this process is: it is
        // not looked for under the directories of the path.
        assert!(dir.0.join("first/resolvectl").is_file());
        assert_eq!(
            locate(OsStr::new("first/resolvectl"), Some(dir.0.as_os_str())),
            None
        );

        // A file that may not be executed is not a program, nor is a
        // directory of that name: the search goes on past both.
        let plain = sub("plain");
        std::fs::write(plain.0.join("resolvectl"), b"#!/bin/sh\n").unwrap();
        let folder = sub("folder");
        std::fs::create_dir(folder.0.join("resolvectl")).unwrap();
        assert_eq!(locate(name, Some(&path(&[&plain, &folder]))), None);
        assert_eq!(
            locate(name, Some(&path(&[&plain, &folder, &second]))),
            Some(in_second)
        );
        assert_eq!(locate(plain.0.join("resolvectl").as_os_str(), None), None);

        // A directory said from where this process is, is not
        // searched, though the program is there by that way too.
        let here = std::env::current_dir().unwrap();
        let up: PathBuf = here.components().skip(1).map(|_| "..").collect();
        let relative = up.join(first.0.strip_prefix("/").unwrap());
        assert!(relative.is_relative() && relative.join(name).is_file());
        assert_eq!(locate(name, Some(relative.as_os_str())), None);
        // Nor is where it is itself, which an empty entry means.
        assert_eq!(locate(name, Some(OsStr::new(":"))), None);
    }

    /// With no `$PATH` the search is `execvp`'s own.
    #[test]
    fn without_a_path_the_usual_places_are_searched() {
        assert_eq!(
            locate(OsStr::new("sh"), None),
            Some(PathBuf::from("/bin/sh"))
        );
        assert_eq!(locate(OsStr::new("zebra-rs-no-such-program"), None), None);
    }

    /// No program is no command: it is said before anything is started,
    /// as the one failure that changed nothing.
    #[tokio::test]
    async fn a_program_that_is_not_there_is_not_started() {
        let dir = Dir::new("not-there");
        let absent = dir.0.join("absent");
        let mut backend = Resolvectl::new(Some(absent.clone().into_os_string()));
        assert_eq!(
            backend.program(),
            Err(Failure::NotRun(format!(
                "{}: no such program",
                absent.display()
            )))
        );
        // It comes, and the next look finds it.
        let there = dir.script("absent", "exit 0");
        assert_eq!(backend.program(), Ok(PathBuf::from(&there)));
        assert_eq!(run(&mut backend, Op::Revert(7)).await, Ok(()));
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
            run(&mut backend, Op::Domains(7, strings(&["example.com"]))).await,
            Ok(())
        );
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap(),
            "--\ndomain\n7\nexample.com\n"
        );

        // An error says what went wrong, not what the interface holds
        // now: resolved can drop the old list before it reports one.
        let refuse = dir.script("refuse", "echo; echo 'Failed to set: no' >&2; exit 1");
        let mut backend = Resolvectl::new(Some(refuse.clone()));
        assert_eq!(
            run(&mut backend, Op::Revert(7)).await,
            Err(Failure::Uncertain(format!(
                "{}: Failed to set: no",
                refuse.to_string_lossy()
            )))
        );

        // Nothing on standard error: how it ended.
        let silent = dir.script("silent", "exit 3");
        let error = match exec(&silent, &[], TIMEOUT).await {
            Err(Failure::Uncertain(error)) => error,
            other => panic!("an error exit does not say that nothing changed: {other:?}"),
        };
        assert!(error.ends_with("exit status: 3"), "{error}");
    }

    /// Cut short by a signal, it may have made its call first.
    #[tokio::test]
    async fn a_program_that_is_killed_leaves_it_open_what_it_did() {
        let dir = Dir::new("killed");
        let killed = dir.script("killed", "kill -KILL $$");
        let error = match exec(&killed, &[], TIMEOUT).await {
            Err(Failure::Uncertain(error)) => error,
            other => panic!("a signal does not say that nothing changed: {other:?}"),
        };
        assert!(error.ends_with("signal: 9 (SIGKILL)"), "{error}");
    }

    #[tokio::test]
    async fn a_program_that_cannot_be_started_has_changed_nothing() {
        let dir = Dir::new("absent");
        let absent = dir.0.join("absent").into_os_string();
        // The one failure that says so.
        let error = match exec(&absent, &[], TIMEOUT).await {
            Err(Failure::NotRun(error)) => error,
            other => panic!("a program that cannot be started has done nothing: {other:?}"),
        };
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
        // What it did before the limit is not known.
        assert_eq!(
            run(&mut backend, Op::Revert(7)).await,
            Err(Failure::Uncertain(format!(
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
    fn an_index_has_an_interface_with_a_name_or_none() {
        let backend = Resolvectl::new(None);
        assert_eq!(backend.ifname(1), Some("lo".to_string()));
        assert_eq!(backend.ifname(u32::MAX), None);
        // "None" is the system's word, and this is how it says it.
        assert_eq!(ask_name(1), Ok("lo".to_string()));
        assert_eq!(ask_name(u32::MAX), Err(libc::ENXIO));
    }

    /// Only the system's word that there is no such interface makes one
    /// gone. A question that could not be asked (no file descriptor
    /// left, no memory, a socket that may not be opened) says nothing of
    /// the interface: it is taken to be there, or what it holds would
    /// be forgotten and never taken back.
    #[test]
    fn an_interface_that_cannot_be_asked_about_is_not_taken_for_gone() {
        assert_eq!(
            known_name(7, Ok("wan0".to_string())),
            Some("wan0".to_string())
        );
        for gone in [libc::ENXIO, libc::ENODEV] {
            assert_eq!(known_name(7, Err(gone)), None, "{gone}");
        }
        for failed in [libc::EMFILE, libc::ENFILE, libc::ENOMEM, libc::EACCES, 0] {
            assert_eq!(
                known_name(7, Err(failed)),
                Some("link 7".to_string()),
                "{failed}"
            );
        }
    }

    /// Against the real `resolvectl` and a running systemd-resolved,
    /// which no other test reaches. It needs root and the host's network
    /// namespace, and makes, renames and removes a dummy interface (left
    /// down, so resolved never asks the servers it is given):
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
        /// `resolvectl dns|domain LINK`: `Link N (NAME): …`. The name
        /// that resolved shows, and what it holds for the link.
        fn held(what: &str, link: &str) -> (String, String) {
            let output = std::process::Command::new("resolvectl")
                .args([what, link])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&output.stdout);
            let (link, values) = text.trim().split_once("):").expect("a link line");
            let (_, name) = link.split_once('(').expect("a name");
            (name.to_string(), values.trim().to_string())
        }
        const RENAMED: &str = "zrsvtest1";
        /// As a source has it from the RIB.
        fn index_of(name: &str) -> Option<u32> {
            nix::net::if_::if_nametoindex(name).ok()
        }

        ip(&["link", "del", IF]);
        ip(&["link", "del", RENAMED]);
        assert!(ip(&["link", "add", IF, "type", "dummy"]), "needs root");
        let link = Link;
        // No stand-in: the program is `resolvectl`, and this is the host.
        let mut backend = Resolvectl::new(None);
        assert_eq!(backend.name(), Ok(OsString::from("resolvectl")));
        let index = index_of(IF).expect("the dummy interface");

        // Every command says the index, and resolved takes it for the
        // interface.
        let servers = vec![
            "198.51.100.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ];
        assert_eq!(run(&mut backend, Op::Dns(index, servers)).await, Ok(()));
        let domains = strings(&["example.com", "corp.example"]);
        assert_eq!(run(&mut backend, Op::Domains(index, domains)).await, Ok(()));
        let is = |values: &str| (IF.to_string(), values.to_string());
        assert_eq!(held("dns", IF), is("198.51.100.53 2001:db8::53"));
        assert_eq!(held("domain", IF), is("example.com corp.example"));

        // No domains clears them and leaves the servers.
        assert_eq!(run(&mut backend, Op::Domains(index, vec![])).await, Ok(()));
        assert_eq!(held("domain", IF), is(""));
        assert_eq!(held("dns", IF), is("198.51.100.53 2001:db8::53"));

        // Renamed, it is the same link to resolved, with what it held,
        // and the index reaches it as before. The old name does not.
        assert!(ip(&["link", "set", IF, "name", RENAMED]));
        assert_eq!(index_of(RENAMED), Some(index));
        assert_eq!(backend.ifname(index), Some(RENAMED.to_string()));
        let renamed = |values: &str| (RENAMED.to_string(), values.to_string());
        assert_eq!(held("dns", RENAMED), renamed("198.51.100.53 2001:db8::53"));
        let other = vec!["198.51.100.54".parse().unwrap()];
        assert_eq!(run(&mut backend, Op::Dns(index, other)).await, Ok(()));
        assert_eq!(held("dns", RENAMED), renamed("198.51.100.54"));
        assert_eq!(run(&mut backend, Op::Revert(index)).await, Ok(()));
        assert_eq!(held("dns", RENAMED), renamed(""));
        assert!(ip(&["link", "set", RENAMED, "name", IF]));

        // An interface that is gone: resolved knows no such link, and
        // there is nothing left to take back.
        drop(link);
        assert_eq!(backend.ifname(index), None);
        match run(&mut backend, Op::Revert(index)).await {
            Err(Failure::Uncertain(why)) => assert!(why.contains("not known"), "{why}"),
            other => panic!("a link that is gone: {other:?}"),
        }

        // Made again under the same name it is another interface, and
        // resolved holds nothing for it. The index of the one that is
        // gone does not reach it.
        assert!(ip(&["link", "add", IF, "type", "dummy"]));
        let _link = Link;
        let again = index_of(IF).expect("the dummy interface");
        assert_ne!(again, index);
        assert_eq!(held("dns", IF), is(""));
        assert!(matches!(
            run(
                &mut backend,
                Op::Dns(index, vec!["198.51.100.53".parse().unwrap()])
            )
            .await,
            Err(Failure::Uncertain(_))
        ));
        assert_eq!(held("dns", IF), is(""));
    }
}
