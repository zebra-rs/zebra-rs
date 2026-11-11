//! `system hostname` applied to the operating system
//! (`docs/design/system-hostname.md`).
//!
//! Without `--feature insomnia` the leaf is a label inside the daemon: the
//! vty prompt, `show hostname`, the DHCP client's option 12. With the
//! feature zebra-rs owns the box's configuration, and the RIB task holds a
//! [`SystemHostname`] that makes the committed name the system's: the
//! kernel host name and the static one in `/etc/hostname`.
//!
//! Three rules shape the code:
//!
//! - **The default network namespace only.** A zebra-rs started by `ip
//!   netns exec` still shares the host's UTS namespace, so its
//!   `sethostname(2)` would rename the host. Every BDD daemon is one.
//! - **Deleting gives the name back.** The first takeover records the name
//!   it found ([`Saved`]); with `system hostname` gone from the running
//!   config that name is restored and the record removed, also when the
//!   line went away while zebra-rs was down.
//! - **Each step can be repeated.** [`reconcile`] compares before it writes
//!   and orders its writes so that running it again after a crash finishes
//!   the job.
//! - **The record is on disk before the name it holds is overwritten.** A
//!   write here returns only once the file and every directory leading to
//!   it are synced, and says so when they cannot be. Otherwise a power
//!   failure could keep the new `/etc/hostname` and lose the record, and
//!   the next start would save zebra-rs's own name as the one to give back.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The static host name: what systemd gives the kernel early in the boot.
const STATIC_PATH: &str = "/etc/hostname";

/// The name found at the first takeover.
const SAVED_PATH: &str = "/var/lib/zebra-rs/system/hostname.json";

/// Names a directory for a file-backed stand-in of the system: `kernel`
/// for the kernel name, `hostname` for `/etc/hostname`, `saved.json` for
/// the record. With it set nothing here calls `sethostname(2)` or opens
/// `/etc/hostname`, so it is safe in any namespace; the BDD harness sets it
/// for every daemon it starts.
///
/// A daemon that is root writes there, so the directory has to be one
/// nobody else can rearrange: not a predictable name under `/tmp`, where
/// another user can put a symbolic link first. [`stand_in_refusal`] turns
/// away what it can tell is not this user's own; choosing the place is up
/// to whoever sets the variable (the BDD harness uses `/run`).
const STUB_ENV: &str = "ZEBRA_HOSTNAME_STUB_DIR";

/// The stand-in's kernel name before anything set one.
const STUB_KERNEL_DEFAULT: &str = "localhost";

/// The longest name the kernel takes (`HOST_NAME_MAX`).
const MAX_LEN: usize = 64;

/// The longest label of a name (RFC 1123).
const MAX_LABEL: usize = 63;

/// Whether `name` can be a system host name: at most 64 characters, in
/// labels of letters, digits and hyphens separated by single dots, none
/// starting or ending with a hyphen. The kernel refuses a longer name, and
/// the schema's pattern cannot count or tell `r1..x` and `r1-` from a name.
pub fn valid(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("a host name is not empty".to_string());
    }
    if name.len() > MAX_LEN {
        return Err(format!(
            "a host name is at most {MAX_LEN} characters, and this one has {}",
            name.len()
        ));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(
                "a host name is labels separated by single dots, with none at either end"
                    .to_string(),
            );
        }
        if label.len() > MAX_LABEL {
            return Err(format!(
                "a host name's label is at most {MAX_LABEL} characters"
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("a host name is made of letters, digits, hyphens and dots".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("a host name's label does not start or end with a hyphen".to_string());
        }
    }
    Ok(())
}

/// The name the system had when zebra-rs first took it over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    /// The static name; `None` when `/etc/hostname` was absent or named
    /// nothing.
    #[serde(rename = "static")]
    pub static_name: Option<String>,
    /// The kernel's name, restored when there was no static one.
    pub kernel: String,
}

/// What [`reconcile`] reads and writes. An error is its text, ready for the
/// log and for `show hostname`.
///
/// The static name and the record are files, and what they hold has to
/// outlive a power failure. `set_static` and `set_saved` therefore return
/// `Ok` only once the change is on disk. One that fails may still have left
/// the new value in view, which a rerun then finds in place: `sync_static`
/// and `sync_saved` put on disk what is there, a value or its absence,
/// without writing it again. The kernel name lives in memory only.
pub trait Backend {
    fn kernel(&self) -> Result<String, String>;
    fn set_kernel(&mut self, name: &str) -> Result<(), String>;
    fn static_name(&self) -> Result<Option<String>, String>;
    fn set_static(&mut self, name: Option<&str>) -> Result<(), String>;
    fn sync_static(&mut self) -> Result<(), String>;
    fn saved(&self) -> Result<Option<Saved>, String>;
    fn set_saved(&mut self, saved: Option<&Saved>) -> Result<(), String>;
    fn sync_saved(&mut self) -> Result<(), String>;
}

/// Make the system's name `wanted`, or with `None` give back the saved one.
/// Returns whether anything was written.
///
/// The order is what makes a rerun finish an interrupted one. Applying: the
/// record first, so that the name found is never lost, then the file, then
/// the kernel. Restoring: the file, the kernel, and the record last, so
/// that it stays until both are back.
///
/// "First" and "last" mean on disk, not only in view, or a power failure
/// could undo the earlier step and keep the later one. So a step that finds
/// its value already in place still syncs it: the run that put it there may
/// have been interrupted, or have failed, before it reached the disk. Two
/// of these are what correctness rests on. A record not yet on disk when
/// the name it holds is overwritten can be lost with the new name kept, and
/// the next start then saves zebra-rs's own name as the one found. A
/// restored name not yet on disk when the record is removed can revert with
/// the record gone, and nothing is left that knows the way back.
pub fn reconcile(backend: &mut impl Backend, wanted: Option<&str>) -> Result<bool, String> {
    let mut changed = false;
    match wanted {
        Some(name) => {
            match backend.saved()? {
                None => {
                    let saved = Saved {
                        static_name: backend.static_name()?,
                        kernel: backend.kernel()?,
                    };
                    backend.set_saved(Some(&saved))?;
                    changed = true;
                }
                Some(_) => backend.sync_saved()?,
            }
            if backend.static_name()?.as_deref() != Some(name) {
                backend.set_static(Some(name))?;
                changed = true;
            } else {
                backend.sync_static()?;
            }
            if backend.kernel()? != name {
                backend.set_kernel(name)?;
                changed = true;
            }
        }
        None => {
            let Some(saved) = backend.saved()? else {
                // Nothing to give back. A removal that an earlier run could
                // not put on disk is put there now: a record that came back
                // with the power would be taken for a name to restore, over
                // whatever the system has been called since.
                backend.sync_saved()?;
                return Ok(false);
            };
            backend.sync_saved()?;
            if backend.static_name()? != saved.static_name {
                backend.set_static(saved.static_name.as_deref())?;
            } else {
                backend.sync_static()?;
            }
            let kernel = saved.static_name.as_deref().unwrap_or(&saved.kernel);
            if backend.kernel()? != kernel {
                backend.set_kernel(kernel)?;
            }
            backend.set_saved(None)?;
            changed = true;
        }
    }
    Ok(changed)
}

/// Where the kernel name lives.
#[derive(Debug)]
enum Kernel {
    /// The real one: `gethostname(2)` and `sethostname(2)`, which act on
    /// this process's UTS namespace.
    Syscall,
    /// The stand-in's file.
    File(PathBuf),
}

/// The system as [`reconcile`] sees it: the real one, or the stand-in in a
/// directory. Both keep the static name and the record in files, through
/// the same code.
#[derive(Debug)]
pub struct Store {
    kernel: Kernel,
    static_path: PathBuf,
    saved_path: PathBuf,
}

impl Store {
    fn system() -> Self {
        Self {
            kernel: Kernel::Syscall,
            static_path: PathBuf::from(STATIC_PATH),
            saved_path: PathBuf::from(SAVED_PATH),
        }
    }

    fn stub(dir: &Path) -> Self {
        Self {
            kernel: Kernel::File(dir.join("kernel")),
            static_path: dir.join("hostname"),
            saved_path: dir.join("saved.json"),
        }
    }
}

/// `what: error`, the form every [`Backend`] error takes.
fn context<T>(what: impl std::fmt::Display, result: io::Result<T>) -> Result<T, String> {
    result.map_err(|e| format!("{what}: {e}"))
}

impl Backend for Store {
    fn kernel(&self) -> Result<String, String> {
        match &self.kernel {
            Kernel::Syscall => context(
                "gethostname",
                hostname::get().map(|name| name.to_string_lossy().into_owned()),
            ),
            Kernel::File(path) => context(
                path.display(),
                read_name(path).map(|name| name.unwrap_or_else(|| STUB_KERNEL_DEFAULT.to_string())),
            ),
        }
    }

    fn set_kernel(&mut self, name: &str) -> Result<(), String> {
        match &self.kernel {
            Kernel::Syscall => context("sethostname", hostname::set(name)),
            Kernel::File(path) => context(path.display(), replace(path, &line(name))),
        }
    }

    fn static_name(&self) -> Result<Option<String>, String> {
        context(self.static_path.display(), read_name(&self.static_path))
    }

    fn set_static(&mut self, name: Option<&str>) -> Result<(), String> {
        let result = match name {
            Some(name) => replace(&self.static_path, &line(name)),
            None => remove(&self.static_path, sync_entry),
        };
        context(self.static_path.display(), result)
    }

    fn sync_static(&mut self) -> Result<(), String> {
        context(self.static_path.display(), sync_path(&self.static_path))
    }

    fn saved(&self) -> Result<Option<Saved>, String> {
        let text = match fs::read_to_string(&self.saved_path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", self.saved_path.display())),
        };
        // A record that does not parse is not taken for an absent one: the
        // next takeover would then save the name zebra-rs itself set.
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", self.saved_path.display()))
    }

    fn set_saved(&mut self, saved: Option<&Saved>) -> Result<(), String> {
        let result = match saved {
            Some(saved) => serde_json::to_vec(saved)
                .map_err(io::Error::other)
                .and_then(|mut json| {
                    json.push(b'\n');
                    replace(&self.saved_path, &json)
                }),
            None => remove(&self.saved_path, sync_entry),
        };
        context(self.saved_path.display(), result)
    }

    fn sync_saved(&mut self) -> Result<(), String> {
        context(self.saved_path.display(), sync_path(&self.saved_path))
    }
}

/// A name as a host name file holds it.
fn line(name: &str) -> Vec<u8> {
    format!("{name}\n").into_bytes()
}

/// The name in a host name file, as systemd reads `/etc/hostname`: the
/// first line that is neither empty nor a comment. `None` when the file is
/// absent or has no such line.
fn read_name(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_string)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether `error` says the path is a mount point, which can be neither
/// renamed over nor removed. Docker bind-mounts `/etc/hostname`.
fn is_mount_point(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EBUSY)
}

/// Give `path` the content `bytes`: atomically, so that a failure leaves
/// the old content, or in place when `path` is a mount point. `Ok` means it
/// is on disk.
fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match write_atomic(path, bytes, sync_entry) {
        Err(e) if is_mount_point(&e) => write_in_place(path, bytes),
        result => result,
    }
}

/// Remove `path`, and put the removal on disk with `sync` ([`sync_entry`];
/// a parameter so that a test can make it fail). An absent path is removed
/// already. A mount point is emptied instead.
fn remove(path: &Path, sync: impl FnOnce(&Path) -> io::Result<()>) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) if is_mount_point(&e) => write_in_place(path, b""),
        Err(e) => Err(e),
    }
}

/// The outcome of syncing a directory, with one failure excused: a
/// filesystem saying that it has no way to sync this object, which fsync(2)
/// reports as `EINVAL`. There is then nothing to wait for. Any other
/// failure stands: the change may not be on disk.
fn excusing_unsupported(synced: io::Result<()>) -> io::Result<()> {
    match synced {
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP)) => Ok(()),
        synced => synced,
    }
}

/// Put the entries of the directory `dir` on disk.
fn sync_dir(dir: &Path) -> io::Result<()> {
    excusing_unsupported(fs::File::open(dir)?.sync_all())
}

/// The directories whose entries lead to `path`, the nearest first.
fn directories(path: &Path) -> impl Iterator<Item = &Path> {
    path.ancestors().skip(1).map(|dir| {
        if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        }
    })
}

/// Put the directory entry of `path` on disk, a new one or a removed one:
/// its directory, and every directory above that one. All of them, because
/// an entry survives a power failure only if each entry leading to it does,
/// and which of those are already on disk is not known: a directory may
/// have been created a moment ago by this write, or by a run that was
/// interrupted before it synced anything. Syncing one that has nothing
/// pending costs nothing.
fn sync_entry(path: &Path) -> io::Result<()> {
    directories(path).try_for_each(sync_dir)
}

/// Put on disk what is at `path` now: the file and its entry, or the
/// absence of one.
fn sync_path(path: &Path) -> io::Result<()> {
    match fs::File::open(path) {
        Ok(file) => {
            file.sync_all()?;
            sync_entry(path)
        }
        // What may not be on disk is a removal, in the directories that
        // exist. One that does not exist never held the file: nothing here
        // removes a directory.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            directories(path).try_for_each(|dir| match sync_dir(dir) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                result => result,
            })
        }
        Err(e) => Err(e),
    }
}

/// The temporary file [`write_atomic`] renames over `path`, beside it so
/// that the rename stays within one filesystem.
fn temporary(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".zebra-rs.tmp");
    path.with_file_name(name)
}

/// Create the temporary file `tmp`, never open one: `O_EXCL` does not
/// follow a symbolic link, and does not write into a file somebody else
/// put under that name. When the name is taken, by an interrupted run or
/// by anybody else, what is there is removed (the link itself, if it is
/// one) and the file created again.
fn create_temporary(tmp: &Path) -> io::Result<fs::File> {
    let create = || {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
    };
    match create() {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(tmp)?;
            create()
        }
        file => file,
    }
}

/// Write `bytes` to `tmp` and rename it over `path`. The rename replaces
/// `path` whatever it is, without following it.
fn write_and_rename(tmp: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_temporary(tmp)?;
    // World-readable whatever the daemon's umask is, as `/etc/hostname` is
    // expected to be.
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)
}

/// Replace `path` with a file holding `bytes`, creating its directory when
/// there is none, and put the result on disk with `sync` ([`sync_entry`]; a
/// parameter so that a test can make it fail).
///
/// The rename, and a directory created for it, are on disk only once the
/// directories holding their entries are, so a failure of `sync` fails the
/// write: the caller must not go on as if the file could not be lost. The
/// new content is then in view all the same, and [`sync_path`] is how a
/// rerun makes sure of it.
fn write_atomic(
    path: &Path,
    bytes: &[u8],
    sync: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = temporary(path);
    let written = write_and_rename(&tmp, path, bytes);
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written?;
    sync(path)
}

/// Rewrite the file at `path`, which exists: a mount point does. It is a
/// file and not a symbolic link, and a link is not followed.
fn write_in_place(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Why the stand-in directory `dir` is not used, if it is not: it exists
/// and is not a directory of this user's own. A symbolic link is not
/// followed to wherever its maker pointed it, and a directory that belongs
/// to somebody else is theirs to fill with links. One that does not exist
/// yet is created by the first write, as this user's.
///
/// This looks at the directory, not at the path leading to it: it cannot
/// make a badly chosen place safe (see [`STUB_ENV`]).
fn stand_in_refusal(dir: &Path) -> Option<String> {
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => return Some(format!("{STUB_ENV}: {}: {e}", dir.display())),
    };
    if !meta.is_dir() {
        return Some(format!("{STUB_ENV}: {} is not a directory", dir.display()));
    }
    (meta.uid() != nix::unistd::geteuid().as_raw())
        .then(|| format!("{STUB_ENV}: {} belongs to another user", dir.display()))
}

/// Where this process's network namespace stands against PID 1's.
#[derive(Debug, PartialEq, Eq)]
enum Netns {
    /// The same: the box's own daemon, or its container's.
    Default,
    /// Another: started by `ip netns exec`.
    Other,
    /// Unreadable, as PID 1's is without root.
    Unknown,
}

/// Compare the `/proc/<pid>/ns/net` link texts of this process (`own`) and
/// of PID 1 (`init`).
fn netns(own: Option<&str>, init: Option<&str>) -> Netns {
    match (own, init) {
        (Some(own), Some(init)) if own == init => Netns::Default,
        (Some(_), Some(_)) => Netns::Other,
        _ => Netns::Unknown,
    }
}

fn namespace_link(path: &str) -> Option<String> {
    fs::read_link(path)
        .ok()
        .map(|link| link.to_string_lossy().into_owned())
}

/// The RIB task's hold on the system's host name, present only with
/// `--feature insomnia`.
#[derive(Debug)]
pub struct SystemHostname {
    /// The system to write to, or why this instance never does.
    store: Result<Store, String>,
    /// Why the last [`Self::sync`] failed, until one succeeds.
    error: Option<String>,
}

impl SystemHostname {
    /// For this process: the stand-in when the environment names one,
    /// otherwise the real system, and that only from the default network
    /// namespace.
    pub fn from_env() -> Self {
        let store = match std::env::var_os(STUB_ENV).filter(|dir| !dir.is_empty()) {
            Some(dir) => match stand_in_refusal(Path::new(&dir)) {
                Some(reason) => Err(reason),
                None => Ok(Store::stub(Path::new(&dir))),
            },
            None => match netns(
                namespace_link("/proc/self/ns/net").as_deref(),
                namespace_link("/proc/1/ns/net").as_deref(),
            ) {
                Netns::Default => Ok(Store::system()),
                Netns::Other => Err("zebra-rs is not in the default network namespace".to_string()),
                Netns::Unknown => Err(
                    "zebra-rs cannot tell whether it is in the default network namespace \
                     (it is not root)"
                        .to_string(),
                ),
            },
        };
        if let Err(reason) = &store {
            tracing::info!("system hostname is not applied to the system: {reason}");
        }
        Self::new(store)
    }

    fn new(store: Result<Store, String>) -> Self {
        Self { store, error: None }
    }

    /// Whether this instance writes the system's name at all.
    pub fn managed(&self) -> bool {
        self.store.is_ok()
    }

    /// Whether the last [`Self::sync`] failed, so that the next commit
    /// tries again though it does not touch the name.
    pub fn failed(&self) -> bool {
        self.error.is_some()
    }

    /// The system's name as this instance reads it, for `show hostname`.
    pub fn os_name(&self) -> Option<String> {
        self.store.as_ref().ok()?.kernel().ok()
    }

    /// Make the system's name the running config's (`wanted`), or give the
    /// saved one back when the config has none.
    pub fn sync(&mut self, wanted: Option<&str>) {
        let Ok(store) = &mut self.store else {
            return;
        };
        // A startup config may carry a name an earlier release took
        // (`config::check::startup_tolerant_check`): it stays a label, and
        // the system keeps the name it has.
        let result = match wanted.map(valid) {
            Some(Err(e)) => Err(format!(
                "\"{}\" is not a system host name: {e}",
                wanted.unwrap_or_default()
            )),
            _ => reconcile(store, wanted),
        };
        match result {
            Ok(changed) => {
                self.error = None;
                match wanted {
                    Some(name) if changed => {
                        tracing::info!("system hostname: the system's host name is {name}");
                    }
                    None if changed => {
                        tracing::info!("system hostname: the system's host name is restored");
                    }
                    _ => {}
                }
            }
            Err(e) => {
                // A commit retries while this stands; say it once.
                if self.error.as_deref() != Some(e.as_str()) {
                    tracing::error!("system hostname: not applied to the system: {e}");
                }
                self.error = Some(e);
            }
        }
    }

    /// Why the system's name is not the running config's (`wanted`), for
    /// `show hostname`. `None` when it is, and when this instance has
    /// nothing to apply.
    pub fn reason(&self, wanted: Option<&str>) -> Option<String> {
        let store = match &self.store {
            Ok(store) => store,
            Err(reason) => return wanted.map(|_| reason.clone()),
        };
        if let Some(error) = &self.error {
            return Some(error.clone());
        }
        let wanted = wanted?;
        // Applied, and changed since by somebody else.
        let os = store.kernel().ok()?;
        (os != wanted).then(|| format!("the system's host name is {os}"))
    }
}

#[cfg(test)]
impl SystemHostname {
    /// On the stand-in in `dir`, as `ZEBRA_HOSTNAME_STUB_DIR` selects it.
    pub fn stub(dir: &Path) -> Self {
        Self::new(Ok(Store::stub(dir)))
    }

    /// One the namespace rule turned away.
    pub fn refused(reason: &str) -> Self {
        Self::new(Err(reason.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_kernel_takes() {
        for name in [
            "r1",
            "R1",
            "9",
            "pe1-core",
            "r1.example.com",
            "a-b.c-d.e",
            &"a".repeat(63),
            &format!("{}.{}", "a".repeat(32), "b".repeat(31)),
        ] {
            assert_eq!(valid(name), Ok(()), "{name}");
        }
    }

    #[test]
    fn names_that_are_not_host_names() {
        for name in [
            "",
            "r1.",
            ".r1",
            "r1..x",
            "r1-",
            "-r1",
            "r1.-x",
            "r1-.x",
            "r_1",
            "r 1",
            "r1\n",
            "ルータ",
            // 65 characters in two legal labels: the kernel's limit.
            &format!("{}.{}", "a".repeat(32), "b".repeat(32)),
            // One label of 64.
            &"a".repeat(64),
        ] {
            assert!(valid(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn the_length_error_gives_the_length() {
        let error = valid(&"a.".repeat(40)).unwrap_err();
        assert!(error.contains("64") && error.contains("80"), "{error}");
    }

    #[test]
    fn only_pid_ones_namespace_is_the_default() {
        assert_eq!(
            netns(Some("net:[4026531840]"), Some("net:[4026531840]")),
            Netns::Default
        );
        assert_eq!(
            netns(Some("net:[4026532665]"), Some("net:[4026531840]")),
            Netns::Other
        );
        // PID 1's link cannot be read without root, and neither exists
        // where there is no /proc.
        assert_eq!(netns(Some("net:[4026531840]"), None), Netns::Unknown);
        assert_eq!(netns(None, Some("net:[4026531840]")), Netns::Unknown);
        assert_eq!(netns(None, None), Netns::Unknown);
    }

    /// The system in memory, with what a power failure would leave of it:
    /// `disk_static` and `disk_saved` follow `static_name` and `saved` only
    /// when a write, or a sync, reaches the disk.
    ///
    /// A write can go wrong in two ways. With `fail_at` the n-th write (from
    /// 0) and every later one fail and change nothing, standing for a crash
    /// at that point. With `unsynced_at` the n-th write is made, and seen
    /// from then on, but does not reach the disk and says so; every later
    /// write fails like a crash.
    ///
    /// It also holds [`reconcile`] to the two rules its order exists for,
    /// and panics when one is broken: the system's name is written only
    /// while the record is on disk, and the record is removed only once the
    /// restored name is.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Fake {
        kernel: String,
        static_name: Option<String>,
        saved: Option<Saved>,
        disk_static: Option<String>,
        disk_saved: Option<Saved>,
        writes: usize,
        fail_at: Option<usize>,
        unsynced_at: Option<usize>,
        /// `sync_static` fails.
        static_sync_fails: bool,
        /// `sync_saved` fails.
        saved_sync_fails: bool,
    }

    /// How far a write of the [`Fake`] got.
    enum Written {
        OnDisk,
        InViewOnly,
    }

    impl Fake {
        fn new(static_name: Option<&str>, kernel: &str) -> Self {
            Self {
                kernel: kernel.to_string(),
                static_name: static_name.map(str::to_string),
                saved: None,
                disk_static: static_name.map(str::to_string),
                disk_saved: None,
                writes: 0,
                fail_at: None,
                unsynced_at: None,
                static_sync_fails: false,
                saved_sync_fails: false,
            }
        }

        fn write(&mut self) -> Result<Written, String> {
            let n = self.writes;
            self.writes += 1;
            if self.unsynced_at == Some(n) {
                return Ok(Written::InViewOnly);
            }
            let crashed =
                self.fail_at.is_some_and(|at| n >= at) || self.unsynced_at.is_some_and(|at| n > at);
            if crashed {
                Err(format!("write {n} failed"))
            } else {
                Ok(Written::OnDisk)
            }
        }

        /// The first rule: a power failure now must not leave the new name
        /// without the record of the one found.
        fn record_is_on_disk(&self) {
            assert!(
                self.saved.is_some() && self.disk_saved == self.saved,
                "the system's name is written while the record is not on disk: {self:?}"
            );
        }

        /// What the system holds, without the bookkeeping.
        fn state(&self) -> (Option<&str>, &str, Option<&Saved>) {
            (
                self.static_name.as_deref(),
                self.kernel.as_str(),
                self.saved.as_ref(),
            )
        }

        /// What is on disk.
        fn disk(&self) -> (Option<&str>, Option<&Saved>) {
            (self.disk_static.as_deref(), self.disk_saved.as_ref())
        }

        /// The same system once the fault is over: the process restarted,
        /// or the next commit trying again.
        fn healed(&self) -> Fake {
            Fake {
                fail_at: None,
                unsynced_at: None,
                static_sync_fails: false,
                saved_sync_fails: false,
                ..self.clone()
            }
        }

        /// What a start finds after a power failure: what was on disk, and
        /// the kernel name a boot makes of it (`boot_kernel` when there is
        /// no static name).
        fn power_failure(&self, boot_kernel: &str) -> Fake {
            Fake {
                kernel: self
                    .disk_static
                    .clone()
                    .unwrap_or_else(|| boot_kernel.to_string()),
                static_name: self.disk_static.clone(),
                saved: self.disk_saved.clone(),
                writes: 0,
                ..self.healed()
            }
        }
    }

    impl Backend for Fake {
        fn kernel(&self) -> Result<String, String> {
            Ok(self.kernel.clone())
        }
        fn set_kernel(&mut self, name: &str) -> Result<(), String> {
            self.record_is_on_disk();
            match self.write()? {
                Written::OnDisk => {
                    self.kernel = name.to_string();
                    Ok(())
                }
                // The kernel's name has no disk to miss: a fault here is
                // the call not being made.
                Written::InViewOnly => Err("sethostname failed".to_string()),
            }
        }
        fn static_name(&self) -> Result<Option<String>, String> {
            Ok(self.static_name.clone())
        }
        fn set_static(&mut self, name: Option<&str>) -> Result<(), String> {
            self.record_is_on_disk();
            let written = self.write()?;
            self.static_name = name.map(str::to_string);
            match written {
                Written::OnDisk => {
                    self.disk_static = self.static_name.clone();
                    Ok(())
                }
                Written::InViewOnly => Err("the static name is not on disk".to_string()),
            }
        }
        fn sync_static(&mut self) -> Result<(), String> {
            if self.static_sync_fails {
                return Err("the static name cannot be synced".to_string());
            }
            self.disk_static = self.static_name.clone();
            Ok(())
        }
        fn saved(&self) -> Result<Option<Saved>, String> {
            Ok(self.saved.clone())
        }
        fn set_saved(&mut self, saved: Option<&Saved>) -> Result<(), String> {
            if saved.is_none() {
                // The second rule: a power failure now must not bring
                // zebra-rs's name back with nothing left to undo it.
                assert_eq!(
                    self.disk_static, self.static_name,
                    "the record is removed while the restored name is not on disk"
                );
            }
            let written = self.write()?;
            self.saved = saved.cloned();
            match written {
                Written::OnDisk => {
                    self.disk_saved = self.saved.clone();
                    Ok(())
                }
                Written::InViewOnly => Err("the record is not on disk".to_string()),
            }
        }
        fn sync_saved(&mut self) -> Result<(), String> {
            if self.saved_sync_fails {
                return Err("the record cannot be synced".to_string());
            }
            self.disk_saved = self.saved.clone();
            Ok(())
        }
    }

    fn saved(static_name: Option<&str>, kernel: &str) -> Saved {
        Saved {
            static_name: static_name.map(str::to_string),
            kernel: kernel.to_string(),
        }
    }

    #[test]
    fn the_first_name_saves_what_was_there() {
        let mut system = Fake::new(Some("debian"), "debian");
        assert_eq!(reconcile(&mut system, Some("r1")), Ok(true));
        let record = saved(Some("debian"), "debian");
        assert_eq!(system.state(), (Some("r1"), "r1", Some(&record)));
    }

    #[test]
    fn a_second_name_keeps_the_first_record() {
        let mut system = Fake::new(Some("debian"), "debian");
        reconcile(&mut system, Some("r1")).unwrap();
        assert_eq!(reconcile(&mut system, Some("r2")), Ok(true));
        // Not `r1`: that was zebra-rs's own, and is not what to give back.
        let record = saved(Some("debian"), "debian");
        assert_eq!(system.state(), (Some("r2"), "r2", Some(&record)));
    }

    #[test]
    fn the_same_name_again_writes_nothing() {
        let mut system = Fake::new(Some("debian"), "debian");
        reconcile(&mut system, Some("r1")).unwrap();
        let writes = system.writes;
        // A restart with an unchanged config.
        assert_eq!(reconcile(&mut system, Some("r1")), Ok(false));
        assert_eq!(system.writes, writes);
    }

    #[test]
    fn deleting_the_name_gives_the_saved_one_back() {
        let mut system = Fake::new(Some("debian"), "debian");
        reconcile(&mut system, Some("r1")).unwrap();
        reconcile(&mut system, Some("r2")).unwrap();
        assert_eq!(reconcile(&mut system, None), Ok(true));
        assert_eq!(system.state(), (Some("debian"), "debian", None));
    }

    #[test]
    fn no_name_and_no_record_touches_nothing() {
        let mut system = Fake::new(Some("debian"), "debian");
        assert_eq!(reconcile(&mut system, None), Ok(false));
        assert_eq!(system.writes, 0);
        assert_eq!(system.state(), (Some("debian"), "debian", None));
    }

    #[test]
    fn a_system_without_a_static_name_gets_its_kernel_name_back() {
        // No /etc/hostname, and a kernel name from somewhere else (DHCP,
        // an image's default).
        let mut system = Fake::new(None, "localhost");
        reconcile(&mut system, Some("r1")).unwrap();
        let record = saved(None, "localhost");
        assert_eq!(system.state(), (Some("r1"), "r1", Some(&record)));
        reconcile(&mut system, None).unwrap();
        // The file is gone again, not left behind empty or as `localhost`.
        assert_eq!(system.state(), (None, "localhost", None));
    }

    #[test]
    fn restoring_prefers_the_static_name_to_the_kernel_one() {
        // A transient kernel name over a static one at takeover: the static
        // name is what a reboot would have given.
        let mut system = Fake::new(Some("debian"), "dhcp-17");
        reconcile(&mut system, Some("r1")).unwrap();
        reconcile(&mut system, None).unwrap();
        assert_eq!(system.state(), (Some("debian"), "debian", None));
    }

    #[test]
    fn a_name_the_system_already_has_is_still_taken_over() {
        let mut system = Fake::new(Some("r1"), "r1");
        // Only the record is written.
        assert_eq!(reconcile(&mut system, Some("r1")), Ok(true));
        assert_eq!(system.writes, 1);
        reconcile(&mut system, Some("r2")).unwrap();
        reconcile(&mut system, None).unwrap();
        assert_eq!(system.state(), (Some("r1"), "r1", None));
    }

    /// How one write of a run goes wrong (see [`Fake`]).
    #[derive(Debug, Clone, Copy)]
    enum Fault {
        Crash,
        Unsynced,
    }

    const FAULTS: [Fault; 2] = [Fault::Crash, Fault::Unsynced];

    /// `start`, with `fault` at the `at`-th write from now.
    fn faulty(start: &Fake, fault: Fault, at: usize) -> Fake {
        let mut system = start.clone();
        match fault {
            Fault::Crash => system.fail_at = Some(start.writes + at),
            Fault::Unsynced => system.unsynced_at = Some(start.writes + at),
        }
        system
    }

    /// The writes `reconcile(wanted)` makes on `start`.
    fn writes_of(start: &Fake, wanted: Option<&str>) -> usize {
        let mut clean = start.clone();
        reconcile(&mut clean, wanted).unwrap();
        clean.writes - start.writes
    }

    /// Run `reconcile(wanted)` on `start` with each fault at every write in
    /// turn, then once more without one, and return the state reached each
    /// time: all must be what an uninterrupted run reaches, and on disk.
    fn crash_everywhere(start: &Fake, wanted: Option<&str>) -> Fake {
        let mut clean = start.clone();
        reconcile(&mut clean, wanted).unwrap();
        let writes = writes_of(start, wanted);
        assert!(writes > 0, "nothing to interrupt");
        for at in 0..writes {
            for fault in FAULTS {
                let mut system = faulty(start, fault, at);
                assert!(reconcile(&mut system, wanted).is_err(), "{fault:?} at {at}");
                // The name found is never lost, wherever the fault is.
                if wanted.is_some() && at > 0 {
                    assert_eq!(system.saved, clean.saved, "{fault:?} at {at}");
                }
                let mut system = system.healed();
                reconcile(&mut system, wanted).unwrap();
                assert_eq!(system.state(), clean.state(), "{fault:?} at {at}");
                // A write that was in view only is not left that way.
                assert_eq!(
                    system.disk(),
                    (system.static_name.as_deref(), system.saved.as_ref()),
                    "{fault:?} at {at}"
                );
            }
        }
        clean
    }

    #[test]
    fn a_crash_while_applying_is_finished_by_the_next_run() {
        let start = Fake::new(Some("debian"), "debian");
        let applied = crash_everywhere(&start, Some("r1"));
        let record = saved(Some("debian"), "debian");
        assert_eq!(applied.state(), (Some("r1"), "r1", Some(&record)));
        // And a change of name, with the record in place.
        let renamed = crash_everywhere(&applied, Some("r2"));
        assert_eq!(renamed.state(), (Some("r2"), "r2", Some(&record)));
    }

    #[test]
    fn a_crash_while_restoring_is_finished_by_the_next_run() {
        let mut applied = Fake::new(Some("debian"), "debian");
        reconcile(&mut applied, Some("r1")).unwrap();
        let restored = crash_everywhere(&applied, None);
        assert_eq!(restored.state(), (Some("debian"), "debian", None));

        // The same with a file to remove rather than rewrite.
        let mut applied = Fake::new(None, "localhost");
        reconcile(&mut applied, Some("r1")).unwrap();
        let restored = crash_everywhere(&applied, None);
        assert_eq!(restored.state(), (None, "localhost", None));
    }

    #[test]
    fn the_record_outlives_a_crash_between_restoring_and_removing_it() {
        let mut system = Fake::new(Some("debian"), "debian");
        reconcile(&mut system, Some("r1")).unwrap();
        // File and kernel restored, the record's removal lost.
        system.fail_at = Some(system.writes + 2);
        assert!(reconcile(&mut system, None).is_err());
        let record = saved(Some("debian"), "debian");
        assert_eq!(system.state(), (Some("debian"), "debian", Some(&record)));
        // A name configured again now saves nothing new.
        system.fail_at = None;
        reconcile(&mut system, Some("r3")).unwrap();
        assert_eq!(system.state(), (Some("r3"), "r3", Some(&record)));
    }

    /// What the order of the writes and the syncs are for. Whatever goes
    /// wrong at whichever write, and whether the power then fails at once
    /// or after the rerun, the disk never holds a name of zebra-rs's without
    /// the record of the one found, and the delete that follows gives that
    /// one back: not zebra-rs's own, and not nothing.
    #[test]
    fn no_fault_or_power_failure_loses_the_name_found() {
        for (found_static, found_kernel) in [(Some("debian"), "debian"), (None, "localhost")] {
            let found = saved(found_static, found_kernel);
            let given_back = (found_static, found_static.unwrap_or(found_kernel), None);
            let fresh = Fake::new(found_static, found_kernel);
            let mut applied = fresh.clone();
            reconcile(&mut applied, Some("r1")).unwrap();

            for (start, wanted) in [
                (&fresh, Some("r1")),
                (&applied, Some("r2")),
                (&applied, None),
            ] {
                for at in 0..writes_of(start, wanted) {
                    for fault in FAULTS {
                        for rerun in [false, true] {
                            let case = format!(
                                "found {found:?}, {wanted:?}, {fault:?} at {at}, rerun {rerun}"
                            );
                            let mut system = faulty(start, fault, at);
                            let _ = reconcile(&mut system, wanted);
                            let mut system = system.healed();
                            if rerun {
                                reconcile(&mut system, wanted).unwrap();
                            }

                            let booted = system.power_failure(found_kernel);
                            match &booted.saved {
                                Some(record) => assert_eq!(record, &found, "{case}"),
                                None => {
                                    assert_eq!(
                                        booted.static_name.as_deref(),
                                        found_static,
                                        "{case}"
                                    )
                                }
                            }

                            // The config still has the name at that start,
                            // and loses it later; or has lost it already.
                            for still_configured in [true, false] {
                                let mut system = booted.clone();
                                if still_configured && wanted.is_some() {
                                    reconcile(&mut system, wanted).unwrap();
                                }
                                reconcile(&mut system, None).unwrap();
                                assert_eq!(system.state(), given_back, "{case}");
                            }
                        }
                    }
                }
            }
        }
    }

    /// The record is written, in view, and its sync fails: the name it
    /// holds is not overwritten, at that attempt or at the next ones, until
    /// the record is on disk.
    #[test]
    fn a_record_that_is_not_on_disk_stops_the_name_change() {
        let mut system = faulty(&Fake::new(Some("debian"), "debian"), Fault::Unsynced, 0);
        assert!(reconcile(&mut system, Some("r1")).is_err());
        let record = saved(Some("debian"), "debian");
        assert_eq!(system.state(), (Some("debian"), "debian", Some(&record)));
        assert_eq!(system.disk(), (Some("debian"), None));

        // The retry finds the record in place. That is not enough.
        let mut system = system.healed();
        system.saved_sync_fails = true;
        assert_eq!(
            reconcile(&mut system, Some("r1")),
            Err("the record cannot be synced".to_string())
        );
        assert_eq!(system.state(), (Some("debian"), "debian", Some(&record)));

        system.saved_sync_fails = false;
        assert_eq!(reconcile(&mut system, Some("r1")), Ok(true));
        assert_eq!(system.state(), (Some("r1"), "r1", Some(&record)));
        assert_eq!(system.disk(), (Some("r1"), Some(&record)));
    }

    /// The same when the record is found by a restore that has a name to
    /// write: somebody renamed the system since the takeover failed.
    #[test]
    fn a_record_that_is_not_on_disk_is_synced_before_a_restore() {
        let mut system = faulty(&Fake::new(Some("debian"), "debian"), Fault::Unsynced, 0);
        assert!(reconcile(&mut system, Some("r1")).is_err());
        let mut system = system.healed();
        system.static_name = Some("other".to_string());
        system.disk_static = system.static_name.clone();
        system.kernel = "other".to_string();
        // The fake panics if `debian` is written before the record is on
        // disk.
        assert_eq!(reconcile(&mut system, None), Ok(true));
        assert_eq!(system.state(), (Some("debian"), "debian", None));
    }

    /// The restored name is written, in view, and its sync fails: the
    /// record stays, and the retry removes it only once the name is on
    /// disk. Otherwise a power failure brings zebra-rs's name back with
    /// nothing left that knows the one before it.
    #[test]
    fn a_restored_name_that_is_not_on_disk_keeps_the_record() {
        let mut applied = Fake::new(Some("debian"), "debian");
        reconcile(&mut applied, Some("r1")).unwrap();
        let record = saved(Some("debian"), "debian");

        let mut system = faulty(&applied, Fault::Unsynced, 0);
        assert!(reconcile(&mut system, None).is_err());
        assert_eq!(system.state(), (Some("debian"), "r1", Some(&record)));
        assert_eq!(system.disk(), (Some("r1"), Some(&record)));

        let mut system = system.healed();
        system.static_sync_fails = true;
        assert_eq!(
            reconcile(&mut system, None),
            Err("the static name cannot be synced".to_string())
        );
        assert_eq!(system.saved.as_ref(), Some(&record));

        system.static_sync_fails = false;
        assert_eq!(reconcile(&mut system, None), Ok(true));
        assert_eq!(system.state(), (Some("debian"), "debian", None));
        assert_eq!(system.disk(), (Some("debian"), None));
    }

    /// A restart with nothing to change still leaves what it found on disk,
    /// and fails when it cannot: the last run may have been cut short
    /// between a write and its sync.
    #[test]
    fn a_run_with_nothing_to_write_syncs_what_is_there() {
        let mut system = Fake::new(Some("debian"), "debian");
        reconcile(&mut system, Some("r1")).unwrap();
        // As a kill between the rename and the directory's sync leaves it.
        system.disk_static = Some("debian".to_string());
        system.disk_saved = None;
        let writes = system.writes;
        assert_eq!(reconcile(&mut system, Some("r1")), Ok(false));
        assert_eq!(system.writes, writes);
        let record = saved(Some("debian"), "debian");
        assert_eq!(system.disk(), (Some("r1"), Some(&record)));

        for (static_sync_fails, saved_sync_fails) in [(true, false), (false, true)] {
            let mut system = system.clone();
            system.static_sync_fails = static_sync_fails;
            system.saved_sync_fails = saved_sync_fails;
            assert!(reconcile(&mut system, Some("r1")).is_err());
        }
    }

    /// The record's removal is in view and its sync fails: the retry finds
    /// no record, and still puts the removal on disk. A record that came
    /// back with the power would be "restored" over whatever the system has
    /// been called since.
    #[test]
    fn a_removal_that_is_not_on_disk_is_synced_by_the_next_run() {
        let mut applied = Fake::new(Some("debian"), "debian");
        reconcile(&mut applied, Some("r1")).unwrap();
        let record = saved(Some("debian"), "debian");

        // Static name, kernel name, and then the removal.
        let mut system = faulty(&applied, Fault::Unsynced, 2);
        assert!(reconcile(&mut system, None).is_err());
        assert_eq!(system.state(), (Some("debian"), "debian", None));
        assert_eq!(system.disk(), (Some("debian"), Some(&record)));

        let mut system = system.healed();
        system.saved_sync_fails = true;
        assert!(reconcile(&mut system, None).is_err());
        system.saved_sync_fails = false;
        assert_eq!(reconcile(&mut system, None), Ok(false));
        assert_eq!(system.disk(), (Some("debian"), None));
    }

    /// A stand-in under a fresh temporary directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("zebra-rs-hostname-{}-{test}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            Self(dir)
        }

        fn store(&self) -> Store {
            Store::stub(&self.0)
        }

        fn read(&self, file: &str) -> Option<String> {
            fs::read_to_string(self.0.join(file)).ok()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_stand_in_keeps_everything_in_its_directory() {
        let scratch = Scratch::new("stand-in");
        let mut store = scratch.store();
        // Nothing there yet: no static name, and the default kernel name.
        assert_eq!(store.static_name(), Ok(None));
        assert_eq!(store.kernel(), Ok("localhost".to_string()));
        assert_eq!(store.saved(), Ok(None));

        assert_eq!(reconcile(&mut store, Some("r1")), Ok(true));
        assert_eq!(scratch.read("hostname").as_deref(), Some("r1\n"));
        assert_eq!(scratch.read("kernel").as_deref(), Some("r1\n"));
        assert_eq!(
            scratch.read("saved.json").as_deref(),
            Some("{\"static\":null,\"kernel\":\"localhost\"}\n")
        );
        // No temporary file is left beside them.
        let mut files: Vec<_> = fs::read_dir(&scratch.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        files.sort();
        assert_eq!(files, ["hostname", "kernel", "saved.json"]);

        // A second store on the directory is a restarted daemon.
        let mut store = scratch.store();
        assert_eq!(reconcile(&mut store, Some("r1")), Ok(false));
        assert_eq!(reconcile(&mut store, None), Ok(true));
        assert_eq!(scratch.read("hostname"), None);
        assert_eq!(scratch.read("kernel").as_deref(), Some("localhost\n"));
        assert_eq!(scratch.read("saved.json"), None);
    }

    #[test]
    fn a_static_name_file_is_read_as_systemd_reads_it() {
        let scratch = Scratch::new("read");
        fs::create_dir_all(&scratch.0).unwrap();
        let path = scratch.0.join("hostname");
        for (content, name) in [
            ("debian\n", Some("debian")),
            ("debian", Some("debian")),
            (
                "# set by the installer\n\n  debian  \nother\n",
                Some("debian"),
            ),
            ("", None),
            ("\n# nothing\n", None),
        ] {
            fs::write(&path, content).unwrap();
            assert_eq!(read_name(&path).unwrap().as_deref(), name, "{content:?}");
        }
        // A file that already says the name, in whatever spelling, is not
        // rewritten.
        fs::write(&path, "# mine\nr1").unwrap();
        fs::write(
            scratch.0.join("saved.json"),
            "{\"static\":\"r1\",\"kernel\":\"r1\"}",
        )
        .unwrap();
        fs::write(scratch.0.join("kernel"), "r1\n").unwrap();
        assert_eq!(reconcile(&mut scratch.store(), Some("r1")), Ok(false));
        assert_eq!(scratch.read("hostname").as_deref(), Some("# mine\nr1"));
    }

    #[test]
    fn a_written_file_is_world_readable() {
        let scratch = Scratch::new("mode");
        let path = scratch.0.join("hostname");
        replace(&path, b"r1\n").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn a_mount_point_is_written_in_place() {
        let scratch = Scratch::new("in-place");
        fs::create_dir_all(&scratch.0).unwrap();
        let path = scratch.0.join("hostname");
        // Only EBUSY, what rename and unlink say of a mount point, falls
        // back: any other failure must leave the old content alone.
        assert!(is_mount_point(&io::Error::from_raw_os_error(libc::EBUSY)));
        assert!(!is_mount_point(&io::Error::from_raw_os_error(libc::ENOSPC)));
        assert!(!is_mount_point(&io::Error::from_raw_os_error(libc::EACCES)));

        fs::write(&path, "a-longer-name\n").unwrap();
        write_in_place(&path, b"r1\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "r1\n");
        // It does not create one: a mount point exists.
        let absent = scratch.0.join("absent");
        assert!(write_in_place(&absent, b"r1\n").is_err());
        assert!(!absent.exists());
    }

    #[test]
    fn a_failed_write_leaves_the_old_content_and_no_temporary_file() {
        let scratch = Scratch::new("failed");
        fs::create_dir_all(&scratch.0).unwrap();
        // The path is a directory: the rename over it fails.
        let path = scratch.0.join("hostname");
        fs::create_dir(&path).unwrap();
        assert!(replace(&path, b"r1\n").is_err());
        assert!(path.is_dir());
        assert!(!temporary(&path).exists());
    }

    /// A write is not done until the directories holding its entry are
    /// synced: a failure there is the write's, though the content is in
    /// place, because the caller goes on to overwrite the name the record
    /// holds.
    #[test]
    fn a_directory_that_cannot_be_synced_fails_the_write() {
        let scratch = Scratch::new("sync-fails");
        let path = scratch.0.join("saved.json");
        let eio = || io::Error::from_raw_os_error(libc::EIO);

        let result = write_atomic(&path, b"{}\n", |synced| {
            // Asked for this path, and after the rename.
            assert_eq!(synced, path);
            assert_eq!(fs::read(&path).unwrap(), b"{}\n");
            Err(eio())
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));

        // A removal is an entry too.
        let result = remove(&path, |synced| {
            assert_eq!(synced, path);
            assert!(!path.exists());
            Err(eio())
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
        // Nothing was removed, so there is nothing to sync.
        remove(&path, |_| panic!("synced a removal that did not happen")).unwrap();
    }

    #[test]
    fn every_directory_leading_to_a_path_is_synced() {
        let dirs = |path: &str| -> Vec<String> {
            directories(Path::new(path))
                .map(|dir| dir.to_str().unwrap().to_string())
                .collect()
        };
        // Not only the nearest: `system`, and `zebra-rs` on a fresh install,
        // are created by the write itself, and an entry is no safer than the
        // ones leading to it.
        assert_eq!(
            dirs("/var/lib/zebra-rs/system/hostname.json"),
            [
                "/var/lib/zebra-rs/system",
                "/var/lib/zebra-rs",
                "/var/lib",
                "/var",
                "/"
            ]
        );
        assert_eq!(dirs("/etc/hostname"), ["/etc", "/"]);
        assert_eq!(dirs("stub/kernel"), ["stub", "."]);
        assert_eq!(dirs("kernel"), ["."]);

        // For real, through two directories the write creates.
        let scratch = Scratch::new("new-dirs");
        let path = scratch.0.join("system").join("hostname.json");
        replace(&path, b"{}\n").unwrap();
        sync_path(&path).unwrap();
        // An absent file's entry is synced as well: a removal.
        sync_path(&scratch.0.join("system").join("absent")).unwrap();
        // And so is one whose directory never existed: what is synced is
        // then the directories above it, which do.
        sync_path(&scratch.0.join("never").join("made").join("absent")).unwrap();
        assert!(!scratch.0.join("never").exists());
        remove(&path, sync_entry).unwrap();
        // A directory that is not there cannot be synced, and that is an
        // error, not something to pass over.
        assert!(sync_entry(&scratch.0.join("missing").join("file")).is_err());
    }

    #[test]
    fn only_a_filesystem_that_cannot_sync_is_excused() {
        let failed = |errno| excusing_unsupported(Err(io::Error::from_raw_os_error(errno)));
        assert!(excusing_unsupported(Ok(())).is_ok());
        assert!(failed(libc::EINVAL).is_ok());
        assert!(failed(libc::ENOTSUP).is_ok());
        for errno in [
            libc::EIO,
            libc::ENOSPC,
            libc::EDQUOT,
            libc::EROFS,
            libc::EACCES,
        ] {
            assert_eq!(failed(errno).unwrap_err().raw_os_error(), Some(errno));
        }
    }

    /// The store's syncs go to the disk, and report what they find there.
    #[test]
    fn the_store_syncs_what_it_holds_and_says_when_it_cannot() {
        let scratch = Scratch::new("store-sync");
        let mut store = scratch.store();
        // Nothing there, not even the directory: an absence to sync.
        assert_eq!(store.sync_static(), Ok(()));
        assert_eq!(store.sync_saved(), Ok(()));
        assert!(!scratch.0.exists());

        reconcile(&mut store, Some("r1")).unwrap();
        assert_eq!(store.sync_static(), Ok(()));
        assert_eq!(store.sync_saved(), Ok(()));

        // A stand-in "directory" that is a file: nothing under it can be
        // opened, and that is not mistaken for nothing being there.
        let file = scratch.0.join("kernel");
        let mut store = Store::stub(&file);
        assert!(store.sync_static().is_err());
        assert!(store.sync_saved().is_err());
    }

    /// The temporary file is created, not opened. A symbolic link put
    /// under its name beforehand would otherwise have this process, which
    /// is root in a daemon, write into whatever file the link names.
    #[test]
    fn a_link_under_the_temporary_name_is_not_written_through() {
        let scratch = Scratch::new("tmp-link");
        fs::create_dir_all(&scratch.0).unwrap();
        let path = scratch.0.join("hostname");
        let victim = scratch.0.join("victim");
        fs::write(&victim, "not yours\n").unwrap();
        std::os::unix::fs::symlink(&victim, temporary(&path)).unwrap();

        replace(&path, b"r1\n").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "not yours\n");
        assert_eq!(fs::read_to_string(&path).unwrap(), "r1\n");
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        assert!(fs::symlink_metadata(temporary(&path)).is_err());

        // A file an interrupted run left under the name is no obstacle.
        fs::write(temporary(&path), "half").unwrap();
        replace(&path, b"r2\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "r2\n");

        // The destination being a link is replaced, not followed.
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        replace(&path, b"r3\n").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "not yours\n");
        assert!(fs::symlink_metadata(&path).unwrap().is_file());

        // And the write in place, for a mount point, refuses one.
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(write_in_place(&path, b"r4\n").is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "not yours\n");
    }

    /// The stand-in is where a root daemon writes: a directory that is a
    /// link to somewhere else, or that somebody else owns, is turned away.
    #[test]
    fn a_stand_in_directory_must_be_this_users_own() {
        let scratch = Scratch::new("stand-in-owner");
        // Not there yet: the first write creates it.
        assert_eq!(stand_in_refusal(&scratch.0), None);
        fs::create_dir_all(&scratch.0).unwrap();
        assert_eq!(stand_in_refusal(&scratch.0), None);

        let file = scratch.0.join("file");
        fs::write(&file, "").unwrap();
        let reason = stand_in_refusal(&file).expect("a file");
        assert!(reason.ends_with("is not a directory"), "{reason}");

        // A link to a directory of our own is still not the directory.
        let link = scratch.0.join("link");
        std::os::unix::fs::symlink(&scratch.0, &link).unwrap();
        let reason = stand_in_refusal(&link).expect("a link");
        assert!(reason.ends_with("is not a directory"), "{reason}");

        // Root's directory, unless this test runs as root.
        if !nix::unistd::geteuid().is_root() {
            let reason = stand_in_refusal(Path::new("/")).expect("root's");
            assert!(reason.ends_with("belongs to another user"), "{reason}");
        }
    }

    #[test]
    fn a_record_that_does_not_parse_stops_the_takeover() {
        let scratch = Scratch::new("corrupt");
        fs::create_dir_all(&scratch.0).unwrap();
        fs::write(scratch.0.join("saved.json"), "{").unwrap();
        fs::write(scratch.0.join("hostname"), "debian\n").unwrap();
        let mut store = scratch.store();
        // Not "no record": that would save `r1` as the name to give back at
        // the next takeover.
        assert!(reconcile(&mut store, Some("r1")).is_err());
        assert!(reconcile(&mut store, None).is_err());
        assert_eq!(scratch.read("hostname").as_deref(), Some("debian\n"));
        assert_eq!(scratch.read("kernel"), None);
    }

    #[test]
    fn an_instance_outside_the_default_namespace_does_nothing() {
        let reason = "zebra-rs is not in the default network namespace";
        let mut system = SystemHostname::new(Err(reason.to_string()));
        assert!(!system.managed());
        system.sync(Some("r1"));
        assert!(!system.failed());
        // Said only when there is a name it would have applied.
        assert_eq!(system.reason(Some("r1")).as_deref(), Some(reason));
        assert_eq!(system.reason(None), None);
        assert_eq!(system.os_name(), None);
    }

    #[test]
    fn sync_applies_restores_and_reports() {
        let scratch = Scratch::new("sync");
        let mut system = SystemHostname::new(Ok(scratch.store()));
        assert!(system.managed());
        assert_eq!(system.os_name().as_deref(), Some("localhost"));

        system.sync(Some("r1"));
        assert!(!system.failed());
        assert_eq!(system.reason(Some("r1")), None);
        assert_eq!(system.os_name().as_deref(), Some("r1"));

        // Somebody else renames the system afterwards.
        fs::write(scratch.0.join("kernel"), "other\n").unwrap();
        assert_eq!(
            system.reason(Some("r1")).as_deref(),
            Some("the system's host name is other")
        );
        // The next sync puts it back.
        system.sync(Some("r1"));
        assert_eq!(system.reason(Some("r1")), None);

        system.sync(None);
        assert_eq!(system.reason(None), None);
        assert_eq!(system.os_name().as_deref(), Some("localhost"));
    }

    #[test]
    fn a_name_the_kernel_would_refuse_is_not_applied() {
        let scratch = Scratch::new("invalid");
        let mut system = SystemHostname::new(Ok(scratch.store()));
        system.sync(Some("r1"));
        // What a startup config an earlier release accepted may hold.
        let long = "a".repeat(70);
        system.sync(Some(&long));
        assert!(system.failed());
        let reason = system.reason(Some(&long)).expect("a reason");
        assert!(reason.contains("is not a system host name"), "{reason}");
        // The system keeps the name it had; it is not restored either.
        assert_eq!(scratch.read("hostname").as_deref(), Some("r1\n"));
        assert_eq!(scratch.read("kernel").as_deref(), Some("r1\n"));
        assert!(scratch.read("saved.json").is_some());
        // A good name clears it.
        system.sync(Some("r2"));
        assert!(!system.failed());
        assert_eq!(scratch.read("kernel").as_deref(), Some("r2\n"));
    }

    #[test]
    fn a_failure_is_kept_until_a_sync_succeeds() {
        let scratch = Scratch::new("failure");
        fs::create_dir_all(&scratch.0).unwrap();
        // The static name's path is a directory: it can be neither read
        // nor replaced.
        fs::create_dir(scratch.0.join("hostname")).unwrap();
        let mut system = SystemHostname::new(Ok(scratch.store()));
        system.sync(Some("r1"));
        assert!(system.failed());
        let reason = system.reason(Some("r1")).expect("a reason");
        assert!(reason.contains("hostname"), "{reason}");
        // Fixed by the operator; the next commit's sync goes through.
        fs::remove_dir(scratch.0.join("hostname")).unwrap();
        system.sync(Some("r1"));
        assert!(!system.failed());
        assert_eq!(system.reason(Some("r1")), None);
        assert_eq!(scratch.read("hostname").as_deref(), Some("r1\n"));
    }
}
