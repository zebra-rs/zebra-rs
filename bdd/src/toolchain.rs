//! Which zebra-rs toolchain a BDD run executes.
//!
//! Every daemon and CLI the harness launches inside a namespace used to be
//! resolved by bare name through root's PATH — `/usr/bin/zebra-rs`,
//! `/usr/bin/vtyctl`, `/usr/bin/pfcp-inject` — and the daemon then loaded
//! its schemas from `/usr/share/zebra-rs/yang`. All four are host-global,
//! and `make install` overwrites them. Two git worktrees that each install
//! therefore clobber one another: a run in worktree A silently exercises
//! whichever binary and schema set worktree B installed last, which reads
//! as an inexplicable product regression.
//!
//! A *staged prefix* removes the host from the picture. `make -C bdd stage`
//! builds this worktree's binaries and copies them, together with this
//! worktree's YANG schemas, into a private tree:
//!
//! ```text
//! <worktree>/bdd/.stage/
//!   bin/{zebra-rs,vtyctl,vtyhelper,pfcp-inject}
//!   share/zebra-rs/yang/*.yang
//! ```
//!
//! The harness then prepends `bin/` to PATH for every in-namespace command
//! and points the daemon at `share/zebra-rs/yang` with `--yang-path`, so a
//! run reads nothing under `/usr` at all.
//!
//! Staged binaries are *copies*, not symlinks into `target/`: cargo rewrites
//! `target/release/zebra-rs` in place, so a rebuild in the same worktree
//! would otherwise swap the binary out from under a run already in flight.
//! Copying pins the whole toolchain for the duration.
//!
//! Resolution order:
//!   1. `$ZEBRA_BDD_PREFIX`, if set and non-empty
//!   2. `<bdd crate>/.stage`, if it exists
//!   3. nothing — fall back to the host-global layout, i.e. exactly the
//!      behavior before staging existed, so a bare
//!      `cargo test --test cucumber` still runs.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Staging root for this worktree. Baked at compile time from the `bdd`
/// crate's own directory, so a test binary built in worktree A can never
/// pick up worktree B's stage no matter where it is invoked from.
const STAGE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/.stage");

/// PATH tail appended after the staged `bin/`. Deliberately a fixed list
/// rather than the harness process's own PATH: the commands run as root
/// under `sudo`, which would normally confine them to `secure_path`, and
/// splicing the invoking user's PATH into a root command would both widen
/// that and make resolution differ from machine to machine.
const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Where the cradle-rs package installs the engine.
const PACKAGED_CRADLE: &str = "/usr/bin/cradle";

/// The cradle-rs release zebra-rs pins (the top-level `cradle-version`).
const CRADLE_PIN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../cradle-version"));

/// A resolved staging prefix: binaries under `bin/`, schemas under
/// `share/zebra-rs/yang/`, mirroring the `/usr` layout `make install`
/// writes.
#[derive(Debug, Clone)]
pub struct Prefix {
    root: PathBuf,
}

impl Prefix {
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory holding the staged binaries.
    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// Directory holding the staged YANG schemas, for `--yang-path`.
    pub fn yang_dir(&self) -> PathBuf {
        self.root.join("share/zebra-rs/yang")
    }

    /// `PATH=…` assignment to hand to `env` ahead of an in-namespace
    /// command, so `zebra-rs` / `vtyctl` / `pfcp-inject` resolve to this
    /// worktree's copies while system tools (`ip`, `bridge`, `timeout`)
    /// keep resolving as before.
    pub fn path_env(&self) -> String {
        format!("PATH={}:{}", self.bin_dir().display(), SYSTEM_PATH)
    }
}

/// The staging prefix for this run, or `None` when the harness should use
/// the host-global toolchain.
///
/// Resolved once per process. Panics if a prefix is present but incomplete —
/// a half-populated stage would otherwise silently fall through to `/usr`,
/// which is the failure mode staging exists to prevent.
pub fn prefix() -> Option<&'static Prefix> {
    static PREFIX: OnceLock<Option<Prefix>> = OnceLock::new();
    PREFIX.get_or_init(resolve).as_ref()
}

fn resolve() -> Option<Prefix> {
    if let Ok(raw) = std::env::var("ZEBRA_BDD_PREFIX")
        && !raw.trim().is_empty()
    {
        return Some(check(PathBuf::from(raw.trim()), "$ZEBRA_BDD_PREFIX"));
    }

    let stage = PathBuf::from(STAGE_DIR);
    if !stage.exists() {
        return None;
    }
    Some(check(stage, "the staged toolchain"))
}

/// Reject a prefix that is missing either half. `make stage` builds into a
/// scratch directory and renames it into place, so an incomplete `.stage`
/// means an interrupted or hand-edited stage rather than a race — and the
/// only safe response is to say so instead of quietly testing `/usr`.
fn check(root: PathBuf, what: &str) -> Prefix {
    let prefix = Prefix { root };
    let zebra = prefix.bin_dir().join("zebra-rs");
    let yang = prefix.yang_dir();
    assert!(
        zebra.is_file() && yang.is_dir(),
        "{what} at {} is incomplete (expected {} and {}); re-run `make -C bdd stage`",
        prefix.root.display(),
        zebra.display(),
        yang.display(),
    );
    prefix
}

/// The cradle engine every zebra-rs daemon of this run spawns, passed to
/// each one as `ZEBRA_CRADLE_BIN`.
///
/// Left to itself zebra-rs looks for `$ZEBRA_CRADLE_BIN`, then
/// `$HOME/.zebra/bin/cradle`, then `/usr/bin/cradle` (`resolve_bin` in
/// zebra-rs/src/cradle/supervisor.rs). Under `sudo` HOME is /root, so a
/// forgotten dev copy at `/root/.zebra/bin/cradle` replaces the packaged
/// engine for every daemon in every worktree, silently: one did, for two
/// months, running cradle 0.9.9 against a 1.1.x pin. Passing the variable
/// takes the home directory out of the lookup.
///
/// The invoking environment's `$ZEBRA_CRADLE_BIN` wins, to test a cradle-rs
/// build; otherwise the packaged engine.
pub fn cradle_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| match std::env::var("ZEBRA_CRADLE_BIN") {
        Ok(raw) if !raw.trim().is_empty() => PathBuf::from(raw.trim()),
        _ => PathBuf::from(PACKAGED_CRADLE),
    })
}

/// Description of the resolved toolchain, printed in the run header. A run
/// that fails for a stale-binary reason should be able to prove it from its
/// own log.
pub fn describe() -> String {
    let zebra = match prefix() {
        Some(p) => {
            let zebra = p.bin_dir().join("zebra-rs");
            let size = std::fs::metadata(&zebra).map(|m| m.len()).unwrap_or(0);
            format!(
                "toolchain: staged at {} (zebra-rs {size} bytes)",
                p.root().display()
            )
        }
        None => "toolchain: host-global (/usr/bin, /usr/share/zebra-rs/yang) \
                 — run `make -C bdd stage` to isolate this worktree"
            .to_string(),
    };
    let bin = cradle_bin();
    let version = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());
    format!(
        "{zebra}\n{}",
        cradle_line(bin, version.as_deref(), CRADLE_PIN.trim())
    )
}

/// The run header's cradle line, from the engine's `--version` output
/// (`cradle X.Y.Z`, or `None` when it would not run) and the pinned release.
fn cradle_line(bin: &Path, version: Option<&str>, pin: &str) -> String {
    let Some(version) = version else {
        return format!(
            "cradle: {} does not run — features that start the engine will fail",
            bin.display()
        );
    };
    let release = version.strip_prefix("cradle ").unwrap_or(version);
    if release == pin {
        format!("cradle: {} ({version})", bin.display())
    } else {
        format!(
            "cradle: {} ({version}) — WARNING: zebra-rs pins {pin} (`cradle-version`)",
            bin.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_mirrors_the_usr_layout() {
        let p = Prefix {
            root: PathBuf::from("/w/bdd/.stage"),
        };
        assert_eq!(p.bin_dir(), PathBuf::from("/w/bdd/.stage/bin"));
        assert_eq!(
            p.yang_dir(),
            PathBuf::from("/w/bdd/.stage/share/zebra-rs/yang")
        );
    }

    #[test]
    fn cradle_line_names_the_engine_and_flags_a_pin_mismatch() {
        let bin = Path::new("/usr/bin/cradle");
        assert_eq!(
            cradle_line(bin, Some("cradle 1.1.3"), "1.1.3"),
            "cradle: /usr/bin/cradle (cradle 1.1.3)"
        );
        assert_eq!(
            cradle_line(bin, Some("cradle 0.9.9"), "1.1.3"),
            "cradle: /usr/bin/cradle (cradle 0.9.9) — WARNING: zebra-rs pins 1.1.3 (`cradle-version`)"
        );
        assert!(cradle_line(bin, None, "1.1.3").contains("does not run"));
    }

    #[test]
    fn the_pin_is_a_release_number() {
        let pin = CRADLE_PIN.trim();
        assert!(
            !pin.is_empty() && pin.split('.').all(|n| n.parse::<u32>().is_ok()),
            "cradle-version should hold X.Y.Z, got {pin:?}"
        );
    }

    #[test]
    fn path_env_puts_the_stage_first() {
        let p = Prefix {
            root: PathBuf::from("/w/bdd/.stage"),
        };
        assert_eq!(
            p.path_env(),
            format!("PATH=/w/bdd/.stage/bin:{}", SYSTEM_PATH)
        );
    }
}
