//! Runtime tracing configuration for the config subsystem itself.
//!
//! Backs the `system tracing { config {...} }` block defined in
//! `zebra-rib-tracing.yang` (the module that owns the whole
//! `system tracing` tree). The RIB / FIB categories in that tree are
//! applied by the RIB task when the committed paths reach it over its
//! subscriber channel; the config manager's own categories cannot take
//! that route — the startup summary this block gates is emitted right
//! after `commit_config` returns, so a channel dispatch would race it.
//! Instead [`ConfigManager::commit_config`] applies `system tracing`
//! lines here synchronously, while walking the commit diff. That is
//! what makes the bootstrap case work: a toggle carried in the startup
//! config file is live before the summary describing that very file's
//! application is (or is not) logged.
//!
//! Same storage model as `rib::tracing`: one process-global block of
//! atomics, lock-free `Relaxed` reads, written only at commit.
//!
//! [`ConfigManager::commit_config`]: super::ConfigManager::commit_config

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use super::ConfigOp;

struct State {
    /// The `system tracing all` master switch — the same leaf the RIB /
    /// FIB block honors; mirrored here so `all` covers the config
    /// categories too.
    all: AtomicBool,

    /// `system tracing config startup` — the startup-config apply
    /// summary (`applied N of M commands`).
    startup: AtomicBool,

    /// `system tracing config vty` — VTY session lifecycle and RPC
    /// events (session create / remove, enable / disable, per-RPC
    /// accept, GC sweeps). These are recurring runtime events, so the
    /// ordinary commit path is early enough — no bootstrap subtlety
    /// like `startup`'s. The one-shot `serve()` setup notices are NOT
    /// here: they fire before the startup config is loaded, so they
    /// log at debug level instead of consulting a toggle no config
    /// could have set yet.
    vty: AtomicBool,
}

impl State {
    const fn new() -> Self {
        State {
            all: AtomicBool::new(false),
            startup: AtomicBool::new(false),
            vty: AtomicBool::new(false),
        }
    }

    /// A category is on when its own toggle is set, or the `all` master
    /// switch is.
    fn on(&self, flag: &AtomicBool) -> bool {
        self.all.load(Relaxed) || flag.load(Relaxed)
    }

    /// Apply one committed config line. The manager hands over every
    /// `system tracing …` diff line; the RIB / FIB category lines fall
    /// through the match untouched (the RIB task owns those), so a miss
    /// here is expected, not an error.
    fn apply(&self, line: &str, op: ConfigOp) {
        let set = op.is_set();
        match line {
            "system tracing all" => self.all.store(set, Relaxed),
            "system tracing config startup" => self.startup.store(set, Relaxed),
            "system tracing config vty" => self.vty.store(set, Relaxed),
            _ => {}
        }
    }
}

static STATE: State = State::new();

/// Apply a committed `system tracing …` Set/Delete line, in CLI-line
/// form (the same flat rendering `commit_config` diffs). Called from
/// the manager's commit loop; lines outside this block's categories are
/// ignored.
pub(super) fn config_dispatch(line: &str, op: ConfigOp) {
    STATE.apply(line, op);
}

/// `system tracing config startup` — gate for the startup-config apply
/// summary.
pub(super) fn startup() -> bool {
    STATE.on(&STATE.startup)
}

/// `system tracing config vty` — gate for VTY session lifecycle and
/// RPC traces.
pub(super) fn vty() -> bool {
    STATE.on(&STATE.vty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_toggle_set_delete() {
        let s = State::new();
        s.apply("system tracing config startup", ConfigOp::Set);
        assert!(s.on(&s.startup));
        s.apply("system tracing config startup", ConfigOp::Delete);
        assert!(!s.on(&s.startup));
    }

    #[test]
    fn vty_toggle_set_delete() {
        let s = State::new();
        s.apply("system tracing config vty", ConfigOp::Set);
        assert!(s.on(&s.vty));
        assert!(!s.on(&s.startup));
        s.apply("system tracing config vty", ConfigOp::Delete);
        assert!(!s.on(&s.vty));
    }

    #[test]
    fn all_master_switch_covers_every_category() {
        let s = State::new();
        s.apply("system tracing all", ConfigOp::Set);
        assert!(s.on(&s.startup));
        assert!(s.on(&s.vty));
        s.apply("system tracing all", ConfigOp::Delete);
        assert!(!s.on(&s.startup));
        assert!(!s.on(&s.vty));
    }

    #[test]
    fn foreign_tracing_lines_ignored() {
        let s = State::new();
        // RIB / FIB category lines flow through the same dispatch and
        // must not disturb the config-side toggles.
        s.apply("system tracing rib route", ConfigOp::Set);
        s.apply("system tracing fib kernel direction receive", ConfigOp::Set);
        assert!(!s.on(&s.startup));
    }
}
