//! Commit history: the configurations the last commits produced.
//!
//! Entry 0 is the running config as the latest commit left it, entry 1
//! the one before, and so on, as Junos numbers its rollbacks. The
//! configure-mode `rollback <n>` puts an entry in the candidate; it takes
//! effect on `commit` like any other edit, and that commit is a new
//! entry 0.
//!
//! Only a commit that changed the running config is an entry. A daemon
//! that starts with no config file, or with one that sets nothing, has
//! an empty history until the first commit that sets something: the
//! empty configuration it started from is not a commit to roll back to.
//!
//! The history is kept in memory: it starts with the commit of the
//! config file at startup, when there is one, and is gone when the
//! daemon stops.

use std::cell::RefCell;
use std::collections::VecDeque;

use chrono::{DateTime, Utc};

/// How many configurations are kept: entries 0 to 49, as Junos has.
pub const HISTORY_MAX: usize = 50;

pub struct CommitRecord {
    pub time: DateTime<Utc>,
    /// The commit took lines of the config file: at startup, or by
    /// `load`.
    pub from_file: bool,
    /// The running config this commit produced, one line for each thing
    /// set: `Config::list`, the rendering a commit diffs. Each line is a
    /// `set` command without the keyword.
    pub config: String,
}

#[derive(Default)]
pub struct CommitHistory {
    /// Newest first.
    records: RefCell<VecDeque<CommitRecord>>,
}

impl CommitHistory {
    /// Record what a commit produced. The caller records only a commit
    /// that changed the running config: one that changed nothing would
    /// push a configuration out of the history for a copy of the one
    /// already at 0.
    pub fn record(&self, config: String, from_file: bool) {
        let mut records = self.records.borrow_mut();
        records.push_front(CommitRecord {
            time: Utc::now(),
            from_file,
            config,
        });
        records.truncate(HISTORY_MAX);
    }

    pub fn len(&self) -> usize {
        self.records.borrow().len()
    }

    /// The configuration of entry `n`.
    pub fn config(&self, n: usize) -> Option<String> {
        self.records.borrow().get(n).map(|r| r.config.clone())
    }

    /// One line an entry, newest first.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (n, record) in self.records.borrow().iter().enumerate() {
            let time = record.time.format("%Y-%m-%d %H:%M:%S UTC");
            let note = if record.from_file {
                "  config file"
            } else {
                ""
            };
            out.push_str(&format!("{n:<4}{time}{note}\n"));
        }
        out
    }
}
