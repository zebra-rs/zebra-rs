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
//! An entry's number goes up with every commit made after it, by any
//! writer: the commit an operator read as 2 is 3 once an apply lands.
//! Its revision does not change. That is the second way to name it
//! (`rollback revision <id>`), for a writer that must have this commit
//! and no other. A revision is the time the daemon started, in seconds
//! since the epoch, and the count of commits recorded since: the count
//! is never used twice, and the start time keeps a revision noted
//! before a restart from naming a different commit after it.
//!
//! The history is kept in memory: it starts with the commit of the
//! config file at startup, when there is one, and is gone when the
//! daemon stops.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use chrono::{DateTime, Utc};

/// How many configurations are kept: entries 0 to 49, as Junos has.
pub const HISTORY_MAX: usize = 50;

pub struct CommitRecord {
    /// What names this commit for as long as it is kept, wherever later
    /// commits move it: `<daemon start>-<count>`.
    pub revision: String,
    pub time: DateTime<Utc>,
    /// The commit took lines of the config file: at startup, or by
    /// `load`.
    pub from_file: bool,
    /// The running config this commit produced, one line for each thing
    /// set: `Config::list`, the rendering a commit diffs. Each line is a
    /// `set` command without the keyword.
    pub config: String,
}

pub struct CommitHistory {
    /// When the history began, in seconds since the epoch: the first
    /// half of every revision.
    start: i64,
    /// The commits recorded since, those no longer kept included: the
    /// second half of the latest revision.
    count: Cell<u64>,
    /// Newest first.
    records: RefCell<VecDeque<CommitRecord>>,
}

impl Default for CommitHistory {
    /// A history that begins now, as the daemon's does when it starts.
    fn default() -> Self {
        Self::starting_at(Utc::now().timestamp())
    }
}

impl CommitHistory {
    pub fn starting_at(start: i64) -> Self {
        Self {
            start,
            count: Cell::new(0),
            records: RefCell::default(),
        }
    }

    /// Record what a commit produced. The caller records only a commit
    /// that changed the running config: one that changed nothing would
    /// push a configuration out of the history for a copy of the one
    /// already at 0.
    pub fn record(&self, config: String, from_file: bool) {
        let count = self.count.get() + 1;
        self.count.set(count);
        let mut records = self.records.borrow_mut();
        records.push_front(CommitRecord {
            revision: format!("{}-{count}", self.start),
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

    /// The number the commit with this revision has now, when it is
    /// still kept.
    pub fn number_of(&self, revision: &str) -> Option<usize> {
        self.records
            .borrow()
            .iter()
            .position(|r| r.revision == revision)
    }

    /// The revisions of the commits kept, newest first.
    pub fn revisions(&self) -> Vec<String> {
        self.records
            .borrow()
            .iter()
            .map(|r| r.revision.clone())
            .collect()
    }

    /// One line an entry, newest first: its number, when it was made and
    /// its revision.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (n, record) in self.records.borrow().iter().enumerate() {
            let time = record.time.format("%Y-%m-%d %H:%M:%S UTC");
            let revision = &record.revision;
            let note = if record.from_file {
                "  config file"
            } else {
                ""
            };
            out.push_str(&format!("{n:<4}{time}  {revision}{note}\n"));
        }
        out
    }
}
