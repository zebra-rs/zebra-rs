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
//! The daemon keeps the history in a directory, one file a commit, and
//! reads it back when it starts ([`CommitHistory::keep_in`]). The commit
//! of the config file at startup is then one more commit: entry 0 when
//! the file differs from what was last committed, and no entry when it
//! is the same. A daemon that starts with nothing, where the history has
//! commits, is an entry too ([`CommitHistory::started_with`]): entry 0 is
//! always what is running. Without a directory (the unit tests) the history is in
//! memory only.
//!
//! A file is the commit's header, `# key: value` lines, and after it the
//! configuration, one line for each thing set. Its name is the commit's
//! sequence number, which only grows: the newest file is the highest. A
//! commit keeps the revision it was given, which its file holds; the
//! commits of a restarted daemon have that daemon's start time in theirs.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};

/// How many configurations are kept: entries 0 to 49, as Junos has.
pub const HISTORY_MAX: usize = 50;

/// What made a commit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// A `commit`, or a `vtyctl apply`.
    Commit,
    /// The config file: at startup, or by `load`.
    ConfigFile,
    /// The daemon, taking back a `commit confirmed` nobody confirmed.
    Unconfirmed,
    /// The daemon started, and not with the configuration last
    /// committed: with no config file, or one whose commit was refused.
    Start,
}

impl Origin {
    /// The word a commit's file has for it.
    fn keyword(self) -> &'static str {
        match self {
            Origin::Commit => "commit",
            Origin::ConfigFile => "config-file",
            Origin::Unconfirmed => "unconfirmed",
            Origin::Start => "start",
        }
    }

    fn from_keyword(word: &str) -> Option<Self> {
        [
            Origin::Commit,
            Origin::ConfigFile,
            Origin::Unconfirmed,
            Origin::Start,
        ]
        .into_iter()
        .find(|origin| origin.keyword() == word)
    }
}

pub struct CommitRecord {
    /// What names this commit for as long as it is kept, wherever later
    /// commits move it: `<daemon start>-<count>`.
    pub revision: String,
    pub time: DateTime<Utc>,
    pub origin: Origin,
    /// The running config this commit produced, one line for each thing
    /// set: `Config::list`, the rendering a commit diffs. Each line is a
    /// `set` command without the keyword.
    pub config: String,
    /// The number its file is named by.
    seq: u64,
}

impl CommitRecord {
    /// The commit as its file holds it.
    fn to_file(&self) -> String {
        format!(
            "# zebra-rs commit\n# revision: {}\n# time: {}\n# origin: {}\n{}",
            self.revision,
            self.time.to_rfc3339_opts(SecondsFormat::Secs, true),
            self.origin.keyword(),
            self.config
        )
    }

    /// Read a commit's file. `None` for a file that is not one: no
    /// header, or a revision, time or origin this release does not read.
    fn from_file(seq: u64, text: &str) -> Option<Self> {
        let mut rest = text.strip_prefix("# zebra-rs commit\n")?;
        let (mut revision, mut time, mut origin) = (None, None, None);
        while let Some(line) = rest.strip_prefix("# ") {
            let (line, after) = line.split_once('\n').unwrap_or((line, ""));
            rest = after;
            // A key this release does not know is a later release's.
            match line.split_once(": ") {
                Some(("revision", value)) => revision = Some(value.to_string()),
                Some(("time", value)) => {
                    time = Some(DateTime::parse_from_rfc3339(value).ok()?.to_utc());
                }
                Some(("origin", value)) => origin = Some(Origin::from_keyword(value)?),
                _ => {}
            }
        }
        Some(Self {
            revision: revision?,
            time: time?,
            origin: origin?,
            config: rest.to_string(),
            seq,
        })
    }
}

/// The name of commit `seq`'s file. Padded, so the names sort as the
/// numbers do.
fn file_name(seq: u64) -> String {
    format!("{seq:010}.conf")
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
    /// Where the commits are kept, when they are.
    dir: RefCell<Option<PathBuf>>,
    /// The number of the next commit's file.
    next_seq: Cell<u64>,
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
            dir: RefCell::default(),
            next_seq: Cell::new(0),
        }
    }

    /// Record what a commit produced. The caller records only a commit
    /// that changed the running config: one that changed nothing would
    /// push a configuration out of the history for a copy of the one
    /// already at 0.
    ///
    /// The config file a daemon starts with is the one case where that
    /// is not enough: it changes the running config, which is empty
    /// then, and is still no commit when it is what the history read
    /// back from its directory has at 0.
    pub fn record(&self, config: String, origin: Origin) {
        let mut records = self.records.borrow_mut();
        if origin == Origin::ConfigFile && records.front().is_some_and(|r| r.config == config) {
            return;
        }
        let count = self.count.get() + 1;
        self.count.set(count);
        let seq = self.next_seq.get();
        self.next_seq.set(seq + 1);
        let record = CommitRecord {
            revision: format!("{}-{count}", self.start),
            time: Utc::now(),
            origin,
            config,
            seq,
        };
        let dir = self.dir.borrow();
        if let Some(dir) = dir.as_deref()
            && let Err(err) = write_commit(dir, &record)
        {
            // The commit is made; only going back to it after a restart
            // is lost.
            tracing::warn!(
                "commit history: cannot write {}: {err}",
                dir.join(file_name(seq)).display()
            );
        }
        records.push_front(record);
        while records.len() > HISTORY_MAX {
            if let (Some(old), Some(dir)) = (records.pop_back(), dir.as_deref()) {
                let _ = std::fs::remove_file(dir.join(file_name(old.seq)));
            }
        }
    }

    /// The daemon has started with `running` as its configuration.
    /// Commit 0 is the running config, always: when the history read
    /// back from its directory has another configuration there (the
    /// config file is gone, or its commit was refused), the one the
    /// daemon is running is a commit in front of it, so that `rollback
    /// 1` is what was running before the restart.
    pub fn started_with(&self, running: String) {
        let differs = self
            .records
            .borrow()
            .front()
            .is_some_and(|last| last.config != running);
        if differs {
            self.record(running, Origin::Start);
        }
    }

    /// Keep the history in `dir` from now on, starting with the commits
    /// already there: the newest [`HISTORY_MAX`] of them. Files beyond
    /// those are removed; a file that is not a commit is left alone and
    /// said.
    ///
    /// A directory that cannot be made or read is reported and the
    /// history stays in memory: the daemon starts all the same.
    pub fn keep_in(&self, dir: &Path) {
        let listing = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .and_then(|()| std::fs::read_dir(dir));
        let listing = match listing {
            Ok(listing) => listing,
            Err(err) => {
                tracing::warn!(
                    "commit history: {}: {err}; kept in memory only",
                    dir.display()
                );
                return;
            }
        };
        let mut seqs: Vec<u64> = listing
            .filter_map(|entry| {
                let name = entry.ok()?.file_name();
                let seq = name.to_str()?.strip_suffix(".conf")?;
                (seq.len() == 10).then(|| seq.parse().ok())?
            })
            .collect();
        seqs.sort_unstable_by(|a, b| b.cmp(a));
        self.next_seq
            .set(seqs.first().map_or(0, |newest| newest + 1));

        let mut records = VecDeque::new();
        for seq in seqs {
            let path = dir.join(file_name(seq));
            if records.len() == HISTORY_MAX {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(text) => match CommitRecord::from_file(seq, &text) {
                    Some(record) => records.push_back(record),
                    None => tracing::warn!(
                        "commit history: {} is not a commit; skipped",
                        path.display()
                    ),
                },
                Err(err) => {
                    tracing::warn!("commit history: {}: {err}; skipped", path.display())
                }
            }
        }
        self.records.replace(records);
        self.dir.replace(Some(dir.to_path_buf()));
    }

    pub fn len(&self) -> usize {
        self.records.borrow().len()
    }

    /// Read the configuration of entry `n` where it is kept. It is as
    /// long as the running config, and a reader has no use for a copy.
    pub fn with_config<R>(&self, n: usize, read: impl FnOnce(&str) -> R) -> Option<R> {
        self.records.borrow().get(n).map(|r| read(&r.config))
    }

    /// The configuration of entry `n`.
    #[cfg(test)]
    pub fn config(&self, n: usize) -> Option<String> {
        self.with_config(n, str::to_string)
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
            let note = match record.origin {
                Origin::Commit => "",
                Origin::ConfigFile => "  config file",
                Origin::Unconfirmed => "  rollback, not confirmed",
                Origin::Start => "  daemon start",
            };
            out.push_str(&format!("{n:<4}{time}  {revision}{note}\n"));
        }
        out
    }

    /// The same listing for a program: an array, newest first, of what
    /// [`Self::render`] prints for each entry.
    pub fn render_json(&self) -> String {
        let commits: Vec<serde_json::Value> = self
            .records
            .borrow()
            .iter()
            .enumerate()
            .map(|(n, record)| {
                serde_json::json!({
                    "number": n,
                    "time": record.time.to_rfc3339_opts(SecondsFormat::Secs, true),
                    "revision": record.revision,
                    "config-file": record.origin == Origin::ConfigFile,
                    "unconfirmed-rollback": record.origin == Origin::Unconfirmed,
                })
            })
            .collect();
        let mut out = serde_json::to_string_pretty(&commits).unwrap_or_else(|_| "[]".into());
        out.push('\n');
        out
    }
}

/// Write a commit's file whole or not at all, readable by its owner
/// only: it is a copy of the configuration, secrets included.
fn write_commit(dir: &Path, record: &CommitRecord) -> std::io::Result<()> {
    use std::io::Write;
    let path = dir.join(file_name(record.seq));
    let tmp = path.with_extension("tmp");
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut file| file.write_all(record.to_file().as_bytes()))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}
