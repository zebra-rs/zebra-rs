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
//! since the epoch, and the count of commits the history has recorded:
//! all of them, those no longer kept and those of the daemon's earlier
//! lives included. The count is what keeps two revisions apart: it is
//! the number the commit's file is named by, which only grows, so it is
//! not used twice by two lives of a daemon that start in the same
//! second (a box with no clock boots at the same time every time, and a
//! daemon that crashes is restarted within the second). The start time
//! is there for a history whose directory was lost, where the count
//! starts over.
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
    /// A `commit` typed in configure mode.
    Commit,
    /// A `vtyctl apply`: a document or lines another writer committed.
    Apply,
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
            Origin::Apply => "apply",
            Origin::ConfigFile => "config-file",
            Origin::Unconfirmed => "unconfirmed",
            Origin::Start => "start",
        }
    }

    /// An operator's commit, or the daemon's rollback of one: what the
    /// history is read for. The others are made without anyone asking,
    /// and often.
    fn by_operator(self) -> bool {
        matches!(self, Origin::Commit | Origin::Unconfirmed)
    }

    /// What the listing says of a commit that is not an operator's
    /// `commit`.
    fn note(self) -> Option<&'static str> {
        match self {
            Origin::Commit => None,
            Origin::Apply => Some("apply"),
            Origin::ConfigFile => Some("config file"),
            Origin::Unconfirmed => Some("rollback, not confirmed"),
            Origin::Start => Some("daemon start"),
        }
    }

    fn from_keyword(word: &str) -> Option<Self> {
        [
            Origin::Commit,
            Origin::Apply,
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
    /// commits move it: `<daemon start>-<count>`, the count being one
    /// more than `seq`.
    pub revision: String,
    pub time: DateTime<Utc>,
    pub origin: Origin,
    /// The login name of who made it, when it was someone's and the
    /// name is known.
    pub user: Option<String>,
    /// The text of `commit comment`.
    pub comment: Option<String>,
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
        let mut file = format!(
            "# zebra-rs commit\n# revision: {}\n# time: {}\n# origin: {}\n",
            self.revision,
            self.time.to_rfc3339_opts(SecondsFormat::Secs, true),
            self.origin.keyword(),
        );
        if let Some(user) = &self.user {
            file.push_str(&format!("# user: {user}\n"));
        }
        if let Some(comment) = &self.comment {
            file.push_str(&format!("# comment: {comment}\n"));
        }
        file.push_str(&self.config);
        file
    }

    /// Read a commit's file. `None` for a file that is not one: no
    /// header, or a revision, time or origin this release does not read.
    fn from_file(seq: u64, text: &str) -> Option<Self> {
        let mut rest = text.strip_prefix("# zebra-rs commit\n")?;
        let (mut revision, mut time, mut origin) = (None, None, None);
        let (mut user, mut comment) = (None, None);
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
                Some(("user", value)) => user = Some(value.to_string()),
                Some(("comment", value)) => comment = Some(value.to_string()),
                _ => {}
            }
        }
        Some(Self {
            revision: revision?,
            time: time?,
            origin: origin?,
            user,
            comment,
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
    /// half of every revision this life of the daemon gives.
    start: i64,
    /// Newest first.
    records: RefCell<VecDeque<CommitRecord>>,
    /// Where the commits are kept, when they are.
    dir: RefCell<Option<PathBuf>>,
    /// The number of the next commit's file: how many commits the
    /// history has recorded, those no longer kept and those of earlier
    /// lives of the daemon included. One more is the second half of
    /// that commit's revision.
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
    pub fn record(
        &self,
        config: String,
        origin: Origin,
        user: Option<String>,
        comment: Option<String>,
    ) {
        let mut records = self.records.borrow_mut();
        if origin == Origin::ConfigFile && records.front().is_some_and(|r| r.config == config) {
            return;
        }
        let seq = self.next_seq.get();
        self.next_seq.set(seq + 1);
        let record = CommitRecord {
            revision: format!("{}-{}", self.start, seq + 1),
            time: Utc::now(),
            origin,
            user,
            comment,
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
            let oldest = oldest_to_drop(&records);
            let old = records.remove(oldest);
            if let (Some(old), Some(dir)) = (old, dir.as_deref()) {
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
            self.record(running, Origin::Start, None, None);
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

    /// One line an entry, newest first: its number, when it was made,
    /// its revision, who made it, and how when it was not a `commit`.
    /// Under it, the comment of an entry that has one.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (n, record) in self.records.borrow().iter().enumerate() {
            let time = record.time.format("%Y-%m-%d %H:%M:%S UTC");
            out.push_str(&format!("{n:<4}{time}  {}", record.revision));
            if let Some(user) = &record.user {
                out.push_str(&format!("  by {user}"));
            }
            if let Some(note) = record.origin.note() {
                out.push_str(&format!("  {note}"));
            }
            out.push('\n');
            if let Some(comment) = &record.comment {
                out.push_str(&format!("    {comment}\n"));
            }
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
                    "origin": record.origin.keyword(),
                    "config-file": record.origin == Origin::ConfigFile,
                    "user": record.user,
                    "comment": record.comment,
                })
            })
            .collect();
        let mut out = serde_json::to_string_pretty(&commits).unwrap_or_else(|_| "[]".into());
        out.push('\n');
        out
    }
}

/// Which entry leaves a history that is over its size: the oldest one
/// of whichever kind has more than half of it, operators' commits or
/// the others. A writer that applies often (bgpcfgd on SONiC, every time
/// CONFIG_DB changes) then cannot push the commits an operator made out
/// of the history, and has half of it for its own.
fn oldest_to_drop(records: &VecDeque<CommitRecord>) -> usize {
    let operators = records.iter().filter(|r| r.origin.by_operator()).count();
    let drop_operator = operators > HISTORY_MAX / 2;
    records
        .iter()
        .rposition(|r| r.origin.by_operator() == drop_operator)
        .unwrap_or(records.len() - 1)
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
