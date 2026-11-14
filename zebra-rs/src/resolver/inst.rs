//! The resolver task: what the sources have learned on each interface
//! for the host to use, and what the system resolver has been given.
//!
//! The task has no configuration of its own. What a source reports is
//! used; a source that is to keep an interface's name servers from the
//! host (`dhcp-options no-name-server`) does not report them.
//!
//! Every change in what a source knows ends in [`Resolver::sync`]: it
//! works out what the system resolver should hold and has the
//! [`Backend`] make up the difference, one command at a time. A command
//! that fails is tried again later, so a resolver that starts after
//! zebra-rs still gets its servers.
//!
//! An interface is its index here, from the report to the command. The
//! sources say the index of the interface they run on
//! ([`super::Report`]), what is learned and what is held are kept by
//! it, and every command says it ([`Op`]). That is how the system
//! resolver keeps an interface's settings too, through a change of
//! name. So no name is looked up anywhere: an interface that is renamed
//! stays the interface it was, with what its source has for it, and one
//! made again under an old name is another, which its source reports
//! anew. A name is what the log and the record call an interface, and
//! is asked of the system when there is something to say.
//!
//! zebra-rs leaves the system resolver as it is when it stops. Which
//! interfaces then hold something of ours is kept on disk
//! ([`super::record`]), and the next run takes back what it has not
//! learned again by the time its wait for the sources is over
//! ([`Resolver::resume`]).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::time::{Instant, sleep_until};

use crate::context::Task;

use super::record::Record;
use super::{LinkDns, Report, ResolverTx, Source};

/// How long after a failed command the next try comes: this at first,
/// twice as long after every further failure, up to [`RETRY_MAX`].
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(300);

/// One change to the system resolver's configuration of an interface.
///
/// The interface is said by its index, never by its name. A name is
/// looked up by whoever is told it, when it is told, and can be another
/// interface's by then: given up by one that was renamed or deleted,
/// and taken by another. The index is the interface for as long as it
/// exists, is what the sources report, and is what the system resolver
/// keeps its settings by. So a command reaches the interface its
/// source runs on, or none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// These are the interface's name servers.
    Dns(u32, Vec<IpAddr>),
    /// These are its search domains; none clears them.
    Domains(u32, Vec<String>),
    /// Forget everything set on the interface.
    Revert(u32),
}

/// Why a command is not known to have gone through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The system resolver is not ours to configure, now or later.
    Refused(String),
    /// The command could not be started, or there was nothing to start
    /// it with: nothing was changed.
    NotRun(String),
    /// The command was started and did not report success: it said no,
    /// gave no answer, or was cut short. None of them says what the
    /// interface holds now. One cut short may have made its call first.
    /// And "no" can come after the change: resolved drops the whole list
    /// it was replacing when it cannot add an entry of the new one, and
    /// then reports the error.
    Uncertain(String),
}

/// What carries the commands out ([`super::resolvectl::Resolvectl`]).
pub trait Backend: Send + 'static {
    /// What a command is run with.
    type Program: Send + Sync;

    /// Look for what the next command is to be run with. An error says
    /// that no command can be started now, and none has been:
    /// [`Failure::Refused`] where the system resolver is not ours, and
    /// [`Failure::NotRun`] where there is nothing to run.
    ///
    /// Asked before every command. Whether one can be started is not
    /// taken from how the last one went: a host without the program
    /// today may have it at the next try.
    fn program(&mut self) -> Result<Self::Program, Failure>;

    /// Run `op` with what [`Backend::program`] found.
    fn run(
        &mut self,
        program: &Self::Program,
        op: &Op,
    ) -> impl Future<Output = Result<(), Failure>> + Send;

    /// Whether the system resolver is this backend's to configure, or
    /// why not: what [`Failure::Refused`] would say of any command,
    /// known without running one.
    fn permitted(&mut self) -> Result<(), String>;

    /// The name the interface of that index has now, if there is one:
    /// whether it is still there, and what the log and the record are
    /// to call it. A name can change and the index does not, and the
    /// system resolver keeps a renamed interface's settings. It keeps
    /// them for as long as that interface exists: one deleted and made
    /// again under the same name has another index, and none of them.
    ///
    /// `None` is the end of what the interface held: it is forgotten
    /// with no command and no further try. So `None` only where it is
    /// known that no interface has the index. Where that cannot be
    /// found out, the interface is there, under whatever name can be
    /// given it.
    fn ifname(&self, ifindex: u32) -> Option<String>;
}

/// What the system resolver holds from us for an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    /// What the interface was called when this was noted: for the
    /// record, which a person may read. The interface itself is the
    /// index this is noted under.
    name: String,
    /// `None`: something, but not known what. A command that was
    /// started did not succeed, or the servers went in and their domains
    /// did not.
    dns: Option<LinkDns>,
}

pub struct Resolver<B> {
    tx: ResolverTx,
    rx: UnboundedReceiver<Report>,
    backend: B,
    /// What each source has for the host to use, by interface index.
    learned: BTreeMap<u32, BTreeMap<Source, LinkDns>>,
    /// What the system resolver holds from us, by interface index. The
    /// settings are an interface's, not a name's: the system resolver
    /// keeps them by index, through a change of name.
    applied: BTreeMap<u32, Held>,
    /// Interfaces whose failure has been said; said again only after a
    /// success.
    complained: BTreeSet<u32>,
    /// The backend refused: nothing more is asked of it.
    refused: bool,
    /// When to try the failed commands again.
    retry: Option<Instant>,
    backoff: Duration,
    /// The interfaces that hold something of ours, on disk for the next
    /// run. An interface is named there before any command that may
    /// give it something is started: a run that is ended while the
    /// command is under way has still left word of it.
    record: Record,
    /// The interfaces an earlier run left set, as far as no source of
    /// this run has had name servers for them yet. They are in `applied`
    /// as holding something, and are not taken back until `sweep`.
    waiting: BTreeSet<u32>,
    /// When the wait for the sources is over.
    sweep: Option<Instant>,
}

impl<B: Backend> Resolver<B> {
    pub fn new(backend: B) -> Resolver<B> {
        let (tx, rx) = mpsc::unbounded_channel();
        Resolver {
            tx,
            rx,
            backend,
            learned: BTreeMap::new(),
            applied: BTreeMap::new(),
            complained: BTreeSet::new(),
            refused: false,
            retry: None,
            backoff: RETRY_MIN,
            record: Record::default(),
            waiting: BTreeSet::new(),
            sweep: None,
        }
    }

    /// Take over from the run before this one: `record` is what it left
    /// on disk, and is kept from now on.
    ///
    /// An interface the record names, and that is still the interface it
    /// was, holds something of that run's. What a source of this run has
    /// name servers for is set as ever, the lease resumed from disk
    /// first of all. What none has by the time `wait` is over is taken
    /// back: a lease that was lost, a router that went, or
    /// `no-name-server` set, while zebra-rs was not running. The sources
    /// need that time. A lease is resumed at once, but a Router
    /// Advertisement has to be heard again.
    ///
    /// An interface is the one it was by its index. One that was
    /// renamed while zebra-rs was not running holds its settings still,
    /// and is the same interface under the name it has now. One whose
    /// index is gone holds nothing: its settings went with it.
    ///
    /// Where the system resolver is not ours to configure, nothing is
    /// taken over and no record is kept: this zebra-rs has set nothing
    /// and will set nothing. The file is then not ours either. The state
    /// directory is the host's whatever the network namespace, so what
    /// is there is the record of the zebra-rs that may, and writing it
    /// anew from here would lose that one's interfaces.
    pub fn resume(&mut self, record: Record, wait: Duration) {
        if self.backend.permitted().is_err() {
            return;
        }
        self.record = record;
        // A wait too long for the clock to count (the largest number
        // there is, for "never") has no end: nothing is taken back, as
        // the RIB under the same flag sweeps nothing.
        let ends = Instant::now().checked_add(wait);
        for (ifindex, name) in self.record.links().clone() {
            let Some(link) = self.backend.ifname(ifindex) else {
                continue;
            };
            tracing::info!("resolver: {}", taken_over(&link, &name, ends.map(|_| wait)));
            let held = Held {
                name: link,
                dns: None,
            };
            self.applied.insert(ifindex, held);
            self.waiting.insert(ifindex);
        }
        if !self.waiting.is_empty() {
            self.sweep = ends;
        }
        // Without the ones that have gone.
        self.record.note(self.held_links());
    }

    /// The wait for the sources is over: what an earlier run left and
    /// no source has claimed is no longer kept for them, and the next
    /// look at what is wanted takes it back. Except from an interface
    /// that went during the wait: that one holds nothing, as every
    /// withdrawal finds out for itself.
    fn swept(&mut self) {
        self.sweep = None;
        self.waiting.clear();
    }

    /// Nothing is held by that interface any more.
    fn forget(&mut self, ifindex: u32) {
        self.applied.remove(&ifindex);
        self.complained.remove(&ifindex);
    }

    /// The interface is no more. What it held went with it, and that is
    /// said where it held something.
    fn gone(&mut self, ifindex: u32) {
        if let Some(held) = self.applied.get(&ifindex) {
            tracing::info!(
                "resolver: {}: its name servers went with the interface",
                held.name
            );
        }
        self.forget(ifindex);
    }

    /// The interfaces that hold something of ours, as the record names
    /// them: by index, each with the name it was noted under.
    fn held_links(&self) -> BTreeMap<u32, String> {
        self.applied
            .iter()
            .map(|(ifindex, held)| (*ifindex, held.name.clone()))
            .collect()
    }

    /// Where the sources send what they learn.
    pub fn tx(&self) -> ResolverTx {
        self.tx.clone()
    }

    async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(report) = self.rx.recv() => {
                    self.learn(report);
                    self.look(false).await;
                }
                _ = sleep_until_opt(self.retry) => self.look(false).await,
                _ = sleep_until_opt(self.sweep) => self.look(true).await,
            }
        }
    }

    /// What every event of the task ends in: a look at what is wanted,
    /// with the system resolver made to hold it ([`Resolver::sync`]).
    /// `wait_over` when the event is the end of the wait for the sources
    /// ([`Resolver::swept`]).
    ///
    /// The reports that are waiting are taken in first, whatever the
    /// event was. Several at once (a lease replaced by another, a commit
    /// that touched several interfaces) are one change. And a time that
    /// comes due beside a report must not act on what that report is
    /// about to change. The end of the wait would take back from an
    /// interface what the report claims for it, and set it again a
    /// moment later, with no name servers in between. A try that comes
    /// due would set what has just been lost.
    async fn look(&mut self, wait_over: bool) {
        while let Ok(report) = self.rx.try_recv() {
            self.learn(report);
        }
        if wait_over {
            self.swept();
        }
        self.sync().await;
    }

    fn learn(&mut self, report: Report) {
        match report.dns {
            Some(dns) => {
                self.learned
                    .entry(report.ifindex)
                    .or_default()
                    .insert(report.source, dns);
            }
            None => {
                if let Some(sources) = self.learned.get_mut(&report.ifindex) {
                    sources.remove(&report.source);
                    if sources.is_empty() {
                        self.learned.remove(&report.ifindex);
                    }
                }
            }
        }
    }

    /// What the system resolver should hold: for every interface
    /// something usable has been learned on, that.
    fn wanted(&self) -> BTreeMap<u32, LinkDns> {
        self.learned
            .iter()
            .filter_map(|(ifindex, sources)| {
                let dns = merge(sources);
                // Search domains alone resolve nothing.
                (!dns.servers.is_empty()).then_some((*ifindex, dns))
            })
            .collect()
    }

    /// Make the system resolver hold what is wanted and, if a command
    /// failed, say when to try again.
    ///
    /// That wait counts from when the commands are over, not from when
    /// they began: one that runs into its time limit takes longer than
    /// the first waits are, and counted from the start they would all be
    /// over already, each failure followed by the next try at once.
    async fn sync(&mut self) {
        let failed = self.reconcile().await;
        self.schedule(failed, Instant::now());
    }

    /// When to try again after commands that `failed`, or that there is
    /// no need to.
    fn schedule(&mut self, failed: bool, now: Instant) {
        if failed {
            self.retry = Some(now + self.backoff);
            self.backoff = (self.backoff * 2).min(RETRY_MAX);
        } else {
            self.retry = None;
            self.backoff = RETRY_MIN;
        }
    }

    /// Have the backend make up the difference between what the system
    /// resolver holds and what is wanted, and the record say which
    /// interfaces hold something after that. True when there is
    /// something to try again: a command that failed, or a record that
    /// could not be written. An interface that is set and not on disk
    /// is one the next run would not know to take back, so the write is
    /// not left for the next change to bring, which may be hours away.
    async fn reconcile(&mut self) -> bool {
        if self.refused {
            return false;
        }
        let failed = self.apply().await;
        self.record.note(self.held_links());
        failed || self.record.unsaved()
    }

    /// One command. What it is to be run with is looked for first, and
    /// with nothing to run it with, nothing is started.
    ///
    /// `ahead` is the interface the command may give something to. It
    /// is put on record once there is a program and before the command
    /// is started: a run that is ended while the command is under way
    /// does not know how it went, and the next one must find the
    /// interface named.
    ///
    /// That holds for every command that can start, whatever became of
    /// the one before it. And a host without the program has none that
    /// can: nothing is put on record there, try after try, where putting
    /// it and taking it off again would write the file every few minutes
    /// for nothing.
    async fn run(&mut self, op: Op, ahead: Option<(&str, u32)>) -> Result<(), Failure> {
        let program = self.backend.program()?;
        if let Some((name, ifindex)) = ahead {
            self.record.hold(name, ifindex);
        }
        self.backend.run(&program, &op).await
    }

    async fn apply(&mut self) -> bool {
        let wanted = self.wanted();
        let mut failed = false;
        // Learned again, what an earlier run left is this run's.
        self.waiting.retain(|ifindex| !wanted.contains_key(ifindex));

        let gone: Vec<u32> = self
            .applied
            .keys()
            .filter(|ifindex| !wanted.contains_key(ifindex) && !self.waiting.contains(ifindex))
            .copied()
            .collect();
        for ifindex in gone {
            // Asked before every withdrawal, the first try and each
            // later one: an interface that is gone took its settings
            // with it, and there is nothing to say to an index that is
            // nobody's. What may have been made under its name since is
            // another interface, and has another index.
            let Some(name) = self.backend.ifname(ifindex) else {
                self.gone(ifindex);
                continue;
            };
            let failure = match self.run(Op::Revert(ifindex), None).await {
                Ok(()) => {
                    tracing::info!("resolver: {name}: name servers withdrawn");
                    self.forget(ifindex);
                    continue;
                }
                Err(Failure::Refused(why)) => {
                    self.refuse(&why);
                    return false;
                }
                Err(failure) => failure,
            };
            if self.backend.ifname(ifindex).is_none() {
                // It went while the command ran, and its settings with
                // it.
                self.forget(ifindex);
                continue;
            }
            // Asked again later. Until then a withdrawal that was
            // started may have been carried out: what the interface
            // holds is no longer known, and wanted again in the meantime
            // it is set again, not taken for held.
            if let Failure::Uncertain(_) = failure
                && let Some(held) = self.applied.get_mut(&ifindex)
            {
                held.dns = None;
            }
            let (Failure::NotRun(why) | Failure::Uncertain(why) | Failure::Refused(why)) = failure;
            failed = true;
            self.complain(ifindex, &name, "withdrawn", &why);
        }

        for (ifindex, dns) in wanted {
            // Held already, by this very interface. What an interface
            // of the same name held before it is that one's, under its
            // own index, and says nothing of this one: a lease lost and
            // found again on an interface made anew in between is set
            // again though nothing else changed.
            if self
                .applied
                .get(&ifindex)
                .is_some_and(|held| held.dns.as_ref() == Some(&dns))
            {
                continue;
            }
            // Asked before every command that sets, as before every
            // withdrawal. An interface that is gone can be given
            // nothing, and what it held went with it. That is no failure
            // and nothing to try again: what comes under its name is
            // another interface, which its source reports by its own
            // index. Of this one the source, which hears of the
            // interface from the RIB and not from here, says in its own
            // time that it has nothing.
            let Some(name) = self.backend.ifname(ifindex) else {
                self.gone(ifindex);
                continue;
            };
            match self.set(ifindex, &name, &dns).await {
                Ok(()) => {
                    tracing::info!("resolver: {name}: {}", describe(&dns));
                    self.complained.remove(&ifindex);
                }
                Err(Failure::Refused(why)) => {
                    self.refuse(&why);
                    return false;
                }
                Err(Failure::NotRun(why) | Failure::Uncertain(why)) => {
                    if self.backend.ifname(ifindex).is_none() {
                        // It went while the commands ran: that is why
                        // they failed, and the end of it.
                        self.gone(ifindex);
                        continue;
                    }
                    failed = true;
                    self.complain(ifindex, &name, "set", &why);
                }
            }
        }
        failed
    }

    /// The servers, then the domains, noting in `applied` what the
    /// system resolver holds after each, so that it is taken back if it
    /// stops being wanted before a later try has put it right:
    ///
    /// - the servers' command not started: what it held before, and that
    ///   stays noted;
    /// - started and not successful: the new servers, the old ones or
    ///   none at all, so "something" is noted in place of the old ones;
    /// - the servers in and the domains not: something of ours that is
    ///   not `dns`;
    /// - both in: `dns`.
    ///
    /// All of it is noted for `ifindex`, which the commands say: it is
    /// that interface's whatever becomes of its name while they run.
    /// `name` is what it is called when they begin, for the record.
    async fn set(&mut self, ifindex: u32, name: &str, dns: &LinkDns) -> Result<(), Failure> {
        let held = |dns: Option<LinkDns>| Held {
            name: name.to_string(),
            dns,
        };
        // On record before the command is started (`run`). A record
        // that cannot be written does not keep the servers from the
        // host: it is tried again with the look that follows
        // (`reconcile`).
        let servers = Op::Dns(ifindex, dns.servers.clone());
        match self.run(servers, Some((name, ifindex))).await {
            Ok(()) => {}
            Err(failure) => {
                if matches!(failure, Failure::Uncertain(_)) {
                    self.applied.insert(ifindex, held(None));
                }
                return Err(failure);
            }
        }
        self.applied.insert(ifindex, held(None));
        // The interface is on record from the servers' command.
        self.run(Op::Domains(ifindex, dns.domains.clone()), None)
            .await?;
        self.applied.insert(ifindex, held(Some(dns.clone())));
        Ok(())
    }

    fn complain(&mut self, ifindex: u32, name: &str, what: &str, why: &str) {
        if self.complained.insert(ifindex) {
            tracing::warn!("resolver: {name}: name servers not {what}: {why}");
        } else {
            tracing::debug!("resolver: {name}: name servers not {what}: {why}");
        }
    }

    fn refuse(&mut self, why: &str) {
        self.refused = true;
        tracing::warn!("resolver: {why}: the system resolver is left alone");
    }
}

/// One interface's sources as one configuration: every usable server and
/// domain once, the sources in their order.
fn merge(sources: &BTreeMap<Source, LinkDns>) -> LinkDns {
    let mut dns = LinkDns::default();
    for from in sources.values() {
        for server in &from.servers {
            if usable_server(server) && !dns.servers.contains(server) {
                dns.servers.push(*server);
            }
        }
        for domain in &from.domains {
            if let Some(domain) = usable_domain(domain)
                && !dns.domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
            {
                dns.domains.push(domain.to_string());
            }
        }
    }
    dns
}

/// An address a name server can have. A lease that names this host
/// (loopback) would point the system resolver at itself.
fn usable_server(server: &IpAddr) -> bool {
    let broadcast = matches!(server, IpAddr::V4(v4) if v4.is_broadcast());
    !(server.is_unspecified() || server.is_loopback() || server.is_multicast() || broadcast)
}

/// A search domain as it came off the wire, when it is a domain name and
/// nothing else: without the dot that may end it. The check matters
/// beyond tidiness: the system resolver reads a leading `~` as "route
/// these names to this link", and `~.` as every name.
fn usable_domain(domain: &str) -> Option<&str> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let label = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    (domain.len() <= 253 && domain.split('.').all(label)).then_some(domain)
}

/// What is said of an interface taken over from an earlier run: what it
/// is called now, as what it is on record where that is another name,
/// and what becomes of what it holds. `wait` is the time its sources
/// have to claim it, and `None` where that time has no end: no time is
/// promised that never comes.
fn taken_over(link: &str, noted: &str, wait: Option<Duration>) -> String {
    let was = if link == noted {
        String::new()
    } else {
        format!(" (as {noted})")
    };
    let then = match wait {
        Some(wait) => format!("taken back in {} s unless learned again", wait.as_secs()),
        None => "and keeps them: the wait for the sources has no end".to_string(),
    };
    format!("{link}: holds name servers of an earlier run{was}, {then}")
}

fn describe(dns: &LinkDns) -> String {
    let join = |items: Vec<String>| items.join(" ");
    let mut text = format!(
        "name servers {}",
        join(dns.servers.iter().map(ToString::to_string).collect())
    );
    if !dns.domains.is_empty() {
        text.push_str(&format!(", search {}", join(dns.domains.clone())));
    }
    text
}

pub fn serve<B: Backend>(mut resolver: Resolver<B>) -> Task<()> {
    Task::spawn(async move {
        resolver.event_loop().await;
    })
}

async fn sleep_until_opt(when: Option<Instant>) {
    match when {
        Some(t) => sleep_until(t).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::resolver::record::tests::Scratch;

    const WAN: &str = "wan0";

    /// A command as the tests say it: with the name its interface had
    /// when the command was started. The command itself says the index,
    /// which a test would have to look up, and the name is what tells
    /// one interface from another on the page.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Said {
        Dns(String, Vec<IpAddr>),
        Domains(String, Vec<String>),
        Revert(String),
    }

    /// What the backend was asked, and what it is to answer: the answers
    /// in order, then success.
    #[derive(Default)]
    struct Script {
        ran: Vec<Said>,
        /// The index each of them said.
        said: Vec<u32>,
        answers: VecDeque<Result<(), Failure>>,
        /// Interfaces that do not exist.
        missing: Vec<String>,
        /// Interfaces that go while the next command runs.
        leaving: Vec<String>,
        /// Interfaces that are renamed while the next command runs: the
        /// name each has, and the one it is given.
        renaming: Vec<(String, String)>,
        /// Interfaces that are deleted and made again while the next
        /// command runs: the same name, another index.
        remaking: Vec<String>,
        /// The index of the interfaces that do. One not said here is
        /// given an index of its own when a test first speaks of it.
        index: BTreeMap<String, u32>,
        /// How many indexes have been given out.
        given: u32,
        /// How long a command takes.
        takes: Duration,
        /// Where the resolver keeps its record, and what that named when
        /// each command was started.
        record: Option<std::path::PathBuf>,
        recorded: Vec<Vec<(String, u32)>>,
        /// The system resolver is not this backend's to configure.
        refuses: bool,
        /// There is no program to run a command with.
        absent: bool,
    }

    /// Where the benches run.
    fn here() -> crate::resolver::record::Origin {
        crate::resolver::record::tests::at("this-boot")
    }

    /// What the record at `path` names.
    fn on_record(path: &std::path::Path) -> Vec<(String, u32)> {
        let mut named: Vec<(String, u32)> = Record::load(path.to_path_buf(), here())
            .links()
            .iter()
            .map(|(index, name)| (name.clone(), *index))
            .collect();
        named.sort();
        named
    }

    fn links(items: &[(&str, u32)]) -> Vec<(String, u32)> {
        items
            .iter()
            .map(|(name, index)| (name.to_string(), *index))
            .collect()
    }

    #[derive(Clone, Default)]
    struct Mock(Arc<Mutex<Script>>);

    impl Backend for Mock {
        type Program = ();

        fn program(&mut self) -> Result<(), Failure> {
            let script = self.0.lock().unwrap();
            if script.refuses {
                Err(Failure::Refused("not here".to_string()))
            } else if script.absent {
                Err(Failure::NotRun("no such program".to_string()))
            } else {
                Ok(())
            }
        }

        async fn run(&mut self, _program: &(), op: &Op) -> Result<(), Failure> {
            let takes = self.0.lock().unwrap().takes;
            tokio::time::sleep(takes).await;
            let mut script = self.0.lock().unwrap();
            let ifindex = match op {
                Op::Dns(ifindex, _) | Op::Domains(ifindex, _) | Op::Revert(ifindex) => *ifindex,
            };
            script.said.push(ifindex);
            let there = script.name(ifindex);
            let name = there.clone().unwrap_or_else(|| format!("#{ifindex}"));
            script.ran.push(match op {
                Op::Dns(_, servers) => Said::Dns(name, servers.clone()),
                Op::Domains(_, domains) => Said::Domains(name, domains.clone()),
                Op::Revert(_) => Said::Revert(name),
            });
            if let Some(path) = script.record.clone() {
                script.recorded.push(on_record(&path));
            }
            if there.is_none() {
                // As the system resolver answers for an index that is
                // no interface's. No scripted answer is used up.
                return Err(Failure::Uncertain(format!("Link {ifindex} not known")));
            }
            let leaving = std::mem::take(&mut script.leaving);
            script.missing.extend(leaving);
            for name in std::mem::take(&mut script.remaking) {
                let index = script.fresh();
                script.index.insert(name, index);
            }
            for (old, new) in std::mem::take(&mut script.renaming) {
                script.rename(&old, &new);
            }
            script.answers.pop_front().unwrap_or(Ok(()))
        }

        fn permitted(&mut self) -> Result<(), String> {
            if self.0.lock().unwrap().refuses {
                Err("not here".to_string())
            } else {
                Ok(())
            }
        }

        fn ifname(&self, ifindex: u32) -> Option<String> {
            self.0.lock().unwrap().name(ifindex)
        }
    }

    impl Script {
        /// The name of the interface of that index, if it is there.
        fn name(&self, ifindex: u32) -> Option<String> {
            self.index
                .iter()
                .find(|(name, index)| **index == ifindex && !self.missing.contains(name))
                .map(|(name, _)| name.clone())
        }

        /// The index of the interface a test calls that, there or gone:
        /// what its source has from the RIB, and goes on saying.
        fn index_of(&mut self, ifname: &str) -> u32 {
            if let Some(index) = self.index.get(ifname) {
                return *index;
            }
            let index = self.fresh();
            self.index.insert(ifname.to_string(), index);
            index
        }

        /// An index no interface has had.
        fn fresh(&mut self) -> u32 {
            self.given += 1;
            1000 + self.given
        }

        /// The interface is given another name, and keeps its index. The
        /// name it had is nobody's.
        fn rename(&mut self, old: &str, new: &str) {
            let index = self.index.remove(old).expect("an interface");
            self.missing.push(old.to_string());
            self.missing.retain(|name| name != new);
            self.index.insert(new.to_string(), index);
        }
    }

    struct Bench {
        resolver: Resolver<Mock>,
        mock: Mock,
        now: Instant,
        /// Where a bench that keeps a record keeps it: gone when the
        /// bench is.
        _scratch: Option<Scratch>,
    }

    impl Bench {
        fn new() -> Bench {
            let mock = Mock::default();
            Bench {
                resolver: Resolver::new(mock.clone()),
                mock,
                now: Instant::now(),
                _scratch: None,
            }
        }

        /// A report from the source that runs on the interface of that
        /// name, and the look at what is wanted that follows it. The
        /// source says the interface's index, as every source does.
        async fn report(&mut self, ifname: &str, dns: Option<LinkDns>) {
            self.learn(ifname, dns);
            self.sync().await;
        }

        /// The same from the source of the interface of that index,
        /// whatever it is called by now.
        async fn report_at(&mut self, ifindex: u32, dns: Option<LinkDns>) {
            self.learn_at(ifindex, dns);
            self.sync().await;
        }

        /// What the event loop does after a change, at the bench's time
        /// and not the clock's.
        async fn sync(&mut self) {
            let failed = self.resolver.reconcile().await;
            self.resolver.schedule(failed, self.now);
        }

        /// What the backend has been asked since the last look.
        fn ran(&mut self) -> Vec<Said> {
            std::mem::take(&mut self.mock.0.lock().unwrap().ran)
        }

        /// The index each of them said.
        fn said(&mut self) -> Vec<u32> {
            std::mem::take(&mut self.mock.0.lock().unwrap().said)
        }

        fn answer(&mut self, answers: &[Result<(), Failure>]) {
            self.mock.0.lock().unwrap().answers = answers.iter().cloned().collect();
        }
    }

    fn dns(servers: &[&str], domains: &[&str]) -> LinkDns {
        LinkDns {
            servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    fn set(name: &str, servers: &[&str], domains: &[&str]) -> Vec<Said> {
        let dns = dns(servers, domains);
        vec![
            Said::Dns(name.to_string(), dns.servers),
            Said::Domains(name.to_string(), dns.domains),
        ]
    }

    fn revert(name: &str) -> Vec<Said> {
        vec![Said::Revert(name.to_string())]
    }

    /// The command was started and did not succeed.
    fn failed() -> Result<(), Failure> {
        Err(Failure::Uncertain("no".to_string()))
    }

    /// The command could not be started.
    fn not_run() -> Result<(), Failure> {
        Err(Failure::NotRun("not there".to_string()))
    }

    impl Bench {
        /// The interface is deleted and made again: the same name,
        /// another index.
        fn recreate(&mut self, ifname: &str) {
            let mut script = self.mock.0.lock().unwrap();
            let index = script.fresh();
            script.index.insert(ifname.to_string(), index);
        }

        /// The interface is given another name, now.
        fn rename(&mut self, old: &str, new: &str) {
            self.index(old);
            self.mock.0.lock().unwrap().rename(old, new);
        }

        /// The same, while the next command runs.
        fn rename_at_the_next_command(&mut self, old: &str, new: &str) {
            self.index(old);
            let mut script = self.mock.0.lock().unwrap();
            script.renaming.push((old.to_string(), new.to_string()));
        }

        /// Two interfaces take each other's names while the next command
        /// runs.
        fn exchange_at_the_next_command(&mut self, one: &str, other: &str) {
            self.index(one);
            self.index(other);
            let mut script = self.mock.0.lock().unwrap();
            for (old, new) in [(one, "spare"), (other, one), ("spare", other)] {
                script.renaming.push((old.to_string(), new.to_string()));
            }
        }

        /// The index of the interface of that name.
        fn index(&self, ifname: &str) -> u32 {
            self.mock.0.lock().unwrap().index_of(ifname)
        }

        /// A source's report, without the look at what is wanted that
        /// follows the last of several.
        fn learn(&mut self, ifname: &str, dns: Option<LinkDns>) {
            self.learn_at(self.index(ifname), dns);
        }

        fn learn_at(&mut self, ifindex: u32, dns: Option<LinkDns>) {
            self.resolver.learn(Report {
                ifindex,
                source: Source::Dhcp4,
                dns,
            });
        }
    }

    impl Bench {
        /// A run that keeps its record in `test`'s own place, after one
        /// that left `left` there. `index` says which interfaces there
        /// are now, when not all of `left` as they were.
        fn after(test: &str, left: &[(&str, u32)], index: Option<&[(&str, u32)]>) -> Bench {
            let scratch = Scratch::new(test);
            let path = scratch.path();
            let mut earlier = Record::load(path.clone(), here());
            for (name, ifindex) in left {
                earlier.hold(name, *ifindex);
            }
            let mut b = Bench::new();
            b._scratch = Some(scratch);
            {
                let mut script = b.mock.0.lock().unwrap();
                for (name, ifindex) in index.unwrap_or(left) {
                    script.index.insert(name.to_string(), *ifindex);
                }
                script.record = Some(path);
            }
            b
        }

        /// Take over from the earlier run, with `WAIT` for the sources.
        fn resume(&mut self) {
            let record = Record::load(self.path(), here());
            self.resolver.resume(record, WAIT);
        }

        fn path(&self) -> std::path::PathBuf {
            self.mock.0.lock().unwrap().record.clone().unwrap()
        }

        /// What the record on disk names.
        fn record(&self) -> Vec<(String, u32)> {
            on_record(&self.path())
        }

        /// What it named when each command since the last look was
        /// started.
        fn recorded(&mut self) -> Vec<Vec<(String, u32)>> {
            std::mem::take(&mut self.mock.0.lock().unwrap().recorded)
        }

        /// The wait for the sources is over.
        async fn sweep(&mut self) {
            self.resolver.swept();
            self.sync().await;
        }
    }

    /// How long the benches wait for the sources.
    const WAIT: Duration = Duration::from_secs(120);

    /// A lease lost, or `no-name-server` set, while zebra-rs was not
    /// running: nobody reports the interface, and what the earlier run
    /// set on it is taken back once the sources have had their time.
    #[tokio::test(start_paused = true)]
    async fn what_an_earlier_run_left_is_taken_back_when_the_wait_is_over() {
        let mut b = Bench::after("left", &[(WAN, 7)], None);
        b.resume();
        assert_eq!(b.resolver.sweep, Some(Instant::now() + WAIT));
        // Not before: a source may yet say it has them.
        b.sync().await;
        b.report("wan1", None).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.record(), links(&[(WAN, 7)]));
        // Nor is there anything to try again in the meantime: what is
        // waited for is where it should be.
        assert_eq!(b.resolver.retry, None);

        b.sweep().await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.sweep, None);
        assert_eq!(b.record(), []);
        // Once.
        b.sync().await;
        assert_eq!(b.ran(), []);
    }

    /// The lease resumed from disk says the same servers as before the
    /// restart. They are set all the same, for what the interface holds
    /// is not known, and the end of the wait takes nothing from it.
    #[tokio::test]
    async fn what_is_learned_again_is_set_and_kept() {
        let mut b = Bench::after("learned-again", &[(WAN, 7)], None);
        b.resume();
        b.report(WAN, Some(dns(&["198.51.100.53"], &["example.com"])))
            .await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &["example.com"]));
        b.sweep().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.record(), links(&[(WAN, 7)]));
        // From then on it is this run's, like any other.
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.record(), []);
    }

    /// Learned again and lost within the wait (a resumed lease the
    /// server refuses), it is taken back then and not at the end of the
    /// wait: this run has had it, and knows it is over.
    #[tokio::test]
    async fn learned_again_and_lost_within_the_wait_is_taken_back_at_once() {
        let mut b = Bench::after("lost-in-wait", &[(WAN, 7)], None);
        b.resume();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        b.sweep().await;
        assert_eq!(b.ran(), []);
    }

    /// `--leftover-sweep-time` can be given a number of seconds no
    /// clock counts to, for "never". The wait then has no end, and is
    /// not a time the task cannot start for: nothing is taken back, and
    /// what is learned again is set as ever.
    #[tokio::test]
    async fn a_wait_too_long_to_count_has_no_end() {
        let mut b = Bench::after("endless-wait", &[(WAN, 7), ("wan1", 8)], None);
        let record = Record::load(b.path(), here());
        b.resolver.resume(record, Duration::from_secs(u64::MAX));
        assert_eq!(b.resolver.sweep, None);
        b.sync().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.record(), links(&[(WAN, 7), ("wan1", 8)]));
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        assert_eq!(b.record(), links(&[(WAN, 7), ("wan1", 8)]));
        assert_eq!(b.resolver.retry, None);
    }

    /// A report that is waiting when the wait ends is heard before
    /// anything is taken back. The interface it claims is set, and not
    /// taken back first and set again after, with no name servers in
    /// between. The one nobody claims is taken back.
    #[tokio::test]
    async fn a_report_waiting_when_the_wait_ends_is_heard_first() {
        let mut b = Bench::after("claimed-at-the-end", &[(WAN, 7), ("wan1", 8)], None);
        b.resume();
        let claim = Report {
            ifindex: 7,
            source: Source::Dhcp4,
            dns: Some(dns(&["198.51.100.53"], &[])),
        };
        b.resolver.tx().send(claim).unwrap();
        b.resolver.look(true).await;
        assert_eq!(
            b.ran(),
            [revert("wan1"), set(WAN, &["198.51.100.53"], &[])].concat()
        );
        assert_eq!(b.record(), links(&[(WAN, 7)]));
    }

    /// The same for a try that comes due: what is tried is what is
    /// wanted by then. A lease lost while its servers waited for another
    /// try is not set, to be taken back a moment later.
    #[tokio::test]
    async fn a_report_waiting_when_a_try_comes_due_is_heard_first() {
        let mut b = Bench::new();
        b.answer(&[not_run()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        assert!(b.resolver.retry.is_some());
        let lost = Report {
            ifindex: b.index(WAN),
            source: Source::Dhcp4,
            dns: None,
        };
        b.resolver.tx().send(lost).unwrap();
        b.resolver.look(false).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);
    }

    /// One interface's source being heard is no word about another's:
    /// the look at what is wanted that it brings leaves the other
    /// interface as the earlier run left it, until the wait is over.
    #[tokio::test]
    async fn one_interface_learned_again_leaves_the_other_waiting() {
        let mut b = Bench::after("other-waits", &[(WAN, 7), ("wan1", 8)], None);
        b.resume();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        assert_eq!(b.record(), links(&[(WAN, 7), ("wan1", 8)]));
        assert_eq!(b.resolver.retry, None);
        b.sweep().await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.record(), links(&[(WAN, 7)]));
    }

    /// Search domains alone resolve nothing and set nothing, so they
    /// claim nothing either.
    #[tokio::test]
    async fn domains_alone_do_not_claim_what_an_earlier_run_left() {
        let mut b = Bench::after("domains-alone", &[(WAN, 7)], None);
        b.resume();
        b.report(WAN, Some(dns(&[], &["example.com"]))).await;
        assert_eq!(b.ran(), []);
        b.sweep().await;
        assert_eq!(b.ran(), revert(WAN));
    }

    /// The settings went with the interface. One that is gone, or whose
    /// name is another interface's now, holds nothing of the earlier
    /// run, and a revert would only take away what somebody else gave
    /// the new one.
    #[tokio::test]
    async fn an_interface_that_is_another_now_holds_nothing_of_the_earlier_run() {
        let now = [("wan1", 9)];
        let mut b = Bench::after("another-now", &[(WAN, 7), ("wan1", 8)], Some(&now));
        b.resume();
        assert_eq!(b.resolver.sweep, None);
        // The record drops them at once, not at the next change.
        assert_eq!(b.record(), []);
        b.sweep().await;
        assert_eq!(b.ran(), []);
        // Learned on the new interface, the servers are set on it.
        b.report("wan1", Some(dns(&["203.0.113.53"], &[]))).await;
        assert_eq!(b.ran(), set("wan1", &["203.0.113.53"], &[]));
        assert_eq!(b.record(), links(&[("wan1", 9)]));
    }

    /// The same for one made again while the wait runs.
    #[tokio::test]
    async fn an_interface_made_again_during_the_wait_is_left_alone() {
        let mut b = Bench::after("made-again", &[(WAN, 7), ("wan1", 8)], None);
        b.resume();
        b.recreate(WAN);
        b.sweep().await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.record(), []);
    }

    /// A withdrawal that fails at the end of the wait is tried again
    /// like any other, and the record names the interface until one
    /// works.
    #[tokio::test]
    async fn a_leftover_that_cannot_be_taken_back_is_tried_again() {
        let mut b = Bench::after("tried-again", &[(WAN, 7)], None);
        b.resume();
        b.answer(&[failed()]);
        b.sweep().await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        assert_eq!(b.record(), links(&[(WAN, 7)]));
        b.sync().await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.record(), []);
    }

    /// The interface is made again between that failure and the next
    /// try. The index was right at the end of the wait and is not any
    /// more: the try is not made, for it would revert the new interface,
    /// and the record lets go of the old one.
    #[tokio::test]
    async fn a_leftover_whose_interface_is_made_again_before_the_next_try_is_left_alone() {
        let mut b = Bench::after("made-again-before-retry", &[(WAN, 7)], None);
        b.resume();
        b.answer(&[failed()]);
        b.sweep().await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        assert_eq!(b.record(), links(&[(WAN, 7)]));

        b.recreate(WAN);
        b.sync().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);
        assert_eq!(b.record(), []);
        // Learned on the new interface, the servers are set on it.
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        assert_eq!(b.record(), links(&[(WAN, b.index(WAN))]));
    }

    /// The interface was given another name while zebra-rs was not
    /// running. It is the same interface, with the same index, and the
    /// system resolver has kept its settings. The name on record is no
    /// interface's any more: the index is, under the name it has now,
    /// and its settings are taken back from it.
    #[tokio::test]
    async fn an_interface_renamed_since_the_earlier_run_is_taken_back_under_its_new_name() {
        let mut b = Bench::after("renamed", &[(WAN, 7)], Some(&[("wan1", 7)]));
        b.resume();
        assert!(b.resolver.sweep.is_some());
        // On record under the name it has, at once.
        assert_eq!(b.record(), links(&[("wan1", 7)]));
        b.sync().await;
        assert_eq!(b.ran(), []);
        b.sweep().await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.record(), []);
    }

    /// Reported by a source of this run, which says its index, it is
    /// claimed like any other: set, and kept at the end of the wait.
    #[tokio::test]
    async fn an_interface_renamed_since_the_earlier_run_is_claimed_under_its_new_name() {
        let mut b = Bench::after("renamed-claimed", &[(WAN, 7)], Some(&[("wan1", 7)]));
        b.resume();
        b.report("wan1", Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set("wan1", &["198.51.100.53"], &[]));
        b.sweep().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.record(), links(&[("wan1", 7)]));
    }

    /// The name on record is another interface's by now, and the one
    /// that had it is there under another: the first holds nothing of
    /// ours and is left alone, the second is taken back.
    #[tokio::test]
    async fn a_name_on_record_that_is_another_interface_s_now_is_not_that_interface() {
        let now = [("wan1", 7), (WAN, 9)];
        let mut b = Bench::after("renamed-name-taken", &[(WAN, 7)], Some(&now));
        b.resume();
        b.sweep().await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.record(), []);
    }

    /// Renamed while the wait runs, or between a withdrawal that failed
    /// and its next try: the same. The record goes on saying the name
    /// the interface was noted under, beside the index that is it.
    #[tokio::test]
    async fn an_interface_renamed_during_the_wait_is_taken_back_under_its_new_name() {
        let mut b = Bench::after("renamed-in-wait", &[(WAN, 7)], None);
        b.resume();
        b.rename(WAN, "wan1");
        // Still waited for: a look before the end of the wait takes
        // nothing back.
        b.sync().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.record(), links(&[(WAN, 7)]));
        b.sweep().await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.said(), [7]);
        assert_eq!(b.record(), []);

        let mut b = Bench::after("renamed-before-retry", &[(WAN, 7)], None);
        b.resume();
        b.answer(&[failed()]);
        b.sweep().await;
        assert_eq!(b.ran(), revert(WAN));
        b.rename(WAN, "wan1");
        b.sync().await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.said(), [7, 7]);
        assert_eq!(b.resolver.retry, None);
        assert_eq!(b.record(), []);
    }

    /// An interface renamed under this run. Its source goes on saying
    /// the interface it runs on, by its index, and that is the interface
    /// the system resolver keeps the settings for. Nothing is said to it
    /// for the change of name, at this look or a later one: it holds
    /// what its source has for it. Other servers reach it under the name
    /// it has by then, and a lease that is lost takes them back from it.
    /// The record names it as it was called when it was last set.
    #[tokio::test]
    async fn an_interface_renamed_under_this_run_keeps_what_its_source_says() {
        let mut b = Bench::after("renamed-running", &[], None);
        b.resume();
        let lease = dns(&["198.51.100.53"], &["example.com"]);
        b.report(WAN, Some(lease.clone())).await;
        b.ran();
        b.said();
        let index = b.index(WAN);

        b.rename(WAN, "wan1");
        // The same again from its source (a renewal), and a look that
        // another interface brings.
        b.report_at(index, Some(lease)).await;
        b.report("lan0", None).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);
        assert_eq!(b.record(), links(&[(WAN, index)]));

        b.report_at(index, Some(dns(&["198.51.100.54"], &[]))).await;
        assert_eq!(b.ran(), set("wan1", &["198.51.100.54"], &[]));
        assert_eq!(b.said(), [index, index]);
        assert_eq!(b.record(), links(&[("wan1", index)]));

        b.report_at(index, None).await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.said(), [index]);
        assert_eq!(b.record(), []);
    }

    /// Two interfaces that take each other's names are the interfaces
    /// they were. Their sources say them by index: each keeps what it
    /// holds, nothing is said to either, and each is taken back by
    /// itself, under the name it has by then.
    #[tokio::test]
    async fn interfaces_that_exchange_their_names_keep_what_is_theirs() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.report("wan1", Some(dns(&["203.0.113.53"], &[]))).await;
        b.ran();
        b.said();
        let (first, second) = (b.index(WAN), b.index("wan1"));
        b.rename(WAN, "spare");
        b.rename("wan1", WAN);
        b.rename("spare", "wan1");
        assert_eq!((b.index("wan1"), b.index(WAN)), (first, second));

        b.sync().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);

        // The one that was wan0 loses its lease.
        b.report_at(first, None).await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.said(), [first]);
        // The other holds what it held, and is given no command for
        // being said again.
        b.report_at(second, Some(dns(&["203.0.113.53"], &[]))).await;
        assert_eq!(b.ran(), []);
        b.report_at(second, None).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.said(), [second]);
        assert!(b.resolver.applied.is_empty());
    }

    /// Two interfaces an earlier run left, both still waited for,
    /// exchange their names during the wait. Both are still waited for:
    /// neither is taken back before the wait is over, and both are when
    /// it is.
    #[tokio::test]
    async fn interfaces_that_exchanged_their_names_are_both_still_waited_for() {
        let mut b = Bench::after("exchanged-waiting", &[(WAN, 7), ("wan1", 8)], None);
        b.resume();
        b.rename(WAN, "spare");
        b.rename("wan1", WAN);
        b.rename("spare", "wan1");
        b.sync().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.record(), links(&[(WAN, 7), ("wan1", 8)]));
        // One of them is claimed by its source, and the other is still
        // waited for.
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        assert_eq!(b.said(), [8, 8]);
        b.sweep().await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.said(), [7]);
        assert_eq!(b.record(), links(&[(WAN, 8)]));
    }

    /// Two interfaces take each other's names while a command for one
    /// of them runs. The commands say the index its source reported:
    /// they reach that interface, under whatever name it has by then,
    /// and it holds what it was given. Nothing is said to the other,
    /// which holds what it held. And there is nothing to look at again
    /// for the names having moved: no name was asked for anything, so
    /// none can have been missed.
    #[tokio::test]
    async fn a_name_that_changes_hands_in_mid_command_changes_nothing() {
        // The command works, or it was started and did not.
        for (leg, answer) in [("worked", Ok(())), ("failed", failed())] {
            let mut b = Bench::after(&format!("exchanged-in-mid-command-{leg}"), &[], None);
            b.resume();
            {
                let mut script = b.mock.0.lock().unwrap();
                script.index.insert(WAN.to_string(), 7);
                script.index.insert("wan1".to_string(), 8);
            }
            let other = dns(&["203.0.113.53"], &[]);
            b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
            b.report("wan1", Some(other.clone())).await;
            b.ran();
            b.said();

            b.exchange_at_the_next_command(WAN, "wan1");
            let worked = answer.is_ok();
            b.answer(&[answer]);
            b.report_at(7, Some(dns(&["198.51.100.54"], &[]))).await;
            assert_eq!((b.index(WAN), b.index("wan1")), (8, 7), "{leg}");
            // Every command of the attempt said 7: the servers' and,
            // where that worked, the domains'. Nothing was said to 8.
            let said = if worked { vec![7, 7] } else { vec![7] };
            assert_eq!(b.said(), said, "{leg}");
            assert_eq!(b.record(), links(&[(WAN, 7), ("wan1", 8)]), "{leg}");
            // Only a command that failed is tried again.
            assert_eq!(b.resolver.retry.is_some(), !worked, "{leg}");
            b.ran();

            // 8 holds what it held: said again by its source, it is
            // given no command. The look that brings takes up the
            // command that failed, for 7 alone.
            b.report_at(8, Some(other)).await;
            if worked {
                assert_eq!(b.ran(), [], "{leg}");
            } else {
                assert_eq!(b.ran(), set("wan1", &["198.51.100.54"], &[]), "{leg}");
                assert_eq!(b.said(), [7, 7], "{leg}");
            }
            assert!(b.resolver.retry.is_none(), "{leg}");
        }
    }

    /// Two interfaces that are both to be taken back exchange their
    /// names while the first withdrawal runs. Each withdrawal says its
    /// interface's index and reaches that one: both are taken back, each
    /// once, though both commands were started under the same name.
    #[tokio::test]
    async fn interfaces_that_exchange_their_names_in_mid_withdrawal_are_both_taken_back() {
        let mut b = Bench::after("exchanged-in-mid-withdrawal", &[], None);
        b.resume();
        {
            let mut script = b.mock.0.lock().unwrap();
            script.index.insert(WAN.to_string(), 7);
            script.index.insert("wan1".to_string(), 8);
        }
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.report("wan1", Some(dns(&["203.0.113.53"], &[]))).await;
        b.ran();
        b.said();

        b.exchange_at_the_next_command(WAN, "wan1");
        b.learn(WAN, None);
        b.learn("wan1", None);
        b.sync().await;
        assert_eq!((b.index(WAN), b.index("wan1")), (8, 7));
        // 7 while it was wan0, and 8 once it was.
        assert_eq!(b.ran(), [revert(WAN), revert(WAN)].concat());
        assert_eq!(b.said(), [7, 8]);
        assert_eq!(b.record(), []);
        assert!(b.resolver.applied.is_empty());
        assert!(b.resolver.retry.is_none());
    }

    /// The same exchange while one interface is taken back and the
    /// other keeps what it holds. The withdrawal says its interface's
    /// index: it reaches that one and no other, whether it works or was
    /// started and did not. The one that keeps its servers holds them
    /// still, and is given no command when its source says them again.
    #[tokio::test]
    async fn a_withdrawal_reaches_its_own_interface_and_no_other() {
        for (leg, answer) in [("worked", Ok(())), ("failed", failed())] {
            let mut b = Bench::after(&format!("withdrawal-reaches-its-own-{leg}"), &[], None);
            b.resume();
            {
                let mut script = b.mock.0.lock().unwrap();
                script.index.insert(WAN.to_string(), 7);
                script.index.insert("wan1".to_string(), 8);
            }
            b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
            b.report("wan1", Some(dns(&["203.0.113.53"], &[]))).await;
            b.ran();
            b.said();

            b.exchange_at_the_next_command(WAN, "wan1");
            let worked = answer.is_ok();
            b.answer(&[answer]);
            b.report_at(7, None).await;
            assert_eq!((b.index(WAN), b.index("wan1")), (8, 7), "{leg}");
            assert_eq!(b.ran(), revert(WAN), "{leg}");
            assert_eq!(b.said(), [7], "{leg}");
            // Only a withdrawal that failed is tried again.
            assert_eq!(b.resolver.retry.is_some(), !worked, "{leg}");

            b.report_at(8, Some(dns(&["203.0.113.53"], &[]))).await;
            if worked {
                assert_eq!(b.ran(), [], "{leg}");
            } else {
                assert_eq!(b.ran(), revert("wan1"), "{leg}");
                assert_eq!(b.said(), [7], "{leg}");
            }
            assert_eq!(b.record(), links(&[("wan1", 8)]), "{leg}");
            assert!(b.resolver.retry.is_none(), "{leg}");
        }
    }

    /// An interface is renamed while its own withdrawal runs. The
    /// withdrawal said its index and has reached it: once is enough.
    #[tokio::test]
    async fn an_interface_renamed_in_mid_withdrawal_is_taken_back_once() {
        let mut b = Bench::after("renamed-in-mid-withdrawal", &[], None);
        b.resume();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();

        b.rename_at_the_next_command(WAN, "wanx");
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.record(), []);
        assert!(b.resolver.applied.is_empty());
        assert!(b.resolver.retry.is_none());
    }

    /// An interface is renamed while its own command runs. The commands
    /// say its index and reach it under the name it has by then: it
    /// holds what it was given, and keeps it, for its source wants it on
    /// that interface whatever it is called. Nothing follows by itself.
    #[tokio::test]
    async fn an_interface_renamed_in_mid_command_keeps_what_it_is_given() {
        let mut b = Bench::after("renamed-in-mid-command", &[], None);
        b.resume();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.said();
        let index = b.index(WAN);

        b.rename_at_the_next_command(WAN, "wanx");
        b.report(WAN, Some(dns(&["198.51.100.54"], &["example.net"])))
            .await;
        assert_eq!(
            b.ran(),
            [
                set(WAN, &["198.51.100.54"], &["example.net"])[..1].to_vec(),
                set("wanx", &["198.51.100.54"], &["example.net"])[1..].to_vec()
            ]
            .concat()
        );
        assert_eq!(b.said(), [index, index]);
        assert!(b.resolver.retry.is_none());
        b.sync().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.record(), links(&[(WAN, index)]));

        // Until its source has nothing for it any more.
        b.report_at(index, None).await;
        assert_eq!(b.ran(), revert("wanx"));
        assert_eq!(b.said(), [index]);
        assert_eq!(b.record(), []);
    }

    /// Two interfaces exchange their names while a command for one of
    /// them runs, and the other is not ours: it was never set. No
    /// command says its index, so it is given nothing, noted for
    /// nothing and never on record, though it has the name the commands
    /// began under.
    #[tokio::test]
    async fn an_exchange_in_mid_command_leaves_the_other_interface_alone() {
        let mut b = Bench::after("untracked-took-the-name", &[], None);
        b.resume();
        {
            let mut script = b.mock.0.lock().unwrap();
            script.index.insert(WAN.to_string(), 7);
            script.index.insert("wan1".to_string(), 8);
        }

        b.exchange_at_the_next_command(WAN, "wan1");
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!((b.index(WAN), b.index("wan1")), (8, 7));
        assert_eq!(b.said(), [7, 7]);
        assert_eq!(b.recorded(), [links(&[(WAN, 7)]), links(&[(WAN, 7)])]);
        assert_eq!(b.record(), links(&[(WAN, 7)]));
        let noted: Vec<u32> = b.resolver.applied.keys().copied().collect();
        assert_eq!(noted, [7]);
        assert!(b.resolver.retry.is_none());
        b.ran();
        b.sync().await;
        assert_eq!(b.ran(), []);

        // The lease is lost: the one interface that was given something
        // is taken back, under the name it has.
        b.report_at(7, None).await;
        assert_eq!(b.ran(), revert("wan1"));
        assert_eq!(b.said(), [7]);
        assert_eq!(b.record(), []);
    }

    /// An interface is deleted and made again while its command runs.
    /// The command said the index of the one that is gone, and so does
    /// the next: the system resolver knows no such link, and the new
    /// interface is given nothing by either. That the command failed is
    /// the old interface going, and the end of it: nothing is tried
    /// again. The new one is another interface, and is set when its
    /// source, which hears of both from the RIB, reports it.
    #[tokio::test]
    async fn an_interface_made_again_in_mid_command_is_set_when_its_source_says_so() {
        let mut b = Bench::after("made-again-in-mid-command", &[], None);
        b.resume();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.said();
        let was = b.index(WAN);

        b.mock.0.lock().unwrap().remaking.push(WAN.to_string());
        let lease = dns(&["198.51.100.54"], &["example.net"]);
        b.report(WAN, Some(lease.clone())).await;
        let is = b.index(WAN);
        assert_ne!(is, was);
        assert_eq!(b.said(), [was, was]);
        assert_eq!(
            b.ran(),
            [
                Said::Dns(WAN.to_string(), vec!["198.51.100.54".parse().unwrap()]),
                Said::Domains(format!("#{was}"), vec!["example.net".to_string()])
            ]
        );
        assert!(b.resolver.retry.is_none());
        assert!(b.resolver.applied.is_empty());
        assert_eq!(b.record(), []);

        b.learn_at(was, None);
        b.learn_at(is, Some(lease));
        b.sync().await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.54"], &["example.net"]));
        assert_eq!(b.said(), [is, is]);
        assert_eq!(b.record(), links(&[(WAN, is)]));
        assert!(b.resolver.retry.is_none());
    }

    /// A record that cannot be written (a full disk, a state directory
    /// in the making) does not keep the servers from the host. But an
    /// interface that is set and not on disk is one the next run would
    /// not take back: the write is tried again like a failed command,
    /// with no change to bring it.
    #[tokio::test]
    async fn a_record_that_could_not_be_written_is_tried_again() {
        let mut b = Bench::after("unwritten", &[], None);
        b.resume();
        b.mock.0.lock().unwrap().index.insert(WAN.to_string(), 7);
        // In the way of the record's directory: a file.
        let path = b.path();
        let dir = path.parent().unwrap();
        std::fs::write(dir, b"").unwrap();

        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        assert_eq!(b.record(), []);
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        // Still in the way: tried again, later each time.
        b.sync().await;
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN * 2));

        std::fs::remove_file(dir).unwrap();
        b.sync().await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.record(), links(&[(WAN, 7)]));
        assert_eq!(b.resolver.retry, None);
        assert_eq!(b.resolver.backoff, RETRY_MIN);
    }

    /// A record of another boot, or none: nothing to wait for.
    #[tokio::test]
    async fn a_run_with_nothing_left_to_it_waits_for_nothing() {
        let mut b = Bench::after("nothing-left", &[], None);
        b.resume();
        assert_eq!(b.resolver.sweep, None);
        b.sweep().await;
        assert_eq!(b.ran(), []);
    }

    /// The interface is on record before the first command that may
    /// give it something is started. A run ended while `resolvectl` is
    /// under way cannot say how that went, and the next one must find
    /// the interface named.
    #[tokio::test]
    async fn an_interface_is_on_record_before_its_first_command() {
        let mut b = Bench::after("before-command", &[], None);
        b.resume();
        b.mock.0.lock().unwrap().index.insert(WAN.to_string(), 7);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran().len(), 2);
        let named = links(&[(WAN, 7)]);
        assert_eq!(b.recorded(), [named.clone(), named.clone()]);
        // And until the withdrawal has worked: named while it runs, not
        // after it.
        b.report(WAN, None).await;
        assert_eq!(b.recorded(), [named]);
        assert_eq!(b.record(), []);
    }

    /// The run that was ended while its command was under way: the
    /// record names the interface, and the next run takes back what the
    /// command may have set.
    #[tokio::test]
    async fn what_a_run_ended_in_mid_command_left_is_taken_back() {
        let mut b = Bench::after("mid-command", &[], None);
        b.resume();
        b.mock.0.lock().unwrap().index.insert(WAN.to_string(), 7);
        // Ended in the command: all that is left of that run is what
        // the record said when the command was started.
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        let at_command = b.recorded().remove(0);
        assert_eq!(at_command, links(&[(WAN, 7)]));

        let left: Vec<(&str, u32)> = at_command.iter().map(|(n, i)| (n.as_str(), *i)).collect();
        let mut next = Bench::after("mid-command", &left, None);
        next.resume();
        next.sweep().await;
        assert_eq!(next.ran(), revert(WAN));
    }

    /// A command that was started and did not succeed may have set
    /// something: the interface stays on record, for this run to take
    /// back or the next.
    #[tokio::test]
    async fn an_interface_a_command_may_have_set_stays_on_record() {
        let mut b = Bench::after("may-have-set", &[], None);
        b.resume();
        b.mock.0.lock().unwrap().index.insert(WAN.to_string(), 7);
        b.answer(&[failed()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.record(), links(&[(WAN, 7)]));
    }

    /// On a host without `resolvectl` there is nothing to start, time
    /// after time. That is seen by looking, before each command: none is
    /// made, and the interface, which holds nothing, is never put on
    /// record. The file is not written and put right again with every
    /// try. It is not written at all.
    #[tokio::test]
    async fn a_host_without_the_program_keeps_no_record() {
        let mut b = Bench::after("no-program", &[], None);
        b.resume();
        {
            let mut script = b.mock.0.lock().unwrap();
            script.index.insert(WAN.to_string(), 7);
            script.absent = true;
        }
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        // Tried again all the same: the program may come.
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        for _ in 0..3 {
            b.sync().await;
        }
        assert_eq!(b.ran(), []);
        assert!(!b.path().exists());

        // It has come: the interface is on record before the first
        // command that can give it something.
        b.mock.0.lock().unwrap().absent = false;
        b.sync().await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        let named = links(&[(WAN, 7)]);
        assert_eq!(b.recorded(), [named.clone(), named.clone()]);
        assert_eq!(b.record(), named);
    }

    /// A command that could not be started although its program was
    /// found (no process to be had, just then) set nothing, and the
    /// record says so again. It says nothing about the next try, which
    /// is on record before it is started like any other: it may well
    /// work, and the run be ended before the record is put right.
    #[tokio::test]
    async fn a_try_after_one_that_could_not_be_started_is_on_record_first() {
        let mut b = Bench::after("after-not-run", &[], None);
        b.resume();
        b.mock.0.lock().unwrap().index.insert(WAN.to_string(), 7);
        let named = links(&[(WAN, 7)]);
        for _ in 0..3 {
            b.answer(&[not_run()]);
            b.learn(WAN, Some(dns(&["198.51.100.53"], &[])));
            b.sync().await;
            assert_eq!(b.recorded(), std::slice::from_ref(&named));
            assert_eq!(b.record(), []);
        }
        // Ended in the next command: all that is left of that run is
        // what the record said when the command was started.
        b.sync().await;
        assert_eq!(b.recorded()[0], named);

        // And the one after it takes back what the command set.
        let mut next = Bench::after("after-not-run", &[(WAN, 7)], None);
        next.resume();
        next.sweep().await;
        assert_eq!(next.ran(), revert(WAN));
    }

    /// The program goes while an interface holds something. Nothing is
    /// started to take it back, the interface stays noted and on record,
    /// and the withdrawal is made when there is a program again.
    #[tokio::test]
    async fn a_withdrawal_with_no_program_to_run_waits_for_one() {
        let mut b = Bench::after("no-program-revert", &[], None);
        b.resume();
        b.mock.0.lock().unwrap().index.insert(WAN.to_string(), 7);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.mock.0.lock().unwrap().absent = true;
        b.report(WAN, None).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        assert_eq!(b.record(), links(&[(WAN, 7)]));

        b.mock.0.lock().unwrap().absent = false;
        b.sync().await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, None);
        assert_eq!(b.record(), []);
    }

    /// Not ours to configure: no interface holds anything, and the one
    /// named ahead of the refused command is taken off the record.
    #[tokio::test]
    async fn a_refusal_leaves_nothing_on_record() {
        let mut b = Bench::after("refused", &[], None);
        b.resume();
        b.mock.0.lock().unwrap().index.insert(WAN.to_string(), 7);
        b.answer(&[Err(Failure::Refused("not here".to_string()))]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.record(), []);
    }

    /// A zebra-rs that may not configure the system resolver (in
    /// another network namespace, or not root) has set nothing. The
    /// record in the state directory, which it shares with the one that
    /// may, is that one's: it is not taken over, and it is not written,
    /// neither without the interfaces that are not there in this
    /// namespace nor with the ones this zebra-rs would have set.
    #[tokio::test]
    async fn a_resolver_that_is_not_ours_leaves_the_record_alone() {
        // One of the other's interfaces has a namesake here, with the
        // same index, and one has not.
        let other = [(WAN, 7), ("wan1", 8)];
        let mut b = Bench::after("not-ours", &other, Some(&[(WAN, 7)]));
        {
            let mut script = b.mock.0.lock().unwrap();
            script.index.insert("wan2".to_string(), 9);
            script.refuses = true;
        }
        b.resume();
        assert_eq!(b.resolver.sweep, None);
        assert_eq!(b.record(), links(&other));
        b.sweep().await;
        assert_eq!(b.ran(), []);

        // Its own interface learns name servers: refused, as ever,
        // with no command made, and the record still names what it
        // named.
        b.report("wan2", Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), []);
        assert!(b.resolver.refused);
        assert_eq!(b.record(), links(&other));
    }

    /// An interface that is gone when its report is looked at (its
    /// source has not heard of that yet) is said nothing: its index is
    /// nobody's. Nothing is put on record, and nothing is tried again:
    /// what comes under its name is another interface, and its source
    /// reports that one. Of this one it says in its own time that it
    /// has nothing.
    #[tokio::test]
    async fn an_interface_that_is_gone_is_said_nothing() {
        let mut b = Bench::after("not-there", &[], None);
        b.resume();
        b.mock.0.lock().unwrap().missing.push(WAN.to_string());
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.recorded(), Vec::<Vec<(String, u32)>>::new());
        assert_eq!(b.record(), []);
        assert!(!b.path().exists());
        assert_eq!(b.resolver.retry, None);
        b.sync().await;
        b.report(WAN, None).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);

        // One that holds something and is to be given other servers
        // when it is gone: what it held went with it.
        let mut b = Bench::after("gone-before-a-change", &[], None);
        b.resume();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.mock.0.lock().unwrap().missing.push(WAN.to_string());
        b.report(WAN, Some(dns(&["198.51.100.54"], &[]))).await;
        assert_eq!(b.ran(), []);
        assert!(b.resolver.applied.is_empty());
        assert_eq!(b.record(), []);
        assert_eq!(b.resolver.retry, None);
    }

    /// The task itself: the end of the wait comes by the clock, with
    /// no report to bring it, and takes back what nothing has claimed.
    #[tokio::test(start_paused = true)]
    async fn the_task_takes_back_at_the_end_of_its_wait_what_nothing_claimed() {
        let mut b = Bench::after("task-sweep", &[(WAN, 7), ("wan1", 8)], None);
        b.resume();
        let Bench { resolver, mock, .. } = b;
        let tx = resolver.tx();
        let _task = serve(resolver);
        let ran = |mock: &Mock| std::mem::take(&mut mock.0.lock().unwrap().ran);

        tx.send(Report {
            ifindex: 7,
            source: Source::Dhcp4,
            dns: Some(dns(&["198.51.100.53"], &[])),
        })
        .unwrap();
        tokio::time::sleep(WAIT - Duration::from_secs(1)).await;
        assert_eq!(ran(&mock), set(WAN, &["198.51.100.53"], &[]));
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(ran(&mock), revert("wan1"));
        // Once, and the wait is not begun again.
        tokio::time::sleep(WAIT * 3).await;
        assert_eq!(ran(&mock), []);
    }

    /// No configuration names the interface: that a source reports its
    /// name servers is the word that the host is to use them.
    #[tokio::test]
    async fn what_an_interface_learns_is_set_once() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        // No domains is said too: it clears the ones set before.
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        // The same again (a renewal), and word of another interface
        // that brings nothing to set.
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.report("wan1", Some(dns(&[], &["example.org"]))).await;
        assert_eq!(b.ran(), []);
        // Other servers.
        b.report(WAN, Some(dns(&["198.51.100.54"], &["example.net"])))
            .await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.54"], &["example.net"]));
    }

    /// A lease that ends, or an interface told to keep its name servers
    /// from the host: the source says it has nothing, either way.
    #[tokio::test]
    async fn what_a_source_no_longer_has_is_taken_back() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        // Nothing is held any more, so nothing more is taken back.
        b.report(WAN, None).await;
        assert_eq!(b.ran(), []);
        // Learned again, it is set again.
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
    }

    #[tokio::test]
    async fn every_interface_is_set_and_taken_back_by_itself() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.report("wan1", Some(dns(&["203.0.113.53"], &["example.net"])))
            .await;
        assert_eq!(
            b.ran(),
            [
                set(WAN, &["198.51.100.53"], &[]),
                set("wan1", &["203.0.113.53"], &["example.net"])
            ]
            .concat()
        );
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        // Both at once, as when the task's inbox holds several reports.
        b.learn(WAN, Some(dns(&["198.51.100.53"], &[])));
        b.learn("wan1", None);
        b.sync().await;
        assert_eq!(
            b.ran(),
            [revert("wan1"), set(WAN, &["198.51.100.53"], &[])].concat()
        );
    }

    #[tokio::test]
    async fn a_lease_with_no_usable_server_sets_nothing() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&[], &["example.com"]))).await;
        b.report(WAN, Some(dns(&["0.0.0.0", "127.0.0.53"], &[])))
            .await;
        assert_eq!(b.ran(), []);
        // And one that loses its servers gives up what it had set.
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.report(WAN, Some(dns(&[], &["example.com"]))).await;
        assert_eq!(b.ran(), revert(WAN));
    }

    #[tokio::test]
    async fn a_failed_command_is_tried_again_later() {
        let mut b = Bench::new();
        b.answer(&[failed()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        // The servers failed, so the domains were not tried.
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[])[..1]);
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));

        // Again, and it fails again: the wait doubles.
        b.answer(&[failed()]);
        b.now += RETRY_MIN;
        b.sync().await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[])[..1]);
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN * 2));

        // Then it works, and nothing more is due.
        b.now += RETRY_MIN * 2;
        b.sync().await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        assert_eq!(b.resolver.retry, None);
        assert_eq!(b.resolver.backoff, RETRY_MIN);
        b.sync().await;
        assert_eq!(b.ran(), []);
    }

    #[tokio::test]
    async fn the_wait_between_tries_stops_growing() {
        let mut b = Bench::new();
        b.learn(WAN, Some(dns(&["198.51.100.53"], &[])));
        for _ in 0..12 {
            b.answer(&[failed()]);
            b.sync().await;
        }
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MAX));
    }

    #[tokio::test]
    async fn servers_set_without_their_domains_are_still_taken_back() {
        let mut b = Bench::new();
        // The servers go in, the domains fail.
        b.answer(&[Ok(()), failed()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &["example.com"])))
            .await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &["example.com"]));
        // Not wanted any more before a try has worked.
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
    }

    /// A command that could not be started set nothing, so there is
    /// nothing to take back: a host without `resolvectl` is not asked to
    /// revert, time after time, what it never held.
    #[tokio::test]
    async fn a_command_that_could_not_be_started_leaves_nothing_to_take_back() {
        let mut b = Bench::new();
        b.answer(&[not_run()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[])[..1]);
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        b.report(WAN, None).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);
    }

    #[tokio::test]
    async fn a_failed_withdrawal_is_tried_again_while_the_interface_is_there() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.answer(&[failed()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        b.sync().await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, None);
    }

    /// The interface goes while the withdrawal runs, which fails for
    /// it: the settings went with it, and there is nothing to try again.
    #[tokio::test]
    async fn a_failed_withdrawal_on_a_deleted_interface_is_the_end_of_it() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.mock.0.lock().unwrap().leaving.push(WAN.to_string());
        b.answer(&[failed()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, None);
        b.sync().await;
        assert_eq!(b.ran(), []);
    }

    /// Gone before the withdrawal, there is nothing to ask for.
    #[tokio::test]
    async fn nothing_is_withdrawn_from_an_interface_that_is_gone() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.mock.0.lock().unwrap().missing.push(WAN.to_string());
        b.report(WAN, None).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);
        assert!(b.resolver.applied.is_empty());
    }

    /// Nor from one that was deleted and made again since it was set:
    /// the new interface has another index, which nothing was ever said
    /// to, and what somebody else has given it is not ours to take.
    #[tokio::test]
    async fn nothing_is_withdrawn_from_an_interface_made_again_since() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        let was = b.index(WAN);
        b.recreate(WAN);
        b.report_at(was, None).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);
        assert!(b.resolver.applied.is_empty());
    }

    /// The same between a withdrawal that failed and its next try,
    /// which can be minutes later: the try is not made on the interface
    /// that has the name by then.
    #[tokio::test]
    async fn a_failed_withdrawal_is_not_tried_again_on_an_interface_made_again() {
        for failure in [failed(), not_run()] {
            let mut b = Bench::new();
            b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
            b.ran();
            b.answer(&[failure]);
            b.report(WAN, None).await;
            assert_eq!(b.ran(), revert(WAN));
            assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));

            b.recreate(WAN);
            b.sync().await;
            assert_eq!(b.ran(), []);
            assert_eq!(b.resolver.retry, None);
            assert!(b.resolver.applied.is_empty());
        }
    }

    #[tokio::test]
    async fn a_refusal_ends_every_further_command() {
        let mut b = Bench::new();
        b.answer(&[Err(Failure::Refused("not here".to_string()))]);
        b.learn("wan1", Some(dns(&["203.0.113.53"], &[])));
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        // The first command was refused; the other interface is not tried.
        assert_eq!(b.ran().len(), 1);
        assert_eq!(b.resolver.retry, None);
        b.report(WAN, Some(dns(&["198.51.100.54"], &[]))).await;
        b.report(WAN, None).await;
        assert_eq!(b.ran(), []);
    }

    /// The lease goes with its interface and comes back, the same, on
    /// the interface made again under that name. Its source says so of
    /// each, by index, and both reports are taken in before either is
    /// acted on: the settings went with the old interface, and the new
    /// one is given them.
    #[tokio::test]
    async fn an_interface_made_again_is_given_its_name_servers_again() {
        let mut b = Bench::new();
        let lease = dns(&["198.51.100.53"], &["example.com"]);
        b.report(WAN, Some(lease.clone())).await;
        b.ran();

        let was = b.index(WAN);
        b.recreate(WAN);
        b.learn_at(was, None);
        b.learn(WAN, Some(lease.clone()));
        b.sync().await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &["example.com"]));
        // Once: the new interface holds them now.
        b.sync().await;
        assert_eq!(b.ran(), []);

        // The same interface losing and finding the same lease has
        // lost nothing, and is not set again.
        b.learn(WAN, None);
        b.learn(WAN, Some(lease));
        b.sync().await;
        assert_eq!(b.ran(), []);
    }

    /// The same, when the withdrawal was acted on by itself and could
    /// not be started, and the interface is made again before its next
    /// try. The entry it leaves, to be tried again, says the servers are
    /// held: by the old interface, which is no reason to leave the new
    /// one unset.
    #[tokio::test]
    async fn an_interface_made_again_after_a_failed_withdrawal_is_given_them_too() {
        let mut b = Bench::new();
        let lease = dns(&["198.51.100.53"], &[]);
        b.report(WAN, Some(lease.clone())).await;
        b.ran();

        b.answer(&[not_run()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        b.recreate(WAN);
        b.report(WAN, Some(lease)).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
    }

    /// A command that was started and did not report success may have
    /// been carried out. The servers it asked for are ours to take back,
    /// should they stop being wanted before a try has succeeded.
    #[tokio::test]
    async fn servers_a_command_may_have_set_are_taken_back() {
        let mut b = Bench::new();
        b.answer(&[failed()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        // No success for the servers, so the domains were not tried.
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[])[..1]);
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, None);
        b.sync().await;
        assert_eq!(b.ran(), []);
    }

    /// Still wanted, they are asked for again.
    #[tokio::test]
    async fn servers_a_command_may_have_set_are_asked_for_again() {
        let mut b = Bench::new();
        b.answer(&[failed()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.sync().await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        assert_eq!(b.resolver.retry, None);
    }

    /// New servers whose command did not succeed leave it open what the
    /// system resolver holds: the new ones, the old ones, or none at
    /// all, for resolved drops the list it was replacing before it
    /// reports that it could not add to the new one. So the old servers,
    /// wanted again before a try has succeeded, are not taken for held:
    /// they are set.
    #[tokio::test]
    async fn a_change_that_did_not_succeed_leaves_nothing_taken_for_held() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.answer(&[failed()]);
        b.report(WAN, Some(dns(&["198.51.100.54"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.54"], &[])[..1]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
    }

    /// New servers whose command could not be started leave the old
    /// ones in, and those, wanted again, are held.
    #[tokio::test]
    async fn a_change_that_could_not_be_started_leaves_the_old_servers_held() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.answer(&[not_run()]);
        b.report(WAN, Some(dns(&["198.51.100.54"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.54"], &[])[..1]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), []);
        // And they are still ours to take back.
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
    }

    /// A withdrawal that was started and did not report success may
    /// have been carried out. The servers wanted again before a later
    /// try has succeeded are not taken for held: they are set.
    #[tokio::test]
    async fn a_withdrawal_that_did_not_succeed_leaves_nothing_taken_for_held() {
        let mut b = Bench::new();
        let lease = dns(&["198.51.100.53"], &["example.com"]);
        b.report(WAN, Some(lease.clone())).await;
        b.ran();
        b.answer(&[failed()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        b.report(WAN, Some(lease)).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &["example.com"]));
    }

    /// One that could not be started changed nothing: the servers are
    /// still in, and wanted again they are held.
    #[tokio::test]
    async fn a_withdrawal_that_could_not_be_started_leaves_the_servers_held() {
        let mut b = Bench::new();
        let lease = dns(&["198.51.100.53"], &[]);
        b.report(WAN, Some(lease.clone())).await;
        b.ran();
        b.answer(&[not_run()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        b.report(WAN, Some(lease)).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);
    }

    /// The wait before the next try counts from the end of the commands.
    /// A command that runs into its time limit takes longer than the
    /// first waits: counted from before it, they were over when it
    /// ended, and the next try followed at once, time after time.
    #[tokio::test(start_paused = true)]
    async fn the_wait_before_a_retry_starts_when_the_commands_are_over() {
        let mut b = Bench::new();
        b.learn(WAN, Some(dns(&["198.51.100.53"], &[])));
        b.mock.0.lock().unwrap().takes = Duration::from_secs(10);
        b.answer(&[failed()]);
        let began = Instant::now();
        b.resolver.sync().await;
        assert_eq!(Instant::now(), began + Duration::from_secs(10));
        assert_eq!(b.resolver.retry, Some(Instant::now() + RETRY_MIN));
    }

    /// What DHCP says goes ahead of what Router Advertisements say (RFC
    /// 8106 §5.3.1), a DHCPv4 lease ahead of a DHCPv6 one, each in its
    /// own order, and what several say is said once.
    #[test]
    fn dhcp_goes_ahead_of_router_advertisements() {
        let mut sources = BTreeMap::new();
        // Taken in the other way round: the order is the sources'.
        sources.insert(
            Source::Ra,
            dns(
                &["2001:db8::99", "2001:db8::11", "198.51.100.53"],
                &["ra.example", "example.com"],
            ),
        );
        sources.insert(
            Source::Dhcp6,
            dns(
                &["2001:db8:53::53", "2001:db8::11"],
                &["v6.example", "example.com"],
            ),
        );
        sources.insert(
            Source::Dhcp4,
            dns(&["198.51.100.53", "198.51.100.54"], &["example.com"]),
        );
        assert_eq!(
            merge(&sources),
            dns(
                &[
                    "198.51.100.53",
                    "198.51.100.54",
                    "2001:db8:53::53",
                    "2001:db8::11",
                    "2001:db8::99",
                ],
                &["example.com", "v6.example", "ra.example"]
            )
        );
    }

    /// One source going leaves the other's, and the interface is set
    /// with what is left; the last one going takes everything back.
    #[tokio::test]
    async fn an_interface_keeps_what_its_other_source_says() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &["example.com"])))
            .await;
        b.ran();
        let ifindex = b.index(WAN);
        let ra = |b: &mut Bench, dns: Option<LinkDns>| {
            b.resolver.learn(Report {
                ifindex,
                source: Source::Ra,
                dns,
            });
        };
        ra(&mut b, Some(dns(&["2001:db8::53"], &[])));
        b.sync().await;
        assert_eq!(
            b.ran(),
            set(WAN, &["198.51.100.53", "2001:db8::53"], &["example.com"])
        );
        // The lease ends; the RA's server stays.
        b.report(WAN, None).await;
        assert_eq!(b.ran(), set(WAN, &["2001:db8::53"], &[]));
        ra(&mut b, None);
        b.sync().await;
        assert_eq!(b.ran(), revert(WAN));
    }

    #[test]
    fn sources_merge_into_one_list_without_repeats() {
        // The merge of one source: its own repeats go too.
        let mut sources = BTreeMap::new();
        sources.insert(
            Source::Dhcp4,
            dns(
                &["198.51.100.53", "198.51.100.54", "198.51.100.53"],
                &["example.com", "Example.COM", "example.net."],
            ),
        );
        assert_eq!(
            merge(&sources),
            dns(
                &["198.51.100.53", "198.51.100.54"],
                &["example.com", "example.net"]
            )
        );
    }

    #[test]
    fn only_addresses_a_server_can_have_are_used() {
        for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
            assert!(!usable_server(&bad.parse().unwrap()), "{bad}");
        }
        for bad in ["::", "::1", "ff02::1"] {
            assert!(!usable_server(&bad.parse().unwrap()), "{bad}");
        }
        for good in ["198.51.100.53", "10.0.0.1", "2001:db8::53", "fe80::1"] {
            assert!(usable_server(&good.parse().unwrap()), "{good}");
        }
    }

    #[test]
    fn only_domain_names_are_search_domains() {
        assert_eq!(usable_domain("example.com"), Some("example.com"));
        assert_eq!(usable_domain("example.com."), Some("example.com"));
        assert_eq!(usable_domain("a-b.x_y.example"), Some("a-b.x_y.example"));
        assert_eq!(usable_domain("lan"), Some("lan"));
        let long_label = "a".repeat(64);
        let long_name = vec!["a".repeat(63); 4].join(".");
        for bad in [
            "",
            ".",
            "~.",
            "~example.com",
            "-example.com",
            "example-.com",
            "exa mple.com",
            "example..com",
            ".example.com",
            "--help",
            "example.com;id",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert_eq!(usable_domain(bad), None, "{bad:?}");
        }
        assert_eq!(long_name.len(), 255);
    }

    /// No time is promised that never comes: where the wait has no
    /// end, the interface is said to keep what it holds.
    #[test]
    fn what_is_said_of_a_leftover_is_what_becomes_of_it() {
        assert_eq!(
            taken_over("wan0", "wan0", Some(Duration::from_secs(120))),
            "wan0: holds name servers of an earlier run, taken back in 120 s unless learned again"
        );
        assert_eq!(
            taken_over("wanx", "wan0", Some(Duration::from_secs(5))),
            "wanx: holds name servers of an earlier run (as wan0), taken back in 5 s unless learned again"
        );
        assert_eq!(
            taken_over("wan0", "wan0", None),
            "wan0: holds name servers of an earlier run, and keeps them: the wait for the sources has no end"
        );
    }

    #[test]
    fn the_log_line_names_servers_and_domains() {
        assert_eq!(
            describe(&dns(&["198.51.100.53", "2001:db8::53"], &[])),
            "name servers 198.51.100.53 2001:db8::53"
        );
        assert_eq!(
            describe(&dns(&["198.51.100.53"], &["example.com", "example.net"])),
            "name servers 198.51.100.53, search example.com example.net"
        );
    }
}
