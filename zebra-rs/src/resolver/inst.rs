//! The resolver task: which interfaces' name servers the host uses
//! (`system name-server dhcp <if>`), what the sources have learned on
//! each, and what the system resolver has been given.
//!
//! Every change, of the configuration or of what a source knows, ends in
//! [`Resolver::sync`]: it works out what the system resolver should hold
//! and has the [`Backend`] make up the difference, one command at a
//! time. A command that fails is tried again later, so a resolver that
//! starts after zebra-rs still gets its servers.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::time::{Instant, sleep_until};

use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, path_from_command};
use crate::context::Task;

use super::{LinkDns, Report, ResolverTx, Source};

/// How long after a failed command the next try comes: this at first,
/// twice as long after every further failure, up to [`RETRY_MAX`].
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(300);

/// One change to the system resolver's configuration of an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// These are the interface's name servers.
    Dns(String, Vec<IpAddr>),
    /// These are its search domains; none clears them.
    Domains(String, Vec<String>),
    /// Forget everything set on the interface.
    Revert(String),
}

/// Why a command is not known to have gone through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The system resolver is not ours to configure, now or later.
    Refused(String),
    /// The command said no, or could not be run: nothing was changed.
    Failed(String),
    /// The command gave no answer (it ran out of time, or was killed).
    /// What it asked for may have been done all the same.
    Unanswered(String),
}

/// What carries the commands out ([`super::resolvectl::Resolvectl`]).
pub trait Backend: Send + 'static {
    fn run(&mut self, op: &Op) -> impl Future<Output = Result<(), Failure>> + Send;

    /// The index of the interface of that name, if there is one. The
    /// system resolver keeps an interface's settings for as long as that
    /// interface exists: one deleted and made again under the same name
    /// has another index, and none of the settings.
    fn ifindex(&self, ifname: &str) -> Option<u32>;
}

/// What the system resolver holds from us for an interface name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    /// The interface the name was when the settings were given: they
    /// are that interface's, not the name's.
    ifindex: Option<u32>,
    /// `None`: something, but not known what. A command went unanswered,
    /// or the servers went in and their domains did not.
    dns: Option<LinkDns>,
}

pub struct Resolver<B> {
    pub cm: ConfigChannel,
    tx: ResolverTx,
    rx: UnboundedReceiver<Report>,
    backend: B,
    /// `system name-server dhcp <if>`.
    enabled: BTreeSet<String>,
    /// What each source knows, by interface.
    learned: BTreeMap<String, BTreeMap<Source, LinkDns>>,
    /// What the system resolver holds from us, by interface name.
    applied: BTreeMap<String, Held>,
    /// Interfaces whose failure has been said; said again only after a
    /// success.
    complained: BTreeSet<String>,
    /// The backend refused: nothing more is asked of it.
    refused: bool,
    /// When to try the failed commands again.
    retry: Option<Instant>,
    backoff: Duration,
}

impl<B: Backend> Resolver<B> {
    pub fn new(backend: B) -> Resolver<B> {
        let (tx, rx) = mpsc::unbounded_channel();
        Resolver {
            cm: ConfigChannel::new(),
            tx,
            rx,
            backend,
            enabled: BTreeSet::new(),
            learned: BTreeMap::new(),
            applied: BTreeMap::new(),
            complained: BTreeSet::new(),
            refused: false,
            retry: None,
            backoff: RETRY_MIN,
        }
    }

    /// Where the sources send what they learn.
    pub fn tx(&self) -> ResolverTx {
        self.tx.clone()
    }

    async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.cm.rx.recv() => {
                    // Once the whole commit is known.
                    if self.process_cm_msg(msg) {
                        self.sync().await;
                    }
                }
                Some(report) = self.rx.recv() => {
                    self.learn(report);
                    // Several at once (a lease replaced by another) are
                    // one change.
                    while let Ok(report) = self.rx.try_recv() {
                        self.learn(report);
                    }
                    self.sync().await;
                }
                _ = sleep_until_opt(self.retry) => self.sync().await,
            }
        }
    }

    /// Take a configuration line. True at the end of a commit.
    fn process_cm_msg(&mut self, msg: ConfigRequest) -> bool {
        if msg.op == ConfigOp::CommitEnd {
            return true;
        }
        let (path, mut args) = path_from_command(&msg.paths);
        if path != "/system/name-server/dhcp" {
            return false;
        }
        match (msg.op, args.string()) {
            (ConfigOp::Set, Some(name)) => {
                self.enabled.insert(name);
            }
            (ConfigOp::Delete, Some(name)) => {
                self.enabled.remove(&name);
            }
            (ConfigOp::Delete, None) => self.enabled.clear(),
            _ => {}
        }
        false
    }

    fn learn(&mut self, report: Report) {
        match report.dns {
            Some(dns) => {
                self.learned
                    .entry(report.ifname)
                    .or_default()
                    .insert(report.source, dns);
            }
            None => {
                if let Some(sources) = self.learned.get_mut(&report.ifname) {
                    sources.remove(&report.source);
                    if sources.is_empty() {
                        self.learned.remove(&report.ifname);
                    }
                }
            }
        }
    }

    /// What the system resolver should hold: for every configured
    /// interface something usable has been learned on, that.
    fn wanted(&self) -> BTreeMap<String, LinkDns> {
        self.enabled
            .iter()
            .filter_map(|name| {
                let dns = merge(self.learned.get(name)?);
                // Search domains alone resolve nothing.
                (!dns.servers.is_empty()).then(|| (name.clone(), dns))
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
    /// resolver holds and what is wanted. True when a command failed and
    /// is to be tried again.
    async fn reconcile(&mut self) -> bool {
        if self.refused {
            return false;
        }
        let wanted = self.wanted();
        let mut failed = false;

        let gone: Vec<String> = self
            .applied
            .keys()
            .filter(|name| !wanted.contains_key(*name))
            .cloned()
            .collect();
        for name in gone {
            let failure = match self.backend.run(&Op::Revert(name.clone())).await {
                Ok(()) => {
                    tracing::info!("resolver: {name}: name servers withdrawn");
                    self.applied.remove(&name);
                    self.complained.remove(&name);
                    continue;
                }
                Err(Failure::Refused(why)) => {
                    self.refuse(&why);
                    return false;
                }
                Err(failure) => failure,
            };
            if self.backend.ifindex(&name).is_none() {
                // The interface went, and its settings with it.
                self.applied.remove(&name);
                self.complained.remove(&name);
                continue;
            }
            // Asked again later. Until then an unanswered withdrawal
            // may have been carried out: what the interface holds is no
            // longer known, and wanted again in the meantime it is set
            // again, not taken for held.
            if let Failure::Unanswered(_) = failure
                && let Some(held) = self.applied.get_mut(&name)
            {
                held.dns = None;
            }
            let (Failure::Failed(why) | Failure::Unanswered(why) | Failure::Refused(why)) = failure;
            failed = true;
            self.complain(&name, "withdrawn", &why);
        }

        for (name, dns) in wanted {
            // The interface the name is now. Looked up before the
            // commands, which look it up again themselves: should it be
            // replaced in between, what is noted here is the older one,
            // and the next look finds the difference.
            let ifindex = self.backend.ifindex(&name);
            // Held already, by this very interface. The same settings
            // noted for the name's previous interface went with it, and
            // this one has none: a lease lost and found again on an
            // interface made anew in between says nothing else changed.
            if self
                .applied
                .get(&name)
                .is_some_and(|held| held.ifindex == ifindex && held.dns.as_ref() == Some(&dns))
            {
                continue;
            }
            match self.set(&name, ifindex, &dns).await {
                Ok(()) => {
                    tracing::info!("resolver: {name}: {}", describe(&dns));
                    self.complained.remove(&name);
                }
                Err(Failure::Refused(why)) => {
                    self.refuse(&why);
                    return false;
                }
                Err(Failure::Failed(why) | Failure::Unanswered(why)) => {
                    failed = true;
                    self.complain(&name, "set", &why);
                }
            }
        }
        failed
    }

    /// The servers, then the domains, noting in `applied` what the
    /// system resolver holds after each, so that it is taken back if it
    /// stops being wanted before a later try has put it right:
    ///
    /// - the servers refused: what it held before, and that stays noted;
    /// - the servers unanswered: perhaps the new ones, perhaps not;
    /// - the servers in and the domains not: something of ours that is
    ///   not `dns`;
    /// - both in: `dns`.
    async fn set(
        &mut self,
        name: &str,
        ifindex: Option<u32>,
        dns: &LinkDns,
    ) -> Result<(), Failure> {
        let unknown = Held { ifindex, dns: None };
        let servers = Op::Dns(name.to_string(), dns.servers.clone());
        match self.backend.run(&servers).await {
            Ok(()) => {}
            Err(failure) => {
                if matches!(failure, Failure::Unanswered(_)) {
                    self.applied.insert(name.to_string(), unknown);
                }
                return Err(failure);
            }
        }
        self.applied.insert(name.to_string(), unknown);
        self.backend
            .run(&Op::Domains(name.to_string(), dns.domains.clone()))
            .await?;
        let held = Held {
            ifindex,
            dns: Some(dns.clone()),
        };
        self.applied.insert(name.to_string(), held);
        Ok(())
    }

    fn complain(&mut self, name: &str, what: &str, why: &str) {
        if self.complained.insert(name.to_string()) {
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
    use crate::config::CommandPath;

    const WAN: &str = "wan0";

    /// What the backend was asked, and what it is to answer: the answers
    /// in order, then success.
    #[derive(Default)]
    struct Script {
        ran: Vec<Op>,
        answers: VecDeque<Result<(), Failure>>,
        /// Interfaces that do not exist.
        missing: Vec<String>,
        /// The index of the interfaces that do: 1 unless said here.
        index: BTreeMap<String, u32>,
        /// How long a command takes.
        takes: Duration,
    }

    #[derive(Clone, Default)]
    struct Mock(Arc<Mutex<Script>>);

    impl Backend for Mock {
        async fn run(&mut self, op: &Op) -> Result<(), Failure> {
            let takes = self.0.lock().unwrap().takes;
            tokio::time::sleep(takes).await;
            let mut script = self.0.lock().unwrap();
            script.ran.push(op.clone());
            script.answers.pop_front().unwrap_or(Ok(()))
        }

        fn ifindex(&self, ifname: &str) -> Option<u32> {
            let script = self.0.lock().unwrap();
            if script.missing.iter().any(|m| m == ifname) {
                return None;
            }
            Some(script.index.get(ifname).copied().unwrap_or(1))
        }
    }

    struct Bench {
        resolver: Resolver<Mock>,
        mock: Mock,
        now: Instant,
    }

    impl Bench {
        fn new() -> Bench {
            let mock = Mock::default();
            Bench {
                resolver: Resolver::new(mock.clone()),
                mock,
                now: Instant::now(),
            }
        }

        /// One configuration line, then the end of its commit.
        async fn commit(&mut self, op: ConfigOp, names: &[&str]) {
            // As the manager delivers it (ymatch: 0 Dir, 2 Key, 3
            // KeyMatched): the list's key is an argument, not a part of
            // the path.
            let cp = |name: &str, ymatch: i32| CommandPath {
                name: name.to_string(),
                ymatch,
                ..Default::default()
            };
            let mut paths = vec![cp("system", 0), cp("name-server", 0), cp("dhcp", 2)];
            paths.extend(names.iter().map(|name| cp(name, 3)));
            assert!(!self.resolver.process_cm_msg(ConfigRequest::new(paths, op)));
            assert!(
                self.resolver
                    .process_cm_msg(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd))
            );
            self.sync().await;
        }

        async fn report(&mut self, ifname: &str, dns: Option<LinkDns>) {
            self.resolver.learn(Report {
                ifname: ifname.to_string(),
                source: Source::Dhcp4,
                dns,
            });
            self.sync().await;
        }

        /// What the event loop does after a change, at the bench's time
        /// and not the clock's.
        async fn sync(&mut self) {
            let failed = self.resolver.reconcile().await;
            self.resolver.schedule(failed, self.now);
        }

        /// What the backend has been asked since the last look.
        fn ran(&mut self) -> Vec<Op> {
            std::mem::take(&mut self.mock.0.lock().unwrap().ran)
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

    fn set(name: &str, servers: &[&str], domains: &[&str]) -> Vec<Op> {
        let dns = dns(servers, domains);
        vec![
            Op::Dns(name.to_string(), dns.servers),
            Op::Domains(name.to_string(), dns.domains),
        ]
    }

    fn revert(name: &str) -> Vec<Op> {
        vec![Op::Revert(name.to_string())]
    }

    fn failed() -> Result<(), Failure> {
        Err(Failure::Failed("no".to_string()))
    }

    fn unanswered() -> Result<(), Failure> {
        Err(Failure::Unanswered("no answer".to_string()))
    }

    impl Bench {
        /// The interface is deleted and made again: the same name,
        /// another index.
        fn recreate(&mut self, ifname: &str) {
            let mut script = self.mock.0.lock().unwrap();
            let index = script.index.entry(ifname.to_string()).or_insert(1);
            *index += 1;
        }

        /// A source's report, without the look at what is wanted that
        /// follows the last of several.
        fn learn(&mut self, ifname: &str, dns: Option<LinkDns>) {
            self.resolver.learn(Report {
                ifname: ifname.to_string(),
                source: Source::Dhcp4,
                dns,
            });
        }
    }

    #[tokio::test]
    async fn nothing_is_set_for_an_interface_that_is_not_configured() {
        let mut b = Bench::new();
        b.report(WAN, Some(dns(&["198.51.100.53"], &["example.com"])))
            .await;
        assert_eq!(b.ran(), []);
        // Configured afterwards, it gets what was learned before.
        b.commit(ConfigOp::Set, &[WAN]).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &["example.com"]));
    }

    #[tokio::test]
    async fn what_a_configured_interface_learns_is_set_once() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        assert_eq!(b.ran(), []);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        // No domains is said too: it clears the ones set before.
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        // The same again (a renewal), and a commit about something else.
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.commit(ConfigOp::Set, &["wan1"]).await;
        assert_eq!(b.ran(), []);
        // Other servers.
        b.report(WAN, Some(dns(&["198.51.100.54"], &["example.net"])))
            .await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.54"], &["example.net"]));
    }

    #[tokio::test]
    async fn a_lost_lease_and_a_deleted_entry_take_it_back() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        // Nothing is held any more, so nothing more is taken back.
        b.commit(ConfigOp::Delete, &[WAN]).await;
        assert_eq!(b.ran(), []);

        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.commit(ConfigOp::Delete, &[WAN]).await;
        assert_eq!(b.ran(), revert(WAN));
        // The lease is still there: configured again, it is set again.
        b.commit(ConfigOp::Set, &[WAN]).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
    }

    #[tokio::test]
    async fn a_delete_without_a_name_clears_every_entry() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.commit(ConfigOp::Set, &["wan1"]).await;
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.report("wan1", Some(dns(&["203.0.113.53"], &[]))).await;
        b.ran();
        b.commit(ConfigOp::Delete, &[]).await;
        assert_eq!(b.ran(), [revert(WAN), revert("wan1")].concat());
    }

    #[tokio::test]
    async fn a_lease_with_no_usable_server_sets_nothing() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
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
        b.commit(ConfigOp::Set, &[WAN]).await;
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
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.resolver.learn(Report {
            ifname: WAN.to_string(),
            source: Source::Dhcp4,
            dns: Some(dns(&["198.51.100.53"], &[])),
        });
        for _ in 0..12 {
            b.answer(&[failed()]);
            b.sync().await;
        }
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MAX));
    }

    #[tokio::test]
    async fn servers_set_without_their_domains_are_still_taken_back() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        // The servers go in, the domains fail.
        b.answer(&[Ok(()), failed()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &["example.com"])))
            .await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &["example.com"]));
        // Not wanted any more before a try has worked.
        b.commit(ConfigOp::Delete, &[WAN]).await;
        assert_eq!(b.ran(), revert(WAN));
    }

    #[tokio::test]
    async fn servers_that_never_went_in_are_not_taken_back() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.answer(&[failed()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.commit(ConfigOp::Delete, &[WAN]).await;
        assert_eq!(b.ran(), []);
        assert_eq!(b.resolver.retry, None);
    }

    #[tokio::test]
    async fn a_failed_withdrawal_is_tried_again_while_the_interface_is_there() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
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

    #[tokio::test]
    async fn a_failed_withdrawal_on_a_deleted_interface_is_the_end_of_it() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.mock.0.lock().unwrap().missing.push(WAN.to_string());
        b.answer(&[failed()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, None);
        b.sync().await;
        assert_eq!(b.ran(), []);
    }

    #[tokio::test]
    async fn a_refusal_ends_every_further_command() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.commit(ConfigOp::Set, &["wan1"]).await;
        b.answer(&[Err(Failure::Refused("not here".to_string()))]);
        b.resolver.learn(Report {
            ifname: "wan1".to_string(),
            source: Source::Dhcp4,
            dns: Some(dns(&["203.0.113.53"], &[])),
        });
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        // The first command was refused; the other interface is not tried.
        assert_eq!(b.ran().len(), 1);
        assert_eq!(b.resolver.retry, None);
        b.report(WAN, Some(dns(&["198.51.100.54"], &[]))).await;
        b.commit(ConfigOp::Delete, &[WAN]).await;
        assert_eq!(b.ran(), []);
    }

    /// The lease goes with its interface and comes back, the same, on
    /// the interface made again under that name, and both reports are
    /// taken in before either is acted on. Nothing changed that the
    /// reports say; the settings went with the old interface all the
    /// same, and the new one must be given them.
    #[tokio::test]
    async fn an_interface_made_again_is_given_its_name_servers_again() {
        let mut b = Bench::new();
        let lease = dns(&["198.51.100.53"], &["example.com"]);
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(lease.clone())).await;
        b.ran();

        b.recreate(WAN);
        b.learn(WAN, None);
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

    /// The same, when the withdrawal was acted on by itself and was
    /// refused, the interface being there again by then. The entry it
    /// leaves, to be tried again, says the servers are held: by the old
    /// interface, which is no reason to leave the new one unset.
    #[tokio::test]
    async fn an_interface_made_again_during_a_withdrawal_is_given_them_too() {
        let mut b = Bench::new();
        let lease = dns(&["198.51.100.53"], &[]);
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(lease.clone())).await;
        b.ran();

        b.recreate(WAN);
        b.answer(&[failed()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        b.report(WAN, Some(lease)).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
    }

    /// A command that got no answer may have been carried out. The
    /// servers it asked for are ours to take back, should they stop
    /// being wanted before a try has an answer.
    #[tokio::test]
    async fn servers_set_without_an_answer_are_taken_back() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.answer(&[unanswered()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        // No answer for the servers, so the domains were not tried.
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[])[..1]);
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        b.commit(ConfigOp::Delete, &[WAN]).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, None);
        b.sync().await;
        assert_eq!(b.ran(), []);
    }

    /// Still wanted, they are asked for again like any that failed.
    #[tokio::test]
    async fn servers_set_without_an_answer_are_asked_for_again() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.answer(&[unanswered()]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.sync().await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
        assert_eq!(b.resolver.retry, None);
    }

    /// New servers that got no answer leave it open which the system
    /// resolver holds, the old or the new. So the old ones, wanted
    /// again, are not taken for held: they are set.
    #[tokio::test]
    async fn an_unanswered_change_leaves_nothing_taken_for_held() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.answer(&[unanswered()]);
        b.report(WAN, Some(dns(&["198.51.100.54"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.54"], &[])[..1]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &[]));
    }

    /// New servers that were refused leave the old ones in, and those,
    /// wanted again, are held.
    #[tokio::test]
    async fn a_refused_change_leaves_the_old_servers_held() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.answer(&[failed()]);
        b.report(WAN, Some(dns(&["198.51.100.54"], &[]))).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.54"], &[])[..1]);
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        assert_eq!(b.ran(), []);
        // And they are still ours to take back.
        b.commit(ConfigOp::Delete, &[WAN]).await;
        assert_eq!(b.ran(), revert(WAN));
    }

    /// A withdrawal that got no answer may have been carried out. The
    /// servers wanted again before a later try has an answer are not
    /// taken for held: they are set.
    #[tokio::test]
    async fn an_unanswered_withdrawal_leaves_nothing_taken_for_held() {
        let mut b = Bench::new();
        let lease = dns(&["198.51.100.53"], &["example.com"]);
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(lease.clone())).await;
        b.ran();
        b.answer(&[unanswered()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        b.report(WAN, Some(lease)).await;
        assert_eq!(b.ran(), set(WAN, &["198.51.100.53"], &["example.com"]));
    }

    /// One that was refused changed nothing: the servers are still in,
    /// and wanted again they are held.
    #[tokio::test]
    async fn a_refused_withdrawal_leaves_the_servers_held() {
        let mut b = Bench::new();
        let lease = dns(&["198.51.100.53"], &[]);
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(lease.clone())).await;
        b.ran();
        b.answer(&[failed()]);
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
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.learn(WAN, Some(dns(&["198.51.100.53"], &[])));
        b.mock.0.lock().unwrap().takes = Duration::from_secs(10);
        b.answer(&[unanswered()]);
        let began = Instant::now();
        b.resolver.sync().await;
        assert_eq!(Instant::now(), began + Duration::from_secs(10));
        assert_eq!(b.resolver.retry, Some(Instant::now() + RETRY_MIN));
    }

    /// A withdrawal that got no answer is asked again while the
    /// interface is there, like one that failed.
    #[tokio::test]
    async fn an_unanswered_withdrawal_is_tried_again() {
        let mut b = Bench::new();
        b.commit(ConfigOp::Set, &[WAN]).await;
        b.report(WAN, Some(dns(&["198.51.100.53"], &[]))).await;
        b.ran();
        b.answer(&[unanswered()]);
        b.report(WAN, None).await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, Some(b.now + RETRY_MIN));
        b.sync().await;
        assert_eq!(b.ran(), revert(WAN));
        assert_eq!(b.resolver.retry, None);
    }

    #[test]
    fn sources_merge_into_one_list_without_repeats() {
        // One source today; the merge is by source all the same.
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
