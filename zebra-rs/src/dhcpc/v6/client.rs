//! The DHCPv6 client state machine (RFC 8415 §18.2), without I/O.
//!
//! [`Client::handle`] takes an [`Event`] and the current time and returns
//! [`Action`]s for the task to carry out: messages to send, a lease to
//! apply or withdraw. Nothing here opens a socket, reads a clock or
//! touches the RIB, so every timer and transition is tested with a
//! scripted server and a clock the test moves.
//!
//! A client asks for an address (one IA_NA), or with `parameters-only`
//! for no address, only for the rest of the configuration (DNS, NTP)
//! through Information-request. Prefix delegation (IA_PD) is P4 of
//! docs/design/dhcp-client.md.
//!
//! | State | Meaning |
//! |---|---|
//! | `Stopped` | not started, or no usable link and no lease |
//! | `Soliciting` | Solicit sent or about to be, collecting Advertises |
//! | `Requesting` | Request sent to the chosen server |
//! | `Bound` | lease held, waiting for T1 |
//! | `Renewing` | Renew sent to the lease's server, T1..T2 |
//! | `Rebinding` | Rebind sent to any server, T2..expiry |
//! | `Confirming` | Confirm: is a lease kept across a restart or a link loss right for this link? |
//! | `Declining` | Decline sent for an address that failed DAD |
//! | `Releasing` | Release sent, waiting for the server's Reply |
//! | `Informing` | Information-request sent or about to be |
//! | `Informed` | parameters held, waiting for their refresh time |
//! | `Backoff` | waiting after a refusal before soliciting again |
//! | `Released` | the operator released the lease; waits for `renew` |
//!
//! Every message goes to `ff02::1:2`: the client neither asks for nor
//! uses the Server Unicast option. It sends no Reconfigure Accept and
//! takes no Reconfigure.
//!
//! A lease's lifetimes, T1 and T2 count from when the Reply that set them
//! arrived (RFC 8415 §18.2.10.1), not from when its request was sent as in
//! DHCPv4.

use std::fmt;
use std::net::Ipv6Addr;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use dhcp_packet::v6::params::{INFINITY, IaAddress, IaNa, NtpServer, Params, StatusCode};
use dhcp_packet::v6::{ClientMessage, Dhcp6Option, msg, opt, status};
use serde::{Deserialize, Serialize};

/// `interface <if> ipv6 dhcpv6-options …`, as far as the protocol goes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Ask for no address, only for the other configuration
    /// (Information-request). It is fixed for the life of a [`Client`]:
    /// see [`Client::set_options`].
    pub parameters_only: bool,
    /// Offer the two-message exchange: a Solicit that a server may answer
    /// with a Reply at once.
    pub rapid_commit: bool,
    /// Give the lease up without telling the server.
    pub no_release: bool,
}

/// What the server granted.
///
/// Every time in it is in seconds from one moment: when the
/// [`Action::Bind`] carrying it was returned. [`Lease::aged`] moves that
/// moment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// The server's DUID.
    pub server_id: Vec<u8>,
    /// Where its messages came from, a link-local address. For people:
    /// the protocol knows a server by its DUID.
    pub server_address: Ipv6Addr,
    /// `None` with `parameters-only`.
    pub ia_na: Option<Ia>,
    pub dns_servers: Vec<Ipv6Addr>,
    pub domain_list: Vec<String>,
    pub ntp_servers: Vec<Ntp>,
}

/// The identity association for the interface's addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ia {
    pub iaid: u32,
    /// When to renew, already chosen by the client where the server left
    /// it open; [`INFINITY`] never. 0 is "now", not "the client decides"
    /// as on the wire.
    pub t1: u32,
    /// When to rebind; as `t1`.
    pub t2: u32,
    pub addresses: Vec<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub address: Ipv6Addr,
    /// Seconds; [`INFINITY`] never ends.
    pub preferred: u32,
    pub valid: u32,
}

/// One NTP server (RFC 5908).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ntp {
    Address(Ipv6Addr),
    Multicast(Ipv6Addr),
    Fqdn(String),
}

impl From<&NtpServer> for Ntp {
    fn from(server: &NtpServer) -> Ntp {
        match server {
            NtpServer::Address(address) => Ntp::Address(*address),
            NtpServer::Multicast(address) => Ntp::Multicast(*address),
            NtpServer::Fqdn(name) => Ntp::Fqdn(name.clone()),
        }
    }
}

impl Lease {
    /// The lease `elapsed` seconds on: every time that much shorter, and
    /// without the addresses whose valid lifetime has run out.
    pub fn aged(&self, elapsed: u32) -> Lease {
        let left = |time: u32| {
            if time == INFINITY {
                INFINITY
            } else {
                time.saturating_sub(elapsed)
            }
        };
        let mut lease = self.clone();
        if let Some(ia) = &mut lease.ia_na {
            ia.t1 = left(ia.t1);
            ia.t2 = left(ia.t2);
            ia.addresses.retain_mut(|a| {
                a.preferred = left(a.preferred);
                a.valid = left(a.valid);
                a.valid > 0
            });
        }
        lease
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Stopped,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Confirming,
    Declining,
    Releasing,
    Informing,
    Informed,
    Backoff,
    Released,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            State::Stopped => "stopped",
            State::Soliciting => "soliciting",
            State::Requesting => "requesting",
            State::Bound => "bound",
            State::Renewing => "renewing",
            State::Rebinding => "rebinding",
            State::Confirming => "confirming",
            State::Declining => "declining",
            State::Releasing => "releasing",
            State::Informing => "informing",
            State::Informed => "informed",
            State::Backoff => "backoff",
            State::Released => "released",
        })
    }
}

#[derive(Debug)]
pub enum Event<'a> {
    /// The interface can carry DHCPv6, or no longer can: the link is up
    /// and has a link-local address past DAD to send from.
    Link(bool),
    /// A lease read back from disk at start: `elapsed` seconds of it are
    /// already gone. Comes before the first `Link(true)`.
    Resume { lease: Lease, elapsed: u32 },
    /// A message for port 546 on this interface, and who sent it.
    Message {
        message: &'a ClientMessage,
        source: Ipv6Addr,
    },
    /// [`Client::deadline`] has passed.
    Timeout,
    /// Duplicate address detection found a leased address in use by
    /// another node (the kernel's `dadfailed`).
    AddressConflict(Ipv6Addr),
    /// The kernel no longer has a leased address: it expired there, or
    /// somebody removed it.
    AddressLost(Ipv6Addr),
    /// `renew dhcpv6 interface <if>`.
    Renew,
    /// `release dhcpv6 interface <if>`.
    Release,
    /// The configuration is gone: release and stop for good. The client
    /// can be dropped once [`Client::finished`].
    Stop,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Send to `ff02::1:2`, port 547, from the interface's link-local
    /// address.
    Send(ClientMessage),
    /// The lease as it stands, its times counted from now: install or
    /// refresh its addresses and withdraw any address of an earlier
    /// `Bind` that is no longer in it. `fresh` says a server's message or
    /// the passing of time made it what it is (write it to disk);
    /// otherwise it is a lease resumed from disk.
    Bind {
        lease: Lease,
        fresh: bool,
    },
    /// The lease is gone: withdraw everything and forget it.
    Unbind,
    Log(String),
}

// Transmission parameters (RFC 8415 §7.6).
const SOL_MAX_DELAY: Duration = Duration::from_secs(1);
const SOL_TIMEOUT: Duration = Duration::from_secs(1);
const SOL_MAX_RT: u32 = 3600;
const REQ_TIMEOUT: Duration = Duration::from_secs(1);
const REQ_MAX_RT: u32 = 30;
const REQ_MAX_RC: u32 = 10;
const CNF_MAX_DELAY: Duration = Duration::from_secs(1);
const CNF_TIMEOUT: Duration = Duration::from_secs(1);
const CNF_MAX_RT: u32 = 4;
const CNF_MAX_RD: Duration = Duration::from_secs(10);
const REN_TIMEOUT: Duration = Duration::from_secs(10);
const REN_MAX_RT: u32 = 600;
const REB_TIMEOUT: Duration = Duration::from_secs(10);
const REB_MAX_RT: u32 = 600;
const INF_MAX_DELAY: Duration = Duration::from_secs(1);
const INF_TIMEOUT: Duration = Duration::from_secs(1);
const INF_MAX_RT: u32 = 3600;
const REL_TIMEOUT: Duration = Duration::from_secs(1);
const REL_MAX_RC: u32 = 4;
const DEC_TIMEOUT: Duration = Duration::from_secs(1);
const DEC_MAX_RC: u32 = 4;
const IRT_DEFAULT: u32 = 86400;
const IRT_MINIMUM: u32 = 600;
/// §21.24, §21.25: a SOL_MAX_RT or INF_MAX_RT option outside this range
/// is ignored.
const MAX_RT_RANGE: RangeInclusive<u32> = 60..=86400;

/// What the Option Request option asks for in every message that has
/// one: DNS servers, the search list, NTP servers and the two
/// retransmission caps.
const WANTED: [u16; 5] = [
    opt::DNS_SERVERS,
    opt::DOMAIN_LIST,
    opt::NTP_SERVER,
    opt::SOL_MAX_RT,
    opt::INF_MAX_RT,
];

/// How far ahead of our own timer the kernel may drop an address.
const EXPIRY_SLACK: Duration = Duration::from_secs(3);
/// The wait after a refusal starts here and doubles up to `BACKOFF_MAX`
/// seconds. RFC 8415 leaves the pace of starting over to the client; this
/// keeps a server that offers and then refuses from being asked in a
/// tight loop.
const BACKOFF_FIRST: u64 = 1;
const BACKOFF_MAX: u64 = 64;

pub struct Client {
    duid: Vec<u8>,
    iaid: u32,
    options: Options,
    state: State,
    link: bool,
    /// `Stop` has been handled.
    ended: bool,
    /// The message exchange under way. `None` in the states that send,
    /// too, while the random delay before a first message runs.
    exchange: Option<Exchange>,
    /// When the state's own timer runs out: a retransmission, T1, the end
    /// of a wait. The addresses' lifetimes are not in it:
    /// [`Client::deadline`] adds them.
    wake: Option<Instant>,
    /// `Soliciting`: the best Advertise so far. `Requesting`: who is
    /// asked.
    server: Option<Server>,
    held: Option<Held>,
    /// `Declining`, `Releasing`: what goes back, and to whom.
    returning: Option<Returning>,
    /// `Releasing`: the state after it, `Released` or `Stopped`.
    release_then: State,
    /// SOL_MAX_RT and INF_MAX_RT, as servers have set them (options 82
    /// and 83).
    sol_max_rt: u32,
    inf_max_rt: u32,
    backoff: u64,
    /// Entropy for transaction ids, delays and retransmission jitter.
    random: Box<dyn FnMut() -> u32 + Send>,
}

/// One message and its retransmissions (RFC 8415 §15).
struct Exchange {
    /// 24 bits, the same in every retransmission.
    xid: u32,
    /// The first transmission: Elapsed Time counts from it.
    started: Instant,
    /// The retransmission timeout now running (RT).
    rt: Duration,
    /// Transmissions made.
    count: u32,
    /// Give up after this many transmissions (MRC); 0 for no limit.
    mrc: u32,
    /// Give up at this time (MRD, as an instant).
    until: Option<Instant>,
    /// A Confirm: the first server to answer NotOnLink.
    not_on_link: Option<Ipv6Addr>,
}

/// A server and what it offers.
struct Server {
    id: Vec<u8>,
    preference: u8,
    /// Named again in the Request.
    addresses: Vec<Ipv6Addr>,
}

struct Held {
    lease: Lease,
    /// When the lease's times count from.
    since: Instant,
}

struct Returning {
    server_id: Vec<u8>,
    addresses: Vec<Ipv6Addr>,
}

/// A server's message, past the checks every message gets.
struct Answer<'a> {
    params: &'a Params,
    server_id: Vec<u8>,
    source: Ipv6Addr,
}

/// What a server's message says about our IA_NA.
enum Verdict<'a> {
    /// Here it is. Its addresses still need a look: see [`usable`].
    Granted(&'a IaNa),
    /// The server could not say (UnspecFail, UseMulticast): the message
    /// goes out again when its retransmission is due.
    Unanswered(String),
    /// The server has no record of the IA.
    NoBinding,
    /// No address: a failure status, or no IA_NA of ours in the message.
    Refused(String),
}

impl Held {
    fn at(&self, secs: u32) -> Option<Instant> {
        (secs != INFINITY).then(|| self.since + Duration::from_secs(u64::from(secs)))
    }

    fn addresses(&self) -> &[Address] {
        self.lease
            .ia_na
            .as_ref()
            .map_or(&[], |ia| ia.addresses.as_slice())
    }

    /// `None` when it never comes.
    fn t1(&self) -> Option<Instant> {
        self.lease.ia_na.as_ref().and_then(|ia| self.at(ia.t1))
    }

    fn t2(&self) -> Option<Instant> {
        self.lease.ia_na.as_ref().and_then(|ia| self.at(ia.t2))
    }

    /// When the first address runs out.
    fn first_expiry(&self) -> Option<Instant> {
        self.addresses()
            .iter()
            .filter_map(|a| self.at(a.valid))
            .min()
    }

    /// When the last one does; `None` when one never does.
    fn last_expiry(&self) -> Option<Instant> {
        self.addresses()
            .iter()
            .map(|a| self.at(a.valid))
            .collect::<Option<Vec<Instant>>>()?
            .into_iter()
            .max()
    }

    /// Count the lease's times from `now` instead, to the second.
    fn rebase(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.since).as_secs();
        self.lease = self.lease.aged(u32::try_from(elapsed).unwrap_or(u32::MAX));
        self.since += Duration::from_secs(elapsed);
    }
}

impl Client {
    /// `duid` and `iaid` are who the client is to a server; see
    /// [`Client::identity`].
    pub fn new(
        duid: Vec<u8>,
        iaid: u32,
        options: Options,
        random: Box<dyn FnMut() -> u32 + Send>,
    ) -> Client {
        Client {
            duid,
            iaid,
            options,
            state: State::Stopped,
            link: false,
            ended: false,
            exchange: None,
            wake: None,
            server: None,
            held: None,
            returning: None,
            release_then: State::Released,
            sol_max_rt: SOL_MAX_RT,
            inf_max_rt: INF_MAX_RT,
            backoff: BACKOFF_FIRST,
            random,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The lease held, its times counted from `now`.
    pub fn lease(&self, now: Instant) -> Option<Lease> {
        self.held.as_ref().map(|held| {
            let elapsed = now.saturating_duration_since(held.since).as_secs();
            held.lease.aged(u32::try_from(elapsed).unwrap_or(u32::MAX))
        })
    }

    /// When to deliver [`Event::Timeout`]: the state's timer or an
    /// address running out, whichever is first.
    pub fn deadline(&self) -> Option<Instant> {
        let expiry = self.held.as_ref().and_then(Held::first_expiry);
        match (self.wake, expiry) {
            (Some(wake), Some(expiry)) => Some(wake.min(expiry)),
            (wake, expiry) => wake.or(expiry),
        }
    }

    /// Whether the UDP socket must be open: whenever the client may send
    /// or be answered.
    pub fn wants_socket(&self) -> bool {
        !matches!(self.state, State::Stopped | State::Released)
    }

    /// `Stop` has been handled and the Release it began is over: nothing
    /// more comes from this client.
    pub fn finished(&self) -> bool {
        self.ended && self.state == State::Stopped
    }

    /// Who the client is to a server: its DUID, and the IAID of its
    /// IA_NA.
    ///
    /// Both are fixed for the life of a `Client`. A server keys a binding
    /// on them: a Renew under another DUID or IAID is another client
    /// asking, and a Release under another leaves the binding in place.
    /// When the configuration gives the interface another DUID, the task
    /// stops this client, which releases the lease as who took it, and
    /// starts a new one.
    pub fn identity(&self) -> (&[u8], u32) {
        (&self.duid, self.iaid)
    }

    /// New options take effect at the next message. `parameters_only` is
    /// not one of them: it decides which of two protocols the client
    /// speaks, and the task starts a new client when it changes.
    pub fn set_options(&mut self, mut options: Options) {
        options.parameters_only = self.options.parameters_only;
        self.options = options;
    }

    pub fn handle(&mut self, event: Event<'_>, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        // After `Stop`, only the Release it began goes on.
        if self.ended && self.state != State::Releasing {
            return out;
        }
        match event {
            Event::Link(up) => self.on_link(up, now, &mut out),
            Event::Resume { lease, elapsed } => self.on_resume(lease, elapsed, now, &mut out),
            Event::Message { message, source } => self.on_message(message, source, now, &mut out),
            Event::Timeout => self.on_timeout(now, &mut out),
            Event::AddressConflict(address) => self.on_conflict(address, now, &mut out),
            Event::AddressLost(address) => self.on_lost(address, now, &mut out),
            Event::Renew => self.on_renew(now, &mut out),
            Event::Release => {
                if self.state != State::Releasing {
                    self.release(State::Released, now, &mut out);
                }
            }
            Event::Stop => {
                self.ended = true;
                if self.state == State::Releasing {
                    self.release_then = State::Stopped;
                } else {
                    self.release(State::Stopped, now, &mut out);
                }
            }
        }
        out
    }

    fn on_link(&mut self, up: bool, now: Instant, out: &mut Vec<Action>) {
        if self.link == up {
            return;
        }
        self.link = up;
        if !up {
            match self.state {
                State::Released => {}
                // The Release cannot be repeated; it went out once.
                State::Releasing => self.finish_return(now, out),
                // A held lease stays, and its lifetimes go on running.
                // Nothing is sent: the timers that send start again when
                // the link is back.
                _ if self.held.is_some() => {
                    self.idle(if self.options.parameters_only {
                        State::Informed
                    } else {
                        State::Bound
                    });
                }
                _ => self.idle(State::Stopped),
            }
            return;
        }
        match self.state {
            State::Released => {}
            // The link may be another one: ask again (§18.2.6).
            _ if self.options.parameters_only => self.inform(now),
            _ if self.held.is_some() => self.verify(now, out),
            _ => self.solicit(now),
        }
    }

    fn on_resume(&mut self, lease: Lease, elapsed: u32, now: Instant, out: &mut Vec<Action>) {
        // Only before anything else has happened: a lease is never held
        // in `Stopped`.
        if self.state != State::Stopped || self.options.parameters_only {
            return;
        }
        let lease = lease.aged(elapsed);
        // Ours, and not run out while we were away.
        if !lease
            .ia_na
            .as_ref()
            .is_some_and(|ia| ia.iaid == self.iaid && !ia.addresses.is_empty())
        {
            return;
        }
        self.held = Some(Held {
            lease: lease.clone(),
            since: now,
        });
        // In use at once; `Link(true)` then verifies it.
        out.push(Action::Bind {
            lease,
            fresh: false,
        });
        self.state = State::Bound;
        self.wake = None;
    }

    fn on_renew(&mut self, now: Instant, out: &mut Vec<Action>) {
        match self.state {
            State::Bound | State::Renewing | State::Rebinding | State::Confirming if self.link => {
                // Past T2 the lease's server has had its turn.
                let t2 = self.held.as_ref().and_then(Held::t2);
                if t2.is_some_and(|t2| now >= t2) {
                    self.settle(now, out);
                } else {
                    self.state = State::Renewing;
                    self.begin(REN_TIMEOUT, 0, t2, now, out);
                }
            }
            State::Informed | State::Informing if self.link => {
                self.state = State::Informing;
                self.begin(INF_TIMEOUT, 0, None, now, out);
            }
            // `release` then `renew`: the Release has gone out once, and
            // that has to do.
            State::Releasing if self.release_then == State::Released => {
                self.idle(State::Stopped);
                if self.link {
                    self.start(now);
                }
            }
            State::Released | State::Backoff | State::Stopped if self.link => self.start(now),
            // The next `Link(true)` starts it.
            State::Released => self.state = State::Stopped,
            _ => {}
        }
    }

    fn on_conflict(&mut self, address: Ipv6Addr, now: Instant, out: &mut Vec<Action>) {
        let Some(server_id) = self
            .held
            .as_ref()
            .filter(|held| held.addresses().iter().any(|a| a.address == address))
            .map(|held| held.lease.server_id.clone())
        else {
            return;
        };
        out.push(Action::Log(format!(
            "{address} is in use by another node; declined"
        )));
        self.remove_address(address, now, out);
        if !self.link {
            // Nobody to tell.
            if self.held.is_none() {
                self.idle(State::Stopped);
            }
            return;
        }
        // One Decline for everything declined so far.
        let mut addresses = match self.returning.take() {
            Some(returning) if self.state == State::Declining => returning.addresses,
            _ => Vec::new(),
        };
        addresses.push(address);
        self.returning = Some(Returning {
            server_id,
            addresses,
        });
        self.server = None;
        self.state = State::Declining;
        self.begin(DEC_TIMEOUT, DEC_MAX_RC, None, now, out);
    }

    fn on_lost(&mut self, address: Ipv6Addr, now: Instant, out: &mut Vec<Action>) {
        let Some(held) = &self.held else {
            return;
        };
        let Some(lost) = held.addresses().iter().find(|a| a.address == address) else {
            return;
        };
        // The kernel counts a lifetime in whole seconds and can drop the
        // address just ahead of our own timer: that is it running out,
        // not somebody removing it.
        let expired = held
            .at(lost.valid)
            .is_some_and(|expiry| now + EXPIRY_SLACK >= expiry);
        out.push(Action::Log(if expired {
            format!("{address} expired")
        } else {
            format!("{address} left the interface")
        }));
        self.remove_address(address, now, out);
        if self.held.is_none() {
            self.restart(now);
        }
    }

    fn on_timeout(&mut self, now: Instant, out: &mut Vec<Action>) {
        // An address that has run out goes whatever the state; the last
        // one takes the lease with it.
        if self.expire(now, out) {
            return;
        }
        if !self.wake.is_some_and(|wake| now >= wake) {
            return;
        }
        match self.state {
            State::Soliciting => {
                if self.exchange.is_none() {
                    // The delay before the first Solicit is over.
                    self.begin(SOL_TIMEOUT, 0, None, now, out);
                } else if self.server.is_some() {
                    // So is the wait for Advertises: the best one is it.
                    self.request(now, out);
                } else {
                    self.retransmit(now, out);
                }
            }
            State::Requesting => {
                if !self.retransmit(now, out) {
                    out.push(Action::Log(
                        "no answer to the request; starting over".into(),
                    ));
                    // Only after NoBinding is a lease held here, and then
                    // no server stands behind it any more.
                    if self.held.take().is_some() {
                        out.push(Action::Unbind);
                    }
                    self.solicit(now);
                }
            }
            // T1, or T2 ending a Renew: `settle` sends what the lease's
            // timers call for now.
            State::Bound => self.settle(now, out),
            State::Renewing | State::Rebinding => {
                if !self.retransmit(now, out) {
                    self.settle(now, out);
                }
            }
            State::Confirming => {
                let Some(exchange) = &self.exchange else {
                    // The delay before the first Confirm is over.
                    return self.begin(CNF_TIMEOUT, 0, Some(now + CNF_MAX_RD), now, out);
                };
                let not_on_link = exchange.not_on_link;
                if self.retransmit(now, out) {
                    return;
                }
                match not_on_link {
                    // §18.2.10.3: NotOnLink and nothing else was heard.
                    Some(_) => {
                        out.push(Action::Log(
                            "no server confirmed the lease; starting over".into(),
                        ));
                        self.held = None;
                        out.push(Action::Unbind);
                        self.solicit(now);
                    }
                    // §18.2.3: nothing was heard. Use it with the
                    // lifetimes last known.
                    None => {
                        out.push(Action::Log(
                            "no server confirmed the lease; using it until it expires".into(),
                        ));
                        self.settle(now, out);
                    }
                }
            }
            State::Declining | State::Releasing => {
                if !self.retransmit(now, out) {
                    self.finish_return(now, out);
                }
            }
            State::Informing => {
                if self.exchange.is_none() {
                    self.begin(INF_TIMEOUT, 0, None, now, out);
                } else {
                    self.retransmit(now, out);
                }
            }
            State::Informed => self.inform(now),
            State::Backoff => self.start(now),
            State::Stopped | State::Released => self.wake = None,
        }
    }

    fn on_message(
        &mut self,
        message: &ClientMessage,
        source: Ipv6Addr,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Some(exchange) = &self.exchange else {
            return;
        };
        if message.transaction_id != exchange.xid
            || !matches!(message.msg_type, msg::ADVERTISE | msg::REPLY)
        {
            return;
        }
        let first_wait_over = exchange.count > 1;
        let params = Params::from_options(&message.options);
        // §16.3, §16.10: it names its server, and this client.
        let Some(server_id) = params.server_id.clone() else {
            return;
        };
        if params.client_id.as_deref() != Some(self.duid.as_slice()) {
            return;
        }
        // Taken even from a message that is of no other use (§18.2.9).
        if let Some(rt) = params.sol_max_rt.filter(|rt| MAX_RT_RANGE.contains(rt)) {
            self.sol_max_rt = rt;
        }
        if let Some(rt) = params.inf_max_rt.filter(|rt| MAX_RT_RANGE.contains(rt)) {
            self.inf_max_rt = rt;
        }
        let answer = Answer {
            params: &params,
            server_id,
            source,
        };
        match (self.state, message.msg_type) {
            (State::Soliciting, msg::ADVERTISE) => {
                self.on_advertise(&answer, first_wait_over, now, out);
            }
            // §18.2.1: only a Reply that commits at once answers a
            // Solicit, and only a Solicit that asked for one.
            (State::Soliciting, msg::REPLY) => {
                if self.options.rapid_commit
                    && params.rapid_commit
                    && let Verdict::Granted(ia) = self.verdict(&answer)
                    && let Some(lease) = self.grant(&answer, ia, out)
                {
                    self.bind(lease, now, out);
                }
            }
            (State::Requesting, msg::REPLY) => self.on_request_reply(&answer, now, out),
            (State::Renewing | State::Rebinding, msg::REPLY) => {
                self.on_renewal_reply(&answer, now, out);
            }
            (State::Confirming, msg::REPLY) => self.on_confirm_reply(&answer, now, out),
            // §18.2.10.2: whatever the status, that is that.
            (State::Declining | State::Releasing, msg::REPLY) => {
                if self
                    .returning
                    .as_ref()
                    .is_some_and(|returning| returning.server_id == answer.server_id)
                {
                    self.finish_return(now, out);
                }
            }
            (State::Informing, msg::REPLY) => self.on_information(&answer, now, out),
            _ => {}
        }
    }

    fn on_advertise(
        &mut self,
        answer: &Answer<'_>,
        first_wait_over: bool,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        // §18.2.9: an Advertise with no address for us is of no use.
        let Verdict::Granted(ia) = self.verdict(answer) else {
            return;
        };
        let addresses: Vec<Ipv6Addr> = usable(ia).iter().map(|a| a.address).collect();
        if addresses.is_empty() {
            return;
        }
        // The highest preference wins, the first to arrive among equals.
        let preference = answer.params.preference.unwrap_or(0);
        if self
            .server
            .as_ref()
            .is_none_or(|best| preference > best.preference)
        {
            self.server = Some(Server {
                id: answer.server_id.clone(),
                preference,
                addresses,
            });
        }
        // Advertises are collected until the first retransmission is due.
        // Preference 255 ends the wait, and once it is over the first
        // Advertise does.
        if preference == 255 || first_wait_over {
            self.request(now, out);
        }
    }

    fn on_request_reply(&mut self, answer: &Answer<'_>, now: Instant, out: &mut Vec<Action>) {
        if self
            .server
            .as_ref()
            .is_none_or(|server| server.id != answer.server_id)
        {
            return;
        }
        let reason = match self.verdict(answer) {
            Verdict::Granted(ia) => match self.grant(answer, ia, out) {
                Some(lease) => return self.bind(lease, now, out),
                None => "no usable address in the reply".to_string(),
            },
            Verdict::Unanswered(reason) => {
                out.push(Action::Log(format!(
                    "server {}: {reason}; asking again",
                    answer.source
                )));
                return;
            }
            Verdict::NoBinding => "NoBinding".to_string(),
            Verdict::Refused(reason) => reason,
        };
        out.push(Action::Log(format!(
            "server {} refused the lease: {reason}",
            answer.source
        )));
        if self.held.take().is_some() {
            out.push(Action::Unbind);
        }
        self.back_off(now);
    }

    fn on_renewal_reply(&mut self, answer: &Answer<'_>, now: Instant, out: &mut Vec<Action>) {
        let Some(held) = &self.held else {
            return;
        };
        // A Renew is for the lease's server to answer, a Rebind for any.
        if self.state == State::Renewing && held.lease.server_id != answer.server_id {
            return;
        }
        let ia = match self.verdict(answer) {
            Verdict::Granted(ia) => ia,
            // §18.2.10.1: ask that server for the binding again. The
            // addresses stay in use meanwhile.
            Verdict::NoBinding => {
                out.push(Action::Log(format!(
                    "server {} has no record of the lease; requesting it again",
                    answer.source
                )));
                self.server = Some(Server {
                    id: answer.server_id.clone(),
                    preference: 0,
                    addresses: held.addresses().iter().map(|a| a.address).collect(),
                });
                return self.request(now, out);
            }
            // The lease stands as it is, and the message goes out again
            // when its retransmission is due: that is the rate limit
            // §18.2.10.1 asks for.
            Verdict::Unanswered(reason) | Verdict::Refused(reason) => {
                out.push(Action::Log(format!(
                    "server {} did not extend the lease: {reason}",
                    answer.source
                )));
                return;
            }
        };
        let Some(mut held) = self.held.take() else {
            return;
        };
        // What the Reply does not name keeps its lifetimes (§18.2.10.1):
        // count them from now, like the ones it sets.
        held.rebase(now);
        let mut addresses = held
            .lease
            .ia_na
            .take()
            .map(|ia| ia.addresses)
            .unwrap_or_default();
        for theirs in &ia.addresses {
            let failed = theirs.status.as_ref().is_some_and(|s| !s.is_success());
            if failed || theirs.preferred > theirs.valid {
                continue;
            }
            let mine = addresses.iter().position(|a| a.address == theirs.address);
            match (mine, theirs.valid) {
                // A valid lifetime of 0 takes the address away.
                (Some(i), 0) => {
                    addresses.remove(i);
                }
                (None, 0) => {}
                (Some(i), _) => {
                    addresses[i].preferred = theirs.preferred;
                    addresses[i].valid = theirs.valid;
                }
                (None, _) => addresses.push(address_of(theirs)),
            }
        }
        if addresses.is_empty() {
            out.push(Action::Log(format!(
                "server {} took the lease back",
                answer.source
            )));
            out.push(Action::Unbind);
            return self.back_off(now);
        }
        let (t1, t2) = renewal_times(ia.t1, ia.t2, &addresses);
        let ia = Ia {
            iaid: self.iaid,
            t1,
            t2,
            addresses,
        };
        let lease = self.lease_from(answer, Some(ia), out);
        self.bind(lease, now, out);
    }

    /// §18.2.10.3: one Success, said or implied, and the addresses are
    /// right for this link whatever other servers say. NotOnLink counts
    /// only when the exchange ends without one (`on_timeout`). Until then
    /// the Confirm goes on being sent: the server that would say Success
    /// may have missed it, on a link that has only just come up.
    fn on_confirm_reply(&mut self, answer: &Answer<'_>, now: Instant, out: &mut Vec<Action>) {
        match answer.params.status.as_ref().filter(|s| !s.is_success()) {
            None => self.settle(now, out),
            Some(status) if status.code == status::NOT_ON_LINK => {
                // Said once, however often it is heard.
                if let Some(exchange) = &mut self.exchange
                    && exchange.not_on_link.is_none()
                {
                    exchange.not_on_link = Some(answer.source);
                    out.push(Action::Log(format!(
                        "server {} says the lease is not for this link",
                        answer.source
                    )));
                }
            }
            // Anything else settles nothing.
            Some(_) => {}
        }
    }

    fn on_information(&mut self, answer: &Answer<'_>, now: Instant, out: &mut Vec<Action>) {
        if answer
            .params
            .status
            .as_ref()
            .is_some_and(|s| !s.is_success())
        {
            return;
        }
        let lease = self.lease_from(answer, None, out);
        // §21.23: a day when the server names no time, never under ten
        // minutes, and never again when it says so (`INFINITY`).
        let refresh = answer
            .params
            .information_refresh_time
            .map_or(IRT_DEFAULT, |time| time.max(IRT_MINIMUM));
        self.exchange = None;
        self.held = Some(Held {
            lease: lease.clone(),
            since: now,
        });
        out.push(Action::Bind { lease, fresh: true });
        self.state = State::Informed;
        self.wake = (refresh != INFINITY).then(|| now + Duration::from_secs(u64::from(refresh)));
    }

    /// What `answer` says about our IA_NA.
    fn verdict<'a>(&self, answer: &Answer<'a>) -> Verdict<'a> {
        let params = answer.params;
        if let Some(status) = params.status.as_ref().filter(|s| !s.is_success()) {
            return match status.code {
                status::UNSPEC_FAIL | status::USE_MULTICAST => {
                    Verdict::Unanswered(status_text(status))
                }
                status::NO_BINDING => Verdict::NoBinding,
                _ => Verdict::Refused(status_text(status)),
            };
        }
        // §21.4: an IA_NA whose T1 is after its T2 is as good as absent.
        let ia = params
            .ia_na
            .iter()
            .find(|ia| ia.iaid == self.iaid && !(ia.t2 > 0 && ia.t1 > ia.t2));
        let Some(ia) = ia else {
            return Verdict::Refused("no address in the reply".into());
        };
        match ia.status.as_ref().filter(|s| !s.is_success()) {
            None => Verdict::Granted(ia),
            Some(status) if status.code == status::NO_BINDING => Verdict::NoBinding,
            Some(status) => Verdict::Refused(status_text(status)),
        }
    }

    /// The lease `ia` gives a client that holds none; `None` when no
    /// address in it can be used.
    fn grant(&self, answer: &Answer<'_>, ia: &IaNa, out: &mut Vec<Action>) -> Option<Lease> {
        let addresses = usable(ia);
        if addresses.is_empty() {
            return None;
        }
        let (t1, t2) = renewal_times(ia.t1, ia.t2, &addresses);
        let ia = Ia {
            iaid: self.iaid,
            t1,
            t2,
            addresses,
        };
        Some(self.lease_from(answer, Some(ia), out))
    }

    fn lease_from(&self, answer: &Answer<'_>, ia_na: Option<Ia>, out: &mut Vec<Action>) -> Lease {
        let params = answer.params;
        for (code, error) in &params.malformed {
            out.push(Action::Log(format!(
                "option {code} from {}: {error}; ignored",
                answer.source
            )));
        }
        Lease {
            server_id: answer.server_id.clone(),
            server_address: answer.source,
            ia_na,
            dns_servers: params.dns_servers.clone(),
            domain_list: params.domain_list.clone(),
            ntp_servers: params.ntp_servers.iter().map(Ntp::from).collect(),
        }
    }

    /// Take `lease` into use, counted from now.
    fn bind(&mut self, lease: Lease, now: Instant, out: &mut Vec<Action>) {
        let held = Held {
            lease: lease.clone(),
            since: now,
        };
        self.exchange = None;
        self.server = None;
        self.backoff = BACKOFF_FIRST;
        out.push(Action::Bind { lease, fresh: true });
        self.state = State::Bound;
        self.wake = held.t1();
        self.held = Some(held);
    }

    /// Take `address` out of the lease, which goes on without it or, when
    /// nothing is left, ends.
    fn remove_address(&mut self, address: Ipv6Addr, now: Instant, out: &mut Vec<Action>) {
        let Some(held) = &mut self.held else {
            return;
        };
        let Some(ia) = &mut held.lease.ia_na else {
            return;
        };
        ia.addresses.retain(|a| a.address != address);
        // Counting the lease from now takes every address that has run
        // out with it, also one whose end is this very moment and whose
        // timer has not fired yet. So what is left is asked after that,
        // not before: a lease with no address must not stay held.
        held.rebase(now);
        if held.addresses().is_empty() {
            self.held = None;
            out.push(Action::Unbind);
        } else {
            out.push(Action::Bind {
                lease: held.lease.clone(),
                fresh: true,
            });
        }
    }

    /// Drop the addresses whose valid lifetime has run out. True when
    /// that was the end of the lease.
    fn expire(&mut self, now: Instant, out: &mut Vec<Action>) -> bool {
        let Some(held) = &mut self.held else {
            return false;
        };
        if !held.first_expiry().is_some_and(|expiry| now >= expiry) {
            return false;
        }
        // Counting the lease from now is what drops them: one rule for
        // what has run out, here and in `remove_address`.
        held.rebase(now);
        if held.addresses().is_empty() {
            out.push(Action::Log("lease expired".into()));
            self.held = None;
            out.push(Action::Unbind);
            self.restart(now);
            return true;
        }
        out.push(Action::Bind {
            lease: held.lease.clone(),
            fresh: true,
        });
        false
    }

    /// Give the lease back, if there is one, and end in `then`.
    fn release(&mut self, then: State, now: Instant, out: &mut Vec<Action>) {
        self.idle(then);
        let Some(held) = self.held.take() else {
            return;
        };
        // §18.2.7: out of use before the Release is sent.
        out.push(Action::Unbind);
        let addresses: Vec<Ipv6Addr> = held.addresses().iter().map(|a| a.address).collect();
        if addresses.is_empty() || self.options.no_release || !self.link {
            return;
        }
        self.returning = Some(Returning {
            server_id: held.lease.server_id,
            addresses,
        });
        self.release_then = then;
        self.state = State::Releasing;
        self.begin(REL_TIMEOUT, REL_MAX_RC, None, now, out);
    }

    /// A Decline or a Release is over: answered, or sent as often as it
    /// is to be.
    fn finish_return(&mut self, now: Instant, out: &mut Vec<Action>) {
        match self.state {
            State::Releasing => self.idle(self.release_then),
            // What is left of the lease goes on; with nothing left, ask
            // for another address, not at once.
            State::Declining if self.held.is_some() => {
                self.returning = None;
                self.settle(now, out);
            }
            State::Declining => self.back_off(now),
            _ => {}
        }
    }

    /// Stay in `state` with nothing under way and no timer of its own.
    fn idle(&mut self, state: State) {
        self.exchange = None;
        self.server = None;
        self.returning = None;
        self.wake = None;
        self.state = state;
    }

    /// Wait before asking again, twice as long each time.
    fn back_off(&mut self, now: Instant) {
        self.idle(State::Backoff);
        self.wake = Some(now + Duration::from_secs(self.backoff));
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
    }

    /// Begin again after a lease was lost.
    fn restart(&mut self, now: Instant) {
        if self.link {
            self.start(now);
        } else {
            self.idle(State::Stopped);
        }
    }

    fn start(&mut self, now: Instant) {
        if self.options.parameters_only {
            self.inform(now);
        } else {
            self.solicit(now);
        }
    }

    /// §18.2.1: the first Solicit waits a random moment, so that clients
    /// that start together do not ask together.
    fn solicit(&mut self, now: Instant) {
        self.idle(State::Soliciting);
        self.wake = Some(now + self.delay(SOL_MAX_DELAY));
    }

    /// §18.2.6: likewise the first Information-request.
    fn inform(&mut self, now: Instant) {
        self.idle(State::Informing);
        self.wake = Some(now + self.delay(INF_MAX_DELAY));
    }

    fn request(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.state = State::Requesting;
        self.begin(REQ_TIMEOUT, REQ_MAX_RC, None, now, out);
    }

    /// Check that a lease kept while the client could not talk is still
    /// right for the link (§18.2.3).
    fn verify(&mut self, now: Instant, out: &mut Vec<Action>) {
        // Past T2 any server is asked about the lease anyway.
        let t2 = self.held.as_ref().and_then(Held::t2);
        if t2.is_some_and(|t2| now >= t2) {
            return self.settle(now, out);
        }
        self.idle(State::Confirming);
        self.wake = Some(now + self.delay(CNF_MAX_DELAY));
    }

    /// Put a held lease in the state its timers call for, sending what
    /// that state sends. Only with a link: without one a lease waits in
    /// `Bound` with no timer (`on_link`).
    fn settle(&mut self, now: Instant, out: &mut Vec<Action>) {
        let Some(held) = &self.held else {
            return;
        };
        let (t1, t2, end) = (held.t1(), held.t2(), held.last_expiry());
        self.idle(State::Bound);
        if t2.is_some_and(|t2| now >= t2) {
            self.state = State::Rebinding;
            self.begin(REB_TIMEOUT, 0, end, now, out);
        } else if t1.is_some_and(|t1| now >= t1) {
            self.state = State::Renewing;
            self.begin(REN_TIMEOUT, 0, t2, now, out);
        } else {
            self.wake = t1;
        }
    }

    /// Send the current state's message for the first time: a new
    /// transaction, retransmitted from `irt` on, at most `mrc` times in
    /// all (0: no limit) and not after `until` (§15).
    fn begin(
        &mut self,
        irt: Duration,
        mrc: u32,
        until: Option<Instant>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        // §18.2.1: the wait after the first Solicit is never shorter than
        // IRT, so that every server's Advertise is in before it ends.
        let rt = self.randomized(irt, irt, self.state == State::Soliciting);
        self.exchange = Some(Exchange {
            xid: (self.random)() & 0x00ff_ffff,
            started: now,
            rt,
            count: 1,
            mrc,
            until,
            not_on_link: None,
        });
        self.transmit(now, out);
        self.wake = Some(not_after(now + rt, until));
    }

    /// Send the message again. False when the exchange has run its
    /// course instead (MRC, MRD).
    fn retransmit(&mut self, now: Instant, out: &mut Vec<Action>) -> bool {
        let mrt = Duration::from_secs(u64::from(match self.state {
            State::Soliciting => self.sol_max_rt,
            State::Informing => self.inf_max_rt,
            State::Requesting => REQ_MAX_RT,
            State::Confirming => CNF_MAX_RT,
            State::Renewing => REN_MAX_RT,
            State::Rebinding => REB_MAX_RT,
            _ => 0,
        }));
        let Some(mut exchange) = self.exchange.take() else {
            return false;
        };
        if (exchange.mrc != 0 && exchange.count >= exchange.mrc)
            || exchange.until.is_some_and(|until| now >= until)
        {
            return false;
        }
        // RT = 2 × RTprev + RAND × RTprev, held at MRT + RAND × MRT.
        let mut rt = self.randomized(exchange.rt * 2, exchange.rt, false);
        if !mrt.is_zero() && rt > mrt {
            rt = self.randomized(mrt, mrt, false);
        }
        exchange.rt = rt;
        exchange.count += 1;
        self.wake = Some(not_after(now + rt, exchange.until));
        self.exchange = Some(exchange);
        self.transmit(now, out);
        true
    }

    /// `fixed + RAND × base`, RAND drawn from -0.1..=0.1, or from above 0
    /// with `positive` (§15).
    fn randomized(&mut self, fixed: Duration, base: Duration, positive: bool) -> Duration {
        let r = u64::from((self.random)());
        // RAND is (r - 1000) / 10000.
        let r = if positive { 1010 + r % 991 } else { r % 2001 };
        let base = base.as_millis() as u64;
        let fixed = fixed.as_millis() as u64;
        Duration::from_millis((fixed + base * r / 10_000).saturating_sub(base / 10))
    }

    /// A random delay of up to `max`.
    fn delay(&mut self, max: Duration) -> Duration {
        Duration::from_millis(u64::from((self.random)()) % (max.as_millis() as u64 + 1))
    }

    /// The message the current state sends, as the exchange stands.
    fn transmit(&self, now: Instant, out: &mut Vec<Action>) {
        let Some(exchange) = &self.exchange else {
            return;
        };
        let held_addresses = || -> Vec<Ipv6Addr> {
            self.held
                .iter()
                .flat_map(|held| held.addresses())
                .map(|a| a.address)
                .collect()
        };
        // The type, the server it is for, and the addresses it names.
        let (msg_type, server_id, addresses) = match self.state {
            State::Soliciting => (msg::SOLICIT, None, Some(Vec::new())),
            State::Requesting => {
                let Some(server) = &self.server else {
                    return;
                };
                (
                    msg::REQUEST,
                    Some(&server.id),
                    Some(server.addresses.clone()),
                )
            }
            State::Confirming => (msg::CONFIRM, None, Some(held_addresses())),
            State::Renewing => (
                msg::RENEW,
                self.held.as_ref().map(|held| &held.lease.server_id),
                Some(held_addresses()),
            ),
            State::Rebinding => (msg::REBIND, None, Some(held_addresses())),
            State::Declining | State::Releasing => {
                let Some(returning) = &self.returning else {
                    return;
                };
                let msg_type = if self.state == State::Declining {
                    msg::DECLINE
                } else {
                    msg::RELEASE
                };
                (
                    msg_type,
                    Some(&returning.server_id),
                    Some(returning.addresses.clone()),
                )
            }
            State::Informing => (msg::INFORMATION_REQUEST, None, None),
            _ => return,
        };
        let mut message = ClientMessage::new(msg_type, exchange.xid);
        message
            .options
            .push(Dhcp6Option::new(opt::CLIENT_ID, self.duid.clone()));
        if let Some(server_id) = server_id {
            message
                .options
                .push(Dhcp6Option::new(opt::SERVER_ID, server_id.clone()));
        }
        // §21.9: hundredths of a second since the exchange began, 0 in
        // its first message.
        let elapsed = now.saturating_duration_since(exchange.started).as_millis() / 10;
        message
            .options
            .push(Dhcp6Option::elapsed_time(elapsed.min(0xffff) as u16));
        match msg_type {
            msg::SOLICIT | msg::REQUEST | msg::RENEW | msg::REBIND => {
                message.options.push(Dhcp6Option::oro(&WANTED));
            }
            // §21.23: the refresh time is asked for here and nowhere
            // else.
            msg::INFORMATION_REQUEST => {
                let mut wanted = WANTED.to_vec();
                wanted.push(opt::INFORMATION_REFRESH_TIME);
                message.options.push(Dhcp6Option::oro(&wanted));
            }
            _ => {}
        }
        if msg_type == msg::SOLICIT && self.options.rapid_commit {
            message.options.push(Dhcp6Option::rapid_commit());
        }
        if let Some(addresses) = addresses {
            // §21.4, §21.6: a client leaves T1, T2 and the lifetimes 0.
            let mut ia = IaNa::new(self.iaid);
            ia.addresses = addresses
                .into_iter()
                .map(|address| IaAddress {
                    address,
                    preferred: 0,
                    valid: 0,
                    status: None,
                    other: Vec::new(),
                })
                .collect();
            if let Ok(option) = ia.emit() {
                message.options.push(option);
            }
        }
        out.push(Action::Send(message));
    }
}

fn not_after(at: Instant, limit: Option<Instant>) -> Instant {
    limit.map_or(at, |limit| at.min(limit))
}

fn address_of(theirs: &IaAddress) -> Address {
    Address {
        address: theirs.address,
        preferred: theirs.preferred,
        valid: theirs.valid,
    }
}

/// The addresses of `ia` a client can use: with a valid lifetime, not
/// preferred for longer than valid (§21.6), without a failure status,
/// each once.
fn usable(ia: &IaNa) -> Vec<Address> {
    let mut addresses: Vec<Address> = Vec::new();
    for theirs in &ia.addresses {
        if theirs.valid > 0
            && theirs.preferred <= theirs.valid
            && theirs.status.as_ref().is_none_or(StatusCode::is_success)
            && !addresses.iter().any(|a| a.address == theirs.address)
        {
            addresses.push(address_of(theirs));
        }
    }
    addresses
}

/// T1 and T2 for an IA with `addresses`, from the server's `t1` and `t2`.
///
/// A time the server sets is used as it is (§21.4: "the client MUST use
/// the values in the T1 and T2 fields … unless values in those fields
/// are 0"), [`INFINITY`] for "never" included (§7.7), and also when it
/// comes after the addresses have run out.
///
/// A time the server leaves 0 is the client's to choose (§14.2):
///
/// - both: 0.5 and 0.8 of the shortest preferred lifetime among the
///   addresses still preferred (of the shortest valid lifetime when none
///   is), at least a second, and never when that lifetime never ends;
/// - T1 alone: the same, but no later than 5/8 of the server's T2, which
///   is the proportion of 0.5 to 0.8, so that the lease's own server is
///   asked before any other;
/// - T2 alone: the same, but no earlier than 8/5 of the server's T1.
fn renewal_times(t1: u32, t2: u32, addresses: &[Address]) -> (u32, u32) {
    let (own_t1, own_t2) = own_renewal_times(addresses);
    match (t1, t2) {
        (0, 0) => (own_t1, own_t2),
        (0, t2) => (own_t1.min(scaled(t2, 5, 8)).max(1), t2),
        (t1, 0) => (t1, own_t2.max(scaled(t1, 8, 5))),
        // Out of order. `verdict` drops such an IA_NA (§21.4), so this
        // is not reached from a server's message.
        (t1, t2) if t1 > t2 => (own_t1, own_t2),
        (t1, t2) => (t1, t2),
    }
}

/// The T1 and T2 a client chooses for `addresses` when the server names
/// neither.
fn own_renewal_times(addresses: &[Address]) -> (u32, u32) {
    let shortest_valid = addresses.iter().map(|a| a.valid).min().unwrap_or(INFINITY);
    let base = addresses
        .iter()
        .map(|a| a.preferred)
        .filter(|&preferred| preferred > 0)
        .min()
        .unwrap_or(shortest_valid);
    if base == INFINITY {
        return (INFINITY, INFINITY);
    }
    let t1 = (base / 2).max(1);
    let t2 = ((u64::from(base) * 4 / 5) as u32).max(t1);
    (t1, t2)
}

/// `time × numerator / denominator`. Never stays never, and a time too
/// long for 32 bits is never.
fn scaled(time: u32, numerator: u64, denominator: u64) -> u32 {
    if time == INFINITY {
        return INFINITY;
    }
    u32::try_from(u64::from(time) * numerator / denominator).unwrap_or(INFINITY)
}

fn status_text(status: &StatusCode) -> String {
    let name = match status.code {
        status::UNSPEC_FAIL => "UnspecFail",
        status::NO_ADDRS_AVAIL => "NoAddrsAvail",
        status::NO_BINDING => "NoBinding",
        status::NOT_ON_LINK => "NotOnLink",
        status::USE_MULTICAST => "UseMulticast",
        status::NO_PREFIX_AVAIL => "NoPrefixAvail",
        code => return format!("status {code} ({})", status.message),
    };
    if status.message.is_empty() {
        name.to_string()
    } else {
        format!("{name} ({})", status.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUID: [u8; 10] = [0, 3, 0, 1, 2, 0, 0, 0, 0, 1];
    const SERVER_DUID: [u8; 10] = [0, 3, 0, 1, 2, 0, 0, 0, 0, 0xfe];
    const OTHER_DUID: [u8; 10] = [0, 3, 0, 1, 2, 0, 0, 0, 0, 0xfd];
    const IAID: u32 = 0x0102_0304;
    const SERVER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const ADDRESS: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
    const ADDRESS2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200);
    const ADDRESS3: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x300);
    const DNS: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn client(options: Options) -> Client {
        // A fixed "random" source that counts up: transaction ids differ,
        // and the delays and the jitter are small and known.
        let mut next = 1299u32;
        Client::new(
            DUID.to_vec(),
            IAID,
            options,
            Box::new(move || {
                next += 1;
                next
            }),
        )
    }

    /// What `server` answers to `request`: its transaction and client
    /// identifier, then `options`.
    fn answer_from(
        server: &[u8],
        request: &ClientMessage,
        msg_type: u8,
        options: Vec<Dhcp6Option>,
    ) -> ClientMessage {
        let mut m = ClientMessage::new(msg_type, request.transaction_id);
        m.options.push(Dhcp6Option::new(
            opt::CLIENT_ID,
            request.option(opt::CLIENT_ID).unwrap(),
        ));
        m.options.push(Dhcp6Option::new(opt::SERVER_ID, server));
        m.options.extend(options);
        m
    }

    fn answer(request: &ClientMessage, msg_type: u8, options: Vec<Dhcp6Option>) -> ClientMessage {
        answer_from(&SERVER_DUID, request, msg_type, options)
    }

    /// Our IA_NA as a server sends it: address, preferred, valid.
    fn ia(t1: u32, t2: u32, addresses: &[(Ipv6Addr, u32, u32)]) -> Dhcp6Option {
        let mut ia = IaNa::new(IAID);
        ia.t1 = t1;
        ia.t2 = t2;
        ia.addresses = addresses
            .iter()
            .map(|&(address, preferred, valid)| IaAddress {
                address,
                preferred,
                valid,
                status: None,
                other: Vec::new(),
            })
            .collect();
        ia.emit().unwrap()
    }

    /// The usual lease: one address, T1 1800, T2 2880, valid for 7200 s.
    fn one_address() -> Dhcp6Option {
        ia(1800, 2880, &[(ADDRESS, 3600, 7200)])
    }

    /// Our IA_NA with a status and no address.
    fn ia_status(code: u16) -> Dhcp6Option {
        let mut ia = IaNa::new(IAID);
        ia.status = Some(StatusCode::new(code, "no"));
        ia.emit().unwrap()
    }

    /// Our IA_NA with one address the server marks with a status.
    fn ia_address_status(code: u16) -> Dhcp6Option {
        let mut ia = IaNa::new(IAID);
        ia.addresses = vec![IaAddress {
            address: ADDRESS,
            preferred: 3600,
            valid: 7200,
            status: Some(StatusCode::new(code, "no")),
            other: Vec::new(),
        }];
        ia.emit().unwrap()
    }

    fn status_option(code: u16) -> Dhcp6Option {
        StatusCode::new(code, "").emit()
    }

    fn preference(value: u8) -> Dhcp6Option {
        Dhcp6Option::new(opt::PREFERENCE, [value])
    }

    fn u32_option(code: u16, value: u32) -> Dhcp6Option {
        Dhcp6Option::new(code, value.to_be_bytes())
    }

    fn sent(actions: &[Action]) -> &ClientMessage {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Send(m) => Some(m),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no message in {actions:?}"))
    }

    fn deliver(c: &mut Client, message: &ClientMessage, now: Instant) -> Vec<Action> {
        c.handle(
            Event::Message {
                message,
                source: SERVER,
            },
            now,
        )
    }

    /// Move the clock to the client's deadline and let its timer fire.
    fn fire(c: &mut Client) -> (Instant, Vec<Action>) {
        let now = c.deadline().expect("a deadline");
        (now, c.handle(Event::Timeout, now))
    }

    fn ia_of(message: &ClientMessage) -> IaNa {
        IaNa::parse(message.option(opt::IA_NA).expect("an IA_NA")).unwrap()
    }

    fn addresses_of(message: &ClientMessage) -> Vec<Ipv6Addr> {
        ia_of(message).addresses.iter().map(|a| a.address).collect()
    }

    fn elapsed_of(message: &ClientMessage) -> u16 {
        let data = message.option(opt::ELAPSED_TIME).unwrap();
        u16::from_be_bytes([data[0], data[1]])
    }

    fn wanted(message: &ClientMessage) -> Vec<u16> {
        message
            .option(opt::ORO)
            .unwrap()
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    /// From `Soliciting` with its delay running: the first Solicit.
    fn first_solicit(c: &mut Client) -> (Instant, ClientMessage) {
        assert_eq!(c.state(), State::Soliciting);
        let (now, actions) = fire(c);
        let solicit = sent(&actions).clone();
        assert_eq!(solicit.msg_type, msg::SOLICIT);
        (now, solicit)
    }

    /// From `Soliciting` with its delay running: Solicit, an Advertise of
    /// `lease` with preference 255, and the Request that follows at once.
    fn to_request(c: &mut Client, lease: &Dhcp6Option) -> (Instant, ClientMessage) {
        let (now, solicit) = first_solicit(c);
        let advertise = answer(
            &solicit,
            msg::ADVERTISE,
            vec![preference(255), lease.clone()],
        );
        let request = sent(&deliver(c, &advertise, now)).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(c.state(), State::Requesting);
        (now, request)
    }

    /// Link up, then Solicit → Advertise → Request → Reply: bound to
    /// `lease`. Returns when.
    fn acquire(c: &mut Client, t0: Instant, lease: Dhcp6Option) -> Instant {
        c.handle(Event::Link(true), t0);
        let (now, request) = to_request(c, &lease);
        let actions = deliver(c, &answer(&request, msg::REPLY, vec![lease]), now);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
        now
    }

    /// A bound client's first Renew, at T1.
    fn first_renew(c: &mut Client) -> (Instant, ClientMessage) {
        let (now, actions) = fire(c);
        let renew = sent(&actions).clone();
        assert_eq!(renew.msg_type, msg::RENEW);
        assert_eq!(c.state(), State::Renewing);
        (now, renew)
    }

    fn address(address: Ipv6Addr, preferred: u32, valid: u32) -> Address {
        Address {
            address,
            preferred,
            valid,
        }
    }

    /// A lease as the task keeps it on disk: `one_address`, just bound.
    fn kept() -> Lease {
        Lease {
            server_id: SERVER_DUID.to_vec(),
            server_address: SERVER,
            ia_na: Some(Ia {
                iaid: IAID,
                t1: 1800,
                t2: 2880,
                addresses: vec![address(ADDRESS, 3600, 7200)],
            }),
            dns_servers: vec![DNS],
            domain_list: vec!["example.com".into()],
            ntp_servers: vec![Ntp::Fqdn("ntp.example.com".into())],
        }
    }

    fn held_addresses(c: &Client, now: Instant) -> Vec<Address> {
        c.lease(now)
            .and_then(|lease| lease.ia_na)
            .map(|ia| ia.addresses)
            .unwrap_or_default()
    }

    #[test]
    fn solicit_advertise_request_reply() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        assert!(!c.wants_socket());
        assert_eq!(c.identity(), (&DUID[..], IAID));

        // The first Solicit waits a random moment, up to a second.
        assert!(c.handle(Event::Link(true), t0).is_empty());
        assert_eq!(c.state(), State::Soliciting);
        assert!(c.wants_socket());
        let (t, solicit) = first_solicit(&mut c);
        assert!(t > t0 && t - t0 <= SOL_MAX_DELAY);
        assert_eq!(solicit.transaction_id & !0x00ff_ffff, 0);
        assert_eq!(solicit.option(opt::CLIENT_ID), Some(&DUID[..]));
        assert!(solicit.option(opt::SERVER_ID).is_none());
        assert_eq!(elapsed_of(&solicit), 0);
        assert!(solicit.option(opt::RAPID_COMMIT).is_none());
        assert!(solicit.option(opt::RECONF_ACCEPT).is_none());
        // SOL_MAX_RT is asked for; the information refresh time is not,
        // outside an Information-request.
        assert_eq!(
            wanted(&solicit),
            [
                opt::DNS_SERVERS,
                opt::DOMAIN_LIST,
                opt::NTP_SERVER,
                opt::SOL_MAX_RT,
                opt::INF_MAX_RT
            ]
        );
        // An empty IA_NA under our IAID.
        let asked = ia_of(&solicit);
        assert_eq!((asked.iaid, asked.t1, asked.t2), (IAID, 0, 0));
        assert!(asked.addresses.is_empty());

        // An Advertise is held until the first retransmission would be
        // due; then its server is asked.
        let advertise = answer(&solicit, msg::ADVERTISE, vec![one_address()]);
        assert!(deliver(&mut c, &advertise, t).is_empty());
        assert_eq!(c.state(), State::Soliciting);
        let (t, actions) = fire(&mut c);
        let request = sent(&actions).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(c.state(), State::Requesting);
        assert_ne!(request.transaction_id, solicit.transaction_id);
        assert_eq!(request.option(opt::CLIENT_ID), Some(&DUID[..]));
        assert_eq!(request.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(elapsed_of(&request), 0);
        assert!(wanted(&request).contains(&opt::DNS_SERVERS));
        // It names the address offered, and no times.
        let asked = ia_of(&request);
        assert_eq!((asked.iaid, asked.t1, asked.t2), (IAID, 0, 0));
        let [a] = &asked.addresses[..] else {
            panic!("{asked:?}")
        };
        assert_eq!((a.address, a.preferred, a.valid), (ADDRESS, 0, 0));

        let reply = answer(
            &request,
            msg::REPLY,
            vec![
                one_address(),
                Dhcp6Option::new(opt::DNS_SERVERS, DNS.octets()),
                Dhcp6Option::new(
                    opt::DOMAIN_LIST,
                    dhcp_packet::name::encode("example.com").unwrap(),
                ),
                Dhcp6Option::new(
                    opt::NTP_SERVER,
                    dhcp_packet::v6::params::encode_ntp_servers(&[NtpServer::Fqdn(
                        "ntp.example.com".into(),
                    )])
                    .unwrap(),
                ),
            ],
        );
        let actions = deliver(&mut c, &reply, t);
        assert_eq!(
            actions,
            [Action::Bind {
                lease: kept(),
                fresh: true
            }]
        );
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.lease(t), Some(kept()));
        // T1 is next; the address runs out much later.
        assert_eq!(c.deadline(), Some(t + secs(1800)));
        assert_eq!(c.lease(t + secs(100)), Some(kept().aged(100)));
    }

    #[test]
    fn messages_that_answer_nothing_are_ignored() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        // Before the first Solicit there is nothing to answer.
        c.handle(Event::Link(true), t0);
        let mut unsent = ClientMessage::new(msg::SOLICIT, 0);
        unsent.options.push(Dhcp6Option::new(opt::CLIENT_ID, DUID));
        let early = answer(
            &unsent,
            msg::ADVERTISE,
            vec![preference(255), one_address()],
        );
        assert!(deliver(&mut c, &early, t0).is_empty());

        let (t, solicit) = first_solicit(&mut c);
        let good = answer(
            &solicit,
            msg::ADVERTISE,
            vec![preference(255), one_address()],
        );
        let mut strays = Vec::new();
        // Another transaction.
        let mut stray = good.clone();
        stray.transaction_id ^= 1;
        strays.push(stray);
        // For another client, or for nobody.
        let mut stray = good.clone();
        stray.options[0] = Dhcp6Option::new(opt::CLIENT_ID, OTHER_DUID);
        strays.push(stray);
        let mut stray = good.clone();
        stray.options.remove(0);
        strays.push(stray);
        // From no server in particular.
        let mut stray = good.clone();
        stray.options.remove(1);
        strays.push(stray);
        // Not a message a client takes.
        for msg_type in [msg::SOLICIT, msg::RECONFIGURE, msg::RELAY_REPL] {
            let mut stray = good.clone();
            stray.msg_type = msg_type;
            strays.push(stray);
        }
        // A Reply to a Solicit that did not ask for one.
        let mut stray = good.clone();
        stray.msg_type = msg::REPLY;
        stray.options.push(Dhcp6Option::rapid_commit());
        strays.push(stray);
        // Nothing for our IA: another IAID, an address that cannot be
        // used, a refusal, T1 after T2, or a failure of the whole message.
        let mut other_ia = IaNa::new(IAID + 1);
        other_ia.addresses = ia_of(&good).addresses;
        for options in [
            vec![other_ia.emit().unwrap()],
            vec![ia(0, 0, &[(ADDRESS, 0, 0)])],
            vec![ia(0, 0, &[(ADDRESS, 7200, 3600)])],
            vec![ia(0, 0, &[])],
            vec![ia_status(status::NO_ADDRS_AVAIL)],
            vec![ia_address_status(status::NOT_ON_LINK)],
            vec![ia(2880, 1800, &[(ADDRESS, 3600, 7200)])],
            vec![one_address(), status_option(status::NO_ADDRS_AVAIL)],
        ] {
            let mut options = options;
            options.push(preference(255));
            strays.push(answer(&solicit, msg::ADVERTISE, options));
        }
        for stray in &strays {
            assert!(deliver(&mut c, stray, t).is_empty(), "{stray:?}");
            assert_eq!(c.state(), State::Soliciting);
        }
        // None of them became the server to ask.
        assert_eq!(sent(&fire(&mut c).1).msg_type, msg::SOLICIT);
        let t = c.deadline().unwrap();
        assert_eq!(sent(&deliver(&mut c, &good, t)).msg_type, msg::REQUEST);
    }

    #[test]
    fn a_transaction_id_is_what_fits_on_the_wire() {
        let t0 = Instant::now();
        // A source of large numbers: 24 bits of each are the id.
        let mut next = 0xfff0_0000u32;
        let random = Box::new(move || {
            next += 0x0001_0001;
            next
        });
        let mut c = Client::new(DUID.to_vec(), IAID, Options::default(), random);
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        assert_eq!(solicit.transaction_id & !0x00ff_ffff, 0);
        // A server answers what it read, and that is recognised.
        let wire = solicit.emit().unwrap();
        let dhcp_packet::v6::Message::Client(read) =
            dhcp_packet::v6::Message::parse(&wire).unwrap()
        else {
            panic!("not a client message")
        };
        assert_eq!(read, solicit);
        let advertise = answer(&read, msg::ADVERTISE, vec![preference(255), one_address()]);
        assert_eq!(sent(&deliver(&mut c, &advertise, t)).msg_type, msg::REQUEST);
    }

    #[test]
    fn an_address_named_twice_is_one_address() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let twice = ia(0, 0, &[(ADDRESS, 3600, 7200), (ADDRESS, 100, 200)]);
        c.handle(Event::Link(true), t0);
        let (t, request) = to_request(&mut c, &twice);
        assert_eq!(addresses_of(&request), [ADDRESS]);
        deliver(&mut c, &answer(&request, msg::REPLY, vec![twice]), t);
        assert_eq!(held_addresses(&c, t), [address(ADDRESS, 3600, 7200)]);
    }

    #[test]
    fn the_highest_preference_wins_the_first_wait() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        let offer = |server: &[u8], value: Option<u8>, addr: Ipv6Addr| {
            let mut options = vec![ia(0, 0, &[(addr, 3600, 7200)])];
            options.extend(value.map(preference));
            answer_from(server, &solicit, msg::ADVERTISE, options)
        };
        // No preference counts as 0; among equals the first stays.
        for advertise in [
            offer(&[0, 3, 0, 1, 1], None, ADDRESS),
            offer(&OTHER_DUID, Some(20), ADDRESS2),
            offer(&SERVER_DUID, Some(20), ADDRESS3),
            offer(&[0, 3, 0, 1, 2], Some(10), ADDRESS),
        ] {
            assert!(deliver(&mut c, &advertise, t).is_empty());
        }
        let request = sent(&fire(&mut c).1).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(request.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        assert_eq!(addresses_of(&request), [ADDRESS2]);
    }

    #[test]
    fn preference_255_ends_the_wait() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        let low = answer_from(
            &OTHER_DUID,
            &solicit,
            msg::ADVERTISE,
            vec![preference(254), ia(0, 0, &[(ADDRESS2, 3600, 7200)])],
        );
        assert!(deliver(&mut c, &low, t).is_empty());
        let top = answer(
            &solicit,
            msg::ADVERTISE,
            vec![preference(255), one_address()],
        );
        let request = sent(&deliver(&mut c, &top, t)).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(request.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(&request), [ADDRESS]);
    }

    #[test]
    fn after_the_first_wait_any_advertise_is_taken() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let (_, solicit) = first_solicit(&mut c);
        let (t, actions) = fire(&mut c);
        assert_eq!(sent(&actions).msg_type, msg::SOLICIT);
        let advertise = answer(&solicit, msg::ADVERTISE, vec![one_address()]);
        let request = sent(&deliver(&mut c, &advertise, t)).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
    }

    #[test]
    fn solicit_is_retransmitted_up_to_sol_max_rt() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let (first, solicit) = first_solicit(&mut c);
        // The first wait is longer than SOL_TIMEOUT, never shorter.
        let mut gap = c.deadline().unwrap() - first;
        assert!(
            gap > SOL_TIMEOUT && gap <= SOL_TIMEOUT.mul_f64(1.1),
            "{gap:?}"
        );
        let cap = secs(u64::from(SOL_MAX_RT));
        for _ in 0..20 {
            let (t, actions) = fire(&mut c);
            let again = sent(&actions);
            assert_eq!(again.msg_type, msg::SOLICIT);
            // The same transaction, and the time since its first message
            // in hundredths of a second, as far as 16 bits go.
            assert_eq!(again.transaction_id, solicit.transaction_id);
            let want = ((t - first).as_millis() / 10).min(0xffff) as u16;
            assert_eq!(elapsed_of(again), want);
            // Twice the wait before, give or take a tenth of it, until
            // that passes SOL_MAX_RT.
            let next = c.deadline().unwrap() - t;
            let doubled = next >= gap.mul_f64(1.9) && next <= gap.mul_f64(2.1) && next <= cap;
            let capped =
                gap.mul_f64(2.1) > cap && next >= cap.mul_f64(0.9) && next <= cap.mul_f64(1.1);
            assert!(doubled || capped, "{gap:?} then {next:?}");
            gap = next;
        }
        assert!(gap >= cap.mul_f64(0.9));
        assert_eq!(elapsed_of(sent(&fire(&mut c).1)), 0xffff);
    }

    #[test]
    fn only_the_first_solicit_wait_is_never_short() {
        // The lowest draw there is: no delay, and RAND at its least.
        let lowest = |options: Options| Client::new(DUID.to_vec(), IAID, options, Box::new(|| 0));
        let t0 = Instant::now();
        let mut c = lowest(Options::default());
        c.handle(Event::Link(true), t0);
        assert_eq!(c.deadline(), Some(t0));
        let (t, _) = first_solicit(&mut c);
        // Above SOL_TIMEOUT, so that every Advertise is in; the waits
        // after it may fall short of twice the one before.
        let first = c.deadline().unwrap() - t;
        assert!(first > SOL_TIMEOUT, "{first:?}");
        let (t, _) = fire(&mut c);
        let second = c.deadline().unwrap() - t;
        assert!(
            second < first * 2 && second >= first.mul_f64(1.89),
            "{first:?} then {second:?}"
        );
        // An Information-request waits for one answer, not for the best.
        let mut c = lowest(parameters_only());
        c.handle(Event::Link(true), t0);
        let (t, _) = first_information_request(&mut c);
        assert_eq!(c.deadline().unwrap() - t, INF_TIMEOUT.mul_f64(0.9));
    }

    #[test]
    fn a_server_sets_sol_max_rt() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        // The last gap between Solicits after many of them.
        let settled_gap = |c: &mut Client| {
            let mut gap = Duration::ZERO;
            for _ in 0..20 {
                let (t, actions) = fire(c);
                assert_eq!(sent(&actions).msg_type, msg::SOLICIT);
                gap = c.deadline().unwrap() - t;
            }
            gap
        };
        // An Advertise that offers nothing still sets it.
        let nothing = |value: u32| {
            answer(
                &solicit,
                msg::ADVERTISE,
                vec![
                    ia_status(status::NO_ADDRS_AVAIL),
                    u32_option(opt::SOL_MAX_RT, value),
                ],
            )
        };
        assert!(deliver(&mut c, &nothing(120), t).is_empty());
        assert_eq!(c.state(), State::Soliciting);
        let gap = settled_gap(&mut c);
        assert!(gap >= secs(108) && gap <= secs(132), "{gap:?}");
        // Values outside 60..=86400 are not taken, nor one in a message
        // that is not a server's to send.
        let t = c.deadline().unwrap();
        deliver(&mut c, &nothing(59), t);
        deliver(&mut c, &nothing(86401), t);
        let mut odd = nothing(600);
        odd.msg_type = msg::RECONFIGURE;
        deliver(&mut c, &odd, t);
        let gap = settled_gap(&mut c);
        assert!(gap >= secs(108) && gap <= secs(132), "{gap:?}");
        // It can go up as well as down.
        let t = c.deadline().unwrap();
        deliver(&mut c, &nothing(7200), t);
        let gap = settled_gap(&mut c);
        assert!(gap >= secs(6480) && gap <= secs(7920), "{gap:?}");
    }

    #[test]
    fn rapid_commit_binds_on_the_reply() {
        let t0 = Instant::now();
        let options = Options {
            rapid_commit: true,
            ..Options::default()
        };
        let mut c = client(options);
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        assert_eq!(solicit.option(opt::RAPID_COMMIT), Some(&[][..]));
        // A Reply that does not commit, or commits nothing, is not one.
        let plain = answer(&solicit, msg::REPLY, vec![one_address()]);
        assert!(deliver(&mut c, &plain, t).is_empty());
        let empty = answer(
            &solicit,
            msg::REPLY,
            vec![
                Dhcp6Option::rapid_commit(),
                ia_status(status::NO_ADDRS_AVAIL),
            ],
        );
        assert!(deliver(&mut c, &empty, t).is_empty());
        assert_eq!(c.state(), State::Soliciting);
        let reply = answer(
            &solicit,
            msg::REPLY,
            vec![Dhcp6Option::rapid_commit(), one_address()],
        );
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.server_id, SERVER_DUID);
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t + secs(1800)));
    }

    #[test]
    fn rapid_commit_falls_back_to_four_messages() {
        let t0 = Instant::now();
        let options = Options {
            rapid_commit: true,
            ..Options::default()
        };
        let mut c = client(options);
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        let advertise = answer(
            &solicit,
            msg::ADVERTISE,
            vec![preference(255), one_address()],
        );
        let request = sent(&deliver(&mut c, &advertise, t)).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        assert!(request.option(opt::RAPID_COMMIT).is_none());
        // A late Reply to the Solicit is under the old transaction.
        let late = answer(
            &solicit,
            msg::REPLY,
            vec![Dhcp6Option::rapid_commit(), one_address()],
        );
        assert!(deliver(&mut c, &late, t).is_empty());
        let actions = deliver(
            &mut c,
            &answer(&request, msg::REPLY, vec![one_address()]),
            t,
        );
        assert!(matches!(&actions[..], [Action::Bind { .. }]), "{actions:?}");
    }

    #[test]
    fn an_unanswered_request_starts_over() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let (mut last, request) = to_request(&mut c, &one_address());
        let mut requests = 1;
        loop {
            let (t, actions) = fire(&mut c);
            assert!(t - last <= secs(u64::from(REQ_MAX_RT)).mul_f64(1.1));
            last = t;
            if c.state() == State::Soliciting {
                assert!(
                    matches!(&actions[..], [Action::Log(_)]),
                    "no lease to withdraw: {actions:?}"
                );
                break;
            }
            let again = sent(&actions);
            assert_eq!(again.msg_type, msg::REQUEST);
            assert_eq!(again.transaction_id, request.transaction_id);
            requests += 1;
        }
        assert_eq!(requests, REQ_MAX_RC);
        // A new Solicit, under a new transaction.
        let (_, solicit) = first_solicit(&mut c);
        assert_ne!(solicit.transaction_id, request.transaction_id);
    }

    #[test]
    fn a_refusal_backs_off_before_soliciting_again() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let refusals = [
            vec![ia_status(status::NO_ADDRS_AVAIL)],
            vec![one_address(), status_option(status::NOT_ON_LINK)],
            vec![ia(0, 0, &[(ADDRESS, 0, 0)])],
            vec![],
        ];
        let waits = [1, 2, 4, 8, 16, 32, 64, 64];
        for (options, wait) in refusals.iter().cycle().zip(waits) {
            let (t, request) = to_request(&mut c, &one_address());
            let actions = deliver(&mut c, &answer(&request, msg::REPLY, options.clone()), t);
            assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
            assert_eq!(c.state(), State::Backoff);
            assert_eq!(c.deadline(), Some(t + secs(wait)));
            assert!(fire(&mut c).1.is_empty());
            assert_eq!(c.state(), State::Soliciting);
        }
        // A lease ends the run: the next refusal waits a second again.
        let (t, request) = to_request(&mut c, &one_address());
        deliver(
            &mut c,
            &answer(&request, msg::REPLY, vec![one_address()]),
            t,
        );
        assert_eq!(c.state(), State::Bound);
        let (t, renew) = first_renew(&mut c);
        let gone = answer(&renew, msg::REPLY, vec![ia(0, 0, &[(ADDRESS, 0, 0)])]);
        let actions = deliver(&mut c, &gone, t);
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Backoff);
        assert_eq!(c.deadline(), Some(t + secs(1)));
        assert!(c.lease(t).is_none());
        // `renew` does not wait the wait out.
        assert!(c.handle(Event::Renew, t).is_empty());
        first_solicit(&mut c);
    }

    #[test]
    fn a_server_that_cannot_say_is_asked_again() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let (t, request) = to_request(&mut c, &one_address());
        let due = c.deadline();
        for code in [status::UNSPEC_FAIL, status::USE_MULTICAST] {
            let reply = answer(&request, msg::REPLY, vec![status_option(code)]);
            let actions = deliver(&mut c, &reply, t);
            assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
            assert_eq!(c.state(), State::Requesting);
            // No sooner than the retransmission was due anyway.
            assert_eq!(c.deadline(), due);
        }
        let again = sent(&fire(&mut c).1).clone();
        assert_eq!(again.msg_type, msg::REQUEST);
        assert_eq!(again.transaction_id, request.transaction_id);
        // Another server's Reply is not an answer to a Request.
        let t = c.deadline().unwrap();
        let other = answer_from(&OTHER_DUID, &request, msg::REPLY, vec![one_address()]);
        assert!(deliver(&mut c, &other, t).is_empty());
        assert_eq!(c.state(), State::Requesting);
    }

    #[test]
    fn renew_rebind_expire() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let bound = acquire(&mut c, t0, one_address());
        let at = |s: u64| bound + secs(s);

        // T1: to the lease's server, naming the address.
        let (t, renew) = first_renew(&mut c);
        assert_eq!(t, at(1800));
        assert_eq!(renew.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(&renew), [ADDRESS]);
        assert_eq!(elapsed_of(&renew), 0);
        assert!(wanted(&renew).contains(&opt::DNS_SERVERS));
        // First again after about 10 s, then less and less often.
        let gap = c.deadline().unwrap() - t;
        assert!(gap >= secs(9) && gap <= secs(11), "{gap:?}");

        // Unanswered until T2: to any server.
        let rebind = loop {
            let (t, actions) = fire(&mut c);
            let message = sent(&actions).clone();
            if c.state() == State::Rebinding {
                assert_eq!(t, at(2880));
                break message;
            }
            assert_eq!(message.msg_type, msg::RENEW);
            assert_eq!(message.transaction_id, renew.transaction_id);
            let gap = c.deadline().unwrap() - t;
            assert!(gap <= secs(u64::from(REN_MAX_RT)).mul_f64(1.1), "{gap:?}");
        };
        assert_eq!(rebind.msg_type, msg::REBIND);
        assert_ne!(rebind.transaction_id, renew.transaction_id);
        assert!(rebind.option(opt::SERVER_ID).is_none());
        assert_eq!(addresses_of(&rebind), [ADDRESS]);
        assert_eq!(elapsed_of(&rebind), 0);
        assert!(wanted(&rebind).contains(&opt::DNS_SERVERS));

        // Unanswered until the address runs out: everything is withdrawn
        // and the search starts again.
        let t = loop {
            let (t, actions) = fire(&mut c);
            if actions.contains(&Action::Unbind) {
                assert!(
                    matches!(&actions[..], [Action::Log(_), Action::Unbind]),
                    "{actions:?}"
                );
                break t;
            }
            assert_eq!(sent(&actions).msg_type, msg::REBIND);
            assert_eq!(sent(&actions).transaction_id, rebind.transaction_id);
        };
        assert_eq!(t, at(7200));
        assert_eq!(c.state(), State::Soliciting);
        assert!(c.lease(t).is_none());
        first_solicit(&mut c);
    }

    #[test]
    fn a_renewal_moves_the_lease() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        acquire(&mut c, t0, one_address());
        let (t, renew) = first_renew(&mut c);
        // Not from another server; the lease's own.
        let longer = vec![ia(3000, 4000, &[(ADDRESS, 5000, 9000)])];
        let other = answer_from(&OTHER_DUID, &renew, msg::REPLY, longer.clone());
        assert!(deliver(&mut c, &other, t).is_empty());
        let t = t + secs(1);
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, longer), t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        // Counted from the Reply.
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!((ia_na.t1, ia_na.t2), (3000, 4000));
        assert_eq!(ia_na.addresses, [address(ADDRESS, 5000, 9000)]);
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t + secs(3000)));
    }

    #[test]
    fn a_rebind_is_for_any_server_to_answer() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        acquire(&mut c, t0, one_address());
        let rebind = loop {
            let (_, actions) = fire(&mut c);
            if c.state() == State::Rebinding {
                break sent(&actions).clone();
            }
        };
        let t = c.deadline().unwrap();
        let reply = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![one_address()]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.server_id, OTHER_DUID);
        // The lease is that server's now.
        let (_, renew) = first_renew(&mut c);
        assert_eq!(renew.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
    }

    #[test]
    fn renew_by_hand_sends_what_the_lease_calls_for() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let bound = acquire(&mut c, t0, one_address());
        // Before T1: a Renew now, to be given up at T2 as any other.
        let t = bound + secs(60);
        let renew = sent(&c.handle(Event::Renew, t)).clone();
        assert_eq!(renew.msg_type, msg::RENEW);
        assert_eq!(c.state(), State::Renewing);
        // Asked again: again, as a new exchange.
        let again = sent(&c.handle(Event::Renew, t)).clone();
        assert_eq!(again.msg_type, msg::RENEW);
        assert_ne!(again.transaction_id, renew.transaction_id);
        let rebind = loop {
            let (t, actions) = fire(&mut c);
            if c.state() == State::Rebinding {
                assert_eq!(t, bound + secs(2880));
                break sent(&actions).clone();
            }
        };
        // Past T2 the lease's server has had its turn: a Rebind.
        let t = c.deadline().unwrap();
        let by_hand = sent(&c.handle(Event::Renew, t)).clone();
        assert_eq!(by_hand.msg_type, msg::REBIND);
        assert_ne!(by_hand.transaction_id, rebind.transaction_id);
        assert_eq!(c.state(), State::Rebinding);
        // Nothing to renew without a link.
        c.handle(Event::Link(false), t);
        assert!(c.handle(Event::Renew, t).is_empty());
        assert_eq!(c.state(), State::Bound);
    }

    #[test]
    fn a_renewal_adds_updates_and_removes_addresses() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let two = ia(1800, 2880, &[(ADDRESS, 3600, 7200), (ADDRESS2, 3600, 7200)]);
        acquire(&mut c, t0, two);
        let (t, renew) = first_renew(&mut c);
        assert_eq!(addresses_of(&renew), [ADDRESS, ADDRESS2]);
        // ADDRESS is taken away, ADDRESS2 is not mentioned, ADDRESS3 is
        // new; one more is not to be used and one was never ours.
        let reply = answer(
            &renew,
            msg::REPLY,
            vec![ia(
                0,
                0,
                &[
                    (ADDRESS, 0, 0),
                    (ADDRESS3, 1000, 2000),
                    (DNS, 2000, 1000),
                    (SERVER, 0, 0),
                ],
            )],
        );
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        let ia_na = lease.ia_na.as_ref().unwrap();
        // ADDRESS2 keeps what was left of its lifetimes at T1.
        assert_eq!(
            ia_na.addresses,
            [address(ADDRESS2, 1800, 5400), address(ADDRESS3, 1000, 2000)]
        );
        // T1 and T2 left to the client: from the shortest preferred
        // lifetime.
        assert_eq!((ia_na.t1, ia_na.t2), (500, 800));
        assert_eq!(c.deadline(), Some(t + secs(500)));
        let (_, renew) = first_renew(&mut c);
        assert_eq!(addresses_of(&renew), [ADDRESS2, ADDRESS3]);
    }

    #[test]
    fn a_renewal_that_gives_nothing_leaves_the_lease() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        acquire(&mut c, t0, one_address());
        let (t, renew) = first_renew(&mut c);
        let due = c.deadline();
        for options in [
            vec![ia_status(status::NO_ADDRS_AVAIL)],
            vec![status_option(status::UNSPEC_FAIL)],
            // Not our IA at all.
            vec![],
        ] {
            let actions = deliver(&mut c, &answer(&renew, msg::REPLY, options), t);
            assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
            assert_eq!(c.state(), State::Renewing);
            assert_eq!(c.deadline(), due);
        }
        assert_eq!(held_addresses(&c, t), [address(ADDRESS, 1800, 5400)]);
        let again = sent(&fire(&mut c).1).clone();
        assert_eq!(again.transaction_id, renew.transaction_id);
    }

    #[test]
    fn no_binding_requests_the_lease_again() {
        let t0 = Instant::now();
        for whole_message in [false, true] {
            let mut c = client(Options::default());
            acquire(&mut c, t0, one_address());
            let (t, renew) = first_renew(&mut c);
            let options = if whole_message {
                vec![status_option(status::NO_BINDING)]
            } else {
                vec![ia_status(status::NO_BINDING)]
            };
            let actions = deliver(&mut c, &answer(&renew, msg::REPLY, options), t);
            // Asked of that server, by address; nothing is withdrawn.
            let [Action::Log(_), Action::Send(request)] = &actions[..] else {
                panic!("{actions:?}")
            };
            assert_eq!(request.msg_type, msg::REQUEST);
            assert_eq!(request.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
            assert_eq!(addresses_of(request), [ADDRESS]);
            assert_eq!(c.state(), State::Requesting);
            assert_eq!(held_addresses(&c, t), [address(ADDRESS, 1800, 5400)]);
            let request = request.clone();
            let actions = deliver(
                &mut c,
                &answer(&request, msg::REPLY, vec![one_address()]),
                t,
            );
            assert_eq!(
                actions,
                [Action::Bind {
                    lease: Lease {
                        dns_servers: vec![],
                        domain_list: vec![],
                        ntp_servers: vec![],
                        ..kept()
                    },
                    fresh: true
                }]
            );
            assert_eq!(c.deadline(), Some(t + secs(1800)));
        }
    }

    #[test]
    fn a_lease_no_server_stands_behind_is_given_up() {
        let t0 = Instant::now();
        // Refused, and not answered at all.
        for refuse in [true, false] {
            let mut c = client(Options::default());
            acquire(&mut c, t0, one_address());
            let (t, renew) = first_renew(&mut c);
            let no_binding = answer(&renew, msg::REPLY, vec![ia_status(status::NO_BINDING)]);
            let request = sent(&deliver(&mut c, &no_binding, t)).clone();
            let actions = if refuse {
                let no = answer(
                    &request,
                    msg::REPLY,
                    vec![ia_status(status::NO_ADDRS_AVAIL)],
                );
                deliver(&mut c, &no, t)
            } else {
                loop {
                    let (_, actions) = fire(&mut c);
                    if c.state() != State::Requesting {
                        break actions;
                    }
                }
            };
            assert!(
                matches!(&actions[..], [Action::Log(_), Action::Unbind]),
                "{actions:?}"
            );
            assert!(c.lease(t).is_none());
            let want = if refuse {
                State::Backoff
            } else {
                State::Soliciting
            };
            assert_eq!(c.state(), want);
        }
    }

    #[test]
    fn renewal_times_are_the_servers_where_it_names_them() {
        let a = |preferred, valid| address(ADDRESS, preferred, valid);
        let usual = [a(3600, 7200)];
        // The server's, as they are: also after the address has run out,
        // also never.
        assert_eq!(renewal_times(1000, 2000, &usual), (1000, 2000));
        assert_eq!(renewal_times(2000, 2000, &usual), (2000, 2000));
        assert_eq!(renewal_times(7200, 9000, &usual), (7200, 9000));
        assert_eq!(renewal_times(1000, INFINITY, &usual), (1000, INFINITY));
        assert_eq!(
            renewal_times(INFINITY, INFINITY, &usual),
            (INFINITY, INFINITY)
        );
        // Both left to the client: from the preferred lifetime.
        assert_eq!(renewal_times(0, 0, &usual), (1800, 2880));
        // T1 left to the client: its own, or earlier to go with the
        // server's T2, never at once.
        assert_eq!(renewal_times(0, 5000, &usual), (1800, 5000));
        assert_eq!(renewal_times(0, 2880, &usual), (1800, 2880));
        assert_eq!(renewal_times(0, 100, &usual), (62, 100));
        assert_eq!(renewal_times(0, 1, &usual), (1, 1));
        assert_eq!(renewal_times(0, INFINITY, &usual), (1800, INFINITY));
        // T2 left to the client: its own, or later to go with the
        // server's T1.
        assert_eq!(renewal_times(1000, 0, &usual), (1000, 2880));
        assert_eq!(renewal_times(1800, 0, &usual), (1800, 2880));
        assert_eq!(renewal_times(3000, 0, &usual), (3000, 4800));
        assert_eq!(renewal_times(INFINITY, 0, &usual), (INFINITY, INFINITY));
        assert_eq!(
            renewal_times(0xf000_0000, 0, &usual),
            (0xf000_0000, INFINITY)
        );
        // Out of order: an IA_NA like that is dropped before this.
        assert_eq!(renewal_times(3000, 2000, &usual), (1800, 2880));
        // The client's own: the shortest preferred lifetime, of the
        // addresses still preferred.
        let several = [a(3600, 7200), a(1000, 7200), a(0, 300)];
        assert_eq!(renewal_times(0, 0, &several), (500, 800));
        assert_eq!(renewal_times(900, 1440, &several), (900, 1440));
        assert_eq!(renewal_times(0, 0, &[a(0, 1000)]), (500, 800));
        assert_eq!(renewal_times(0, 0, &[a(1, 2)]), (1, 1));
        assert_eq!(renewal_times(0, 0, &[a(3600, INFINITY)]), (1800, 2880));
        // Never, for a lease that never ends, unless the server names a
        // time.
        let forever = [a(INFINITY, INFINITY)];
        assert_eq!(renewal_times(0, 0, &forever), (INFINITY, INFINITY));
        assert_eq!(renewal_times(1000, 2000, &forever), (1000, 2000));
        assert_eq!(renewal_times(0, 2000, &forever), (1250, 2000));
        assert_eq!(renewal_times(0, INFINITY, &forever), (INFINITY, INFINITY));
        assert_eq!(renewal_times(1000, 0, &forever), (1000, INFINITY));
    }

    #[test]
    fn a_rebind_time_from_the_server_stands_when_t1_is_left_open() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let bound = acquire(&mut c, t0, ia(0, 100, &[(ADDRESS, 3600, 7200)]));
        let ia_na = c.lease(bound).unwrap().ia_na.unwrap();
        assert_eq!((ia_na.t1, ia_na.t2), (62, 100));
        let (t, _) = first_renew(&mut c);
        assert_eq!(t, bound + secs(62));
        let rebind = loop {
            let (t, actions) = fire(&mut c);
            if c.state() == State::Rebinding {
                assert_eq!(t, bound + secs(100));
                break sent(&actions).clone();
            }
        };
        assert_eq!(rebind.msg_type, msg::REBIND);
    }

    #[test]
    fn a_server_that_says_never_is_never_asked() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let never = ia(INFINITY, INFINITY, &[(ADDRESS, 3600, 7200)]);
        let bound = acquire(&mut c, t0, never);
        // No Renew, no Rebind: the address runs out and that is that.
        assert_eq!(c.deadline(), Some(bound + secs(7200)));
        let (_, actions) = fire(&mut c);
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Soliciting);
    }

    #[test]
    fn a_lease_that_never_ends_has_no_timers() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        acquire(&mut c, t0, ia(0, 0, &[(ADDRESS, INFINITY, INFINITY)]));
        assert_eq!(c.deadline(), None);
        // It can still be renewed by hand: once now, again in time.
        let t = t0 + secs(100_000);
        let renew = sent(&c.handle(Event::Renew, t)).clone();
        assert_eq!(renew.msg_type, msg::RENEW);
        assert_eq!(
            held_addresses(&c, t),
            [address(ADDRESS, INFINITY, INFINITY)]
        );
    }

    #[test]
    fn a_resumed_lease_is_used_at_once_and_confirmed() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let actions = c.handle(
            Event::Resume {
                lease: kept(),
                elapsed: 600,
            },
            t0,
        );
        assert_eq!(
            actions,
            [Action::Bind {
                lease: kept().aged(600),
                fresh: false
            }]
        );
        let aged = kept().aged(600).ia_na.unwrap();
        assert_eq!((aged.t1, aged.t2), (1200, 2280));
        assert_eq!(aged.addresses, [address(ADDRESS, 3000, 6600)]);
        assert_eq!(c.state(), State::Bound);
        // Without a link nothing is sent: only the address's end is on
        // the clock.
        assert_eq!(c.deadline(), Some(t0 + secs(6600)));

        assert!(c.handle(Event::Link(true), t0).is_empty());
        assert_eq!(c.state(), State::Confirming);
        let (t, actions) = fire(&mut c);
        assert!(t - t0 <= CNF_MAX_DELAY);
        let confirm = sent(&actions).clone();
        assert_eq!(confirm.msg_type, msg::CONFIRM);
        assert_eq!(confirm.option(opt::CLIENT_ID), Some(&DUID[..]));
        assert!(confirm.option(opt::SERVER_ID).is_none());
        assert!(confirm.option(opt::ORO).is_none());
        assert_eq!(addresses_of(&confirm), [ADDRESS]);

        // Any server may say so; saying nothing of a status is Success.
        let reply = answer_from(&OTHER_DUID, &confirm, msg::REPLY, vec![]);
        assert!(deliver(&mut c, &reply, t).is_empty());
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t0 + secs(1200)));
        let (_, renew) = first_renew(&mut c);
        assert_eq!(renew.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
    }

    #[test]
    fn a_lease_for_another_link_is_dropped() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(
            Event::Resume {
                lease: kept(),
                elapsed: 0,
            },
            t0,
        );
        c.handle(Event::Link(true), t0);
        let (t, actions) = fire(&mut c);
        let confirm = sent(&actions).clone();
        // A status that settles nothing is not an answer.
        let unsure = answer(
            &confirm,
            msg::REPLY,
            vec![status_option(status::UNSPEC_FAIL)],
        );
        assert!(deliver(&mut c, &unsure, t).is_empty());
        assert_eq!(c.state(), State::Confirming);
        // NotOnLink is noted, once, and the Confirm goes on: another
        // server may yet say otherwise.
        let reply = answer(
            &confirm,
            msg::REPLY,
            vec![status_option(status::NOT_ON_LINK)],
        );
        let actions = deliver(&mut c, &reply, t);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        assert!(deliver(&mut c, &reply, t).is_empty());
        assert_eq!(c.state(), State::Confirming);
        assert!(c.lease(t).is_some());
        // None does: when the exchange is over, so is the lease.
        let (ended, actions) = loop {
            let (now, actions) = fire(&mut c);
            if c.state() != State::Confirming {
                break (now, actions);
            }
            assert_eq!(sent(&actions).msg_type, msg::CONFIRM);
        };
        assert_eq!(ended, t + CNF_MAX_RD);
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert!(c.lease(ended).is_none());
        first_solicit(&mut c);
    }

    #[test]
    fn one_success_outweighs_not_on_link() {
        let t0 = Instant::now();
        // The Success right after the NotOnLink, and one retransmission
        // later.
        for late in [false, true] {
            let mut c = client(Options::default());
            c.handle(
                Event::Resume {
                    lease: kept(),
                    elapsed: 0,
                },
                t0,
            );
            c.handle(Event::Link(true), t0);
            let (mut t, actions) = fire(&mut c);
            let confirm = sent(&actions).clone();
            let no = answer_from(
                &OTHER_DUID,
                &confirm,
                msg::REPLY,
                vec![status_option(status::NOT_ON_LINK)],
            );
            assert!(matches!(&deliver(&mut c, &no, t)[..], [Action::Log(_)]));
            if late {
                let (now, actions) = fire(&mut c);
                assert_eq!(sent(&actions).msg_type, msg::CONFIRM);
                t = now;
            }
            let yes = answer(&confirm, msg::REPLY, vec![status_option(status::SUCCESS)]);
            assert!(deliver(&mut c, &yes, t).is_empty());
            assert_eq!(c.state(), State::Bound);
            assert_eq!(c.lease(t0), Some(kept()));
            assert_eq!(c.deadline(), Some(t0 + secs(1800)));
            // What the other server goes on saying is not heard.
            assert!(deliver(&mut c, &no, t).is_empty());
            assert_eq!(c.state(), State::Bound);
        }
    }

    #[test]
    fn an_unconfirmed_lease_is_kept() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(
            Event::Resume {
                lease: kept(),
                elapsed: 0,
            },
            t0,
        );
        c.handle(Event::Link(true), t0);
        let (first, actions) = fire(&mut c);
        let confirm = sent(&actions).clone();
        let mut confirms = 1;
        let (t, actions) = loop {
            let (t, actions) = fire(&mut c);
            if c.state() != State::Confirming {
                break (t, actions);
            }
            let again = sent(&actions);
            assert_eq!(again.msg_type, msg::CONFIRM);
            assert_eq!(again.transaction_id, confirm.transaction_id);
            confirms += 1;
        };
        // 1, 2, 4 s apart and then the ten seconds are up.
        assert_eq!(confirms, 4);
        assert_eq!(t, first + CNF_MAX_RD);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t0 + secs(1800)));
    }

    #[test]
    fn a_resumed_lease_past_t2_is_rebound() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let actions = c.handle(
            Event::Resume {
                lease: kept(),
                elapsed: 3000,
            },
            t0,
        );
        assert!(matches!(&actions[..], [Action::Bind { fresh: false, .. }]));
        let rebind = sent(&c.handle(Event::Link(true), t0)).clone();
        assert_eq!(rebind.msg_type, msg::REBIND);
        assert_eq!(c.state(), State::Rebinding);
    }

    #[test]
    fn a_lease_past_t1_is_renewed_once_confirmed() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(
            Event::Resume {
                lease: kept(),
                elapsed: 2000,
            },
            t0,
        );
        c.handle(Event::Link(true), t0);
        let (t, actions) = fire(&mut c);
        let confirm = sent(&actions).clone();
        assert_eq!(confirm.msg_type, msg::CONFIRM);
        let actions = deliver(&mut c, &answer(&confirm, msg::REPLY, vec![]), t);
        assert_eq!(sent(&actions).msg_type, msg::RENEW);
        assert_eq!(c.state(), State::Renewing);
    }

    #[test]
    fn a_lease_that_ran_out_or_is_not_ours_is_not_resumed() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let resume = |lease: Lease, elapsed: u32| Event::Resume { lease, elapsed };
        assert!(c.handle(resume(kept(), 7200), t0).is_empty());
        let mut foreign = kept();
        foreign.ia_na.as_mut().unwrap().iaid += 1;
        assert!(c.handle(resume(foreign, 0), t0).is_empty());
        let mut none = kept();
        none.ia_na = None;
        assert!(c.handle(resume(none, 0), t0).is_empty());
        assert_eq!(c.state(), State::Stopped);
        assert_eq!(c.deadline(), None);
        // One of two addresses left.
        let mut two = kept();
        let ia_na = two.ia_na.as_mut().unwrap();
        ia_na.addresses.insert(0, address(ADDRESS2, 100, 200));
        let actions = c.handle(resume(two, 200), t0);
        let [Action::Bind { lease, .. }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS, 3400, 7000)]
        );
        // Nothing resumes over a lease already held.
        assert!(c.handle(resume(kept(), 0), t0).is_empty());
    }

    #[test]
    fn a_lease_survives_the_link() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let bound = acquire(&mut c, t0, one_address());
        // A link that was there all along is no news.
        assert!(c.handle(Event::Link(true), bound).is_empty());
        assert_eq!(c.state(), State::Bound);
        assert!(c.handle(Event::Link(false), bound).is_empty());
        assert_eq!(c.state(), State::Bound);
        // No T1 without a link; the address still runs out.
        assert_eq!(c.deadline(), Some(bound + secs(7200)));
        assert!(c.handle(Event::Link(true), bound + secs(60)).is_empty());
        assert_eq!(c.state(), State::Confirming);
        // Down again in the middle of that, and for good.
        fire(&mut c);
        assert!(c.handle(Event::Link(false), bound + secs(70)).is_empty());
        assert_eq!(c.state(), State::Bound);
        let (t, actions) = fire(&mut c);
        assert_eq!(t, bound + secs(7200));
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Stopped);
        assert_eq!(c.deadline(), None);
    }

    #[test]
    fn an_acquisition_stops_with_the_link() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        // Said twice is said once.
        assert!(c.handle(Event::Link(true), t0).is_empty());
        let (t, request) = to_request(&mut c, &one_address());
        assert!(c.handle(Event::Link(false), t).is_empty());
        assert_eq!(c.state(), State::Stopped);
        assert_eq!(c.deadline(), None);
        // What was under way is over.
        let late = answer(&request, msg::REPLY, vec![one_address()]);
        assert!(deliver(&mut c, &late, t).is_empty());
        assert!(c.handle(Event::Link(true), t).is_empty());
        first_solicit(&mut c);
    }

    #[test]
    fn addresses_run_out_one_by_one() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let two = ia(50, 80, &[(ADDRESS, 100, 200), (ADDRESS2, 3600, 7200)]);
        let bound = acquire(&mut c, t0, two);
        // Only the lifetimes are on the clock without a link.
        c.handle(Event::Link(false), bound);
        let (t, actions) = fire(&mut c);
        assert_eq!(t, bound + secs(200));
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS2, 3400, 7000)]
        );
        assert_eq!(c.state(), State::Bound);
        let (t, actions) = fire(&mut c);
        assert_eq!(t, bound + secs(7200));
        assert!(actions.contains(&Action::Unbind));
    }

    #[test]
    fn an_address_can_run_out_before_t1() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let two = ia(1000, 2000, &[(ADDRESS, 100, 200), (ADDRESS2, 3600, 7200)]);
        let bound = acquire(&mut c, t0, two);
        let (t, actions) = fire(&mut c);
        assert_eq!(t, bound + secs(200));
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.addresses, [address(ADDRESS2, 3400, 7000)]);
        assert_eq!((ia_na.t1, ia_na.t2), (800, 1800));
        // T1 is where it was, and the Renew names what is left.
        assert_eq!(c.state(), State::Bound);
        let (t, renew) = first_renew(&mut c);
        assert_eq!(t, bound + secs(1000));
        assert_eq!(addresses_of(&renew), [ADDRESS2]);
    }

    #[test]
    fn addresses_that_end_together_end_the_lease() {
        let t0 = Instant::now();
        // The kernel reports the first one gone, or a duplicate, at the
        // moment both run out and before the client's own timer fires.
        for conflict in [false, true] {
            let mut c = client(Options::default());
            // Never renewed: nothing but the lifetimes is on the clock.
            let two = ia(
                INFINITY,
                INFINITY,
                &[(ADDRESS, 100, 200), (ADDRESS2, 100, 200)],
            );
            let bound = acquire(&mut c, t0, two);
            let end = bound + secs(200);
            assert_eq!(c.deadline(), Some(end));
            let event = if conflict {
                Event::AddressConflict(ADDRESS)
            } else {
                Event::AddressLost(ADDRESS)
            };
            let actions = c.handle(event, end);
            // The other address has run out too: no lease is left, and
            // the client is not left bound to nothing with no timer.
            assert!(
                matches!(&actions[..], [Action::Log(_), Action::Unbind, ..]),
                "{actions:?}"
            );
            assert!(c.lease(end).is_none());
            let want = if conflict {
                State::Declining
            } else {
                State::Soliciting
            };
            assert_eq!(c.state(), want);
            assert!(c.deadline().is_some());
            assert!(c.handle(Event::AddressLost(ADDRESS2), end).is_empty());
            // It finds its way back to asking.
            while c.state() != State::Soliciting {
                fire(&mut c);
            }
            first_solicit(&mut c);
        }
    }

    #[test]
    fn a_duplicate_address_is_declined() {
        let t0 = Instant::now();
        // Answered, and not.
        for answered in [true, false] {
            let mut c = client(Options::default());
            let t = acquire(&mut c, t0, one_address());
            // Not one of ours.
            assert!(c.handle(Event::AddressConflict(ADDRESS2), t).is_empty());
            let actions = c.handle(Event::AddressConflict(ADDRESS), t);
            let [Action::Log(_), Action::Unbind, Action::Send(decline)] = &actions[..] else {
                panic!("{actions:?}")
            };
            assert_eq!(decline.msg_type, msg::DECLINE);
            assert_eq!(decline.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
            assert_eq!(addresses_of(decline), [ADDRESS]);
            assert!(decline.option(opt::ORO).is_none());
            assert_eq!(c.state(), State::Declining);
            assert!(c.lease(t).is_none());
            let decline = decline.clone();
            let ended = if answered {
                // Not for another server to answer.
                let other = answer_from(&OTHER_DUID, &decline, msg::REPLY, vec![]);
                assert!(deliver(&mut c, &other, t).is_empty());
                assert_eq!(c.state(), State::Declining);
                assert!(deliver(&mut c, &answer(&decline, msg::REPLY, vec![]), t).is_empty());
                t
            } else {
                let mut declines = 1;
                loop {
                    let (t, actions) = fire(&mut c);
                    if c.state() != State::Declining {
                        assert!(actions.is_empty());
                        assert_eq!(declines, DEC_MAX_RC);
                        break t;
                    }
                    assert_eq!(sent(&actions).transaction_id, decline.transaction_id);
                    declines += 1;
                }
            };
            // Another address is asked for, not at once.
            assert_eq!(c.state(), State::Backoff);
            assert_eq!(c.deadline(), Some(ended + secs(1)));
            fire(&mut c);
            first_solicit(&mut c);
        }
    }

    #[test]
    fn declining_one_address_leaves_the_others() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let three = ia(
            1800,
            2880,
            &[
                (ADDRESS, 3600, 7200),
                (ADDRESS2, 3600, 7200),
                (ADDRESS3, 3600, 7200),
            ],
        );
        let t = acquire(&mut c, t0, three);
        let actions = c.handle(Event::AddressConflict(ADDRESS), t);
        let [
            Action::Log(_),
            Action::Bind { lease, fresh: true },
            Action::Send(decline),
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        let left: Vec<Ipv6Addr> = lease
            .ia_na
            .iter()
            .flat_map(|ia| &ia.addresses)
            .map(|a| a.address)
            .collect();
        assert_eq!(left, [ADDRESS2, ADDRESS3]);
        assert_eq!(addresses_of(decline), [ADDRESS]);
        // A second one while that is under way: one Decline for both.
        let actions = c.handle(Event::AddressConflict(ADDRESS3), t);
        let decline = sent(&actions).clone();
        assert_eq!(addresses_of(&decline), [ADDRESS, ADDRESS3]);
        assert_eq!(held_addresses(&c, t), [address(ADDRESS2, 3600, 7200)]);
        // Then the lease goes on.
        assert!(deliver(&mut c, &answer(&decline, msg::REPLY, vec![]), t).is_empty());
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t + secs(1800)));
    }

    #[test]
    fn a_duplicate_found_without_a_link_is_only_dropped() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let two = ia(1800, 2880, &[(ADDRESS, 3600, 7200), (ADDRESS2, 3600, 7200)]);
        let t = acquire(&mut c, t0, two);
        c.handle(Event::Link(false), t);
        // Nobody to tell.
        let actions = c.handle(Event::AddressConflict(ADDRESS), t);
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Bind { .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
        let actions = c.handle(Event::AddressConflict(ADDRESS2), t);
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Stopped);
        assert_eq!(c.deadline(), None);
    }

    #[test]
    fn a_lost_address_is_asked_for_again() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let t = acquire(&mut c, t0, one_address());
        assert!(c.handle(Event::AddressLost(ADDRESS2), t).is_empty());
        let actions = c.handle(Event::AddressLost(ADDRESS), t + secs(10));
        assert_eq!(
            actions,
            [
                Action::Log(format!("{ADDRESS} left the interface")),
                Action::Unbind
            ]
        );
        assert_eq!(c.state(), State::Soliciting);
        first_solicit(&mut c);
    }

    #[test]
    fn the_kernel_may_expire_an_address_first() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let two = ia(50, 80, &[(ADDRESS, 100, 200), (ADDRESS2, 3600, 7200)]);
        let t = acquire(&mut c, t0, two);
        c.handle(Event::Link(false), t);
        let actions = c.handle(Event::AddressLost(ADDRESS), t + secs(198));
        let [Action::Log(text), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(text, &format!("{ADDRESS} expired"));
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS2, 3402, 7002)]
        );
        // Without a link the end of the last address is the end.
        let actions = c.handle(Event::AddressLost(ADDRESS2), t + secs(300));
        assert!(actions.contains(&Action::Unbind));
        assert_eq!(c.state(), State::Stopped);
    }

    #[test]
    fn release_gives_the_address_back() {
        let t0 = Instant::now();
        // Answered, and not.
        for answered in [true, false] {
            let mut c = client(Options::default());
            let t = acquire(&mut c, t0, one_address());
            let actions = c.handle(Event::Release, t);
            // Out of use first, then said.
            let [Action::Unbind, Action::Send(release)] = &actions[..] else {
                panic!("{actions:?}")
            };
            assert_eq!(release.msg_type, msg::RELEASE);
            assert_eq!(release.option(opt::CLIENT_ID), Some(&DUID[..]));
            assert_eq!(release.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
            assert_eq!(addresses_of(release), [ADDRESS]);
            assert_eq!(c.state(), State::Releasing);
            assert!(c.wants_socket() && c.lease(t).is_none());
            let release = release.clone();
            // A second `release` changes nothing.
            assert!(c.handle(Event::Release, t).is_empty());
            if answered {
                // Whatever the status.
                let reply = answer(
                    &release,
                    msg::REPLY,
                    vec![status_option(status::NO_BINDING)],
                );
                assert!(deliver(&mut c, &reply, t).is_empty());
            } else {
                let mut releases = 1;
                loop {
                    let (_, actions) = fire(&mut c);
                    if c.state() != State::Releasing {
                        assert!(actions.is_empty());
                        break;
                    }
                    assert_eq!(sent(&actions).transaction_id, release.transaction_id);
                    releases += 1;
                }
                assert_eq!(releases, REL_MAX_RC);
            }
            assert_eq!(c.state(), State::Released);
            assert_eq!(c.deadline(), None);
            assert!(!c.wants_socket() && !c.finished());
            // The link coming and going does not wake it; `renew` does.
            c.handle(Event::Link(false), t);
            assert!(c.handle(Event::Link(true), t).is_empty());
            assert_eq!(c.state(), State::Released);
            assert!(c.handle(Event::Renew, t).is_empty());
            first_solicit(&mut c);
        }
    }

    #[test]
    fn renew_cuts_a_release_short() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let t = acquire(&mut c, t0, one_address());
        c.handle(Event::Release, t);
        assert_eq!(c.state(), State::Releasing);
        assert!(c.handle(Event::Renew, t).is_empty());
        first_solicit(&mut c);
    }

    #[test]
    fn a_release_that_cannot_be_said_only_forgets() {
        let t0 = Instant::now();
        // `no-release`, and no link to say it on.
        for no_release in [true, false] {
            let mut c = client(Options::default());
            let t = acquire(&mut c, t0, one_address());
            if no_release {
                c.set_options(Options {
                    no_release: true,
                    ..Options::default()
                });
            } else {
                c.handle(Event::Link(false), t);
            }
            assert_eq!(c.handle(Event::Release, t), [Action::Unbind]);
            assert_eq!(c.state(), State::Released);
            assert_eq!(c.deadline(), None);
            // `renew` without a link waits for it.
            if !no_release {
                assert!(c.handle(Event::Renew, t).is_empty());
                assert_eq!(c.state(), State::Stopped);
                c.handle(Event::Link(true), t);
                first_solicit(&mut c);
            }
        }
    }

    #[test]
    fn releasing_nothing_is_only_a_state() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        let (t, _) = to_request(&mut c, &one_address());
        assert!(c.handle(Event::Release, t).is_empty());
        assert_eq!(c.state(), State::Released);
        assert_eq!(c.deadline(), None);
    }

    #[test]
    fn a_release_ends_when_the_link_does() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let t = acquire(&mut c, t0, one_address());
        c.handle(Event::Release, t);
        assert!(c.handle(Event::Link(false), t).is_empty());
        assert_eq!(c.state(), State::Released);
        assert_eq!(c.deadline(), None);
    }

    #[test]
    fn stop_is_final() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let t = acquire(&mut c, t0, one_address());
        let actions = c.handle(Event::Stop, t);
        let [Action::Unbind, Action::Send(release)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(release.msg_type, msg::RELEASE);
        let release = release.clone();
        // Until the Release is over the client is still needed.
        assert_eq!(c.state(), State::Releasing);
        assert!(!c.finished() && c.wants_socket());
        assert!(c.handle(Event::Renew, t).is_empty());
        assert_eq!(c.state(), State::Releasing);
        assert_eq!(sent(&fire(&mut c).1).msg_type, msg::RELEASE);
        assert!(deliver(&mut c, &answer(&release, msg::REPLY, vec![]), t).is_empty());
        assert_eq!(c.state(), State::Stopped);
        assert!(c.finished() && !c.wants_socket());
        // Nothing starts it again.
        for event in [
            Event::Link(false),
            Event::Link(true),
            Event::Renew,
            Event::Timeout,
            Event::Resume {
                lease: kept(),
                elapsed: 0,
            },
        ] {
            assert!(c.handle(event, t).is_empty());
            assert_eq!(c.state(), State::Stopped);
            assert_eq!(c.deadline(), None);
        }
    }

    #[test]
    fn stop_takes_over_a_release_under_way() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let t = acquire(&mut c, t0, one_address());
        let release = sent(&c.handle(Event::Release, t)).clone();
        assert!(c.handle(Event::Stop, t).is_empty());
        assert!(!c.finished());
        deliver(&mut c, &answer(&release, msg::REPLY, vec![]), t);
        assert_eq!(c.state(), State::Stopped);
        assert!(c.finished());
    }

    #[test]
    fn stop_with_no_lease_is_over_at_once() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        assert!(c.handle(Event::Stop, t0).is_empty());
        assert!(c.finished());
        assert_eq!(c.deadline(), None);
    }

    fn parameters_only() -> Options {
        Options {
            parameters_only: true,
            ..Options::default()
        }
    }

    /// From `Informing` with its delay running: the Information-request.
    fn first_information_request(c: &mut Client) -> (Instant, ClientMessage) {
        assert_eq!(c.state(), State::Informing);
        let (now, actions) = fire(c);
        let request = sent(&actions).clone();
        assert_eq!(request.msg_type, msg::INFORMATION_REQUEST);
        (now, request)
    }

    #[test]
    fn parameters_only_asks_for_information() {
        let t0 = Instant::now();
        let mut c = client(parameters_only());
        // A lease on disk is not this client's business.
        let resume = Event::Resume {
            lease: kept(),
            elapsed: 0,
        };
        assert!(c.handle(resume, t0).is_empty());
        assert!(c.handle(Event::Link(true), t0).is_empty());
        let (t, request) = first_information_request(&mut c);
        assert!(t - t0 <= INF_MAX_DELAY);
        assert_eq!(request.option(opt::CLIENT_ID), Some(&DUID[..]));
        assert!(request.option(opt::SERVER_ID).is_none());
        assert!(request.option(opt::IA_NA).is_none());
        assert_eq!(elapsed_of(&request), 0);
        let asked = wanted(&request);
        assert!(asked.contains(&opt::INFORMATION_REFRESH_TIME));
        assert!(asked.contains(&opt::INF_MAX_RT) && asked.contains(&opt::DNS_SERVERS));

        // A failure is not an answer.
        let failed = answer(
            &request,
            msg::REPLY,
            vec![status_option(status::UNSPEC_FAIL)],
        );
        assert!(deliver(&mut c, &failed, t).is_empty());
        let reply = answer(
            &request,
            msg::REPLY,
            vec![
                Dhcp6Option::new(opt::DNS_SERVERS, DNS.octets()),
                u32_option(opt::INFORMATION_REFRESH_TIME, 1200),
            ],
        );
        let actions = deliver(&mut c, &reply, t);
        let want = Lease {
            server_id: SERVER_DUID.to_vec(),
            server_address: SERVER,
            ia_na: None,
            dns_servers: vec![DNS],
            domain_list: vec![],
            ntp_servers: vec![],
        };
        assert_eq!(
            actions,
            [Action::Bind {
                lease: want.clone(),
                fresh: true
            }]
        );
        assert_eq!(c.state(), State::Informed);
        assert_eq!(c.lease(t + secs(100)), Some(want));
        // Asked again when the refresh time is up, under a new
        // transaction.
        assert_eq!(c.deadline(), Some(t + secs(1200)));
        assert!(fire(&mut c).1.is_empty());
        let (_, again) = first_information_request(&mut c);
        assert_ne!(again.transaction_id, request.transaction_id);
    }

    #[test]
    fn the_refresh_time_has_a_floor_a_default_and_no_end() {
        let t0 = Instant::now();
        for (refresh, want) in [
            (Some(100), Some(600)),
            (Some(600), Some(600)),
            (Some(100_000), Some(100_000)),
            (None, Some(86400)),
            (Some(INFINITY), None),
        ] {
            let mut c = client(parameters_only());
            c.handle(Event::Link(true), t0);
            let (t, request) = first_information_request(&mut c);
            let options = refresh
                .map(|time| u32_option(opt::INFORMATION_REFRESH_TIME, time))
                .into_iter()
                .collect();
            deliver(&mut c, &answer(&request, msg::REPLY, options), t);
            assert_eq!(c.state(), State::Informed);
            assert_eq!(c.deadline(), want.map(|s| t + secs(s)), "{refresh:?}");
        }
    }

    #[test]
    fn an_information_request_is_retransmitted_up_to_inf_max_rt() {
        let t0 = Instant::now();
        let mut c = client(parameters_only());
        c.handle(Event::Link(true), t0);
        let (t, request) = first_information_request(&mut c);
        let gap = c.deadline().unwrap() - t;
        assert!(gap >= secs(1).mul_f64(0.9) && gap <= secs(1).mul_f64(1.1));
        let settled_gap = |c: &mut Client| {
            let mut gap = Duration::ZERO;
            for _ in 0..20 {
                let (t, actions) = fire(c);
                let again = sent(&actions);
                assert_eq!(again.msg_type, msg::INFORMATION_REQUEST);
                assert_eq!(again.transaction_id, request.transaction_id);
                gap = c.deadline().unwrap() - t;
            }
            gap
        };
        let gap = settled_gap(&mut c);
        assert!(gap >= secs(3240) && gap <= secs(3960), "{gap:?}");
        // A server's INF_MAX_RT, in a message that is no answer.
        let t = c.deadline().unwrap();
        let capped = answer(
            &request,
            msg::REPLY,
            vec![
                status_option(status::UNSPEC_FAIL),
                u32_option(opt::INF_MAX_RT, 300),
            ],
        );
        assert!(deliver(&mut c, &capped, t).is_empty());
        let gap = settled_gap(&mut c);
        assert!(gap >= secs(270) && gap <= secs(330), "{gap:?}");
        // Values outside 60..=86400 are not taken.
        let t = c.deadline().unwrap();
        for value in [59, 86401] {
            let mut odd = capped.clone();
            odd.options[3] = u32_option(opt::INF_MAX_RT, value);
            deliver(&mut c, &odd, t);
        }
        let gap = settled_gap(&mut c);
        assert!(gap >= secs(270) && gap <= secs(330), "{gap:?}");
    }

    #[test]
    fn information_follows_the_link_and_the_operator() {
        let t0 = Instant::now();
        let mut c = client(parameters_only());
        c.handle(Event::Link(true), t0);
        let (t, request) = first_information_request(&mut c);
        deliver(&mut c, &answer(&request, msg::REPLY, vec![]), t);
        assert_eq!(c.state(), State::Informed);
        // `renew` asks at once.
        let again = sent(&c.handle(Event::Renew, t)).clone();
        assert_eq!(again.msg_type, msg::INFORMATION_REQUEST);
        deliver(&mut c, &answer(&again, msg::REPLY, vec![]), t);
        // What is known is kept while the link is away, and asked for
        // again when it is back: it may be another link.
        assert!(c.handle(Event::Link(false), t).is_empty());
        assert_eq!(c.state(), State::Informed);
        assert!(c.lease(t).is_some());
        assert_eq!(c.deadline(), None);
        assert!(c.handle(Event::Link(true), t).is_empty());
        first_information_request(&mut c);
        // `release` forgets it, with nothing to give back.
        assert_eq!(c.handle(Event::Release, t), [Action::Unbind]);
        assert_eq!(c.state(), State::Released);
        assert!(c.handle(Event::Renew, t).is_empty());
        first_information_request(&mut c);
    }

    #[test]
    fn options_change_at_the_next_message() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        c.handle(Event::Link(true), t0);
        c.set_options(Options {
            parameters_only: true,
            rapid_commit: true,
            no_release: false,
        });
        // Rapid commit, yes; another protocol, no.
        let (t, solicit) = first_solicit(&mut c);
        assert!(solicit.option(opt::RAPID_COMMIT).is_some());
        c.handle(Event::Release, t);
        c.handle(Event::Renew, t);
        assert_eq!(c.state(), State::Soliciting);
    }

    #[test]
    fn retransmission_times_stay_within_a_tenth() {
        let draw = |value: u32, fixed: u64, base: u64, positive: bool| {
            let mut c = Client::new(
                DUID.to_vec(),
                IAID,
                Options::default(),
                Box::new(move || value),
            );
            c.randomized(secs(fixed), secs(base), positive)
        };
        assert_eq!(draw(0, 10, 10, false), secs(9));
        assert_eq!(draw(1000, 10, 10, false), secs(10));
        assert_eq!(draw(2000, 10, 10, false), secs(11));
        assert_eq!(draw(2001, 10, 10, false), secs(9));
        // RT = 2 × RTprev + RAND × RTprev.
        assert_eq!(draw(0, 20, 10, false), secs(19));
        assert_eq!(draw(2000, 20, 10, false), secs(21));
        // Above the base, never on it.
        for value in [0, 1, 990, 991, u32::MAX] {
            let rt = draw(value, 1, 1, true);
            assert!(rt > secs(1) && rt <= Duration::from_millis(1100), "{rt:?}");
        }
    }

    #[test]
    fn a_lease_keeps_its_shape_on_disk() {
        let json = serde_json::to_value(kept()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "server_id": [0, 3, 0, 1, 2, 0, 0, 0, 0, 254],
                "server_address": "fe80::1",
                "ia_na": {
                    "iaid": 0x0102_0304,
                    "t1": 1800,
                    "t2": 2880,
                    "addresses": [
                        {"address": "2001:db8::100", "preferred": 3600, "valid": 7200}
                    ],
                },
                "dns_servers": ["2001:db8::53"],
                "domain_list": ["example.com"],
                "ntp_servers": [{"fqdn": "ntp.example.com"}],
            })
        );
        let back: Lease = serde_json::from_value(json).unwrap();
        assert_eq!(back, kept());
    }
}
