//! The DHCPv6 client state machine (RFC 8415 §18.2), without I/O.
//!
//! [`Client::handle`] takes an [`Event`] and the current time and returns
//! [`Action`]s for the task to carry out: messages to send, a lease to
//! apply or withdraw. Nothing here opens a socket, reads a clock or
//! touches the RIB, so every timer and transition is tested with a
//! scripted server and a clock the test moves.
//!
//! A client asks for an address (one IA_NA), for delegated prefixes (an
//! IA_PD each), or for both in one exchange ([`Asks`]). With nothing to
//! ask for (`parameters-only`) it asks for the rest of the configuration
//! alone (DNS, NTP), through Information-request.
//!
//! | State | Meaning |
//! |---|---|
//! | `Stopped` | not started, or no usable link and no lease |
//! | `Soliciting` | Solicit sent or about to be, collecting Advertises |
//! | `Requesting` | Request sent to the chosen server, or to one that had no record of what it leased |
//! | `Bound` | lease held, waiting for T1 |
//! | `Renewing` | a Renew under way with each server whose leases have reached T1, until T2 |
//! | `Rebinding` | Rebind sent to any server about what is past its T2, until nothing is |
//! | `Confirming` | is a lease kept across a restart or a link loss right for this link? A Confirm, or a Rebind when the lease holds a prefix |
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

use dhcp_packet::v6::params::{
    INFINITY, IaAddress, IaNa, IaPd as WirePd, IaPrefix, NtpServer, Params, StatusCode,
};
use dhcp_packet::v6::{ClientMessage, Dhcp6Option, msg, opt, status};
use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

/// `interface <if> ipv6 dhcpv6-options …`, as far as the protocol goes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Offer the two-message exchange: a Solicit that a server may answer
    /// with a Reply at once.
    pub rapid_commit: bool,
    /// Give the lease up without telling the server.
    pub no_release: bool,
}

/// What a client asks a server for: the identity associations it wants
/// filled. With none it asks for the other configuration only
/// (`parameters-only`, an Information-request).
///
/// It is fixed for the life of a [`Client`], like the DUID: see
/// [`Client::identity`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asks {
    /// `address dhcpv6`: an address, in an IA_NA under this IAID.
    pub ia_na: Option<u32>,
    /// `dhcpv6-options pd <id>`: a delegated prefix each, in an IA_PD.
    pub ia_pd: Vec<PdAsk>,
}

/// One prefix delegation asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdAsk {
    /// The IAID of its IA_PD: the `pd <id>` number.
    pub iaid: u32,
    /// The prefix length hinted at (`pd <id> length`). A hint: the
    /// server delegates what it sees fit.
    pub length: u8,
}

impl Asks {
    /// Nothing to lease: the client speaks Information-request.
    pub fn is_empty(&self) -> bool {
        self.ia_na.is_none() && self.ia_pd.is_empty()
    }

    /// How many identity associations.
    fn count(&self) -> usize {
        usize::from(self.ia_na.is_some()) + self.ia_pd.len()
    }
}

/// What the server granted.
///
/// Every time in it is in seconds from one moment: when the
/// [`Action::Bind`] carrying it was returned. [`Lease::aged`] moves that
/// moment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// The DUID of the server the other configuration is from: the one
    /// the addresses are leased from, or without an address the first
    /// prefix. Who an identity association is leased from is its own
    /// `server_id`.
    pub server_id: Vec<u8>,
    /// Where its messages came from, a link-local address. For people:
    /// the protocol knows a server by its DUID.
    pub server_address: Ipv6Addr,
    /// The addresses. `None` when none is held: none was asked for, or
    /// the server gave none.
    pub ia_na: Option<Ia>,
    /// The delegated prefixes: an entry for each IA_PD that holds any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ia_pd: Vec<IaPd>,
    pub dns_servers: Vec<Ipv6Addr>,
    pub domain_list: Vec<String>,
    pub ntp_servers: Vec<Ntp>,
}

/// The identity association for the interface's addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ia {
    pub iaid: u32,
    /// The DUID of the server the addresses are leased from: who is asked
    /// to renew them, and told when they go back. Each identity
    /// association has its own, since a Rebind is for any server to
    /// answer and one may answer for a part of the lease only.
    ///
    /// Empty in a lease written before it was kept: [`Lease::server_id`]
    /// then.
    #[serde(default)]
    pub server_id: Vec<u8>,
    /// When to renew, already chosen by the client where the server left
    /// it open; [`INFINITY`] never. 0 is "now", not "the client decides"
    /// as on the wire. Each identity association of a lease has its own,
    /// and one Renew covers them all (RFC 8415 §18.2.4), at the earliest:
    /// [`Lease::renewal`].
    pub t1: u32,
    /// When to rebind; as `t1`.
    pub t2: u32,
    pub addresses: Vec<Address>,
}

/// An identity association for delegated prefixes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IaPd {
    pub iaid: u32,
    /// As [`Ia::server_id`].
    #[serde(default)]
    pub server_id: Vec<u8>,
    /// As [`Ia::t1`] and [`Ia::t2`].
    pub t1: u32,
    pub t2: u32,
    pub prefixes: Vec<Prefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub address: Ipv6Addr,
    /// Seconds; [`INFINITY`] never ends.
    pub preferred: u32,
    pub valid: u32,
}

/// A delegated prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefix {
    pub prefix: Ipv6Net,
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
    /// without the addresses and prefixes whose valid lifetime has run
    /// out.
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
        for ia in &mut lease.ia_pd {
            ia.t1 = left(ia.t1);
            ia.t2 = left(ia.t2);
            ia.prefixes.retain_mut(|p| {
                p.preferred = left(p.preferred);
                p.valid = left(p.valid);
                p.valid > 0
            });
        }
        lease.prune();
        lease
    }

    /// Whether an address or a prefix is held.
    pub fn has_leases(&self) -> bool {
        self.ia_na
            .as_ref()
            .is_some_and(|ia| !ia.addresses.is_empty())
            || self.ia_pd.iter().any(|ia| !ia.prefixes.is_empty())
    }

    /// An identity association that holds nothing is not in the lease:
    /// it is one to ask for again.
    fn prune(&mut self) {
        if self
            .ia_na
            .as_ref()
            .is_some_and(|ia| ia.addresses.is_empty())
        {
            self.ia_na = None;
        }
        self.ia_pd.retain(|ia| !ia.prefixes.is_empty());
    }

    /// Keep only the identity associations `asks` asks for.
    fn keep(&mut self, asks: &Asks) {
        if self
            .ia_na
            .as_ref()
            .is_some_and(|ia| asks.ia_na != Some(ia.iaid))
        {
            self.ia_na = None;
        }
        self.ia_pd
            .retain(|ia| asks.ia_pd.iter().any(|ask| ask.iaid == ia.iaid));
    }

    /// A lease written before each identity association kept its server
    /// had one for all of them.
    fn adopt(&mut self) {
        let ia_na = self.ia_na.iter_mut().map(|ia| &mut ia.server_id);
        let ia_pd = self.ia_pd.iter_mut().map(|ia| &mut ia.server_id);
        for server_id in ia_na.chain(ia_pd).filter(|id| id.is_empty()) {
            server_id.clone_from(&self.server_id);
        }
    }

    /// Drop these identity associations, with all they hold.
    fn forget(&mut self, ias: &Ias) {
        if ias.ia_na {
            self.ia_na = None;
        }
        self.ia_pd.retain(|ia| !ias.ia_pd.contains(&ia.iaid));
    }

    /// When the lease is renewed, and when it is rebound: the earliest T1
    /// and the earliest T2 among its identity associations, [`INFINITY`]
    /// for never. One Renew, and one Rebind, covers them all (RFC 8415
    /// §18.2.4).
    pub fn renewal(&self) -> (u32, u32) {
        let ia_na = self.ia_na.iter().map(|ia| (ia.t1, ia.t2));
        let ia_pd = self.ia_pd.iter().map(|ia| (ia.t1, ia.t2));
        let times: Vec<(u32, u32)> = ia_na.chain(ia_pd).collect();
        let t1 = times.iter().map(|(t1, _)| *t1).min().unwrap_or(INFINITY);
        let t2 = times.iter().map(|(_, t2)| *t2).min().unwrap_or(INFINITY);
        (t1, t2)
    }

    /// The lifetimes of everything held: preferred, valid.
    fn lifetimes(&self) -> Vec<(u32, u32)> {
        let addresses = self.ia_na.iter().flat_map(|ia| lifetimes(&ia.addresses));
        let prefixes = self.ia_pd.iter().flat_map(|ia| lifetimes(&ia.prefixes));
        addresses.chain(prefixes).collect()
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
    /// The lease as it stands, its times counted from now, to the second:
    /// install or refresh its addresses and prefixes, and withdraw any of
    /// an earlier `Bind` that is no longer in it. `fresh` says a server's message or
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
    asks: Asks,
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
    /// asked. With a lease held: whose exchange is being dealt with
    /// (`renewals`).
    server: Option<Server>,
    /// `Renewing`, `Rebinding`, and `Requesting` with a lease held: the
    /// exchanges under way. None of them waits for another. While one is
    /// sent, or its answer read, it is in `state`, `server`, `exchange`
    /// and `wake` instead, like any other state's exchange; otherwise
    /// `state` names the most pressing of them (`renewing`).
    renewals: Vec<Renewal>,
    /// Servers that are not sent a Request yet, and until when
    /// (`on_recovery_reply`).
    quiet: Vec<(Vec<u8>, Instant)>,
    held: Option<Held>,
    /// `Declining`, `Releasing`: what goes back, and to whom.
    returning: Option<Returning>,
    /// `Releasing`: what goes back after that, to the other servers
    /// something is leased from. Each `release` sets it anew.
    returning_next: Vec<Returning>,
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

/// An exchange under way about a lease that is held: a Renew with one
/// server about what is leased from it, the Request that follows when
/// that server answers NoBinding, or the Rebind, which is for any server
/// and about all of the lease.
struct Renewal {
    /// Who is asked: nobody in particular (no DUID) in a Rebind. For a
    /// Request, also what it names and what the server had no record of.
    server: Server,
    /// `Renewing`, `Requesting` or `Rebinding`: which of the three.
    state: State,
    exchange: Exchange,
    /// When it is sent again.
    wake: Option<Instant>,
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
    /// A Renew or a Rebind: the identity associations a Reply has
    /// answered for so far. It is over when that is every one held.
    answered: Ias,
}

/// The addresses and prefixes a message names.
#[derive(Clone, Default)]
struct Named {
    addresses: Vec<Ipv6Addr>,
    /// Each with the IAID of its IA_PD.
    prefixes: Vec<(u32, Ipv6Net)>,
}

/// Some of the identity associations a client asks for.
#[derive(Clone, Default)]
struct Ias {
    ia_na: bool,
    /// The IA_PDs, by IAID.
    ia_pd: Vec<u32>,
}

impl Ias {
    /// Every one in `asks` that is not in `but`.
    fn all_but(asks: &Asks, but: &Ias) -> Ias {
        let ia_pd = asks.ia_pd.iter().map(|ask| ask.iaid);
        Ias {
            ia_na: asks.ia_na.is_some() && !but.ia_na,
            ia_pd: ia_pd.filter(|iaid| !but.ia_pd.contains(iaid)).collect(),
        }
    }

    fn is_empty(&self) -> bool {
        !self.ia_na && self.ia_pd.is_empty()
    }

    /// Add those in `other`.
    fn include(&mut self, other: &Ias) {
        self.ia_na |= other.ia_na;
        for iaid in &other.ia_pd {
            if !self.ia_pd.contains(iaid) {
                self.ia_pd.push(*iaid);
            }
        }
    }

    /// Whether one of them is in `other`.
    fn meets(&self, other: &Ias) -> bool {
        (self.ia_na && other.ia_na) || self.ia_pd.iter().any(|iaid| other.ia_pd.contains(iaid))
    }

    /// Whether every one in `other` is among them.
    fn covers(&self, other: &Ias) -> bool {
        (self.ia_na || !other.ia_na) && other.ia_pd.iter().all(|iaid| self.ia_pd.contains(iaid))
    }

    /// Take those in `other` out.
    fn exclude(&mut self, other: &Ias) {
        self.ia_na &= !other.ia_na;
        self.ia_pd.retain(|iaid| !other.ia_pd.contains(iaid));
    }

    /// Add the ones `grant` speaks of.
    fn add(&mut self, grant: &Grant<'_>) {
        self.ia_na |= grant.ia_na.is_some();
        for ia in &grant.ia_pd {
            if !self.ia_pd.contains(&ia.iaid) {
                self.ia_pd.push(ia.iaid);
            }
        }
    }

    /// Whether every identity association `lease` holds is among them,
    /// those in `but` aside.
    fn cover(&self, lease: &Lease, but: &Ias) -> bool {
        let ia_pd = &mut lease.ia_pd.iter();
        (self.ia_na || but.ia_na || lease.ia_na.is_none())
            && ia_pd.all(|ia| self.ia_pd.contains(&ia.iaid) || but.ia_pd.contains(&ia.iaid))
    }
}

/// A server and what it offers. In `Renewing` only who it is counts: the
/// server of the Renew being dealt with.
struct Server {
    id: Vec<u8>,
    preference: u8,
    /// How many of the identity associations asked for it offers.
    count: usize,
    /// Before a lease is held: what it offers, named again in the
    /// Request.
    named: Named,
    /// A Request after NoBinding: the identity associations the server
    /// had no record of.
    lost: Ias,
    /// With a lease held: the identity associations this exchange leaves
    /// to others, though its server leases them. Another exchange has
    /// given something of them since this one went out (`restored`), or
    /// a Request was out about them when this Renew began (`renewing`).
    settled: Ias,
}

impl Renewal {
    fn is_request(&self) -> bool {
        self.state == State::Requesting
    }

    fn is_rebind(&self) -> bool {
        self.state == State::Rebinding
    }

    /// What a Renew or a Request asks its server about, of what is
    /// `held`: what is leased from that server and what the server had no
    /// record of, but what the exchange leaves out. (Nothing, so, for the
    /// Rebind: it is with no server.)
    fn asks(&self, held: &Held) -> Ias {
        let mut asks = held.all();
        asks.exclude(&held.others(&self.server.id, &self.server.lost));
        asks.exclude(&self.server.settled);
        asks
    }
}

impl Server {
    /// The server a Renew is for.
    fn asked(id: Vec<u8>) -> Server {
        Server {
            id,
            preference: 0,
            count: 0,
            named: Named::default(),
            lost: Ias::default(),
            settled: Ias::default(),
        }
    }
}

struct Held {
    lease: Lease,
    /// When the lease's times count from.
    since: Instant,
}

struct Returning {
    server_id: Vec<u8>,
    named: Named,
}

/// A server's message, past the checks every message gets.
struct Answer<'a> {
    params: &'a Params,
    server_id: Vec<u8>,
    source: Ipv6Addr,
}

/// What a server's message holds for the identity associations asked
/// for: each one that is there without a failure status. Their addresses
/// and prefixes still need a look: see [`usable`].
#[derive(Default)]
struct Grant<'a> {
    ia_na: Option<&'a IaNa>,
    ia_pd: Vec<&'a WirePd>,
}

impl Grant<'_> {
    fn is_empty(&self) -> bool {
        self.ia_na.is_none() && self.ia_pd.is_empty()
    }
}

/// What a server's message says about what is asked for.
enum Verdict<'a> {
    Granted(Grant<'a>),
    /// The server could not say (UnspecFail, UseMulticast): the message
    /// goes out again when its retransmission is due.
    Unanswered(String),
    /// The server has no record of some identity associations. With
    /// them, what the message holds for the others.
    NoBinding(Grant<'a>, Ias),
    /// Nothing: a failure status, or none of our identity associations
    /// in the message.
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

    /// The earliest renewal time of any identity association held;
    /// `None` when it never comes.
    fn t1(&self) -> Option<Instant> {
        self.at(self.lease.renewal().0)
    }

    fn t2(&self) -> Option<Instant> {
        self.at(self.lease.renewal().1)
    }

    /// When the first address or prefix runs out.
    fn first_expiry(&self) -> Option<Instant> {
        let valid = self.lease.lifetimes().into_iter().map(|(_, valid)| valid);
        valid.filter_map(|valid| self.at(valid)).min()
    }

    /// §18.2.12: a lease with a delegated prefix is verified with a
    /// Rebind, since a Confirm speaks of addresses only.
    fn verified_by_rebind(&self) -> bool {
        !self.lease.ia_pd.is_empty()
    }

    /// What is held, as a message names it, the identity associations in
    /// `but` aside.
    fn named_but(&self, but: &Ias) -> Named {
        let addresses = self.addresses().iter().filter(|_| !but.ia_na);
        let ia_pd = self.lease.ia_pd.iter();
        let ia_pd = ia_pd.filter(|ia| !but.ia_pd.contains(&ia.iaid));
        Named {
            addresses: addresses.map(|a| a.address).collect(),
            prefixes: ia_pd
                .flat_map(|ia| ia.prefixes.iter().map(|p| (ia.iaid, p.prefix)))
                .collect(),
        }
    }

    /// The identity associations leased from another server than
    /// `server`, those in `but` aside.
    fn others(&self, server: &[u8], but: &Ias) -> Ias {
        let ia_na = self.lease.ia_na.as_ref();
        let ia_pd = self.lease.ia_pd.iter();
        let ia_pd = ia_pd.filter(|ia| ia.server_id != server && !but.ia_pd.contains(&ia.iaid));
        Ias {
            ia_na: !but.ia_na && ia_na.is_some_and(|ia| ia.server_id != server),
            ia_pd: ia_pd.map(|ia| ia.iaid).collect(),
        }
    }

    /// Each identity association's T1, and the server it is leased from.
    fn renewals(&self) -> impl Iterator<Item = (Option<Instant>, &Vec<u8>)> {
        self.times().map(|(t1, _, server_id)| (t1, server_id))
    }

    /// Each identity association by itself, with its T1 and T2 and the
    /// server it is leased from.
    fn each(&self) -> impl Iterator<Item = (Ias, Option<Instant>, Option<Instant>, &Vec<u8>)> {
        let ia_na = self.lease.ia_na.iter().map(|ia| {
            let one = Ias {
                ia_na: true,
                ia_pd: Vec::new(),
            };
            (one, ia.t1, ia.t2, &ia.server_id)
        });
        let ia_pd = self.lease.ia_pd.iter().map(|ia| {
            let one = Ias {
                ia_na: false,
                ia_pd: vec![ia.iaid],
            };
            (one, ia.t1, ia.t2, &ia.server_id)
        });
        ia_na
            .chain(ia_pd)
            .map(|(one, t1, t2, server_id)| (one, self.at(t1), self.at(t2), server_id))
    }

    /// Each identity association's T1 and T2, and the server it is leased
    /// from.
    fn times(&self) -> impl Iterator<Item = (Option<Instant>, Option<Instant>, &Vec<u8>)> {
        self.each()
            .map(|(_, t1, t2, server_id)| (t1, t2, server_id))
    }

    /// Every identity association held.
    fn all(&self) -> Ias {
        let mut all = Ias::default();
        for (one, ..) in self.each() {
            all.include(&one);
        }
        all
    }

    /// The identity associations past their T2, and those not.
    fn overdue(&self, now: Instant) -> (Ias, Ias) {
        let past = |t2: u32| self.at(t2).is_some_and(|t2| now >= t2);
        let (mut overdue, mut rest) = (Ias::default(), Ias::default());
        if let Some(ia) = &self.lease.ia_na {
            if past(ia.t2) {
                overdue.ia_na = true;
            } else {
                rest.ia_na = true;
            }
        }
        for ia in &self.lease.ia_pd {
            if past(ia.t2) {
                overdue.ia_pd.push(ia.iaid);
            } else {
                rest.ia_pd.push(ia.iaid);
            }
        }
        (overdue, rest)
    }

    /// The servers something is leased from, that of the addresses first.
    fn servers(&self) -> Vec<Vec<u8>> {
        let mut servers: Vec<Vec<u8>> = Vec::new();
        for (_, server_id) in self.renewals() {
            if !servers.contains(server_id) {
                servers.push(server_id.clone());
            }
        }
        servers
    }

    /// What goes back to each server something is leased from.
    fn returning(&self) -> Vec<Returning> {
        let servers = self.servers().into_iter();
        let returning = servers.map(|server_id| Returning {
            named: self.named_but(&self.others(&server_id, &Ias::default())),
            server_id,
        });
        returning.collect()
    }

    /// Count the lease's times from `now` instead, to the second.
    fn rebase(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.since).as_secs();
        self.lease = self.lease.aged(u32::try_from(elapsed).unwrap_or(u32::MAX));
        self.since += Duration::from_secs(elapsed);
    }
}

impl Client {
    /// `duid` and `asks` are who the client is to a server and what it
    /// wants of it; see [`Client::identity`].
    pub fn new(
        duid: Vec<u8>,
        asks: Asks,
        options: Options,
        random: Box<dyn FnMut() -> u32 + Send>,
    ) -> Client {
        Client {
            duid,
            asks,
            options,
            state: State::Stopped,
            link: false,
            ended: false,
            exchange: None,
            wake: None,
            server: None,
            renewals: Vec::new(),
            quiet: Vec::new(),
            held: None,
            returning: None,
            returning_next: Vec::new(),
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
    /// address or a prefix running out, whichever is first.
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

    /// Who the client is to a server, and what it asks of it: its DUID,
    /// and the identity associations it wants filled, each with its
    /// IAID.
    ///
    /// Both are fixed for the life of a `Client`. A server keys a binding
    /// on the DUID and the IAID: a Renew under another is another client
    /// asking, and a Release under another leaves the binding in place.
    /// And with nothing to ask for the client speaks another protocol
    /// (Information-request). When the configuration gives the interface
    /// another DUID or asks for something else, the task stops this
    /// client, which releases the lease as who took it, and starts a new
    /// one.
    pub fn identity(&self) -> (&[u8], &Asks) {
        (&self.duid, &self.asks)
    }

    #[cfg(test)]
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// New options take effect at the next message.
    pub fn set_options(&mut self, options: Options) {
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
                // The Release cannot be repeated; it went out once. The
                // ones still to come for other servers cannot be said.
                State::Releasing => {
                    self.returning_next.clear();
                    self.finish_return(now, out);
                }
                // A held lease stays, and its lifetimes go on running.
                // Nothing is sent: the timers that send start again when
                // the link is back.
                _ if self.held.is_some() => {
                    self.idle(if self.asks.is_empty() {
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
            _ if self.asks.is_empty() => self.inform(now),
            _ if self.held.is_some() => self.verify(now, out),
            _ => self.solicit(now),
        }
    }

    fn on_resume(&mut self, lease: Lease, elapsed: u32, now: Instant, out: &mut Vec<Action>) {
        // Only before anything else has happened: a lease is never held
        // in `Stopped`.
        if self.state != State::Stopped {
            return;
        }
        // What is asked for now, and has not run out while we were away.
        // (For a client that asks for nothing, that is nothing.)
        let mut lease = lease.aged(elapsed);
        lease.adopt();
        lease.keep(&self.asks);
        if !lease.has_leases() {
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
                // Every server is asked, whatever its T1, that leases
                // something not past its T2. What is past it is for any
                // server: the Rebind (`renewing`).
                let mut servers: Vec<Vec<u8>> = Vec::new();
                let held = self.held.iter();
                for (_, t2, server_id) in held.flat_map(Held::times) {
                    if !t2.is_some_and(|t2| now >= t2) && !servers.contains(server_id) {
                        servers.push(server_id.clone());
                    }
                }
                self.idle(State::Bound);
                for server_id in servers {
                    self.begin_renew(server_id, Ias::default(), now, out);
                }
                self.renewing(now, out);
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
        // The Decline is for the server the addresses are leased from.
        let ia_na = self
            .held
            .as_ref()
            .and_then(|held| held.lease.ia_na.as_ref());
        let Some(server_id) = ia_na
            .filter(|ia| ia.addresses.iter().any(|a| a.address == address))
            .map(|ia| ia.server_id.clone())
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
        let mut named = match self.returning.take() {
            Some(returning) if self.state == State::Declining => returning.named,
            _ => Named::default(),
        };
        named.addresses.push(address);
        self.returning = Some(Returning { server_id, named });
        self.server = None;
        self.renewals.clear();
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
        } else if !self.renewals.is_empty() {
            self.renewing(now, out);
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
            // With a lease held: the exchanges about it.
            State::Renewing | State::Requesting | State::Rebinding if !self.renewals.is_empty() => {
                self.on_renewals_timeout(now, out);
            }
            State::Requesting => {
                if !self.retransmit(now, out) {
                    out.push(Action::Log(
                        "no answer to the request; starting over".into(),
                    ));
                    self.solicit(now);
                }
            }
            // T1 or T2: `settle` sends what the lease's timers call for
            // now.
            State::Bound | State::Renewing | State::Rebinding => self.settle(now, out),
            State::Confirming => {
                let Some(exchange) = &self.exchange else {
                    // The delay before the first Confirm is over.
                    return self.begin(CNF_TIMEOUT, 0, Some(now + CNF_MAX_RD), now, out);
                };
                let not_on_link = exchange.not_on_link;
                let partly = !exchange.answered.is_empty();
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
                    // A Rebind in a Confirm's place, answered for some
                    // identity associations only: the others stay as
                    // they are.
                    None if partly => {
                        out.push(Action::Log(
                            "no server answered for all of the lease; using the rest as it is"
                                .into(),
                        ));
                        self.settle(now, out);
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
        if self.renewals.is_empty() {
            return self.on_answer(message, source, now, out);
        }
        // With a lease held, each of its servers has an exchange of its
        // own under way: the one this answers, if any.
        if self.load(message.transaction_id) {
            self.on_answer(message, source, now, out);
            self.store();
            self.renewing(now, out);
        }
    }

    /// `Renewing`, `Rebinding`, and `Requesting` with a lease held: the
    /// timer of the exchanges under way about the lease.
    fn on_renewals_timeout(&mut self, now: Instant, out: &mut Vec<Action>) {
        // Each is sent again at its own pace.
        let is_due = |r: &&Renewal| r.wake.is_some_and(|wake| now >= wake);
        let due = self.renewals.iter().filter(is_due);
        let due: Vec<u32> = due.map(|renewal| renewal.exchange.xid).collect();
        for xid in due {
            if !self.load(xid) {
                continue;
            }
            // A Renew and a Rebind go on. A Request is given up.
            if !self.retransmit(now, out) {
                self.on_unanswered_request(now, out);
            }
            self.store();
        }
        self.renewing(now, out);
    }

    /// The Request that followed NoBinding has been sent as often as it is
    /// to be. No server stands behind what that server had no record of:
    /// it goes. What else is held goes on.
    fn on_unanswered_request(&mut self, now: Instant, out: &mut Vec<Action>) {
        let lost = self.server.take().map(|server| server.lost);
        let Some(held) = &mut self.held else {
            return;
        };
        held.lease.forget(&lost.unwrap_or_default());
        held.rebase(now);
        if held.lease.has_leases() {
            out.push(Action::Log(
                "no answer to the request; the rest of the lease goes on".into(),
            ));
            out.push(Action::Bind {
                lease: held.lease.clone(),
                fresh: true,
            });
            return;
        }
        out.push(Action::Log(
            "no answer to the request; starting over".into(),
        ));
        self.held = None;
        out.push(Action::Unbind);
        self.solicit(now);
    }

    /// A message for the exchange under way.
    fn on_answer(
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
                    && let Verdict::Granted(grant) = self.verdict(&answer, now)
                    && let Some(lease) = self.grant(&answer, &grant, out)
                {
                    self.bind(lease, now, out);
                }
            }
            (State::Requesting, msg::REPLY) => self.on_request_reply(&answer, now, out),
            (State::Renewing | State::Rebinding, msg::REPLY) => {
                self.on_renewal_reply(&answer, now, out);
            }
            // A lease with a delegated prefix was asked about with a
            // Rebind (`transmit`), and is answered as one.
            (State::Confirming, msg::REPLY) => {
                let rebind = self.held.as_ref().is_some_and(Held::verified_by_rebind);
                if rebind {
                    self.on_renewal_reply(&answer, now, out);
                } else {
                    self.on_confirm_reply(&answer, now, out);
                }
            }
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
        // §18.2.9: an Advertise with no address and no prefix for us is
        // of no use.
        let Verdict::Granted(grant) = self.verdict(answer, now) else {
            return;
        };
        let mut named = Named::default();
        let mut count = 0;
        if let Some(ia) = grant.ia_na {
            let addresses = usable(addresses_in(ia), |a| a.address);
            named.addresses = addresses.iter().map(|a| a.address).collect();
            count += usize::from(!addresses.is_empty());
        }
        for ia in &grant.ia_pd {
            let prefixes = usable(prefixes_in(ia), |p| p.prefix);
            count += usize::from(!prefixes.is_empty());
            named
                .prefixes
                .extend(prefixes.iter().map(|p| (ia.iaid, p.prefix)));
        }
        if count == 0 {
            return;
        }
        // The server that offers more of what is asked for wins: an
        // address without the prefix is half a lease. Then the highest
        // preference, and among equals the first to arrive.
        let preference = answer.params.preference.unwrap_or(0);
        if self
            .server
            .as_ref()
            .is_none_or(|best| (count, preference) > (best.count, best.preference))
        {
            self.server = Some(Server {
                id: answer.server_id.clone(),
                preference,
                count,
                named,
                lost: Ias::default(),
                settled: Ias::default(),
            });
        }
        // Advertises are collected until the first retransmission is due.
        // Preference 255 ends the wait, when that server offers all that
        // is asked for, and once the wait is over the first Advertise
        // does.
        let all = count == self.asks.count();
        if (preference == 255 && all) || first_wait_over {
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
        let verdict = self.verdict(answer, now);
        if let Verdict::Unanswered(reason) = &verdict {
            out.push(Action::Log(format!(
                "server {}: {reason}; asking again",
                answer.source
            )));
            return;
        }
        // Only after NoBinding is a lease held here.
        if let Some(held) = self.held.take() {
            return self.on_recovery_reply(held, verdict, answer, now, out);
        }
        let reason = match verdict {
            Verdict::Granted(grant) => match self.grant(answer, &grant, out) {
                Some(lease) => return self.bind(lease, now, out),
                None => "no usable address or prefix in the reply".to_string(),
            },
            Verdict::NoBinding(..) => "NoBinding".to_string(),
            Verdict::Unanswered(reason) | Verdict::Refused(reason) => reason,
        };
        out.push(Action::Log(format!(
            "server {} refused the lease: {reason}",
            answer.source
        )));
        self.back_off(now);
    }

    /// The Reply to the Request that followed NoBinding, with the lease
    /// still `held` (§18.2.10.1).
    ///
    /// An identity association the server had no record of is what this
    /// Reply makes of it, and gone when the Reply gives nothing for it:
    /// no server stands behind what was held of it. Every other one is
    /// updated as a renewal updates it, so what the Reply does not name
    /// stays.
    fn on_recovery_reply(
        &mut self,
        mut held: Held,
        verdict: Verdict<'_>,
        answer: &Answer<'_>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let (grant, mut refusal) = match verdict {
            Verdict::Granted(grant) | Verdict::NoBinding(grant, _) => (grant, None),
            Verdict::Unanswered(reason) | Verdict::Refused(reason) => {
                (Grant::default(), Some(reason))
            }
        };
        let lost = self.server.take().map(|server| server.lost);
        held.lease.forget(&lost.unwrap_or_default());
        let given = self.apply(&mut held, answer, &grant, now, out);
        self.restored(&given);
        let lease = &held.lease;
        if !lease.has_leases() {
            refusal.get_or_insert("no usable address or prefix in the reply".to_string());
        }
        if let Some(reason) = refusal {
            out.push(Action::Log(format!(
                "server {} refused the lease: {reason}",
                answer.source
            )));
        }
        if !lease.has_leases() {
            out.push(Action::Unbind);
            return self.back_off(now);
        }
        // Something leased from that server is still to be renewed. It is
        // asked again, and may say NoBinding again: it is not sent another
        // Request for a while, longer each time, or a server that says
        // NoBinding and then gives nothing would be asked in a tight loop.
        let is_due = |(t1, server_id): (Option<Instant>, &Vec<u8>)| {
            *server_id == answer.server_id && t1.is_some_and(|t1| now >= t1)
        };
        if held.renewals().any(is_due) {
            let wait = Duration::from_secs(self.backoff);
            self.quiet.push((answer.server_id.clone(), now + wait));
            self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        } else {
            self.backoff = BACKOFF_FIRST;
        }
        // The Request is over. The lease's times count on from where they
        // did (`apply`): other exchanges may be under way, and `renewing`
        // says what this one's end leaves.
        self.exchange = None;
        out.push(Action::Bind {
            lease: held.lease.clone(),
            fresh: true,
        });
        self.held = Some(held);
    }

    /// Whether `server_id` is not to be sent a Request yet.
    fn is_quiet(&mut self, server_id: &[u8], now: Instant) -> bool {
        self.quiet.retain(|(_, until)| now < *until);
        self.quiet.iter().any(|(quiet, _)| quiet == server_id)
    }

    fn on_renewal_reply(&mut self, answer: &Answer<'_>, now: Instant, out: &mut Vec<Action>) {
        if self.held.is_none() {
            return;
        }
        // A Renew is for the server it was sent to to answer, a Rebind
        // for any.
        let asked = self.server.as_ref().map(|server| &server.id);
        if self.state == State::Renewing && asked != Some(&answer.server_id) {
            return;
        }
        // What the message left out, its Reply has no say about.
        let left_out = self.left_out(now);
        let (grant, lost) = match self.verdict(answer, now) {
            Verdict::Granted(grant) => (grant, None),
            Verdict::NoBinding(grant, lost) => (grant, Some(lost)),
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
        // What the Reply holds is taken, whatever it says of the rest.
        let given = self.apply(&mut held, answer, &grant, now, out);
        self.restored(&given);
        if !held.lease.has_leases() {
            out.push(Action::Log(format!(
                "server {} took the lease back",
                answer.source
            )));
            out.push(Action::Unbind);
            return self.back_off(now);
        }
        // §18.2.10.1: the server has no record of an identity
        // association. It is asked for all of them again, with a Request,
        // and what is held stays in use meanwhile. Unless a Request to it
        // has just come to nothing (`on_recovery_reply`): then this is a
        // Reply that leaves that identity association out.
        // Nor when a Request is out with it for all of that already, which
        // a Rebind beside it can bring about.
        let with = |r: &&Renewal| r.is_request() && r.server.id == answer.server_id;
        let request = self.renewals.iter().find(with);
        let out_for = request.map(|request| request.server.lost.clone());
        let news = |lost: &Ias| {
            let out_for = out_for.as_ref();
            out_for.is_none_or(|out_for| !out_for.covers(lost))
        };
        let quiet = self.is_quiet(&answer.server_id, now);
        if let Some(mut lost) = lost.clone().filter(|lost| !quiet && news(lost)) {
            // One Request asks a server about all it has no record of: one
            // that is out is begun anew, for this as well.
            lost.include(&out_for.unwrap_or_default());
            if !grant.is_empty() {
                out.push(Action::Bind {
                    lease: held.lease.clone(),
                    fresh: true,
                });
            }
            out.push(Action::Log(format!(
                "server {} has no record of the lease; requesting it again",
                answer.source
            )));
            // The Request speaks of what is leased from that server and
            // of what it had no record of; another server's is left out
            // (`left_out`).
            self.server = Some(Server {
                lost,
                ..Server::asked(answer.server_id.clone())
            });
            self.held = Some(held);
            // One more exchange about the lease: the others go on beside
            // it. A Rebind that brought it about is for the other servers
            // too, and goes on. A Renew with this server does not, nor a
            // Request: this Request asks about all that is leased from
            // it, and all it has no record of.
            let server = self.server.take();
            if self.state == State::Rebinding {
                self.store_as(Server::asked(Vec::new()));
            }
            self.renewals.retain(|r| r.server.id != answer.server_id);
            self.server = server;
            self.request(now, out);
            self.store();
            return self.renewing(now, out);
        }
        if lost.is_some() {
            out.push(Action::Log(format!(
                "server {} has no record of the lease; not requesting it again yet",
                answer.source
            )));
            // Nothing else in the Reply: nothing changes.
            if grant.is_empty() {
                self.held = Some(held);
                return;
            }
        }
        // A Renew or a Rebind is over when every identity association it
        // asks about has been answered in it: by this Reply or, since a
        // Rebind is for any server to answer, by an earlier one. For what
        // a Reply leaves out it goes on, sent again when its
        // retransmission is due, which is the rate limit §18.2.10.1 asks
        // for. What the Reply did extend is in use meanwhile.
        let over = self.exchange.as_mut().is_none_or(|exchange| {
            exchange.answered.add(&grant);
            exchange.answered.cover(&held.lease, &left_out)
        });
        // A Rebind sent in a Confirm's place is alone, and its end is the
        // end of the verification.
        if over && self.state == State::Confirming {
            return self.bind(held.lease, now, out);
        }
        out.push(Action::Bind {
            lease: held.lease.clone(),
            fresh: true,
        });
        if over {
            // Other exchanges may be under way, and `renewing` says what
            // this one's end leaves.
            self.backoff = BACKOFF_FIRST;
        } else {
            out.push(Action::Log(format!(
                "server {} answered for part of the lease; asking about the rest again",
                answer.source
            )));
        }
        self.held = Some(held);
    }

    /// Apply `grant` to what is `held` (§18.2.10.1). An identity
    /// association the Reply speaks of gets its T1 and T2 from it; one it
    /// does not speak of keeps its own, like the lifetimes of what the
    /// Reply does not name. Returns the ones it gave something of.
    ///
    /// The lease's times go on counting from where they did, moved on by
    /// whole seconds: a Reply that leaves something out may come again
    /// and again (`on_renewal_reply`), and must not push on what it
    /// leaves out a little each time. What the Reply sets can so end up
    /// to a second early.
    fn apply(
        &self,
        held: &mut Held,
        answer: &Answer<'_>,
        grant: &Grant<'_>,
        now: Instant,
        out: &mut Vec<Action>,
    ) -> Ias {
        let mut given = Ias::default();
        held.rebase(now);
        // Nothing for us in the Reply: the rest of it is not ours either.
        if grant.is_empty() {
            return given;
        }
        let lease = &mut held.lease;
        // An identity association is leased from the server that last gave
        // something of it. A Reply that only takes away, as any server
        // may for what is not right for the link, changes nothing there.
        if let Some(theirs) = grant.ia_na {
            let ia = lease.ia_na.get_or_insert(Ia {
                iaid: theirs.iaid,
                server_id: Vec::new(),
                t1: 0,
                t2: 0,
                addresses: Vec::new(),
            });
            if merge(&mut ia.addresses, addresses_in(theirs), |a| a.address) {
                ia.server_id.clone_from(&answer.server_id);
                given.ia_na = true;
            }
            let lifetimes = lifetimes(&ia.addresses);
            (ia.t1, ia.t2) = renewal_times(theirs.t1, theirs.t2, &lifetimes);
        }
        for theirs in &grant.ia_pd {
            let at = match lease.ia_pd.iter().position(|ia| ia.iaid == theirs.iaid) {
                Some(at) => at,
                None => {
                    lease.ia_pd.push(IaPd {
                        iaid: theirs.iaid,
                        server_id: Vec::new(),
                        t1: 0,
                        t2: 0,
                        prefixes: Vec::new(),
                    });
                    lease.ia_pd.len() - 1
                }
            };
            let ia = &mut lease.ia_pd[at];
            if merge(&mut ia.prefixes, prefixes_in(theirs), |p| p.prefix) {
                ia.server_id.clone_from(&answer.server_id);
                given.ia_pd.push(ia.iaid);
            }
            let lifetimes = lifetimes(&ia.prefixes);
            (ia.t1, ia.t2) = renewal_times(theirs.t1, theirs.t2, &lifetimes);
        }
        // An identity association the Reply emptied is one to ask for
        // again.
        lease.prune();
        // The other configuration is that of the server the addresses are
        // leased from, or without an address the first prefix. A server
        // that speaks of another part of the lease, or only takes away,
        // leaves it as it is.
        let ia_na = lease.ia_na.iter().map(|ia| &ia.server_id);
        let ia_pd = lease.ia_pd.iter().map(|ia| &ia.server_id);
        let first = ia_na.chain(ia_pd).next();
        if first == Some(&answer.server_id) {
            held.lease = Lease {
                ia_na: lease.ia_na.take(),
                ia_pd: std::mem::take(&mut lease.ia_pd),
                ..self.lease_from(answer, out)
            };
        }
        given
    }

    /// Identity associations have been given again, by whatever server.
    /// The exchanges that are out have no say about them any more: an
    /// answer to one of those is to a question from before, and must not
    /// undo what is held now. A Request is no longer about one of them
    /// that its server had no record of, and a late Reply to it cannot
    /// take one of them away either, though its own server gave it.
    fn restored(&mut self, given: &Ias) {
        for renewal in &mut self.renewals {
            renewal.server.lost.exclude(given);
            renewal.server.settled.include(given);
        }
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
        let lease = self.lease_from(answer, out);
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

    /// What `answer` says about what is asked for.
    fn verdict<'a>(&self, answer: &Answer<'a>, now: Instant) -> Verdict<'a> {
        let params = answer.params;
        // What the message did not ask about, its answer cannot speak of.
        let left_out = self.left_out(now);
        if let Some(status) = failure(&params.status) {
            return match status.code {
                status::UNSPEC_FAIL | status::USE_MULTICAST => {
                    Verdict::Unanswered(status_text(status))
                }
                status::NO_BINDING => {
                    Verdict::NoBinding(Grant::default(), Ias::all_but(&self.asks, &left_out))
                }
                _ => Verdict::Refused(status_text(status)),
            };
        }
        // §21.4, §21.21: an identity association whose T1 is after its T2
        // is as good as absent.
        let in_order = |t1: u32, t2: u32| !(t2 > 0 && t1 > t2);
        let mut grant = Grant::default();
        // The status of each identity association that has one, and the
        // ones it is NoBinding for.
        let mut failures = Vec::new();
        let mut lost = Ias::default();
        let ia_na = self.asks.ia_na.filter(|_| !left_out.ia_na);
        let ia_na = ia_na.and_then(|iaid| {
            let mut all = params.ia_na.iter();
            all.find(|ia| ia.iaid == iaid && in_order(ia.t1, ia.t2))
        });
        if let Some(ia) = ia_na {
            match failure(&ia.status) {
                None => grant.ia_na = Some(ia),
                Some(status) => {
                    lost.ia_na = status.code == status::NO_BINDING;
                    failures.push(status);
                }
            }
        }
        for ask in &self.asks.ia_pd {
            if left_out.ia_pd.contains(&ask.iaid) {
                continue;
            }
            let mut all = params.ia_pd.iter();
            let Some(ia) = all.find(|ia| ia.iaid == ask.iaid && in_order(ia.t1, ia.t2)) else {
                continue;
            };
            match failure(&ia.status) {
                None => grant.ia_pd.push(ia),
                Some(status) => {
                    if status.code == status::NO_BINDING {
                        lost.ia_pd.push(ia.iaid);
                    }
                    failures.push(status);
                }
            }
        }
        if !lost.is_empty() {
            return Verdict::NoBinding(grant, lost);
        }
        if grant.is_empty() {
            return Verdict::Refused(match failures.first() {
                Some(status) => status_text(status),
                None => "no address or prefix in the reply".into(),
            });
        }
        Verdict::Granted(grant)
    }

    /// The lease `grant` gives a client that holds none: what can be
    /// used of it. `None` when nothing can.
    fn grant(
        &self,
        answer: &Answer<'_>,
        grant: &Grant<'_>,
        out: &mut Vec<Action>,
    ) -> Option<Lease> {
        let ia_na = grant.ia_na.and_then(|theirs| {
            let addresses = usable(addresses_in(theirs), |a| a.address);
            if addresses.is_empty() {
                return None;
            }
            let (t1, t2) = renewal_times(theirs.t1, theirs.t2, &lifetimes(&addresses));
            Some(Ia {
                iaid: theirs.iaid,
                server_id: answer.server_id.clone(),
                t1,
                t2,
                addresses,
            })
        });
        let mut ia_pd = Vec::new();
        for theirs in &grant.ia_pd {
            let prefixes = usable(prefixes_in(theirs), |p| p.prefix);
            if prefixes.is_empty() {
                continue;
            }
            let (t1, t2) = renewal_times(theirs.t1, theirs.t2, &lifetimes(&prefixes));
            ia_pd.push(IaPd {
                iaid: theirs.iaid,
                server_id: answer.server_id.clone(),
                t1,
                t2,
                prefixes,
            });
        }
        if ia_na.is_none() && ia_pd.is_empty() {
            return None;
        }
        Some(Lease {
            ia_na,
            ia_pd,
            ..self.lease_from(answer, out)
        })
    }

    /// The server and the other configuration of `answer`, with nothing
    /// leased yet.
    fn lease_from(&self, answer: &Answer<'_>, out: &mut Vec<Action>) -> Lease {
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
            ia_na: None,
            ia_pd: Vec::new(),
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
        // Counting the lease from now takes every address and prefix that
        // has run out with it, also one whose end is this very moment and
        // whose timer has not fired yet. So what is left is asked after
        // that, not before: a lease that holds nothing must not stay
        // held.
        held.rebase(now);
        if !held.lease.has_leases() {
            self.held = None;
            out.push(Action::Unbind);
        } else {
            out.push(Action::Bind {
                lease: held.lease.clone(),
                fresh: true,
            });
        }
    }

    /// Drop the addresses and prefixes whose valid lifetime has run out.
    /// True when that was the end of the lease.
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
        if !held.lease.has_leases() {
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
        // What ran out may be all that a Renew or the Rebind still went on
        // for.
        if !self.renewals.is_empty() {
            self.renewing(now, out);
        }
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
        // Each server is told of what was leased from it, one after
        // another.
        let mut returning = held.returning();
        if returning.is_empty() || self.options.no_release || !self.link {
            return;
        }
        self.returning = Some(returning.remove(0));
        self.returning_next = returning;
        self.release_then = then;
        self.state = State::Releasing;
        self.begin(REL_TIMEOUT, REL_MAX_RC, None, now, out);
    }

    /// A Decline or a Release is over: answered, or sent as often as it
    /// is to be.
    fn finish_return(&mut self, now: Instant, out: &mut Vec<Action>) {
        match self.state {
            // The next server's turn.
            State::Releasing if !self.returning_next.is_empty() => {
                self.returning = Some(self.returning_next.remove(0));
                self.begin(REL_TIMEOUT, REL_MAX_RC, None, now, out);
            }
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
        self.renewals.clear();
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
        if self.asks.is_empty() {
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
    /// right for the link (§18.2.3), with a Confirm, or with a Rebind
    /// when it holds a delegated prefix (§18.2.12): `transmit` sends what
    /// the lease calls for.
    fn verify(&mut self, now: Instant, out: &mut Vec<Action>) {
        // Past T2 any server is asked about the lease anyway.
        let t2 = self.held.as_ref().and_then(Held::t2);
        if t2.is_some_and(|t2| now >= t2) {
            return self.settle(now, out);
        }
        self.idle(State::Confirming);
        self.wake = Some(now + self.delay(CNF_MAX_DELAY));
    }

    /// Put a held lease in the state its timers call for, with nothing
    /// under way from before, sending what that state sends. Only with a
    /// link: without one a lease waits in `Bound` with no timer
    /// (`on_link`).
    fn settle(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.held.is_none() {
            return;
        }
        self.idle(State::Bound);
        self.renewing(now, out);
    }

    /// With a lease held and a link: bring the exchanges under way about
    /// the lease in line with it, and set the state and the timer.
    ///
    /// Each identity association has its times, and none waits for
    /// another (RFC 8415 §18.2.4, §18.2.5, §21.4):
    ///
    /// - from its T1, a Renew with the server it is leased from, unless
    ///   an exchange under way with that server asks about it already. A
    ///   server's Renew is about all that is leased from it. It is sent
    ///   again at its own pace, and is over when the server has answered
    ///   for all of it that is not past its T2 or left to another
    ///   exchange;
    /// - from its T2, the Rebind: one for all that is past its T2, for
    ///   any server. It goes on until nothing is past its T2 any more:
    ///   extended, or run out;
    /// - a Request that follows NoBinding goes on beside either until it
    ///   is answered or given up.
    fn renewing(&mut self, now: Instant, out: &mut Vec<Action>) {
        let Some(held) = &self.held else {
            return;
        };
        let (overdue, _) = held.overdue(now);
        let rebinding = !overdue.is_empty();
        self.renewals.retain(|renewal| match renewal.state {
            // A Request goes on until it is answered or given up, or
            // until another exchange has restored all that its server
            // had no record of (`restored`).
            State::Requesting => !renewal.server.lost.is_empty(),
            State::Rebinding => rebinding,
            // A Renew is over when nothing is left for it. All that is
            // leased from its server has been answered for, or is past
            // its T2 and the Rebind's to ask about, or is left to
            // another exchange.
            _ => {
                let server = &renewal.server;
                let others = held.others(&server.id, &Ias::default());
                let mut done = renewal.exchange.answered.clone();
                done.include(&overdue);
                done.include(&server.settled);
                !done.cover(&held.lease, &others)
            }
        });
        // To begin: a Renew with each server that leases something
        // between its T1 and its T2 that no exchange under way asks about.
        // A Request that is out goes on, and is left what it asks about.
        // A Renew with that server which leaves this out does not: the
        // new one takes its place.
        let (mut asked, mut left) = (Ias::default(), Ias::default());
        for renewal in &self.renewals {
            let asks = renewal.asks(held);
            if renewal.is_request() {
                left.include(&asks);
            }
            asked.include(&asks);
        }
        let mut begin: Vec<Vec<u8>> = Vec::new();
        for (one, t1, t2, server_id) in held.each() {
            if t1.is_some_and(|t1| now >= t1)
                && !t2.is_some_and(|t2| now >= t2)
                && !asked.meets(&one)
                && !begin.contains(server_id)
            {
                begin.push(server_id.clone());
            }
        }
        if rebinding && !self.renewals.iter().any(Renewal::is_rebind) {
            self.state = State::Rebinding;
            self.server = Some(Server::asked(Vec::new()));
            self.begin(REB_TIMEOUT, 0, None, now, out);
            self.store();
        }
        for server_id in begin {
            self.renewals
                .retain(|r| r.state != State::Renewing || r.server.id != server_id);
            self.begin_renew(server_id, left.clone(), now, out);
        }
        let Some(held) = &self.held else {
            return;
        };
        if self.renewals.is_empty() {
            self.state = State::Bound;
            self.wake = held.t1();
            return;
        }
        // The state is the most pressing of what is under way.
        self.state = if self.renewals.iter().any(Renewal::is_request) {
            State::Requesting
        } else if rebinding {
            State::Rebinding
        } else {
            State::Renewing
        };
        // Next: an exchange to send again, or a T1 or a T2 to come.
        let again = self.renewals.iter().filter_map(|renewal| renewal.wake);
        let times = held.times();
        let ahead = times.flat_map(|(t1, t2, _)| [t1, t2].into_iter().flatten());
        self.wake = again.chain(ahead.filter(|at| *at > now)).min();
    }

    /// Begin a Renew with one server. It speaks of what is leased from
    /// that server, `left` to another exchange with it aside, and of what
    /// nobody has filled, and of nothing leased from another.
    fn begin_renew(&mut self, server_id: Vec<u8>, left: Ias, now: Instant, out: &mut Vec<Action>) {
        self.state = State::Renewing;
        self.server = Some(Server {
            settled: left,
            ..Server::asked(server_id)
        });
        self.begin(REN_TIMEOUT, 0, None, now, out);
        self.store();
    }

    /// Make the exchange with this transaction id, among those under way
    /// with the lease's servers, the one being dealt with. False when
    /// there is none.
    fn load(&mut self, xid: u32) -> bool {
        let renewals = &mut self.renewals;
        let Some(at) = renewals.iter().position(|r| r.exchange.xid == xid) else {
            return false;
        };
        let renewal = renewals.remove(at);
        self.state = renewal.state;
        self.server = Some(renewal.server);
        self.exchange = Some(renewal.exchange);
        self.wake = renewal.wake;
        true
    }

    /// Put the exchange being dealt with back among those under way, if
    /// it still is.
    fn store(&mut self) {
        if let Some(server) = self.server.take() {
            self.store_as(server);
        }
    }

    fn store_as(&mut self, server: Server) {
        if let Some(exchange) = self.exchange.take() {
            self.renewals.push(Renewal {
                server,
                state: self.state,
                exchange,
                wake: self.wake.take(),
            });
        }
    }

    /// The identity associations the current state's message says nothing
    /// of, and its Reply has no say about: those leased from another
    /// server than the one it is for, and those another exchange has
    /// given something of since this one went out.
    ///
    /// That is in a Renew, and in the Request that follows NoBinding,
    /// which does speak of what its server had no record of. No other
    /// message is for one server while a lease is held.
    ///
    /// A Rebind is for any server, and about what is past its T2 as it is
    /// sent or answered: the rest is left out of it.
    fn left_out(&self, now: Instant) -> Ias {
        match (&self.held, &self.server, self.state) {
            (Some(held), Some(server), State::Renewing | State::Requesting) => {
                let mut left_out = held.others(&server.id, &server.lost);
                left_out.include(&server.settled);
                left_out
            }
            (Some(held), _, State::Rebinding) => held.overdue(now).1,
            _ => Ias::default(),
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
            answered: Ias::default(),
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
        // A message for one server says nothing of what is leased from
        // another.
        let left_out = self.left_out(now);
        let held = || {
            let held = self.held.as_ref();
            held.map(|held| held.named_but(&left_out))
                .unwrap_or_default()
        };
        let by_rebind = self.held.as_ref().is_some_and(Held::verified_by_rebind);
        // The type, the server it is for, what it names, and whether
        // every identity association asked for is in it or only those it
        // names something of.
        let (msg_type, server_id, named, all) = match self.state {
            State::Soliciting => (msg::SOLICIT, None, Named::default(), true),
            State::Requesting => {
                let Some(server) = &self.server else {
                    return;
                };
                // Before a lease is held, what the server offered. After
                // NoBinding, what is held as the Request goes out.
                let named = match &self.held {
                    Some(_) => held(),
                    None => server.named.clone(),
                };
                (msg::REQUEST, Some(&server.id), named, true)
            }
            // A Confirm speaks of addresses only. §18.2.12: a lease with
            // a delegated prefix is asked about with a Rebind instead,
            // in a Confirm's time (`retransmit`).
            State::Confirming if !by_rebind => (msg::CONFIRM, None, held(), false),
            State::Confirming | State::Rebinding => (msg::REBIND, None, held(), true),
            State::Renewing => {
                let Some(server) = &self.server else {
                    return;
                };
                (msg::RENEW, Some(&server.id), held(), true)
            }
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
                    returning.named.clone(),
                    false,
                )
            }
            State::Informing => (msg::INFORMATION_REQUEST, None, Named::default(), false),
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
        message
            .options
            .extend(self.ia_options(&named, all, &left_out));
        out.push(Action::Send(message));
    }

    /// The identity associations of a message: every one asked for
    /// (`all`), or only those `named` has something of, and never one in
    /// `left_out`. A client leaves T1, T2 and the lifetimes 0 (§21.4,
    /// §21.6, §21.21, §21.22).
    fn ia_options(&self, named: &Named, all: bool, left_out: &Ias) -> Vec<Dhcp6Option> {
        let mut options = Vec::new();
        if let Some(iaid) = self.asks.ia_na
            && !left_out.ia_na
            && (all || !named.addresses.is_empty())
        {
            let mut ia = IaNa::new(iaid);
            let addresses = named.addresses.iter();
            ia.addresses = addresses
                .map(|&address| IaAddress {
                    address,
                    preferred: 0,
                    valid: 0,
                    status: None,
                    other: Vec::new(),
                })
                .collect();
            options.extend(ia.emit().ok());
        }
        for ask in &self.asks.ia_pd {
            if left_out.ia_pd.contains(&ask.iaid) {
                continue;
            }
            let mut ia = WirePd::new(ask.iaid);
            let prefixes = named.prefixes.iter();
            ia.prefixes = prefixes
                .filter(|(iaid, _)| *iaid == ask.iaid)
                .map(|(_, prefix)| IaPrefix {
                    prefix: prefix.addr(),
                    prefix_len: prefix.prefix_len(),
                    preferred: 0,
                    valid: 0,
                    status: None,
                    other: Vec::new(),
                })
                .collect();
            if ia.prefixes.is_empty() {
                if !all {
                    continue;
                }
                // Nothing to name: ask, with the length wanted as a hint.
                ia.prefixes.push(IaPrefix::hint(ask.length));
            }
            options.extend(ia.emit().ok());
        }
        options
    }
}

fn not_after(at: Instant, limit: Option<Instant>) -> Instant {
    limit.map_or(at, |limit| at.min(limit))
}

/// An address or a prefix as a lease holds it: something with lifetimes.
trait Timed {
    /// Preferred, valid.
    fn lifetimes(&self) -> (u32, u32);
    fn set_lifetimes(&mut self, preferred: u32, valid: u32);
}

impl Timed for Address {
    fn lifetimes(&self) -> (u32, u32) {
        (self.preferred, self.valid)
    }

    fn set_lifetimes(&mut self, preferred: u32, valid: u32) {
        (self.preferred, self.valid) = (preferred, valid);
    }
}

impl Timed for Prefix {
    fn lifetimes(&self) -> (u32, u32) {
        (self.preferred, self.valid)
    }

    fn set_lifetimes(&mut self, preferred: u32, valid: u32) {
        (self.preferred, self.valid) = (preferred, valid);
    }
}

fn lifetimes<T: Timed>(items: &[T]) -> Vec<(u32, u32)> {
    items.iter().map(Timed::lifetimes).collect()
}

/// A status that is not Success.
fn failure(status: &Option<StatusCode>) -> Option<&StatusCode> {
    status.as_ref().filter(|s| !s.is_success())
}

/// The addresses a server's IA_NA holds, each with whether the server
/// marked it with a failure status.
fn addresses_in(ia: &IaNa) -> Vec<(Address, bool)> {
    let theirs = ia.addresses.iter();
    theirs
        .map(|a| {
            let address = Address {
                address: a.address,
                preferred: a.preferred,
                valid: a.valid,
            };
            (address, failure(&a.status).is_some())
        })
        .collect()
}

/// The prefixes a server's IA_PD holds, likewise. A server may leave bits
/// set past the prefix length: they are not part of the prefix.
fn prefixes_in(ia: &WirePd) -> Vec<(Prefix, bool)> {
    let theirs = ia.prefixes.iter();
    theirs
        .filter_map(|p| {
            let prefix = Prefix {
                prefix: Ipv6Net::new(p.prefix, p.prefix_len).ok()?.trunc(),
                preferred: p.preferred,
                valid: p.valid,
            };
            Some((prefix, failure(&p.status).is_some()))
        })
        .collect()
}

/// The addresses or prefixes among `theirs` a client can use: with a
/// valid lifetime, not preferred for longer than valid (§21.6, §21.22),
/// without a failure status, each once.
fn usable<T: Timed, K: PartialEq>(theirs: Vec<(T, bool)>, key: impl Fn(&T) -> K) -> Vec<T> {
    let mut mine: Vec<T> = Vec::new();
    for (item, failed) in theirs {
        let (preferred, valid) = item.lifetimes();
        if valid > 0 && preferred <= valid && !failed && !mine.iter().any(|m| key(m) == key(&item))
        {
            mine.push(item);
        }
    }
    mine
}

/// Apply what a Reply to a Renew or a Rebind holds for an identity
/// association to what is held of it (§18.2.10.1): what it gives a valid
/// lifetime of 0 goes, what it gives lifetimes is added or updated, and
/// what it does not name stays as it is. True when it gave anything.
fn merge<T: Timed, K: PartialEq>(
    mine: &mut Vec<T>,
    theirs: Vec<(T, bool)>,
    key: impl Fn(&T) -> K,
) -> bool {
    let mut gave = false;
    for (item, failed) in theirs {
        let (preferred, valid) = item.lifetimes();
        if failed || preferred > valid {
            continue;
        }
        let at = mine.iter().position(|m| key(m) == key(&item));
        match (at, valid) {
            // A valid lifetime of 0 takes it away.
            (Some(at), 0) => {
                mine.remove(at);
            }
            (None, 0) => {}
            (Some(at), _) => {
                mine[at].set_lifetimes(preferred, valid);
                gave = true;
            }
            (None, _) => {
                mine.push(item);
                gave = true;
            }
        }
    }
    gave
}

/// T1 and T2 for an identity association whose addresses or prefixes
/// have `lifetimes` (preferred, valid), from the server's `t1` and `t2`.
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
fn renewal_times(t1: u32, t2: u32, lifetimes: &[(u32, u32)]) -> (u32, u32) {
    let (own_t1, own_t2) = own_renewal_times(lifetimes);
    match (t1, t2) {
        (0, 0) => (own_t1, own_t2),
        (0, t2) => (own_t1.min(scaled(t2, 5, 8)).max(1), t2),
        (t1, 0) => (t1, own_t2.max(scaled(t1, 8, 5))),
        // Out of order. `verdict` drops such an identity association
        // (§21.4), so this is not reached from a server's message.
        (t1, t2) if t1 > t2 => (own_t1, own_t2),
        (t1, t2) => (t1, t2),
    }
}

/// The T1 and T2 a client chooses for `lifetimes` when the server names
/// neither.
fn own_renewal_times(lifetimes: &[(u32, u32)]) -> (u32, u32) {
    let valid = lifetimes.iter().map(|(_, valid)| *valid);
    let shortest_valid = valid.min().unwrap_or(INFINITY);
    let base = lifetimes
        .iter()
        .map(|(preferred, _)| *preferred)
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

    /// An address, and nothing else.
    fn address_only() -> Asks {
        Asks {
            ia_na: Some(IAID),
            ia_pd: vec![],
        }
    }

    /// A client that asks for an address.
    fn client(options: Options) -> Client {
        client_asking(address_only(), options)
    }

    fn client_asking(asks: Asks, options: Options) -> Client {
        // A fixed "random" source that counts up: transaction ids differ,
        // and the delays and the jitter are small and known.
        let mut next = 1299u32;
        Client::new(
            DUID.to_vec(),
            asks,
            options,
            Box::new(move || {
                next += 1;
                next
            }),
        )
    }

    /// A client with nothing to ask for but the other configuration
    /// (`parameters-only`).
    fn parameters_client() -> Client {
        client_asking(Asks::default(), Options::default())
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
                server_id: SERVER_DUID.to_vec(),
                t1: 1800,
                t2: 2880,
                addresses: vec![address(ADDRESS, 3600, 7200)],
            }),
            ia_pd: vec![],
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
        assert_eq!(c.identity(), (&DUID[..], &address_only()));

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
        let mut c = Client::new(DUID.to_vec(), address_only(), Options::default(), random);
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
        let lowest =
            |asks: Asks| Client::new(DUID.to_vec(), asks, Options::default(), Box::new(|| 0));
        let t0 = Instant::now();
        let mut c = lowest(address_only());
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
        let mut c = lowest(Asks::default());
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
        let a = |preferred: u32, valid: u32| (preferred, valid);
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
    fn an_address_that_runs_out_leaves_the_renew_under_way() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        let two = ia(10, 1000, &[(ADDRESS, 30, 35), (ADDRESS2, 3600, 7200)]);
        let t0 = acquire(&mut c, t0, two);
        let (_, renew) = first_renew(&mut c);
        // Nobody answers, and one address runs out meanwhile.
        let actions = loop {
            let (t, actions) = fire(&mut c);
            if t == t0 + secs(35) {
                break actions;
            }
            assert_eq!(sent(&actions).transaction_id, renew.transaction_id);
        };
        // The lease goes on without it, and so does the Renew: it is not
        // begun anew.
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na.as_ref().unwrap().addresses.len(), 1);
        assert_eq!(c.state(), State::Renewing);
        let again = sent(&fire(&mut c).1).clone();
        assert_eq!(again.msg_type, msg::RENEW);
        assert_eq!(again.transaction_id, renew.transaction_id);
        assert_eq!(addresses_of(&again), [ADDRESS2]);

        // So for a Rebind.
        let mut c = client(Options::default());
        let two = ia(10, 20, &[(ADDRESS, 30, 35), (ADDRESS2, 3600, 7200)]);
        let t0 = acquire(&mut c, t0, two);
        first_renew(&mut c);
        let rebind = sent(&fire(&mut c).1).clone();
        assert_eq!(rebind.msg_type, msg::REBIND);
        let actions = loop {
            let (t, actions) = fire(&mut c);
            if t == t0 + secs(35) {
                break actions;
            }
            assert_eq!(sent(&actions).transaction_id, rebind.transaction_id);
        };
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Rebinding);
        let again = sent(&fire(&mut c).1).clone();
        assert_eq!(again.transaction_id, rebind.transaction_id);
        assert_eq!(addresses_of(&again), [ADDRESS2]);
    }

    #[test]
    fn a_renewal_by_hand_takes_the_place_of_the_one_under_way() {
        let t0 = Instant::now();
        let mut c = client(Options::default());
        acquire(&mut c, t0, one_address());
        let (t, first) = first_renew(&mut c);
        let t = t + secs(1);
        let actions = c.handle(Event::Renew, t);
        let [Action::Send(second)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(second.msg_type, msg::RENEW);
        assert_ne!(second.transaction_id, first.transaction_id);
        let second = second.clone();
        // The first is over: an answer to it comes too late, and only the
        // second is sent again.
        let late = answer(&first, msg::REPLY, vec![one_address()]);
        assert!(deliver(&mut c, &late, t).is_empty());
        let (_, actions) = fire(&mut c);
        let [Action::Send(again)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(again.transaction_id, second.transaction_id);
    }

    #[test]
    fn a_renew_ends_when_what_it_was_left_for_is_gone() {
        // The prefix a Reply left out runs out before its T2.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 100, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 100, &[(DELEGATED, 30, 40)]),
        ];
        let (t0, _) = acquire_all(&mut c, Instant::now(), lease);
        let (t, renew) = first_renew(&mut c);
        deliver(&mut c, &answer(&renew, msg::REPLY, vec![one_address()]), t);
        assert_eq!(c.state(), State::Renewing);
        let actions = loop {
            let (t, actions) = fire(&mut c);
            if t == t0 + secs(40) {
                break actions;
            }
            assert_eq!(sent(&actions).transaction_id, renew.transaction_id);
        };
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t0 + secs(10 + 1800)));

        // The address a Reply left out is dropped by the kernel.
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, Instant::now(), vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(&mut c);
        deliver(&mut c, &answer(&renew, msg::REPLY, vec![one_prefix()]), t);
        assert_eq!(c.state(), State::Renewing);
        let actions = c.handle(Event::AddressLost(ADDRESS), t + secs(5));
        assert!(
            matches!(
                &actions[..],
                [Action::Log(_), Action::Bind { fresh: true, .. }]
            ),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
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
        let mut c = parameters_client();
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
            ia_pd: vec![],
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
            let mut c = parameters_client();
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
        let mut c = parameters_client();
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
        let mut c = parameters_client();
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
            rapid_commit: true,
            no_release: false,
        });
        let (_, solicit) = first_solicit(&mut c);
        assert!(solicit.option(opt::RAPID_COMMIT).is_some());
        assert!(c.options().rapid_commit);
        // What is asked for is not an option: it stays what it was.
        assert_eq!(c.identity().1, &address_only());
    }

    #[test]
    fn retransmission_times_stay_within_a_tenth() {
        let draw = |value: u32, fixed: u64, base: u64, positive: bool| {
            let mut c = Client::new(
                DUID.to_vec(),
                address_only(),
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

    /// The IAID of the prefix delegation the tests ask for.
    const PD: u32 = 7;
    const DELEGATED: &str = "2001:db8:100::/56";

    fn ask_pd(iaid: u32, length: u8) -> PdAsk {
        PdAsk { iaid, length }
    }

    /// An address and a prefix.
    fn both() -> Asks {
        Asks {
            ia_na: Some(IAID),
            ia_pd: vec![ask_pd(PD, 56)],
        }
    }

    fn prefixes_only() -> Asks {
        Asks {
            ia_na: None,
            ia_pd: vec![ask_pd(PD, 56)],
        }
    }

    /// An IA_PD as a server sends it: prefix, preferred, valid.
    fn ia_pd(iaid: u32, t1: u32, t2: u32, prefixes: &[(&str, u32, u32)]) -> Dhcp6Option {
        let mut ia = WirePd::new(iaid);
        ia.t1 = t1;
        ia.t2 = t2;
        ia.prefixes = prefixes
            .iter()
            .map(|&(prefix, preferred, valid)| {
                let (address, length) = prefix.split_once('/').unwrap();
                IaPrefix {
                    prefix: address.parse().unwrap(),
                    prefix_len: length.parse().unwrap(),
                    preferred,
                    valid,
                    status: None,
                    other: Vec::new(),
                }
            })
            .collect();
        ia.emit().unwrap()
    }

    /// The usual delegation: one /56, valid for 7200 s.
    fn one_prefix() -> Dhcp6Option {
        ia_pd(PD, 1800, 2880, &[(DELEGATED, 3600, 7200)])
    }

    /// An IA_PD with a status and no prefix.
    fn ia_pd_status(iaid: u32, code: u16) -> Dhcp6Option {
        let mut ia = WirePd::new(iaid);
        ia.status = Some(StatusCode::new(code, "no"));
        ia.emit().unwrap()
    }

    /// The IA_PDs of a client's message: the IAID of each, and what it
    /// names. A client leaves the times in them 0.
    fn pds_of(message: &ClientMessage) -> Vec<(u32, Vec<String>)> {
        let options = message.options.iter().filter(|o| o.code == opt::IA_PD);
        options
            .map(|option| {
                let ia = WirePd::parse(&option.data).unwrap();
                assert_eq!((ia.t1, ia.t2), (0, 0));
                let prefixes = ia.prefixes.iter().map(|p| {
                    assert_eq!((p.preferred, p.valid), (0, 0));
                    format!("{}/{}", p.prefix, p.prefix_len)
                });
                (ia.iaid, prefixes.collect())
            })
            .collect()
    }

    fn named(iaid: u32, prefix: &str) -> (u32, Vec<String>) {
        (iaid, vec![prefix.to_string()])
    }

    fn prefix(prefix: &str, preferred: u32, valid: u32) -> Prefix {
        Prefix {
            prefix: prefix.parse().unwrap(),
            preferred,
            valid,
        }
    }

    /// `kept` with the usual delegation beside the address.
    fn kept_with_prefix() -> Lease {
        Lease {
            ia_pd: vec![IaPd {
                iaid: PD,
                server_id: SERVER_DUID.to_vec(),
                t1: 1800,
                t2: 2880,
                prefixes: vec![prefix(DELEGATED, 3600, 7200)],
            }],
            ..kept()
        }
    }

    /// Link up, then Solicit, an Advertise and a Reply that both hold
    /// `options`: bound to what they grant. Returns when, and the lease.
    fn acquire_all(c: &mut Client, t0: Instant, options: Vec<Dhcp6Option>) -> (Instant, Lease) {
        c.handle(Event::Link(true), t0);
        let (mut now, solicit) = first_solicit(c);
        let mut offered = vec![preference(255)];
        offered.extend(options.clone());
        let mut actions = deliver(c, &answer(&solicit, msg::ADVERTISE, offered), now);
        if actions.is_empty() {
            // Not all that is asked for: the wait for a better offer
            // runs out first.
            (now, actions) = fire(c);
        }
        let request = sent(&actions).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        let actions = deliver(c, &answer(&request, msg::REPLY, options), now);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(c.state(), State::Bound);
        (now, lease.clone())
    }

    #[test]
    fn a_prefix_is_asked_for_with_the_address() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        assert_eq!(c.identity(), (&DUID[..], &both()));
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        // An empty IA_NA, and an IA_PD that hints at the length wanted.
        assert!(ia_of(&solicit).addresses.is_empty());
        assert_eq!(pds_of(&solicit), [named(PD, "::/56")]);

        let lease = vec![
            one_address(),
            ia_pd(PD, 1000, 1600, &[(DELEGATED, 3600, 7200)]),
        ];
        let mut offered = vec![preference(255)];
        offered.extend(lease.clone());
        let advertise = answer(&solicit, msg::ADVERTISE, offered);
        let request = sent(&deliver(&mut c, &advertise, t)).clone();
        // The Request names what was offered.
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(addresses_of(&request), [ADDRESS]);
        assert_eq!(pds_of(&request), [named(PD, DELEGATED)]);

        let actions = deliver(&mut c, &answer(&request, msg::REPLY, lease), t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        // Each keeps the times the server gave it. One Renew is for both,
        // at the earlier.
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!((ia_na.t1, ia_na.t2), (1800, 2880));
        assert_eq!(lease.renewal(), (1000, 1600));
        assert_eq!(ia_na.addresses, [address(ADDRESS, 3600, 7200)]);
        assert_eq!(
            lease.ia_pd,
            [IaPd {
                iaid: PD,
                server_id: SERVER_DUID.to_vec(),
                t1: 1000,
                t2: 1600,
                prefixes: vec![prefix(DELEGATED, 3600, 7200)],
            }]
        );
        assert_eq!(c.deadline(), Some(t + secs(1000)));

        // The Renew names both, and so does the Release. The Rebind at
        // the prefix's T2 is about the prefix: the address is not past
        // its own.
        let (_, renew) = first_renew(&mut c);
        assert_eq!(addresses_of(&renew), [ADDRESS]);
        assert_eq!(pds_of(&renew), [named(PD, DELEGATED)]);
        let (at, rebind) = loop {
            let (at, actions) = fire(&mut c);
            if c.state() == State::Rebinding {
                break (at, sent(&actions).clone());
            }
        };
        assert_eq!(at, t + secs(1600));
        assert_eq!(rebind.msg_type, msg::REBIND);
        assert!(rebind.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(&rebind), [named(PD, DELEGATED)]);
        // The Renew goes on beside it, for the address, until the
        // address's own T2. Then the Rebind is about both.
        let both = loop {
            let (at, actions) = fire(&mut c);
            // (Nothing is sent at the address's own T1, with its
            // server's Renew out, nor at its T2 itself: the Rebind is
            // under way, and names the address from its next time.)
            let Some(Action::Send(message)) = actions.first() else {
                assert!(at == t + secs(1800) || at == t + secs(2880));
                continue;
            };
            if message.msg_type == msg::RENEW {
                assert!(at < t + secs(2880));
                assert_eq!(message.transaction_id, renew.transaction_id);
            } else if message.option(opt::IA_NA).is_some() {
                assert!(at >= t + secs(2880));
                break message.clone();
            }
        };
        assert_eq!(both.transaction_id, rebind.transaction_id);
        assert_eq!(addresses_of(&both), [ADDRESS]);
        assert_eq!(pds_of(&both), [named(PD, DELEGATED)]);
        let t = c.deadline().unwrap();
        let actions = c.handle(Event::Release, t);
        let [Action::Unbind, Action::Send(release)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(release.msg_type, msg::RELEASE);
        assert_eq!(addresses_of(release), [ADDRESS]);
        assert_eq!(pds_of(release), [named(PD, DELEGATED)]);
        // One server, one Release.
        let release = release.clone();
        assert!(deliver(&mut c, &answer(&release, msg::REPLY, vec![]), t).is_empty());
        assert_eq!(c.state(), State::Released);
    }

    #[test]
    fn prefixes_can_be_all_that_is_asked_for() {
        let t0 = Instant::now();
        let asks = Asks {
            ia_na: None,
            ia_pd: vec![ask_pd(PD, 56), ask_pd(PD + 1, 60)],
        };
        let mut c = client_asking(asks, Options::default());
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        assert!(solicit.option(opt::IA_NA).is_none());
        assert_eq!(
            pds_of(&solicit),
            [named(PD, "::/56"), named(PD + 1, "::/60")]
        );
        // The server delegates one of the two.
        let lease = vec![
            ia_pd(PD, 0, 0, &[(DELEGATED, 3600, 7200)]),
            ia_pd_status(PD + 1, status::NO_PREFIX_AVAIL),
        ];
        let advertise = answer(&solicit, msg::ADVERTISE, lease.clone());
        assert!(deliver(&mut c, &advertise, t).is_empty());
        let (t, actions) = fire(&mut c);
        let request = sent(&actions).clone();
        // What was offered is named; the other is asked for all the same.
        assert!(request.option(opt::IA_NA).is_none());
        assert_eq!(
            pds_of(&request),
            [named(PD, DELEGATED), named(PD + 1, "::/60")]
        );
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, lease), t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na, None);
        assert_eq!(
            lease.ia_pd,
            [IaPd {
                iaid: PD,
                server_id: SERVER_DUID.to_vec(),
                t1: 1800,
                t2: 2880,
                prefixes: vec![prefix(DELEGATED, 3600, 7200)],
            }]
        );
        // The Renew asks for the other again.
        let (t, renew) = first_renew(&mut c);
        assert!(renew.option(opt::IA_NA).is_none());
        assert_eq!(
            pds_of(&renew),
            [named(PD, DELEGATED), named(PD + 1, "::/60")]
        );
        // With its last prefix a lease of prefixes is over.
        c.handle(Event::Link(false), t);
        let (ended, actions) = fire(&mut c);
        assert_eq!(ended, t + secs(7200 - 1800));
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Stopped);
    }

    #[test]
    fn the_server_that_offers_more_is_asked() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        // The highest preference there is, and half of what is asked
        // for: it does not end the wait.
        let half = answer_from(
            &OTHER_DUID,
            &solicit,
            msg::ADVERTISE,
            vec![preference(255), one_address()],
        );
        assert!(deliver(&mut c, &half, t).is_empty());
        assert_eq!(c.state(), State::Soliciting);
        // No preference at all, and all of it: that one is asked.
        let whole = answer(&solicit, msg::ADVERTISE, vec![one_address(), one_prefix()]);
        assert!(deliver(&mut c, &whole, t).is_empty());
        let request = sent(&fire(&mut c).1).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(request.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(pds_of(&request), [named(PD, DELEGATED)]);

        // Preference 255 with all of it is taken at once.
        let mut c = client_asking(both(), Options::default());
        c.handle(Event::Link(true), t0);
        let (t, solicit) = first_solicit(&mut c);
        let whole = answer(
            &solicit,
            msg::ADVERTISE,
            vec![preference(255), one_address(), one_prefix()],
        );
        assert_eq!(sent(&deliver(&mut c, &whole, t)).msg_type, msg::REQUEST);
    }

    #[test]
    fn what_a_server_withholds_is_asked_for_at_the_next_renewal() {
        let t0 = Instant::now();
        // The address without the prefix.
        let mut c = client_asking(both(), Options::default());
        let granted = vec![one_address(), ia_pd_status(PD, status::NO_PREFIX_AVAIL)];
        let (_, lease) = acquire_all(&mut c, t0, granted);
        assert!(lease.ia_na.is_some() && lease.ia_pd.is_empty());
        let (t, renew) = first_renew(&mut c);
        assert_eq!(addresses_of(&renew), [ADDRESS]);
        assert_eq!(pds_of(&renew), [named(PD, "::/56")]);
        // Now it is there.
        let reply = answer(&renew, msg::REPLY, vec![one_address(), one_prefix()]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
        assert!(lease.ia_na.is_some());

        // The prefix without the address.
        let mut c = client_asking(both(), Options::default());
        let granted = vec![ia_status(status::NO_ADDRS_AVAIL), one_prefix()];
        let (_, lease) = acquire_all(&mut c, t0, granted);
        assert!(lease.ia_na.is_none() && lease.ia_pd.len() == 1);
        let (t, renew) = first_renew(&mut c);
        assert!(ia_of(&renew).addresses.is_empty());
        assert_eq!(pds_of(&renew), [named(PD, DELEGATED)]);
        // A renewal that still has no address extends what is held, and
        // the client goes on asking at the times the server gives.
        let reply = answer(
            &renew,
            msg::REPLY,
            vec![ia_status(status::NO_ADDRS_AVAIL), one_prefix()],
        );
        let actions = deliver(&mut c, &reply, t);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t + secs(1800)));
        // A Release names what is held, and no identity association
        // that holds nothing.
        let actions = c.handle(Event::Release, t);
        let release = sent(&actions);
        assert_eq!(release.msg_type, msg::RELEASE);
        assert!(release.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(release), [named(PD, DELEGATED)]);
    }

    #[test]
    fn a_delegation_changes_and_runs_out() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(&mut c);
        // The server moves the delegation: the old prefix gets a valid
        // lifetime of 0, and another comes.
        let moved = ia_pd(
            PD,
            1800,
            2880,
            &[(DELEGATED, 0, 0), ("2001:db8:200::/56", 100, 200)],
        );
        let reply = answer(&renew, msg::REPLY, vec![one_address(), moved]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(
            lease.ia_pd[0].prefixes,
            [prefix("2001:db8:200::/56", 100, 200)]
        );
        // The new prefix runs out before the address does: the lease
        // goes on without it.
        c.handle(Event::Link(false), t);
        let (expired, actions) = fire(&mut c);
        assert_eq!(expired, t + secs(200));
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS, 3400, 7000)]
        );
        assert_eq!(c.state(), State::Bound);
    }

    #[test]
    fn what_a_reply_says_nothing_of_is_still_to_be_renewed() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(&mut c);
        let due = c.deadline();
        // The Reply speaks of the delegation alone, and takes its prefix
        // away. The address it says nothing of stays as it is, with the
        // T1 that has just passed: the Renew that was for it too goes on.
        let reply = answer(
            &renew,
            msg::REPLY,
            vec![ia_pd(PD, 1800, 2880, &[(DELEGATED, 0, 0)])],
        );
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }, Action::Log(_)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.addresses, [address(ADDRESS, 1800, 5400)]);
        assert_eq!((ia_na.t1, ia_na.t2), (0, 1080));
        // Not at once: when its retransmission is due.
        assert_eq!(c.state(), State::Renewing);
        assert_eq!(c.deadline(), due);
        let again = sent(&fire(&mut c).1).clone();
        assert_eq!(again.msg_type, msg::RENEW);
        assert_eq!(again.transaction_id, renew.transaction_id);
        assert_eq!(addresses_of(&again), [ADDRESS]);
        assert_eq!(pds_of(&again), [named(PD, "::/56")]);
    }

    #[test]
    fn a_prefix_a_reply_leaves_out_is_asked_about_until_it_runs_out() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        // The prefix is to be renewed long before the address.
        let short = ia_pd(PD, 10, 20, &[(DELEGATED, 30, 40)]);
        let (t0, lease) = acquire_all(&mut c, t0, vec![one_address(), short]);
        assert_eq!(lease.renewal(), (10, 20));
        let (t, renew) = first_renew(&mut c);
        assert_eq!(t, t0 + secs(10));
        let due = c.deadline();
        // A server that extends the address and says nothing of the
        // prefix: it does not delegate, perhaps.
        let half = |request: &ClientMessage| answer(request, msg::REPLY, vec![one_address()]);
        let actions = deliver(&mut c, &half(&renew), t);
        let [Action::Bind { lease, fresh: true }, Action::Log(_)] = &actions[..] else {
            panic!("{actions:?}")
        };
        // The address has its new times, the prefix what is left of its
        // own.
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!((ia_na.t1, ia_na.t2), (1800, 2880));
        assert_eq!(ia_na.addresses, [address(ADDRESS, 3600, 7200)]);
        assert_eq!(
            lease.ia_pd,
            [IaPd {
                iaid: PD,
                server_id: SERVER_DUID.to_vec(),
                t1: 0,
                t2: 10,
                prefixes: vec![prefix(DELEGATED, 20, 30)],
            }]
        );
        // For the prefix that was no answer: the Renew goes on, at its
        // own pace.
        assert_eq!(c.state(), State::Renewing);
        assert_eq!(c.deadline(), due);
        // At the prefix's T2 any server is asked, about all of it.
        let (t, actions) = fire(&mut c);
        assert_eq!(t, t0 + secs(20));
        let rebind = sent(&actions).clone();
        assert_eq!(rebind.msg_type, msg::REBIND);
        assert_eq!(c.state(), State::Rebinding);
        // It is about the prefix, which alone is past its T2, and takes
        // the Renew's place: the address has been answered for.
        assert!(rebind.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(&rebind), [named(PD, DELEGATED)]);
        let due = c.deadline();
        // An answer about the address is no answer to it.
        let actions = deliver(&mut c, &half(&rebind), t);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        assert_eq!(c.state(), State::Rebinding);
        assert_eq!(c.deadline(), due);
        let (t, actions) = fire(&mut c);
        assert!(t < t0 + secs(40));
        assert_eq!(sent(&actions).transaction_id, rebind.transaction_id);
        // Nobody extends the prefix: it runs out, and the lease goes on
        // without it. The address has been answered for, so the Rebind
        // is over.
        let (t, actions) = fire(&mut c);
        assert_eq!(t, t0 + secs(40));
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(lease.ia_na.as_ref().unwrap().addresses.len(), 1);
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t0 + secs(10 + 1800)));
        // The next Renew asks for a prefix anew.
        let (_, renew) = first_renew(&mut c);
        assert_eq!(pds_of(&renew), [named(PD, "::/56")]);
    }

    #[test]
    fn a_renew_that_goes_on_ends_when_the_lease_now_says() {
        let start = Instant::now();
        let lasting = [(DELEGATED, 3600, 7200)];
        // The address is to be rebound first, 20 s on, and the next Renew
        // would come after that.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 20, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 100, &lasting),
        ];
        let (t0, _) = acquire_all(&mut c, start, lease);
        let (t, renew) = first_renew(&mut c);
        assert_eq!(c.deadline(), Some(t0 + secs(20)));
        // The Reply moves the address's times on and leaves the prefix
        // out. The earliest T2 is the prefix's now, 100 s on: the same
        // Renew is sent until then.
        deliver(&mut c, &answer(&renew, msg::REPLY, vec![one_address()]), t);
        assert_eq!(c.state(), State::Renewing);
        let (t, actions) = fire(&mut c);
        assert!(t > t0 + secs(20) && t < t0 + secs(21), "{:?}", t - t0);
        assert_eq!(sent(&actions).msg_type, msg::RENEW);
        assert_eq!(sent(&actions).transaction_id, renew.transaction_id);
        let (t, rebind) = loop {
            let (t, actions) = fire(&mut c);
            if c.state() != State::Renewing {
                break (t, sent(&actions).clone());
            }
            assert_eq!(sent(&actions).transaction_id, renew.transaction_id);
        };
        assert_eq!(t, t0 + secs(100));
        assert_eq!(rebind.msg_type, msg::REBIND);

        // The other way: the Reply gives the address a T2 that comes
        // before the next Renew would.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 100, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 100, &lasting),
        ];
        let (t0, _) = acquire_all(&mut c, start, lease);
        let (t, renew) = first_renew(&mut c);
        assert!(c.deadline().unwrap() > t0 + secs(19));
        let soon = ia(3, 5, &[(ADDRESS, 3600, 7200)]);
        deliver(&mut c, &answer(&renew, msg::REPLY, vec![soon]), t);
        assert_eq!(c.state(), State::Renewing);
        // The address's new T1 comes first, with nothing to do: its
        // server's Renew is out. Then its T2.
        assert_eq!(c.deadline(), Some(t + secs(3)));
        assert!(fire(&mut c).1.is_empty());
        assert_eq!(c.deadline(), Some(t + secs(5)));
        let (_, actions) = fire(&mut c);
        assert_eq!(sent(&actions).msg_type, msg::REBIND);
        assert_eq!(c.state(), State::Rebinding);
    }

    #[test]
    fn a_renewal_is_over_when_all_of_the_lease_is_answered_for() {
        let t0 = Instant::now();
        // The operator renews a lease long before its T1, and the server
        // answers for the address alone.
        let mut c = client_asking(both(), Options::default());
        let (t0, _) = acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let t = t0 + secs(600);
        let actions = c.handle(Event::Renew, t);
        let [Action::Send(renew)] = &actions[..] else {
            panic!("{actions:?}")
        };
        let renew = renew.clone();
        assert_eq!(renew.msg_type, msg::RENEW);
        let due = c.deadline();
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, vec![one_address()]), t);
        let [Action::Bind { lease, fresh: true }, Action::Log(_)] = &actions[..] else {
            panic!("{actions:?}")
        };
        // The prefix keeps its lifetimes, and its own T1 and T2.
        assert_eq!(
            lease.ia_pd,
            [IaPd {
                iaid: PD,
                server_id: SERVER_DUID.to_vec(),
                t1: 1200,
                t2: 2280,
                prefixes: vec![prefix(DELEGATED, 3000, 6600)],
            }]
        );
        // All of the lease was asked about: the Renew goes on.
        assert_eq!(c.state(), State::Renewing);
        assert_eq!(c.deadline(), due);
        let (t, actions) = fire(&mut c);
        let again = sent(&actions).clone();
        assert_eq!(again.transaction_id, renew.transaction_id);
        // An answer for the prefix alone. The address was answered for
        // before: that is all of the lease, and the Renew is over.
        let rest = answer(&again, msg::REPLY, vec![one_prefix()]);
        let actions = deliver(&mut c, &rest, t);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
        // The address's T1 comes first, 1800 s after its own answer.
        let next = c.deadline().unwrap();
        assert!(
            next >= t0 + secs(2400) && next < t0 + secs(2401),
            "{:?}",
            next - t0
        );
    }

    #[test]
    fn a_verification_goes_on_for_what_a_reply_leaves_out() {
        let t0 = Instant::now();
        // A lease with a prefix, kept across a restart: any server is
        // asked about all of it.
        let resumed = |c: &mut Client| {
            let lease = kept_with_prefix();
            c.handle(
                Event::Resume {
                    lease,
                    elapsed: 600,
                },
                t0,
            );
            c.handle(Event::Link(true), t0);
            let (t, actions) = fire(c);
            let rebind = sent(&actions).clone();
            assert_eq!(rebind.msg_type, msg::REBIND);
            (t, rebind)
        };
        // A server answers for the address alone. The prefix's T1 is far
        // off, but whether it is right for this link is still not known:
        // the Rebind goes on.
        let mut c = client_asking(both(), Options::default());
        let (first, rebind) = resumed(&mut c);
        let due = c.deadline();
        let half = answer(&rebind, msg::REPLY, vec![one_address()]);
        let actions = deliver(&mut c, &half, first);
        let [Action::Bind { lease, fresh: true }, Action::Log(_)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_pd, kept_with_prefix().aged(600).ia_pd);
        assert_eq!(c.state(), State::Confirming);
        assert_eq!(c.deadline(), due);
        let (t, actions) = fire(&mut c);
        assert_eq!(sent(&actions).msg_type, msg::REBIND);
        assert_eq!(sent(&actions).transaction_id, rebind.transaction_id);
        // Another server knows the prefix, and that it is not for this
        // link. With that everything held is answered for.
        let gone = ia_pd(PD, 0, 0, &[(DELEGATED, 0, 0)]);
        let other = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![gone]);
        let actions = deliver(&mut c, &other, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert!(lease.ia_na.is_some());
        assert_eq!(c.state(), State::Bound);
        assert!(c.deadline().unwrap() > t + secs(1700));

        // Nobody answers for the prefix: the verification ends when a
        // Confirm would, and the prefix is used as it is.
        let mut c = client_asking(both(), Options::default());
        let (first, rebind) = resumed(&mut c);
        let half = answer(&rebind, msg::REPLY, vec![one_address()]);
        deliver(&mut c, &half, first);
        let (ended, actions) = loop {
            let (t, actions) = fire(&mut c);
            if c.state() != State::Confirming {
                break (t, actions);
            }
            assert_eq!(sent(&actions).transaction_id, rebind.transaction_id);
        };
        assert_eq!(ended, first + CNF_MAX_RD);
        assert_eq!(
            actions,
            [Action::Log(
                "no server answered for all of the lease; using the rest as it is".into()
            )]
        );
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.lease(ended).unwrap().ia_pd.len(), 1);
        // The prefix's own T1 is next, 1200 s after the lease was
        // resumed.
        assert_eq!(c.deadline(), Some(t0 + secs(1200)));
    }

    #[test]
    fn a_prefix_is_what_its_length_says() {
        let t0 = Instant::now();
        let mut c = client_asking(prefixes_only(), Options::default());
        // Bits set past the length are not part of the prefix; the same
        // prefix named again is the same prefix; and one that is
        // preferred for longer than it is valid, or not valid at all, is
        // not used.
        let odd = ia_pd(
            PD,
            0,
            0,
            &[
                ("2001:db8:100:ff::1/56", 3600, 7200),
                (DELEGATED, 100, 200),
                ("2001:db8:300::/56", 7200, 3600),
                ("2001:db8:400::/56", 0, 0),
            ],
        );
        let (_, lease) = acquire_all(&mut c, t0, vec![odd]);
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
    }

    #[test]
    fn a_lease_with_a_prefix_is_verified_with_a_rebind() {
        let t0 = Instant::now();
        let resume = || Event::Resume {
            lease: kept_with_prefix(),
            elapsed: 600,
        };
        let mut c = client_asking(both(), Options::default());
        let actions = c.handle(resume(), t0);
        assert_eq!(
            actions,
            [Action::Bind {
                lease: kept_with_prefix().aged(600),
                fresh: false
            }]
        );
        c.handle(Event::Link(true), t0);
        assert_eq!(c.state(), State::Confirming);
        let (first, actions) = fire(&mut c);
        // A Confirm speaks of addresses only: any server is asked about
        // all of it, with a Rebind.
        let rebind = sent(&actions).clone();
        assert_eq!(rebind.msg_type, msg::REBIND);
        assert!(rebind.option(opt::SERVER_ID).is_none());
        assert_eq!(addresses_of(&rebind), [ADDRESS]);
        assert_eq!(pds_of(&rebind), [named(PD, DELEGATED)]);
        // In a Confirm's time: again after about a second, and over in
        // ten, after which the lease is used as it is.
        let gap = c.deadline().unwrap() - first;
        assert!(gap <= CNF_TIMEOUT.mul_f64(1.1), "{gap:?}");
        let (ended, actions) = loop {
            let (t, actions) = fire(&mut c);
            if c.state() != State::Confirming {
                break (t, actions);
            }
            assert_eq!(sent(&actions).msg_type, msg::REBIND);
            assert_eq!(sent(&actions).transaction_id, rebind.transaction_id);
        };
        assert_eq!(ended, first + CNF_MAX_RD);
        assert_eq!(
            actions,
            [Action::Log(
                "no server confirmed the lease; using it until it expires".into()
            )]
        );
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t0 + secs(1200)));

        // Answered, by any server: what it says of the lease is taken. A
        // prefix that is not right for this link comes back with a valid
        // lifetime of 0.
        let mut c = client_asking(both(), Options::default());
        c.handle(resume(), t0);
        c.handle(Event::Link(true), t0);
        let (t, actions) = fire(&mut c);
        let rebind = sent(&actions).clone();
        let reply = answer_from(
            &OTHER_DUID,
            &rebind,
            msg::REPLY,
            vec![one_address(), ia_pd(PD, 0, 0, &[(DELEGATED, 0, 0)])],
        );
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(lease.server_id, OTHER_DUID);
        assert_eq!(c.state(), State::Bound);

        // A lease of addresses alone is confirmed, also for a client
        // that asks for a prefix as well.
        let mut c = client_asking(both(), Options::default());
        c.handle(
            Event::Resume {
                lease: kept(),
                elapsed: 0,
            },
            t0,
        );
        c.handle(Event::Link(true), t0);
        let confirm = sent(&fire(&mut c).1).clone();
        assert_eq!(confirm.msg_type, msg::CONFIRM);
        assert_eq!(addresses_of(&confirm), [ADDRESS]);
        assert!(pds_of(&confirm).is_empty());
    }

    #[test]
    fn only_what_is_asked_for_is_resumed() {
        let t0 = Instant::now();
        let resume = || Event::Resume {
            lease: kept_with_prefix(),
            elapsed: 0,
        };
        // The address, without the prefix nobody asks for now.
        let mut c = client(Options::default());
        assert_eq!(
            c.handle(resume(), t0),
            [Action::Bind {
                lease: kept(),
                fresh: false
            }]
        );
        // The prefix, without the address.
        let mut c = client_asking(prefixes_only(), Options::default());
        let actions = c.handle(resume(), t0);
        let [
            Action::Bind {
                lease,
                fresh: false,
            },
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na, None);
        assert_eq!(lease.ia_pd, kept_with_prefix().ia_pd);
        // Another delegation: nothing of the lease is this client's.
        let other = Asks {
            ia_na: None,
            ia_pd: vec![ask_pd(PD + 1, 56)],
        };
        let mut c = client_asking(other, Options::default());
        assert!(c.handle(resume(), t0).is_empty());
        assert_eq!(c.state(), State::Stopped);
    }

    #[test]
    fn declining_the_address_leaves_the_prefix() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        let (t, _) = acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let actions = c.handle(Event::AddressConflict(ADDRESS), t);
        let [
            Action::Log(_),
            Action::Bind { lease, fresh: true },
            Action::Send(decline),
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na, None);
        assert_eq!(lease.ia_pd.len(), 1);
        // A Decline is about addresses.
        assert_eq!(decline.msg_type, msg::DECLINE);
        assert_eq!(addresses_of(decline), [ADDRESS]);
        assert!(pds_of(decline).is_empty());
        // The lease goes on, and another address is asked for with the
        // next Renew.
        let decline = decline.clone();
        assert!(deliver(&mut c, &answer(&decline, msg::REPLY, vec![]), t).is_empty());
        assert_eq!(c.state(), State::Bound);
        let (_, renew) = first_renew(&mut c);
        assert!(ia_of(&renew).addresses.is_empty());
        assert_eq!(pds_of(&renew), [named(PD, DELEGATED)]);
    }

    #[test]
    fn no_binding_for_one_requests_all_of_it_again() {
        let t0 = Instant::now();
        let no_binding = || ia_pd_status(PD, status::NO_BINDING);
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(&mut c);
        // What the Reply says of the address is taken before anything
        // else: here, longer lifetimes.
        let longer = ia(1800, 2880, &[(ADDRESS, 4000, 8000)]);
        let reply = answer(&renew, msg::REPLY, vec![longer, no_binding()]);
        let actions = deliver(&mut c, &reply, t);
        let [
            Action::Bind { lease, fresh: true },
            Action::Log(_),
            Action::Send(request),
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.addresses, [address(ADDRESS, 4000, 8000)]);
        assert_eq!((ia_na.t1, ia_na.t2), (1800, 2880));
        // The prefix stays in use as it was.
        assert_eq!(
            lease.ia_pd,
            [IaPd {
                iaid: PD,
                server_id: SERVER_DUID.to_vec(),
                t1: 0,
                t2: 1080,
                prefixes: vec![prefix(DELEGATED, 1800, 5400)],
            }]
        );
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(request.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(request), [ADDRESS]);
        assert_eq!(pds_of(request), [named(PD, DELEGATED)]);
        assert_eq!(c.state(), State::Requesting);
        assert_eq!(c.lease(t).as_ref(), Some(lease));

        // An address the Reply takes away is out of use before the
        // Request, which does not name it.
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(&mut c);
        let revoked = || ia(0, 0, &[(ADDRESS, 0, 0)]);
        let reply = answer(&renew, msg::REPLY, vec![revoked(), no_binding()]);
        let actions = deliver(&mut c, &reply, t);
        let [
            Action::Bind { lease, fresh: true },
            Action::Log(_),
            Action::Send(request),
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na, None);
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 1800, 5400)]);
        assert_eq!(request.msg_type, msg::REQUEST);
        assert!(ia_of(request).addresses.is_empty());
        assert_eq!(pds_of(request), [named(PD, DELEGATED)]);
        assert_eq!(c.lease(t).as_ref(), Some(lease));

        // With nothing left there is no lease to ask that server for
        // again: the client starts over, not at once.
        let mut c = client_asking(both(), Options::default());
        let granted = vec![one_address(), ia_pd_status(PD, status::NO_PREFIX_AVAIL)];
        acquire_all(&mut c, t0, granted);
        let (t, renew) = first_renew(&mut c);
        let reply = answer(&renew, msg::REPLY, vec![revoked(), no_binding()]);
        let actions = deliver(&mut c, &reply, t);
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Backoff);
        assert!(c.lease(t).is_none());
    }

    /// A lease of an address and a prefix, renewed with a Reply that
    /// extends the address (and names a DNS server) and has no record of
    /// the delegation: returns when, and the Request that follows.
    fn lose_the_prefix(c: &mut Client, t0: Instant) -> (Instant, ClientMessage) {
        acquire_all(c, t0, vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(c);
        let reply = answer(
            &renew,
            msg::REPLY,
            vec![
                ia(1800, 2880, &[(ADDRESS, 4000, 8000)]),
                ia_pd_status(PD, status::NO_BINDING),
                Dhcp6Option::new(opt::DNS_SERVERS, DNS.octets()),
            ],
        );
        let request = sent(&deliver(c, &reply, t)).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        (t, request)
    }

    #[test]
    fn the_request_after_no_binding_is_merged_into_the_lease() {
        let t0 = Instant::now();
        let renewed = [address(ADDRESS, 4000, 8000)];
        let reply_to = |c: &mut Client, request: &ClientMessage, t, options| {
            deliver(c, &answer(request, msg::REPLY, options), t)
        };
        // The server delegates again and names no address: the address
        // was not what it had no record of, and stays as it is.
        let mut c = client_asking(both(), Options::default());
        let (t, request) = lose_the_prefix(&mut c, t0);
        let actions = reply_to(&mut c, &request, t, vec![ia(0, 0, &[]), one_prefix()]);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.addresses, renewed);
        // Its times were left to the client.
        assert_eq!((ia_na.t1, ia_na.t2), (2000, 3200));
        assert_eq!(
            lease.ia_pd,
            [IaPd {
                iaid: PD,
                server_id: SERVER_DUID.to_vec(),
                t1: 1800,
                t2: 2880,
                prefixes: vec![prefix(DELEGATED, 3600, 7200)],
            }]
        );
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t + secs(1800)));

        // The delegation is what the Reply makes of it: a prefix held
        // before and not given again has no server behind it.
        let mut c = client_asking(both(), Options::default());
        let (t, request) = lose_the_prefix(&mut c, t0);
        let another = ia_pd(PD, 1800, 2880, &[("2001:db8:200::/56", 3600, 7200)]);
        let actions = reply_to(&mut c, &request, t, vec![one_address(), another]);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(
            lease.ia_pd[0].prefixes,
            [prefix("2001:db8:200::/56", 3600, 7200)]
        );

        // No prefix this time: the delegation goes, the address stays.
        let mut c = client_asking(both(), Options::default());
        let (t, request) = lose_the_prefix(&mut c, t0);
        let none = ia_pd_status(PD, status::NO_PREFIX_AVAIL);
        let actions = reply_to(&mut c, &request, t, vec![ia(0, 0, &[]), none]);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(lease.ia_na.as_ref().unwrap().addresses, renewed);
        assert_eq!(c.state(), State::Bound);

        // Refused outright: likewise, and the address is as the renewal
        // left it, with the rest of what that Reply said.
        let mut c = client_asking(both(), Options::default());
        let (t, request) = lose_the_prefix(&mut c, t0);
        let no = vec![status_option(status::NO_ADDRS_AVAIL)];
        let actions = reply_to(&mut c, &request, t, no);
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.addresses, renewed);
        assert_eq!((ia_na.t1, ia_na.t2), (1800, 2880));
        assert_eq!(lease.dns_servers, [DNS]);
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t + secs(1800)));

        // Not answered at all: likewise, once the Request has been sent
        // as often as it is to be.
        let mut c = client_asking(both(), Options::default());
        let (t, _) = lose_the_prefix(&mut c, t0);
        let (ended, actions) = loop {
            let (ended, actions) = fire(&mut c);
            if c.state() != State::Requesting {
                break (ended, actions);
            }
        };
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        // What is left of the address's lifetimes by now.
        let waited = (ended - t).as_secs() as u32;
        assert!(waited > 60, "{waited}");
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS, 4000 - waited, 8000 - waited)]
        );
        assert_eq!(c.lease(ended).as_ref(), Some(lease));
        assert_eq!(c.state(), State::Bound);

        // Two delegations, and no record of one of them: the other is not
        // touched, though the Reply names nothing of it.
        let asks = Asks {
            ia_na: None,
            ia_pd: vec![ask_pd(PD, 56), ask_pd(PD + 1, 56)],
        };
        let mut c = client_asking(asks, Options::default());
        let second = || ia_pd(PD + 1, 1800, 2880, &[("2001:db8:200::/56", 3600, 7200)]);
        acquire_all(&mut c, t0, vec![one_prefix(), second()]);
        let (t, renew) = first_renew(&mut c);
        let lost = ia_pd_status(PD, status::NO_BINDING);
        let reply = answer(&renew, msg::REPLY, vec![lost, second()]);
        let request = sent(&deliver(&mut c, &reply, t)).clone();
        let options = vec![
            ia_pd_status(PD, status::NO_PREFIX_AVAIL),
            ia_pd(PD + 1, 0, 0, &[]),
        ];
        let actions = reply_to(&mut c, &request, t, options);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_pd.len(), 1);
        assert_eq!(lease.ia_pd[0].iaid, PD + 1);
        assert_eq!(
            lease.ia_pd[0].prefixes,
            [prefix("2001:db8:200::/56", 3600, 7200)]
        );

        // A server with no record of any of it, which then refuses: the
        // lease is over.
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(&mut c);
        let reply = answer(&renew, msg::REPLY, vec![status_option(status::NO_BINDING)]);
        let request = sent(&deliver(&mut c, &reply, t)).clone();
        let no = vec![status_option(status::NO_ADDRS_AVAIL)];
        let actions = reply_to(&mut c, &request, t, no);
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Backoff);
        assert!(c.lease(t).is_none());
    }

    /// `kept_with_prefix`, with the prefix leased from another server
    /// and the first to be renewed.
    fn mixed() -> Lease {
        let mut lease = kept_with_prefix();
        lease.ia_pd[0].server_id = OTHER_DUID.to_vec();
        (lease.ia_pd[0].t1, lease.ia_pd[0].t2) = (1000, 1600);
        lease
    }

    /// A client bound to `lease`, and when the lease's times count from.
    fn holding(lease: Lease) -> (Client, Instant) {
        holding_as(both(), lease)
    }

    fn holding_as(asks: Asks, lease: Lease) -> (Client, Instant) {
        let t0 = Instant::now();
        let mut c = client_asking(asks, Options::default());
        c.handle(Event::Resume { lease, elapsed: 0 }, t0);
        c.handle(Event::Link(true), t0);
        // Nobody answers the verification.
        while c.state() == State::Confirming {
            fire(&mut c);
        }
        assert_eq!(c.state(), State::Bound);
        (c, t0)
    }

    #[test]
    fn each_server_is_asked_about_what_is_leased_from_it() {
        let (mut c, t0) = holding(mixed());
        // The prefix is to be renewed first: with its server, in a Renew
        // that says nothing of the address.
        let (t, renew) = first_renew(&mut c);
        assert_eq!(t, t0 + secs(1000));
        assert_eq!(renew.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        assert!(renew.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(&renew), [named(PD, DELEGATED)]);
        // The address's server has no say in it.
        let not_asked = answer(&renew, msg::REPLY, vec![one_address(), one_prefix()]);
        assert!(deliver(&mut c, &not_asked, t).is_empty());
        // Nor has the prefix's server a say about the address.
        let reply = answer_from(
            &OTHER_DUID,
            &renew,
            msg::REPLY,
            vec![
                ia(100, 200, &[(ADDRESS, 9000, 9000)]),
                ia_pd(PD, 1000, 1600, &[(DELEGATED, 3600, 7200)]),
            ],
        );
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.server_id, SERVER_DUID);
        assert_eq!(ia_na.addresses, [address(ADDRESS, 2600, 6200)]);
        assert_eq!((ia_na.t1, ia_na.t2), (800, 1880));
        assert_eq!(lease.ia_pd[0].server_id, OTHER_DUID);
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
        // The rest of the configuration stays the address's server's.
        assert_eq!(lease.server_id, SERVER_DUID);
        assert_eq!(lease.dns_servers, [DNS]);
        assert_eq!(c.state(), State::Bound);

        // The address is next, with its own server.
        let (t, renew) = first_renew(&mut c);
        assert_eq!(t, t0 + secs(1800));
        assert_eq!(renew.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(&renew), [ADDRESS]);
        assert!(pds_of(&renew).is_empty());
        // That server has no record of it: the Request is about the
        // address alone too, and so is what its Reply can change.
        let reply = answer(&renew, msg::REPLY, vec![ia_status(status::NO_BINDING)]);
        let request = sent(&deliver(&mut c, &reply, t)).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(request.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(&request), [ADDRESS]);
        assert!(pds_of(&request).is_empty());
        let gone = ia_pd(PD, 0, 0, &[(DELEGATED, 0, 0)]);
        let reply = answer(&request, msg::REPLY, vec![one_address(), gone]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS, 3600, 7200)]
        );
        assert_eq!(lease.ia_pd[0].server_id, OTHER_DUID);
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 2800, 6400)]);
        assert_eq!(c.state(), State::Bound);

        // Given back, each server is told of its own: one, then the
        // other.
        let actions = c.handle(Event::Release, t);
        let [Action::Unbind, Action::Send(first)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(first.msg_type, msg::RELEASE);
        assert_eq!(first.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(first), [ADDRESS]);
        assert!(pds_of(first).is_empty());
        let first = first.clone();
        let actions = deliver(&mut c, &answer(&first, msg::REPLY, vec![]), t);
        let [Action::Send(second)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(second.msg_type, msg::RELEASE);
        assert_eq!(second.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        assert!(second.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(second), [named(PD, DELEGATED)]);
        assert_ne!(second.transaction_id, first.transaction_id);
        assert_eq!(c.state(), State::Releasing);
        let second = second.clone();
        let reply = answer_from(&OTHER_DUID, &second, msg::REPLY, vec![]);
        assert!(deliver(&mut c, &reply, t).is_empty());
        assert_eq!(c.state(), State::Released);

        // A second server that does not answer is told as often as the
        // first would be.
        let (mut c, t0) = holding(mixed());
        let first = sent(&c.handle(Event::Release, t0 + secs(20))).clone();
        let actions = deliver(&mut c, &answer(&first, msg::REPLY, vec![]), t0 + secs(20));
        let mut told = actions.len();
        while c.state() == State::Releasing {
            told += fire(&mut c).1.len();
        }
        assert_eq!(told as u32, REL_MAX_RC);
        assert_eq!(c.state(), State::Released);

        // A link that goes meanwhile ends it: the second server cannot
        // be told.
        let (mut c, t0) = holding(mixed());
        let actions = c.handle(Event::Release, t0 + secs(20));
        assert_eq!(sent(&actions).msg_type, msg::RELEASE);
        assert!(c.handle(Event::Link(false), t0 + secs(20)).is_empty());
        assert_eq!(c.state(), State::Released);
        assert_eq!(c.deadline(), None);
    }

    #[test]
    fn a_server_that_does_not_answer_holds_up_no_other_renewal() {
        // The prefix is one server's and to be renewed first; the address
        // is another's.
        let two_servers = || {
            let mut lease = kept_with_prefix();
            (lease.ia_pd[0].t1, lease.ia_pd[0].t2) = (100, 1000);
            let ia_na = lease.ia_na.as_mut().unwrap();
            ia_na.server_id = OTHER_DUID.to_vec();
            (ia_na.t1, ia_na.t2) = (200, 800);
            lease
        };
        let (mut c, t0) = holding(two_servers());
        let (t, to_a) = first_renew(&mut c);
        assert_eq!(t, t0 + secs(100));
        assert_eq!(to_a.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert!(to_a.option(opt::IA_NA).is_none());
        // That server stays silent. Its Renew is sent again and again,
        // and at the address's T1 the other server gets a Renew of its
        // own.
        let (t, to_b) = loop {
            let (t, actions) = fire(&mut c);
            let [Action::Send(message)] = &actions[..] else {
                panic!("{actions:?}")
            };
            if message.transaction_id != to_a.transaction_id {
                break (t, message.clone());
            }
            assert!(t < t0 + secs(200));
        };
        assert_eq!(t, t0 + secs(200));
        assert_eq!(to_b.msg_type, msg::RENEW);
        assert_eq!(to_b.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        assert_eq!(addresses_of(&to_b), [ADDRESS]);
        assert!(pds_of(&to_b).is_empty());
        // An answer that extends nothing leaves each Renew its own pace:
        // the second one's turn is next, alone.
        let refusal = vec![ia_pd_status(PD, status::NO_PREFIX_AVAIL)];
        let actions = deliver(&mut c, &answer(&to_a, msg::REPLY, refusal), t);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        let (again, actions) = fire(&mut c);
        let [Action::Send(message)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(message.transaction_id, to_b.transaction_id);
        let gap = again - t;
        assert!(gap >= secs(9) && gap <= secs(11), "{gap:?}");
        // The second server answers: its Renew is over, the first one's
        // goes on.
        let reply = answer_from(&OTHER_DUID, &to_b, msg::REPLY, vec![one_address()]);
        let actions = deliver(&mut c, &reply, again);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.addresses, [address(ADDRESS, 3600, 7200)]);
        assert_eq!(c.state(), State::Renewing);
        // Until the prefix's T2: any server is asked then, about the
        // prefix.
        let (t, rebind) = loop {
            let (t, actions) = fire(&mut c);
            let [Action::Send(message)] = &actions[..] else {
                panic!("{actions:?}")
            };
            if c.state() != State::Renewing {
                break (t, message.clone());
            }
            assert_eq!(message.transaction_id, to_a.transaction_id);
        };
        assert_eq!(t, t0 + secs(1000));
        assert_eq!(rebind.msg_type, msg::REBIND);
        assert!(rebind.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(&rebind), [named(PD, DELEGATED)]);

        // With both silent, the earliest T2 of all is the address's.
        let (mut c, t0) = holding(two_servers());
        let mut asked: Vec<u32> = Vec::new();
        let t = loop {
            let (t, actions) = fire(&mut c);
            if c.state() != State::Renewing {
                break t;
            }
            let xid = sent(&actions).transaction_id;
            if !asked.contains(&xid) {
                asked.push(xid);
            }
        };
        assert_eq!(asked.len(), 2);
        assert_eq!(t, t0 + secs(800));
        assert_eq!(c.state(), State::Rebinding);

        // A renewal by hand asks both at once.
        let (mut c, t0) = holding(two_servers());
        let actions = c.handle(Event::Renew, t0 + secs(20));
        let [Action::Send(first), Action::Send(second)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(first.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        assert_eq!(addresses_of(first), [ADDRESS]);
        assert_eq!(second.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(pds_of(second), [named(PD, DELEGATED)]);
        assert_eq!(c.state(), State::Renewing);
    }

    #[test]
    fn a_server_that_takes_a_part_away_is_not_the_server_of_the_rest() {
        // Two addresses and two prefixes, all of them the first server's.
        let mut lease = kept_with_prefix();
        let ia_na = lease.ia_na.as_mut().unwrap();
        ia_na.addresses.push(address(ADDRESS2, 3600, 7200));
        let more = prefix("2001:db8:200::/56", 3600, 7200);
        lease.ia_pd[0].prefixes.push(more.clone());
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        c.handle(Event::Resume { lease, elapsed: 0 }, t0);
        c.handle(Event::Link(true), t0);
        let (t, actions) = fire(&mut c);
        let rebind = sent(&actions).clone();
        // Another server: one address and one prefix are not for this
        // link. It says nothing of the others.
        let reply = answer_from(
            &OTHER_DUID,
            &rebind,
            msg::REPLY,
            vec![
                ia(0, 0, &[(ADDRESS, 0, 0)]),
                ia_pd(PD, 0, 0, &[(DELEGATED, 0, 0)]),
            ],
        );
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.addresses, [address(ADDRESS2, 3600, 7200)]);
        assert_eq!(ia_na.server_id, SERVER_DUID);
        assert_eq!(lease.ia_pd[0].prefixes, [more]);
        assert_eq!(lease.ia_pd[0].server_id, SERVER_DUID);
    }

    #[test]
    fn a_server_is_asked_for_what_it_has_no_record_of_whoever_leased_it() {
        let t0 = Instant::now();
        for lost_address in [true, false] {
            let mut c = client_asking(both(), Options::default());
            acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
            let (t, rebind) = loop {
                let (t, actions) = fire(&mut c);
                if c.state() == State::Rebinding {
                    break (t, sent(&actions).clone());
                }
            };
            // Another server takes one part over, and has no record of
            // the other.
            let options = if lost_address {
                vec![ia_status(status::NO_BINDING), one_prefix()]
            } else {
                vec![one_address(), ia_pd_status(PD, status::NO_BINDING)]
            };
            let reply = answer_from(&OTHER_DUID, &rebind, msg::REPLY, options);
            let request = sent(&deliver(&mut c, &reply, t)).clone();
            // It is asked for both: the one it has no record of is not
            // left out for being another server's.
            assert_eq!(request.msg_type, msg::REQUEST);
            assert_eq!(request.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
            assert_eq!(addresses_of(&request), [ADDRESS]);
            assert_eq!(pds_of(&request), [named(PD, DELEGATED)]);
        }

        // A server that takes no part over: asked for what it has no
        // record of all the same, and until it answers.
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let (t, rebind) = loop {
            let (t, actions) = fire(&mut c);
            if c.state() == State::Rebinding {
                break (t, sent(&actions).clone());
            }
        };
        let options = vec![ia_status(status::NO_BINDING)];
        let reply = answer_from(&OTHER_DUID, &rebind, msg::REPLY, options);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Log(_), Action::Send(request)] = &actions[..] else {
            panic!("{actions:?}")
        };
        let request = request.clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(addresses_of(&request), [ADDRESS]);
        // The prefix is the first server's: not this one's to speak of.
        assert!(pds_of(&request).is_empty());
        assert_eq!(c.state(), State::Requesting);
        let (_, actions) = fire(&mut c);
        assert_eq!(sent(&actions).transaction_id, request.transaction_id);
        // The Rebind goes on beside the Request, as it was.
        let again = loop {
            let (_, actions) = fire(&mut c);
            if sent(&actions).msg_type == msg::REBIND {
                break sent(&actions).clone();
            }
        };
        assert_eq!(again.transaction_id, rebind.transaction_id);
        let reply = answer_from(&OTHER_DUID, &request, msg::REPLY, vec![one_address()]);
        let actions = deliver(&mut c, &reply, t);
        let Some(Action::Bind { lease, fresh: true }) = actions.first() else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na.as_ref().unwrap().server_id, OTHER_DUID);
        assert_eq!(lease.ia_pd[0].server_id, SERVER_DUID);
    }

    #[test]
    fn a_server_with_no_record_of_anything_loses_only_its_own() {
        let no_binding = || vec![status_option(status::NO_BINDING)];
        let refusal = || vec![status_option(status::NO_ADDRS_AVAIL)];
        // The prefix's server, asked first.
        let (mut c, _) = holding(mixed());
        let (t, renew) = first_renew(&mut c);
        let reply = answer_from(&OTHER_DUID, &renew, msg::REPLY, no_binding());
        let request = sent(&deliver(&mut c, &reply, t)).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        let reply = answer_from(&OTHER_DUID, &request, msg::REPLY, refusal());
        let actions = deliver(&mut c, &reply, t);
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert!(lease.ia_na.is_some());
        assert_eq!(c.state(), State::Bound);

        // The address's server, when the address is the first to be
        // renewed.
        let address_first = || {
            let mut lease = mixed();
            (lease.ia_pd[0].t1, lease.ia_pd[0].t2) = (3000, 3200);
            lease
        };
        let (mut c, _) = holding(address_first());
        let (t, renew) = first_renew(&mut c);
        assert_eq!(renew.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        let request = sent(&deliver(
            &mut c,
            &answer(&renew, msg::REPLY, no_binding()),
            t,
        ))
        .clone();
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, refusal()), t);
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na, None);
        assert_eq!(lease.ia_pd.len(), 1);

        // And when that server does answer, its Renew is over: the
        // prefix was not its to answer for.
        let (mut c, _) = holding(address_first());
        let (t, renew) = first_renew(&mut c);
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, vec![one_address()]), t);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
    }

    #[test]
    fn a_reply_that_only_takes_away_changes_no_server() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        c.handle(
            Event::Resume {
                lease: kept_with_prefix(),
                elapsed: 600,
            },
            t0,
        );
        c.handle(Event::Link(true), t0);
        let (t, actions) = fire(&mut c);
        let rebind = sent(&actions).clone();
        // The lease's server renews the address, and names a DNS server.
        let dns = Dhcp6Option::new(opt::DNS_SERVERS, DNS.octets());
        let renewed = answer(&rebind, msg::REPLY, vec![one_address(), dns]);
        deliver(&mut c, &renewed, t);
        // Another server says the prefix is not for this link, and names
        // another DNS server.
        let gone = ia_pd(PD, 0, 0, &[(DELEGATED, 0, 0)]);
        let dns = Dhcp6Option::new(opt::DNS_SERVERS, ADDRESS3.octets());
        let other = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![gone, dns]);
        let actions = deliver(&mut c, &other, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        // The prefix goes. The address is still the first server's, and
        // so is the rest of the configuration.
        assert!(lease.ia_pd.is_empty());
        assert_eq!(lease.ia_na.as_ref().unwrap().server_id, SERVER_DUID);
        assert_eq!(lease.server_id, SERVER_DUID);
        assert_eq!(lease.dns_servers, [DNS]);
        // That server is asked to renew the address, and told when it
        // goes back.
        let (t, renew) = first_renew(&mut c);
        assert_eq!(renew.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        let actions = c.handle(Event::Release, t);
        assert_eq!(sent(&actions).msg_type, msg::RELEASE);
        assert_eq!(
            sent(&actions).option(opt::SERVER_ID),
            Some(&SERVER_DUID[..])
        );
    }

    #[test]
    fn a_server_that_extends_a_part_is_the_server_of_that_part() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        let (t0, _) = acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        // The lease's server is gone: nobody answers the Renew, and at T2
        // any server is asked.
        let (t, rebind) = loop {
            let (t, actions) = fire(&mut c);
            if c.state() == State::Rebinding {
                break (t, sent(&actions).clone());
            }
        };
        assert_eq!(t, t0 + secs(2880));
        // Another server extends the prefix and knows nothing of the
        // address.
        let dns = Dhcp6Option::new(opt::DNS_SERVERS, ADDRESS3.octets());
        let reply = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![one_prefix(), dns]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }, Action::Log(_)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_pd[0].server_id, OTHER_DUID);
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
        // The address is still the first server's, as is the rest of the
        // configuration, and the Rebind goes on for it.
        assert_eq!(lease.ia_na.as_ref().unwrap().server_id, SERVER_DUID);
        assert_eq!(lease.server_id, SERVER_DUID);
        assert!(lease.dns_servers.is_empty());
        assert_eq!(c.state(), State::Rebinding);
    }

    #[test]
    fn the_rest_of_the_configuration_is_from_the_first_server_left() {
        let (mut c, t0) = holding(mixed());
        let t = t0 + secs(20);
        // A duplicate address is declined with the server it is leased
        // from.
        let actions = c.handle(Event::AddressConflict(ADDRESS), t);
        let decline = sent(&actions).clone();
        assert_eq!(decline.msg_type, msg::DECLINE);
        assert_eq!(decline.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        deliver(&mut c, &answer(&decline, msg::REPLY, vec![]), t);
        assert_eq!(c.state(), State::Bound);
        // Only the prefix is left. What its server says of DNS counts
        // from its next answer on.
        assert_eq!(c.lease(t).unwrap().dns_servers, [DNS]);
        let (t, renew) = first_renew(&mut c);
        assert_eq!(renew.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        // Nobody holds the address now: this server is asked for one.
        assert!(ia_of(&renew).addresses.is_empty());
        let dns = Dhcp6Option::new(opt::DNS_SERVERS, ADDRESS3.octets());
        let reply = answer_from(&OTHER_DUID, &renew, msg::REPLY, vec![one_prefix(), dns]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.server_id, OTHER_DUID);
        assert_eq!(lease.dns_servers, [ADDRESS3]);

        // A Decline is exchanged alone. The Renew it interrupts begins
        // anew when it is over.
        let (mut c, _) = holding(mixed());
        let (t, renew) = first_renew(&mut c);
        let actions = c.handle(Event::AddressConflict(ADDRESS), t);
        let decline = sent(&actions).clone();
        assert_eq!(decline.msg_type, msg::DECLINE);
        assert_eq!(c.state(), State::Declining);
        let actions = deliver(&mut c, &answer(&decline, msg::REPLY, vec![]), t);
        let [Action::Send(again)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(again.msg_type, msg::RENEW);
        assert_eq!(again.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        assert_ne!(again.transaction_id, renew.transaction_id);
        assert_eq!(c.state(), State::Renewing);

        // The Decline goes by the address's own server, whatever the
        // lease names for the rest.
        let mut lease = mixed();
        lease.server_id = OTHER_DUID.to_vec();
        let (mut c, t0) = holding(lease);
        let actions = c.handle(Event::AddressConflict(ADDRESS), t0 + secs(20));
        assert_eq!(
            sent(&actions).option(opt::SERVER_ID),
            Some(&SERVER_DUID[..])
        );
    }

    #[test]
    fn a_lease_kept_before_servers_were_told_apart_has_one() {
        // As the lease file had it: one server for all of the lease.
        let mut json = serde_json::to_value(kept_with_prefix()).unwrap();
        json["ia_na"].as_object_mut().unwrap().remove("server_id");
        json["ia_pd"][0]
            .as_object_mut()
            .unwrap()
            .remove("server_id");
        let old: Lease = serde_json::from_value(json).unwrap();
        assert!(old.ia_na.as_ref().unwrap().server_id.is_empty());
        assert!(old.ia_pd[0].server_id.is_empty());
        // Resumed, every part is that server's.
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        let actions = c.handle(
            Event::Resume {
                lease: old,
                elapsed: 0,
            },
            t0,
        );
        assert_eq!(
            actions,
            [Action::Bind {
                lease: kept_with_prefix(),
                fresh: false
            }]
        );
    }

    #[test]
    fn a_server_that_gives_nothing_back_is_not_sent_request_after_request() {
        let t0 = Instant::now();
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        // A server that will not extend the address, has no record of
        // the delegation, and gives nothing when asked again.
        let lost = || {
            vec![
                ia_status(status::NO_ADDRS_AVAIL),
                ia_pd_status(PD, status::NO_BINDING),
            ]
        };
        let nothing = || {
            vec![
                ia_status(status::NO_ADDRS_AVAIL),
                ia_pd_status(PD, status::NO_PREFIX_AVAIL),
            ]
        };
        let round = |c: &mut Client, renew: &ClientMessage, t: Instant| {
            let request = sent(&deliver(c, &answer(renew, msg::REPLY, lost()), t)).clone();
            assert_eq!(request.msg_type, msg::REQUEST);
            let actions = deliver(c, &answer(&request, msg::REPLY, nothing()), t);
            // The address is still to be renewed: a Renew for it goes out
            // at once.
            let [
                Action::Log(_),
                Action::Bind { lease, fresh: true },
                Action::Send(again),
            ] = &actions[..]
            else {
                panic!("{actions:?}")
            };
            assert!(lease.ia_pd.is_empty() && lease.ia_na.is_some());
            assert_eq!(again.msg_type, msg::RENEW);
            assert_eq!(c.state(), State::Renewing);
            again.clone()
        };
        let (mut t, mut renew) = first_renew(&mut c);
        // NoBinding again gets no Request for a second, then for two,
        // then four, and never for more than 64: until then it is a Reply
        // that extends nothing, and the Renew goes on at its own pace.
        for wait in [1, 2, 4, 8, 16, 32, 64, 64, 64] {
            renew = round(&mut c, &renew, t);
            let due = c.deadline();
            let soon = t + secs(wait) - Duration::from_millis(1);
            let actions = deliver(&mut c, &answer(&renew, msg::REPLY, lost()), soon);
            assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
            assert_eq!(c.state(), State::Renewing);
            assert_eq!(c.deadline(), due);
            t += secs(wait);
        }
        // An answer for all of it, and the wait starts from a second
        // again.
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, vec![one_address()]), t);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
        let (t, renew) = first_renew(&mut c);
        let renew = round(&mut c, &renew, t);
        let soon = t + Duration::from_millis(999);
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, lost()), soon);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, lost()), t + secs(1));
        assert_eq!(sent(&actions).msg_type, msg::REQUEST);

        // A Request that leaves nothing more to renew ends the growing
        // wait, like any answer for all of it: the next one that comes to
        // nothing makes its server quiet for a second again.
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(&mut c);
        let renew = round(&mut c, &renew, t);
        let t = t + secs(1);
        let request = sent(&deliver(&mut c, &answer(&renew, msg::REPLY, lost()), t)).clone();
        let back = vec![one_address(), ia_pd_status(PD, status::NO_PREFIX_AVAIL)];
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, back), t);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
        let (t, renew) = first_renew(&mut c);
        let renew = round(&mut c, &renew, t);
        let soon = t + Duration::from_millis(999);
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, lost()), soon);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, lost()), t + secs(1));
        assert_eq!(sent(&actions).msg_type, msg::REQUEST);

        // What such a Reply does give is taken all the same.
        let mut c = client_asking(both(), Options::default());
        acquire_all(&mut c, t0, vec![one_address(), one_prefix()]);
        let (t, renew) = first_renew(&mut c);
        let renew = round(&mut c, &renew, t);
        let some = vec![one_address(), ia_pd_status(PD, status::NO_BINDING)];
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, some), t);
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS, 3600, 7200)]
        );
        assert_eq!(c.state(), State::Bound);
    }

    #[test]
    fn only_a_request_that_came_to_nothing_makes_its_server_quiet() {
        let lost = || vec![ia_status(status::NO_BINDING)];
        // The Request restores the lease. Asked again at once, the server
        // says NoBinding again: a Request again.
        let mut c = client(Options::default());
        acquire(&mut c, Instant::now(), one_address());
        let (t, renew) = first_renew(&mut c);
        let request = sent(&deliver(&mut c, &answer(&renew, msg::REPLY, lost()), t)).clone();
        deliver(
            &mut c,
            &answer(&request, msg::REPLY, vec![one_address()]),
            t,
        );
        assert_eq!(c.state(), State::Bound);
        let renew = sent(&c.handle(Event::Renew, t)).clone();
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, lost()), t);
        assert_eq!(sent(&actions).msg_type, msg::REQUEST);

        // So when another server's part is still to be renewed: that is
        // not this server's doing.
        let mut lease = mixed();
        (lease.ia_pd[0].t1, lease.ia_pd[0].t2) = (1800, 2880);
        let (mut c, _) = holding(lease);
        let (t, actions) = fire(&mut c);
        let to_a = sent(&actions).clone();
        let request = sent(&deliver(&mut c, &answer(&to_a, msg::REPLY, lost()), t)).clone();
        deliver(
            &mut c,
            &answer(&request, msg::REPLY, vec![one_address()]),
            t,
        );
        assert_eq!(c.state(), State::Renewing);
        let to_a = sent(&c.handle(Event::Renew, t)).clone();
        assert_eq!(to_a.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        let actions = deliver(&mut c, &answer(&to_a, msg::REPLY, lost()), t);
        assert_eq!(sent(&actions).msg_type, msg::REQUEST);

        // And a quiet server makes no other server quiet. The first
        // server leases the address and a prefix, the second another
        // prefix.
        let asks = Asks {
            ia_na: Some(IAID),
            ia_pd: vec![ask_pd(PD, 56), ask_pd(PD + 1, 56)],
        };
        let mut lease = kept_with_prefix();
        lease.ia_pd.push(IaPd {
            iaid: PD + 1,
            server_id: OTHER_DUID.to_vec(),
            t1: 1800,
            t2: 2880,
            prefixes: vec![prefix("2001:db8:200::/56", 3600, 7200)],
        });
        let (mut c, _) = holding_as(asks, lease);
        let (t, actions) = fire(&mut c);
        let [Action::Send(to_a), Action::Send(to_b)] = &actions[..] else {
            panic!("{actions:?}")
        };
        let (to_a, to_b) = (to_a.clone(), to_b.clone());
        // The first will not extend the address, has no record of its
        // prefix, and gives nothing back.
        let options = vec![
            ia_status(status::NO_ADDRS_AVAIL),
            ia_pd_status(PD, status::NO_BINDING),
        ];
        let request = sent(&deliver(&mut c, &answer(&to_a, msg::REPLY, options), t)).clone();
        let options = vec![
            ia_status(status::NO_ADDRS_AVAIL),
            ia_pd_status(PD, status::NO_PREFIX_AVAIL),
        ];
        deliver(&mut c, &answer(&request, msg::REPLY, options), t);
        // The second has no record of its own prefix: a Request, to it.
        let options = vec![ia_pd_status(PD + 1, status::NO_BINDING)];
        let reply = answer_from(&OTHER_DUID, &to_b, msg::REPLY, options);
        let actions = deliver(&mut c, &reply, t);
        assert_eq!(sent(&actions).msg_type, msg::REQUEST);
        assert_eq!(sent(&actions).option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
    }

    #[test]
    fn a_request_to_one_server_leaves_the_others_renews_under_way() {
        // The address and the prefix are to be renewed at the same time,
        // each with its own server.
        let both_due = || {
            let mut lease = mixed();
            (lease.ia_pd[0].t1, lease.ia_pd[0].t2) = (1800, 2880);
            lease
        };
        let (mut c, t0) = holding(both_due());
        let (t, actions) = fire(&mut c);
        assert_eq!(t, t0 + secs(1800));
        let [Action::Send(to_a), Action::Send(to_b)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(to_a.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(to_b.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        let (to_a, to_b) = (to_a.clone(), to_b.clone());
        // The address's server has no record of it: a Request, to it.
        let reply = answer(&to_a, msg::REPLY, vec![ia_status(status::NO_BINDING)]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Log(_), Action::Send(request)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(request.msg_type, msg::REQUEST);
        assert!(pds_of(request).is_empty());
        assert_eq!(c.state(), State::Requesting);
        let request = request.clone();
        // Meanwhile the prefix's server is asked on, at the Renew's pace.
        let (again, renew) = loop {
            let (now, actions) = fire(&mut c);
            let [Action::Send(message)] = &actions[..] else {
                panic!("{actions:?}")
            };
            if message.msg_type == msg::RENEW {
                break (now, message.clone());
            }
            assert_eq!(message.transaction_id, request.transaction_id);
        };
        assert_eq!(renew.transaction_id, to_b.transaction_id);
        let gap = again - t;
        assert!(gap >= secs(9) && gap <= secs(11), "{gap:?}");
        assert_eq!(c.state(), State::Requesting);
        // And its answer is taken: the prefix has its new lifetimes with
        // the Request still out.
        let reply = answer_from(&OTHER_DUID, &to_b, msg::REPLY, vec![one_prefix()]);
        let actions = deliver(&mut c, &reply, again);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
        assert_eq!(c.state(), State::Requesting);
        // The Request is answered: all of it is renewed.
        let reply = answer(&request, msg::REPLY, vec![one_address()]);
        let actions = deliver(&mut c, &reply, again);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS, 3600, 7200)]
        );
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
        assert_eq!(c.state(), State::Bound);

        // A Request nobody answers: the other server's Renew goes on
        // after it is given up.
        let (mut c, _) = holding(both_due());
        let (t, actions) = fire(&mut c);
        let to_a = sent(&actions).clone();
        let reply = answer(&to_a, msg::REPLY, vec![ia_status(status::NO_BINDING)]);
        deliver(&mut c, &reply, t);
        let actions = loop {
            let (_, actions) = fire(&mut c);
            if c.state() != State::Requesting {
                break actions;
            }
        };
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na, None);
        assert_eq!(lease.ia_pd.len(), 1);
        assert_eq!(c.state(), State::Renewing);
        let (_, actions) = fire(&mut c);
        assert_eq!(sent(&actions).msg_type, msg::RENEW);
        assert_eq!(sent(&actions).option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
    }

    #[test]
    fn a_request_has_no_say_about_what_another_server_gave_since() {
        let lost = || vec![status_option(status::NO_BINDING)];
        // From the Renew at T1 to the Rebind at T2, with the server's
        // Request out: returns the Request, the Rebind, and when.
        let to_rebind = |c: &mut Client| {
            let (t, renew) = first_renew(c);
            let request = sent(&deliver(c, &answer(&renew, msg::REPLY, lost()), t)).clone();
            assert_eq!(request.msg_type, msg::REQUEST);
            loop {
                let (now, actions) = fire(c);
                if sent(&actions).msg_type == msg::REBIND {
                    break (request, sent(&actions).clone(), now);
                }
            }
        };
        // The server has no record of the address. Before it answers the
        // Request, another server gives the address again, in answer to
        // the Rebind.
        let mut c = client(Options::default());
        acquire(&mut c, Instant::now(), ia(10, 20, &[(ADDRESS, 3600, 7200)]));
        let (request, rebind, t) = to_rebind(&mut c);
        let reply = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![one_address()]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na.as_ref().unwrap().server_id, OTHER_DUID);
        // The Request has nothing left to ask for: it is over, whatever
        // its server says now, and the lease is the other server's to
        // renew.
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t + secs(1800)));
        let refusal = vec![ia_status(status::NO_ADDRS_AVAIL)];
        assert!(deliver(&mut c, &answer(&request, msg::REPLY, refusal), t).is_empty());
        let (_, renew) = first_renew(&mut c);
        assert_eq!(renew.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        assert_eq!(addresses_of(&renew), [ADDRESS]);

        // No record of the address nor of the prefix, and the other
        // server gives the address alone: the Request goes on, for the
        // prefix.
        let both_lost_and = |c: &mut Client, given: Dhcp6Option| {
            let lease = vec![
                ia(10, 20, &[(ADDRESS, 3600, 7200)]),
                ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
            ];
            acquire_all(c, Instant::now(), lease);
            let (request, rebind, t) = to_rebind(c);
            let reply = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![given]);
            deliver(c, &reply, t);
            assert_eq!(c.state(), State::Requesting);
            (request, t)
        };
        let both_lost = |c: &mut Client| both_lost_and(c, one_address());
        // Refused: the prefix goes, and the address stays.
        let mut c = client_asking(both(), Options::default());
        let (request, t) = both_lost(&mut c);
        let refusal = vec![status_option(status::NO_ADDRS_AVAIL)];
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, refusal), t);
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(lease.ia_na.as_ref().unwrap().server_id, OTHER_DUID);
        assert_eq!(c.state(), State::Bound);
        // Never answered: likewise.
        let mut c = client_asking(both(), Options::default());
        both_lost(&mut c);
        let actions = loop {
            let (_, actions) = fire(&mut c);
            if c.state() != State::Requesting {
                break actions;
            }
        };
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(lease.ia_na.as_ref().unwrap().server_id, OTHER_DUID);
        assert_eq!(c.state(), State::Bound);
        // The other way about: the prefix given again, the address
        // refused.
        let mut c = client_asking(both(), Options::default());
        let (request, t) = both_lost_and(&mut c, one_prefix());
        let refusal = vec![status_option(status::NO_ADDRS_AVAIL)];
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, refusal), t);
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na, None);
        assert_eq!(lease.ia_pd[0].server_id, OTHER_DUID);

        // The server itself gives the address again, in answer to the
        // Rebind, with its Request still out for the prefix. The Request
        // is no longer about the address: it does not name it, and a
        // late answer to it that takes the address away is an answer to
        // a question from before.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 20, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
        ];
        acquire_all(&mut c, Instant::now(), lease);
        let (request, rebind, t) = to_rebind(&mut c);
        deliver(&mut c, &answer(&rebind, msg::REPLY, vec![one_address()]), t);
        assert_eq!(c.state(), State::Requesting);
        let again = loop {
            let (_, actions) = fire(&mut c);
            if sent(&actions).msg_type == msg::REQUEST {
                break sent(&actions).clone();
            }
        };
        assert_eq!(again.transaction_id, request.transaction_id);
        assert!(again.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(&again), [named(PD, DELEGATED)]);
        let late = vec![
            ia(0, 0, &[(ADDRESS, 0, 0)]),
            ia_pd_status(PD, status::NO_PREFIX_AVAIL),
        ];
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, late), t);
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS, 3600, 7200)]
        );
        assert_eq!(c.state(), State::Bound);

        // The other way about: the prefix given again by the server
        // itself, and taken away by a late answer to the Request.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 20, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
        ];
        acquire_all(&mut c, Instant::now(), lease);
        let (request, rebind, t) = to_rebind(&mut c);
        deliver(&mut c, &answer(&rebind, msg::REPLY, vec![one_prefix()]), t);
        let again = loop {
            let (_, actions) = fire(&mut c);
            if sent(&actions).msg_type == msg::REQUEST {
                break sent(&actions).clone();
            }
        };
        assert_eq!(addresses_of(&again), [ADDRESS]);
        assert!(pds_of(&again).is_empty());
        let late = vec![
            ia_status(status::NO_ADDRS_AVAIL),
            ia_pd(PD, 0, 0, &[(DELEGATED, 0, 0)]),
        ];
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, late), t);
        let [Action::Log(_), Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na, None);
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);

        // Two servers have no record of the address, and each is sent a
        // Request. What one gives, the other's refusal does not undo.
        const THIRD_DUID: [u8; 10] = [0, 3, 0, 1, 2, 0, 0, 0, 0, 0xfc];
        let mut c = client(Options::default());
        acquire(&mut c, Instant::now(), ia(10, 20, &[(ADDRESS, 3600, 7200)]));
        let (_, rebind, t) = to_rebind(&mut c);
        let no_record = |server: &[u8]| answer_from(server, &rebind, msg::REPLY, lost());
        let first = sent(&deliver(&mut c, &no_record(&OTHER_DUID), t)).clone();
        let second = sent(&deliver(&mut c, &no_record(&THIRD_DUID), t)).clone();
        assert_eq!(first.option(opt::SERVER_ID), Some(&OTHER_DUID[..]));
        assert_eq!(second.option(opt::SERVER_ID), Some(&THIRD_DUID[..]));
        let reply = answer_from(&THIRD_DUID, &second, msg::REPLY, vec![one_address()]);
        let actions = deliver(&mut c, &reply, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_na.as_ref().unwrap().server_id, THIRD_DUID);
        assert_eq!(c.state(), State::Bound);
        let refusal = vec![ia_status(status::NO_ADDRS_AVAIL)];
        let late = answer_from(&OTHER_DUID, &first, msg::REPLY, refusal);
        assert!(deliver(&mut c, &late, t).is_empty());
        assert!(c.lease(t).is_some());
    }

    #[test]
    fn a_rebind_has_no_say_about_what_is_not_past_its_t2() {
        // The address and the prefix are both past T2. The server has no
        // record of the address and will not extend the prefix: a Request
        // to it, and a Rebind about both.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 20, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
        ];
        acquire_all(&mut c, Instant::now(), lease);
        let (t, renew) = first_renew(&mut c);
        let lost = vec![
            ia_status(status::NO_BINDING),
            ia_pd_status(PD, status::NO_PREFIX_AVAIL),
        ];
        let request = sent(&deliver(&mut c, &answer(&renew, msg::REPLY, lost), t)).clone();
        let (rebind, t) = loop {
            let (now, actions) = fire(&mut c);
            if sent(&actions).msg_type == msg::REBIND {
                break (sent(&actions).clone(), now);
            }
        };
        assert_eq!(addresses_of(&rebind), [ADDRESS]);
        assert_eq!(pds_of(&rebind), [named(PD, DELEGATED)]);
        // The Request gives the address again. The Rebind goes on, for
        // the prefix.
        let back = vec![one_address(), ia_pd_status(PD, status::NO_PREFIX_AVAIL)];
        deliver(&mut c, &answer(&request, msg::REPLY, back), t);
        assert_eq!(c.state(), State::Rebinding);
        // A late answer to the Rebind, from when it asked about the
        // address too, takes the address away: it is no longer what the
        // Rebind is about.
        let gone = || ia(0, 0, &[(ADDRESS, 0, 0)]);
        let late = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![gone()]);
        let actions = deliver(&mut c, &late, t);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        assert_eq!(held_addresses(&c, t), [address(ADDRESS, 3600, 7200)]);
        // What such an answer says of the prefix is taken.
        let late = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![gone(), one_prefix()]);
        let actions = deliver(&mut c, &late, t);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        let ia_na = lease.ia_na.as_ref().unwrap();
        assert_eq!(ia_na.addresses, [address(ADDRESS, 3600, 7200)]);
        assert_eq!(ia_na.server_id, SERVER_DUID);
        assert_eq!(lease.ia_pd[0].server_id, OTHER_DUID);
        assert_eq!(c.state(), State::Bound);

        // And the Rebind, sent again, no longer asks about the address.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 20, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
        ];
        acquire_all(&mut c, Instant::now(), lease);
        let (t, renew) = first_renew(&mut c);
        let lost = vec![
            ia_status(status::NO_BINDING),
            ia_pd_status(PD, status::NO_PREFIX_AVAIL),
        ];
        let request = sent(&deliver(&mut c, &answer(&renew, msg::REPLY, lost), t)).clone();
        let (rebind, t) = loop {
            let (now, actions) = fire(&mut c);
            if sent(&actions).msg_type == msg::REBIND {
                break (sent(&actions).clone(), now);
            }
        };
        let back = vec![one_address(), ia_pd_status(PD, status::NO_PREFIX_AVAIL)];
        deliver(&mut c, &answer(&request, msg::REPLY, back), t);
        let (_, actions) = fire(&mut c);
        let again = sent(&actions);
        assert_eq!(again.transaction_id, rebind.transaction_id);
        assert!(again.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(again), [named(PD, DELEGATED)]);
    }

    /// One server leases both. The prefix is past its T2 while the
    /// address has long to go, and nobody answers the Renew: returns the
    /// Renew, the Rebind that goes out for the prefix beside it, and when
    /// (with when the lease's times count from).
    fn renew_beside_rebind(c: &mut Client) -> (ClientMessage, ClientMessage, Instant, Instant) {
        let lease = vec![
            ia(10, 1000, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
        ];
        let (t0, _) = acquire_all(c, Instant::now(), lease);
        let (_, renew) = first_renew(c);
        let (t, rebind) = loop {
            let (now, actions) = fire(c);
            if sent(&actions).msg_type == msg::REBIND {
                break (now, sent(&actions).clone());
            }
        };
        assert_eq!(t, t0 + secs(20));
        assert!(rebind.option(opt::IA_NA).is_none());
        (renew, rebind, t, t0)
    }

    #[test]
    fn a_renew_is_over_when_all_it_still_asks_about_is_answered() {
        // The Rebind is answered: the prefix is renewed. The Renew is
        // still out, for the address, and no longer asks about the
        // prefix.
        let mut c = client_asking(both(), Options::default());
        let (renew, rebind, t, _) = renew_beside_rebind(&mut c);
        let actions = deliver(&mut c, &answer(&rebind, msg::REPLY, vec![one_prefix()]), t);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Renewing);
        let (now, actions) = fire(&mut c);
        let again = sent(&actions).clone();
        assert_eq!(again.transaction_id, renew.transaction_id);
        assert_eq!(addresses_of(&again), [ADDRESS]);
        assert!(pds_of(&again).is_empty());
        // Answered for the address, it is over: the prefix was not its
        // to wait for any more.
        let actions = deliver(
            &mut c,
            &answer(&again, msg::REPLY, vec![one_address()]),
            now,
        );
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);

        // The prefix comes to its T1 again with that Renew still out: a
        // new Renew asks about both.
        let mut c = client_asking(both(), Options::default());
        let (renew, rebind, t, t0) = renew_beside_rebind(&mut c);
        let soon = ia_pd(PD, 30, 5000, &[(DELEGATED, 3600, 7200)]);
        deliver(&mut c, &answer(&rebind, msg::REPLY, vec![soon]), t);
        let (at, anew) = loop {
            let (now, actions) = fire(&mut c);
            let [Action::Send(message)] = &actions[..] else {
                panic!("{actions:?}")
            };
            assert_eq!(message.msg_type, msg::RENEW);
            if message.transaction_id != renew.transaction_id {
                break (now, message.clone());
            }
            assert!(pds_of(message).is_empty());
        };
        assert_eq!(at, t0 + secs(20 + 30));
        assert_eq!(addresses_of(&anew), [ADDRESS]);
        assert_eq!(pds_of(&anew), [named(PD, DELEGATED)]);
        // The old one is over.
        let late = answer(&renew, msg::REPLY, vec![one_address()]);
        assert!(deliver(&mut c, &late, at).is_empty());
    }

    #[test]
    fn no_binding_to_a_rebind_brings_a_request_though_a_renew_is_out() {
        // The server answers the Rebind: it has no record of the prefix.
        // Its Renew, out for the address, does not hold the Request back.
        let mut c = client_asking(both(), Options::default());
        let (renew, rebind, t, _) = renew_beside_rebind(&mut c);
        let lost = vec![ia_pd_status(PD, status::NO_BINDING)];
        let actions = deliver(&mut c, &answer(&rebind, msg::REPLY, lost), t);
        let [Action::Log(_), Action::Send(request)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(request.msg_type, msg::REQUEST);
        assert_eq!(request.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(request), [ADDRESS]);
        assert_eq!(pds_of(request), [named(PD, DELEGATED)]);
        assert_eq!(c.state(), State::Requesting);
        // The Request asks about all that server leases: the Renew is
        // over, and an answer to it comes too late.
        for _ in 0..6 {
            let (_, actions) = fire(&mut c);
            assert_ne!(sent(&actions).msg_type, msg::RENEW);
        }
        let late = answer(&renew, msg::REPLY, vec![one_address()]);
        assert!(deliver(&mut c, &late, t).is_empty());
    }

    #[test]
    fn what_a_request_leaves_out_is_renewed_beside_it() {
        // The server has no record of the address nor of the prefix: a
        // Request to it, and at T2 a Rebind beside it.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 20, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
        ];
        acquire_all(&mut c, Instant::now(), lease);
        let (t, renew) = first_renew(&mut c);
        let lost = vec![status_option(status::NO_BINDING)];
        let request = sent(&deliver(&mut c, &answer(&renew, msg::REPLY, lost), t)).clone();
        let (rebind, t) = loop {
            let (now, actions) = fire(&mut c);
            if sent(&actions).msg_type == msg::REBIND {
                break (sent(&actions).clone(), now);
            }
        };
        // The Rebind brings the address back, to be renewed in 5 s. The
        // Request goes on, for the prefix, and leaves the address out.
        let soon = ia(5, 40, &[(ADDRESS, 3600, 7200)]);
        deliver(&mut c, &answer(&rebind, msg::REPLY, vec![soon]), t);
        assert_eq!(c.state(), State::Requesting);
        // At the address's T1 it is renewed, with the Request still out:
        // a Renew to the same server, about the address alone.
        let (at, renew) = loop {
            let (now, actions) = fire(&mut c);
            let [Action::Send(message)] = &actions[..] else {
                panic!("{actions:?}")
            };
            if message.msg_type == msg::RENEW {
                break (now, message.clone());
            }
            assert!(now < t + secs(5));
        };
        assert_eq!(at, t + secs(5));
        assert_eq!(renew.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(&renew), [ADDRESS]);
        assert!(pds_of(&renew).is_empty());
        assert_eq!(c.state(), State::Requesting);
        // The server has no record of what the Rebind gave either: one
        // Request asks it for both, in the place of the one that was out
        // for the other. Tried with the address given and then lost, and
        // with the prefix.
        for address_first in [true, false] {
            let mut d = client_asking(both(), Options::default());
            let lease = vec![
                ia(10, 20, &[(ADDRESS, 3600, 7200)]),
                ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
            ];
            acquire_all(&mut d, Instant::now(), lease);
            let (t, first) = first_renew(&mut d);
            let lost = vec![status_option(status::NO_BINDING)];
            let old = sent(&deliver(&mut d, &answer(&first, msg::REPLY, lost), t)).clone();
            let (rebind, t) = loop {
                let (now, actions) = fire(&mut d);
                if sent(&actions).msg_type == msg::REBIND {
                    break (sent(&actions).clone(), now);
                }
            };
            let (soon, lost) = if address_first {
                (
                    ia(5, 40, &[(ADDRESS, 3600, 7200)]),
                    ia_status(status::NO_BINDING),
                )
            } else {
                (
                    ia_pd(PD, 5, 40, &[(DELEGATED, 3600, 7200)]),
                    ia_pd_status(PD, status::NO_BINDING),
                )
            };
            deliver(&mut d, &answer(&rebind, msg::REPLY, vec![soon]), t);
            let again = loop {
                let (_, actions) = fire(&mut d);
                if sent(&actions).msg_type == msg::RENEW {
                    break sent(&actions).clone();
                }
            };
            // (The Request is sent again meanwhile.)
            let now = loop {
                let (now, actions) = fire(&mut d);
                if sent(&actions).msg_type == msg::REQUEST {
                    assert_eq!(sent(&actions).transaction_id, old.transaction_id);
                    break now;
                }
            };
            // The Rebind, still out for the other, is told once more that
            // the server has no record of that: the Request is out for
            // it already, and that brings no other.
            let known = if address_first {
                ia_pd_status(PD, status::NO_BINDING)
            } else {
                ia_status(status::NO_BINDING)
            };
            let actions = deliver(&mut d, &answer(&rebind, msg::REPLY, vec![known]), now);
            assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
            let actions = deliver(&mut d, &answer(&again, msg::REPLY, vec![lost]), now);
            let [Action::Log(_), Action::Send(both)] = &actions[..] else {
                panic!("{actions:?}")
            };
            assert_eq!(both.msg_type, msg::REQUEST);
            assert_ne!(both.transaction_id, old.transaction_id);
            assert_eq!(addresses_of(both), [ADDRESS]);
            assert_eq!(pds_of(both), [named(PD, DELEGATED)]);
            assert_eq!(d.state(), State::Requesting);
            // The old Request is over, and so is the Renew.
            let both = both.clone();
            let late = answer(&old, msg::REPLY, vec![one_address(), one_prefix()]);
            assert!(deliver(&mut d, &late, now).is_empty());
            for _ in 0..6 {
                let (_, actions) = fire(&mut d);
                let message = sent(&actions);
                assert_ne!(message.msg_type, msg::RENEW);
                if message.msg_type == msg::REQUEST {
                    assert_eq!(message.transaction_id, both.transaction_id);
                }
            }
            // It is out for both: what it does not give again goes.
            let back = if address_first {
                vec![one_address(), ia_pd_status(PD, status::NO_PREFIX_AVAIL)]
            } else {
                vec![ia_status(status::NO_ADDRS_AVAIL), one_prefix()]
            };
            let actions = deliver(&mut d, &answer(&both, msg::REPLY, back), now);
            let [Action::Bind { lease, fresh: true }] = &actions[..] else {
                panic!("{actions:?}")
            };
            assert_eq!(lease.ia_na.is_some(), address_first);
            assert_eq!(lease.ia_pd.is_empty(), address_first);
            assert_eq!(d.state(), State::Bound);
        }

        // Each is answered by itself.
        let actions = deliver(&mut c, &answer(&renew, msg::REPLY, vec![one_address()]), at);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Requesting);
        let back = vec![one_prefix()];
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, back), at);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(
            lease.ia_na.as_ref().unwrap().addresses,
            [address(ADDRESS, 3600, 7200)]
        );
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
        assert_eq!(c.state(), State::Bound);
    }

    #[test]
    fn one_servers_t1_leaves_another_servers_renew_as_it_is() {
        // The address and the prefix are to be renewed at once, each with
        // its server.
        let mut lease = mixed();
        (lease.ia_pd[0].t1, lease.ia_pd[0].t2) = (1800, 2880);
        let (mut c, _) = holding(lease);
        let (t, actions) = fire(&mut c);
        let [Action::Send(to_a), Action::Send(to_b)] = &actions[..] else {
            panic!("{actions:?}")
        };
        let (to_a, to_b) = (to_a.clone(), to_b.clone());
        // The address's server answers, and wants it renewed again in
        // 5 s. The prefix's server has not answered yet.
        let soon = ia(5, 4000, &[(ADDRESS, 3600, 7200)]);
        deliver(&mut c, &answer(&to_a, msg::REPLY, vec![soon]), t);
        let (at, actions) = fire(&mut c);
        assert_eq!(at, t + secs(5));
        let [Action::Send(again)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(again.msg_type, msg::RENEW);
        assert_eq!(again.option(opt::SERVER_ID), Some(&SERVER_DUID[..]));
        assert_eq!(addresses_of(again), [ADDRESS]);
        assert_ne!(again.transaction_id, to_a.transaction_id);
        // The prefix's Renew is the one that went out: its answer is
        // taken.
        let reply = answer_from(&OTHER_DUID, &to_b, msg::REPLY, vec![one_prefix()]);
        let actions = deliver(&mut c, &reply, at);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
        assert_eq!(c.state(), State::Renewing);
    }

    #[test]
    fn a_request_names_what_is_held_when_it_is_sent() {
        let mut c = client(Options::default());
        let two = ia(10, 1000, &[(ADDRESS, 30, 35), (ADDRESS2, 3600, 7200)]);
        let t0 = acquire(&mut c, Instant::now(), two);
        let (t, renew) = first_renew(&mut c);
        let reply = answer(&renew, msg::REPLY, vec![ia_status(status::NO_BINDING)]);
        let request = sent(&deliver(&mut c, &reply, t)).clone();
        assert_eq!(addresses_of(&request), [ADDRESS, ADDRESS2]);
        // One address runs out with the Request still out: it is not
        // asked for again.
        let again = loop {
            let (now, actions) = fire(&mut c);
            if now > t0 + secs(35) {
                break sent(&actions).clone();
            }
        };
        assert_eq!(again.msg_type, msg::REQUEST);
        assert_eq!(again.transaction_id, request.transaction_id);
        assert_eq!(addresses_of(&again), [ADDRESS2]);
    }

    #[test]
    fn what_one_server_answers_moves_no_other_servers_times() {
        // The address is to be renewed first; the prefix is another
        // server's.
        let address_first = || {
            let mut lease = mixed();
            lease.ia_na.as_mut().unwrap().t1 = 100;
            (lease.ia_pd[0].t1, lease.ia_pd[0].t2) = (3000, 3200);
            lease
        };
        let left = |c: &Client, at: Instant| {
            let lease = c.lease(at).unwrap();
            let prefix = &lease.ia_pd[0].prefixes[0];
            (prefix.preferred, prefix.valid)
        };
        // A Renew answered a moment after a whole second.
        let (mut c, t0) = holding(address_first());
        first_renew(&mut c);
        let (t, actions) = fire(&mut c);
        assert!((t - t0).subsec_millis() > 0);
        let again = sent(&actions).clone();
        deliver(&mut c, &answer(&again, msg::REPLY, vec![one_address()]), t);
        assert_eq!(c.state(), State::Bound);
        assert_eq!(left(&c, t0 + secs(200)), (3400, 7000));

        // So for the Request after NoBinding.
        let (mut c, t0) = holding(address_first());
        let (t, renew) = first_renew(&mut c);
        let reply = answer(&renew, msg::REPLY, vec![ia_status(status::NO_BINDING)]);
        deliver(&mut c, &reply, t);
        let (t, actions) = fire(&mut c);
        assert!((t - t0).subsec_millis() > 0);
        let request = sent(&actions).clone();
        assert_eq!(request.msg_type, msg::REQUEST);
        deliver(
            &mut c,
            &answer(&request, msg::REPLY, vec![one_address()]),
            t,
        );
        assert_eq!(c.state(), State::Bound);
        assert_eq!(left(&c, t0 + secs(200)), (3400, 7000));
    }

    #[test]
    fn a_rebind_goes_out_at_t2_beside_a_request() {
        // The address is one server's. The prefix is another's, to be
        // rebound at 150 s and gone at 180 s.
        let two_servers = || {
            let mut lease = mixed();
            lease.ia_na.as_mut().unwrap().t1 = 100;
            (lease.ia_pd[0].t1, lease.ia_pd[0].t2) = (100, 150);
            lease.ia_pd[0].prefixes = vec![prefix(DELEGATED, 170, 180)];
            lease
        };
        // The address's server has no record of it, and does not answer
        // the Request; the prefix's server does not answer its Renew.
        let recovering = |c: &mut Client| {
            let (t, actions) = fire(c);
            let [Action::Send(to_a), Action::Send(to_b)] = &actions[..] else {
                panic!("{actions:?}")
            };
            let to_b = to_b.clone();
            let reply = answer(to_a, msg::REPLY, vec![ia_status(status::NO_BINDING)]);
            let request = sent(&deliver(c, &reply, t)).clone();
            assert_eq!(request.msg_type, msg::REQUEST);
            (request, to_b)
        };
        // Until T2 the Request and the Renew are sent, each at its pace.
        // At T2 a Rebind takes the Renew's place, for any server and
        // about all of the lease, with the Request still out.
        let to_t2 = |c: &mut Client, request: &ClientMessage, to_b: &ClientMessage| loop {
            let (now, actions) = fire(c);
            let [Action::Send(message)] = &actions[..] else {
                panic!("{actions:?}")
            };
            if message.msg_type == msg::REBIND {
                break (now, message.clone());
            }
            let xid = message.transaction_id;
            assert!(xid == request.transaction_id || xid == to_b.transaction_id);
        };
        let (mut c, t0) = holding(two_servers());
        let (request, to_b) = recovering(&mut c);
        let (at, rebind) = to_t2(&mut c, &request, &to_b);
        assert_eq!(at, t0 + secs(150));
        assert!(rebind.option(opt::SERVER_ID).is_none());
        assert!(rebind.option(opt::IA_NA).is_none());
        assert_eq!(pds_of(&rebind), [named(PD, DELEGATED)]);
        assert_eq!(c.state(), State::Requesting);
        // A server extends the prefix: nothing is past its T2 any more,
        // and the Rebind is over. The Request goes on.
        let reply = answer_from(&OTHER_DUID, &rebind, msg::REPLY, vec![one_prefix()]);
        let actions = deliver(&mut c, &reply, at);
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.ia_pd[0].prefixes, [prefix(DELEGATED, 3600, 7200)]);
        assert_eq!(c.state(), State::Requesting);
        for _ in 0..3 {
            let (_, actions) = fire(&mut c);
            if c.state() != State::Requesting {
                break;
            }
            let [Action::Send(message)] = &actions[..] else {
                panic!("{actions:?}")
            };
            assert_eq!(message.transaction_id, request.transaction_id);
        }

        // Nobody answers the Rebind either: it is sent until the prefix
        // runs out, and is over then.
        let (mut c, t0) = holding(two_servers());
        let (request, to_b) = recovering(&mut c);
        let (_, rebind) = to_t2(&mut c, &request, &to_b);
        let mut rebinds = 1;
        let actions = loop {
            let (now, actions) = fire(&mut c);
            if now == t0 + secs(180) {
                break actions;
            }
            let xid = sent(&actions).transaction_id;
            assert!(xid == request.transaction_id || xid == rebind.transaction_id);
            rebinds += usize::from(xid == rebind.transaction_id);
        };
        assert!(rebinds >= 2, "{rebinds}");
        let [Action::Bind { lease, fresh: true }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert!(lease.ia_pd.is_empty());
        assert_eq!(c.state(), State::Requesting);
        let (_, actions) = fire(&mut c);
        assert_eq!(sent(&actions).transaction_id, request.transaction_id);

        // One server, and T2 comes with its Request out. The Rebind goes
        // out beside it. NoBinding again, to the Rebind, brings no second
        // Request.
        let mut c = client(Options::default());
        let t0 = acquire(&mut c, Instant::now(), ia(10, 20, &[(ADDRESS, 3600, 7200)]));
        let (t, renew) = first_renew(&mut c);
        let lost = || vec![ia_status(status::NO_BINDING)];
        let request = sent(&deliver(&mut c, &answer(&renew, msg::REPLY, lost()), t)).clone();
        let (at, rebind) = to_t2(&mut c, &request, &request);
        assert_eq!(at, t0 + secs(20));
        let actions = deliver(&mut c, &answer(&rebind, msg::REPLY, lost()), at);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        // The Request is sent as often as a Request is, then given up:
        // nothing is left.
        let mut asked = 0;
        let actions = loop {
            let (_, actions) = fire(&mut c);
            if c.state() != State::Requesting {
                break actions;
            }
            let [Action::Send(message)] = &actions[..] else {
                panic!("{actions:?}")
            };
            asked += u32::from(message.msg_type == msg::REQUEST);
        };
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Unbind]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Soliciting);
        // Counted from T2 on: the Request had gone out a few times before.
        assert!((4..REQ_MAX_RC).contains(&asked), "{asked}");

        // The Request answered after T2, with something still past it:
        // the Rebind that is under way goes on.
        let mut c = client_asking(both(), Options::default());
        let lease = vec![
            ia(10, 20, &[(ADDRESS, 3600, 7200)]),
            ia_pd(PD, 10, 20, &[(DELEGATED, 3600, 7200)]),
        ];
        acquire_all(&mut c, Instant::now(), lease);
        let (t, renew) = first_renew(&mut c);
        let lost = vec![
            ia_status(status::NO_BINDING),
            ia_pd_status(PD, status::NO_PREFIX_AVAIL),
        ];
        let request = sent(&deliver(&mut c, &answer(&renew, msg::REPLY, lost), t)).clone();
        let (at, rebind) = to_t2(&mut c, &request, &request);
        let back = vec![one_address(), ia_pd_status(PD, status::NO_PREFIX_AVAIL)];
        let actions = deliver(&mut c, &answer(&request, msg::REPLY, back), at);
        assert!(
            matches!(&actions[..], [Action::Bind { fresh: true, .. }]),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Rebinding);
        let (_, actions) = fire(&mut c);
        assert_eq!(sent(&actions).transaction_id, rebind.transaction_id);
    }

    #[test]
    fn a_delegated_prefix_keeps_its_shape_on_disk() {
        let json = serde_json::to_value(kept_with_prefix()).unwrap();
        assert_eq!(
            json["ia_pd"],
            serde_json::json!([{
                "iaid": 7,
                "server_id": [0, 3, 0, 1, 2, 0, 0, 0, 0, 254],
                "t1": 1800,
                "t2": 2880,
                "prefixes": [
                    {"prefix": "2001:db8:100::/56", "preferred": 3600, "valid": 7200}
                ],
            }])
        );
        let back: Lease = serde_json::from_value(json).unwrap();
        assert_eq!(back, kept_with_prefix());
        // A lease written before prefixes were held has no such key, and
        // reads as a lease without any.
        let old = serde_json::to_value(kept()).unwrap();
        assert!(old.get("ia_pd").is_none());
        let back: Lease = serde_json::from_value(old).unwrap();
        assert_eq!(back, kept());
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
                    "server_id": [0, 3, 0, 1, 2, 0, 0, 0, 0, 254],
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
