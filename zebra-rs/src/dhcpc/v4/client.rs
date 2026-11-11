//! The DHCPv4 client state machine (RFC 2131 §4.4), without I/O.
//!
//! [`Client::handle`] takes an [`Event`] and the current time and returns
//! [`Action`]s for the task to carry out: packets to send, an address to
//! probe, a lease to apply or withdraw. Nothing here opens a socket, reads
//! a clock or touches the RIB, so every timer and transition is tested
//! with a scripted server and a clock the test moves.
//!
//! States, with what the task must have open in each
//! ([`Client::wants_packet_socket`], [`Client::wants_udp_socket`]):
//!
//! | State | Meaning | Socket |
//! |---|---|---|
//! | `Stopped` | not started, or no carrier and no lease | – |
//! | `Selecting` | DISCOVER sent, waiting for an OFFER | packet |
//! | `Requesting` | REQUEST sent for an offer | packet |
//! | `Probing` | ACK received, checking the address is free (ARP) | packet |
//! | `Bound` | lease held, waiting for T1 | UDP |
//! | `Renewing` | REQUEST unicast to the server, T1..T2 | UDP |
//! | `Rebinding` | REQUEST broadcast, T2..expiry | UDP |
//! | `Rebooting` | verifying a lease kept across a restart or a carrier loss | both |
//! | `Backoff` | waiting after a NAK or a DECLINE before starting over | – |
//! | `Released` | the operator released the lease; waits for `renew` | – |

use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use dhcp_packet::v4::params::{INFINITE, Params};
use dhcp_packet::v4::{BOOTREPLY, DhcpOption, Packet, msg, opt};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

/// `interface <if> ipv4 dhcp-options …`, as far as the protocol goes.
/// The route options (distance, `no-default-route`) belong to the task.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Option 61; none sent when unset, so the server keys on `chaddr`.
    pub client_id: Option<Vec<u8>>,
    /// Option 12.
    pub host_name: Option<String>,
    /// Option 60.
    pub vendor_class_id: Option<String>,
    /// Option 77, one RFC 3004 class.
    pub user_class: Option<String>,
    /// Servers whose offers are ignored.
    pub reject: Vec<Ipv4Net>,
    /// Ask for option 26 and keep it in the lease.
    pub request_mtu: bool,
}

/// What the server granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub server_id: Ipv4Addr,
    pub broadcast: Option<Ipv4Addr>,
    /// Option 3, ignored for routing when `classless_routes` is not empty
    /// (RFC 3442).
    pub routers: Vec<Ipv4Addr>,
    /// Option 121: destination and router; router `0.0.0.0` is on-link.
    pub classless_routes: Vec<(Ipv4Net, Ipv4Addr)>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub domain_search: Vec<String>,
    pub ntp_servers: Vec<Ipv4Addr>,
    pub mtu: Option<u16>,
    /// Seconds; [`INFINITE`] never expires.
    pub lease_time: u32,
    pub t1: u32,
    pub t2: u32,
}

impl Lease {
    pub fn net(&self) -> Ipv4Net {
        Ipv4Net::new(self.address, self.prefix_len).unwrap_or_else(|_| Ipv4Net::from(self.address))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Stopped,
    Selecting,
    Requesting,
    Probing,
    Bound,
    Renewing,
    Rebinding,
    Rebooting,
    Backoff,
    Released,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            State::Stopped => "stopped",
            State::Selecting => "selecting",
            State::Requesting => "requesting",
            State::Probing => "probing",
            State::Bound => "bound",
            State::Renewing => "renewing",
            State::Rebinding => "rebinding",
            State::Rebooting => "rebooting",
            State::Backoff => "backoff",
            State::Released => "released",
        })
    }
}

#[derive(Debug)]
pub enum Event<'a> {
    /// The interface can carry packets (or no longer can).
    Carrier(bool),
    /// A lease read back from disk at start: `elapsed` seconds of it are
    /// already gone. Comes before the first `Carrier(true)`.
    Resume { lease: Lease, elapsed: u32 },
    /// A BOOTREPLY for this interface, and who sent it.
    Packet {
        packet: &'a Packet,
        source: Ipv4Addr,
    },
    /// [`Client::deadline`] has passed.
    Timeout,
    /// Someone else answered for the address being probed.
    ArpConflict,
    /// The kernel no longer has the leased address (it expired there, or
    /// somebody removed it).
    AddressLost,
    /// `renew dhcp interface <if>`.
    Renew,
    /// `release dhcp interface <if>`.
    Release,
    /// The configuration is gone: release and stop for good.
    Stop,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Broadcast from `0.0.0.0` through the packet socket.
    Broadcast(Packet),
    /// Send through the UDP socket, from the leased address (the packet's
    /// `ciaddr`): to the server, or to `255.255.255.255` when rebinding.
    Send(Ipv4Addr, Packet),
    /// ARP-probe the address before using it.
    Probe(Ipv4Addr),
    /// The lease is good for `remaining` more seconds: install or refresh
    /// the address and what hangs off it. `fresh` says the server has just
    /// confirmed it (write it to disk); otherwise it is a lease resumed
    /// from disk.
    Bind {
        lease: Lease,
        remaining: u32,
        fresh: bool,
    },
    /// The lease is gone: withdraw everything and forget it.
    Unbind,
    Log(String),
}

/// RFC 2131 §4.1: retransmit after 4 s, doubling up to 64 s.
const RETRANSMIT_FIRST: u64 = 4;
const RETRANSMIT_MAX: u64 = 64;
/// REQUESTs for an offer before going back to DISCOVER.
const REQUEST_TRIES: u32 = 4;
/// REQUESTs to verify a kept lease before using it unverified (§3.2).
const REBOOT_TRIES: u32 = 2;
/// §4.4.5: no retransmission in RENEWING / REBINDING sooner than this.
const RENEW_MIN: Duration = Duration::from_secs(60);
/// §3.1: wait this long after a DECLINE.
const DECLINE_WAIT: Duration = Duration::from_secs(10);
/// ARP probes for a new address, and the gap between them.
const PROBES: u32 = 2;
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// How far ahead of our expiry timer the kernel may drop the address.
const EXPIRY_SLACK: Duration = Duration::from_secs(3);
/// The backoff after a NAK starts here and doubles up to `RETRANSMIT_MAX`.
const NAK_BACKOFF_FIRST: u64 = 1;

pub struct Client {
    mac: [u8; 6],
    options: Options,
    /// The interface MTU, sent as the maximum message size.
    mtu: u16,
    state: State,
    carrier: bool,
    xid: u32,
    /// When this acquisition began, for the `secs` field.
    started: Instant,
    /// Transmissions made in the current state.
    tries: u32,
    deadline: Option<Instant>,
    /// When the REQUEST the lease answers was sent: lease times count
    /// from here (§4.4.1).
    request_sent: Instant,
    /// The offer being requested.
    offer: Option<(Ipv4Addr, Ipv4Addr)>,
    /// A granted lease not yet in use (being probed).
    pending: Option<Lease>,
    lease: Option<Lease>,
    /// Absolute lease timers; `None` for an infinite lease.
    timers: Option<Timers>,
    nak_backoff: u64,
    /// Entropy for transaction ids and retransmission jitter.
    random: Box<dyn FnMut() -> u32 + Send>,
}

#[derive(Debug, Clone, Copy)]
struct Timers {
    t1: Instant,
    t2: Instant,
    expiry: Instant,
}

impl Client {
    pub fn new(
        mac: [u8; 6],
        mtu: u32,
        options: Options,
        now: Instant,
        random: Box<dyn FnMut() -> u32 + Send>,
    ) -> Client {
        Client {
            mac,
            options,
            mtu: mtu.clamp(576, u32::from(u16::MAX)) as u16,
            state: State::Stopped,
            carrier: false,
            xid: 0,
            started: now,
            tries: 0,
            deadline: None,
            request_sent: now,
            offer: None,
            pending: None,
            lease: None,
            timers: None,
            nak_backoff: NAK_BACKOFF_FIRST,
            random,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    #[cfg(test)]
    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    /// The address being probed for conflicts, while that is going on.
    pub fn probing(&self) -> Option<Ipv4Addr> {
        match self.state {
            State::Probing => self.pending.as_ref().map(|lease| lease.address),
            _ => None,
        }
    }

    /// When to deliver [`Event::Timeout`].
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Seconds until T1, T2 and expiry; `None` without a lease or when it
    /// never expires.
    pub fn remaining(&self, now: Instant) -> Option<(u32, u32, u32)> {
        let secs = |at: Instant| at.saturating_duration_since(now).as_secs() as u32;
        self.timers
            .map(|t| (secs(t.t1), secs(t.t2), secs(t.expiry)))
    }

    /// Whether the packet socket must be open: the states that send from,
    /// or are answered at, an address the interface does not have yet.
    pub fn wants_packet_socket(&self) -> bool {
        matches!(
            self.state,
            State::Selecting | State::Requesting | State::Probing | State::Rebooting
        )
    }

    /// Whether the UDP socket must be open: whenever a lease is held.
    pub fn wants_udp_socket(&self) -> bool {
        self.lease.is_some()
    }

    /// Who the client is to a server: the hardware address, and the
    /// client identifier when one is configured.
    ///
    /// It is fixed for the life of a `Client`. RFC 2131 §4.2 has a client
    /// use the same identifier in every message about a lease: a RENEW
    /// under another one is another client asking, and a RELEASE under
    /// another one leaves the lease allocated. So [`Client::set_options`]
    /// does not touch the identifier, and nothing changes the hardware
    /// address. When the configuration or the link gives the interface
    /// another identity, the task stops this client, which releases the
    /// lease as who took it, and starts a new one.
    pub fn identity(&self) -> ([u8; 6], Option<&[u8]>) {
        (self.mac, self.options.client_id.as_deref())
    }

    /// New options take effect at the next message. The client identifier
    /// is not one of them: see [`Client::identity`].
    pub fn set_options(&mut self, mut options: Options) {
        options.client_id = self.options.client_id.take();
        self.options = options;
    }

    /// The interface MTU, sent as the maximum message size.
    pub fn set_mtu(&mut self, mtu: u32) {
        self.mtu = mtu.clamp(576, u32::from(u16::MAX)) as u16;
    }

    pub fn handle(&mut self, event: Event<'_>, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match event {
            Event::Carrier(up) => self.on_carrier(up, now, &mut out),
            Event::Resume { lease, elapsed } => self.on_resume(lease, elapsed, now, &mut out),
            Event::Packet { packet, source } => self.on_packet(packet, source, now, &mut out),
            Event::Timeout => self.on_timeout(now, &mut out),
            Event::ArpConflict => self.on_conflict(now, &mut out),
            Event::AddressLost => {
                if self.lease.is_some() {
                    // The kernel counts the address's lifetime in whole
                    // seconds and can drop it just ahead of our own
                    // expiry timer: that is the lease running out, not
                    // somebody removing the address.
                    let expired = self.timers.is_some_and(|t| now + EXPIRY_SLACK >= t.expiry);
                    out.push(Action::Log(if expired {
                        "lease expired".into()
                    } else {
                        "the leased address left the interface".into()
                    }));
                    self.unbind(&mut out);
                    self.restart(now, &mut out);
                }
            }
            Event::Renew => self.on_renew(now, &mut out),
            Event::Release => {
                self.release(&mut out, now);
                self.state = State::Released;
                self.deadline = None;
            }
            Event::Stop => {
                self.release(&mut out, now);
                self.state = State::Stopped;
                self.deadline = None;
            }
        }
        out
    }

    fn on_carrier(&mut self, up: bool, now: Instant, out: &mut Vec<Action>) {
        if self.carrier == up {
            return;
        }
        self.carrier = up;
        if !up {
            // A held lease stays, with its timers; an acquisition under
            // way cannot go on.
            if self.lease.is_none() && self.state != State::Released {
                self.state = State::Stopped;
                self.deadline = None;
                self.pending = None;
                self.offer = None;
            }
            return;
        }
        match self.state {
            State::Released => {}
            _ if self.lease.is_some() => self.reboot(now, out),
            _ => self.discover(now, out),
        }
    }

    fn on_resume(&mut self, lease: Lease, elapsed: u32, now: Instant, out: &mut Vec<Action>) {
        if self.lease.is_some() || self.state != State::Stopped {
            return;
        }
        let remaining = if lease.lease_time == INFINITE {
            INFINITE
        } else {
            match lease.lease_time.checked_sub(elapsed) {
                Some(left) if left > 0 => left,
                // Expired while we were away.
                _ => return,
            }
        };
        self.timers = (lease.lease_time != INFINITE).then(|| {
            let left =
                |total: u32| now + Duration::from_secs(u64::from(total.saturating_sub(elapsed)));
            Timers {
                t1: left(lease.t1),
                t2: left(lease.t2),
                expiry: left(lease.lease_time),
            }
        });
        self.lease = Some(lease.clone());
        // In use at once (§3.2); `Carrier(true)` then verifies it.
        out.push(Action::Bind {
            lease,
            remaining,
            fresh: false,
        });
        self.state = State::Bound;
        self.deadline = self.timers.map(|t| t.t1);
    }

    fn on_renew(&mut self, now: Instant, out: &mut Vec<Action>) {
        match self.state {
            State::Bound | State::Renewing | State::Rebinding => {
                self.started = now;
                self.enter_renewing(now, out);
            }
            State::Released | State::Backoff | State::Stopped if self.carrier => {
                self.discover(now, out);
            }
            State::Released => self.state = State::Stopped,
            _ => {}
        }
    }

    fn on_conflict(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.state != State::Probing {
            return;
        }
        let Some(lease) = self.pending.take() else {
            return;
        };
        out.push(Action::Log(format!(
            "{} is in use by another host; declined",
            lease.address
        )));
        let mut decline = self.message(msg::DECLINE, now);
        decline.push_option(DhcpOption::address(opt::REQUESTED_ADDRESS, lease.address));
        decline.push_option(DhcpOption::address(opt::SERVER_ID, lease.server_id));
        out.push(Action::Broadcast(decline));
        self.state = State::Backoff;
        self.deadline = Some(now + DECLINE_WAIT);
    }

    fn on_timeout(&mut self, now: Instant, out: &mut Vec<Action>) {
        // A lease that has run out ends whatever state it was in.
        if let Some(timers) = self.timers
            && self.lease.is_some()
            && now >= timers.expiry
        {
            out.push(Action::Log("lease expired".into()));
            self.unbind(out);
            self.restart(now, out);
            return;
        }
        match self.state {
            State::Selecting => {
                let discover = self.discover_message(now);
                out.push(Action::Broadcast(discover));
                self.retransmit_later(now);
            }
            State::Requesting => {
                if self.tries >= REQUEST_TRIES {
                    out.push(Action::Log(
                        "no answer to the request; starting over".into(),
                    ));
                    self.discover(now, out);
                    return;
                }
                if let Some((address, server)) = self.offer {
                    let request = self.select_message(address, server, now);
                    out.push(Action::Broadcast(request));
                }
                self.retransmit_later(now);
            }
            State::Probing => {
                let Some(lease) = self.pending.clone() else {
                    self.discover(now, out);
                    return;
                };
                if self.tries < PROBES {
                    out.push(Action::Probe(lease.address));
                    self.tries += 1;
                    self.deadline = Some(now + PROBE_INTERVAL);
                } else {
                    self.pending = None;
                    self.bind(lease, now, out);
                }
            }
            State::Rebooting => {
                if self.tries >= REBOOT_TRIES {
                    out.push(Action::Log(
                        "no server confirmed the lease; using it until it expires".into(),
                    ));
                    self.settle(now, out);
                    return;
                }
                if let Some(lease) = &self.lease {
                    let request = self.reboot_message(lease.address, now);
                    out.push(Action::Broadcast(request));
                }
                self.retransmit_later(now);
            }
            // T1, T2, or a retransmission: `settle` sends what the
            // lease's timers call for now.
            State::Bound | State::Renewing | State::Rebinding => self.settle(now, out),
            State::Backoff => self.discover(now, out),
            State::Stopped | State::Released => self.deadline = None,
        }
    }

    fn on_packet(
        &mut self,
        packet: &Packet,
        source: Ipv4Addr,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if packet.op != BOOTREPLY
            || packet.xid != self.xid
            || packet.ethernet_address() != Some(self.mac)
        {
            return;
        }
        let params = Params::from_packet(packet);
        // RFC 6842 §3: a reply that carries a client identifier is for
        // the client that sent it. A server returns the identifier it was
        // sent and none otherwise, so one that is not ours, or any when
        // we send none, marks a reply to somebody else. So does one too
        // short to be an identifier, which the decoder sets aside.
        let unreadable = params
            .malformed
            .iter()
            .any(|(code, _)| *code == opt::CLIENT_ID);
        if unreadable
            || (params.client_id.is_some()
                && params.client_id.as_deref() != self.options.client_id.as_deref())
        {
            return;
        }
        let Some(msg_type) = params.message_type else {
            return;
        };
        let server = params.server_id.unwrap_or(source);
        if self.rejected(server) || self.rejected(source) {
            return;
        }
        match (self.state, msg_type) {
            (State::Selecting, msg::OFFER) => {
                if packet.yiaddr.is_unspecified() || params.server_id.is_none() {
                    return;
                }
                self.offer = Some((packet.yiaddr, server));
                let request = self.select_message(packet.yiaddr, server, now);
                self.request_sent = now;
                out.push(Action::Broadcast(request));
                self.state = State::Requesting;
                self.tries = 1;
                self.retransmit_later_from(now, 1);
            }
            (State::Requesting, msg::ACK) => {
                if self
                    .offer
                    .is_some_and(|(_, offered_by)| offered_by != server)
                {
                    return;
                }
                let Some(lease) = self.lease_from(packet, &params, server, out) else {
                    return;
                };
                self.offer = None;
                self.pending = Some(lease.clone());
                self.state = State::Probing;
                self.tries = 1;
                out.push(Action::Probe(lease.address));
                self.deadline = Some(now + PROBE_INTERVAL);
            }
            (State::Rebooting | State::Renewing | State::Rebinding, msg::ACK) => {
                let Some(lease) = self.lease_from(packet, &params, server, out) else {
                    return;
                };
                // A different address is not a renewal of this lease.
                if self
                    .lease
                    .as_ref()
                    .is_some_and(|l| l.address != lease.address)
                {
                    return;
                }
                self.bind(lease, now, out);
            }
            (
                State::Requesting | State::Rebooting | State::Renewing | State::Rebinding,
                msg::NAK,
            ) => {
                // A REQUEST for an offer names its server, and the others
                // take it as a refusal of theirs (§3.1). One that answers
                // anyway does not end the acquisition, as its ACK above
                // would not complete it. There is an offer only while
                // such a REQUEST is out: a lease being verified or
                // extended names no server, and any may refuse that.
                if self
                    .offer
                    .is_some_and(|(_, offered_by)| offered_by != server)
                {
                    return;
                }
                out.push(Action::Log(match &params.message {
                    Some(reason) => format!("server {server} refused the lease: {reason}"),
                    None => format!("server {server} refused the lease"),
                }));
                if self.lease.is_some() {
                    self.unbind(out);
                }
                self.offer = None;
                self.state = State::Backoff;
                self.deadline = Some(now + Duration::from_secs(self.nak_backoff));
                self.nak_backoff = (self.nak_backoff * 2).min(RETRANSMIT_MAX);
            }
            _ => {}
        }
    }

    fn rejected(&self, server: Ipv4Addr) -> bool {
        self.options.reject.iter().any(|net| net.contains(&server))
    }

    /// The lease an ACK grants, or `None` (with a log line) when the ACK
    /// lacks what a lease needs.
    fn lease_from(
        &self,
        packet: &Packet,
        params: &Params,
        server: Ipv4Addr,
        out: &mut Vec<Action>,
    ) -> Option<Lease> {
        let address = packet.yiaddr;
        if address.is_unspecified() {
            return None;
        }
        let Some(lease_time) = params.lease_time.filter(|&t| t > 0) else {
            out.push(Action::Log(format!(
                "ACK from {server} without a lease time; ignored"
            )));
            return None;
        };
        for (code, error) in &params.malformed {
            out.push(Action::Log(format!(
                "option {code} from {server}: {error}; ignored"
            )));
        }
        let prefix_len = params.prefix_len.unwrap_or_else(|| {
            let classful = match address.octets()[0] {
                0..=127 => 8,
                128..=191 => 16,
                _ => 24,
            };
            out.push(Action::Log(format!(
                "ACK from {server} without a subnet mask; using /{classful}"
            )));
            classful
        });
        let (t1, t2) = if lease_time == INFINITE {
            (INFINITE, INFINITE)
        } else {
            // §4.4.5 defaults, also when the server's values are out of
            // order.
            let t1 = params.renewal_time.unwrap_or(lease_time / 2);
            let t2 = params
                .rebinding_time
                .unwrap_or((u64::from(lease_time) * 7 / 8) as u32);
            if t1 < t2 && t2 < lease_time {
                (t1, t2)
            } else {
                (lease_time / 2, (u64::from(lease_time) * 7 / 8) as u32)
            }
        };
        Some(Lease {
            address,
            prefix_len,
            server_id: server,
            broadcast: params.broadcast_address,
            routers: params.routers.clone(),
            classless_routes: params
                .classless_routes
                .iter()
                .filter_map(|r| {
                    Ipv4Net::new(r.destination, r.prefix_len)
                        .ok()
                        .map(|net| (net, r.router))
                })
                .collect(),
            dns_servers: params.dns_servers.clone(),
            domain_name: params.domain_name.clone(),
            domain_search: params.domain_search.clone(),
            ntp_servers: params.ntp_servers.clone(),
            mtu: params
                .interface_mtu
                .filter(|&mtu| self.options.request_mtu && mtu >= 576),
            lease_time,
            t1,
            t2,
        })
    }

    /// Take `lease` into use, counted from when its REQUEST went out.
    fn bind(&mut self, lease: Lease, now: Instant, out: &mut Vec<Action>) {
        let since = self.request_sent;
        self.timers = (lease.lease_time != INFINITE).then(|| {
            let at = |secs: u32| since + Duration::from_secs(u64::from(secs));
            Timers {
                t1: at(lease.t1),
                t2: at(lease.t2),
                expiry: at(lease.lease_time),
            }
        });
        let remaining = match self.timers {
            Some(t) => t.expiry.saturating_duration_since(now).as_secs() as u32,
            None => INFINITE,
        };
        self.lease = Some(lease.clone());
        self.nak_backoff = NAK_BACKOFF_FIRST;
        out.push(Action::Bind {
            lease,
            remaining,
            fresh: true,
        });
        self.state = State::Bound;
        self.tries = 0;
        self.deadline = self.timers.map(|t| t.t1);
    }

    fn unbind(&mut self, out: &mut Vec<Action>) {
        self.lease = None;
        self.timers = None;
        self.pending = None;
        out.push(Action::Unbind);
    }

    /// Give the lease back, if there is one.
    fn release(&mut self, out: &mut Vec<Action>, now: Instant) {
        self.offer = None;
        self.pending = None;
        let Some(lease) = self.lease.clone() else {
            return;
        };
        self.xid = (self.random)();
        self.started = now;
        let mut release = self.message(msg::RELEASE, now);
        release.ciaddr = lease.address;
        release.push_option(DhcpOption::address(opt::SERVER_ID, lease.server_id));
        out.push(Action::Send(lease.server_id, release));
        self.unbind(out);
    }

    /// Begin again after a lease was lost.
    fn restart(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.carrier {
            self.discover(now, out);
        } else {
            self.state = State::Stopped;
            self.deadline = None;
        }
    }

    fn discover(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.xid = (self.random)();
        self.started = now;
        self.offer = None;
        self.pending = None;
        self.state = State::Selecting;
        self.tries = 0;
        let discover = self.discover_message(now);
        out.push(Action::Broadcast(discover));
        self.retransmit_later(now);
    }

    /// Verify a lease that was kept while the client could not talk.
    fn reboot(&mut self, now: Instant, out: &mut Vec<Action>) {
        let Some(address) = self.lease.as_ref().map(|l| l.address) else {
            return;
        };
        self.xid = (self.random)();
        self.started = now;
        self.state = State::Rebooting;
        self.tries = 0;
        self.request_sent = now;
        let request = self.reboot_message(address, now);
        out.push(Action::Broadcast(request));
        self.retransmit_later(now);
    }

    /// Put a held lease in the state its timers call for, sending the
    /// REQUEST that state sends.
    fn settle(&mut self, now: Instant, out: &mut Vec<Action>) {
        let Some(timers) = self.timers else {
            self.state = State::Bound;
            self.deadline = None;
            return;
        };
        if now < timers.t1 {
            self.state = State::Bound;
            self.deadline = Some(timers.t1);
        } else if now < timers.t2 {
            if self.state != State::Renewing {
                self.started = now;
            }
            self.enter_renewing(now, out);
        } else {
            if self.state != State::Rebinding {
                self.started = now;
            }
            self.state = State::Rebinding;
            self.send_renewal(Ipv4Addr::BROADCAST, now, out);
            self.deadline = Some(Self::halfway(now, timers.expiry));
        }
    }

    fn enter_renewing(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.state = State::Renewing;
        if let Some(server) = self.lease.as_ref().map(|lease| lease.server_id) {
            self.send_renewal(server, now, out);
        }
        // An infinite lease renewed by hand has no T2: one REQUEST, no
        // retry.
        self.deadline = self.timers.map(|timers| Self::halfway(now, timers.t2));
    }

    /// One REQUEST for the lease held, to its server or to everyone.
    ///
    /// Each goes out under a transaction id of its own, taken together
    /// with the time it is sent: the lease an ACK grants counts from the
    /// REQUEST it answers (§4.4.5). Were retransmissions to share an id,
    /// an ACK could not be told from a late answer to an earlier copy, and
    /// timing it from the latest copy would keep the lease past what the
    /// server granted. Retransmissions here are a minute or more apart, so
    /// giving up on the earlier copy's answer costs nothing.
    fn send_renewal(&mut self, destination: Ipv4Addr, now: Instant, out: &mut Vec<Action>) {
        let Some(address) = self.lease.as_ref().map(|lease| lease.address) else {
            return;
        };
        self.xid = (self.random)();
        self.request_sent = now;
        let request = self.renew_message(address, now);
        out.push(Action::Send(destination, request));
    }

    /// §4.4.5: half the time left to `limit`, at least a minute, and not
    /// past `limit` itself.
    fn halfway(now: Instant, limit: Instant) -> Instant {
        let left = limit.saturating_duration_since(now);
        (now + (left / 2).max(RENEW_MIN)).min(limit)
    }

    fn retransmit_later(&mut self, now: Instant) {
        self.tries += 1;
        self.retransmit_later_from(now, self.tries);
    }

    /// The delay before transmission `tries + 1`: 4, 8, … 64 s, ±1 s.
    fn retransmit_later_from(&mut self, now: Instant, tries: u32) {
        let base = (RETRANSMIT_FIRST << (tries.saturating_sub(1)).min(4)).min(RETRANSMIT_MAX);
        let jitter = u64::from((self.random)() % 2001);
        self.deadline = Some(now + Duration::from_millis(base * 1000 + jitter - 1000));
    }

    /// A request with the fields and options every message carries.
    fn message(&self, msg_type: u8, now: Instant) -> Packet {
        let mut packet = Packet::request(msg_type, self.xid, self.mac);
        packet.secs = now
            .saturating_duration_since(self.started)
            .as_secs()
            .min(u64::from(u16::MAX)) as u16;
        if let Some(id) = &self.options.client_id {
            packet.push_option(DhcpOption::new(opt::CLIENT_ID, id.clone()));
        }
        packet
    }

    /// The options a DISCOVER and every REQUEST end with.
    fn finish(&self, packet: &mut Packet) {
        if let Some(name) = &self.options.host_name {
            packet.push_option(DhcpOption::new(opt::HOST_NAME, name.as_bytes()));
        }
        if let Some(class) = &self.options.vendor_class_id {
            packet.push_option(DhcpOption::new(opt::VENDOR_CLASS_ID, class.as_bytes()));
        }
        if let Some(class) = &self.options.user_class
            && let Ok(option) = DhcpOption::user_class(&[class.as_bytes()])
        {
            packet.push_option(option);
        }
        let mut wanted = vec![
            opt::SUBNET_MASK,
            opt::ROUTER,
            opt::DNS_SERVER,
            opt::DOMAIN_NAME,
            opt::BROADCAST_ADDRESS,
            opt::NTP_SERVER,
            opt::DOMAIN_SEARCH,
            opt::CLASSLESS_STATIC_ROUTE,
        ];
        if self.options.request_mtu {
            wanted.push(opt::INTERFACE_MTU);
        }
        packet.push_option(DhcpOption::parameter_request_list(&wanted));
        packet.push_option(DhcpOption::max_message_size(self.mtu));
    }

    fn discover_message(&self, now: Instant) -> Packet {
        let mut packet = self.message(msg::DISCOVER, now);
        self.finish(&mut packet);
        packet
    }

    /// SELECTING → REQUESTING: names the address and the server (§4.3.2).
    fn select_message(&self, address: Ipv4Addr, server: Ipv4Addr, now: Instant) -> Packet {
        let mut packet = self.message(msg::REQUEST, now);
        packet.push_option(DhcpOption::address(opt::REQUESTED_ADDRESS, address));
        packet.push_option(DhcpOption::address(opt::SERVER_ID, server));
        self.finish(&mut packet);
        packet
    }

    /// INIT-REBOOT: names the address, no server.
    fn reboot_message(&self, address: Ipv4Addr, now: Instant) -> Packet {
        let mut packet = self.message(msg::REQUEST, now);
        packet.push_option(DhcpOption::address(opt::REQUESTED_ADDRESS, address));
        self.finish(&mut packet);
        packet
    }

    /// RENEWING / REBINDING: the address goes in `ciaddr`.
    fn renew_message(&self, address: Ipv4Addr, now: Instant) -> Packet {
        let mut packet = self.message(msg::REQUEST, now);
        packet.ciaddr = address;
        self.finish(&mut packet);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcp_packet::v4::Body;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 100);

    fn client(options: Options, now: Instant) -> Client {
        // A fixed "random" source: transaction ids count up, and the
        // jitter (value % 2001) stays small and known.
        let mut next = 1000u32;
        Client::new(
            MAC,
            1500,
            options,
            now,
            Box::new(move || {
                next += 1;
                next
            }),
        )
    }

    /// The server's reply to `request`: `msg_type` with `options`.
    fn reply(request: &Packet, msg_type: u8, yiaddr: Ipv4Addr, options: Vec<DhcpOption>) -> Packet {
        reply_from(Some(SERVER), request, msg_type, yiaddr, options)
    }

    /// The same from `server`, or from one that does not say who it is.
    fn reply_from(
        server: Option<Ipv4Addr>,
        request: &Packet,
        msg_type: u8,
        yiaddr: Ipv4Addr,
        options: Vec<DhcpOption>,
    ) -> Packet {
        let mut p = request.clone();
        p.op = BOOTREPLY;
        p.yiaddr = yiaddr;
        let mut all = vec![DhcpOption::message_type(msg_type)];
        all.extend(server.map(|server| DhcpOption::address(opt::SERVER_ID, server)));
        all.extend(options);
        p.body = Body::Options(all);
        p
    }

    fn lease_options(lease_time: u32) -> Vec<DhcpOption> {
        vec![
            DhcpOption::new(opt::LEASE_TIME, lease_time.to_be_bytes()),
            DhcpOption::address(opt::SUBNET_MASK, Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::address(opt::ROUTER, SERVER),
        ]
    }

    fn sent(actions: &[Action]) -> &Packet {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Broadcast(p) | Action::Send(_, p) => Some(p),
                _ => None,
            })
            .expect("a packet")
    }

    fn deliver(c: &mut Client, packet: &Packet, now: Instant) -> Vec<Action> {
        c.handle(
            Event::Packet {
                packet,
                source: SERVER,
            },
            now,
        )
    }

    /// DISCOVER → OFFER → REQUEST → ACK → two probes → bound.
    fn acquire(c: &mut Client, now: Instant, lease_time: u32) -> Instant {
        let actions = c.handle(Event::Carrier(true), now);
        let discover = sent(&actions).clone();
        assert_eq!(discover.message_type(), Some(msg::DISCOVER));
        let actions = deliver(c, &reply(&discover, msg::OFFER, ADDRESS, vec![]), now);
        let request = sent(&actions).clone();
        assert_eq!(request.message_type(), Some(msg::REQUEST));
        assert_eq!(c.state(), State::Requesting);
        let ack = reply(&request, msg::ACK, ADDRESS, lease_options(lease_time));
        assert_eq!(deliver(c, &ack, now), [Action::Probe(ADDRESS)]);
        assert_eq!(c.state(), State::Probing);
        let t = now + PROBE_INTERVAL;
        assert_eq!(c.handle(Event::Timeout, t), [Action::Probe(ADDRESS)]);
        let t = t + PROBE_INTERVAL;
        let actions = c.handle(Event::Timeout, t);
        assert!(
            matches!(&actions[..], [Action::Bind { lease, fresh: true, .. }] if lease.address == ADDRESS),
            "{actions:?}"
        );
        assert_eq!(c.state(), State::Bound);
        t
    }

    #[test]
    fn discover_request_bind() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        assert!(!c.wants_packet_socket() && !c.wants_udp_socket());
        let actions = c.handle(Event::Carrier(true), t0);
        assert!(c.wants_packet_socket());
        let discover = sent(&actions).clone();
        assert_eq!(discover.ethernet_address(), Some(MAC));
        assert_eq!(discover.ciaddr, Ipv4Addr::UNSPECIFIED);
        // No client identifier unless configured; the parameter list asks
        // for classless routes but not the MTU.
        assert!(discover.option(opt::CLIENT_ID).is_none());
        let wanted = &discover.option(opt::PARAMETER_REQUEST_LIST).unwrap().data;
        assert!(wanted.contains(&opt::CLASSLESS_STATIC_ROUTE));
        assert!(!wanted.contains(&opt::INTERFACE_MTU));

        // An offer under another transaction id, or for another MAC, is
        // not ours.
        let mut stray = reply(&discover, msg::OFFER, ADDRESS, vec![]);
        stray.xid ^= 1;
        assert!(deliver(&mut c, &stray, t0).is_empty());
        let mut stray = reply(&discover, msg::OFFER, ADDRESS, vec![]);
        stray.chaddr[5] ^= 1;
        assert!(deliver(&mut c, &stray, t0).is_empty());

        let actions = deliver(&mut c, &reply(&discover, msg::OFFER, ADDRESS, vec![]), t0);
        let request = sent(&actions).clone();
        assert_eq!(request.xid, discover.xid);
        assert_eq!(
            request.option(opt::REQUESTED_ADDRESS).unwrap().data,
            ADDRESS.octets()
        );
        assert_eq!(
            request.option(opt::SERVER_ID).unwrap().data,
            SERVER.octets()
        );

        let ack = reply(&request, msg::ACK, ADDRESS, lease_options(3600));
        deliver(&mut c, &ack, t0);
        c.handle(Event::Timeout, t0 + PROBE_INTERVAL);
        let actions = c.handle(Event::Timeout, t0 + 2 * PROBE_INTERVAL);
        let [
            Action::Bind {
                lease,
                remaining,
                fresh: true,
            },
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.net().to_string(), "192.0.2.100/24");
        assert_eq!(lease.routers, [SERVER]);
        assert_eq!((lease.lease_time, lease.t1, lease.t2), (3600, 1800, 3150));
        // Counted from the REQUEST, two probe seconds ago.
        assert_eq!(*remaining, 3598);
        assert!(!c.wants_packet_socket() && c.wants_udp_socket());
        assert_eq!(c.deadline(), Some(t0 + Duration::from_secs(1800)));
    }

    #[test]
    fn discover_is_retransmitted_with_backoff() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        c.handle(Event::Carrier(true), t0);
        // Each gap is the base (4, 8, 16, 32, 64, 64 s) ± 1 s.
        let mut now = t0;
        for base in [4u64, 8, 16, 32, 64, 64] {
            let gap = c.deadline().unwrap().duration_since(now);
            assert!(
                gap >= Duration::from_secs(base - 1) && gap <= Duration::from_secs(base + 1),
                "{base}: {gap:?}"
            );
            now = c.deadline().unwrap();
            let actions = c.handle(Event::Timeout, now);
            assert_eq!(sent(&actions).message_type(), Some(msg::DISCOVER));
        }
    }

    #[test]
    fn request_gives_up_and_rediscovers() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        let discover = sent(&c.handle(Event::Carrier(true), t0)).clone();
        deliver(&mut c, &reply(&discover, msg::OFFER, ADDRESS, vec![]), t0);
        let mut requests = 1;
        loop {
            let now = c.deadline().unwrap();
            let actions = c.handle(Event::Timeout, now);
            match sent(&actions).message_type() {
                Some(msg::REQUEST) => requests += 1,
                Some(msg::DISCOVER) => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(requests, REQUEST_TRIES);
        assert_eq!(c.state(), State::Selecting);
    }

    #[test]
    fn renew_rebind_expire() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        acquire(&mut c, t0, 3600);
        let at = |secs: u64| t0 + Duration::from_secs(secs);

        // T1: unicast to the server, the address in ciaddr.
        let actions = c.handle(Event::Timeout, at(1800));
        let [Action::Send(to, renew)] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(*to, SERVER);
        assert_eq!(renew.ciaddr, ADDRESS);
        assert!(renew.option(opt::REQUESTED_ADDRESS).is_none());
        assert!(renew.option(opt::SERVER_ID).is_none());
        assert_eq!(c.state(), State::Renewing);
        // Half the time left to T2 (3150): 675 s.
        assert_eq!(c.deadline(), Some(at(1800 + 675)));

        // Unanswered until T2: broadcast.
        let mut now = c.deadline().unwrap();
        loop {
            let actions = c.handle(Event::Timeout, now);
            if c.state() == State::Rebinding {
                assert!(matches!(
                    &actions[..],
                    [Action::Send(Ipv4Addr::BROADCAST, _)]
                ));
                break;
            }
            assert!(matches!(&actions[..], [Action::Send(SERVER, _)]));
            assert!(c.deadline().unwrap() <= at(3150));
            now = c.deadline().unwrap();
        }
        assert!(now >= at(3150));

        // Unanswered until expiry: everything is withdrawn and discovery
        // starts again.
        loop {
            now = c.deadline().unwrap();
            let actions = c.handle(Event::Timeout, now);
            if actions.contains(&Action::Unbind) {
                assert_eq!(sent(&actions).message_type(), Some(msg::DISCOVER));
                break;
            }
            assert!(now < at(3600));
        }
        assert_eq!(now, at(3600));
        assert_eq!(c.state(), State::Selecting);
        assert!(c.lease().is_none() && !c.wants_udp_socket());
    }

    #[test]
    fn renewal_moves_the_lease() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        acquire(&mut c, t0, 3600);
        let t1 = t0 + Duration::from_secs(1800);
        let renew = sent(&c.handle(Event::Timeout, t1)).clone();
        let actions = deliver(
            &mut c,
            &reply(&renew, msg::ACK, ADDRESS, lease_options(7200)),
            t1,
        );
        let [
            Action::Bind {
                lease,
                remaining: 7200,
                fresh: true,
            },
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.lease_time, 7200);
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t1 + Duration::from_secs(3600)));

        // An ACK naming another address does not renew this lease.
        let renew = sent(&c.handle(Event::Renew, t1)).clone();
        let other = Ipv4Addr::new(192, 0, 2, 200);
        assert!(
            deliver(
                &mut c,
                &reply(&renew, msg::ACK, other, lease_options(7200)),
                t1
            )
            .is_empty()
        );
        assert_eq!(c.state(), State::Renewing);
    }

    /// A renewal's ACK is timed from the REQUEST it answers. A late
    /// answer to an earlier REQUEST is not taken for an answer to the
    /// latest, which would keep the lease past what the server granted.
    #[test]
    fn a_late_ack_does_not_stretch_the_lease() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        acquire(&mut c, t0, 3600);
        let at = |secs: u64| t0 + Duration::from_secs(secs);

        // T1, and unanswered: sent again halfway to T2.
        let first = sent(&c.handle(Event::Timeout, at(1800))).clone();
        assert_eq!(c.deadline(), Some(at(2475)));
        let second = sent(&c.handle(Event::Timeout, at(2475))).clone();
        assert_ne!(first.xid, second.xid);
        // Only now does the answer to the first one arrive. Timed from
        // the second REQUEST it would run to 6075 s; the server granted
        // it until 5400 s.
        let late = reply(&first, msg::ACK, ADDRESS, lease_options(3600));
        assert!(deliver(&mut c, &late, at(2480)).is_empty());
        assert_eq!(c.state(), State::Renewing);
        // The answer to the second counts from the second.
        let ack = reply(&second, msg::ACK, ADDRESS, lease_options(3600));
        let actions = deliver(&mut c, &ack, at(2480));
        assert!(
            matches!(
                &actions[..],
                [Action::Bind {
                    remaining: 3595,
                    ..
                }]
            ),
            "{actions:?}"
        );
        assert_eq!(c.remaining(at(2475)), Some((1800, 3150, 3600)));

        // The same when rebinding: T2 is now at 5625 s, expiry at 6075 s.
        let first = loop {
            let now = c.deadline().unwrap();
            let actions = c.handle(Event::Timeout, now);
            if c.state() == State::Rebinding {
                break sent(&actions).clone();
            }
        };
        let retry = c.deadline().unwrap();
        assert_eq!(retry, at(5850));
        let actions = c.handle(Event::Timeout, retry);
        assert!(matches!(
            &actions[..],
            [Action::Send(Ipv4Addr::BROADCAST, _)]
        ));
        let second = sent(&actions).clone();
        assert_ne!(first.xid, second.xid);
        let late = reply(&first, msg::ACK, ADDRESS, lease_options(3600));
        assert!(deliver(&mut c, &late, retry).is_empty());
        assert_eq!(c.state(), State::Rebinding);
        let ack = reply(&second, msg::ACK, ADDRESS, lease_options(3600));
        let actions = deliver(&mut c, &ack, retry);
        assert!(
            matches!(
                &actions[..],
                [Action::Bind {
                    remaining: 3600,
                    ..
                }]
            ),
            "{actions:?}"
        );
        assert_eq!(c.remaining(retry), Some((1800, 3150, 3600)));
    }

    /// RFC 2131 §3.1: a REQUEST for an offer names the server it takes,
    /// and that server alone answers it.
    #[test]
    fn only_the_selected_server_answers_a_request() {
        const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
        let from_other = |c: &mut Client, packet: &Packet, now: Instant| {
            c.handle(
                Event::Packet {
                    packet,
                    source: OTHER,
                },
                now,
            )
        };
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        let discover = sent(&c.handle(Event::Carrier(true), t0)).clone();
        let offer = reply(&discover, msg::OFFER, ADDRESS, vec![]);
        let request = sent(&deliver(&mut c, &offer, t0)).clone();
        assert_eq!(c.state(), State::Requesting);
        let due = c.deadline();
        // Another server's NAK does not end the acquisition, nor does
        // its ACK complete it. One that names no server is told by where
        // it came from.
        let none = Ipv4Addr::UNSPECIFIED;
        for stray in [
            reply_from(Some(OTHER), &request, msg::NAK, none, vec![]),
            reply_from(None, &request, msg::NAK, none, vec![]),
            reply_from(
                Some(OTHER),
                &request,
                msg::ACK,
                ADDRESS,
                lease_options(3600),
            ),
        ] {
            assert!(from_other(&mut c, &stray, t0).is_empty(), "{stray:?}");
            assert_eq!(c.state(), State::Requesting);
            assert_eq!(c.deadline(), due);
        }
        // The selected server's ACK still does.
        let ack = reply(&request, msg::ACK, ADDRESS, lease_options(3600));
        assert_eq!(deliver(&mut c, &ack, t0), [Action::Probe(ADDRESS)]);

        // Its NAK ends the acquisition, also when it names no server.
        for server in [Some(SERVER), None] {
            let mut c = client(Options::default(), t0);
            let discover = sent(&c.handle(Event::Carrier(true), t0)).clone();
            let offer = reply(&discover, msg::OFFER, ADDRESS, vec![]);
            let request = sent(&deliver(&mut c, &offer, t0)).clone();
            let nak = reply_from(server, &request, msg::NAK, none, vec![]);
            let actions = deliver(&mut c, &nak, t0);
            assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
            assert_eq!(c.state(), State::Backoff);
        }

        // A lease being verified names no server (§4.3.2): any server on
        // the link may refuse it.
        let mut c = client(Options::default(), t0);
        let bound = acquire(&mut c, t0, 3600);
        c.handle(Event::Carrier(false), bound);
        let reboot = sent(&c.handle(Event::Carrier(true), bound)).clone();
        assert_eq!(c.state(), State::Rebooting);
        let nak = reply_from(Some(OTHER), &reboot, msg::NAK, none, vec![]);
        let actions = from_other(&mut c, &nak, bound);
        assert!(actions.contains(&Action::Unbind), "{actions:?}");
        assert_eq!(c.state(), State::Backoff);
    }

    /// RFC 6842 §3: a reply that carries a client identifier is for the
    /// client that sent that identifier.
    #[test]
    fn a_reply_for_another_client_identifier_is_ignored() {
        let t0 = Instant::now();
        let a = &[0, b'A'][..];
        let b = &[0, b'B'][..];
        // What the client sends, what the reply carries, whether it is
        // taken.
        let cases = [
            (Some(a), Some(a), true),
            // A server from before RFC 6842 does not return it.
            (Some(a), None, true),
            (Some(a), Some(b), false),
            (Some(a), Some(&a[..1]), false),
            (None, None, true),
            // A server returns none unless it was sent one.
            (None, Some(a), false),
        ];
        for (mine, theirs, taken) in cases {
            let options = Options {
                client_id: mine.map(<[u8]>::to_vec),
                ..Default::default()
            };
            let returned = |extra: Vec<DhcpOption>| -> Vec<DhcpOption> {
                theirs
                    .map(|id| DhcpOption::new(opt::CLIENT_ID, id))
                    .into_iter()
                    .chain(extra)
                    .collect()
            };
            // An OFFER.
            let mut c = client(options.clone(), t0);
            let discover = sent(&c.handle(Event::Carrier(true), t0)).clone();
            let offer = reply(&discover, msg::OFFER, ADDRESS, returned(vec![]));
            let actions = deliver(&mut c, &offer, t0);
            assert_eq!(!actions.is_empty(), taken, "{mine:?} {theirs:?}");
            let want = if taken {
                State::Requesting
            } else {
                State::Selecting
            };
            assert_eq!(c.state(), want, "{mine:?} {theirs:?}");

            // An ACK and a NAK, from the server that was selected.
            let mut c = client(options, t0);
            let discover = sent(&c.handle(Event::Carrier(true), t0)).clone();
            let offer = reply(&discover, msg::OFFER, ADDRESS, vec![]);
            let request = sent(&deliver(&mut c, &offer, t0)).clone();
            let nak = reply(&request, msg::NAK, Ipv4Addr::UNSPECIFIED, returned(vec![]));
            let ack = reply(&request, msg::ACK, ADDRESS, returned(lease_options(3600)));
            if taken {
                assert_eq!(deliver(&mut c, &ack, t0), [Action::Probe(ADDRESS)]);
            } else {
                assert!(deliver(&mut c, &nak, t0).is_empty(), "{mine:?} {theirs:?}");
                assert!(deliver(&mut c, &ack, t0).is_empty(), "{mine:?} {theirs:?}");
                assert_eq!(c.state(), State::Requesting);
            }
        }
    }

    #[test]
    fn nak_withdraws_and_backs_off() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        acquire(&mut c, t0, 3600);
        let mut now = t0 + Duration::from_secs(1800);
        let renew = sent(&c.handle(Event::Timeout, now)).clone();
        let nak = reply(
            &renew,
            msg::NAK,
            Ipv4Addr::UNSPECIFIED,
            vec![DhcpOption::new(opt::MESSAGE, *b"moved")],
        );
        let actions = deliver(&mut c, &nak, now);
        assert!(actions.contains(&Action::Unbind));
        assert!(
            matches!(&actions[0], Action::Log(text) if text.ends_with("refused the lease: moved"))
        );
        assert_eq!(c.state(), State::Backoff);
        assert_eq!(c.deadline(), Some(now + Duration::from_secs(1)));

        // A server that refuses every request is asked less and less often.
        for backoff in [2u64, 4, 8] {
            now = c.deadline().unwrap();
            let discover = sent(&c.handle(Event::Timeout, now)).clone();
            let request = sent(&deliver(
                &mut c,
                &reply(&discover, msg::OFFER, ADDRESS, vec![]),
                now,
            ))
            .clone();
            deliver(
                &mut c,
                &reply(&request, msg::NAK, Ipv4Addr::UNSPECIFIED, vec![]),
                now,
            );
            assert_eq!(c.deadline(), Some(now + Duration::from_secs(backoff)));
        }
    }

    #[test]
    fn address_conflict_is_declined() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        let discover = sent(&c.handle(Event::Carrier(true), t0)).clone();
        let request = sent(&deliver(
            &mut c,
            &reply(&discover, msg::OFFER, ADDRESS, vec![]),
            t0,
        ))
        .clone();
        deliver(
            &mut c,
            &reply(&request, msg::ACK, ADDRESS, lease_options(3600)),
            t0,
        );
        let actions = c.handle(Event::ArpConflict, t0);
        let decline = sent(&actions);
        assert_eq!(decline.message_type(), Some(msg::DECLINE));
        assert_eq!(
            decline.option(opt::REQUESTED_ADDRESS).unwrap().data,
            ADDRESS.octets()
        );
        assert_eq!(
            decline.option(opt::SERVER_ID).unwrap().data,
            SERVER.octets()
        );
        assert!(decline.option(opt::PARAMETER_REQUEST_LIST).is_none());
        assert!(!actions.iter().any(|a| matches!(a, Action::Bind { .. })));
        assert_eq!(c.deadline(), Some(t0 + DECLINE_WAIT));
        let actions = c.handle(Event::Timeout, t0 + DECLINE_WAIT);
        assert_eq!(sent(&actions).message_type(), Some(msg::DISCOVER));
        // A conflict report outside the probe is not about us.
        assert!(c.handle(Event::ArpConflict, t0 + DECLINE_WAIT).is_empty());
    }

    #[test]
    fn resume_verifies_then_trusts_the_lease() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        acquire(&mut c, t0, 3600);
        let lease = c.lease().unwrap().clone();

        // A new process, 1000 s into the lease.
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        let actions = c.handle(
            Event::Resume {
                lease: lease.clone(),
                elapsed: 1000,
            },
            t0,
        );
        assert_eq!(
            actions,
            [Action::Bind {
                lease: lease.clone(),
                remaining: 2600,
                fresh: false
            }]
        );
        assert_eq!(c.remaining(t0), Some((800, 2150, 2600)));

        // INIT-REBOOT: the address as option 50, not in ciaddr, no server.
        let actions = c.handle(Event::Carrier(true), t0);
        let request = sent(&actions).clone();
        assert!(matches!(&actions[..], [Action::Broadcast(_)]));
        assert_eq!(request.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            request.option(opt::REQUESTED_ADDRESS).unwrap().data,
            ADDRESS.octets()
        );
        assert!(request.option(opt::SERVER_ID).is_none());
        assert_eq!(c.state(), State::Rebooting);
        assert!(c.wants_packet_socket() && c.wants_udp_socket());

        // No server answers: after the retries the lease is used as it is.
        let mut now = c.deadline().unwrap();
        assert_eq!(
            sent(&c.handle(Event::Timeout, now)).message_type(),
            Some(msg::REQUEST)
        );
        now = c.deadline().unwrap();
        let actions = c.handle(Event::Timeout, now);
        assert!(matches!(&actions[..], [Action::Log(_)]), "{actions:?}");
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.deadline(), Some(t0 + Duration::from_secs(800)));

        // A lease that ran out while we were away is not resumed.
        let mut c = client(Options::default(), t0);
        assert!(
            c.handle(
                Event::Resume {
                    lease,
                    elapsed: 3600
                },
                t0
            )
            .is_empty()
        );
        assert!(c.lease().is_none());
    }

    #[test]
    fn reboot_ack_and_nak() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        acquire(&mut c, t0, 3600);
        let lease = c.lease().unwrap().clone();
        let resume = |c: &mut Client| {
            c.handle(
                Event::Resume {
                    lease: lease.clone(),
                    elapsed: 10,
                },
                t0,
            );
            sent(&c.handle(Event::Carrier(true), t0)).clone()
        };

        let mut c = client(Options::default(), t0);
        let request = resume(&mut c);
        let actions = deliver(
            &mut c,
            &reply(&request, msg::ACK, ADDRESS, lease_options(3600)),
            t0,
        );
        assert!(matches!(
            &actions[..],
            [Action::Bind {
                remaining: 3600,
                fresh: true,
                ..
            }]
        ));
        assert_eq!(c.state(), State::Bound);

        let mut c = client(Options::default(), t0);
        let request = resume(&mut c);
        let actions = deliver(
            &mut c,
            &reply(&request, msg::NAK, Ipv4Addr::UNSPECIFIED, vec![]),
            t0,
        );
        assert!(actions.contains(&Action::Unbind));
        assert_eq!(c.state(), State::Backoff);
    }

    #[test]
    fn carrier_loss_keeps_a_lease_but_stops_an_acquisition() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        c.handle(Event::Carrier(true), t0);
        assert!(c.handle(Event::Carrier(false), t0).is_empty());
        assert_eq!(c.state(), State::Stopped);
        assert_eq!(c.deadline(), None);

        let bound = acquire(&mut c, t0, 3600);
        assert!(c.handle(Event::Carrier(false), bound).is_empty());
        assert_eq!(c.state(), State::Bound);
        assert!(c.lease().is_some());
        // Back up: the lease is verified, not asked for anew.
        let actions = c.handle(Event::Carrier(true), bound);
        assert_eq!(c.state(), State::Rebooting);
        assert!(sent(&actions).option(opt::REQUESTED_ADDRESS).is_some());
    }

    #[test]
    fn release_and_renew_by_hand() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        let bound = acquire(&mut c, t0, 3600);
        let actions = c.handle(Event::Release, bound);
        let [Action::Send(to, release), Action::Unbind] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(*to, SERVER);
        assert_eq!(release.message_type(), Some(msg::RELEASE));
        assert_eq!(release.ciaddr, ADDRESS);
        assert_eq!(c.state(), State::Released);
        // Released stays released across a carrier flap…
        c.handle(Event::Carrier(false), bound);
        assert!(c.handle(Event::Carrier(true), bound).is_empty());
        // …until the operator renews.
        let actions = c.handle(Event::Renew, bound);
        assert_eq!(sent(&actions).message_type(), Some(msg::DISCOVER));

        // Stop releases too, and a second release has nothing to give back.
        let mut c = client(Options::default(), t0);
        let bound = acquire(&mut c, t0, 3600);
        assert_eq!(c.handle(Event::Stop, bound).len(), 2);
        assert!(c.handle(Event::Release, bound).is_empty());
    }

    #[test]
    fn address_lost_starts_over() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        let bound = acquire(&mut c, t0, 3600);
        let actions = c.handle(Event::AddressLost, bound);
        assert!(actions.contains(&Action::Unbind));
        assert_eq!(sent(&actions).message_type(), Some(msg::DISCOVER));
        // Without a lease there is nothing to lose.
        assert!(c.handle(Event::AddressLost, bound).is_empty());

        // The kernel dropping the address a moment before our own timer
        // is the lease expiring, and is reported as that.
        let mut c = client(Options::default(), t0);
        acquire(&mut c, t0, 3600);
        let actions = c.handle(Event::AddressLost, t0 + Duration::from_secs(3599));
        assert_eq!(actions[0], Action::Log("lease expired".into()));
        assert!(actions.contains(&Action::Unbind));
    }

    #[test]
    fn options_shape_the_messages_and_the_lease() {
        let t0 = Instant::now();
        let options = Options {
            client_id: Some(vec![0, b'w', b'a', b'n']),
            host_name: Some("router".into()),
            vendor_class_id: Some("zebra".into()),
            user_class: Some("isp".into()),
            reject: vec!["192.0.2.66/32".parse().unwrap()],
            request_mtu: true,
        };
        let mut c = client(options, t0);
        let discover = sent(&c.handle(Event::Carrier(true), t0)).clone();
        assert_eq!(
            discover.option(opt::CLIENT_ID).unwrap().data,
            [0, b'w', b'a', b'n']
        );
        assert_eq!(discover.option(opt::HOST_NAME).unwrap().data, b"router");
        assert_eq!(
            discover.option(opt::VENDOR_CLASS_ID).unwrap().data,
            b"zebra"
        );
        assert_eq!(
            discover.option(opt::USER_CLASS).unwrap().data,
            [3, b'i', b's', b'p']
        );
        assert!(
            discover
                .option(opt::PARAMETER_REQUEST_LIST)
                .unwrap()
                .data
                .contains(&opt::INTERFACE_MTU)
        );

        // The rejected server's offer is ignored, by identifier or source.
        let rogue = Ipv4Addr::new(192, 0, 2, 66);
        let mut offer = reply(&discover, msg::OFFER, ADDRESS, vec![]);
        offer.body = Body::Options(vec![
            DhcpOption::message_type(msg::OFFER),
            DhcpOption::address(opt::SERVER_ID, rogue),
        ]);
        assert!(deliver(&mut c, &offer, t0).is_empty());
        let offer = reply(&discover, msg::OFFER, ADDRESS, vec![]);
        assert!(
            c.handle(
                Event::Packet {
                    packet: &offer,
                    source: rogue
                },
                t0
            )
            .is_empty()
        );

        let request = sent(&deliver(&mut c, &offer, t0)).clone();
        let mut options = lease_options(600);
        options.extend([
            DhcpOption::new(opt::INTERFACE_MTU, 1492u16.to_be_bytes()),
            DhcpOption::new(
                opt::CLASSLESS_STATIC_ROUTE,
                [0, 192, 0, 2, 1, 8, 10, 0, 0, 0, 0],
            ),
            // T1 after T2: the defaults apply.
            DhcpOption::new(opt::RENEWAL_TIME, 590u32.to_be_bytes()),
            DhcpOption::new(opt::REBINDING_TIME, 100u32.to_be_bytes()),
        ]);
        deliver(&mut c, &reply(&request, msg::ACK, ADDRESS, options), t0);
        c.handle(Event::Timeout, t0 + PROBE_INTERVAL);
        let actions = c.handle(Event::Timeout, t0 + 2 * PROBE_INTERVAL);
        let [Action::Bind { lease, .. }] = &actions[..] else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.mtu, Some(1492));
        assert_eq!(
            lease.classless_routes,
            [
                ("0.0.0.0/0".parse().unwrap(), SERVER),
                ("10.0.0.0/8".parse().unwrap(), Ipv4Addr::UNSPECIFIED),
            ]
        );
        assert_eq!((lease.t1, lease.t2), (300, 525));
    }

    /// A lease is renewed and released as who took it. New options reach
    /// the next message, but not a new client identifier: that is a new
    /// identity, and the task starts a new client for it.
    #[test]
    fn the_identity_of_a_lease_does_not_change() {
        let t0 = Instant::now();
        let as_a = Options {
            client_id: Some(vec![0, b'A']),
            host_name: Some("one".into()),
            ..Default::default()
        };
        let mut c = client(as_a, t0);
        let bound = acquire(&mut c, t0, 3600);
        assert_eq!(c.identity(), (MAC, Some(&[0, b'A'][..])));

        c.set_options(Options {
            client_id: Some(vec![0, b'B']),
            host_name: Some("two".into()),
            ..Default::default()
        });
        assert_eq!(c.identity(), (MAC, Some(&[0, b'A'][..])));
        let renew = sent(&c.handle(Event::Renew, bound)).clone();
        assert_eq!(renew.option(opt::CLIENT_ID).unwrap().data, [0, b'A']);
        assert_eq!(renew.option(opt::HOST_NAME).unwrap().data, b"two");
        let release = sent(&c.handle(Event::Stop, bound)).clone();
        assert_eq!(release.message_type(), Some(msg::RELEASE));
        assert_eq!(release.option(opt::CLIENT_ID).unwrap().data, [0, b'A']);
        assert_eq!(release.ethernet_address(), Some(MAC));

        // Unset stays unset, too.
        let mut c = client(Options::default(), t0);
        c.set_options(Options {
            client_id: Some(vec![0, b'B']),
            ..Default::default()
        });
        assert_eq!(c.identity(), (MAC, None));
    }

    #[test]
    fn incomplete_acks() {
        let t0 = Instant::now();
        let mut c = client(Options::default(), t0);
        let discover = sent(&c.handle(Event::Carrier(true), t0)).clone();
        let request = sent(&deliver(
            &mut c,
            &reply(&discover, msg::OFFER, ADDRESS, vec![]),
            t0,
        ))
        .clone();
        // No lease time: not a lease.
        let actions = deliver(&mut c, &reply(&request, msg::ACK, ADDRESS, vec![]), t0);
        assert!(matches!(&actions[..], [Action::Log(_)]));
        assert_eq!(c.state(), State::Requesting);
        // No mask: the classful one, with a note. An infinite lease has
        // no timers.
        let options = vec![DhcpOption::new(opt::LEASE_TIME, INFINITE.to_be_bytes())];
        let actions = deliver(&mut c, &reply(&request, msg::ACK, ADDRESS, options), t0);
        assert!(
            matches!(&actions[..], [Action::Log(_), Action::Probe(_)]),
            "{actions:?}"
        );
        c.handle(Event::Timeout, t0 + PROBE_INTERVAL);
        let actions = c.handle(Event::Timeout, t0 + 2 * PROBE_INTERVAL);
        let [
            Action::Bind {
                lease,
                remaining: INFINITE,
                ..
            },
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        assert_eq!(lease.prefix_len, 24);
        assert_eq!(c.deadline(), None);
        assert_eq!(c.remaining(t0), None);
    }
}
