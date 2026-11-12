//! The DHCPv6 side of the DHCP client task: one [`Client`] state machine
//! per interface configured with `ipv6 address dhcpv6`,
//! `ipv6 dhcpv6-options pd` or `ipv6 dhcpv6-options parameters-only`,
//! driven by the socket, the clock, the RIB's link and address events
//! and the configuration.
//!
//! It shares the task ([`Dhcpc`]) and its event loop with DHCPv4 and
//! keeps its own state beside it ([`V6`]). Everything a lease gives goes
//! through the RIB:
//!
//! - each address as a dynamic /128 that brings no connected route
//!   (`AddrOrigin::Dhcp6`);
//! - each delegated prefix as a discard route in the interface's VRF
//!   ([`Dhcpc::sync_pd_routes`]);
//! - a /64 of a delegated prefix as a dynamic address on each interface
//!   `pd <id> interface` names (`AddrOrigin::Pd`,
//!   [`Dhcpc::sync_pd_lan`]), which brings its connected route.
//!
//! The default route and the on-link prefixes are the RA host's to
//! install (`nd`), not this client's.
//!
//! A client is one identity: its DUID and what it asks for (an address,
//! prefixes, or parameters only). When the configuration changes either,
//! or is deleted, the client is *retired*: it releases its lease as who
//! took it, and lives on beside its successor until the server has
//! answered the Release or it has been sent as often as it is to be.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

use dhcp_packet::v6::Message as Dhcp6Message;
use ipnet::{IpNet, Ipv6Net};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::Args;
use crate::dhcpc::ident::{self, DuidStore};
use crate::dhcpc::inst::{DEFAULT_DISTANCE, Dhcpc, LinkInfo, lifetime, report_dns, unix_now};
use crate::dhcpc::lease::Kept6;
use crate::fib::AddrOpts;
use crate::nd::host::eui64;
use crate::resolver::{LinkDns, Source};
use crate::rib::entry::RibEntry;
use crate::rib::link::{AddrOrigin, LinkAddr};
use crate::rib::{Message, Nexthop, RibType};

use super::client::{Action, Address, Asks, Client, Event, Lease, Options, PdAsk, Prefix, State};
use super::socket::{self, Input6, Socket6};

/// `interface <if> ipv6 address dhcpv6` and `… ipv6 dhcpv6-options …`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IfConfig6 {
    /// `ipv6 address dhcpv6` is set: lease an address.
    pub address: bool,
    /// `dhcpv6-options duid`: this interface's own DUID.
    pub duid: Option<Vec<u8>>,
    pub parameters_only: bool,
    pub rapid_commit: bool,
    pub no_release: bool,
    /// `dhcpv6-options pd <id>`: the delegations to ask for, by IAID.
    pub pd: BTreeMap<u32, PdConfig>,
    /// `no-name-server`: the name servers and search domains the server
    /// names are shown, not reported for the host's own use.
    pub no_name_server: bool,
}

/// `dhcpv6-options pd <id> …`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PdConfig {
    /// `length`: the prefix length to hint at.
    pub length: Option<u8>,
    /// `interface <if>`: the interfaces numbered from the delegation,
    /// by name. Not part of what the client asks a server for: they
    /// come and go while the prefix is held.
    pub interfaces: BTreeMap<String, LanConfig>,
}

/// `dhcpv6-options pd <id> interface <if> …`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LanConfig {
    /// `sla-id`: which /64 of the prefix; the first when not set.
    pub sla_id: Option<u32>,
    /// `address`: the host part. Not set, it is made from the
    /// interface's hardware address.
    pub address: Option<u64>,
}

/// Why an interface has no address from a delegated prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoAddress {
    /// There is no such interface (yet).
    NoLink,
    /// It is the interface the prefix is delegated on, which must not
    /// be numbered from it (RFC 8415 §6.3).
    Upstream,
    /// It is in another VRF than that interface.
    OtherVrf,
    /// The prefix is longer than a /64: it holds no /64 to give.
    NoSubnet,
    /// `sla-id` needs more bits than the prefix leaves up to the 64th
    /// (RFC 7084 WPD-3).
    SlaId,
    /// No `address`, and no hardware address to make one from.
    NoHardwareAddress,
}

impl std::fmt::Display for NoAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NoAddress::NoLink => "no such interface",
            NoAddress::Upstream => "the prefix is delegated on this interface",
            NoAddress::OtherVrf => "in another VRF",
            NoAddress::NoSubnet => "the prefix is longer than a /64",
            NoAddress::SlaId => "the prefix has no room for this sla-id",
            NoAddress::NoHardwareAddress => "no hardware address: set `address`",
        })
    }
}

/// The /64 of `prefix` that `sla_id` numbers: the bits from the prefix's
/// length up to the 64th.
pub fn subnet(prefix: Ipv6Net, sla_id: u32) -> Result<Ipv6Net, NoAddress> {
    let Some(bits) = 64u8.checked_sub(prefix.prefix_len()) else {
        return Err(NoAddress::NoSubnet);
    };
    if u64::from(sla_id).checked_shr(bits.into()).unwrap_or(0) != 0 {
        return Err(NoAddress::SlaId);
    }
    let network = u128::from(prefix.network()) | (u128::from(sla_id) << 64);
    Ok(Ipv6Net::new_assert(Ipv6Addr::from(network), 64))
}

/// The address `lan` gives an interface with hardware address `mac` in
/// `subnet`, a /64.
fn address_in(
    subnet: Ipv6Net,
    lan: &LanConfig,
    mac: Option<[u8; 6]>,
) -> Result<Ipv6Net, NoAddress> {
    let address = match lan.address {
        Some(host) => Ipv6Addr::from(u128::from(subnet.network()) | u128::from(host)),
        // A loopback's is all zeros, which names nobody.
        None => match mac.filter(|mac| mac.iter().any(|octet| *octet != 0)) {
            Some(mac) => eui64(subnet, mac),
            None => return Err(NoAddress::NoHardwareAddress),
        },
    };
    Ok(Ipv6Net::new_assert(address, 64))
}

/// One `pd <id> interface <if>` worked out for one prefix held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The delegation, and the prefix of it.
    pub id: u32,
    pub prefix: Ipv6Net,
    /// The interface to number, as configured.
    pub ifname: String,
    /// Its link and its address in its /64, or why it has none.
    pub address: Result<(u32, Ipv6Net), NoAddress>,
    /// The prefix's lifetimes, which are the address's.
    pub preferred: u32,
    pub valid: u32,
}

/// An address an interface holds from a delegated prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LanAddress {
    /// The interface the prefix is delegated on: the lease is its.
    upstream: String,
    /// The RIB is to be told of it again, though it has been: the
    /// lease's lifetimes moved, or the link came up and may have lost it.
    stale: bool,
}

/// The lifetime an address an earlier run left is claimed with, to be
/// deleted at once: were the deletion lost, it goes all the same.
const LEFTOVER_LIFETIME: u32 = 1;

/// The length hinted at when `pd <id> length` is not set (VyOS's
/// default).
const PD_LENGTH: u8 = 64;

impl IfConfig6 {
    /// Whether a client runs at all.
    pub fn wanted(&self) -> bool {
        self.address || self.parameters_only || !self.pd.is_empty()
    }

    fn options(&self) -> Options {
        Options {
            rapid_commit: self.rapid_commit,
            no_release: self.no_release,
        }
    }

    /// What the client of interface `name` asks for: an address with
    /// `address dhcpv6`, a prefix for each `pd`, and nothing but the
    /// other configuration with `parameters-only` alone. What is to be
    /// leased is asked for whenever it is configured: a commit holding
    /// `parameters-only` beside it is refused (`config::check`), and a
    /// startup config that does is taken this way.
    fn asks(&self, name: &str) -> Asks {
        let ia_pd = self.pd.iter().map(|(&iaid, pd)| PdAsk {
            iaid,
            length: pd.length.unwrap_or(PD_LENGTH),
        });
        Asks {
            ia_na: self.address.then(|| ident::iaid(name)),
            ia_pd: ia_pd.collect(),
        }
    }
}

/// A client and what it has put in the RIB.
pub struct Session {
    pub client: Client,
    /// The lease whose addresses and prefixes are in the RIB.
    pub bound: Option<Lease>,
    /// UNIX time the server last confirmed `bound`.
    pub obtained: Option<u64>,
}

/// A client on its way out (see the module documentation).
struct Retiring {
    session: Session,
    /// `Stop` has been handed to it. A lease read back from disk under
    /// another identity is first resumed, and stopped only once the
    /// link can carry its Release.
    stopped: bool,
}

/// One configured interface.
#[derive(Default)]
pub struct Iface6 {
    pub cfg: IfConfig6,
    /// The kernel link, while there is one.
    pub ifindex: Option<u32>,
    pub session: Option<Session>,
    retiring: Option<Retiring>,
    socket: Option<Socket6>,
    /// The socket could not be opened and that has been said once.
    socket_failed: bool,
}

/// Which of an interface's two clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Current,
    Retiring,
}

const SLOTS: [Slot; 2] = [Slot::Current, Slot::Retiring];

impl Iface6 {
    fn slot(&self, slot: Slot) -> Option<&Session> {
        match slot {
            Slot::Current => self.session.as_ref(),
            Slot::Retiring => self.retiring.as_ref().map(|retiring| &retiring.session),
        }
    }

    fn slot_mut(&mut self, slot: Slot) -> Option<&mut Session> {
        match slot {
            Slot::Current => self.session.as_mut(),
            Slot::Retiring => self.retiring.as_mut().map(|retiring| &mut retiring.session),
        }
    }

    /// Whether `slot`'s client has `address` in the RIB.
    fn holds(&self, slot: Slot, address: Ipv6Addr) -> bool {
        self.slot(slot)
            .and_then(|session| session.bound.as_ref())
            .is_some_and(|lease| addresses(lease).iter().any(|a| a.address == address))
    }
}

/// The DHCPv6 state of the task.
pub struct V6 {
    /// By interface name: configuration can precede the link.
    pub ifaces: BTreeMap<String, Iface6>,
    input_tx: UnboundedSender<Input6>,
    pub(in crate::dhcpc) input_rx: UnboundedReceiver<Input6>,
    /// Each interface's link-local addresses, and whether a message can
    /// leave from each: installed, and past duplicate address detection.
    link_locals: BTreeMap<u32, BTreeMap<Ipv6Addr, bool>>,
    /// The system DUID, once it has been read or made.
    duid: Option<Vec<u8>>,
    /// Interfaces whose configuration changed in the commit under way.
    pub(in crate::dhcpc) touched: Vec<String>,
    /// The discard routes the RIB was last told of: each delegated
    /// prefix, in a VRF's table (`None`: the default one).
    pd_routes: BTreeSet<(Option<String>, Ipv6Net)>,
    /// The addresses interfaces hold from delegated prefixes, as the RIB
    /// was last told: by link and address (`sync_pd_lan`).
    pd_lan: BTreeMap<(u32, Ipv6Net), LanAddress>,
    /// The `pd <id> interface` entries that give no address, each with
    /// the reason last said of it: by the interface the prefix is
    /// delegated on, the delegation, the prefix and the interface.
    pd_lan_refused: BTreeMap<(String, u32, Ipv6Net, String), NoAddress>,
    /// Addresses a lease read back from disk had given: the interface
    /// the lease is of, then the interface each is on, by name. They
    /// are still in the kernel, and nobody's until the next
    /// `sync_pd_lan` claims or removes them.
    pd_lan_left: Vec<(String, String, Ipv6Net)>,
    /// What the resolver task was last told, by interface (`sync_dns6`).
    reported_dns: BTreeMap<String, LinkDns>,
}

impl V6 {
    pub fn new() -> V6 {
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        V6 {
            ifaces: BTreeMap::new(),
            input_tx,
            input_rx,
            link_locals: BTreeMap::new(),
            duid: None,
            touched: Vec::new(),
            pd_routes: BTreeSet::new(),
            pd_lan: BTreeMap::new(),
            pd_lan_refused: BTreeMap::new(),
            pd_lan_left: Vec::new(),
            reported_dns: BTreeMap::new(),
        }
    }
}

/// What a server said of name servers, if anything: the servers (option
/// 23) and the search list (option 24). The same for a lease and for
/// what `parameters-only` was given without one.
fn lease_dns6(lease: &Lease) -> Option<LinkDns> {
    let dns = LinkDns {
        servers: lease.dns_servers.iter().copied().map(IpAddr::V6).collect(),
        domains: lease.domain_list.clone(),
    };
    (dns != LinkDns::default()).then_some(dns)
}

fn addresses(lease: &Lease) -> &[Address] {
    lease
        .ia_na
        .as_ref()
        .map_or(&[], |ia| ia.addresses.as_slice())
}

/// The delegated prefixes of a lease, whichever delegation each is of.
fn prefixes(lease: &Lease) -> impl Iterator<Item = &Prefix> {
    lease.ia_pd.iter().flat_map(|ia| ia.prefixes.iter())
}

/// What a lease holds as the log names it: its addresses, then its
/// prefixes.
fn address_list(lease: &Lease) -> String {
    let addresses = addresses(lease).iter().map(|a| a.address.to_string());
    let prefixes = prefixes(lease).map(|p| p.prefix.to_string());
    let list: Vec<String> = addresses.chain(prefixes).collect();
    list.join(", ")
}

/// The route that holds a delegated prefix: what of it is in use has
/// more specific routes, and the rest goes nowhere.
fn discard() -> RibEntry {
    let mut entry = RibEntry::new(RibType::DhcpClient);
    entry.distance = DEFAULT_DISTANCE;
    entry.nexthop = Nexthop::Blackhole(0);
    entry
}

/// A leased address as the RIB holds it: a host address.
fn host(address: Ipv6Addr) -> IpNet {
    IpNet::V6(Ipv6Net::from(address))
}

impl Dhcpc {
    /// Whether DHCPv6 can be spoken on `ifindex`: the link is up and has
    /// a link-local address to send from.
    fn ready6(&self, ifindex: u32) -> bool {
        self.links.get(&ifindex).is_some_and(|link| link.up)
            && self
                .v6
                .link_locals
                .get(&ifindex)
                .is_some_and(|addresses| addresses.values().any(|usable| *usable))
    }

    /// The earliest timer of any DHCPv6 client.
    pub(in crate::dhcpc) fn next_deadline6(&self) -> Option<Instant> {
        self.v6
            .ifaces
            .values()
            .flat_map(|iface| SLOTS.map(|slot| iface.slot(slot)))
            .flatten()
            .filter_map(|session| session.client.deadline())
            .min()
    }

    pub(in crate::dhcpc) fn process_timeouts6(&mut self, now: Instant) {
        let due: Vec<(String, Slot)> = self
            .v6
            .ifaces
            .iter()
            .flat_map(|(name, iface)| SLOTS.map(|slot| (name, slot, iface.slot(slot))))
            .filter(|(_, _, session)| {
                session
                    .and_then(|session| session.client.deadline())
                    .is_some_and(|at| at <= now)
            })
            .map(|(name, slot, _)| (name.clone(), slot))
            .collect();
        for (name, slot) in due {
            self.with_iface6(&name, |dhcpc, ifindex, iface| {
                dhcpc.feed6(&name, ifindex, iface, slot, Event::Timeout, now);
            });
        }
    }

    pub(in crate::dhcpc) fn process_input6(&mut self, input: Input6) {
        let Some(name) = self.links.get(&input.ifindex).map(|link| link.name.clone()) else {
            return;
        };
        // A relay's envelope is not for a client.
        let Ok(Dhcp6Message::Client(message)) = Dhcp6Message::parse(&input.payload) else {
            return;
        };
        let now = Instant::now();
        self.with_iface6(&name, |dhcpc, ifindex, iface| {
            // Each client knows its own transactions.
            for slot in SLOTS {
                let event = Event::Message {
                    message: &message,
                    source: input.source,
                };
                dhcpc.feed6(&name, ifindex, iface, slot, event, now);
            }
        });
    }

    /// A link appeared, or is described anew, with the IPv6 addresses it
    /// has.
    pub(in crate::dhcpc) fn link_added6(&mut self, ifindex: u32, name: &str, addr6: &[LinkAddr]) {
        let link_locals = addr6
            .iter()
            .filter_map(link_local_state)
            .collect::<BTreeMap<_, _>>();
        self.v6.link_locals.insert(ifindex, link_locals);
        self.reconcile6(name);
        self.sync_link6(name);
        self.start_waiting6();
        // The link may be a VRF that a client's interface is in, known
        // only now: the routes go to its table. Or an interface that is
        // to be numbered from a delegation.
        self.sync_pd();
    }

    /// A link's hardware address changed, or it has one now.
    pub(in crate::dhcpc) fn link_mac6(&mut self, name: &str) {
        self.reconcile6(name);
        self.start_waiting6();
        // An address made from it is another now.
        self.sync_pd();
    }

    /// A link came up. An interface numbered from a delegation may have
    /// lost its address meanwhile: the kernel takes a link's IPv6
    /// addresses away when it is set down, and one added to a link that
    /// is down has no route to its /64. So the RIB is told again.
    pub(in crate::dhcpc) fn link_up6(&mut self, ifindex: u32) {
        for ((link, _), held) in self.v6.pd_lan.iter_mut() {
            if *link == ifindex {
                held.stale = true;
            }
        }
        self.sync_pd_lan();
    }

    /// Look again at the clients that could not start because the system
    /// DUID has to be made and no interface had a hardware address to
    /// make it from (`duid_for`). The address may now be there, and on
    /// any interface: the event that brought it reconciles only its own.
    ///
    /// Also when the system has its DUID by now: the interface that
    /// brought the address may have been waiting itself, and its own
    /// reconciling has then just made the DUID the others wait for.
    fn start_waiting6(&mut self) {
        let waiting: Vec<String> = self
            .v6
            .ifaces
            .iter()
            .filter(|(_, iface)| {
                iface.session.is_none() && iface.cfg.wanted() && iface.cfg.duid.is_none()
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in waiting {
            self.reconcile6(&name);
        }
    }

    /// The link is gone (deleted, or moved to another VRF, which the RIB
    /// reports as a delete and an add): drop the binding without a
    /// Release. A link coming back starts from scratch.
    pub(in crate::dhcpc) fn link_deleted6(&mut self, ifindex: u32, name: &str) {
        self.v6.link_locals.remove(&ifindex);
        let Some(mut iface) = self.v6.ifaces.remove(name) else {
            // A VRF a client's interface was in, perhaps, or an
            // interface numbered from a delegation. Its address is
            // taken back like any that is no longer wanted: a link that
            // only moved to another VRF still has it.
            self.sync_pd();
            return;
        };
        for slot in SLOTS {
            if let Some(lease) = iface
                .slot_mut(slot)
                .and_then(|session| session.bound.take())
            {
                for address in addresses(&lease) {
                    self.withdraw6(ifindex, address.address);
                }
            }
        }
        iface.session = None;
        iface.retiring = None;
        iface.ifindex = None;
        self.store.remove6(name);
        self.finish6(name, iface);
    }

    /// Tell `name`'s clients whether the interface can carry DHCPv6 now.
    /// Called on every event that may have changed that.
    pub(in crate::dhcpc) fn sync_link6(&mut self, name: &str) {
        let now = Instant::now();
        self.with_iface6(name, |dhcpc, ifindex, iface| {
            let ready = dhcpc.ready6(ifindex);
            dhcpc.feed6(name, ifindex, iface, Slot::Current, Event::Link(ready), now);
            dhcpc.pump_retiring6(name, ifindex, iface, now);
        });
    }

    /// An IPv6 address appeared, changed or went away.
    pub(in crate::dhcpc) fn addr_event6(&mut self, addr: &LinkAddr, add: bool) {
        let IpNet::V6(net) = addr.addr else {
            return;
        };
        let Some(name) = self.links.get(&addr.ifindex).map(|link| link.name.clone()) else {
            return;
        };
        if let Some((address, usable)) = link_local_state(addr) {
            let link_locals = self.v6.link_locals.entry(addr.ifindex).or_default();
            if add {
                link_locals.insert(address, usable);
            } else {
                link_locals.remove(&address);
            }
            self.sync_link6(&name);
            return;
        }
        // An address an interface holds from a delegation: there is
        // nobody to decline it to, as there is for a leased one, and
        // the kernel does not use it.
        if add && addr.flags.dadfailed && self.v6.pd_lan.contains_key(&(addr.ifindex, net)) {
            tracing::warn!(
                "dhcpv6 client: {name}: {net} failed duplicate address detection: another node on the link has it; give the interface another `address`"
            );
        }
        // A leased address is on the interface as a /128. The same
        // address under another length is somebody else's entry.
        if net.prefix_len() != 128 {
            return;
        }
        let address = net.addr();
        let now = Instant::now();
        self.with_iface6(&name, |dhcpc, ifindex, iface| {
            for slot in SLOTS {
                if !iface.holds(slot, address) {
                    continue;
                }
                if !add {
                    // The kernel dropped a leased address (our own
                    // withdrawal forgets it first).
                    let event = Event::AddressLost(address);
                    dhcpc.feed6(name.as_str(), ifindex, iface, slot, event, now);
                } else if addr.flags.dadfailed {
                    let event = Event::AddressConflict(address);
                    dhcpc.feed6(name.as_str(), ifindex, iface, slot, event, now);
                } else if !addr.config && addr.valid_lft == Some(u32::MAX) {
                    // The configuration named the leased address too,
                    // which made it permanent in the kernel, and has now
                    // let go of it: the lease owns it alone again, so
                    // its lifetimes go back on.
                    let current = iface
                        .slot(slot)
                        .and_then(|session| session.client.lease(now));
                    if let Some(lease) = current
                        && let Some(leased) =
                            addresses(&lease).iter().find(|a| a.address == address)
                        && leased.valid != u32::MAX
                    {
                        dhcpc.install6(ifindex, leased);
                    }
                }
            }
        });
    }

    /// Bring `name`'s client in line with its configuration and its
    /// link: start it, retire it, or hand it changed options.
    pub(in crate::dhcpc) fn reconcile6(&mut self, name: &str) {
        let now = Instant::now();
        let Some(mut iface) = self.v6.ifaces.remove(name) else {
            return;
        };
        let link = self
            .links
            .iter()
            .find(|(_, link)| link.name == name)
            .map(|(ifindex, link)| (*ifindex, link.mac));
        // Without a link the configuration waits (`link_deleted6` has
        // seen to a client there was).
        if let Some((ifindex, mac)) = link {
            iface.ifindex = Some(ifindex);
            let wanted = iface.cfg.wanted();
            let options = iface.cfg.options();
            let identity = if wanted {
                self.duid_for(&iface.cfg, mac)
                    .map(|duid| (duid, iface.cfg.asks(name)))
            } else {
                None
            };
            // A client is one DUID and one set of things asked for
            // (`Client::identity`). When the configuration gives the
            // interface another, or takes the client away, the lease
            // goes back as who took it.
            let stale = match (&iface.session, &identity) {
                (None, _) => false,
                (Some(_), None) => !wanted,
                (Some(session), Some((duid, asks))) => {
                    session.client.identity() != (duid.as_slice(), asks)
                }
            };
            // A client that has not been stopped yet stops under the
            // options as they are now: `no-release` set in the commit
            // that takes the client away is meant for that client.
            // (What it asks for and as whom are not options.)
            if let Some(retiring) = iface.retiring.as_mut()
                && !retiring.stopped
            {
                retiring.session.client.set_options(options.clone());
            }
            if stale {
                if wanted {
                    tracing::info!(
                        "dhcpv6 client: {name}: the client's identity or what it asks for changed; what the old one holds is released"
                    );
                } else {
                    tracing::info!("dhcpv6 client: {name}: stopped");
                }
                if let Some(session) = iface.session.as_mut() {
                    session.client.set_options(options.clone());
                }
                self.retire6(name, ifindex, &mut iface, now);
            }
            if let Some((duid, iaid)) = identity {
                match iface.session.as_mut() {
                    Some(session) => session.client.set_options(options),
                    None => self.start6(name, ifindex, &mut iface, (duid, iaid), options, now),
                }
            }
        }
        self.finish6(name, iface);
    }

    /// The DUID `cfg` asks for: its own, or the system's, which is read
    /// from disk or made on first use. `None` when it has to be made and
    /// no hardware address is known yet to make it from.
    fn duid_for(&mut self, cfg: &IfConfig6, mac: Option<[u8; 6]>) -> Option<Vec<u8>> {
        if let Some(duid) = &cfg.duid {
            return Some(duid.clone());
        }
        if self.v6.duid.is_none() {
            let store = DuidStore::new(self.store.dir());
            let duid = match store.load() {
                // The one on disk is who the system is, whatever
                // interfaces it has now: reading it takes no hardware
                // address.
                Ok(Some(duid)) => duid,
                // There is none, or the file cannot be read: one is
                // made, which does take a hardware address. The
                // interface's own, or else the first one there is.
                loaded => {
                    let real = |mac: &[u8; 6]| mac.iter().any(|octet| *octet != 0);
                    let mac = mac
                        .filter(real)
                        .or_else(|| self.links.values().find_map(|link| link.mac.filter(real)))?;
                    let made = match loaded {
                        Ok(_) => store.create(mac, unix_now()),
                        // Not replaced: the error says nothing about
                        // what the file holds.
                        Err(e) => Err(e),
                    };
                    made.unwrap_or_else(|e| {
                        tracing::warn!(
                            "dhcpv6 client: the system DUID cannot be kept in {}: {e}; using one that will not survive a restart",
                            self.store.dir().display()
                        );
                        ident::duid_llt(mac, unix_now())
                    })
                }
            };
            tracing::info!("dhcpv6 client: system DUID {}", ident::format_duid(&duid));
            self.v6.duid = Some(duid);
        }
        self.v6.duid.clone()
    }

    /// Start a client for `iface` as `identity`, resuming the lease on
    /// disk when that identity took it.
    fn start6(
        &mut self,
        name: &str,
        ifindex: u32,
        iface: &mut Iface6,
        (duid, asks): (Vec<u8>, Asks),
        options: Options,
        now: Instant,
    ) {
        let unix = unix_now();
        let mut resume = None;
        let mut left = Vec::new();
        if let Some(mut kept) = self.store.load6(name, unix) {
            left = std::mem::take(&mut kept.lan);
            // Ours when it was taken as who the interface is now: the
            // same DUID, asking for the same.
            if kept.duid == duid && kept.asks == asks {
                resume = Some(kept);
            } else {
                self.retire_saved6(name, ifindex, iface, kept, now);
            }
        }
        let client = Client::new(duid, asks, options, Box::new(rand::random::<u32>));
        let mut session = Session {
            client,
            bound: None,
            obtained: None,
        };
        let mut actions = Vec::new();
        if let Some(kept) = resume {
            session.obtained = Some(unix.saturating_sub(u64::from(kept.elapsed)));
            actions = session.client.handle(
                Event::Resume {
                    lease: kept.lease,
                    elapsed: kept.elapsed,
                },
                now,
            );
            if actions.is_empty() {
                // It ran out while we were away.
                self.store.remove6(name);
                session.obtained = None;
            }
        }
        if self.ready6(ifindex) {
            actions.extend(session.client.handle(Event::Link(true), now));
        }
        iface.session = Some(session);
        tracing::info!("dhcpv6 client: {name}: started");
        self.carry_out6(name, ifindex, iface, Slot::Current, actions);
        // The addresses that lease gave interfaces are still in the
        // kernel, as long as the prefix each is of has not run out
        // (their lifetimes are the prefix's). Whoever holds the lease
        // now, `sync_pd_lan` claims the ones still wanted and removes
        // the rest.
        let held: Vec<Ipv6Net> = SLOTS
            .iter()
            .filter_map(|slot| iface.slot(*slot)?.bound.as_ref())
            .flat_map(prefixes)
            .map(|prefix| prefix.prefix)
            .collect();
        left.retain(|(_, address)| held.iter().any(|prefix| prefix.contains(&address.addr())));
        let left = left.into_iter();
        self.v6
            .pd_lan_left
            .extend(left.map(|(ifname, address)| (name.to_string(), ifname, address)));
    }

    /// Stop `iface`'s client for good. A lease it holds is withdrawn and
    /// released as the identity that took it; while the Release is under
    /// way the client stays, as the retiring one.
    fn retire6(&mut self, name: &str, ifindex: u32, iface: &mut Iface6, now: Instant) {
        self.end_retiring6(name, ifindex, iface, now);
        self.feed6(name, ifindex, iface, Slot::Current, Event::Stop, now);
        if let Some(session) = iface.session.take()
            && !session.client.finished()
        {
            iface.retiring = Some(Retiring {
                session,
                stopped: true,
            });
        }
    }

    /// The lease on disk was taken under another identity, or the
    /// interface no longer asks for an address: the DUID or the mode
    /// changed while zebra-rs was not running. It is not ours to renew
    /// as who the interface is now, and it must not be left allocated
    /// either. So it is resumed as who took it, which claims its
    /// addresses, and released as that identity as soon as the link can
    /// carry the Release (`pump_retiring6`).
    fn retire_saved6(
        &mut self,
        name: &str,
        ifindex: u32,
        iface: &mut Iface6,
        kept: Kept6,
        now: Instant,
    ) {
        // The file is the next lease's from here on.
        self.store.remove6(name);
        let options = Options {
            no_release: iface.cfg.no_release,
            ..Options::default()
        };
        let mut client = Client::new(kept.duid, kept.asks, options, Box::new(rand::random::<u32>));
        let actions = client.handle(
            Event::Resume {
                lease: kept.lease,
                elapsed: kept.elapsed,
            },
            now,
        );
        if actions.is_empty() {
            // It has run out: nothing to give back.
            return;
        }
        tracing::info!(
            "dhcpv6 client: {name}: the saved lease was taken under another identity; releasing it"
        );
        self.end_retiring6(name, ifindex, iface, now);
        iface.retiring = Some(Retiring {
            session: Session {
                client,
                bound: None,
                obtained: None,
            },
            stopped: false,
        });
        self.carry_out6(name, ifindex, iface, Slot::Retiring, actions);
        self.pump_retiring6(name, ifindex, iface, now);
    }

    /// Move the retiring client along with the link. One that still
    /// holds a saved lease is stopped once the link can carry its
    /// Release; one whose Release is under way ends it when the link
    /// goes.
    fn pump_retiring6(&mut self, name: &str, ifindex: u32, iface: &mut Iface6, now: Instant) {
        let ready = self.ready6(ifindex);
        let Some(retiring) = iface.retiring.as_ref() else {
            return;
        };
        if retiring.stopped {
            let event = Event::Link(ready);
            self.feed6(name, ifindex, iface, Slot::Retiring, event, now);
        } else if ready {
            self.stop_retiring6(name, ifindex, iface, now);
        }
    }

    /// Stop the retiring client, if it has not been stopped yet (it
    /// holds a saved lease and waits for the link): what it holds is
    /// withdrawn now, and its Release goes out if the link can carry it.
    /// It then stays until that Release is over, like any retiring
    /// client.
    fn stop_retiring6(&mut self, name: &str, ifindex: u32, iface: &mut Iface6, now: Instant) {
        if !iface.retiring.as_ref().is_some_and(|r| !r.stopped) {
            return;
        }
        let link = Event::Link(self.ready6(ifindex));
        self.feed6(name, ifindex, iface, Slot::Retiring, link, now);
        self.feed6(name, ifindex, iface, Slot::Retiring, Event::Stop, now);
        if let Some(retiring) = iface.retiring.as_mut() {
            retiring.stopped = true;
        }
    }

    /// Make room for another retiring client: the one there is stopped,
    /// if it has not been, and dropped. Its Release has gone out once if
    /// the link allowed.
    fn end_retiring6(&mut self, name: &str, ifindex: u32, iface: &mut Iface6, now: Instant) {
        self.stop_retiring6(name, ifindex, iface, now);
        iface.retiring = None;
    }

    /// Take `name`'s interface out of the map for `f`, when it has a
    /// link, and put it back in the state `f` left it.
    fn with_iface6(&mut self, name: &str, f: impl FnOnce(&mut Dhcpc, u32, &mut Iface6)) {
        let Some(mut iface) = self.v6.ifaces.remove(name) else {
            return;
        };
        if let Some(ifindex) = iface.ifindex {
            f(self, ifindex, &mut iface);
        }
        self.finish6(name, iface);
    }

    /// Put `iface` back, without what it no longer needs: a retiring
    /// client that is done, a socket nobody listens on, or the entry
    /// itself when neither configuration nor client is left.
    fn finish6(&mut self, name: &str, mut iface: Iface6) {
        let done = |retiring: &Retiring| {
            let client = &retiring.session.client;
            // Finished, or its lease ran out before it could be stopped.
            client.finished()
                || (client.state() == State::Stopped && retiring.session.bound.is_none())
        };
        if iface.retiring.as_ref().is_some_and(done) {
            iface.retiring = None;
        }
        let listening = SLOTS
            .iter()
            .filter_map(|slot| iface.slot(*slot))
            .any(|session| session.client.wants_socket());
        if !listening {
            iface.socket = None;
        }
        if iface.cfg != IfConfig6::default() || iface.session.is_some() || iface.retiring.is_some()
        {
            self.v6.ifaces.insert(name.to_string(), iface);
        }
        // Every change to a client or its configuration ends here.
        self.sync_pd();
        self.sync_dns6();
    }

    /// What follows the delegated prefixes held: their discard routes,
    /// and the addresses of the interfaces numbered from them.
    fn sync_pd(&mut self) {
        self.sync_pd_routes();
        self.sync_pd_lan();
    }

    /// Hand the RIB a discard route for each delegated prefix held, in
    /// the table of the VRF the interface is in, and take back those of
    /// prefixes no longer held. After every event that may have changed
    /// a lease or its interface.
    ///
    /// RFC 7084 WPD-5: a packet for a part of the prefix that is not in
    /// use must not follow the default route back to the router that
    /// delegated it, which would send it here again. The route stays
    /// while the lease is held, link up or down: the prefix is still
    /// this router's.
    pub(in crate::dhcpc) fn sync_pd_routes(&mut self) {
        let mut wanted = BTreeSet::new();
        for iface in self.v6.ifaces.values() {
            let Some(ifindex) = iface.ifindex else {
                continue;
            };
            let vrf = self.vrf_of(ifindex);
            let sessions = SLOTS.iter().filter_map(|slot| iface.slot(*slot));
            let leases = sessions.filter_map(|session| session.bound.as_ref());
            for prefix in leases.flat_map(prefixes) {
                wanted.insert((vrf.clone(), prefix.prefix));
            }
        }
        for (vrf, prefix) in self.v6.pd_routes.difference(&wanted) {
            let rib = RibEntry::new(RibType::DhcpClient);
            let prefix = *prefix;
            let _ = self.rib.send(match vrf.clone() {
                Some(vrf) => Message::Ipv6DelVrf { vrf, prefix, rib },
                None => Message::Ipv6Del { prefix, rib },
            });
        }
        for (vrf, prefix) in wanted.difference(&self.v6.pd_routes) {
            let rib = discard();
            let prefix = *prefix;
            let _ = self.rib.send(match vrf.clone() {
                Some(vrf) => Message::Ipv6AddVrf { vrf, prefix, rib },
                None => Message::Ipv6Add { prefix, rib },
            });
        }
        self.v6.pd_routes = wanted;
    }

    /// The link named `name`, if there is one.
    fn link_named(&self, name: &str) -> Option<(u32, &LinkInfo)> {
        let mut links = self.links.iter();
        links
            .find(|(_, link)| link.name == name)
            .map(|(ifindex, link)| (*ifindex, link))
    }

    /// The VRF device `ifindex` is in, or is. A master the task has not
    /// heard of yet counts as one: a link dump names a member before its
    /// VRF.
    fn vrf_device(&self, ifindex: u32) -> Option<u32> {
        let link = self.links.get(&ifindex)?;
        if link.is_vrf {
            return Some(ifindex);
        }
        let master = link.master?;
        match self.links.get(&master) {
            Some(link) if !link.is_vrf => None,
            _ => Some(master),
        }
    }

    /// The address `lan` gives the interface `ifname` in `prefix`, which
    /// is delegated on `upstream`, with the link it goes on.
    fn lan_address(
        &self,
        upstream: u32,
        ifname: &str,
        lan: &LanConfig,
        prefix: Ipv6Net,
    ) -> Result<(u32, Ipv6Net), NoAddress> {
        let (ifindex, link) = self.link_named(ifname).ok_or(NoAddress::NoLink)?;
        if ifindex == upstream {
            return Err(NoAddress::Upstream);
        }
        // The prefix is routed to this router in the VRF it was asked
        // for in, and its discard route is in that table.
        if self.vrf_device(ifindex) != self.vrf_device(upstream) {
            return Err(NoAddress::OtherVrf);
        }
        let subnet = subnet(prefix, lan.sla_id.unwrap_or(0))?;
        Ok((ifindex, address_in(subnet, lan, link.mac)?))
    }

    /// What `iface`'s delegations give the interfaces configured under
    /// them: one entry for each `pd <id> interface` and each prefix the
    /// delegation holds, with the prefix's lifetimes as they stand at
    /// `now`.
    ///
    /// By the lease of the current client only. One on its way out holds
    /// its lease to give it back, and what it was delegated numbers
    /// nothing any more.
    pub(in crate::dhcpc) fn assignments6(&self, iface: &Iface6, now: Instant) -> Vec<Assignment> {
        let mut out = Vec::new();
        let (Some(upstream), Some(session)) = (iface.ifindex, &iface.session) else {
            return out;
        };
        // What is in the RIB, with the time it has left now.
        let Some(lease) = session
            .bound
            .as_ref()
            .and_then(|_| session.client.lease(now))
        else {
            return out;
        };
        for ia in &lease.ia_pd {
            let Some(pd) = iface.cfg.pd.get(&ia.iaid) else {
                continue;
            };
            for prefix in &ia.prefixes {
                for (ifname, lan) in &pd.interfaces {
                    out.push(Assignment {
                        id: ia.iaid,
                        prefix: prefix.prefix,
                        ifname: ifname.clone(),
                        address: self.lan_address(upstream, ifname, lan, prefix.prefix),
                        preferred: prefix.preferred,
                        valid: prefix.valid,
                    });
                }
            }
        }
        out
    }

    /// The addresses `upstream`'s delegations have given, as its lease
    /// file names them: by the name of the interface each is on.
    fn lan_record(&self, upstream: &str) -> Vec<(String, Ipv6Net)> {
        let mut record = Vec::new();
        for ((ifindex, address), held) in &self.v6.pd_lan {
            if held.upstream == upstream
                && let Some(link) = self.links.get(ifindex)
            {
                record.push((link.name.clone(), *address));
            }
        }
        record
    }

    /// Give each interface `pd <id> interface` names its address in a
    /// /64 of each prefix that delegation holds, and take back the
    /// addresses of prefixes, of configuration and of links that are no
    /// more. After every event that may have changed a lease, an
    /// interface or the configuration.
    ///
    /// An address has its prefix's lifetimes, and the kernel counts them
    /// down: it is handed over again when the lease's times move (a
    /// renewal), not otherwise. Unlike a leased address it brings its
    /// connected route. The /64 is this router's to put on the link, and
    /// that route is what takes its traffic off the prefix's discard
    /// route.
    ///
    /// An address the kernel loses meanwhile (an operator deletes it, or
    /// sets the link down) comes back with the next renewal, or when the
    /// link comes up (`link_up6`).
    pub(in crate::dhcpc) fn sync_pd_lan(&mut self) {
        let now = Instant::now();
        let mut wanted: BTreeMap<(u32, Ipv6Net), (String, AddrOpts)> = BTreeMap::new();
        let mut refused = BTreeMap::new();
        for (upstream, iface) in &self.v6.ifaces {
            for assignment in self.assignments6(iface, now) {
                match assignment.address {
                    Ok(key) => {
                        let opts = AddrOpts {
                            valid_lft: assignment.valid,
                            preferred_lft: assignment.preferred,
                            noprefixroute: false,
                            broadcast: None,
                        };
                        wanted.insert(key, (upstream.clone(), opts));
                    }
                    Err(reason) => {
                        let Assignment {
                            id, prefix, ifname, ..
                        } = assignment;
                        refused.insert((upstream.clone(), id, prefix, ifname), reason);
                    }
                }
            }
        }
        // Each reason is said once, when it comes to be: here the
        // operator learns that a line of the configuration does nothing.
        // (An interface that is not there yet is how a configuration
        // starts.)
        for (key, reason) in &refused {
            if *reason == NoAddress::NoLink || self.v6.pd_lan_refused.get(key) == Some(reason) {
                continue;
            }
            let (upstream, id, prefix, ifname) = key;
            tracing::warn!(
                "dhcpv6 client: {upstream}: pd {id} interface {ifname} gets no address from {prefix}: {reason}"
            );
        }
        self.v6.pd_lan_refused = refused;

        // What an earlier run left in the kernel. The RIB read it back
        // as nobody's: one that is wanted is claimed below like any new
        // one, and the others are claimed here so that they can be
        // removed.
        let mut changed: BTreeSet<String> = BTreeSet::new();
        for (upstream, ifname, address) in std::mem::take(&mut self.v6.pd_lan_left) {
            // Whatever becomes of it, the lease file is to name what is
            // held from here on.
            changed.insert(upstream);
            let Some((ifindex, _)) = self.link_named(&ifname) else {
                continue;
            };
            if wanted.contains_key(&(ifindex, address)) {
                continue;
            }
            let _ = self.rib.send(Message::AddrDynAdd {
                ifindex,
                addr: IpNet::V6(address),
                origin: AddrOrigin::Pd,
                opts: AddrOpts {
                    valid_lft: LEFTOVER_LIFETIME,
                    preferred_lft: 0,
                    noprefixroute: false,
                    broadcast: None,
                },
            });
            self.withdraw_lan(ifindex, address);
            tracing::info!("dhcpv6 client: {ifname}: {address} of an earlier lease removed");
        }

        // The old before the new: a prefix that changed leaves first.
        for ((ifindex, address), held) in &self.v6.pd_lan {
            if wanted.contains_key(&(*ifindex, *address)) {
                continue;
            }
            self.withdraw_lan(*ifindex, *address);
            if let Some(link) = self.links.get(ifindex) {
                tracing::info!("dhcpv6 client: {}: {address} withdrawn", link.name);
            }
            changed.insert(held.upstream.clone());
        }
        for ((ifindex, address), (upstream, opts)) in &wanted {
            let held = self.v6.pd_lan.get(&(*ifindex, *address));
            if held.is_some_and(|held| !held.stale && held.upstream == *upstream) {
                continue;
            }
            let _ = self.rib.send(Message::AddrDynAdd {
                ifindex: *ifindex,
                addr: IpNet::V6(*address),
                origin: AddrOrigin::Pd,
                opts: *opts,
            });
            if held.is_none() {
                if let Some(link) = self.links.get(ifindex) {
                    tracing::info!(
                        "dhcpv6 client: {}: {address} from the prefix delegated on {upstream}, valid {}",
                        link.name,
                        lifetime(opts.valid_lft),
                    );
                }
                changed.insert(upstream.clone());
            }
        }
        self.v6.pd_lan = wanted
            .into_iter()
            .map(|(key, (upstream, _))| {
                let held = LanAddress {
                    upstream,
                    stale: false,
                };
                (key, held)
            })
            .collect();
        // The lease file names them, for the run after this one.
        for upstream in changed {
            let record = self.lan_record(&upstream);
            if let Err(e) = self.store.set_lan6(&upstream, &record) {
                tracing::warn!("dhcpv6 client: {upstream}: lease file not updated: {e}");
            }
        }
    }

    fn withdraw_lan(&self, ifindex: u32, address: Ipv6Net) {
        let _ = self.rib.send(Message::AddrDynDel {
            ifindex,
            addr: IpNet::V6(address),
            origin: AddrOrigin::Pd,
        });
    }

    /// Tell the resolver task what the clients now say of name servers:
    /// every change, once. They are the host's own unless the interface
    /// has `dhcpv6-options no-name-server`: set while they are held, it
    /// takes them back; deleted, it gives the held ones.
    ///
    /// Only the current client says anything. One on its way out holds
    /// a lease only to release it (one saved under another DUID, until
    /// the link can carry the Release), as a DHCPv4 lease on its way
    /// back says nothing either.
    fn sync_dns6(&mut self) {
        let Some(resolver) = &self.resolver else {
            return;
        };
        let mut now = BTreeMap::new();
        for (name, iface) in &self.v6.ifaces {
            if iface.cfg.no_name_server {
                continue;
            }
            let held = iface.session.as_ref().and_then(|s| s.bound.as_ref());
            if let Some(dns) = held.and_then(lease_dns6) {
                now.insert(name.clone(), dns);
            }
        }
        report_dns(resolver, Source::Dhcp6, &mut self.v6.reported_dns, now);
    }

    /// Feed `event` to `slot`'s client and carry out what it asks for.
    fn feed6(
        &mut self,
        name: &str,
        ifindex: u32,
        iface: &mut Iface6,
        slot: Slot,
        event: Event<'_>,
        now: Instant,
    ) {
        let Some(session) = iface.slot_mut(slot) else {
            return;
        };
        let actions = session.client.handle(event, now);
        self.carry_out6(name, ifindex, iface, slot, actions);
    }

    fn carry_out6(
        &mut self,
        name: &str,
        ifindex: u32,
        iface: &mut Iface6,
        slot: Slot,
        actions: Vec<Action>,
    ) {
        let Iface6 {
            session,
            retiring,
            socket,
            socket_failed,
            ..
        } = iface;
        let session = match slot {
            Slot::Current => session.as_mut(),
            Slot::Retiring => retiring.as_mut().map(|retiring| &mut retiring.session),
        };
        let Some(session) = session else {
            return;
        };
        // Open what the new state needs before sending through it.
        if session.client.wants_socket() && socket.is_none() {
            match socket::open(ifindex, name, self.v6.input_tx.clone()) {
                Ok(opened) => {
                    *socket = Some(opened);
                    *socket_failed = false;
                }
                // Said once; the next event tries again.
                Err(e) if !*socket_failed => {
                    tracing::warn!("dhcpv6 client: {name}: UDP socket: {e}");
                    *socket_failed = true;
                }
                Err(_) => {}
            }
        }
        for action in actions {
            match action {
                Action::Send(message) => {
                    if let (Some(socket), Ok(payload)) = (socket.as_ref(), message.emit())
                        && let Err(e) = socket.send(&payload)
                    {
                        tracing::debug!("dhcpv6 client: {name}: send failed: {e}");
                    }
                }
                Action::Bind { lease, fresh } => {
                    // The file is the current client's (see `Unbind`
                    // below): a retiring one's lease is on its way out,
                    // and written again it would come back at the next
                    // start.
                    let save = fresh && slot == Slot::Current;
                    self.bind6(name, ifindex, session, lease, fresh, save);
                }
                Action::Unbind => {
                    if let Some(lease) = session.bound.take() {
                        for address in addresses(&lease) {
                            self.withdraw6(ifindex, address.address);
                        }
                        if lease.has_leases() {
                            tracing::info!(
                                "dhcpv6 client: {name}: {} withdrawn",
                                address_list(&lease)
                            );
                        }
                    }
                    session.obtained = None;
                    // The file is the current client's: a retiring one's
                    // went when it retired.
                    if slot == Slot::Current {
                        self.store.remove6(name);
                    }
                }
                Action::Log(text) => tracing::info!("dhcpv6 client: {name}: {text}"),
            }
        }
    }

    /// Put `lease` in the RIB in place of what `session` had there, and
    /// with `save` on disk. `fresh` says a server has just confirmed it;
    /// otherwise it is one resumed from disk.
    fn bind6(
        &mut self,
        name: &str,
        ifindex: u32,
        session: &mut Session,
        lease: Lease,
        fresh: bool,
        save: bool,
    ) {
        let old: Vec<Ipv6Addr> = session
            .bound
            .as_ref()
            .map(|old| addresses(old).iter().map(|a| a.address).collect())
            .unwrap_or_default();
        let new = addresses(&lease);
        let gone: Vec<Ipv6Addr> = old
            .iter()
            .copied()
            .filter(|address| !new.iter().any(|a| a.address == *address))
            .collect();
        for address in &gone {
            self.withdraw6(ifindex, *address);
            tracing::info!("dhcpv6 client: {name}: {address} withdrawn");
        }
        for address in new {
            self.install6(ifindex, address);
        }
        // A delegated prefix is a route, which follows what is bound
        // (`sync_pd_routes`); here it is only said.
        let delegated = |lease: &Lease| prefixes(lease).map(|p| p.prefix).collect();
        let old_prefixes: BTreeSet<Ipv6Net> =
            session.bound.as_ref().map(delegated).unwrap_or_default();
        let new_prefixes: BTreeSet<Ipv6Net> = delegated(&lease);
        for prefix in old_prefixes.difference(&new_prefixes) {
            tracing::info!("dhcpv6 client: {name}: {prefix} withdrawn");
        }
        // The lease's times count from now: so do those of the
        // addresses its prefixes give interfaces (`sync_pd_lan`).
        for held in self.v6.pd_lan.values_mut() {
            if held.upstream == name {
                held.stale = true;
            }
        }
        if fresh {
            let obtained = unix_now();
            session.obtained = Some(obtained);
            // Under the identity that took it, which is the client's.
            // What `parameters-only` learns is asked for again instead.
            let lan = self.lan_record(name);
            if save
                && lease.has_leases()
                && let Err(e) =
                    self.store
                        .save6(name, session.client.identity(), obtained, &lease, &lan)
            {
                tracing::warn!("dhcpv6 client: {name}: lease not saved: {e}");
            }
        }
        let changed = session.bound.is_none()
            || !gone.is_empty()
            || new.iter().any(|a| !old.contains(&a.address))
            || old_prefixes != new_prefixes;
        match (lease.has_leases(), changed || !fresh) {
            (true, true) => {
                let valid = new.iter().map(|a| a.valid);
                let longest = valid.chain(prefixes(&lease).map(|p| p.valid)).max();
                let longest = longest.unwrap_or(0);
                tracing::info!(
                    "dhcpv6 client: {name}: {} {} from {}, valid {}",
                    if fresh { "bound" } else { "resumed" },
                    address_list(&lease),
                    lease.server_address,
                    lifetime(longest),
                );
            }
            (true, false) => {
                tracing::debug!("dhcpv6 client: {name}: renewed {}", address_list(&lease));
            }
            (false, true) => tracing::info!(
                "dhcpv6 client: {name}: configuration parameters from {}",
                lease.server_address
            ),
            (false, false) => tracing::debug!(
                "dhcpv6 client: {name}: configuration parameters refreshed from {}",
                lease.server_address
            ),
        }
        session.bound = Some(lease);
    }

    /// Ask the RIB to put a leased address on the interface, or to move
    /// its lifetimes: a /128 that brings no connected route. Whether its
    /// prefix is on-link is for a Router Advertisement to say (RFC 5942),
    /// and the RA host installs that route.
    fn install6(&self, ifindex: u32, address: &Address) {
        let _ = self.rib.send(Message::AddrDynAdd {
            ifindex,
            addr: host(address.address),
            origin: AddrOrigin::Dhcp6,
            opts: AddrOpts {
                valid_lft: address.valid,
                preferred_lft: address.preferred,
                noprefixroute: true,
                broadcast: None,
            },
        });
    }

    fn withdraw6(&self, ifindex: u32, address: Ipv6Addr) {
        let _ = self.rib.send(Message::AddrDynDel {
            ifindex,
            addr: host(address),
            origin: AddrOrigin::Dhcp6,
        });
    }

    fn named_iface6(&self, mut args: Args) -> Result<String, String> {
        let name = args.string().ok_or("% Interface name required")?;
        match self.v6.ifaces.get(&name) {
            Some(iface) if iface.session.is_some() => Ok(name),
            _ => Err(format!("No DHCPv6 client on {name}")),
        }
    }

    /// `renew dhcpv6 interface <if>`.
    pub(in crate::dhcpc) fn renew6(&mut self, args: Args) -> String {
        let name = match self.named_iface6(args) {
            Ok(name) => name,
            Err(e) => return e,
        };
        let now = Instant::now();
        self.with_iface6(&name, |dhcpc, ifindex, iface| {
            dhcpc.feed6(&name, ifindex, iface, Slot::Current, Event::Renew, now);
        });
        format!("Renewing the DHCPv6 lease on {name}")
    }

    /// `release dhcpv6 interface <if>`: no lease is wanted on the
    /// interface. That is the current client's, and also one saved under
    /// an earlier identity that still waits for the link to be given
    /// back: left alone, its addresses would stay on the interface.
    pub(in crate::dhcpc) fn release6(&mut self, args: Args) -> String {
        let name = match self.named_iface6(args) {
            Ok(name) => name,
            Err(e) => return e,
        };
        let now = Instant::now();
        self.with_iface6(&name, |dhcpc, ifindex, iface| {
            dhcpc.feed6(&name, ifindex, iface, Slot::Current, Event::Release, now);
            dhcpc.stop_retiring6(&name, ifindex, iface, now);
        });
        format!("Released the DHCPv6 lease on {name}")
    }
}

/// The link-local address `addr` carries, and whether a message can
/// leave from it: it is installed, and duplicate address detection has
/// passed it. `None` for any other address.
fn link_local_state(addr: &LinkAddr) -> Option<(Ipv6Addr, bool)> {
    let IpNet::V6(net) = addr.addr else {
        return None;
    };
    let address = net.addr();
    if !address.is_unicast_link_local() {
        return None;
    }
    let usable = addr.fib && !addr.flags.tentative && !addr.flags.dadfailed;
    Some((address, usable))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::time::Duration;

    use tokio::sync::mpsc::UnboundedReceiver;

    use super::*;
    use crate::config::{ConfigOp, ConfigRequest};
    use crate::dhcpc::inst::{LinkInfo, clock};
    use crate::dhcpc::lease::Store;
    use crate::dhcpc::v6::client::{Ia, IaPd};
    use crate::dhcpc::v6::show::show_leases6;
    use crate::resolver::Report;
    use crate::rib::api::RibRx;
    use crate::rib::client::{ProtoId, RibClient, RibInbound};
    use crate::rib::link::AddrFlags;

    // No such device: the socket fails to open, which the task tolerates,
    // so nothing is ever sent.
    const IF: &str = "dhcpc6-test0";
    const IFINDEX: u32 = 0x7fff_ffe0;
    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const DUID: [u8; 10] = [0, 3, 0, 1, 2, 0, 0, 0, 0, 1];
    const OTHER_DUID: [u8; 10] = [0, 3, 0, 1, 2, 0, 0, 0, 0, 2];
    const SERVER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x10);
    const ADDRESS: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x100);
    const ADDRESS2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x200);
    const PREFIX: &str = "2001:db8:100::/56";
    const PREFIX2: &str = "2001:db8:200::/56";
    const VRF: &str = "red";
    const VRF_IFINDEX: u32 = 0x7fff_ffe1;
    /// Two interfaces behind the router, to number from a delegation.
    const LAN: &str = "dhcpc6-lan0";
    const LAN_IFINDEX: u32 = 0x7fff_ffe2;
    const LAN2: &str = "dhcpc6-lan1";
    const LAN2_IFINDEX: u32 = 0x7fff_ffe3;

    struct Bench {
        dhcpc: Dhcpc,
        rib: UnboundedReceiver<RibInbound>,
        dir: PathBuf,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            clock::hold(None);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A task that knows one link, up, with no address yet.
    fn bench(test: &str) -> Bench {
        // A lease saved and read back within a test is of the age the
        // test gave it.
        clock::hold(Some(1_800_000_000));
        let dir = std::env::temp_dir().join(format!("zebra-dhcpc6-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (tx, rib) = mpsc::unbounded_channel();
        let (_tx, rib_rx) = mpsc::unbounded_channel();
        let client = RibClient::new(tx, ProtoId::from_raw(1));
        let mut dhcpc = Dhcpc::with_store(client, rib_rx, None, Store::new(&dir));
        dhcpc.links.insert(
            IFINDEX,
            LinkInfo {
                name: IF.to_string(),
                mac: Some(MAC),
                mtu: 1500,
                up: true,
                master: None,
                is_vrf: false,
            },
        );
        Bench { dhcpc, rib, dir }
    }

    fn lease(addresses: &[Ipv6Addr]) -> Lease {
        Lease {
            server_id: vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 0xfe],
            server_address: SERVER,
            ia_na: Some(Ia {
                iaid: ident::iaid(IF),
                server_id: vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 0xfe],
                t1: 1800,
                t2: 2880,
                addresses: addresses
                    .iter()
                    .map(|&address| Address {
                        address,
                        preferred: 3600,
                        valid: 7200,
                    })
                    .collect(),
            }),
            ia_pd: vec![],
            dns_servers: vec![],
            domain_list: vec![],
            ntp_servers: vec![],
        }
    }

    /// `lease` with a prefix delegated under each of the `pd` ids too.
    fn delegated(mut lease: Lease, pd: &[(u32, &str)]) -> Lease {
        for &(iaid, prefix) in pd {
            lease.ia_pd.push(IaPd {
                iaid,
                server_id: lease.server_id.clone(),
                t1: 1800,
                t2: 2880,
                prefixes: vec![Prefix {
                    prefix: prefix.parse().unwrap(),
                    preferred: 3600,
                    valid: 7200,
                }],
            });
        }
        lease
    }

    /// A lease of prefixes and no address.
    fn prefixes_only(pd: &[(u32, &str)]) -> Lease {
        let mut lease = lease(&[]);
        lease.ia_na = None;
        delegated(lease, pd)
    }

    /// `dhcpv6-options pd <id>` for each of `ids`, with `address dhcpv6`
    /// or without.
    fn pd_config(address: bool, ids: &[u32]) -> IfConfig6 {
        IfConfig6 {
            address,
            duid: Some(DUID.to_vec()),
            pd: ids.iter().map(|id| (*id, PdConfig::default())).collect(),
            ..IfConfig6::default()
        }
    }

    /// `cfg` committed.
    fn commit(b: &mut Bench, cfg: IfConfig6) {
        b.dhcpc.v6.ifaces.entry(IF.to_string()).or_default().cfg = cfg;
        b.dhcpc.reconcile6(IF);
    }

    /// The link is in VRF `red`, which the task knows of or not yet.
    fn enslave(b: &mut Bench, vrf_known: bool) {
        b.dhcpc.links.get_mut(&IFINDEX).unwrap().master = Some(VRF_IFINDEX);
        if vrf_known {
            b.dhcpc.links.insert(
                VRF_IFINDEX,
                LinkInfo {
                    name: VRF.to_string(),
                    mac: None,
                    mtu: 65575,
                    up: true,
                    master: None,
                    is_vrf: true,
                },
            );
        }
    }

    /// `address dhcpv6` with `dhcpv6-options duid`, committed.
    fn configure(b: &mut Bench, duid: &[u8]) {
        let cfg = &mut b.dhcpc.v6.ifaces.entry(IF.to_string()).or_default().cfg;
        cfg.address = true;
        cfg.duid = Some(duid.to_vec());
        b.dhcpc.reconcile6(IF);
    }

    /// A lease on disk taken as `duid`, `age` seconds ago.
    /// A lease on disk, taken `age` seconds ago as `duid` asking for an
    /// address.
    fn save(b: &Bench, duid: &[u8], age: u64, lease: &Lease) {
        let asks = Asks {
            ia_na: Some(ident::iaid(IF)),
            ia_pd: Vec::new(),
        };
        save_as(b, (duid, &asks), age, lease);
    }

    fn save_as(b: &Bench, identity: (&[u8], &Asks), age: u64, lease: &Lease) {
        b.dhcpc
            .store
            .save6(IF, identity, unix_now() - age, lease, &[])
            .unwrap();
    }

    fn saved(b: &Bench) -> Option<Kept6> {
        b.dhcpc.store.load6(IF, unix_now())
    }

    /// The kernel's word on an address of the link.
    fn kernel(address: Ipv6Addr, len: u8, flags: AddrFlags) -> LinkAddr {
        LinkAddr {
            addr: IpNet::V6(Ipv6Net::new(address, len).unwrap()),
            ifindex: IFINDEX,
            fib: true,
            flags,
            valid_lft: Some(7200),
            ..Default::default()
        }
    }

    /// A link-local address past DAD appears: DHCPv6 can be spoken.
    fn make_ready(b: &mut Bench) {
        let addr = kernel(LINK_LOCAL, 64, AddrFlags::default());
        b.dhcpc.addr_event6(&addr, true);
    }

    fn state(b: &Bench) -> State {
        let iface = &b.dhcpc.v6.ifaces[IF];
        iface.session.as_ref().expect("a client").client.state()
    }

    fn duid_of(b: &Bench) -> Vec<u8> {
        let iface = &b.dhcpc.v6.ifaces[IF];
        let session = iface.session.as_ref().expect("a client");
        session.client.identity().0.to_vec()
    }

    fn retiring(b: &Bench) -> Option<State> {
        let iface = b.dhcpc.v6.ifaces.get(IF)?;
        Some(iface.retiring.as_ref()?.session.client.state())
    }

    /// What the task asked of the RIB since the last call.
    fn asked(b: &mut Bench) -> Vec<String> {
        let mut out = Vec::new();
        // The interfaces numbered from a delegation, as the tests call
        // them.
        let lan = |ifindex: u32| match ifindex {
            LAN_IFINDEX => "lan0",
            LAN2_IFINDEX => "lan1",
            VRF_IFINDEX => VRF,
            _ => panic!("an address for link {ifindex}"),
        };
        while let Ok(inbound) = b.rib.try_recv() {
            out.push(match inbound.msg {
                Message::AddrDynAdd {
                    ifindex,
                    addr,
                    origin: AddrOrigin::Pd,
                    opts,
                } => {
                    // It brings the route to its /64.
                    assert!(!opts.noprefixroute && opts.broadcast.is_none());
                    let times = format!("{}/{}", opts.preferred_lft, opts.valid_lft);
                    format!("{} add {addr} {times}", lan(ifindex))
                }
                Message::AddrDynDel {
                    ifindex,
                    addr,
                    origin: AddrOrigin::Pd,
                } => format!("{} del {addr}", lan(ifindex)),
                Message::AddrDynAdd {
                    ifindex,
                    addr,
                    origin,
                    opts,
                } => {
                    assert_eq!((ifindex, origin), (IFINDEX, AddrOrigin::Dhcp6));
                    assert!(opts.noprefixroute && opts.broadcast.is_none());
                    format!("add {addr} {}/{}", opts.preferred_lft, opts.valid_lft)
                }
                Message::AddrDynDel {
                    ifindex,
                    addr,
                    origin,
                } => {
                    assert_eq!((ifindex, origin), (IFINDEX, AddrOrigin::Dhcp6));
                    format!("del {addr}")
                }
                Message::Ipv6Add { prefix, rib } => format!("route {prefix} {}", route(&rib)),
                Message::Ipv6AddVrf { vrf, prefix, rib } => {
                    format!("route {prefix} vrf {vrf} {}", route(&rib))
                }
                Message::Ipv6Del { prefix, rib } => {
                    assert_eq!(rib.rtype, RibType::DhcpClient);
                    format!("no route {prefix}")
                }
                Message::Ipv6DelVrf { vrf, prefix, rib } => {
                    assert_eq!(rib.rtype, RibType::DhcpClient);
                    format!("no route {prefix} vrf {vrf}")
                }
                _ => "other".to_string(),
            });
        }
        out
    }

    /// A route as the task hands it to the RIB.
    fn route(rib: &RibEntry) -> String {
        assert_eq!(rib.rtype, RibType::DhcpClient);
        let to = match &rib.nexthop {
            Nexthop::Blackhole(0) => "discard",
            _ => "elsewhere",
        };
        format!("{to} distance {}", rib.distance)
    }

    fn verb() -> Args {
        Args(VecDeque::from([IF.to_string()]))
    }

    /// Let every timer that is due within `within` fire, in order.
    fn run_timers(b: &mut Bench, within: Duration) {
        let end = Instant::now() + within;
        while let Some(at) = b.dhcpc.next_deadline6().filter(|at| *at <= end) {
            b.dhcpc.process_timeouts6(at);
        }
    }

    #[tokio::test]
    async fn a_client_waits_for_a_link_local_address_past_dad() {
        let mut b = bench("ready");
        configure(&mut b, &DUID);
        assert_eq!(state(&b), State::Stopped);
        assert_eq!(duid_of(&b), DUID);
        // Still in DAD, or failed it: not one to send from.
        let tentative = AddrFlags {
            tentative: true,
            ..AddrFlags::default()
        };
        b.dhcpc
            .addr_event6(&kernel(LINK_LOCAL, 64, tentative), true);
        assert_eq!(state(&b), State::Stopped);
        let failed = AddrFlags {
            dadfailed: true,
            ..AddrFlags::default()
        };
        b.dhcpc.addr_event6(&kernel(LINK_LOCAL, 64, failed), true);
        assert_eq!(state(&b), State::Stopped);
        // A global address does not help either.
        b.dhcpc
            .addr_event6(&kernel(ADDRESS2, 64, AddrFlags::default()), true);
        assert_eq!(state(&b), State::Stopped);
        make_ready(&mut b);
        assert_eq!(state(&b), State::Soliciting);
        // Gone again, with the address or with the link.
        b.dhcpc
            .addr_event6(&kernel(LINK_LOCAL, 64, AddrFlags::default()), false);
        assert_eq!(state(&b), State::Stopped);
        make_ready(&mut b);
        assert_eq!(state(&b), State::Soliciting);
        b.dhcpc.links.get_mut(&IFINDEX).unwrap().up = false;
        b.dhcpc.sync_link6(IF);
        assert_eq!(state(&b), State::Stopped);
        assert!(asked(&mut b).is_empty());
    }

    #[tokio::test]
    async fn a_saved_lease_is_resumed_into_the_rib() {
        let mut b = bench("resume");
        save(&b, &DUID, 600, &lease(&[ADDRESS, ADDRESS2]));
        configure(&mut b, &DUID);
        // Each address a /128 with what is left of its lifetimes.
        assert_eq!(
            asked(&mut b),
            [
                format!("add {ADDRESS}/128 3000/6600"),
                format!("add {ADDRESS2}/128 3000/6600"),
            ]
        );
        assert_eq!(state(&b), State::Bound);
        assert!(saved(&b).is_some());
        // With the link able to carry it, the lease is verified.
        make_ready(&mut b);
        assert_eq!(state(&b), State::Confirming);

        // The kernel drops one address: the lease goes on with the other.
        b.dhcpc
            .addr_event6(&kernel(ADDRESS, 128, AddrFlags::default()), false);
        let asked_now = asked(&mut b);
        assert_eq!(asked_now[0], format!("del {ADDRESS}/128"));
        assert!(asked_now[1].starts_with(&format!("add {ADDRESS2}/128 ")));
        let kept = saved(&b).expect("still a lease on disk");
        assert_eq!(addresses(&kept.lease).len(), 1);
        // An address that is not the lease's is nobody's business here,
        // nor is the lease's own under another prefix length.
        let stranger = Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 9);
        b.dhcpc
            .addr_event6(&kernel(stranger, 128, AddrFlags::default()), false);
        b.dhcpc
            .addr_event6(&kernel(ADDRESS2, 64, AddrFlags::default()), false);
        assert!(asked(&mut b).is_empty());
        // The last one gone: the lease is over and a new one is asked for.
        b.dhcpc
            .addr_event6(&kernel(ADDRESS2, 128, AddrFlags::default()), false);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS2}/128")]);
        assert_eq!(state(&b), State::Soliciting);
        assert!(saved(&b).is_none());
    }

    #[tokio::test]
    async fn a_lease_that_ran_out_is_not_resumed() {
        let mut b = bench("ran-out");
        save(&b, &DUID, 7200, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        assert!(asked(&mut b).is_empty());
        assert!(saved(&b).is_none());
        assert_eq!(state(&b), State::Stopped);
    }

    #[tokio::test]
    async fn a_duplicate_address_is_withdrawn_and_declined() {
        let mut b = bench("dad");
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        make_ready(&mut b);
        asked(&mut b);
        let failed = AddrFlags {
            dadfailed: true,
            tentative: true,
            ..AddrFlags::default()
        };
        b.dhcpc.addr_event6(&kernel(ADDRESS, 128, failed), true);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(state(&b), State::Declining);
        assert!(saved(&b).is_none());
    }

    #[tokio::test]
    async fn an_address_the_configuration_lets_go_of_gets_its_lifetime_back() {
        let mut b = bench("permanent");
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        asked(&mut b);
        // Permanent in the kernel and no longer configured.
        let mut permanent = kernel(ADDRESS, 128, AddrFlags::default());
        permanent.valid_lft = Some(u32::MAX);
        b.dhcpc.addr_event6(&permanent, true);
        assert_eq!(asked(&mut b), [format!("add {ADDRESS}/128 3600/7200")]);
        // While the configuration holds it, it stays as it is; so does
        // one that already has a lifetime.
        permanent.config = true;
        b.dhcpc.addr_event6(&permanent, true);
        b.dhcpc
            .addr_event6(&kernel(ADDRESS, 128, AddrFlags::default()), true);
        assert!(asked(&mut b).is_empty());
    }

    #[tokio::test]
    async fn deleted_configuration_withdraws_and_forgets() {
        let mut b = bench("deleted");
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        asked(&mut b);
        // No link to say a Release on: it is over at once.
        b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg = IfConfig6::default();
        b.dhcpc.reconcile6(IF);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert!(saved(&b).is_none());
        assert!(!b.dhcpc.v6.ifaces.contains_key(IF));
        assert_eq!(b.dhcpc.next_deadline6(), None);
    }

    #[tokio::test]
    async fn a_release_is_seen_through_after_the_configuration_is_gone() {
        let mut b = bench("retire");
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        make_ready(&mut b);
        asked(&mut b);
        b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg = IfConfig6::default();
        b.dhcpc.reconcile6(IF);
        // Out of use at once; the client stays for its Release.
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert!(saved(&b).is_none());
        assert!(b.dhcpc.v6.ifaces[IF].session.is_none());
        assert_eq!(retiring(&b), Some(State::Releasing));
        // Nobody answers: sent as often as it is to be, then it is gone,
        // and the interface with it.
        run_timers(&mut b, Duration::from_secs(60));
        assert!(!b.dhcpc.v6.ifaces.contains_key(IF));
        assert_eq!(b.dhcpc.next_deadline6(), None);
        assert!(asked(&mut b).is_empty());
    }

    #[tokio::test]
    async fn another_duid_gives_the_lease_back_and_asks_as_itself() {
        let mut b = bench("identity");
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        make_ready(&mut b);
        asked(&mut b);
        configure(&mut b, &OTHER_DUID);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(duid_of(&b), OTHER_DUID);
        assert_eq!(state(&b), State::Soliciting);
        assert_eq!(retiring(&b), Some(State::Releasing));
        // Options that are not who the client is leave it be.
        b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg.rapid_commit = true;
        b.dhcpc.reconcile6(IF);
        assert_eq!(retiring(&b), Some(State::Releasing));
        let session = b.dhcpc.v6.ifaces[IF].session.as_ref().unwrap();
        assert!(session.client.options().rapid_commit);
        run_timers(&mut b, Duration::from_secs(20));
        assert_eq!(retiring(&b), None);
        assert_eq!(duid_of(&b), OTHER_DUID);
    }

    #[tokio::test]
    async fn another_mode_is_another_client() {
        let mut b = bench("mode");
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        make_ready(&mut b);
        asked(&mut b);
        let cfg = &mut b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg;
        cfg.address = false;
        cfg.parameters_only = true;
        b.dhcpc.reconcile6(IF);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(state(&b), State::Informing);
        assert_eq!(retiring(&b), Some(State::Releasing));
        // An address beside `parameters-only` (a startup config can hold
        // both): the address is asked for.
        b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg.address = true;
        b.dhcpc.reconcile6(IF);
        assert_eq!(state(&b), State::Soliciting);
    }

    #[tokio::test]
    async fn a_lease_saved_under_another_duid_is_released_as_that_duid() {
        let mut b = bench("saved-identity");
        save(&b, &OTHER_DUID, 600, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        // Claimed, so that it can be withdrawn; the file is the next
        // lease's.
        assert_eq!(asked(&mut b), [format!("add {ADDRESS}/128 3000/6600")]);
        assert!(saved(&b).is_none());
        assert_eq!(duid_of(&b), DUID);
        assert_eq!(retiring(&b), Some(State::Bound));
        // It goes back when the link can carry the Release.
        make_ready(&mut b);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(retiring(&b), Some(State::Releasing));
        assert_eq!(state(&b), State::Soliciting);
        run_timers(&mut b, Duration::from_secs(20));
        assert_eq!(retiring(&b), None);
        assert_eq!(state(&b), State::Soliciting);
    }

    #[tokio::test]
    async fn a_saved_lease_nobody_can_release_runs_out_and_is_withdrawn() {
        let mut b = bench("saved-expires");
        save(&b, &OTHER_DUID, 7190, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        assert_eq!(asked(&mut b), [format!("add {ADDRESS}/128 0/10")]);
        // The link never comes: at the end of its lifetime it goes.
        run_timers(&mut b, Duration::from_secs(20));
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(retiring(&b), None);
        assert_eq!(state(&b), State::Stopped);
    }

    /// `release dhcpv6 interface` while a lease saved under another DUID
    /// still waits for the link: that lease goes too, not only the
    /// current client's.
    #[tokio::test]
    async fn an_operator_release_also_ends_a_saved_lease_that_is_waiting() {
        let mut b = bench("release-pending");
        save(&b, &OTHER_DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        assert_eq!(asked(&mut b), [format!("add {ADDRESS}/128 3600/7200")]);
        assert_eq!(retiring(&b), Some(State::Bound));
        assert_eq!(
            b.dhcpc.release6(verb()),
            format!("Released the DHCPv6 lease on {IF}")
        );
        // Withdrawn. With no link to say a Release on, that is the end
        // of it.
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(retiring(&b), None);
        assert_eq!(state(&b), State::Released);
        // The link coming later brings nothing back.
        make_ready(&mut b);
        assert!(asked(&mut b).is_empty());
        assert_eq!(state(&b), State::Released);

        // With a link, its Release is seen through as any other.
        let mut b = bench("release-pending-link");
        save(&b, &OTHER_DUID, 0, &lease(&[ADDRESS]));
        b.dhcpc.links.get_mut(&IFINDEX).unwrap().up = false;
        configure(&mut b, &DUID);
        let ll = kernel(LINK_LOCAL, 64, AddrFlags::default());
        b.dhcpc
            .v6
            .link_locals
            .entry(IFINDEX)
            .or_default()
            .insert(LINK_LOCAL, link_local_state(&ll).unwrap().1);
        b.dhcpc.links.get_mut(&IFINDEX).unwrap().up = true;
        // The link is there now, and nothing has told the clients yet.
        assert_eq!(retiring(&b), Some(State::Bound));
        asked(&mut b);
        b.dhcpc.release6(verb());
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(retiring(&b), Some(State::Releasing));
        run_timers(&mut b, Duration::from_secs(20));
        assert_eq!(retiring(&b), None);
        assert_eq!(state(&b), State::Released);
    }

    /// A retiring client's lease is on its way out: when it changes (one
    /// of its addresses goes), it is not written to disk again, where
    /// the next start would find it and take it for a lease to resume.
    #[tokio::test]
    async fn a_retiring_lease_is_not_saved_again() {
        // Waiting for the link, with the file already the next lease's.
        let mut b = bench("retiring-save");
        save(&b, &OTHER_DUID, 0, &lease(&[ADDRESS, ADDRESS2]));
        configure(&mut b, &DUID);
        assert!(saved(&b).is_none());
        asked(&mut b);
        b.dhcpc
            .addr_event6(&kernel(ADDRESS, 128, AddrFlags::default()), false);
        let asked_now = asked(&mut b);
        assert_eq!(asked_now[0], format!("del {ADDRESS}/128"));
        assert!(asked_now[1].starts_with(&format!("add {ADDRESS2}/128 ")));
        assert_eq!(retiring(&b), Some(State::Bound));
        assert!(saved(&b).is_none(), "the old identity's lease is back");

        // The current client's lease is still saved when it changes, and
        // a retiring one does not write over it.
        let mut b = bench("retiring-save-current");
        save(&b, &DUID, 0, &lease(&[ADDRESS, ADDRESS2]));
        configure(&mut b, &DUID);
        b.dhcpc
            .addr_event6(&kernel(ADDRESS, 128, AddrFlags::default()), false);
        let kept = saved(&b).expect("the current lease");
        assert_eq!(kept.duid, DUID);
        assert_eq!(addresses(&kept.lease).len(), 1);
    }

    /// The DUID on disk is read without a hardware address: an interface
    /// that has none (a tunnel, a PPP link) still gets its client. Only
    /// making a DUID waits for one.
    #[tokio::test]
    async fn a_saved_duid_needs_no_hardware_address() {
        let stored = [0, 1, 0, 1, 1, 2, 3, 4, 2, 0, 0, 0, 0, 7];
        let without_mac = |test: &str| {
            let mut b = bench(test);
            b.dhcpc.links.get_mut(&IFINDEX).unwrap().mac = None;
            b
        };
        let want_address = |b: &mut Bench| {
            let cfg = &mut b.dhcpc.v6.ifaces.entry(IF.to_string()).or_default().cfg;
            cfg.address = true;
            b.dhcpc.reconcile6(IF);
        };
        let mut b = without_mac("duid-no-mac");
        std::fs::create_dir_all(&b.dir).unwrap();
        std::fs::write(b.dir.join("duid"), ident::format_duid(&stored)).unwrap();
        want_address(&mut b);
        assert_eq!(duid_of(&b), stored);

        // With none on disk, the client waits for an address to make one
        // from, and nothing is written meanwhile.
        let mut b = without_mac("duid-no-mac-none");
        want_address(&mut b);
        assert!(b.dhcpc.v6.ifaces[IF].session.is_none());
        assert_eq!(DuidStore::new(&b.dir).load().unwrap(), None);
        b.dhcpc.links.get_mut(&IFINDEX).unwrap().mac = Some(MAC);
        b.dhcpc.reconcile6(IF);
        let made = duid_of(&b);
        assert_eq!(made[8..], MAC);
        assert_eq!(DuidStore::new(&b.dir).load().unwrap(), Some(made));
        // An all-zero address is no address.
        let mut b = without_mac("duid-zero-mac");
        b.dhcpc.links.get_mut(&IFINDEX).unwrap().mac = Some([0; 6]);
        want_address(&mut b);
        assert!(b.dhcpc.v6.ifaces[IF].session.is_none());
    }

    /// `no-release` set in the commit that takes the client away is for
    /// that client: it stops without a Release.
    #[tokio::test]
    async fn no_release_set_with_the_deletion_stops_without_a_release() {
        for no_release in [true, false] {
            let mut b = bench("no-release");
            save(&b, &DUID, 0, &lease(&[ADDRESS]));
            configure(&mut b, &DUID);
            make_ready(&mut b);
            asked(&mut b);
            let cfg = &mut b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg;
            cfg.address = false;
            cfg.no_release = no_release;
            b.dhcpc.reconcile6(IF);
            assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
            let want = (!no_release).then_some(State::Releasing);
            assert_eq!(retiring(&b), want, "no-release {no_release}");
        }

        // The same with another DUID in that commit: the old client goes
        // silently, the new one asks.
        let mut b = bench("no-release-identity");
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        make_ready(&mut b);
        b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg.no_release = true;
        configure(&mut b, &OTHER_DUID);
        assert_eq!(retiring(&b), None);
        assert_eq!(duid_of(&b), OTHER_DUID);
        assert_eq!(state(&b), State::Soliciting);

        // And for a lease saved under another DUID that still waits for
        // the link: `no-release` set meanwhile holds when it is stopped.
        let mut b = bench("no-release-waiting");
        save(&b, &OTHER_DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        assert_eq!(retiring(&b), Some(State::Bound));
        b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg.no_release = true;
        b.dhcpc.reconcile6(IF);
        asked(&mut b);
        make_ready(&mut b);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(retiring(&b), None);
    }

    /// A client that waits for a hardware address to make the system
    /// DUID from starts when one appears, also on another interface.
    #[tokio::test]
    async fn a_client_waiting_for_the_duid_starts_when_any_interface_brings_an_address() {
        let other = |mac: Option<[u8; 6]>| LinkInfo {
            name: "dhcpc6-test1".to_string(),
            mac,
            mtu: 1500,
            up: true,
            master: None,
            is_vrf: false,
        };
        // The other interface appears with an address, or gets one later.
        for appears_with_it in [true, false] {
            let mut b = bench("duid-waiting");
            b.dhcpc.links.get_mut(&IFINDEX).unwrap().mac = None;
            let cfg = &mut b.dhcpc.v6.ifaces.entry(IF.to_string()).or_default().cfg;
            cfg.address = true;
            b.dhcpc.reconcile6(IF);
            assert!(b.dhcpc.v6.ifaces[IF].session.is_none());

            let mac = [2, 0, 0, 0, 0, 9];
            if appears_with_it {
                b.dhcpc.links.insert(IFINDEX + 1, other(Some(mac)));
                b.dhcpc.link_added6(IFINDEX + 1, "dhcpc6-test1", &[]);
            } else {
                // Without one it changes nothing.
                b.dhcpc.links.insert(IFINDEX + 1, other(None));
                b.dhcpc.link_added6(IFINDEX + 1, "dhcpc6-test1", &[]);
                assert!(b.dhcpc.v6.ifaces[IF].session.is_none());
                b.dhcpc.links.get_mut(&(IFINDEX + 1)).unwrap().mac = Some(mac);
                b.dhcpc.link_mac6("dhcpc6-test1");
            }
            let made = duid_of(&b);
            assert_eq!(made[8..], mac, "appears with it: {appears_with_it}");
            assert_eq!(DuidStore::new(&b.dir).load().unwrap(), Some(made));
        }
    }

    /// Two clients wait for the system DUID, and the interface of one of
    /// them gets the hardware address: that one's own reconciling makes
    /// the DUID, and the other must not be left waiting for it.
    #[tokio::test]
    async fn every_client_waiting_for_the_duid_starts_when_one_of_them_gets_an_address() {
        const OTHER: &str = "dhcpc6-test1";
        // The address comes as a change to a known link, or with the
        // link described anew.
        for described_anew in [false, true] {
            let mut b = bench("duid-waiting-two");
            b.dhcpc.links.get_mut(&IFINDEX).unwrap().mac = None;
            b.dhcpc.links.insert(
                IFINDEX + 1,
                LinkInfo {
                    name: OTHER.to_string(),
                    mac: None,
                    mtu: 1500,
                    up: true,
                    master: None,
                    is_vrf: false,
                },
            );
            for name in [IF, OTHER] {
                let cfg = &mut b.dhcpc.v6.ifaces.entry(name.to_string()).or_default().cfg;
                cfg.address = true;
                b.dhcpc.reconcile6(name);
                assert!(b.dhcpc.v6.ifaces[name].session.is_none());
            }
            // The second one gets it. (The first sorts before it, so it
            // is not the one the event names.)
            b.dhcpc.links.get_mut(&(IFINDEX + 1)).unwrap().mac = Some(MAC);
            if described_anew {
                b.dhcpc.link_added6(IFINDEX + 1, OTHER, &[]);
            } else {
                b.dhcpc.link_mac6(OTHER);
            }
            let duid = |name: &str| {
                let session = b.dhcpc.v6.ifaces[name].session.as_ref();
                session.map(|session| session.client.identity().0.to_vec())
            };
            let made = duid(OTHER).expect("the interface with the address");
            assert_eq!(made[8..], MAC);
            assert_eq!(
                duid(IF),
                Some(made),
                "the other waiting client, described anew: {described_anew}"
            );
        }
    }

    #[tokio::test]
    async fn a_deleted_link_drops_the_binding() {
        let mut b = bench("link");
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        make_ready(&mut b);
        asked(&mut b);
        b.dhcpc.links.remove(&IFINDEX);
        b.dhcpc.link_deleted6(IFINDEX, IF);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert!(saved(&b).is_none());
        // The configuration waits for the link.
        let iface = &b.dhcpc.v6.ifaces[IF];
        assert!(iface.session.is_none() && iface.ifindex.is_none());
        assert_eq!(b.dhcpc.next_deadline6(), None);
    }

    #[tokio::test]
    async fn a_delegated_prefix_is_held_by_a_discard_route() {
        let mut b = bench("pd-route");
        let cfg = pd_config(false, &[1]);
        let asks = cfg.asks(IF);
        assert_eq!(asks.ia_na, None);
        assert_eq!(
            asks.ia_pd,
            [PdAsk {
                iaid: 1,
                length: 64
            }]
        );
        save_as(&b, (&DUID, &asks), 600, &prefixes_only(&[(1, PREFIX)]));
        commit(&mut b, cfg);
        // No address to put on the interface: the route is all of it.
        assert_eq!(
            asked(&mut b),
            [format!("route {PREFIX} discard distance 210")]
        );
        assert_eq!(state(&b), State::Bound);
        let kept = saved(&b).expect("a lease of prefixes is a lease");
        assert_eq!(kept.asks, asks);
        // Shown with what is left of its times, under its delegation.
        let shown = show_leases6(&b.dhcpc, Args(VecDeque::new()), false).unwrap();
        let line = format!("  Prefix:       {PREFIX} preferred 3000s valid 6600s (pd 1)\n");
        assert!(shown.contains(&line), "{shown}");
        assert!(shown.contains("  Renew in:     1200s\n"), "{shown}");
        assert!(
            !shown.contains("IAID:") && !shown.contains("Address:"),
            "{shown}"
        );
        let json = show_leases6(&b.dhcpc, Args(VecDeque::new()), true).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            json[0]["pd"],
            serde_json::json!([{
                "id": 1,
                "prefixes": [{"prefix": PREFIX, "preferred_in": 3000, "valid_in": 6600}],
                "server_duid": "00:03:00:01:02:00:00:00:00:fe",
                "renew_in": 1200,
                "rebind_in": 2280,
            }])
        );
        // The prefix is this router's while the lease is held, whatever
        // the link does.
        make_ready(&mut b);
        b.dhcpc.links.get_mut(&IFINDEX).unwrap().up = false;
        b.dhcpc.sync_link6(IF);
        b.dhcpc.links.get_mut(&IFINDEX).unwrap().up = true;
        b.dhcpc.sync_link6(IF);
        assert!(asked(&mut b).is_empty());
        // Deleted configuration takes it back.
        commit(&mut b, IfConfig6::default());
        assert_eq!(asked(&mut b), [format!("no route {PREFIX}")]);
        assert!(saved(&b).is_none());
        assert_eq!(retiring(&b), Some(State::Releasing));
    }

    /// One configuration line as the configuration manager hands it
    /// over, and the end of its commit.
    fn config_line(b: &mut Bench, leaf: &str, values: &[&str], op: ConfigOp) {
        let callback = b.dhcpc.callbacks[&format!("/interface/ipv6/dhcpv6-options/{leaf}")];
        let mut args = vec![IF.to_string()];
        args.extend(values.iter().map(|value| value.to_string()));
        callback(&mut b.dhcpc, Args(VecDeque::from(args)), op);
        b.dhcpc
            .process_cm_msg(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
    }

    #[tokio::test]
    async fn pd_is_configured_by_its_id() {
        let mut b = bench("pd-config");
        let pd = |b: &Bench| b.dhcpc.v6.ifaces.get(IF).map(|iface| iface.cfg.pd.clone());
        let hint = |length| PdConfig {
            length,
            ..PdConfig::default()
        };
        config_line(&mut b, "pd", &["7"], ConfigOp::Set);
        assert_eq!(pd(&b), Some(BTreeMap::from([(7, hint(None))])));
        // The delegation alone starts a client, which asks for it.
        make_ready(&mut b);
        assert_eq!(state(&b), State::Soliciting);
        let session = b.dhcpc.v6.ifaces[IF].session.as_ref().unwrap();
        assert_eq!(
            session.client.identity().1.ia_pd,
            [PdAsk {
                iaid: 7,
                length: 64
            }]
        );
        // The hint is a leaf of it, and comes with its entry or after.
        config_line(&mut b, "pd/length", &["7", "48"], ConfigOp::Set);
        config_line(&mut b, "pd/length", &["9", "56"], ConfigOp::Set);
        assert_eq!(
            pd(&b),
            Some(BTreeMap::from([(7, hint(Some(48))), (9, hint(Some(56)))]))
        );
        config_line(&mut b, "pd/length", &["7"], ConfigOp::Delete);
        assert_eq!(
            pd(&b),
            Some(BTreeMap::from([(7, hint(None)), (9, hint(Some(56)))]))
        );
        // A deleted entry is gone whichever of its lines comes last: the
        // leaf's delete does not bring it back.
        config_line(&mut b, "pd", &["9"], ConfigOp::Delete);
        config_line(&mut b, "pd/length", &["9"], ConfigOp::Delete);
        assert_eq!(pd(&b), Some(BTreeMap::from([(7, hint(None))])));
        config_line(&mut b, "pd", &["7"], ConfigOp::Delete);
        config_line(&mut b, "pd/length", &["7"], ConfigOp::Delete);
        // Nothing configured, and no client: the interface is forgotten.
        assert_eq!(pd(&b), None);
    }

    #[tokio::test]
    async fn a_lost_address_leaves_the_prefix_and_its_route() {
        let mut b = bench("pd-address-lost");
        let cfg = pd_config(true, &[1, 2]);
        let held = delegated(lease(&[ADDRESS]), &[(1, PREFIX)]);
        save_as(&b, (&DUID, &cfg.asks(IF)), 0, &held);
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [
                format!("add {ADDRESS}/128 3600/7200"),
                format!("route {PREFIX} discard distance 210"),
            ]
        );
        // A delegation asked for and not held is shown as that.
        let shown = show_leases6(&b.dhcpc, Args(VecDeque::new()), false).unwrap();
        assert!(shown.contains(&format!("{PREFIX} preferred")), "{shown}");
        assert!(shown.contains("                none (pd 2)\n"), "{shown}");
        // The kernel drops the address: the lease goes on as the prefix
        // alone, on disk too, and the route is not touched.
        b.dhcpc
            .addr_event6(&kernel(ADDRESS, 128, AddrFlags::default()), false);
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        let kept = saved(&b).expect("the prefix is still leased");
        assert!(addresses(&kept.lease).is_empty());
        assert_eq!(prefixes(&kept.lease).count(), 1);
        let bound = b.dhcpc.v6.ifaces[IF]
            .session
            .as_ref()
            .unwrap()
            .bound
            .as_ref();
        assert_eq!(bound.map(|lease| prefixes(lease).count()), Some(1));
    }

    #[tokio::test]
    async fn a_prefix_that_runs_out_loses_its_route() {
        let mut b = bench("pd-expiry");
        let cfg = pd_config(true, &[1, 2]);
        let held = delegated(lease(&[ADDRESS]), &[(1, PREFIX), (2, PREFIX2)]);
        save_as(&b, (&DUID, &cfg.asks(IF)), 7190, &held);
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [
                format!("add {ADDRESS}/128 0/10"),
                format!("route {PREFIX} discard distance 210"),
                format!("route {PREFIX2} discard distance 210"),
            ]
        );
        // No link to renew on: at the end of its lifetime all of it goes.
        run_timers(&mut b, Duration::from_secs(20));
        assert_eq!(
            asked(&mut b),
            [
                format!("del {ADDRESS}/128"),
                format!("no route {PREFIX}"),
                format!("no route {PREFIX2}"),
            ]
        );
        assert!(saved(&b).is_none());
    }

    #[tokio::test]
    async fn another_delegation_asked_for_is_another_client() {
        let mut b = bench("pd-identity");
        let cfg = pd_config(true, &[1]);
        let held = delegated(lease(&[ADDRESS]), &[(1, PREFIX)]);
        save_as(&b, (&DUID, &cfg.asks(IF)), 0, &held);
        commit(&mut b, cfg);
        make_ready(&mut b);
        asked(&mut b);
        // A hint is part of what is asked for, like the delegation.
        let mut hinted = pd_config(true, &[1]);
        hinted.pd.get_mut(&1).unwrap().length = Some(56);
        assert_eq!(
            hinted.asks(IF).ia_pd,
            [PdAsk {
                iaid: 1,
                length: 56
            }]
        );
        commit(&mut b, hinted);
        assert_eq!(
            asked(&mut b),
            [format!("del {ADDRESS}/128"), format!("no route {PREFIX}")]
        );
        assert_eq!(state(&b), State::Soliciting);
        assert_eq!(retiring(&b), Some(State::Releasing));

        // A lease on disk that was taken asking for something else is
        // not this client's to go on with: it is given back.
        let mut b = bench("pd-saved-identity");
        let asks = pd_config(true, &[1]).asks(IF);
        save_as(&b, (&DUID, &asks), 600, &held);
        commit(&mut b, pd_config(true, &[2]));
        assert_eq!(
            asked(&mut b),
            [
                format!("add {ADDRESS}/128 3000/6600"),
                format!("route {PREFIX} discard distance 210"),
            ]
        );
        assert!(saved(&b).is_none());
        assert_eq!(retiring(&b), Some(State::Bound));
        make_ready(&mut b);
        assert_eq!(
            asked(&mut b),
            [format!("del {ADDRESS}/128"), format!("no route {PREFIX}")]
        );
        assert_eq!(retiring(&b), Some(State::Releasing));
        assert_eq!(state(&b), State::Soliciting);
    }

    #[tokio::test]
    async fn the_discard_route_is_in_the_vrf_of_the_interface() {
        let mut b = bench("pd-vrf");
        enslave(&mut b, true);
        let cfg = pd_config(false, &[1]);
        save_as(
            &b,
            (&DUID, &cfg.asks(IF)),
            0,
            &prefixes_only(&[(1, PREFIX)]),
        );
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [format!("route {PREFIX} vrf {VRF} discard distance 210")]
        );
        // The link goes (a move to another VRF is that, and a new link):
        // the route goes from the table it was put in.
        b.dhcpc.links.remove(&IFINDEX);
        b.dhcpc.link_deleted6(IFINDEX, IF);
        assert_eq!(asked(&mut b), [format!("no route {PREFIX} vrf {VRF}")]);

        // A VRF the task hears of after its member: the route moves to
        // its table.
        let mut b = bench("pd-vrf-late");
        enslave(&mut b, false);
        let cfg = pd_config(false, &[1]);
        save_as(
            &b,
            (&DUID, &cfg.asks(IF)),
            0,
            &prefixes_only(&[(1, PREFIX)]),
        );
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [format!("route {PREFIX} discard distance 210")]
        );
        enslave(&mut b, true);
        b.dhcpc.link_added6(VRF_IFINDEX, VRF, &[]);
        assert_eq!(
            asked(&mut b),
            [
                format!("no route {PREFIX}"),
                format!("route {PREFIX} vrf {VRF} discard distance 210"),
            ]
        );
        // And back when the VRF goes.
        b.dhcpc.links.remove(&VRF_IFINDEX);
        b.dhcpc.link_deleted6(VRF_IFINDEX, VRF);
        assert_eq!(
            asked(&mut b),
            [
                format!("no route {PREFIX} vrf {VRF}"),
                format!("route {PREFIX} discard distance 210"),
            ]
        );
    }

    /// A link behind the router, with a hardware address.
    fn add_lan(b: &mut Bench, ifindex: u32, name: &str) {
        b.dhcpc.links.insert(
            ifindex,
            LinkInfo {
                name: name.to_string(),
                mac: Some([2, 0, 0, 0, 0, ifindex as u8]),
                mtu: 1500,
                up: true,
                master: None,
                is_vrf: false,
            },
        );
    }

    /// `pd 1`, with `interface <name> sla-id <n>` and its `address` for
    /// each of `interfaces`.
    fn lan_config(interfaces: &[(&str, u32, Option<u64>)]) -> IfConfig6 {
        let mut cfg = pd_config(false, &[1]);
        let pd = cfg.pd.get_mut(&1).unwrap();
        for &(name, sla_id, address) in interfaces {
            let lan = LanConfig {
                sla_id: Some(sla_id),
                address,
            };
            pd.interfaces.insert(name.to_string(), lan);
        }
        cfg
    }

    /// `lease` on disk, taken `age` seconds ago as `cfg` asks, with the
    /// addresses it had given other interfaces.
    fn save_given(b: &Bench, cfg: &IfConfig6, age: u64, lease: &Lease, given: &[(&str, &str)]) {
        let given: Vec<(String, Ipv6Net)> = given
            .iter()
            .map(|(name, address)| (name.to_string(), address.parse().unwrap()))
            .collect();
        let identity = (&DUID[..], &cfg.asks(IF));
        b.dhcpc
            .store
            .save6(IF, identity, unix_now() - age, lease, &given)
            .unwrap();
    }

    /// The addresses the lease file names as given, by interface.
    fn given(b: &Bench) -> Vec<(String, String)> {
        let lan = saved(b).map(|kept| kept.lan).unwrap_or_default();
        lan.into_iter()
            .map(|(name, address)| (name, address.to_string()))
            .collect()
    }

    fn shown(b: &Bench) -> String {
        show_leases6(&b.dhcpc, Args(VecDeque::new()), false).unwrap()
    }

    #[test]
    fn a_subnet_is_numbered_by_the_bits_up_to_the_64th() {
        let net = |text: &str| text.parse::<Ipv6Net>().unwrap();
        for (prefix, sla_id, want) in [
            ("2001:db8:100::/56", 0, Ok("2001:db8:100::/64")),
            ("2001:db8:100::/56", 1, Ok("2001:db8:100:1::/64")),
            ("2001:db8:100::/56", 255, Ok("2001:db8:100:ff::/64")),
            ("2001:db8:100::/56", 256, Err(NoAddress::SlaId)),
            ("2001:db8:100::/48", 0xffff, Ok("2001:db8:100:ffff::/64")),
            ("2001:db8:100::/48", 0x1_0000, Err(NoAddress::SlaId)),
            // A /64 is its own one subnet.
            ("2001:db8:100:5::/64", 0, Ok("2001:db8:100:5::/64")),
            ("2001:db8:100:5::/64", 1, Err(NoAddress::SlaId)),
            ("2001:db8:100:5::/63", 1, Ok("2001:db8:100:5::/64")),
            ("2001:db8:100:4::/63", 2, Err(NoAddress::SlaId)),
            // As many bits as an sla-id has, and more.
            ("2001:db8::/32", u32::MAX, Ok("2001:db8:ffff:ffff::/64")),
            ("2001::/16", u32::MAX, Ok("2001:0:ffff:ffff::/64")),
            ("::/0", 5, Ok("0:0:0:5::/64")),
            // Nothing to give.
            ("2001:db8:100:5:8000::/65", 0, Err(NoAddress::NoSubnet)),
            ("2001:db8:100:5::1/128", 0, Err(NoAddress::NoSubnet)),
        ] {
            assert_eq!(
                subnet(net(prefix), sla_id),
                want.map(net),
                "{prefix} {sla_id}"
            );
        }

        let subnet = net("2001:db8:100:1::/64");
        let host = |address| LanConfig {
            sla_id: None,
            address,
        };
        let mac = Some([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        for (address, mac, want) in [
            (Some(1), mac, Ok("2001:db8:100:1::1/64")),
            (
                Some(u64::MAX),
                None,
                Ok("2001:db8:100:1:ffff:ffff:ffff:ffff/64"),
            ),
            // From the hardware address, unless it says which.
            (None, mac, Ok("2001:db8:100:1:5054:ff:fe12:3456/64")),
            (None, None, Err(NoAddress::NoHardwareAddress)),
            (None, Some([0; 6]), Err(NoAddress::NoHardwareAddress)),
        ] {
            let got = address_in(subnet, &host(address), mac);
            assert_eq!(got, want.map(net), "{address:?} {mac:?}");
        }
    }

    #[tokio::test]
    async fn an_interface_is_numbered_from_a_delegated_prefix() {
        let mut b = bench("lan");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        add_lan(&mut b, LAN2_IFINDEX, LAN2);
        let cfg = lan_config(&[(LAN, 1, Some(1)), (LAN2, 0xff, None)]);
        save_given(&b, &cfg, 600, &prefixes_only(&[(1, PREFIX)]), &[]);
        commit(&mut b, cfg);
        // Each its /64, with what is left of the prefix's lifetimes.
        let first = "2001:db8:100:1::1/64";
        let second = "2001:db8:100:ff:0:ff:fe00:e3/64";
        assert_eq!(
            asked(&mut b),
            [
                format!("route {PREFIX} discard distance 210"),
                format!("lan0 add {first} 3000/6600"),
                format!("lan1 add {second} 3000/6600"),
            ]
        );
        // Shown under the prefix, and named in the lease file.
        let text = shown(&b);
        assert!(text.contains(&format!("    on {LAN}: {first}\n")), "{text}");
        assert!(
            text.contains(&format!("    on {LAN2}: {second}\n")),
            "{text}"
        );
        let json = show_leases6(&b.dhcpc, Args(VecDeque::new()), true).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            json[0]["pd"][0]["prefixes"][0]["interfaces"],
            serde_json::json!([
                {"interface": LAN, "address": first},
                {"interface": LAN2, "address": second},
            ])
        );
        let both = [
            (LAN.to_string(), first.to_string()),
            (LAN2.to_string(), second.to_string()),
        ];
        assert_eq!(given(&b), both);

        // The kernel counts the lifetimes down: nothing is said again
        // while the lease is what it was.
        make_ready(&mut b);
        b.dhcpc.sync_pd_lan();
        assert!(asked(&mut b).is_empty());
        // A link that comes up may have lost its address: it is told
        // again, and no other. Going down says nothing.
        b.dhcpc.process_rib_msg(RibRx::LinkDown(LAN_IFINDEX));
        assert!(asked(&mut b).is_empty());
        b.dhcpc.process_rib_msg(RibRx::LinkUp(LAN_IFINDEX));
        assert_eq!(asked(&mut b), [format!("lan0 add {first} 3000/6600")]);

        // An interface that goes takes its address out of the file, and
        // one that comes (back) gets its address.
        b.dhcpc.links.remove(&LAN2_IFINDEX);
        b.dhcpc.link_deleted6(LAN2_IFINDEX, LAN2);
        assert_eq!(asked(&mut b), [format!("lan1 del {second}")]);
        assert_eq!(given(&b), both[..1]);
        add_lan(&mut b, LAN2_IFINDEX, LAN2);
        b.dhcpc.link_added6(LAN2_IFINDEX, LAN2, &[]);
        assert_eq!(asked(&mut b), [format!("lan1 add {second} 3000/6600")]);
        assert_eq!(given(&b), both);

        // The prefix given back: so are its addresses.
        b.dhcpc.release6(verb());
        assert_eq!(
            asked(&mut b),
            [
                format!("no route {PREFIX}"),
                format!("lan0 del {first}"),
                format!("lan1 del {second}"),
            ]
        );
        assert!(saved(&b).is_none());
    }

    #[tokio::test]
    async fn a_lease_whose_times_move_tells_the_interfaces_again() {
        let mut b = bench("lan-times");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        add_lan(&mut b, LAN2_IFINDEX, LAN2);
        // Two delegations, the second with ten seconds to live.
        let mut cfg = lan_config(&[(LAN, 1, Some(1))]);
        let mut second = PdConfig::default();
        let lan = LanConfig {
            sla_id: Some(2),
            address: Some(1),
        };
        second.interfaces.insert(LAN2.to_string(), lan);
        cfg.pd.insert(2, second);
        let mut held = prefixes_only(&[(1, PREFIX), (2, PREFIX2)]);
        held.ia_pd[1].prefixes[0].preferred = 100;
        held.ia_pd[1].prefixes[0].valid = 610;
        save_given(&b, &cfg, 600, &held, &[]);
        commit(&mut b, cfg);
        let first = "2001:db8:100:1::1/64";
        let short = "2001:db8:200:2::1/64";
        assert_eq!(
            asked(&mut b),
            [
                format!("route {PREFIX} discard distance 210"),
                format!("route {PREFIX2} discard distance 210"),
                format!("lan0 add {first} 3000/6600"),
                // No longer preferred: for what is still open only.
                format!("lan1 add {short} 0/10"),
            ]
        );
        // The second runs out. Its address goes before anything else,
        // and the lease, which is another now, is said again with the
        // times it has: the other address's count from here.
        run_timers(&mut b, Duration::from_secs(20));
        assert_eq!(
            asked(&mut b),
            [
                format!("no route {PREFIX2}"),
                format!("lan1 del {short}"),
                format!("lan0 add {first} 2990/6590"),
            ]
        );
        assert_eq!(given(&b), [(LAN.to_string(), first.to_string())]);

        // The link the prefix is delegated on goes: the binding is
        // dropped, and what it gave with it.
        b.dhcpc.links.remove(&IFINDEX);
        b.dhcpc.link_deleted6(IFINDEX, IF);
        assert_eq!(
            asked(&mut b),
            [format!("no route {PREFIX}"), format!("lan0 del {first}")]
        );
    }

    #[tokio::test]
    async fn a_lease_written_again_still_names_what_it_gave() {
        let mut b = bench("lan-rewritten");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        let mut cfg = lan_config(&[(LAN, 1, Some(1))]);
        cfg.address = true;
        let held = delegated(lease(&[ADDRESS]), &[(1, PREFIX)]);
        save_given(&b, &cfg, 0, &held, &[]);
        commit(&mut b, cfg);
        let first = "2001:db8:100:1::1/64";
        assert_eq!(
            asked(&mut b),
            [
                format!("add {ADDRESS}/128 3600/7200"),
                format!("route {PREFIX} discard distance 210"),
                format!("lan0 add {first} 3600/7200"),
            ]
        );
        let named = [(LAN.to_string(), first.to_string())];
        assert_eq!(given(&b), named);
        // The kernel drops the leased address: the lease is another,
        // and written again. What its prefix gave is as it was, in the
        // file too, and is told again as the lease is.
        b.dhcpc
            .addr_event6(&kernel(ADDRESS, 128, AddrFlags::default()), false);
        assert_eq!(
            asked(&mut b),
            [
                format!("del {ADDRESS}/128"),
                format!("lan0 add {first} 3600/7200"),
            ]
        );
        let kept = saved(&b).expect("the prefix is still leased");
        assert!(addresses(&kept.lease).is_empty());
        assert_eq!(given(&b), named);
    }

    #[tokio::test]
    async fn the_interfaces_of_a_delegation_follow_the_configuration() {
        let mut b = bench("lan-config");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        add_lan(&mut b, LAN2_IFINDEX, LAN2);
        let cfg = pd_config(false, &[1]);
        save_given(&b, &cfg, 0, &prefixes_only(&[(1, PREFIX)]), &[]);
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [format!("route {PREFIX} discard distance 210")]
        );
        let add = |address: &str| format!("add {address} 3600/7200");
        let del = |address: &str| format!("del {address}");

        // An interface is one line: the first /64, and an address made
        // from its hardware address.
        config_line(&mut b, "pd/interface", &["1", LAN], ConfigOp::Set);
        let made = "2001:db8:100::ff:fe00:e2/64";
        assert_eq!(asked(&mut b), [format!("lan0 {}", add(made))]);
        // Its leaves come with it or after, and each moves the address.
        config_line(
            &mut b,
            "pd/interface/address",
            &["1", LAN, "1"],
            ConfigOp::Set,
        );
        let host = "2001:db8:100::1/64";
        assert_eq!(
            asked(&mut b),
            [format!("lan0 {}", del(made)), format!("lan0 {}", add(host))]
        );
        config_line(
            &mut b,
            "pd/interface/sla-id",
            &["1", LAN, "16"],
            ConfigOp::Set,
        );
        let numbered = "2001:db8:100:10::1/64";
        assert_eq!(
            asked(&mut b),
            [
                format!("lan0 {}", del(host)),
                format!("lan0 {}", add(numbered))
            ]
        );
        // A leaf alone makes its entry.
        config_line(
            &mut b,
            "pd/interface/sla-id",
            &["1", LAN2, "17"],
            ConfigOp::Set,
        );
        let other = "2001:db8:100:11:0:ff:fe00:e3/64";
        assert_eq!(asked(&mut b), [format!("lan1 {}", add(other))]);
        // None of it is asked of a server: the client is who it was.
        assert_eq!(state(&b), State::Bound);
        assert_eq!(retiring(&b), None);
        assert_eq!(given(&b).len(), 2);

        // A leaf deleted is its default again.
        config_line(&mut b, "pd/interface/sla-id", &["1", LAN], ConfigOp::Delete);
        assert_eq!(
            asked(&mut b),
            [
                format!("lan0 {}", del(numbered)),
                format!("lan0 {}", add(host))
            ]
        );
        config_line(
            &mut b,
            "pd/interface/address",
            &["1", LAN],
            ConfigOp::Delete,
        );
        assert_eq!(
            asked(&mut b),
            [format!("lan0 {}", del(host)), format!("lan0 {}", add(made))]
        );
        config_line(
            &mut b,
            "pd/interface/address",
            &["1", LAN, "1"],
            ConfigOp::Set,
        );
        assert_eq!(
            asked(&mut b),
            [format!("lan0 {}", del(made)), format!("lan0 {}", add(host))]
        );
        // A deleted entry is gone whichever of its lines comes last.
        config_line(&mut b, "pd/interface", &["1", LAN2], ConfigOp::Delete);
        assert_eq!(asked(&mut b), [format!("lan1 {}", del(other))]);
        config_line(
            &mut b,
            "pd/interface/sla-id",
            &["1", LAN2],
            ConfigOp::Delete,
        );
        config_line(
            &mut b,
            "pd/interface/address",
            &["1", LAN2],
            ConfigOp::Delete,
        );
        assert!(asked(&mut b).is_empty());
        let interfaces = |b: &Bench| {
            let pd = &b.dhcpc.v6.ifaces[IF].cfg.pd[&1];
            pd.interfaces.keys().cloned().collect::<Vec<_>>()
        };
        assert_eq!(interfaces(&b), [LAN]);
        assert_eq!(given(&b), [(LAN.to_string(), host.to_string())]);

        // So is a deleted delegation, with its interfaces: the prefix is
        // given back, and the lines of its interfaces bring nothing
        // back.
        config_line(&mut b, "pd", &["1"], ConfigOp::Delete);
        assert_eq!(
            asked(&mut b),
            [format!("no route {PREFIX}"), format!("lan0 {}", del(host))]
        );
        config_line(&mut b, "pd/interface", &["1", LAN], ConfigOp::Delete);
        config_line(
            &mut b,
            "pd/interface/address",
            &["1", LAN],
            ConfigOp::Delete,
        );
        assert!(asked(&mut b).is_empty());
        assert!(b.dhcpc.v6.ifaces[IF].cfg.pd.is_empty());
    }

    #[tokio::test]
    async fn an_interface_that_cannot_be_numbered_is_said_and_left_alone() {
        let mut b = bench("lan-refused");
        // Neither interface is there yet; one entry names the interface
        // the prefix is delegated on, and one a /64 a /56 does not have.
        let cfg = lan_config(&[(LAN, 1, Some(1)), (LAN2, 256, Some(1)), (IF, 2, Some(1))]);
        save_given(&b, &cfg, 0, &prefixes_only(&[(1, PREFIX)]), &[]);
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [format!("route {PREFIX} discard distance 210")]
        );
        let none = |name: &str, reason: &str| format!("    on {name}: none ({reason})\n");
        let text = shown(&b);
        assert!(text.contains(&none(LAN, "no such interface")), "{text}");
        assert!(text.contains(&none(LAN2, "no such interface")), "{text}");
        let upstream = "the prefix is delegated on this interface";
        assert!(text.contains(&none(IF, upstream)), "{text}");

        // The interfaces appear: one is numbered, the other still not.
        add_lan(&mut b, LAN_IFINDEX, LAN);
        b.dhcpc.link_added6(LAN_IFINDEX, LAN, &[]);
        let first = "2001:db8:100:1::1/64";
        assert_eq!(asked(&mut b), [format!("lan0 add {first} 3600/7200")]);
        add_lan(&mut b, LAN2_IFINDEX, LAN2);
        b.dhcpc.link_added6(LAN2_IFINDEX, LAN2, &[]);
        assert!(asked(&mut b).is_empty());
        let text = shown(&b);
        let no_room = "the prefix has no room for this sla-id";
        assert!(text.contains(&none(LAN2, no_room)), "{text}");
        assert!(text.contains(&format!("    on {LAN}: {first}\n")), "{text}");
        let refused: Vec<NoAddress> = b.dhcpc.v6.pd_lan_refused.values().copied().collect();
        assert_eq!(refused, [NoAddress::SlaId, NoAddress::Upstream]);

        // The prefix is in the table of the VRF it is delegated in, and
        // numbers no interface outside it.
        enslave(&mut b, true);
        b.dhcpc.link_added6(VRF_IFINDEX, VRF, &[]);
        assert_eq!(
            asked(&mut b),
            [
                format!("no route {PREFIX}"),
                format!("route {PREFIX} vrf {VRF} discard distance 210"),
                format!("lan0 del {first}"),
            ]
        );
        assert!(shown(&b).contains(&none(LAN, "in another VRF")));
        // One that joins it is numbered, and so is the VRF's own device.
        b.dhcpc.links.get_mut(&LAN_IFINDEX).unwrap().master = Some(VRF_IFINDEX);
        b.dhcpc.link_added6(LAN_IFINDEX, LAN, &[]);
        assert_eq!(asked(&mut b), [format!("lan0 add {first} 3600/7200")]);
        let mut cfg = b.dhcpc.v6.ifaces[IF].cfg.clone();
        let lan = LanConfig {
            sla_id: Some(3),
            address: Some(1),
        };
        let pd = cfg.pd.get_mut(&1).unwrap();
        pd.interfaces.insert(VRF.to_string(), lan);
        commit(&mut b, cfg);
        assert_eq!(asked(&mut b), ["red add 2001:db8:100:3::1/64 3600/7200"]);
    }

    #[tokio::test]
    async fn an_address_made_from_the_hardware_address_follows_it() {
        let mut b = bench("lan-mac");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        b.dhcpc.links.get_mut(&LAN_IFINDEX).unwrap().mac = None;
        let cfg = lan_config(&[(LAN, 1, None)]);
        save_given(&b, &cfg, 0, &prefixes_only(&[(1, PREFIX)]), &[]);
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [format!("route {PREFIX} discard distance 210")]
        );
        let reason = "no hardware address: set `address`";
        let text = shown(&b);
        assert!(
            text.contains(&format!("    on {LAN}: none ({reason})\n")),
            "{text}"
        );
        // It has one now, and then another.
        for (last, made) in [(0xe2, "e2"), (0xe9, "e9")] {
            b.dhcpc.links.get_mut(&LAN_IFINDEX).unwrap().mac = Some([2, 0, 0, 0, 0, last]);
            b.dhcpc.link_mac6(LAN);
            let asked_now = asked(&mut b);
            let add = format!("lan0 add 2001:db8:100:1:0:ff:fe00:{made}/64 3600/7200");
            assert_eq!(asked_now.last(), Some(&add), "{asked_now:?}");
            assert_eq!(asked_now.len(), if last == 0xe2 { 1 } else { 2 });
        }
    }

    #[tokio::test]
    async fn what_an_earlier_run_gave_is_claimed_or_removed() {
        let first = "2001:db8:100:1::1/64";
        let second = "2001:db8:100:2::1/64";
        // The lease is resumed, and one of the two interfaces it had
        // numbered is no longer configured: that address is claimed to
        // be removed, and the other with the times it has now.
        let mut b = bench("lan-left");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        add_lan(&mut b, LAN2_IFINDEX, LAN2);
        let cfg = lan_config(&[(LAN, 1, Some(1))]);
        let held = prefixes_only(&[(1, PREFIX)]);
        save_given(&b, &cfg, 600, &held, &[(LAN, first), (LAN2, second)]);
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [
                format!("route {PREFIX} discard distance 210"),
                format!("lan1 add {second} 0/1"),
                format!("lan1 del {second}"),
                format!("lan0 add {first} 3000/6600"),
            ]
        );
        assert_eq!(given(&b), [(LAN.to_string(), first.to_string())]);

        // No interface is configured any more: the file names none
        // either, or the next run would remove them once more.
        let mut b = bench("lan-left-all");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        let cfg = pd_config(false, &[1]);
        save_given(&b, &cfg, 600, &held, &[(LAN, first), ("gone0", second)]);
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [
                format!("route {PREFIX} discard distance 210"),
                format!("lan0 add {first} 0/1"),
                format!("lan0 del {first}"),
            ]
        );
        assert!(saved(&b).is_some());
        assert!(given(&b).is_empty());

        // The lease was taken as somebody else and is given back: what
        // it gave goes at once, though the interface is still
        // configured. The next lease numbers it.
        let mut b = bench("lan-left-retired");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        let cfg = lan_config(&[(LAN, 1, Some(1))]);
        save_given(&b, &cfg, 600, &held, &[(LAN, first)]);
        let mut hinted = cfg.clone();
        hinted.pd.get_mut(&1).unwrap().length = Some(56);
        commit(&mut b, hinted);
        assert_eq!(
            asked(&mut b),
            [
                format!("route {PREFIX} discard distance 210"),
                format!("lan0 add {first} 0/1"),
                format!("lan0 del {first}"),
            ]
        );
        assert_eq!(retiring(&b), Some(State::Bound));

        // A prefix that ran out while nobody looked took its addresses
        // with it: the kernel has none to remove.
        let mut b = bench("lan-left-expired");
        add_lan(&mut b, LAN_IFINDEX, LAN);
        let cfg = pd_config(false, &[1, 2]);
        let mut held = prefixes_only(&[(1, PREFIX), (2, PREFIX2)]);
        held.ia_pd[1].prefixes[0].valid = 610;
        save_given(&b, &cfg, 700, &held, &[(LAN, "2001:db8:200:1::1/64")]);
        commit(&mut b, cfg);
        assert_eq!(
            asked(&mut b),
            [format!("route {PREFIX} discard distance 210")]
        );
    }

    #[tokio::test]
    async fn the_verbs_name_their_interface() {
        let mut b = bench("verbs");
        assert_eq!(b.dhcpc.renew6(verb()), format!("No DHCPv6 client on {IF}"));
        assert_eq!(
            b.dhcpc.release6(verb()),
            format!("No DHCPv6 client on {IF}")
        );
        assert_eq!(
            b.dhcpc.renew6(Args(VecDeque::new())),
            "% Interface name required"
        );
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        make_ready(&mut b);
        asked(&mut b);
        assert_eq!(
            b.dhcpc.renew6(verb()),
            format!("Renewing the DHCPv6 lease on {IF}")
        );
        assert_eq!(state(&b), State::Renewing);
        assert_eq!(
            b.dhcpc.release6(verb()),
            format!("Released the DHCPv6 lease on {IF}")
        );
        assert_eq!(asked(&mut b), [format!("del {ADDRESS}/128")]);
        assert_eq!(state(&b), State::Releasing);
        run_timers(&mut b, Duration::from_secs(20));
        assert_eq!(state(&b), State::Released);
        // It stays released, and stays there, until asked again.
        assert!(b.dhcpc.v6.ifaces.contains_key(IF));
        assert_eq!(b.dhcpc.next_deadline6(), None);
        b.dhcpc.renew6(verb());
        assert_eq!(state(&b), State::Soliciting);
    }

    #[tokio::test]
    async fn the_system_duid_is_made_once_and_shared() {
        let mut b = bench("duid");
        b.dhcpc.links.insert(
            IFINDEX + 1,
            LinkInfo {
                name: "dhcpc6-test1".to_string(),
                mac: Some([2, 0, 0, 0, 0, 9]),
                mtu: 1500,
                up: true,
                master: None,
                is_vrf: false,
            },
        );
        for name in [IF, "dhcpc6-test1"] {
            let cfg = &mut b.dhcpc.v6.ifaces.entry(name.to_string()).or_default().cfg;
            cfg.address = true;
            b.dhcpc.reconcile6(name);
        }
        // A DUID-LLT from the first interface's hardware address, on
        // disk, and the same for both; the IAIDs tell them apart.
        let first = duid_of(&b);
        assert_eq!(first[..4], [0, 1, 0, 1]);
        assert_eq!(first[8..], MAC);
        let on_disk = DuidStore::new(&b.dir).load().unwrap();
        assert_eq!(on_disk.as_ref(), Some(&first));
        let other = &b.dhcpc.v6.ifaces["dhcpc6-test1"];
        let (duid, asks) = other.session.as_ref().unwrap().client.identity();
        assert_eq!(duid, first);
        assert_eq!(asks.ia_na, Some(ident::iaid("dhcpc6-test1")));
        assert_ne!(asks.ia_na, Some(ident::iaid(IF)));
        // Its own DUID for one interface leaves the other's alone.
        configure(&mut b, &OTHER_DUID);
        assert_eq!(duid_of(&b), OTHER_DUID);
        let other = &b.dhcpc.v6.ifaces["dhcpc6-test1"];
        assert_eq!(other.session.as_ref().unwrap().client.identity().0, first);
    }

    const DNS1: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x53, 0, 0, 0, 0, 0x53);
    const DNS2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x53, 0, 0, 0, 0, 0x54);

    /// `lease()`, with what a server says of name resolution.
    fn lease_with_dns(addresses: &[Ipv6Addr]) -> Lease {
        Lease {
            dns_servers: vec![DNS1, DNS2],
            domain_list: vec!["example.com".to_string(), "corp.example".to_string()],
            ..lease(addresses)
        }
    }

    fn its_dns() -> LinkDns {
        LinkDns {
            servers: vec![IpAddr::V6(DNS1), IpAddr::V6(DNS2)],
            domains: vec!["example.com".to_string(), "corp.example".to_string()],
        }
    }

    /// Take the resolver's place.
    fn resolver(b: &mut Bench) -> UnboundedReceiver<Report> {
        let (tx, rx) = mpsc::unbounded_channel();
        b.dhcpc.set_resolver(tx);
        rx
    }

    /// What the task reported of `IF` since the last call.
    fn reported(rx: &mut UnboundedReceiver<Report>) -> Vec<Option<LinkDns>> {
        let mut out = Vec::new();
        while let Ok(report) = rx.try_recv() {
            assert_eq!((report.ifname.as_str(), report.source), (IF, Source::Dhcp6));
            out.push(report.dns);
        }
        out
    }

    /// The resolver hears of a lease's name servers when the lease is
    /// held, once, and that they are gone when it is given up.
    #[tokio::test]
    async fn a_held_lease_reports_its_name_servers_until_it_ends() {
        let mut b = bench("dns-held");
        let mut rx = resolver(&mut b);
        save(&b, &DUID, 60, &lease_with_dns(&[ADDRESS]));
        configure(&mut b, &DUID);
        assert_eq!(state(&b), State::Bound);
        assert_eq!(reported(&mut rx), [Some(its_dns())]);

        // Verified with the server, a leaf that is not about them
        // changed: nothing is said twice.
        make_ready(&mut b);
        b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg.rapid_commit = true;
        b.dhcpc.reconcile6(IF);
        assert_eq!(reported(&mut rx), []);

        b.dhcpc.release6(verb());
        assert_eq!(reported(&mut rx), [None]);
        b.dhcpc.reconcile6(IF);
        assert_eq!(reported(&mut rx), []);
    }

    #[tokio::test]
    async fn deleting_the_configuration_takes_the_name_servers_back() {
        let mut b = bench("dns-config");
        let mut rx = resolver(&mut b);
        save(&b, &DUID, 0, &lease_with_dns(&[ADDRESS]));
        configure(&mut b, &DUID);
        reported(&mut rx);
        b.dhcpc.v6.ifaces.get_mut(IF).unwrap().cfg = IfConfig6::default();
        b.dhcpc.reconcile6(IF);
        assert_eq!(reported(&mut rx), [None]);
    }

    #[tokio::test]
    async fn a_deleted_link_takes_the_name_servers_back() {
        let mut b = bench("dns-link");
        let mut rx = resolver(&mut b);
        save(&b, &DUID, 0, &lease_with_dns(&[ADDRESS]));
        configure(&mut b, &DUID);
        reported(&mut rx);
        b.dhcpc.link_deleted6(IFINDEX, IF);
        assert_eq!(reported(&mut rx), [None]);
    }

    /// One `dhcpv6-options` leaf of `IF` set or deleted, as the
    /// configuration delivers it, and the end of its commit.
    fn commit_option(b: &mut Bench, leaf: &str, op: ConfigOp) {
        let callback = b.dhcpc.callbacks[&format!("/interface/ipv6/dhcpv6-options/{leaf}")];
        callback(&mut b.dhcpc, verb(), op);
        b.dhcpc
            .process_cm_msg(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
    }

    /// `dhcpv6-options no-name-server`: the lease is held like any
    /// other, and the host is told nothing of its name servers. Deleted
    /// under a held lease it gives the ones held, and set it takes them
    /// back, without the server or the lease hearing of either.
    #[tokio::test]
    async fn no_name_server_keeps_a_lease_s_name_servers_from_the_host() {
        let mut b = bench("dns-opt-out");
        let mut rx = resolver(&mut b);
        save(&b, &DUID, 0, &lease_with_dns(&[ADDRESS]));
        commit_option(&mut b, "no-name-server", ConfigOp::Set);
        assert!(b.dhcpc.v6.ifaces[IF].cfg.no_name_server);
        configure(&mut b, &DUID);
        assert_eq!(state(&b), State::Bound);
        assert_eq!(reported(&mut rx), []);
        asked(&mut b);

        commit_option(&mut b, "no-name-server", ConfigOp::Delete);
        assert!(!b.dhcpc.v6.ifaces[IF].cfg.no_name_server);
        assert_eq!(reported(&mut rx), [Some(its_dns())]);
        commit_option(&mut b, "no-name-server", ConfigOp::Set);
        assert_eq!(reported(&mut rx), [None]);
        assert_eq!(state(&b), State::Bound);
        assert!(asked(&mut b).is_empty());
        assert!(saved(&b).is_some());
    }

    /// The leaf alone, with no client asked for, is kept and says
    /// nothing; deleted, nothing is left of the interface.
    #[tokio::test]
    async fn no_name_server_alone_starts_nothing() {
        let mut b = bench("dns-opt-out-alone");
        let mut rx = resolver(&mut b);
        commit_option(&mut b, "no-name-server", ConfigOp::Set);
        assert!(b.dhcpc.v6.ifaces[IF].session.is_none());
        assert!(b.dhcpc.v6.ifaces[IF].cfg.no_name_server);
        commit_option(&mut b, "no-name-server", ConfigOp::Delete);
        assert!(!b.dhcpc.v6.ifaces.contains_key(IF));
        assert_eq!(reported(&mut rx), []);
    }

    /// Another DUID is another client: the lease goes back and its name
    /// servers with it, before the successor has any.
    #[tokio::test]
    async fn another_duid_takes_the_name_servers_back() {
        let mut b = bench("dns-other-duid");
        let mut rx = resolver(&mut b);
        save(&b, &DUID, 0, &lease_with_dns(&[ADDRESS]));
        configure(&mut b, &DUID);
        make_ready(&mut b);
        assert_eq!(reported(&mut rx), [Some(its_dns())]);
        configure(&mut b, &OTHER_DUID);
        assert_eq!(retiring(&b), Some(State::Releasing));
        assert_eq!(reported(&mut rx), [None]);
    }

    /// A lease saved under another DUID is resumed only to be released
    /// as who took it, and held until the link can carry the Release.
    /// The host is not pointed at its name servers meanwhile.
    #[tokio::test]
    async fn a_lease_on_its_way_back_reports_no_name_servers() {
        let mut b = bench("dns-retiring");
        let mut rx = resolver(&mut b);
        save(&b, &OTHER_DUID, 600, &lease_with_dns(&[ADDRESS]));
        configure(&mut b, &DUID);
        // Held, with its address on the interface.
        assert_eq!(retiring(&b), Some(State::Bound));
        let held = b.dhcpc.v6.ifaces[IF].retiring.as_ref().unwrap();
        assert_eq!(
            held.session.bound.as_ref().and_then(lease_dns6),
            Some(its_dns())
        );
        assert_eq!(reported(&mut rx), []);
        // Nor when it goes back.
        make_ready(&mut b);
        assert_eq!(retiring(&b), Some(State::Releasing));
        assert_eq!(reported(&mut rx), []);
    }

    /// A lease that runs out takes its name servers with it.
    #[tokio::test]
    async fn a_lease_that_runs_out_takes_the_name_servers_back() {
        let mut b = bench("dns-expires");
        let mut rx = resolver(&mut b);
        save(&b, &DUID, 7190, &lease_with_dns(&[ADDRESS]));
        configure(&mut b, &DUID);
        assert_eq!(reported(&mut rx), [Some(its_dns())]);
        // The link never comes: at the end of its lifetime it goes.
        run_timers(&mut b, Duration::from_secs(20));
        assert_eq!(reported(&mut rx), [None]);
    }

    /// What `parameters-only` is given comes without a lease, and its
    /// name servers are reported all the same. Other servers at the
    /// next answer replace them.
    #[tokio::test]
    async fn parameters_without_a_lease_report_their_name_servers() {
        let mut b = bench("dns-parameters");
        let mut rx = resolver(&mut b);
        let cfg = &mut b.dhcpc.v6.ifaces.entry(IF.to_string()).or_default().cfg;
        cfg.parameters_only = true;
        cfg.duid = Some(DUID.to_vec());
        b.dhcpc.reconcile6(IF);
        assert_eq!(reported(&mut rx), []);

        let given = |servers: Vec<Ipv6Addr>| Lease {
            ia_na: None,
            dns_servers: servers,
            ..lease_with_dns(&[])
        };
        fn session(b: &mut Bench) -> &mut Session {
            let iface = b.dhcpc.v6.ifaces.get_mut(IF).unwrap();
            iface.session.as_mut().expect("a client")
        }
        session(&mut b).bound = Some(given(vec![DNS1, DNS2]));
        b.dhcpc.reconcile6(IF);
        assert_eq!(reported(&mut rx), [Some(its_dns())]);
        assert!(asked(&mut b).is_empty());

        session(&mut b).bound = Some(given(vec![DNS2]));
        b.dhcpc.reconcile6(IF);
        let mut other = its_dns();
        other.servers.remove(0);
        assert_eq!(reported(&mut rx), [Some(other)]);
    }

    /// A lease that names no server and no domain says nothing.
    #[tokio::test]
    async fn a_lease_without_name_servers_reports_nothing() {
        let mut b = bench("dns-none");
        let mut rx = resolver(&mut b);
        save(&b, &DUID, 0, &lease(&[ADDRESS]));
        configure(&mut b, &DUID);
        assert_eq!(state(&b), State::Bound);
        assert_eq!(reported(&mut rx), []);
    }
}
