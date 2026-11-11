//! The DHCPv6 side of the DHCP client task: one [`Client`] state machine
//! per interface configured with `ipv6 address dhcpv6` or
//! `ipv6 dhcpv6-options parameters-only`, driven by the socket, the
//! clock, the RIB's link and address events and the configuration.
//!
//! It shares the task ([`Dhcpc`]) and its event loop with DHCPv4 and
//! keeps its own state beside it ([`V6`]). Everything a lease gives goes
//! through the RIB: each address as a dynamic /128 that brings no
//! connected route (`AddrOrigin::Dhcp6`). The default route and the
//! on-link prefixes are the RA host's to install (`nd`), not this
//! client's.
//!
//! A client is one identity (DUID, IAID) and one of the two protocols
//! (an address, or parameters only). When the configuration changes
//! either, or is deleted, the client is *retired*: it releases its lease
//! as who took it, and lives on beside its successor until the server
//! has answered the Release or it has been sent as often as it is to be.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::Instant;

use dhcp_packet::v6::Message as Dhcp6Message;
use ipnet::{IpNet, Ipv6Net};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::Args;
use crate::dhcpc::ident::{self, DuidStore};
use crate::dhcpc::inst::{Dhcpc, lifetime, unix_now};
use crate::dhcpc::lease::Kept6;
use crate::fib::AddrOpts;
use crate::rib::Message;
use crate::rib::link::{AddrOrigin, LinkAddr};

use super::client::{Action, Address, Asks, Client, Event, Lease, Options, State};
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
}

impl IfConfig6 {
    /// Whether a client runs at all.
    pub fn wanted(&self) -> bool {
        self.address || self.parameters_only
    }

    fn options(&self) -> Options {
        Options {
            rapid_commit: self.rapid_commit,
            no_release: self.no_release,
        }
    }

    /// What the client of interface `name` asks for: an address with
    /// `address dhcpv6`, and nothing but the other configuration with
    /// `parameters-only` alone. An address is asked for whenever
    /// `address dhcpv6` is there: a commit holding `parameters-only`
    /// beside it is refused (`config::check`), and a startup config that
    /// does is taken this way.
    fn asks(&self, name: &str) -> Asks {
        Asks {
            ia_na: self.address.then(|| ident::iaid(name)),
            ia_pd: Vec::new(),
        }
    }
}

/// A client and what it has put in the RIB.
pub struct Session {
    pub client: Client,
    /// The lease whose addresses are in the RIB.
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
        }
    }
}

fn addresses(lease: &Lease) -> &[Address] {
    lease
        .ia_na
        .as_ref()
        .map_or(&[], |ia| ia.addresses.as_slice())
}

/// The addresses of a lease as the log names them.
fn address_list(lease: &Lease) -> String {
    let list: Vec<String> = addresses(lease)
        .iter()
        .map(|a| a.address.to_string())
        .collect();
    list.join(", ")
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
    }

    /// A link's hardware address changed, or it has one now.
    pub(in crate::dhcpc) fn link_mac6(&mut self, name: &str) {
        self.reconcile6(name);
        self.start_waiting6();
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
        if let Some(kept) = self.store.load6(name, unix) {
            // The file holds an address lease, under the IAID of its
            // IA_NA.
            if kept.duid == duid && asks.ia_na == Some(kept.iaid) {
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
        let asks = Asks {
            ia_na: Some(kept.iaid),
            ia_pd: Vec::new(),
        };
        let mut client = Client::new(kept.duid, asks, options, Box::new(rand::random::<u32>));
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
                        if lease.ia_na.is_some() {
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
        if fresh {
            let obtained = unix_now();
            session.obtained = Some(obtained);
            // Under the identity that took it, which is the client's.
            // What `parameters-only` learns is asked for again instead.
            if save
                && let Some(ia) = &lease.ia_na
                && let Err(e) = self.store.save6(
                    name,
                    (session.client.identity().0, ia.iaid),
                    obtained,
                    &lease,
                )
            {
                tracing::warn!("dhcpv6 client: {name}: lease not saved: {e}");
            }
        }
        let changed = session.bound.is_none()
            || !gone.is_empty()
            || new.iter().any(|a| !old.contains(&a.address));
        match (&lease.ia_na, changed || !fresh) {
            (Some(ia), true) => {
                let longest = ia.addresses.iter().map(|a| a.valid).max().unwrap_or(0);
                tracing::info!(
                    "dhcpv6 client: {name}: {} {} from {}, valid {}",
                    if fresh { "bound" } else { "resumed" },
                    address_list(&lease),
                    lease.server_address,
                    lifetime(longest),
                );
            }
            (Some(_), false) => {
                tracing::debug!("dhcpv6 client: {name}: renewed {}", address_list(&lease));
            }
            (None, true) => tracing::info!(
                "dhcpv6 client: {name}: configuration parameters from {}",
                lease.server_address
            ),
            (None, false) => tracing::debug!(
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
    use crate::dhcpc::inst::LinkInfo;
    use crate::dhcpc::lease::Store;
    use crate::dhcpc::v6::client::Ia;
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

    struct Bench {
        dhcpc: Dhcpc,
        rib: UnboundedReceiver<RibInbound>,
        dir: PathBuf,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A task that knows one link, up, with no address yet.
    fn bench(test: &str) -> Bench {
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

    /// `address dhcpv6` with `dhcpv6-options duid`, committed.
    fn configure(b: &mut Bench, duid: &[u8]) {
        let cfg = &mut b.dhcpc.v6.ifaces.entry(IF.to_string()).or_default().cfg;
        cfg.address = true;
        cfg.duid = Some(duid.to_vec());
        b.dhcpc.reconcile6(IF);
    }

    /// A lease on disk taken as `duid`, `age` seconds ago.
    fn save(b: &Bench, duid: &[u8], age: u64, lease: &Lease) {
        let identity = (duid, ident::iaid(IF));
        b.dhcpc
            .store
            .save6(IF, identity, unix_now() - age, lease)
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
        while let Ok(inbound) = b.rib.try_recv() {
            out.push(match inbound.msg {
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
                _ => "other".to_string(),
            });
        }
        out
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
}
