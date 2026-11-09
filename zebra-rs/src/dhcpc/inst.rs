//! The DHCP client task: one [`Client`] state machine per configured
//! interface, driven by the sockets, the clock, the RIB's link events and
//! the configuration.
//!
//! Every path into a client goes through [`Dhcpc::drive`]: it feeds one
//! event to the state machine and carries out the actions that come back —
//! packets through the interface's sockets, the address and routes through
//! the RIB, the lease to disk.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dhcp_packet::v4::Packet;
use ipnet::{IpNet, Ipv4Net};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep_until;

use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::Task;
use crate::fib::AddrOpts;
use crate::rib::Message;
use crate::rib::api::RibRx;
use crate::rib::client::RibClient;
use crate::rib::link::{AddrOrigin, Link};

use super::config::Callback;
use super::lease::Store;
use super::routes::{Leg, Routes, Wanted, lease_routes};
use super::v4::client::{Action, Client, Event, Lease, Options};
use super::v4::socket::{self, ArpReader, Input, PacketReader, UdpReader};

/// `default-route-distance` when not configured: above every routing
/// protocol, so a routed default always wins over a leased one (VyOS's
/// default).
pub const DEFAULT_DISTANCE: u8 = 210;

/// How long a saved lease that must be given back waits, once the link
/// is up, for its address and a route to be usable; and how often that is
/// looked at when no event says so.
const RELEASE_WAIT: Duration = Duration::from_secs(10);
const RELEASE_POLL: Duration = Duration::from_millis(250);

pub type ShowCallback = fn(&Dhcpc, Args, bool) -> Result<String, std::fmt::Error>;

/// `interface <if> ipv4 address dhcp` and `… ipv4 dhcp-options …`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IfConfig {
    /// `ipv4 address dhcp` is set.
    pub enabled: bool,
    pub client_id: Option<Vec<u8>>,
    pub host_name: Option<String>,
    pub vendor_class_id: Option<String>,
    pub user_class: Option<String>,
    pub reject: Vec<Ipv4Net>,
    pub distance: Option<u8>,
    pub no_default_route: bool,
}

impl IfConfig {
    fn options(&self, system_hostname: &Option<String>) -> Options {
        Options {
            client_id: self.client_id.clone(),
            // The system's name unless the interface has its own.
            host_name: self.host_name.clone().or_else(|| system_hostname.clone()),
            vendor_class_id: self.vendor_class_id.clone(),
            user_class: self.user_class.clone(),
            reject: self.reject.clone(),
            request_mtu: false,
        }
    }

    pub fn distance(&self) -> u8 {
        self.distance.unwrap_or(DEFAULT_DISTANCE)
    }
}

/// What the task remembers of a kernel link.
#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub name: String,
    pub mac: Option<[u8; 6]>,
    pub mtu: u32,
    pub up: bool,
    pub master: Option<u32>,
    /// A VRF device: its name is the VRF's.
    pub is_vrf: bool,
}

impl LinkInfo {
    fn from(link: &Link) -> LinkInfo {
        LinkInfo {
            name: link.name.clone(),
            mac: link.mac.map(|mac| mac.octets()),
            mtu: link.mtu,
            up: link.is_up(),
            master: link.master,
            is_vrf: link.vrf_table.is_some(),
        }
    }
}

/// One configured interface.
#[derive(Default)]
pub struct Iface {
    pub cfg: IfConfig,
    /// The kernel link, while there is one.
    pub ifindex: Option<u32>,
    pub client: Option<Client>,
    /// The lease whose address and routes are in the RIB.
    pub bound: Option<Lease>,
    /// UNIX time `bound` began.
    pub obtained: Option<u64>,
    packet: Option<PacketReader>,
    arp: Option<ArpReader>,
    udp: Option<UdpReader>,
    /// A socket could not be opened and that has been said once.
    socket_failed: bool,
    /// A saved lease taken under another identity is on its way back to
    /// the server (`Dhcpc::begin_release`): `client` is the old identity's,
    /// holding that lease, until `Dhcpc::pump_release` has sent the
    /// RELEASE. The time is when to stop waiting, set once the link is up.
    releasing: Option<Option<Instant>>,
    /// The operator released the lease while no client of the current
    /// identity existed yet: the next one starts as released and waits
    /// for `renew` (`Dhcpc::release_pending`).
    start_released: bool,
}

impl Iface {
    fn close_all(&mut self) {
        self.packet = None;
        self.arp = None;
        self.udp = None;
    }
}

pub struct Dhcpc {
    rib: RibClient,
    rib_rx: UnboundedReceiver<RibRx>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub callbacks: HashMap<String, Callback>,
    input_tx: UnboundedSender<Input>,
    input_rx: UnboundedReceiver<Input>,
    pub links: BTreeMap<u32, LinkInfo>,
    /// By interface name: configuration can precede the link.
    pub ifaces: BTreeMap<String, Iface>,
    routes: Routes,
    store: Store,
    /// `system hostname`, sent as option 12 unless an interface sets its
    /// own.
    pub hostname: Option<String>,
    /// Interfaces whose configuration changed in the commit under way.
    pub(super) touched: Vec<String>,
    /// When to look at the pending releases next (`next_wakeup`).
    release_poll: Option<Instant>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Dhcpc {
    pub fn new(
        rib: RibClient,
        rib_rx: UnboundedReceiver<RibRx>,
        hostname: Option<String>,
    ) -> Dhcpc {
        let store = Store::new(super::lease::default_dir());
        Dhcpc::with_store(rib, rib_rx, hostname, store)
    }

    fn with_store(
        rib: RibClient,
        rib_rx: UnboundedReceiver<RibRx>,
        hostname: Option<String>,
        store: Store,
    ) -> Dhcpc {
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let mut dhcpc = Dhcpc {
            rib,
            rib_rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            callbacks: HashMap::new(),
            input_tx,
            input_rx,
            links: BTreeMap::new(),
            ifaces: BTreeMap::new(),
            routes: Routes::default(),
            store,
            hostname,
            touched: Vec::new(),
            release_poll: None,
        };
        dhcpc.callback_build();
        dhcpc.show_build();
        dhcpc
    }

    async fn event_loop(&mut self) {
        // The RIB's link dump first, so the configuration that follows
        // finds its interfaces (see `nd::inst`).
        while let Some(msg) = self.rib_rx.recv().await {
            if matches!(msg, RibRx::EoR) {
                break;
            }
            self.process_rib_msg(msg);
        }
        loop {
            let wakeup = self.next_wakeup(Instant::now());
            tokio::select! {
                Some(input) = self.input_rx.recv() => self.process_input(input),
                Some(msg) = self.rib_rx.recv() => self.process_rib_msg(msg),
                Some(msg) = self.cm.rx.recv() => self.process_cm_msg(msg),
                Some(msg) = self.show.rx.recv() => self.process_show_msg(msg).await,
                _ = sleep_until_opt(wakeup) => self.on_wakeup(Instant::now()),
            }
        }
    }

    /// When the event loop must wake by itself: the earliest client timer,
    /// or the next look at a pending release.
    ///
    /// The release poll is a deadline that stays where it is until it has
    /// been served (`on_wakeup`). Worked out afresh as "a quarter of a
    /// second from now" on every pass of the loop, it would be pushed back
    /// by every other event, and a loop kept busy would never reach it:
    /// the release, and the limit on waiting for it, hang on this tick
    /// whenever no event brings them about.
    fn next_wakeup(&mut self, now: Instant) -> Option<Instant> {
        if self.ifaces.values().any(|iface| iface.releasing.is_some()) {
            self.release_poll.get_or_insert(now + RELEASE_POLL);
        } else {
            self.release_poll = None;
        }
        self.ifaces
            .values()
            .filter(|iface| iface.releasing.is_none())
            .filter_map(|iface| iface.client.as_ref()?.deadline())
            .chain(self.release_poll)
            .min()
    }

    fn on_wakeup(&mut self, now: Instant) {
        self.process_timeouts();
        if self.release_poll.is_some_and(|at| at <= now) {
            self.release_poll = None;
            self.pump_releases(now);
        }
    }

    fn process_timeouts(&mut self) {
        let now = Instant::now();
        let due: Vec<String> = self
            .ifaces
            .iter()
            .filter(|(_, iface)| {
                // A lease being given back is not renewed in the meantime.
                iface.releasing.is_none()
                    && iface
                        .client
                        .as_ref()
                        .and_then(Client::deadline)
                        .is_some_and(|at| at <= now)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in due {
            self.drive(&name, Event::Timeout);
        }
    }

    fn iface_name(&self, ifindex: u32) -> Option<String> {
        self.ifaces
            .iter()
            .find(|(_, iface)| iface.ifindex == Some(ifindex))
            .map(|(name, _)| name.clone())
    }

    fn process_input(&mut self, input: Input) {
        match input {
            Input::Dhcp {
                ifindex,
                source,
                payload,
            } => {
                let Some(name) = self.iface_name(ifindex) else {
                    return;
                };
                if let Ok(packet) = Packet::parse(&payload) {
                    self.drive(
                        &name,
                        Event::Packet {
                            packet: &packet,
                            source,
                        },
                    );
                }
            }
            Input::Arp { ifindex, arp } => {
                let Some(name) = self.iface_name(ifindex) else {
                    return;
                };
                let probing = self.ifaces[&name].client.as_ref().and_then(Client::probing);
                let mac = self.links.get(&ifindex).and_then(|link| link.mac);
                if let (Some(address), Some(mac)) = (probing, mac)
                    && arp.conflicts_with(address, mac)
                {
                    self.drive(&name, Event::ArpConflict);
                }
            }
        }
    }

    fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            RibRx::LinkAdd(link) => {
                let name = link.name.clone();
                self.links.insert(link.index, LinkInfo::from(&link));
                self.reconcile(&name);
            }
            RibRx::LinkDel(ifindex) => {
                if let Some(link) = self.links.remove(&ifindex) {
                    self.detach(&link.name);
                }
            }
            RibRx::LinkUp(ifindex) | RibRx::LinkDown(ifindex) => {
                let up = matches!(msg, RibRx::LinkUp(_));
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.up = up;
                let name = link.name.clone();
                if self.is_releasing(&name) {
                    // The old identity's client only has a RELEASE left
                    // to send, which the link coming up may now allow.
                    self.sync_routes();
                    self.pump_release(&name);
                } else {
                    self.drive(&name, Event::Carrier(up));
                }
            }
            RibRx::LinkMtu { ifindex, mtu } => {
                if let Some(link) = self.links.get_mut(&ifindex) {
                    link.mtu = mtu;
                    let name = link.name.clone();
                    self.reconcile(&name);
                }
            }
            RibRx::LinkMac { ifindex, mac } => {
                if let Some(link) = self.links.get_mut(&ifindex) {
                    link.mac = Some(mac.octets());
                    let name = link.name.clone();
                    self.reconcile(&name);
                }
            }
            RibRx::AddrAdd(addr) => {
                if let Some(name) = self.iface_name(addr.ifindex)
                    && self.is_releasing(&name)
                {
                    // Perhaps the address a RELEASE is waiting for.
                    self.pump_release(&name);
                    return;
                }
                // The configuration named the leased address too, which
                // made it permanent in the kernel, and has now let go of
                // it: the lease owns it alone again, so its lifetime
                // goes back on. (A lease that never expires has none.)
                if addr.config || addr.valid_lft != Some(u32::MAX) {
                    return;
                }
                let Some(name) = self.iface_name(addr.ifindex) else {
                    return;
                };
                let iface = &self.ifaces[&name];
                let (Some(lease), Some(client)) = (&iface.bound, &iface.client) else {
                    return;
                };
                if IpNet::V4(lease.net()) != addr.addr {
                    return;
                }
                if let Some((_, _, remaining)) = client.remaining(Instant::now()) {
                    self.install_address(addr.ifindex, lease, remaining);
                }
            }
            RibRx::AddrDel(addr) => {
                // The kernel dropped an address: ours, if a lease holds
                // it (our own withdrawal clears `bound` first).
                let Some(name) = self.iface_name(addr.ifindex) else {
                    return;
                };
                let ours = self.ifaces[&name]
                    .bound
                    .as_ref()
                    .is_some_and(|lease| IpNet::V4(lease.net()) == addr.addr);
                if !ours {
                    return;
                }
                if self.is_releasing(&name) {
                    // The address the RELEASE was to leave from is gone:
                    // there is nothing left to wait for.
                    if let Some(iface) = self.ifaces.get_mut(&name) {
                        iface.bound = None;
                    }
                    self.pump_release(&name);
                } else {
                    self.drive(&name, Event::AddressLost);
                }
            }
            _ => {}
        }
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        if msg.op == ConfigOp::CommitEnd {
            // Apply once the whole commit is known, so `address dhcp`
            // and its options take effect together.
            let mut touched = std::mem::take(&mut self.touched);
            touched.sort();
            touched.dedup();
            for name in touched {
                self.reconcile(&name);
            }
            return;
        }
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path).copied() {
            f(self, args, msg.op);
        }
    }

    async fn process_show_msg(&mut self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        let output = match path.as_str() {
            "/renew/dhcp/interface" => self.renew(args),
            "/release/dhcp/interface" => self.release(args),
            _ => match self.show_cb.get(&path) {
                Some(f) => f(self, args, msg.json)
                    .unwrap_or_else(|e| format!("Error formatting output: {e}")),
                None => return,
            },
        };
        let _ = msg.resp.send(output).await;
    }

    /// Every interface's configuration changed (the system host name).
    pub(super) fn touch_all(&mut self) {
        self.touched.extend(self.ifaces.keys().cloned());
    }

    /// Bring `name`'s client in line with its configuration and its link:
    /// start it, stop it, or hand it changed options.
    pub(super) fn reconcile(&mut self, name: &str) {
        let now = Instant::now();
        let Some(mut iface) = self.ifaces.remove(name) else {
            return;
        };
        let link = self
            .links
            .iter()
            .find(|(_, link)| link.name == name)
            .map(|(ifindex, link)| (*ifindex, link.clone()));
        let usable = link
            .as_ref()
            .and_then(|(ifindex, link)| Some((*ifindex, link.mac?, link.mtu, link.up)));
        match usable {
            // A saved lease is on its way back to the server: the client
            // is the old identity's, and `pump_release` (below) finishes
            // with it and comes back here for the current configuration.
            Some((ifindex, ..)) if iface.cfg.enabled && iface.releasing.is_some() => {
                iface.ifindex = Some(ifindex);
            }
            Some((ifindex, mac, mtu, up)) if iface.cfg.enabled => {
                let options = iface.cfg.options(&self.hostname);
                iface.ifindex = Some(ifindex);
                // A client is one identity (`Client::identity`). When the
                // configuration (the client identifier) or the link (the
                // hardware address) gives the interface another one, the
                // lease goes back as who took it, and a new client asks
                // as who the interface is now.
                let changed = iface
                    .client
                    .as_ref()
                    .is_some_and(|client| client.identity() != (mac, options.client_id.as_deref()));
                if changed {
                    tracing::info!(
                        "dhcp client: {name}: identity changed ({}); the lease taken under the old one is released",
                        identity_text(mac, options.client_id.as_deref())
                    );
                    self.stop_client(name, ifindex, &mut iface, now);
                }
                match iface.client.as_mut() {
                    Some(client) => {
                        client.set_options(options);
                        client.set_mtu(mtu);
                    }
                    None => {
                        iface =
                            self.start_client(name, ifindex, iface, (mac, mtu, up), options, now);
                    }
                }
            }
            _ => {
                // No `address dhcp` any more: give the lease back. (A
                // link that went away is handled by `detach`.)
                if let (Some(_), Some(ifindex)) = (&iface.client, iface.ifindex)
                    && !iface.cfg.enabled
                {
                    self.stop_client(name, ifindex, &mut iface, now);
                    tracing::info!("dhcp client: {name}: stopped");
                }
                if !iface.cfg.enabled {
                    // Configured again, it asks for a lease.
                    iface.start_released = false;
                }
            }
        }
        if iface.cfg != IfConfig::default() || iface.client.is_some() {
            self.ifaces.insert(name.to_string(), iface);
        }
        self.sync_routes();
        self.pump_release(name);
    }

    /// Stop `iface`'s client for good: a lease it holds is released, as
    /// the identity that took it, and everything it gave is withdrawn.
    fn stop_client(&mut self, name: &str, ifindex: u32, iface: &mut Iface, now: Instant) {
        if let Some(client) = iface.client.as_mut() {
            let actions = client.handle(Event::Stop, now);
            self.perform(name, ifindex, iface, actions);
        }
        iface.client = None;
        iface.releasing = None;
        iface.close_all();
    }

    /// Start a client for `iface` as `(mac, options.client_id)`, resuming
    /// the lease on disk when that identity took it.
    fn start_client(
        &mut self,
        name: &str,
        ifindex: u32,
        mut iface: Iface,
        (mac, mtu, up): ([u8; 6], u32, bool),
        options: Options,
        now: Instant,
    ) -> Iface {
        let unix = unix_now();
        let mut resume = None;
        if let Some(kept) = self.store.load(name, unix) {
            if (kept.mac, kept.client_id.as_deref()) == (mac, options.client_id.as_deref()) {
                resume = Some(kept);
            } else if self.begin_release(name, ifindex, &mut iface, kept, mtu, &options, now) {
                // The client for `options` starts once that lease has
                // been given back (`pump_release`).
                return iface;
            }
        }
        let mut client = Client::new(mac, mtu, options, now, Box::new(rand::random::<u32>));
        let mut actions = Vec::new();
        if std::mem::take(&mut iface.start_released) {
            // The operator released the lease before this client existed
            // (`release_pending`): it starts released, and stays so until
            // `renew` or a configuration change.
            client.handle(Event::Release, now);
        } else if let Some(kept) = resume {
            iface.obtained = Some(unix - u64::from(kept.elapsed));
            actions.extend(client.handle(
                Event::Resume {
                    lease: kept.lease,
                    elapsed: kept.elapsed,
                },
                now,
            ));
            if actions.is_empty() {
                // It ran out while we were away.
                self.store.remove(name);
                iface.obtained = None;
            }
        }
        if up {
            actions.extend(client.handle(Event::Carrier(true), now));
        }
        iface.client = Some(client);
        tracing::info!("dhcp client: {name}: started");
        self.perform(name, ifindex, &mut iface, actions);
        iface
    }

    /// The lease on disk was taken under another identity: the client
    /// identifier or the hardware address changed while zebra-rs was not
    /// running. It is not ours to renew as who the interface is now, and
    /// it must not be left allocated either. So it is resumed as who took
    /// it, which claims its address and its routes, and `pump_release`
    /// then releases it as that identity.
    ///
    /// Not in one step: the RELEASE leaves from the lease's address, and
    /// after a reboot that address is not on the interface until the RIB
    /// has installed it. Sent at once, the RELEASE would fail and the
    /// lease be forgotten here while the server kept it.
    ///
    /// False when the lease has run out and there is nothing to give back.
    fn begin_release(
        &mut self,
        name: &str,
        ifindex: u32,
        iface: &mut Iface,
        kept: super::lease::Kept,
        mtu: u32,
        options: &Options,
        now: Instant,
    ) -> bool {
        let mut as_then = options.clone();
        as_then.client_id = kept.client_id;
        let mut client = Client::new(kept.mac, mtu, as_then, now, Box::new(rand::random::<u32>));
        let actions = client.handle(
            Event::Resume {
                lease: kept.lease,
                elapsed: kept.elapsed,
            },
            now,
        );
        if actions.is_empty() {
            self.store.remove(name);
            return false;
        }
        tracing::info!(
            "dhcp client: {name}: the saved lease was taken under another identity; releasing it"
        );
        iface.client = Some(client);
        iface.releasing = Some(None);
        self.perform(name, ifindex, iface, actions);
        true
    }

    pub(super) fn is_releasing(&self, name: &str) -> bool {
        self.ifaces
            .get(name)
            .is_some_and(|iface| iface.releasing.is_some())
    }

    fn pump_releases(&mut self, now: Instant) {
        let names: Vec<String> = self
            .ifaces
            .iter()
            .filter(|(_, iface)| iface.releasing.is_some())
            .map(|(name, _)| name.clone())
            .collect();
        for name in names {
            self.pump_release_at(&name, now);
        }
    }

    fn pump_release(&mut self, name: &str) {
        self.pump_release_at(name, Instant::now());
    }

    /// Finish giving back a saved lease (`begin_release`) once its RELEASE
    /// can go out: the link is up, the lease's address is on the interface
    /// and there is a route to the server. Called on every event that may
    /// have brought that about, and on a short tick.
    ///
    /// With the link down it waits for the link. With the link up it
    /// waits `RELEASE_WAIT` for the RIB, then gives up: the lease is
    /// withdrawn here and left to run out at the server.
    fn pump_release_at(&mut self, name: &str, now: Instant) {
        let Some(iface) = self.ifaces.get_mut(name) else {
            return;
        };
        let Some(give_up) = iface.releasing.as_mut() else {
            return;
        };
        let pending = match (iface.ifindex, &iface.bound) {
            (Some(ifindex), Some(lease)) => Some((ifindex, lease.address, lease.server_id)),
            // Nothing held any more: it ran out, or the link went away.
            _ => None,
        };
        let mut sendable = true;
        if let Some((ifindex, address, server)) = pending {
            if !self.links.get(&ifindex).is_some_and(|link| link.up) {
                // The wait for the RIB starts when the link is up.
                *give_up = None;
                return;
            }
            sendable = socket::can_send_from(name, address, server);
            let give_up = *give_up.get_or_insert(now + RELEASE_WAIT);
            if !sendable && now < give_up {
                return;
            }
        }
        if !sendable {
            tracing::warn!(
                "dhcp client: {name}: the saved lease could not be released: no way to its server from its address; it is left to run out"
            );
        }
        let Some(mut iface) = self.ifaces.remove(name) else {
            return;
        };
        if let Some(ifindex) = iface.ifindex {
            self.stop_client(name, ifindex, &mut iface, now);
        } else {
            iface.client = None;
            iface.releasing = None;
            iface.close_all();
        }
        self.ifaces.insert(name.to_string(), iface);
        // Now as who the interface is.
        self.reconcile(name);
    }

    /// The link is gone (deleted, or moved to another VRF, which the RIB
    /// reports as a delete and an add): drop the binding without a
    /// RELEASE. A link coming back starts from scratch.
    fn detach(&mut self, name: &str) {
        let Some(iface) = self.ifaces.get_mut(name) else {
            return;
        };
        if let (Some(lease), Some(ifindex)) = (iface.bound.take(), iface.ifindex) {
            let _ = self.rib.send(Message::AddrDynDel {
                ifindex,
                addr: IpNet::V4(lease.net()),
                origin: AddrOrigin::Dhcp4,
            });
        }
        iface.client = None;
        iface.releasing = None;
        iface.ifindex = None;
        iface.obtained = None;
        iface.close_all();
        self.store.remove(name);
        self.sync_routes();
    }

    /// Feed `event` to `name`'s client and carry out what it asks for.
    pub(super) fn drive(&mut self, name: &str, event: Event<'_>) {
        // A saved lease on its way back (`begin_release`) takes no further
        // part in the protocol: its client, the old identity's, is only
        // there to send the RELEASE, which `pump_release` sees to. Nothing
        // else may move it, or the pending transition and the client's
        // state would part ways.
        if self.is_releasing(name) {
            return;
        }
        let Some(mut iface) = self.ifaces.remove(name) else {
            return;
        };
        if let (Some(client), Some(ifindex)) = (iface.client.as_mut(), iface.ifindex) {
            let actions = client.handle(event, Instant::now());
            self.perform(name, ifindex, &mut iface, actions);
        }
        self.ifaces.insert(name.to_string(), iface);
        self.sync_routes();
    }

    fn perform(&mut self, name: &str, ifindex: u32, iface: &mut Iface, actions: Vec<Action>) {
        // Open what the new state needs before sending through it; close
        // what it no longer needs only afterwards (a RELEASE leaves
        // through the socket of the lease it gives up).
        self.open_sockets(name, ifindex, iface);
        for action in actions {
            match action {
                Action::Broadcast(packet) => {
                    if let Some(socket) = &iface.packet
                        && let Err(e) = socket.broadcast_dhcp(ifindex, &packet.emit())
                    {
                        tracing::debug!("dhcp client: {name}: broadcast failed: {e}");
                    }
                }
                Action::Send(destination, packet) => {
                    // From the leased address, which the message names
                    // as `ciaddr`, whatever else the interface holds.
                    if let Some(socket) = &iface.udp
                        && let Err(e) = socket.send_dhcp(packet.ciaddr, destination, &packet.emit())
                    {
                        tracing::debug!("dhcp client: {name}: send to {destination} failed: {e}");
                    }
                }
                Action::Probe(address) => {
                    let mac = self.links.get(&ifindex).and_then(|link| link.mac);
                    if let (Some(socket), Some(mac)) = (&iface.arp, mac)
                        && let Err(e) = socket.probe(ifindex, mac, address)
                    {
                        tracing::debug!("dhcp client: {name}: ARP probe failed: {e}");
                    }
                }
                Action::Bind {
                    lease,
                    remaining,
                    fresh,
                } => self.bind(name, ifindex, iface, lease, remaining, fresh),
                Action::Unbind => {
                    if let Some(lease) = iface.bound.take() {
                        tracing::info!("dhcp client: {name}: {} withdrawn", lease.net());
                        let _ = self.rib.send(Message::AddrDynDel {
                            ifindex,
                            addr: IpNet::V4(lease.net()),
                            origin: AddrOrigin::Dhcp4,
                        });
                    }
                    iface.obtained = None;
                    self.store.remove(name);
                }
                Action::Log(text) => tracing::info!("dhcp client: {name}: {text}"),
            }
        }
        if let Some(client) = &iface.client {
            if !client.wants_packet_socket() {
                iface.packet = None;
            }
            if client.probing().is_none() {
                iface.arp = None;
            }
            if !client.wants_udp_socket() {
                iface.udp = None;
            }
        }
    }

    fn open_sockets(&mut self, name: &str, ifindex: u32, iface: &mut Iface) {
        let Some(client) = &iface.client else {
            return;
        };
        let mut failed = None;
        if client.wants_packet_socket() && iface.packet.is_none() {
            match socket::open_packet(ifindex, self.input_tx.clone()) {
                Ok(reader) => iface.packet = Some(reader),
                Err(e) => failed = Some(format!("packet socket: {e}")),
            }
        }
        if client.probing().is_some() && iface.arp.is_none() {
            match socket::open_arp(ifindex, self.input_tx.clone()) {
                Ok(reader) => iface.arp = Some(reader),
                Err(e) => failed = Some(format!("ARP socket: {e}")),
            }
        }
        if client.wants_udp_socket() && iface.udp.is_none() {
            match socket::open_udp(ifindex, name, self.input_tx.clone()) {
                Ok(reader) => iface.udp = Some(reader),
                Err(e) => failed = Some(format!("UDP socket: {e}")),
            }
        }
        match failed {
            // Said once; the next event tries again.
            Some(reason) if !iface.socket_failed => {
                tracing::warn!("dhcp client: {name}: {reason}");
                iface.socket_failed = true;
            }
            Some(_) => {}
            None => iface.socket_failed = false,
        }
    }

    fn bind(
        &mut self,
        name: &str,
        ifindex: u32,
        iface: &mut Iface,
        lease: Lease,
        remaining: u32,
        fresh: bool,
    ) {
        let net = lease.net();
        // A lease for another address replaces the old one's.
        if let Some(old) = iface.bound.as_ref().filter(|old| old.net() != net) {
            let _ = self.rib.send(Message::AddrDynDel {
                ifindex,
                addr: IpNet::V4(old.net()),
                origin: AddrOrigin::Dhcp4,
            });
        }
        self.install_address(ifindex, &lease, remaining);
        if fresh {
            // The lease began when its REQUEST went out.
            let age = lease.lease_time.saturating_sub(remaining);
            let obtained = unix_now().saturating_sub(u64::from(age));
            iface.obtained = Some(obtained);
            // Under the identity that took it, which is the client's.
            if let Some(client) = &iface.client
                && let Err(e) = self.store.save(name, client.identity(), obtained, &lease)
            {
                tracing::warn!("dhcp client: {name}: lease not saved: {e}");
            }
        }
        let renewed = iface.bound.as_ref().is_some_and(|old| old.net() == net);
        if !renewed || !fresh {
            tracing::info!(
                "dhcp client: {name}: {} {net} from {}, lease {}",
                if fresh { "bound" } else { "resumed" },
                lease.server_id,
                lifetime(remaining),
            );
        } else {
            tracing::debug!(
                "dhcp client: {name}: renewed {net}, lease {}",
                lifetime(remaining)
            );
        }
        let (_, on_link) = lease_routes(&lease, iface.cfg.no_default_route);
        if !renewed {
            for prefix in on_link {
                tracing::warn!(
                    "dhcp client: {name}: on-link route {prefix} from the lease is not installed"
                );
            }
        }
        iface.bound = Some(lease);
    }

    /// Ask the RIB to put the lease's address on the interface, or to
    /// move its lifetime, with `remaining` seconds left.
    fn install_address(&self, ifindex: u32, lease: &Lease, remaining: u32) {
        let net = lease.net();
        let _ = self.rib.send(Message::AddrDynAdd {
            ifindex,
            addr: IpNet::V4(net),
            origin: AddrOrigin::Dhcp4,
            opts: AddrOpts {
                valid_lft: remaining,
                preferred_lft: remaining,
                noprefixroute: false,
                broadcast: lease.broadcast.or_else(|| broadcast_of(net)),
            },
        });
    }

    /// The VRF `ifindex` is in: its master's name, when that is a VRF.
    pub(super) fn vrf_of(&self, ifindex: u32) -> Option<String> {
        let master = self.links.get(&ifindex)?.master?;
        self.links
            .get(&master)
            .filter(|link| link.is_vrf)
            .map(|link| link.name.clone())
    }

    /// Hand the RIB whatever the leases held now route. A lease on a link
    /// that is down keeps its address but routes nothing: that is what
    /// lets a backup uplink at a higher distance take over (see
    /// [`super::routes`]).
    fn sync_routes(&mut self) {
        let mut wanted = Wanted::new();
        for iface in self.ifaces.values() {
            let (Some(lease), Some(ifindex)) = (&iface.bound, iface.ifindex) else {
                continue;
            };
            if !self.links.get(&ifindex).is_some_and(|link| link.up) {
                continue;
            }
            let vrf = self.vrf_of(ifindex);
            let (routes, _) = lease_routes(lease, iface.cfg.no_default_route);
            for (prefix, gateway) in routes {
                wanted.entry((vrf.clone(), prefix)).or_default().push(Leg {
                    distance: iface.cfg.distance(),
                    ifindex,
                    gateway,
                });
            }
        }
        for message in self.routes.sync(wanted) {
            let _ = self.rib.send(message);
        }
    }

    fn named_iface(&self, mut args: Args) -> Result<String, String> {
        let name = args.string().ok_or("% Interface name required")?;
        match self.ifaces.get(&name) {
            Some(iface) if iface.client.is_some() => Ok(name),
            _ => Err(format!("No DHCP client on {name}")),
        }
    }

    fn renew(&mut self, args: Args) -> String {
        match self.named_iface(args) {
            Ok(name) if self.is_releasing(&name) => {
                // A lease is asked for as soon as the saved one is back
                // with the server; see whether that can be now.
                self.pump_release(&name);
                format!("Releasing the lease saved under the previous identity on {name} first")
            }
            Ok(name) => {
                self.drive(&name, Event::Renew);
                format!("Renewing the DHCP lease on {name}")
            }
            Err(e) => e,
        }
    }

    fn release(&mut self, args: Args) -> String {
        match self.named_iface(args) {
            Ok(name) => {
                if self.is_releasing(&name) {
                    self.release_pending(&name);
                } else {
                    self.drive(&name, Event::Release);
                }
                format!("Released the DHCP lease on {name}")
            }
            Err(e) => e,
        }
    }

    /// `release dhcp interface <if>` while a saved lease is still on its
    /// way back as the identity that took it. The operator wants no lease
    /// here: the RELEASE goes out now, as well as it can, the pending
    /// transition ends, and the interface is left released as who it is
    /// now, until `renew` or a configuration change. Left to finish by
    /// itself, the transition would start a client that asks for a lease
    /// at once.
    fn release_pending(&mut self, name: &str) {
        let Some(mut iface) = self.ifaces.remove(name) else {
            return;
        };
        match iface.ifindex {
            Some(ifindex) => self.stop_client(name, ifindex, &mut iface, Instant::now()),
            None => {
                iface.client = None;
                iface.releasing = None;
                iface.close_all();
            }
        }
        iface.start_released = true;
        self.ifaces.insert(name.to_string(), iface);
        self.reconcile(name);
    }
}

/// An identity for a log line: the hardware address and the client
/// identifier, as the CLI spells them.
fn identity_text(mac: [u8; 6], client_id: Option<&[u8]>) -> String {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    match client_id {
        Some(id) => format!("hardware address {}, client-id {}", hex(&mac), hex(id)),
        None => format!("hardware address {}, no client-id", hex(&mac)),
    }
}

fn broadcast_of(net: Ipv4Net) -> Option<Ipv4Addr> {
    // A /31 or /32 has no broadcast address.
    (net.prefix_len() < 31).then(|| net.broadcast())
}

pub(super) fn lifetime(seconds: u32) -> String {
    if seconds == u32::MAX {
        "forever".to_string()
    } else {
        format!("{seconds}s")
    }
}

pub fn serve(mut dhcpc: Dhcpc) -> Task<()> {
    Task::spawn(async move {
        dhcpc.event_loop().await;
    })
}

async fn sleep_until_opt(when: Option<Instant>) {
    match when {
        Some(t) => sleep_until(t.into()).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;

    use super::*;
    use crate::dhcpc::v4::client::State;
    use crate::rib::client::{ProtoId, RibInbound};

    // No such device: the task's sockets fail to open, which it tolerates,
    // and nothing can be sent from a lease's address.
    const IF: &str = "dhcpc-test0";
    const IFINDEX: u32 = 0x7fff_fff0;
    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const OLD: [u8; 2] = [0, b'A'];
    const NEW: [u8; 2] = [0, b'B'];

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

    fn bench(test: &str, link_up: bool) -> Bench {
        let dir = std::env::temp_dir().join(format!("zebra-dhcpc-{}-{test}", std::process::id()));
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
                up: link_up,
                master: None,
                is_vrf: false,
            },
        );
        Bench { dhcpc, rib, dir }
    }

    fn lease() -> Lease {
        Lease {
            address: Ipv4Addr::new(192, 0, 2, 100),
            prefix_len: 24,
            server_id: Ipv4Addr::new(192, 0, 2, 1),
            broadcast: None,
            routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
            classless_routes: vec![],
            dns_servers: vec![],
            domain_name: None,
            domain_search: vec![],
            ntp_servers: vec![],
            mtu: None,
            lease_time: 3600,
            t1: 1800,
            t2: 3150,
        }
    }

    /// A lease on disk taken as `OLD`, the interface configured as `NEW`:
    /// the task starts giving the lease back.
    fn with_saved_lease(b: &mut Bench) {
        b.dhcpc
            .store
            .save(IF, (MAC, Some(&OLD)), unix_now(), &lease())
            .unwrap();
        let cfg = &mut b.dhcpc.ifaces.entry(IF.to_string()).or_default().cfg;
        cfg.enabled = true;
        cfg.client_id = Some(NEW.to_vec());
        b.dhcpc.reconcile(IF);
        assert!(b.dhcpc.is_releasing(IF));
        assert_eq!(client_id(b), Some(OLD.to_vec()));
    }

    fn client_id(b: &Bench) -> Option<Vec<u8>> {
        let client = b.dhcpc.ifaces[IF].client.as_ref().expect("a client");
        client.identity().1.map(<[u8]>::to_vec)
    }

    fn state(b: &Bench) -> State {
        b.dhcpc.ifaces[IF]
            .client
            .as_ref()
            .expect("a client")
            .state()
    }

    /// What the task asked of the RIB since the last call.
    fn asked(b: &mut Bench) -> Vec<&'static str> {
        let mut out = Vec::new();
        while let Ok(inbound) = b.rib.try_recv() {
            out.push(match inbound.msg {
                Message::AddrDynAdd { .. } => "address add",
                Message::AddrDynDel { .. } => "address del",
                Message::Ipv4Add { .. } => "route add",
                Message::Ipv4Del { .. } => "route del",
                _ => "other",
            });
        }
        out
    }

    fn verb(name: &str) -> Args {
        Args(VecDeque::from([name.to_string()]))
    }

    /// `release dhcp interface` while a saved lease is still on its way
    /// back: the transition ends there, and the interface stays released
    /// as the identity it has now. It used to go on and ask for a lease.
    #[tokio::test]
    async fn an_operator_release_ends_a_pending_release_and_stays_released() {
        let mut b = bench("verb", false);
        with_saved_lease(&mut b);
        // The link is down: the release waits, holding the saved lease.
        assert_eq!(asked(&mut b), ["address add"]);

        assert_eq!(
            b.dhcpc.release(verb(IF)),
            format!("Released the DHCP lease on {IF}")
        );
        assert!(!b.dhcpc.is_releasing(IF));
        assert_eq!(client_id(&b), Some(NEW.to_vec()));
        assert_eq!(state(&b), State::Released);
        assert_eq!(asked(&mut b), ["address del"]);
        assert!(b.dhcpc.store.load(IF, unix_now()).is_none());

        // Nothing brings a lease back by itself: a tick long after, a
        // reconcile, the link coming up.
        b.dhcpc.on_wakeup(Instant::now() + RELEASE_WAIT * 3);
        b.dhcpc.reconcile(IF);
        b.dhcpc.process_rib_msg(RibRx::LinkUp(IFINDEX));
        assert_eq!(state(&b), State::Released);
        assert!(asked(&mut b).is_empty());

        // The operator's `renew` does, as who the interface is now.
        b.dhcpc.renew(verb(IF));
        assert_eq!(state(&b), State::Selecting);
        assert_eq!(client_id(&b), Some(NEW.to_vec()));
    }

    /// `renew` while the saved lease is on its way back does not renew it
    /// as the old identity; packets and timers do not move it either.
    #[tokio::test]
    async fn a_pending_release_takes_no_protocol_events() {
        let mut b = bench("frozen", false);
        with_saved_lease(&mut b);
        asked(&mut b);
        let reply = b.dhcpc.renew(verb(IF));
        assert!(reply.starts_with("Releasing the lease saved under the previous identity"));
        b.dhcpc.drive(IF, Event::Timeout);
        b.dhcpc.drive(IF, Event::Renew);
        assert!(b.dhcpc.is_releasing(IF));
        assert_eq!(state(&b), State::Bound);
        assert_eq!(client_id(&b), Some(OLD.to_vec()));
        assert!(asked(&mut b).is_empty());
    }

    /// The release waits for the link without a limit, then a bounded
    /// time for the address and a route, then gives up and lets the
    /// interface ask as its new identity.
    #[tokio::test]
    async fn a_pending_release_waits_then_gives_up() {
        let mut b = bench("giveup", false);
        with_saved_lease(&mut b);
        let t0 = Instant::now();

        // Link down: no amount of time ends it.
        b.dhcpc.pump_release_at(IF, t0 + RELEASE_WAIT * 5);
        assert!(b.dhcpc.is_releasing(IF));

        // Link up: the wait begins. (No such device, so the RELEASE
        // never becomes sendable here.)
        b.dhcpc.process_rib_msg(RibRx::LinkUp(IFINDEX));
        let t1 = Instant::now();
        b.dhcpc
            .pump_release_at(IF, t1 + RELEASE_WAIT - Duration::from_secs(1));
        assert!(b.dhcpc.is_releasing(IF));
        assert_eq!(client_id(&b), Some(OLD.to_vec()));

        b.dhcpc
            .pump_release_at(IF, t1 + RELEASE_WAIT + Duration::from_secs(1));
        assert!(!b.dhcpc.is_releasing(IF));
        assert_eq!(client_id(&b), Some(NEW.to_vec()));
        assert_eq!(state(&b), State::Selecting);
        assert!(b.dhcpc.store.load(IF, unix_now()).is_none());
    }

    /// The poll for pending releases is a deadline that other events do
    /// not push back.
    #[tokio::test]
    async fn the_release_poll_is_not_postponed_by_other_events() {
        let mut b = bench("poll", false);
        assert_eq!(b.dhcpc.next_wakeup(Instant::now()), None);
        with_saved_lease(&mut b);

        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let first = b.dhcpc.next_wakeup(t0);
        assert_eq!(first, Some(t0 + RELEASE_POLL));
        // The loop turns for other reasons; the deadline stays.
        assert_eq!(b.dhcpc.next_wakeup(t0 + ms(100)), first);
        assert_eq!(b.dhcpc.next_wakeup(t0 + ms(240)), first);
        // A wakeup before it is due does not serve it.
        b.dhcpc.on_wakeup(t0 + ms(240));
        assert_eq!(b.dhcpc.next_wakeup(t0 + ms(245)), first);
        // Served, the next one counts from then.
        b.dhcpc.on_wakeup(t0 + RELEASE_POLL);
        assert_eq!(
            b.dhcpc.next_wakeup(t0 + RELEASE_POLL + ms(5)),
            Some(t0 + RELEASE_POLL * 2 + ms(5))
        );

        // Without a pending release there is nothing to poll for.
        b.dhcpc.release(verb(IF));
        assert_eq!(b.dhcpc.next_wakeup(t0 + RELEASE_POLL * 3), None);
    }
}
