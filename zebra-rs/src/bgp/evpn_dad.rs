//! EVPN duplicate address detection (RFC 7432 §15.1), as FRR's zebra does
//! it (`zebra_evpn_dup_addr_detect_for_mac` / `_for_neigh`).
//!
//! A MAC that moves between this node and a remote VTEP `max-moves` times
//! within `time` seconds is a duplicate: two hosts (or a loop) claiming one
//! address. Detection is counted on the moves this node sees:
//!
//! * a **local** learn of a MAC that was remote starts the window (or
//!   counts within it);
//! * a **remote** route taking a MAC over from this node counts only while
//!   a window that a local learn started is open — a remote-to-remote move,
//!   or a sequence number change alone, is not a move here.
//!
//! An IP counts separately when it moves to a *different* MAC (the MAC's
//! own moves already cover a host keeping its MAC), and an IP bound to a
//! duplicate MAC is a duplicate with it.
//!
//! A host on an Ethernet Segment this node shares with a peer is reachable
//! over our own port wherever it was learned (RFC 7432 §8.4): a route the
//! peer advertises for it on that segment is FRR's sync route, and the
//! host moving between the peer and this node is no move.
//!
//! On detection a warning is logged. Without `freeze` nothing else changes
//! (FRR's default, warn-only); the address stays marked until cleared. With
//! `freeze` this node stops advertising the address and stops installing
//! remote routes for it, holding the kernel in its last state, until the
//! freeze time elapses (never, for `permanent`) or `clear bgp evpn
//! dup-addr` releases it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::inst::{Bgp, Message};
use crate::context::Task;
use crate::rib::MacAddr;
use crate::rib::api::FdbEntry;

/// RFC 7432 §15.1's default N.
pub const DEFAULT_MAX_MOVES: u32 = 5;
/// RFC 7432 §15.1's default M, in seconds.
pub const DEFAULT_TIME: u32 = 180;

/// What happens to a duplicate besides the warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freeze {
    /// Warn only: routes keep flowing.
    Off,
    /// Hold until cleared by the operator.
    Permanent,
    /// Hold for this many seconds, then recover.
    For(u32),
}

/// `router bgp afi-safi evpn dup-addr-detection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DadConfig {
    pub enabled: bool,
    pub max_moves: u32,
    /// The detection window, in seconds.
    pub time: u32,
    pub freeze: Freeze,
}

impl DadConfig {
    /// When the freeze releases a duplicate detected at `now`: `None` for
    /// warn-only or a permanent freeze.
    pub fn freeze_until(&self, now: Instant) -> Option<Instant> {
        match self.freeze {
            Freeze::For(secs) => Some(now + Duration::from_secs(secs.into())),
            Freeze::Off | Freeze::Permanent => None,
        }
    }
}

impl Default for DadConfig {
    /// On, as in FRR, with RFC 7432's defaults and no freeze.
    fn default() -> Self {
        Self {
            enabled: true,
            max_moves: DEFAULT_MAX_MOVES,
            time: DEFAULT_TIME,
            freeze: Freeze::Off,
        }
    }
}

/// Where an address currently lives, as far as detection is concerned:
/// FRR's `ZEBRA_MAC_LOCAL` / `ZEBRA_MAC_REMOTE` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Local,
    /// Installed from a remote route (or held back from installing one).
    Remote {
        vtep: Option<IpAddr>,
        sticky: bool,
        /// The route's Ethernet Segment, when this node is attached to it
        /// too: the address is reachable over our own port as well.
        es: Option<[u8; 10]>,
    },
}

/// A remote MAC/IP route installed (or held) for an address, as detection
/// sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteRoute {
    pub rd: [u8; 8],
    pub vtep: Option<IpAddr>,
    pub sticky: bool,
    /// Its Ethernet Segment, when this node is attached to that segment
    /// too: the host is reachable over our own port, and the route only
    /// syncs it (FRR's `zebra_evpn_process_sync_macip_add`). Never a move.
    pub es: Option<[u8; 10]>,
    /// Its MAC Mobility sequence number. Of the routes live for an
    /// address, the one with the highest says where it is: a route for an
    /// older binding of an IP, re-run while a newer one binds it to another
    /// MAC, does not move the IP back to its MAC, as FRR ignores it
    /// (`zebra_evpn_neigh_is_bgp_seq_ok`).
    pub seq: u32,
}

impl RemoteRoute {
    fn owner(&self) -> Owner {
        Owner::Remote {
            vtep: self.vtep,
            sticky: self.sticky,
            es: self.es,
        }
    }
}

/// A detected duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duplicate {
    pub since: Instant,
    /// When a timed freeze releases it; `None` for warn-only or a
    /// permanent freeze.
    pub until: Option<Instant>,
}

/// Detection state for one MAC or IP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    pub owner: Option<Owner>,
    /// Moves counted in the current window.
    pub count: u32,
    /// When the current window started (a local learn).
    pub start: Option<Instant>,
    pub duplicate: Option<Duplicate>,
    /// The remote routes installed (or held) for the address, by RD and
    /// the IP (MAC probe) or MAC (IP probe) they bind. While the address
    /// is remote it is where the newest of them is, and it stops being
    /// remote when the last one goes.
    pub remote_routes: BTreeMap<([u8; 8], RouteBinding), RemoteRoute>,
}

/// The other half of a MAC/IP route's key, from the probe's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteBinding {
    Ip(Option<IpAddr>),
    Mac(MacAddr),
}

impl Probe {
    /// Count one move, FRR's way. The caller has established that
    /// detection is on, that this event is a move, and that the address is
    /// not already a duplicate. Returns whether it just became one.
    fn record(&mut self, config: &DadConfig, now: Instant, local: bool) -> bool {
        let window = Duration::from_secs(config.time.into());
        let mut reset = self
            .start
            .is_none_or(|start| now.saturating_duration_since(start) > window);
        // RFC 7432: a PE that detects a move via local learning starts the
        // M-second timer — the first local move opens a window.
        if local && !reset {
            reset = self.count == 0;
        }
        if reset {
            self.count = 0;
            // Only a local learn starts a window; a remote move outside
            // one counts nothing.
            if local {
                self.start = Some(now);
            }
        } else if !local {
            self.count += 1;
        }
        if local {
            self.count += 1;
        }
        if self.count < config.max_moves {
            return false;
        }
        self.duplicate = Some(Duplicate {
            since: now,
            until: config.freeze_until(now),
        });
        true
    }

    /// Forget the window and any duplicate mark, keeping the owner.
    fn clear(&mut self) {
        self.count = 0;
        self.start = None;
        self.duplicate = None;
    }

    /// Nothing worth keeping: no owner, no open window, no mark. A window
    /// that has run out counts as closed: its moves no longer count.
    fn idle(&self, config: &DadConfig, now: Instant) -> bool {
        let window = Duration::from_secs(config.time.into());
        let open = self.count > 0
            && self
                .start
                .is_some_and(|start| now.saturating_duration_since(start) <= window);
        self.owner.is_none() && !open && self.duplicate.is_none()
    }

    /// The newest of the remote routes live for the address.
    fn newest_remote(&self) -> Option<(RouteBinding, RemoteRoute)> {
        self.remote_routes
            .iter()
            .max_by_key(|(_, route)| route.seq)
            .map(|((_, binding), route)| (*binding, *route))
    }

    /// One remote route for the address went. A remote address is now
    /// where the newest of those left is (a segment peer's sync route gone,
    /// an ordinary route left is no longer exempt), and with the last it is
    /// no longer remote.
    fn remote_route_gone(&mut self, route: ([u8; 8], RouteBinding)) {
        self.remote_routes.remove(&route);
        if matches!(self.owner, Some(Owner::Remote { .. })) {
            self.owner = self.newest_remote().map(|(_, route)| route.owner());
        }
    }
}

/// Detection state for one IP: the probe plus the MAC it is bound to, so a
/// move to a different MAC can be told from a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpProbe {
    pub mac: MacAddr,
    pub probe: Probe,
}

/// A detected address, for the recovery timer and `clear`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DadKey {
    Mac(u32, MacAddr),
    Ip(u32, IpAddr),
}

/// What an event means for the route that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Advertise or install as usual.
    Proceed,
    /// The address is frozen: neither advertise nor install it.
    Hold,
}

/// All detection state of one BGP instance.
#[derive(Debug, Default)]
pub struct EvpnDad {
    pub config: DadConfig,
    pub macs: BTreeMap<(u32, MacAddr), Probe>,
    pub ips: BTreeMap<(u32, IpAddr), IpProbe>,
    /// This node's own MAC/IP routes to withdraw because a remote route
    /// took a frozen address over: `(vni, mac, None)` for every route of
    /// the MAC, `(vni, mac, Some(ip))` for the route binding `ip`. Drained
    /// by `Bgp::evpn_dad_drain`, which has the peers the withdrawal needs,
    /// after every event (`Bgp::event_upkeep`).
    pub withdraw: BTreeSet<(u32, MacAddr, Option<IpAddr>)>,
    /// The recovery timer of each address a timed freeze holds, one per
    /// address: dropping it (a release, a change of freeze policy) cancels
    /// it, rather than leaving it to wake for nothing.
    pub recovery: BTreeMap<DadKey, Task<()>>,
}

impl EvpnDad {
    fn freezes(&self) -> bool {
        self.config.enabled && self.config.freeze != Freeze::Off
    }

    pub fn mac_duplicate(&self, vni: u32, mac: MacAddr) -> bool {
        self.macs
            .get(&(vni, mac))
            .is_some_and(|probe| probe.duplicate.is_some())
    }

    /// An IP is a duplicate when it was detected itself, or (FRR's
    /// inheritance) when the MAC it is bound to was.
    pub fn ip_duplicate(&self, vni: u32, ip: IpAddr, mac: MacAddr) -> bool {
        self.mac_duplicate(vni, mac)
            || self
                .ips
                .get(&(vni, ip))
                .is_some_and(|entry| entry.probe.duplicate.is_some())
    }

    /// Whether the MAC/IP route `(vni, mac, ip)` is frozen.
    pub fn frozen(&self, vni: u32, mac: MacAddr, ip: Option<IpAddr>) -> bool {
        self.freezes()
            && match ip {
                Some(ip) => self.ip_duplicate(vni, ip, mac),
                None => self.mac_duplicate(vni, mac),
            }
    }

    /// This node learned `mac` (bound to `ip`, for a MAC/IP route) and is
    /// about to advertise it. Returns the verdict and the addresses that
    /// just became duplicates.
    pub fn local_learn(
        &mut self,
        vni: u32,
        mac: MacAddr,
        ip: Option<IpAddr>,
        now: Instant,
    ) -> (Verdict, Vec<DadKey>) {
        let config = self.config;
        let mut detected = Vec::new();
        let probe = self.macs.entry((vni, mac)).or_default();
        // A move only from a remote owner, and not from a peer on one of
        // our segments: the host was reachable over our own port all
        // along. A remote sticky MAC learned here is an operator error FRR
        // reports and does not count.
        if let Some(Owner::Remote {
            vtep,
            sticky: false,
            es: None,
        }) = probe.owner
            && config.enabled
            && probe.duplicate.is_none()
            && probe.record(&config, now, true)
        {
            warn_detected(vni, &mac.to_string(), "local update, last", vtep);
            detected.push(DadKey::Mac(vni, mac));
        }
        probe.owner = Some(Owner::Local);
        if let Some(ip) = ip {
            self.ip_leaves_duplicate_mac(vni, ip, mac);
            let entry = self.ips.entry((vni, ip)).or_insert_with(|| IpProbe {
                mac,
                probe: Probe::default(),
            });
            // FRR's scenario B: the IP moved here on a different MAC.
            if let Some(Owner::Remote { vtep, es: None, .. }) = entry.probe.owner
                && entry.mac != mac
                && config.enabled
                && entry.probe.duplicate.is_none()
                && entry.probe.record(&config, now, true)
            {
                warn_detected(vni, &format!("{mac} IP {ip}"), "local update, last", vtep);
                detected.push(DadKey::Ip(vni, ip));
            }
            entry.mac = mac;
            entry.probe.owner = Some(Owner::Local);
        }
        (self.verdict(vni, mac, ip), detected)
    }

    /// A remote `route` for `mac`, bound to `ip`, beats this node's own
    /// and is about to be installed.
    pub fn remote_takeover(
        &mut self,
        vni: u32,
        mac: MacAddr,
        ip: Option<IpAddr>,
        route: RemoteRoute,
        now: Instant,
    ) -> (Verdict, Vec<DadKey>) {
        let config = self.config;
        let mut detected = Vec::new();
        let RemoteRoute { rd, vtep, es, .. } = route;
        let probe = self.macs.entry((vni, mac)).or_default();
        // A takeover from this node, while a window a local learn opened
        // is still counting; a sync route takes nothing over.
        if !matches!(probe.owner, Some(Owner::Remote { .. }))
            && es.is_none()
            && probe.count > 0
            && config.enabled
            && probe.duplicate.is_none()
            && probe.record(&config, now, false)
        {
            warn_detected(vni, &mac.to_string(), "remote update, from", vtep);
            detected.push(DadKey::Mac(vni, mac));
        }
        probe
            .remote_routes
            .insert((rd, RouteBinding::Ip(ip)), route);
        probe.owner = probe.newest_remote().map(|(_, route)| route.owner());
        if let Some(ip) = ip {
            // Only a binding at least as new as every other live one moves
            // the IP; an older one leaves it where it is.
            let binding = (rd, RouteBinding::Mac(mac));
            let binds = self.ips.get(&(vni, ip)).is_none_or(|entry| {
                entry
                    .probe
                    .remote_routes
                    .iter()
                    .all(|(key, other)| *key == binding || route.seq >= other.seq)
            });
            if binds {
                self.ip_leaves_duplicate_mac(vni, ip, mac);
            }
            let entry = self.ips.entry((vni, ip)).or_insert_with(|| IpProbe {
                mac,
                probe: Probe::default(),
            });
            if binds
                && entry.mac != mac
                && !matches!(entry.probe.owner, Some(Owner::Remote { .. }))
                && es.is_none()
                && entry.probe.count > 0
                && config.enabled
                && entry.probe.duplicate.is_none()
                && entry.probe.record(&config, now, false)
            {
                warn_detected(vni, &format!("{mac} IP {ip}"), "remote update, from", vtep);
                detected.push(DadKey::Ip(vni, ip));
            }
            if binds {
                entry.mac = mac;
                entry.probe.owner = Some(route.owner());
            }
            entry.probe.remote_routes.insert(binding, route);
            // Not the newest. An older binding re-run leaves the IP where it
            // is, but the IP's own binding replaced by an older one (a lower
            // number in an UPDATE, a best path falling back) may leave
            // another binding the newest.
            if !binds {
                self.ip_to_newest_binding(vni, ip);
            }
        }
        (self.verdict(vni, mac, ip), detected)
    }

    /// A remote IP is at the newest of its live bindings. After one of them
    /// came, went or changed its number, the IP moves to the newest if its
    /// own binding no longer is; a binding tied with the newest keeps it.
    /// Not a move this node takes part in, so nothing is counted.
    fn ip_to_newest_binding(&mut self, vni: u32, ip: IpAddr) {
        let Some(entry) = self.ips.get(&(vni, ip)) else {
            return;
        };
        if !matches!(entry.probe.owner, Some(Owner::Remote { .. })) {
            return;
        }
        let Some((RouteBinding::Mac(newest), newest_route)) = entry.probe.newest_remote() else {
            return;
        };
        let own = entry
            .probe
            .remote_routes
            .iter()
            .filter(|((_, binding), _)| *binding == RouteBinding::Mac(entry.mac))
            .map(|(_, route)| *route)
            .max_by_key(|route| route.seq);
        let (mac, route) = match own {
            Some(own) if own.seq >= newest_route.seq => (entry.mac, own),
            _ => (newest, newest_route),
        };
        self.ip_leaves_duplicate_mac(vni, ip, mac);
        if let Some(entry) = self.ips.get_mut(&(vni, ip)) {
            entry.mac = mac;
            entry.probe.owner = Some(route.owner());
        }
    }

    /// `ip` is about to be bound to `mac`. If it leaves a duplicate MAC for
    /// one that is not, it leaves that MAC's hold and its own detection
    /// starts over, as FRR's `zebra_evpn_ip_inherit_dad_from_mac` does
    /// ("clear duplicate flag for IP and reset detection params and let IP
    /// DAD retrigger"): the moves it made before are forgotten, so the
    /// rebinding is not counted on top of them. Without the reset an IP
    /// that had moved once, its MAC then detected, was itself detected by
    /// the rebinding (`max-moves 2`) and frozen.
    fn ip_leaves_duplicate_mac(&mut self, vni: u32, ip: IpAddr, mac: MacAddr) {
        let Some(old) = self.ips.get(&(vni, ip)).map(|entry| entry.mac) else {
            return;
        };
        if old != mac
            && self.mac_duplicate(vni, old)
            && !self.mac_duplicate(vni, mac)
            && let Some(entry) = self.ips.get_mut(&(vni, ip))
        {
            entry.probe.clear();
            self.recovery.remove(&DadKey::Ip(vni, ip));
        }
    }

    /// This node no longer has `mac` (bound to `ip`, for a MAC/IP route):
    /// the FDB entry was deleted. The address stops being local, and its
    /// state goes once nothing is left of it. Detection made an entry for
    /// every local MAC and IP, with detection on or off, and nothing removed
    /// it: the maps grew with every MAC that ever came and went.
    pub fn local_gone(&mut self, vni: u32, mac: MacAddr, ip: Option<IpAddr>, now: Instant) {
        let config = self.config;
        match ip {
            None => {
                if let Some(probe) = self.macs.get_mut(&(vni, mac)) {
                    if probe.owner == Some(Owner::Local) {
                        probe.owner = None;
                    }
                    if probe.idle(&config, now) {
                        self.macs.remove(&(vni, mac));
                    }
                }
            }
            Some(ip) => {
                if let Some(entry) = self.ips.get_mut(&(vni, ip)) {
                    if entry.mac == mac && entry.probe.owner == Some(Owner::Local) {
                        entry.probe.owner = None;
                    }
                    if entry.probe.idle(&config, now) {
                        self.ips.remove(&(vni, ip));
                    }
                }
            }
        }
    }

    fn verdict(&self, vni: u32, mac: MacAddr, ip: Option<IpAddr>) -> Verdict {
        if self.frozen(vni, mac, ip) {
            Verdict::Hold
        } else {
            Verdict::Proceed
        }
    }

    /// The remote route (RD `rd`) for `mac`, bound to `ip`, is no longer
    /// installed: withdrawn, or beaten by this node's own.
    pub fn remote_gone(
        &mut self,
        rd: [u8; 8],
        vni: u32,
        mac: MacAddr,
        ip: Option<IpAddr>,
        now: Instant,
    ) {
        let config = self.config;
        if let Some(probe) = self.macs.get_mut(&(vni, mac)) {
            probe.remote_route_gone((rd, RouteBinding::Ip(ip)));
            if probe.idle(&config, now) {
                self.macs.remove(&(vni, mac));
            }
        }
        if let Some(ip) = ip
            && let Some(entry) = self.ips.get_mut(&(vni, ip))
        {
            entry.probe.remote_route_gone((rd, RouteBinding::Mac(mac)));
            if entry.probe.idle(&config, now) {
                self.ips.remove(&(vni, ip));
                return;
            }
            self.ip_to_newest_binding(vni, ip);
        }
    }

    /// Release `key` from detection, as a recovery timer or `clear` does.
    /// A MAC releases the IPs bound to it along with it. Returns whether
    /// anything was marked.
    pub fn release(&mut self, key: DadKey) -> bool {
        match key {
            DadKey::Mac(vni, mac) => {
                let Some(probe) = self.macs.get_mut(&(vni, mac)) else {
                    return false;
                };
                let was = probe.duplicate.is_some();
                probe.clear();
                self.recovery.remove(&key);
                // A release, on a clear or a recovery, not a move: a scan
                // of the VNI's IPs, rather than an index of each MAC's,
                // which would be one more copy of the IPs' bindings.
                for ((_, ip), entry) in self
                    .ips
                    .range_mut((vni, IpAddr::from([0u8; 4]))..=(vni, IpAddr::from([0xffu8; 16])))
                    .filter(|(_, entry)| entry.mac == mac)
                {
                    entry.probe.clear();
                    self.recovery.remove(&DadKey::Ip(vni, *ip));
                }
                was
            }
            DadKey::Ip(vni, ip) => {
                let Some(entry) = self.ips.get_mut(&(vni, ip)) else {
                    return false;
                };
                let was = entry.probe.duplicate.is_some();
                entry.probe.clear();
                self.recovery.remove(&key);
                was
            }
        }
    }

    /// The addresses `clear bgp evpn dup-addr` names: every detected one in
    /// `vni` (or in every VNI), optionally narrowed to one MAC or IP.
    pub fn detected(
        &self,
        vni: Option<u32>,
        mac: Option<MacAddr>,
        ip: Option<IpAddr>,
    ) -> Vec<DadKey> {
        let in_vni = |v: u32| vni.is_none_or(|vni| vni == v);
        let macs = self
            .macs
            .iter()
            .filter(|((v, m), probe)| {
                probe.duplicate.is_some()
                    && in_vni(*v)
                    && ip.is_none()
                    && mac.is_none_or(|mac| mac == *m)
            })
            .map(|((v, m), _)| DadKey::Mac(*v, *m));
        let ips = self
            .ips
            .iter()
            .filter(|((v, i), entry)| {
                entry.probe.duplicate.is_some()
                    && in_vni(*v)
                    && mac.is_none()
                    && ip.is_none_or(|ip| ip == *i)
            })
            .map(|((v, i), _)| DadKey::Ip(*v, *i));
        macs.chain(ips).collect()
    }

    /// The duplicate MACs that hold `ip` in `vni` (or in every VNI), the
    /// IP being bound to them: releasing the IP alone cannot let it go.
    pub fn held_by_mac(&self, vni: Option<u32>, ip: IpAddr) -> Vec<(u32, MacAddr)> {
        self.ips
            .iter()
            .filter(|((v, i), entry)| {
                *i == ip && vni.is_none_or(|vni| vni == *v) && self.mac_duplicate(*v, entry.mac)
            })
            .map(|((v, _), entry)| (*v, entry.mac))
            .collect()
    }

    /// The recovery deadline armed for `key`, if any.
    pub fn until(&self, key: DadKey) -> Option<Instant> {
        let probe = match key {
            DadKey::Mac(vni, mac) => self.macs.get(&(vni, mac))?,
            DadKey::Ip(vni, ip) => &self.ips.get(&(vni, ip))?.probe,
        };
        probe.duplicate?.until
    }

    /// The configuration changed. Returns the detected addresses whose
    /// routes must be re-run: all of them when detection is turned off
    /// (which, as `no dup-addr-detection` in FRR, releases every one and
    /// forgets every window), or when the freeze policy changed, which
    /// applies to existing duplicates too, a timed freeze counting from
    /// `now`. Changes to the detection window or threshold keep existing
    /// deadlines. The recovery timers go with the old policy; the caller
    /// arms the new one's.
    pub fn set_config(&mut self, config: DadConfig, now: Instant) -> Vec<DadKey> {
        let freeze_changed = self.config.freeze != config.freeze;
        let keys = self.detected(None, None, None);
        self.config = config;
        if !config.enabled {
            for probe in self.macs.values_mut() {
                probe.clear();
            }
            for entry in self.ips.values_mut() {
                entry.probe.clear();
            }
            self.recovery.clear();
            return keys;
        }
        if freeze_changed {
            let until = config.freeze_until(now);
            self.recovery.clear();
            for probe in self
                .macs
                .values_mut()
                .chain(self.ips.values_mut().map(|entry| &mut entry.probe))
            {
                if let Some(duplicate) = &mut probe.duplicate {
                    duplicate.until = until;
                }
            }
            return keys;
        }
        Vec::new()
    }
}

fn warn_detected(vni: u32, what: &str, during: &str, vtep: Option<IpAddr>) {
    let vtep = vtep.map_or_else(|| "-".to_string(), |vtep| vtep.to_string());
    tracing::warn!("VNI {vni}: MAC {what} detected as duplicate during {during} VTEP {vtep}");
}

/// The recovery timer for a timed freeze: `EvpnDadRecover` arrives at
/// `until`, the absolute deadline however late the task first runs (a
/// timer counting its period from then would extend the freeze). `until`
/// identifies the freeze, so a wake-up already on its way when the freeze
/// was cleared or re-detected is discarded. The task is aborted when
/// dropped.
fn recovery_timer(tx: &mpsc::Sender<Message>, key: DadKey, until: Instant) -> Option<Task<()>> {
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::warn!(
            "EVPN duplicate address {key:?}: no runtime to arm the recovery timer; \
             it stays frozen until cleared"
        );
        return None;
    }
    let tx = tx.clone();
    Some(Task::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
        let _ = tx.send(Message::EvpnDadRecover { key, until }).await;
    }))
}

impl EvpnDad {
    /// Arm the recovery timer of every address in `keys` that a timed
    /// freeze holds. An address has none armed before: a release drops its
    /// timer, and so does a change of freeze policy (`set_config`).
    pub fn arm(&mut self, tx: &mpsc::Sender<Message>, keys: &[DadKey]) {
        for key in keys {
            if let Some(timer) = self
                .until(*key)
                .and_then(|until| recovery_timer(tx, *key, until))
            {
                self.recovery.insert(*key, timer);
            }
        }
    }
}

impl Bgp {
    /// Withdraw this speaker's routes that a freeze now holds: those of
    /// `mac` in `vni`, and those binding `ip` to any MAC. Withdrawn without
    /// re-running the remote routes they competed with — those are held too.
    pub(super) fn evpn_dad_withdraw_held(&mut self, vni: u32, mac: MacAddr, ip: Option<IpAddr>) {
        let binding = ip
            .into_iter()
            .flat_map(|ip| self.local_fdb.ip(vni, ip))
            .filter(|entry| entry.mac != mac);
        let held: Vec<FdbEntry> = self
            .local_fdb
            .mac(vni, mac)
            .chain(binding)
            .filter(|entry| {
                self.local_rib
                    .evpn_dad
                    .frozen(entry.vni, entry.mac, entry.ip)
                    && self.evpn_macip_originated(entry)
            })
            .cloned()
            .collect();
        for entry in held {
            self.evpn_withdraw_macip_route(&entry);
        }
    }

    /// Withdraw the routes remote takeovers of frozen addresses queued.
    pub fn evpn_dad_drain(&mut self) {
        for (vni, mac, ip) in std::mem::take(&mut self.local_rib.evpn_dad.withdraw) {
            self.evpn_dad_withdraw_held(vni, mac, ip);
        }
    }

    /// A timed freeze elapsed.
    pub fn evpn_dad_recover(&mut self, key: DadKey, until: Instant) {
        if self.local_rib.evpn_dad.until(key) != Some(until) {
            return;
        }
        tracing::info!("EVPN duplicate address {key:?}: freeze elapsed, recovering");
        self.local_rib.evpn_dad.release(key);
        self.evpn_dad_rerun(key);
    }

    /// `clear bgp evpn dup-addr vni <all|N> [mac M | ip I]`: release the
    /// matching detected addresses. Returns how many there were.
    ///
    /// An IP named on its own whose MAC is still a duplicate is left
    /// alone, as FRR refuses it ("Requested IP's associated MAC … is
    /// still in duplicate state"): it stays frozen with the MAC, and
    /// clearing the MAC releases both.
    pub fn evpn_dad_clear(
        &mut self,
        vni: Option<u32>,
        mac: Option<MacAddr>,
        ip: Option<IpAddr>,
    ) -> usize {
        let dad = &self.local_rib.evpn_dad;
        let mut keys = dad.detected(vni, mac, ip);
        if let Some(ip) = ip {
            for (v, mac) in dad.held_by_mac(vni, ip) {
                tracing::warn!(
                    "clear bgp evpn dup-addr: VNI {v} IP {ip}: its MAC {mac} is still a \
                     duplicate; clear the MAC to release both"
                );
                keys.retain(|key| *key != DadKey::Ip(v, ip));
            }
        }
        for key in &keys {
            self.local_rib.evpn_dad.release(*key);
            self.evpn_dad_rerun(*key);
        }
        keys.len()
    }

    /// The `clear bgp evpn dup-addr vni …` path tail after `vni` (empty,
    /// `/mac` or `/ip`) and its arguments: the VNI (or `all`), then the
    /// MAC or IP.
    pub(super) fn clear_evpn_dup_addr(&mut self, filter: &str, args: &mut crate::config::Args) {
        let invalid = |what: &str, value: Option<String>| {
            tracing::warn!(
                "clear bgp evpn dup-addr: invalid {what} {}; nothing cleared",
                value.as_deref().unwrap_or("(missing)")
            );
        };
        let arg = args.string();
        let vni = match arg.as_deref() {
            Some("all") => None,
            Some(vni) => match vni.parse() {
                Ok(vni) => Some(vni),
                Err(_) => return invalid("VNI", arg),
            },
            None => return invalid("VNI", arg),
        };
        let arg = args.string();
        let (mac, ip) = match filter {
            "" => (None, None),
            "/mac" => match arg.as_deref().and_then(|mac| mac.parse().ok()) {
                Some(mac) => (Some(mac), None),
                None => return invalid("MAC", arg),
            },
            "/ip" => match arg.as_deref().and_then(|ip| ip.parse().ok()) {
                Some(ip) => (None, Some(ip)),
                None => return invalid("IP", arg),
            },
            _ => return invalid("filter", Some(filter.to_string())),
        };
        let released = self.evpn_dad_clear(vni, mac, ip);
        tracing::info!("clear bgp evpn dup-addr: released {released} duplicate address(es)");
    }

    /// Apply new `dup-addr-detection` settings.
    pub fn evpn_dad_configure(&mut self, config: DadConfig) {
        if self.local_rib.evpn_dad.config == config {
            return;
        }
        let keys = self.local_rib.evpn_dad.set_config(config, Instant::now());
        if self.local_rib.evpn_dad.freezes() {
            // Now held (or held for a new time): withdraw what is still
            // advertised and arm the recovery deadlines.
            self.local_rib.evpn_dad.arm(&self.tx, &keys);
            for key in keys {
                match key {
                    DadKey::Mac(vni, mac) => self.evpn_dad_withdraw_held(vni, mac, None),
                    DadKey::Ip(vni, ip) => {
                        if let Some(entry) = self.local_rib.evpn_dad.ips.get(&(vni, ip)) {
                            self.evpn_dad_withdraw_held(vni, entry.mac, Some(ip));
                        }
                    }
                }
            }
        } else {
            for key in keys {
                self.evpn_dad_rerun(key);
            }
        }
    }

    /// Re-run the routes of a released (or no longer frozen) address, as
    /// FRR does on recovery: one learned here is advertised again (and so
    /// beats the remote routes it outranks), otherwise the remote routes
    /// are installed.
    fn evpn_dad_rerun(&mut self, key: DadKey) {
        let dad = &self.local_rib.evpn_dad;
        let (vni, mac, ip, owner) = match key {
            DadKey::Mac(vni, mac) => (
                vni,
                Some(mac),
                None,
                dad.macs.get(&(vni, mac)).and_then(|p| p.owner),
            ),
            DadKey::Ip(vni, ip) => {
                let entry = dad.ips.get(&(vni, ip));
                (
                    vni,
                    entry.map(|e| e.mac),
                    Some(ip),
                    entry.and_then(|e| e.probe.owner),
                )
            }
        };
        let remote = |owner: Option<Owner>| matches!(owner, Some(Owner::Remote { .. }));
        let mut local = Vec::new();
        if !remote(owner) {
            // An IP's local bindings on a MAC that has since gone remote
            // are not re-advertised: the remote route beat them, and
            // learning them again would count a move of the MAC.
            local = match key {
                DadKey::Mac(_, mac) => self.local_fdb.mac(vni, mac).cloned().collect(),
                DadKey::Ip(_, ip) => self
                    .local_fdb
                    .ip(vni, ip)
                    .filter(|entry| !remote(dad.macs.get(&(vni, entry.mac)).and_then(|p| p.owner)))
                    .cloned()
                    .collect(),
            };
        }
        // Each origination re-runs the remote routes it competes with.
        for entry in &local {
            self.evpn_originate_macip(entry);
        }
        if local.is_empty()
            && let Some(mac) = mac
        {
            self.evpn_reconcile_remote_mac(vni, mac.octets(), ip);
        }
    }
}

/// `show evpn dup-addr`.
#[derive(Debug, serde::Serialize)]
pub struct DadView {
    pub enabled: bool,
    pub max_moves: u32,
    pub time: u32,
    /// `off`, `permanent` or the freeze time in seconds.
    pub freeze: String,
    pub addresses: Vec<DadAddressView>,
}

/// One address `show evpn dup-addr` lists: detected, or with moves counted
/// in an open window.
#[derive(Debug, serde::Serialize)]
pub struct DadAddressView {
    pub vni: u32,
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub duplicate: bool,
    /// Duplicate because the MAC the IP is bound to is.
    pub inherited: bool,
    pub moves: u32,
    /// `local`, `remote <vtep>`, or `-`.
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_secs_ago: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovers_in_secs: Option<u64>,
}

impl EvpnDad {
    pub fn view(&self, now: Instant) -> DadView {
        let location = |owner: Option<Owner>| match owner {
            Some(Owner::Local) => "local".to_string(),
            Some(Owner::Remote {
                vtep: Some(vtep), ..
            }) => format!("remote {vtep}"),
            Some(Owner::Remote { vtep: None, .. }) => "remote".to_string(),
            None => "-".to_string(),
        };
        let window = Duration::from_secs(self.config.time.into());
        // Moves in a window that has since closed are not worth showing.
        let counting = |probe: &Probe| {
            probe.count > 0
                && probe
                    .start
                    .is_some_and(|start| now.saturating_duration_since(start) <= window)
        };
        let row = |vni: u32, mac: MacAddr, ip: Option<IpAddr>, probe: &Probe, inherited: bool| {
            DadAddressView {
                vni,
                mac: mac.to_string(),
                ip: ip.map(|ip| ip.to_string()),
                duplicate: probe.duplicate.is_some() || inherited,
                inherited: inherited && probe.duplicate.is_none(),
                moves: probe.count,
                location: location(probe.owner),
                detected_secs_ago: probe
                    .duplicate
                    .map(|dup| now.saturating_duration_since(dup.since).as_secs()),
                recovers_in_secs: probe
                    .duplicate
                    .and_then(|dup| dup.until)
                    .map(|until| until.saturating_duration_since(now).as_secs()),
            }
        };
        let mut addresses: Vec<DadAddressView> = self
            .macs
            .iter()
            .filter(|(_, probe)| probe.duplicate.is_some() || counting(probe))
            .map(|((vni, mac), probe)| row(*vni, *mac, None, probe, false))
            .collect();
        addresses.extend(
            self.ips
                .iter()
                .filter(|((vni, _), entry)| {
                    entry.probe.duplicate.is_some()
                        || counting(&entry.probe)
                        || self.mac_duplicate(*vni, entry.mac)
                })
                .map(|((vni, ip), entry)| {
                    row(
                        *vni,
                        entry.mac,
                        Some(*ip),
                        &entry.probe,
                        self.mac_duplicate(*vni, entry.mac),
                    )
                }),
        );
        addresses.sort_by(|a, b| (a.vni, &a.mac, &a.ip).cmp(&(b.vni, &b.mac, &b.ip)));
        DadView {
            enabled: self.config.enabled,
            max_moves: self.config.max_moves,
            time: self.config.time,
            freeze: match self.config.freeze {
                Freeze::Off => "off".to_string(),
                Freeze::Permanent => "permanent".to_string(),
                Freeze::For(secs) => secs.to_string(),
            },
            addresses,
        }
    }
}

pub fn format_dad_view(view: &DadView) -> Result<String, std::fmt::Error> {
    use std::fmt::Write;
    let mut out = String::new();
    if !view.enabled {
        writeln!(out, "Duplicate address detection: disabled")?;
        return Ok(out);
    }
    let freeze = match view.freeze.as_str() {
        "off" => "off (warn only)".to_string(),
        "permanent" => "permanent".to_string(),
        secs => format!("{secs}s"),
    };
    writeln!(
        out,
        "Duplicate address detection: max-moves {} within {}s, freeze {freeze}",
        view.max_moves, view.time
    )?;
    if view.addresses.is_empty() {
        writeln!(out, "No duplicate addresses")?;
        return Ok(out);
    }
    writeln!(out)?;
    writeln!(
        out,
        "{:<9} {:<17} {:<39} {:<10} {:<5} {:<24} Detected",
        "VNI", "MAC", "IP", "State", "Moves", "Location"
    )?;
    for row in &view.addresses {
        let state = match (row.duplicate, row.inherited) {
            (true, true) => "dup (MAC)",
            (true, false) => "duplicate",
            (false, _) => "counting",
        };
        let detected = match (row.detected_secs_ago, row.recovers_in_secs) {
            (Some(ago), Some(left)) => format!("{ago}s ago, recovers in {left}s"),
            (Some(ago), None) => format!("{ago}s ago"),
            _ => "-".to_string(),
        };
        writeln!(
            out,
            "{:<9} {:<17} {:<39} {:<10} {:<5} {:<24} {detected}",
            row.vni,
            row.mac,
            row.ip.as_deref().unwrap_or("-"),
            state,
            row.moves,
            row.location,
        )?;
    }
    Ok(out)
}

pub fn show_evpn_dup_addr(
    bgp: &Bgp,
    _args: crate::config::Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let view = bgp.local_rib.evpn_dad.view(Instant::now());
    if json {
        return Ok(serde_json::to_string_pretty(&view)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }
    format_dad_view(&view)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VNI: u32 = 100;
    const RD: [u8; 8] = [0, 1, 10, 0, 0, 11, 0, 100];
    const VTEP: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 11)));

    fn mac(last: u8) -> MacAddr {
        MacAddr::from([2, 0, 0, 0, 0, last])
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 10, 0, last])
    }

    fn dad(max_moves: u32, freeze: Freeze) -> EvpnDad {
        EvpnDad {
            config: DadConfig {
                enabled: true,
                max_moves,
                time: 180,
                freeze,
            },
            ..Default::default()
        }
    }

    /// A route from `VTEP`: not sticky, on no segment of ours.
    fn route() -> RemoteRoute {
        RemoteRoute {
            rd: RD,
            vtep: VTEP,
            sticky: false,
            es: None,
            seq: 1,
        }
    }

    /// One remote takeover followed by one local learn, `secs` after `t`.
    fn flap(dad: &mut EvpnDad, t: Instant, secs: u64) -> Vec<DadKey> {
        let now = t + Duration::from_secs(secs);
        let (_, mut keys) = dad.remote_takeover(VNI, mac(1), None, route(), now);
        keys.extend(dad.local_learn(VNI, mac(1), None, now).1);
        keys
    }

    /// Mark `mac` detected, as a flap would.
    fn mark_duplicate(dad: &mut EvpnDad, mac: MacAddr, t: Instant) {
        dad.macs.entry((VNI, mac)).or_default().duplicate = Some(Duplicate {
            since: t,
            until: None,
        });
    }

    /// A recovery timer wakes at the freeze's deadline, however late its
    /// task first runs. A timer counting its period from its first run
    /// extended the freeze: one first run 31 s into a 30 s freeze waited
    /// another 30 s.
    #[tokio::test(start_paused = true)]
    async fn recovery_wakes_at_the_deadline_however_late_the_timer_starts() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut dad = dad(2, Freeze::For(30));
        let t = Instant::now();
        let mut keys = flap(&mut dad, t, 0);
        keys.extend(flap(&mut dad, t, 0));
        assert_eq!(keys, vec![DadKey::Mac(VNI, mac(1))]);
        dad.arm(&tx, &keys);
        let deadline = dad.until(keys[0]).unwrap();
        // The clock passes the deadline before the timer's task first runs.
        tokio::time::advance(Duration::from_secs(31)).await;
        let message = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("woken at the deadline")
            .expect("channel open");
        let Message::EvpnDadRecover { key, until } = message else {
            panic!("expected a recovery");
        };
        assert_eq!((key, until), (keys[0], deadline));
    }

    /// Releasing a MAC releases the IPs bound to it, and their recovery
    /// timers go with them.
    #[tokio::test]
    async fn releasing_a_mac_drops_its_ips_timers() {
        let t = Instant::now();
        let (tx, _rx) = mpsc::channel(1);
        let mut dad = dad(2, Freeze::For(60));
        // The IP moves from mac(2) to mac(1) and back: detected on its own.
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t);
        dad.local_learn(VNI, mac(1), Some(ip(5)), t); // 1
        let (_, keys) = dad.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t); // 2
        assert_eq!(keys, vec![DadKey::Ip(VNI, ip(5))]);
        dad.arm(&tx, &keys);
        mark_duplicate(&mut dad, mac(2), t);
        assert!(dad.recovery.contains_key(&DadKey::Ip(VNI, ip(5))));

        assert!(dad.release(DadKey::Mac(VNI, mac(2))));
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.duplicate, None);
        assert!(dad.recovery.is_empty());

        // Released on its own, an IP drops its timer too.
        dad.local_learn(VNI, mac(1), Some(ip(5)), t); // 1
        let (_, keys) = dad.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t); // 2
        dad.arm(&tx, &keys);
        assert_eq!(dad.recovery.len(), 1);
        assert!(dad.release(DadKey::Ip(VNI, ip(5))));
        assert!(dad.recovery.is_empty());

        // And so does an IP that leaves a duplicate MAC for a clean one,
        // its own mark forgotten with its moves.
        dad.local_learn(VNI, mac(1), Some(ip(5)), t); // 1
        let (_, keys) = dad.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t); // 2
        dad.arm(&tx, &keys);
        mark_duplicate(&mut dad, mac(2), t);
        dad.remote_takeover(VNI, mac(3), Some(ip(5)), route(), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.duplicate, None);
        assert!(dad.recovery.is_empty());
    }

    /// A host on a segment this node shares with the peer is reachable over
    /// our own port wherever it was learned. The peer's route for it on the
    /// segment only syncs it (FRR's sync route), so neither that route nor
    /// a learn here after it is a move, for the MAC or for an IP changing
    /// MACs. A route from a peer off our segments still is.
    #[test]
    fn moves_with_a_peer_on_our_segment_do_not_count() {
        let t = Instant::now();
        let sync = RemoteRoute {
            es: Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            ..route()
        };
        let mut dad = dad(2, Freeze::Permanent);
        // From a peer off our segments, then here: the MAC moved, and the
        // IP moved from mac(2) to mac(1). Both windows are open.
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t);
        dad.local_learn(VNI, mac(1), Some(ip(5)), t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 1);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 1);

        // Back and forth between the peer on our segment and here.
        for _ in 0..3 {
            dad.remote_takeover(VNI, mac(2), Some(ip(5)), sync, t);
            dad.remote_takeover(VNI, mac(1), None, sync, t);
            dad.local_learn(VNI, mac(1), Some(ip(5)), t);
        }
        assert_eq!(dad.detected(None, None, None), vec![]);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 1);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 1);

        // Off our segments the takeover counts, and completes detection.
        let (_, keys) = dad.remote_takeover(VNI, mac(1), None, route(), t);
        assert_eq!(keys, vec![DadKey::Mac(VNI, mac(1))]);
    }

    /// Only the newest binding of an IP moves it. A route for an older one,
    /// re-run (by a reconcile, a refresh) while a newer route binds the IP
    /// to another MAC, leaves the IP where it is; it moved it back, and the
    /// host learned here on its newest MAC then counted as an IP move.
    #[test]
    fn an_older_binding_of_an_ip_does_not_move_it() {
        let t = Instant::now();
        let older = RemoteRoute {
            rd: [0, 1, 10, 0, 0, 12, 0, 100],
            ..route()
        };
        let newer = RemoteRoute { seq: 5, ..route() };
        let mut dad = dad(2, Freeze::Permanent);
        // (mac(2), seq 5) is the newest; (mac(1), seq 1) re-runs after it.
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), newer, t);
        dad.remote_takeover(VNI, mac(1), Some(ip(5)), older, t);
        assert_eq!(dad.ips[&(VNI, ip(5))].mac, mac(2));
        // The host, on the same MAC, is learned here: the MAC moved, the IP
        // did not leave it.
        dad.local_learn(VNI, mac(2), Some(ip(5)), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 0);

        // Nor is an older binding re-run a takeover of the IP from here.
        let mut dad = super::EvpnDad {
            config: dad.config,
            ..Default::default()
        };
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), newer, t);
        dad.local_learn(VNI, mac(3), Some(ip(5)), t); // 1
        let (_, keys) = dad.remote_takeover(VNI, mac(1), Some(ip(5)), older, t);
        assert_eq!(keys, vec![]);
        let entry = &dad.ips[&(VNI, ip(5))];
        assert_eq!((entry.mac, entry.probe.count), (mac(3), 1));
        assert_eq!(entry.probe.owner, Some(Owner::Local));
        // With no other binding live, an older-numbered route binds the IP
        // all the same: the IP is remote, on that MAC.
        dad.remote_takeover(VNI, mac(1), Some(ip(6)), older, t);
        let entry = &dad.ips[&(VNI, ip(6))];
        assert_eq!(entry.mac, mac(1));
        assert!(matches!(entry.probe.owner, Some(Owner::Remote { .. })));
    }

    /// An IP is where the newest of its live bindings is. A withdrawn one
    /// no longer counts, however high its number was, and when the IP's
    /// binding is withdrawn it goes back to the newest one left.
    #[test]
    fn an_ip_is_at_its_newest_live_binding() {
        let t = Instant::now();
        let at = |rd_last: u8, seq: u32| RemoteRoute {
            rd: [0, 1, 10, 0, 0, rd_last, 0, 100],
            seq,
            ..route()
        };
        let mut dad = dad(3, Freeze::Permanent);
        dad.remote_takeover(VNI, mac(1), Some(ip(5)), at(11, 1), t);
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), at(12, 5), t);
        dad.remote_takeover(VNI, mac(1), Some(ip(5)), at(11, 1), t); // re-run
        assert_eq!(dad.ips[&(VNI, ip(5))].mac, mac(2));

        // mac(2)'s route withdrawn: the IP is on mac(1), and the host
        // learned here on mac(1) kept its MAC.
        dad.remote_gone(at(12, 5).rd, VNI, mac(2), Some(ip(5)), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].mac, mac(1));
        dad.local_learn(VNI, mac(1), Some(ip(5)), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 0);
    }

    /// The IP's own binding replaced by an older one (a lower number in an
    /// UPDATE, a best path falling back) leaves another binding the newest,
    /// and the IP moves there; it stayed, and the host learned here on the
    /// newest binding's MAC counted an IP move. A binding tied with the
    /// newest keeps the IP.
    #[test]
    fn an_ip_follows_its_binding_replaced_by_an_older_one() {
        let t = Instant::now();
        let at = |rd_last: u8, seq: u32| RemoteRoute {
            rd: [0, 1, 10, 0, 0, rd_last, 0, 100],
            seq,
            ..route()
        };
        let mut dad = dad(3, Freeze::Permanent);
        dad.remote_takeover(VNI, mac(1), Some(ip(5)), at(11, 10), t);
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), at(12, 5), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].mac, mac(1));
        dad.remote_takeover(VNI, mac(1), Some(ip(5)), at(11, 1), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].mac, mac(2));
        dad.local_learn(VNI, mac(2), Some(ip(5)), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 0);

        // mac(2) and mac(1) tie at 10, the IP on mac(2), the one that came
        // last; an older binding re-run does not move it to mac(1).
        let mut dad = super::EvpnDad {
            config: dad.config,
            ..Default::default()
        };
        dad.remote_takeover(VNI, mac(1), Some(ip(5)), at(12, 10), t);
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), at(11, 10), t);
        dad.remote_takeover(VNI, mac(3), Some(ip(5)), at(13, 1), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].mac, mac(2));
    }

    /// A remote address is where the newest of its live routes is. A
    /// segment peer's sync route withdrawn, or re-run older than an
    /// ordinary route, leaves the ordinary route deciding, so a learn here
    /// is a move again.
    #[test]
    fn an_ordinary_route_left_is_not_exempt() {
        let t = Instant::now();
        let es = Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let ordinary = |seq| RemoteRoute { seq, ..route() };
        let sync = |seq| RemoteRoute {
            rd: [0, 1, 10, 0, 0, 12, 0, 100],
            es,
            seq,
            ..route()
        };
        let owner_es = |dad: &EvpnDad| match dad.macs[&(VNI, mac(1))].owner {
            Some(Owner::Remote { es, .. }) => es,
            owner => panic!("not remote: {owner:?}"),
        };

        // The sync route is the newest, then goes.
        let mut dad = dad(3, Freeze::Permanent);
        dad.remote_takeover(VNI, mac(1), None, ordinary(1), t);
        dad.remote_takeover(VNI, mac(1), None, sync(2), t);
        assert_eq!(owner_es(&dad), es);
        dad.remote_gone(sync(2).rd, VNI, mac(1), None, t);
        assert_eq!(owner_es(&dad), None);
        dad.local_learn(VNI, mac(1), None, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 1);

        // The sync route re-runs older than the ordinary one.
        let mut dad = super::EvpnDad {
            config: dad.config,
            ..Default::default()
        };
        dad.remote_takeover(VNI, mac(1), None, ordinary(3), t);
        dad.remote_takeover(VNI, mac(1), None, sync(2), t);
        assert_eq!(owner_es(&dad), None);
        dad.local_learn(VNI, mac(1), None, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 1);
    }

    /// An IP leaving a duplicate MAC for a clean one forgets its earlier
    /// moves (FRR's `zebra_evpn_ip_inherit_dad_from_mac`), so the
    /// rebinding does not complete its own detection; on a duplicate MAC,
    /// or a MAC that is not one in the first place, it keeps them.
    #[test]
    fn an_ip_leaving_a_duplicate_mac_forgets_its_moves() {
        let t = Instant::now();
        let setup = || {
            let mut dad = dad(2, Freeze::Permanent);
            // On mac(2) remotely, then learned here on mac(1): one move.
            dad.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t);
            dad.local_learn(VNI, mac(1), Some(ip(5)), t);
            assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 1);
            dad
        };

        let mut clean = setup();
        mark_duplicate(&mut clean, mac(1), t);
        let (verdict, keys) = clean.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t);
        assert_eq!((verdict, keys), (Verdict::Proceed, vec![]));
        let probe = &clean.ips[&(VNI, ip(5))].probe;
        assert_eq!((probe.count, probe.duplicate), (0, None));

        // To a MAC that is a duplicate too: the move still counts.
        let mut dup = setup();
        mark_duplicate(&mut dup, mac(1), t);
        mark_duplicate(&mut dup, mac(3), t);
        let (verdict, _) = dup.remote_takeover(VNI, mac(3), Some(ip(5)), route(), t);
        assert_eq!(verdict, Verdict::Hold);
        assert_eq!(dup.ips[&(VNI, ip(5))].probe.count, 2);

        // From a MAC that is not a duplicate: likewise.
        let mut plain = setup();
        let (_, keys) = plain.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t);
        assert_eq!(keys, vec![DadKey::Ip(VNI, ip(5))]);
    }

    /// A local address that goes (its FDB entry deleted) is forgotten,
    /// detection on or off, unless a window it opened is still counting:
    /// that stays until it runs out.
    #[test]
    fn a_local_address_that_goes_is_forgotten() {
        let t = Instant::now();
        for enabled in [true, false] {
            let mut dad = dad(2, Freeze::Off);
            dad.config.enabled = enabled;
            dad.local_learn(VNI, mac(1), Some(ip(1)), t);
            dad.local_gone(VNI, mac(1), Some(ip(1)), t);
            dad.local_gone(VNI, mac(1), None, t);
            assert!(
                dad.macs.is_empty() && dad.ips.is_empty(),
                "enabled {enabled}"
            );
        }

        // A learn of a remote MAC opens a window (one move).
        let mut dad = dad(3, Freeze::Off);
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.local_learn(VNI, mac(1), None, t);
        dad.local_gone(VNI, mac(1), None, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 1, "window open");
        dad.remote_gone(RD, VNI, mac(1), None, t + Duration::from_secs(181));
        assert!(dad.macs.is_empty(), "window run out");
    }

    /// A first local learn, or one after the remote route went, is not a
    /// move; refreshes of a local MAC are not moves either.    /// A first local learn, or one after the remote route went, is not a
    /// move; refreshes of a local MAC are not moves either.
    #[test]
    fn only_a_learn_of_a_remote_mac_is_a_move() {
        let mut dad = dad(2, Freeze::Off);
        let t = Instant::now();
        dad.local_learn(VNI, mac(1), None, t);
        dad.local_learn(VNI, mac(1), None, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
        // A remote route outside any window counts nothing.
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
        dad.remote_gone(RD, VNI, mac(1), None, t);
        dad.local_learn(VNI, mac(1), None, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
    }

    /// FRR counts a local learn of a remote MAC, then a remote takeover
    /// while that window is open; `max-moves` within the window detects.
    #[test]
    fn max_moves_within_the_window_detects() {
        let mut dad = dad(5, Freeze::Off);
        let t = Instant::now();
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        assert!(dad.local_learn(VNI, mac(1), None, t).1.is_empty()); // 1
        assert!(flap(&mut dad, t, 10).is_empty()); // 2, 3
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 3);
        // The fourth move, a takeover, does not yet; the fifth, local, does.
        let now = t + Duration::from_secs(20);
        let (verdict, keys) = dad.remote_takeover(VNI, mac(1), None, route(), now);
        assert_eq!((verdict, keys), (Verdict::Proceed, vec![]));
        let (verdict, keys) = dad.local_learn(VNI, mac(1), None, now);
        assert_eq!(keys, vec![DadKey::Mac(VNI, mac(1))]);
        // Warn-only: routes keep flowing.
        assert_eq!(verdict, Verdict::Proceed);
        assert!(dad.mac_duplicate(VNI, mac(1)));
        assert!(!dad.frozen(VNI, mac(1), None));
    }

    /// Moves spread wider than the window never add up.
    #[test]
    fn moves_outside_the_window_restart_it() {
        let mut dad = dad(3, Freeze::Off);
        let t = Instant::now();
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.local_learn(VNI, mac(1), None, t); // 1
        // Past the window: the takeover counts nothing, the learn restarts.
        assert!(flap(&mut dad, t, 200).is_empty());
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 1);
        assert!(flap(&mut dad, t, 400).is_empty());
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 1);
        assert!(!dad.mac_duplicate(VNI, mac(1)));
    }

    /// A remote VTEP change or a sticky remote MAC is not a move.
    #[test]
    fn remote_to_remote_and_sticky_moves_do_not_count() {
        let mut dad = dad(2, Freeze::Off);
        let t = Instant::now();
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.local_learn(VNI, mac(1), None, t); // 1
        dad.remote_takeover(VNI, mac(1), None, route(), t); // 2: detected
        assert!(dad.mac_duplicate(VNI, mac(1)));

        let mut dad = super::EvpnDad {
            config: dad.config,
            ..Default::default()
        };
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.local_learn(VNI, mac(1), None, t); // 1
        dad.remote_takeover(
            VNI,
            mac(1),
            None,
            RemoteRoute {
                sticky: true,
                ..route()
            },
            t + Duration::from_secs(1),
        ); // 2
        dad.release(DadKey::Mac(VNI, mac(1)));
        // Sticky remote owner: the local learn is not counted.
        assert!(dad.local_learn(VNI, mac(1), None, t).1.is_empty());
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
        // Another VTEP taking over from a remote owner is not a move.
        let other = Some(IpAddr::from([10, 0, 0, 12]));
        dad.remote_takeover(VNI, mac(2), None, route(), t);
        dad.local_learn(VNI, mac(2), None, t); // 1
        dad.remote_takeover(VNI, mac(2), None, route(), t); // 2
        dad.release(DadKey::Mac(VNI, mac(2)));
        dad.remote_takeover(
            VNI,
            mac(2),
            None,
            RemoteRoute {
                vtep: other,
                ..route()
            },
            t,
        );
        assert_eq!(dad.macs[&(VNI, mac(2))].count, 0);
    }

    /// Under freeze a duplicate is held, and its IPs with it; a timed
    /// freeze carries the recovery deadline; release lifts both.
    #[test]
    fn freeze_holds_the_mac_and_its_ips_until_released() {
        let mut dad = dad(2, Freeze::For(60));
        let t = Instant::now();
        dad.local_learn(VNI, mac(1), Some(ip(5)), t);
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.local_learn(VNI, mac(1), None, t); // 1
        let (verdict, keys) = dad.remote_takeover(VNI, mac(1), None, route(), t); // 2
        assert_eq!(verdict, Verdict::Hold);
        assert_eq!(keys, vec![DadKey::Mac(VNI, mac(1))]);
        assert_eq!(dad.until(keys[0]), Some(t + Duration::from_secs(60)));
        assert!(dad.frozen(VNI, mac(1), Some(ip(5))));
        // Later events for a frozen address are held without counting.
        assert_eq!(dad.local_learn(VNI, mac(1), None, t).0, Verdict::Hold);
        assert!(dad.release(DadKey::Mac(VNI, mac(1))));
        assert!(!dad.frozen(VNI, mac(1), Some(ip(5))));
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
        assert!(!dad.release(DadKey::Mac(VNI, mac(1))));
    }

    /// An IP moving between MACs on this node and a remote one is detected
    /// on its own; the same MAC re-learned is not an IP move.
    #[test]
    fn an_ip_moving_between_macs_is_detected() {
        let mut dad = dad(2, Freeze::Permanent);
        let t = Instant::now();
        dad.remote_takeover(VNI, mac(1), Some(ip(5)), route(), t);
        // The IP appears here on another MAC: one move.
        dad.local_learn(VNI, mac(2), Some(ip(5)), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 1);
        // Back behind the peer on the first MAC: two, detected.
        let (verdict, keys) = dad.remote_takeover(VNI, mac(1), Some(ip(5)), route(), t);
        assert_eq!(keys, vec![DadKey::Ip(VNI, ip(5))]);
        assert_eq!(verdict, Verdict::Hold);
        // Permanent: no deadline. The MACs themselves are not duplicates.
        assert_eq!(dad.until(keys[0]), None);
        assert!(!dad.mac_duplicate(VNI, mac(1)));
        assert!(!dad.frozen(VNI, mac(1), None));
        assert!(dad.frozen(VNI, mac(1), Some(ip(5))));

        // An IP that keeps its MAC is the MAC's move, not the IP's.
        let mut dad = super::EvpnDad {
            config: dad.config,
            ..Default::default()
        };
        dad.remote_takeover(VNI, mac(1), Some(ip(5)), route(), t);
        dad.local_learn(VNI, mac(1), Some(ip(5)), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 0);
    }

    /// `clear` names detected addresses by VNI, MAC or IP.
    #[test]
    fn detected_filters_by_vni_mac_and_ip() {
        let mut dad = dad(1, Freeze::Off);
        let t = Instant::now();
        for (vni, m) in [(100, mac(1)), (200, mac(2))] {
            dad.remote_takeover(vni, m, None, route(), t);
            dad.local_learn(vni, m, None, t);
        }
        dad.remote_takeover(100, mac(3), Some(ip(5)), route(), t);
        dad.local_learn(100, mac(4), Some(ip(5)), t);
        assert_eq!(dad.detected(None, None, None).len(), 3);
        assert_eq!(
            dad.detected(Some(200), None, None),
            vec![DadKey::Mac(200, mac(2))]
        );
        assert_eq!(
            dad.detected(None, Some(mac(1)), None),
            vec![DadKey::Mac(100, mac(1))]
        );
        assert_eq!(
            dad.detected(Some(100), None, Some(ip(5))),
            vec![DadKey::Ip(100, ip(5))]
        );
    }

    /// Turning detection off forgets every probe, as `no dup-addr-detection`
    /// does in FRR, and reports a lifted freeze.
    #[test]
    fn disabling_detection_clears_state_and_lifts_the_freeze() {
        let mut dad = dad(1, Freeze::Permanent);
        let t = Instant::now();
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.local_learn(VNI, mac(1), None, t);
        assert!(dad.frozen(VNI, mac(1), None));
        let keys = dad.set_config(
            DadConfig {
                enabled: false,
                ..dad.config
            },
            t,
        );
        assert_eq!(keys, vec![DadKey::Mac(VNI, mac(1))]);
        assert!(!dad.mac_duplicate(VNI, mac(1)));
        // Disabled, nothing is counted.
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.local_learn(VNI, mac(1), None, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
    }

    /// A new freeze policy applies to existing duplicates, a timed one
    /// counting from the change; threshold and window changes keep the
    /// deadlines.
    #[test]
    fn freeze_policy_changes_reset_deadlines_but_threshold_changes_do_not() {
        let mut dad = dad(2, Freeze::Off);
        let t = Instant::now();
        // Detect a MAC and an independent IP, both initially warn-only.
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.local_learn(VNI, mac(1), None, t);
        dad.remote_takeover(VNI, mac(1), None, route(), t);
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t);
        dad.local_learn(VNI, mac(3), Some(ip(5)), t);
        dad.remote_takeover(VNI, mac(2), Some(ip(5)), route(), t);
        let keys = vec![DadKey::Mac(VNI, mac(1)), DadKey::Ip(VNI, ip(5))];
        assert_eq!(dad.detected(None, None, None), keys);

        let now = t + Duration::from_secs(10);
        assert_eq!(
            dad.set_config(
                DadConfig {
                    freeze: Freeze::For(30),
                    ..dad.config
                },
                now
            ),
            keys
        );
        let deadline = now + Duration::from_secs(30);
        for key in &keys {
            assert_eq!(dad.until(*key), Some(deadline));
        }
        assert!(
            dad.set_config(
                DadConfig {
                    max_moves: 5,
                    time: 60,
                    ..dad.config
                },
                now
            )
            .is_empty()
        );
        for key in &keys {
            assert_eq!(dad.until(*key), Some(deadline));
        }

        for freeze in [Freeze::Permanent, Freeze::For(60), Freeze::Off] {
            assert_eq!(
                dad.set_config(
                    DadConfig {
                        freeze,
                        ..dad.config
                    },
                    now
                ),
                keys
            );
            let until = if freeze == Freeze::For(60) {
                Some(now + Duration::from_secs(60))
            } else {
                None
            };
            for key in &keys {
                assert_eq!(dad.until(*key), until);
            }
        }
        assert!(
            dad.mac_duplicate(VNI, mac(1)),
            "removing a freeze keeps duplicate marks"
        );
        assert!(!dad.frozen(VNI, mac(1), None));
        assert!(!dad.frozen(VNI, mac(2), Some(ip(5))));
    }
}
