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
    },
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
    /// the IP (MAC probe) or MAC (IP probe) they bind: it stops being
    /// remote when the last one goes.
    pub remote_routes: BTreeSet<([u8; 8], RouteBinding)>,
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
        let until = match config.freeze {
            Freeze::For(secs) => Some(now + Duration::from_secs(secs.into())),
            Freeze::Off | Freeze::Permanent => None,
        };
        self.duplicate = Some(Duplicate { since: now, until });
        true
    }

    /// Forget the window and any duplicate mark, keeping the owner.
    fn clear(&mut self) {
        self.count = 0;
        self.start = None;
        self.duplicate = None;
    }

    /// Nothing worth keeping: no owner, no open window, no mark.
    fn idle(&self) -> bool {
        self.owner.is_none() && self.count == 0 && self.duplicate.is_none()
    }

    /// One remote route for the address went; with the last, it is no
    /// longer remote.
    fn remote_route_gone(&mut self, route: ([u8; 8], RouteBinding)) {
        self.remote_routes.remove(&route);
        if self.remote_routes.is_empty() && matches!(self.owner, Some(Owner::Remote { .. })) {
            self.owner = None;
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
    /// by `Bgp::evpn_dad_drain`, which has the peers the withdrawal needs.
    pub withdraw: BTreeSet<(u32, MacAddr, Option<IpAddr>)>,
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
        // A move only from a remote owner; a remote sticky MAC learned
        // here is an operator error FRR reports and does not count.
        if let Some(Owner::Remote { vtep, sticky }) = probe.owner
            && config.enabled
            && !sticky
            && probe.duplicate.is_none()
            && probe.record(&config, now, true)
        {
            warn_detected(vni, &mac.to_string(), "local update, last", vtep);
            detected.push(DadKey::Mac(vni, mac));
        }
        probe.owner = Some(Owner::Local);
        if let Some(ip) = ip {
            let entry = self.ips.entry((vni, ip)).or_insert_with(|| IpProbe {
                mac,
                probe: Probe::default(),
            });
            // FRR's scenario B: the IP moved here on a different MAC.
            if let Some(Owner::Remote { vtep, .. }) = entry.probe.owner
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

    /// A remote route (RD `rd`) for `mac`, bound to `ip`, from `vtep`
    /// beats this node's own and is about to be installed.
    #[allow(clippy::too_many_arguments)]
    pub fn remote_takeover(
        &mut self,
        rd: [u8; 8],
        vni: u32,
        mac: MacAddr,
        ip: Option<IpAddr>,
        vtep: Option<IpAddr>,
        sticky: bool,
        now: Instant,
    ) -> (Verdict, Vec<DadKey>) {
        let config = self.config;
        let mut detected = Vec::new();
        let owner = Some(Owner::Remote { vtep, sticky });
        let probe = self.macs.entry((vni, mac)).or_default();
        // A takeover from this node, while a window a local learn opened
        // is still counting.
        if !matches!(probe.owner, Some(Owner::Remote { .. }))
            && probe.count > 0
            && config.enabled
            && probe.duplicate.is_none()
            && probe.record(&config, now, false)
        {
            warn_detected(vni, &mac.to_string(), "remote update, from", vtep);
            detected.push(DadKey::Mac(vni, mac));
        }
        probe.owner = owner;
        probe.remote_routes.insert((rd, RouteBinding::Ip(ip)));
        if let Some(ip) = ip {
            let entry = self.ips.entry((vni, ip)).or_insert_with(|| IpProbe {
                mac,
                probe: Probe::default(),
            });
            if entry.mac != mac
                && !matches!(entry.probe.owner, Some(Owner::Remote { .. }))
                && entry.probe.count > 0
                && config.enabled
                && entry.probe.duplicate.is_none()
                && entry.probe.record(&config, now, false)
            {
                warn_detected(vni, &format!("{mac} IP {ip}"), "remote update, from", vtep);
                detected.push(DadKey::Ip(vni, ip));
            }
            entry.mac = mac;
            entry.probe.owner = owner;
            entry
                .probe
                .remote_routes
                .insert((rd, RouteBinding::Mac(mac)));
        }
        (self.verdict(vni, mac, ip), detected)
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
    pub fn remote_gone(&mut self, rd: [u8; 8], vni: u32, mac: MacAddr, ip: Option<IpAddr>) {
        if let Some(probe) = self.macs.get_mut(&(vni, mac)) {
            probe.remote_route_gone((rd, RouteBinding::Ip(ip)));
            if probe.idle() {
                self.macs.remove(&(vni, mac));
            }
        }
        if let Some(ip) = ip
            && let Some(entry) = self.ips.get_mut(&(vni, ip))
        {
            entry.probe.remote_route_gone((rd, RouteBinding::Mac(mac)));
            if entry.probe.idle() {
                self.ips.remove(&(vni, ip));
            }
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
                for ((_, _), entry) in self
                    .ips
                    .range_mut((vni, IpAddr::from([0u8; 4]))..=(vni, IpAddr::from([0xffu8; 16])))
                    .filter(|(_, entry)| entry.mac == mac)
                {
                    entry.probe.clear();
                }
                was
            }
            DadKey::Ip(vni, ip) => {
                let Some(entry) = self.ips.get_mut(&(vni, ip)) else {
                    return false;
                };
                let was = entry.probe.duplicate.is_some();
                entry.probe.clear();
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
    /// deadlines.
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
            return keys;
        }
        if freeze_changed {
            let until = match config.freeze {
                Freeze::For(secs) => Some(now + Duration::from_secs(secs.into())),
                Freeze::Off | Freeze::Permanent => None,
            };
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

/// Arm the recovery timer for a timed freeze: `EvpnDadRecover` arrives at
/// `until`. `until` identifies the freeze, so a wake-up for one that has
/// since been cleared or re-detected is discarded.
pub fn arm_recovery(tx: &mpsc::Sender<Message>, key: DadKey, until: Instant) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            let tx = tx.clone();
            handle.spawn(async move {
                tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
                let _ = tx.send(Message::EvpnDadRecover { key, until }).await;
            });
        }
        Err(_) => tracing::warn!(
            "EVPN duplicate address {key:?}: no runtime to arm the recovery timer; \
             it stays frozen until cleared"
        ),
    }
}

/// Arm the recovery timer of every address in `detected` that a timed
/// freeze holds.
pub fn arm_detected(dad: &EvpnDad, tx: &mpsc::Sender<Message>, detected: &[DadKey]) {
    for key in detected {
        if let Some(until) = dad.until(*key) {
            arm_recovery(tx, *key, until);
        }
    }
}

impl Bgp {
    /// Withdraw this speaker's routes that a freeze now holds: those of
    /// `mac` in `vni`, and those binding `ip` to any MAC. Withdrawn without
    /// re-running the remote routes they competed with — those are held too.
    pub(super) fn evpn_dad_withdraw_held(&mut self, vni: u32, mac: MacAddr, ip: Option<IpAddr>) {
        let held: Vec<FdbEntry> = self
            .local_fdb
            .values()
            .filter(|entry| {
                entry.vni == vni
                    && (entry.mac == mac || ip.is_some_and(|ip| entry.ip == Some(ip)))
                    && self
                        .local_rib
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
    pub fn evpn_dad_clear(
        &mut self,
        vni: Option<u32>,
        mac: Option<MacAddr>,
        ip: Option<IpAddr>,
    ) -> usize {
        let keys = self.local_rib.evpn_dad.detected(vni, mac, ip);
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
        let Some(vni) = args.string() else {
            return;
        };
        let vni = match vni.as_str() {
            "all" => None,
            vni => match vni.parse() {
                Ok(vni) => Some(vni),
                Err(_) => return,
            },
        };
        let (mac, ip) = match filter {
            "" => (None, None),
            "/mac" => match args.string().and_then(|mac| mac.parse().ok()) {
                Some(mac) => (Some(mac), None),
                None => return,
            },
            "/ip" => match args.string().and_then(|ip| ip.parse().ok()) {
                Some(ip) => (None, Some(ip)),
                None => return,
            },
            _ => return,
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
            arm_detected(&self.local_rib.evpn_dad, &self.tx, &keys);
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
        let mut local = Vec::new();
        if !matches!(owner, Some(Owner::Remote { .. })) {
            local = self
                .local_fdb
                .values()
                .filter(|entry| {
                    entry.vni == vni
                        && match key {
                            DadKey::Mac(_, mac) => entry.mac == mac,
                            DadKey::Ip(_, ip) => entry.ip == Some(ip),
                        }
                })
                .cloned()
                .collect();
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
        self.evpn_dad_drain();
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

    /// One remote takeover followed by one local learn, `secs` after `t`.
    fn flap(dad: &mut EvpnDad, t: Instant, secs: u64) -> Vec<DadKey> {
        let now = t + Duration::from_secs(secs);
        let (_, mut keys) = dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, now);
        keys.extend(dad.local_learn(VNI, mac(1), None, now).1);
        keys
    }

    /// A first local learn, or one after the remote route went, is not a
    /// move; refreshes of a local MAC are not moves either.
    #[test]
    fn only_a_learn_of_a_remote_mac_is_a_move() {
        let mut dad = dad(2, Freeze::Off);
        let t = Instant::now();
        dad.local_learn(VNI, mac(1), None, t);
        dad.local_learn(VNI, mac(1), None, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
        // A remote route outside any window counts nothing.
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
        dad.remote_gone(RD, VNI, mac(1), None);
        dad.local_learn(VNI, mac(1), None, t);
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
    }

    /// FRR counts a local learn of a remote MAC, then a remote takeover
    /// while that window is open; `max-moves` within the window detects.
    #[test]
    fn max_moves_within_the_window_detects() {
        let mut dad = dad(5, Freeze::Off);
        let t = Instant::now();
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
        assert!(dad.local_learn(VNI, mac(1), None, t).1.is_empty()); // 1
        assert!(flap(&mut dad, t, 10).is_empty()); // 2, 3
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 3);
        // The fourth move, a takeover, does not yet; the fifth, local, does.
        let now = t + Duration::from_secs(20);
        let (verdict, keys) = dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, now);
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
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
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
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
        dad.local_learn(VNI, mac(1), None, t); // 1
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t); // 2: detected
        assert!(dad.mac_duplicate(VNI, mac(1)));

        let mut dad = super::EvpnDad {
            config: dad.config,
            ..Default::default()
        };
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
        dad.local_learn(VNI, mac(1), None, t); // 1
        dad.remote_takeover(
            RD,
            VNI,
            mac(1),
            None,
            VTEP,
            true,
            t + Duration::from_secs(1),
        ); // 2
        dad.release(DadKey::Mac(VNI, mac(1)));
        // Sticky remote owner: the local learn is not counted.
        assert!(dad.local_learn(VNI, mac(1), None, t).1.is_empty());
        assert_eq!(dad.macs[&(VNI, mac(1))].count, 0);
        // Another VTEP taking over from a remote owner is not a move.
        let other = Some(IpAddr::from([10, 0, 0, 12]));
        dad.remote_takeover(RD, VNI, mac(2), None, VTEP, false, t);
        dad.local_learn(VNI, mac(2), None, t); // 1
        dad.remote_takeover(RD, VNI, mac(2), None, VTEP, false, t); // 2
        dad.release(DadKey::Mac(VNI, mac(2)));
        dad.remote_takeover(RD, VNI, mac(2), None, other, false, t);
        assert_eq!(dad.macs[&(VNI, mac(2))].count, 0);
    }

    /// Under freeze a duplicate is held, and its IPs with it; a timed
    /// freeze carries the recovery deadline; release lifts both.
    #[test]
    fn freeze_holds_the_mac_and_its_ips_until_released() {
        let mut dad = dad(2, Freeze::For(60));
        let t = Instant::now();
        dad.local_learn(VNI, mac(1), Some(ip(5)), t);
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
        dad.local_learn(VNI, mac(1), None, t); // 1
        let (verdict, keys) = dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t); // 2
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
        dad.remote_takeover(RD, VNI, mac(1), Some(ip(5)), VTEP, false, t);
        // The IP appears here on another MAC: one move.
        dad.local_learn(VNI, mac(2), Some(ip(5)), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 1);
        // Back behind the peer on the first MAC: two, detected.
        let (verdict, keys) = dad.remote_takeover(RD, VNI, mac(1), Some(ip(5)), VTEP, false, t);
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
        dad.remote_takeover(RD, VNI, mac(1), Some(ip(5)), VTEP, false, t);
        dad.local_learn(VNI, mac(1), Some(ip(5)), t);
        assert_eq!(dad.ips[&(VNI, ip(5))].probe.count, 0);
    }

    /// `clear` names detected addresses by VNI, MAC or IP.
    #[test]
    fn detected_filters_by_vni_mac_and_ip() {
        let mut dad = dad(1, Freeze::Off);
        let t = Instant::now();
        for (vni, m) in [(100, mac(1)), (200, mac(2))] {
            dad.remote_takeover(RD, vni, m, None, VTEP, false, t);
            dad.local_learn(vni, m, None, t);
        }
        dad.remote_takeover(RD, 100, mac(3), Some(ip(5)), VTEP, false, t);
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
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
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
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
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
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
        dad.local_learn(VNI, mac(1), None, t);
        dad.remote_takeover(RD, VNI, mac(1), None, VTEP, false, t);
        dad.remote_takeover(RD, VNI, mac(2), Some(ip(5)), VTEP, false, t);
        dad.local_learn(VNI, mac(3), Some(ip(5)), t);
        dad.remote_takeover(RD, VNI, mac(2), Some(ip(5)), VTEP, false, t);
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
