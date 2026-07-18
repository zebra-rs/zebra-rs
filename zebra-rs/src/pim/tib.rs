//! The Tree Information Base: (*,G), (S,G) and (S,G,rpt) entries in
//! one table with typed keys (the ZebOS unified-TIB shape). Each
//! entry combines upstream Join/Prune state, downstream
//! per-interface state, local (IGMP) membership, register state and
//! the installed-MFC shadow. `tib_update` is the single
//! reconvergence point: every input event mutates one facet and
//! calls it; it re-evaluates the RFC 7761 predicates
//! (`super::macros`) and diffs the result against the running
//! upstream state and the kernel MFC.
//!
//! Kernel note: no (*,G) MFC entries are installed — shared-tree
//! traffic is handled by NOCACHE-created (S,G) entries whose OIL is
//! the *inherited* olist, so every active source gets its own MFC
//! row. This sidesteps the kernel's (*,G) IIF∈OIF quirk entirely.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::assert_fsm::AssertState;
use super::inst::Pim;
use super::macros::{inherited_effective, inherited_olist, join_desired_effective, mfc_oifs};
use super::mroute::{REG_VIF, Upcall, UpcallKind};
use super::rpf::RpfState;

/// Join/Prune holdtime we advertise and the downstream expiry we run
/// (3.5 × the 60 s J/P period).
pub const JP_HOLDTIME: u16 = 210;

/// (S,G) keepalive for traffic-created (NOCACHE / register) state.
pub const KEEPALIVE_PERIOD: Duration = Duration::from_secs(210);

/// Prune-pending delay on a LAN with other neighbors: propagation
/// delay (500 ms) + override interval (2500 ms).
pub const PRUNE_PENDING_DELAY: Duration = Duration::from_millis(3000);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SgKey {
    /// Shared-tree state rooted at RP(G).
    StarG { grp: Ipv4Addr },
    /// Source-tree state.
    Sg { src: Ipv4Addr, grp: Ipv4Addr },
    /// Source pruned off the shared tree (downstream prune records;
    /// the upstream side rides the (*,G) refresh).
    SgRpt { src: Ipv4Addr, grp: Ipv4Addr },
}

impl SgKey {
    pub fn grp(&self) -> Ipv4Addr {
        match self {
            SgKey::StarG { grp } | SgKey::Sg { grp, .. } | SgKey::SgRpt { grp, .. } => *grp,
        }
    }
}

impl fmt::Display for SgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SgKey::StarG { grp } => write!(f, "(*, {})", grp),
            SgKey::Sg { src, grp } => write!(f, "({}, {})", src, grp),
            SgKey::SgRpt { src, grp } => write!(f, "({}, {}, rpt)", src, grp),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinState {
    NotJoined,
    Joined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsState {
    Join,
    PrunePending { until: Instant },
}

#[derive(Debug, Clone, Copy)]
pub struct Downstream {
    pub state: DsState,
    /// Expiry Timer (ET): holdtime from the last Join (for SgRpt
    /// entries: from the last rpt-Prune).
    pub expires: Instant,
}

/// DR-side register FSM per (S,G) (RFC 7761 §4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegState {
    NoInfo,
    /// Registering: the register VIF sits in the OIL, WHOLEPKT punts
    /// become unicast Registers to the RP.
    Join,
    /// Register-Stop received: suppressed until `until`.
    Prune {
        until: Instant,
    },
    /// Suppression about to lapse: Null-Register sent, waiting out
    /// the probe window.
    JoinPending {
        until: Instant,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledMfc {
    pub iif: u16,
    pub oifs: Vec<u16>,
}

pub struct TibEntry {
    pub join_state: JoinState,
    /// RPF snapshot this entry currently operates on; refreshed by
    /// `tib_rpf_change` so a change can prune the old upstream first.
    pub rpf: RpfState,
    /// Address the RPF tracking follows: the source for (S,G), RP(G)
    /// for (*,G). `None` for (S,G,rpt) (no upstream of its own) and
    /// for (*,G) without a known RP.
    pub rpf_target: Option<Ipv4Addr>,
    /// Interfaces with local IGMP membership ((S,G) INCLUDE sources
    /// on Sg entries; EXCLUDE/any-source membership on StarG).
    pub local: BTreeSet<u32>,
    /// Downstream per-interface state, keyed by ifindex. On SgRpt
    /// entries presence means "rpt-pruned on this interface".
    pub downstream: BTreeMap<u32, Downstream>,
    /// Assert election state per contested interface (Sg entries).
    pub asserts: BTreeMap<u32, AssertState>,
    /// Kernel MFC shadow — `Some` while installed (Sg entries only).
    pub installed: Option<InstalledMfc>,
    /// Keepalive deadline for traffic-created state (NOCACHE at any
    /// router, Register/Null-Register RX at the RP).
    pub stream_expires: Option<Instant>,
    /// Register FSM (Sg at the DR only).
    pub reg_state: RegState,
    /// SPT bit: native traffic has been seen on the source tree —
    /// arms the (S,G,rpt) prune toward the RP.
    pub spt_bit: bool,
    pub uptime: Instant,
}

impl TibEntry {
    pub fn new() -> Self {
        Self {
            join_state: JoinState::NotJoined,
            rpf: RpfState::Unresolved,
            rpf_target: None,
            local: BTreeSet::new(),
            downstream: BTreeMap::new(),
            asserts: BTreeMap::new(),
            installed: None,
            stream_expires: None,
            reg_state: RegState::NoInfo,
            spt_bit: false,
            uptime: Instant::now(),
        }
    }
}

impl Default for TibEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl Pim {
    pub(crate) fn tib_get_or_create(&mut self, key: SgKey) -> &mut TibEntry {
        if !self.tib.contains_key(&key) {
            let target = match key {
                SgKey::Sg { src, .. } => Some(src),
                SgKey::StarG { grp } => self.rp_lookup(grp),
                SgKey::SgRpt { .. } => None,
            };
            let mut entry = TibEntry::new();
            entry.rpf_target = target;
            if let Some(addr) = target {
                entry.rpf = self.rpf_acquire(addr);
            }
            self.tib.insert(key, entry);
            tracing::info!("pim: {} created", key);
        }
        self.tib.get_mut(&key).unwrap()
    }

    // ---- TIB bridge (IGMP membership → PIM state) ----

    pub(crate) fn tib_local_join(&mut self, key: SgKey, ifindex: u32) {
        self.tib_get_or_create(key).local.insert(ifindex);
        self.tib_update(key);
    }

    pub(crate) fn tib_local_prune(&mut self, key: SgKey, ifindex: u32) {
        if let Some(entry) = self.tib.get_mut(&key) {
            entry.local.remove(&ifindex);
            self.tib_update(key);
        }
    }

    // ---- downstream Join/Prune RX (per-interface FSM) ----

    pub(crate) fn downstream_join(&mut self, ifindex: u32, key: SgKey, holdtime: u16) {
        let now = Instant::now();
        let entry = self.tib_get_or_create(key);
        entry.downstream.insert(
            ifindex,
            Downstream {
                state: DsState::Join,
                expires: now + Duration::from_secs(holdtime as u64),
            },
        );
        self.tib_update(key);
    }

    pub(crate) fn downstream_prune(&mut self, ifindex: u32, key: SgKey) {
        let Some(entry) = self.tib.get_mut(&key) else {
            return;
        };
        let Some(ds) = entry.downstream.get_mut(&ifindex) else {
            return;
        };
        if !matches!(ds.state, DsState::Join) {
            return;
        }
        // With other PIM routers on the LAN, hold the prune open for
        // the override window so another receiver's Join can cancel
        // it; point-to-point acts on the next tick.
        let others = self
            .links
            .get(&ifindex)
            .map(|l| l.nbrs.len() > 1)
            .unwrap_or(false);
        let until = if others {
            Instant::now() + PRUNE_PENDING_DELAY
        } else {
            Instant::now()
        };
        ds.state = DsState::PrunePending { until };
        // Forwarding is unchanged until the timer fires (tick).
    }

    /// (S,G,rpt) prune RX: record the pruned interface on the SgRpt
    /// entry — it drops out of the (S,G) inherited olist.
    pub(crate) fn downstream_rpt_prune(&mut self, ifindex: u32, key: SgKey, holdtime: u16) {
        let now = Instant::now();
        let entry = self.tib_get_or_create(key);
        entry.downstream.insert(
            ifindex,
            Downstream {
                state: DsState::Join,
                expires: now + Duration::from_secs(holdtime as u64),
            },
        );
        self.tib_update(key);
    }

    /// (S,G,rpt) join RX cancels a recorded prune.
    pub(crate) fn downstream_rpt_join(&mut self, ifindex: u32, key: SgKey) {
        if let Some(entry) = self.tib.get_mut(&key) {
            entry.downstream.remove(&ifindex);
            self.tib_update(key);
        }
    }

    // ---- upcalls from the kernel dataplane ----

    pub(crate) fn process_upcall(&mut self, upcall: Upcall) {
        match upcall.kind {
            UpcallKind::Nocache => {
                if !upcall.grp.is_multicast() || upcall.grp.octets()[..3] == [224, 0, 0] {
                    return;
                }
                let key = SgKey::Sg {
                    src: upcall.src,
                    grp: upcall.grp,
                };
                let entry = self.tib_get_or_create(key);
                // Traffic keeps punting until an MFC entry exists;
                // stamp/refresh the keepalive and (re)install — with
                // no receivers this is a "negative" empty-OIL entry
                // that silences the punts until KAT expiry.
                entry.stream_expires = Some(Instant::now() + KEEPALIVE_PERIOD);
                // First-hop router duty: register toward the RP when
                // we are the DR for the directly-connected source.
                self.register_check_fhr(key, upcall.vif);
                self.tib_update(key);
            }
            UpcallKind::WrongVif | UpcallKind::WrVifWhole => {
                // Data on a non-IIF interface. On an interface we
                // forward to, another forwarder exists on that LAN —
                // run the assert election. Anywhere else it is the
                // SPT-bit signal: the shared-tree copy still arriving
                // proves the source tree is live, so the (S,G,rpt)
                // prune can go out.
                let key = SgKey::Sg {
                    src: upcall.src,
                    grp: upcall.grp,
                };
                let arrival = self.fp.ifindex_of(upcall.vif);
                let contested = arrival
                    .map(|ifindex| mfc_oifs(&self.tib, key).contains(&ifindex))
                    .unwrap_or(false);
                if contested {
                    self.assert_data_trigger(key, arrival.unwrap());
                } else {
                    self.spt_bit_set(key);
                }
            }
            UpcallKind::WholePkt => {
                self.register_wholepkt(upcall);
            }
        }
    }

    // ---- RPF change propagation ----

    pub(crate) fn tib_rpf_change(&mut self, key: SgKey, state: RpfState) {
        let Some(entry) = self.tib.get_mut(&key) else {
            return;
        };
        let old = entry.rpf;
        if old == state {
            return;
        }
        // Prune off the old upstream before adopting the new path.
        if entry.join_state == JoinState::Joined
            && let RpfState::Gateway { ifindex, nexthop } = old
        {
            entry.join_state = JoinState::NotJoined;
            self.jp_send_entry(ifindex, nexthop, key, false);
        }
        if let Some(entry) = self.tib.get_mut(&key) {
            entry.rpf = state;
        }
        tracing::info!("pim: {} RPF change {:?} -> {:?}", key, old, state);
        self.tib_update(key);
    }

    /// Re-point an entry at a different RPF target (RP mapping
    /// changed for a (*,G)).
    pub(crate) fn tib_retarget(&mut self, key: SgKey, target: Option<Ipv4Addr>) {
        let Some(entry) = self.tib.get(&key) else {
            return;
        };
        let old_target = entry.rpf_target;
        if old_target == target {
            return;
        }
        // Leave the old tree.
        if entry.join_state == JoinState::Joined
            && let RpfState::Gateway { ifindex, nexthop } = entry.rpf
        {
            self.jp_send_entry(ifindex, nexthop, key, false);
        }
        let new_rpf = match target {
            Some(addr) => self.rpf_acquire(addr),
            None => RpfState::Unresolved,
        };
        if let Some(old) = old_target {
            self.rpf_release(old);
        }
        let entry = self.tib.get_mut(&key).unwrap();
        entry.join_state = JoinState::NotJoined;
        entry.rpf_target = target;
        entry.rpf = new_rpf;
        tracing::info!("pim: {} re-targeted to {:?}", key, target);
        self.tib_update(key);
    }

    // ---- neighbor hooks ----

    /// Every gateway entry whose RPF interface is `ifindex`. A
    /// neighbor change may make or break coverage of a gateway
    /// nexthop (which can be the neighbor's hello source *or* a
    /// secondary address), so re-evaluate the whole set and let
    /// `tib_update`'s coverage check decide join/prune.
    fn gateway_keys_on(&self, ifindex: u32) -> Vec<SgKey> {
        self.tib
            .iter()
            .filter(|(_, e)| matches!(e.rpf, RpfState::Gateway { ifindex: i, .. } if i == ifindex))
            .map(|(key, _)| *key)
            .collect()
    }

    /// A new PIM neighbor appeared: entries parked for lack of an
    /// upstream neighbor on this interface may now join.
    pub(crate) fn tib_neighbor_up(&mut self, ifindex: u32, _addr: Ipv4Addr) {
        for key in self.gateway_keys_on(ifindex) {
            self.tib_update(key);
        }
    }

    /// A PIM neighbor vanished (already removed from the link's
    /// table): entries joined through it lose coverage in
    /// `tib_update` and fall back to NotJoined with no prune TX.
    pub(crate) fn tib_neighbor_down(&mut self, ifindex: u32, _addr: Ipv4Addr) {
        for key in self.gateway_keys_on(ifindex) {
            self.tib_update(key);
        }
    }

    /// RFC 7761 §4.3.1: a neighbor's Generation-ID changed, so it
    /// restarted and lost its downstream Join state. Re-send a Join
    /// (toward the entry's actual RPF nexthop, which the restarted
    /// neighbor owns) for every entry joined through that neighbor,
    /// so its tree is rebuilt without waiting a full refresh period.
    pub(crate) fn tib_genid_resync(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let targets: Vec<(SgKey, Ipv4Addr)> = self
            .tib
            .iter()
            .filter_map(|(key, e)| match e.rpf {
                RpfState::Gateway {
                    ifindex: i,
                    nexthop,
                } if i == ifindex
                    && e.join_state == JoinState::Joined
                    && (nexthop == addr
                        || self
                            .links
                            .get(&ifindex)
                            .map(|l| l.neighbor_covers(&nexthop))
                            .unwrap_or(false)) =>
                {
                    Some((*key, nexthop))
                }
                _ => None,
            })
            .collect();
        for (key, nexthop) in targets {
            self.jp_send_entry(ifindex, nexthop, key, true);
        }
    }

    /// PIM stopped on an interface: drop every per-interface facet
    /// that references it.
    pub(crate) fn tib_iface_purge(&mut self, ifindex: u32) {
        let keys: Vec<SgKey> = self.tib.keys().copied().collect();
        for key in keys {
            if let Some(entry) = self.tib.get_mut(&key) {
                let touched = entry.local.remove(&ifindex)
                    | entry.downstream.remove(&ifindex).is_some()
                    | entry.asserts.remove(&ifindex).is_some()
                    | (entry.rpf.ifindex() == Some(ifindex));
                if touched {
                    self.tib_update(key);
                }
            }
        }
    }

    // ---- the reconvergence point ----

    /// Re-evaluate one entry end-to-end: lifetime, upstream
    /// Join/Prune state, kernel MFC. (*,G)/(S,G,rpt) changes cascade
    /// into the same-group (S,G) entries whose inherited olist they
    /// feed.
    pub(crate) fn tib_update(&mut self, key: SgKey) {
        let Some(entry) = self.tib.get(&key) else {
            return;
        };

        // Lifetime: nothing local, nothing downstream, no live
        // traffic keepalive, register idle → delete.
        let now = Instant::now();
        let stream_alive = entry.stream_expires.map(|t| t > now).unwrap_or(false);
        if entry.local.is_empty()
            && entry.downstream.is_empty()
            && !stream_alive
            && entry.reg_state == RegState::NoInfo
        {
            let was = entry.join_state;
            let rpf = entry.rpf;
            let target = entry.rpf_target;
            if entry.installed.is_some()
                && let SgKey::Sg { src, grp } = key
            {
                self.fp.mfc_del(src, grp);
            }
            if was == JoinState::Joined
                && let RpfState::Gateway { ifindex, nexthop } = rpf
            {
                self.jp_send_entry(ifindex, nexthop, key, false);
            }
            self.tib.remove(&key);
            if let Some(addr) = target {
                self.rpf_release(addr);
            }
            tracing::info!("pim: {} deleted", key);
            self.tib_cascade(key);
            return;
        }

        // Upstream FSM. JoinDesired:
        //   (*,G): immediate olist non-empty, RP known, not the RP.
        //   (S,G): immediate non-empty, or KAT running with a
        //          non-empty inherited olist (the RP / LHR SPT-join
        //          clause).
        // Sending additionally requires a live PIM gateway neighbor.
        // Interfaces that fell out of the raw olist no longer host a
        // contest (CouldAssert false) — drop their assert state.
        {
            let raw = inherited_olist(&self.tib, key);
            let entry = self.tib.get_mut(&key).unwrap();
            entry.asserts.retain(|ifindex, _| raw.contains(ifindex));
        }

        let jd = match key {
            SgKey::StarG { grp } => join_desired_effective(&self.tib, key) && !self.i_am_rp(grp),
            SgKey::Sg { .. } => {
                join_desired_effective(&self.tib, key)
                    || (stream_alive && !inherited_effective(&self.tib, key).is_empty())
            }
            SgKey::SgRpt { .. } => false,
        };
        let entry = self.tib.get(&key).unwrap();
        let upstream_nbr = match entry.rpf {
            RpfState::Gateway { ifindex, nexthop } => self
                .links
                .get(&ifindex)
                .filter(|l| l.enabled && l.neighbor_covers(&nexthop))
                .map(|_| (ifindex, nexthop)),
            _ => None,
        };
        let want_joined = jd && upstream_nbr.is_some();
        let is_joined = entry.join_state == JoinState::Joined;
        if want_joined && !is_joined {
            let (ifindex, nexthop) = upstream_nbr.unwrap();
            self.tib.get_mut(&key).unwrap().join_state = JoinState::Joined;
            self.jp_send_entry(ifindex, nexthop, key, true);
            self.jp_refresh_arm(ifindex, nexthop);
            tracing::info!("pim: {} joined toward {}", key, nexthop);
        } else if !want_joined && is_joined {
            self.tib.get_mut(&key).unwrap().join_state = JoinState::NotJoined;
            if let Some((ifindex, nexthop)) = upstream_nbr {
                self.jp_send_entry(ifindex, nexthop, key, false);
                tracing::info!("pim: {} pruned toward {}", key, nexthop);
            }
        }

        // Kernel MFC — (S,G) entries only. OIL = inherited olist
        // (immediate + shared-tree minus rpt-pruned) minus IIF, plus
        // the register VIF while actively registering.
        if let SgKey::Sg { src, grp } = key {
            let entry = self.tib.get(&key).unwrap();
            let iif_vif = entry.rpf.ifindex().and_then(|ifindex| self.fp.vif(ifindex));
            let registering = entry.reg_state == RegState::Join;
            let desired = match iif_vif {
                Some(iif) => {
                    let mut oifs: Vec<u16> = mfc_oifs(&self.tib, key)
                        .iter()
                        .filter_map(|ifindex| self.fp.vif(*ifindex))
                        .collect();
                    if registering {
                        oifs.push(REG_VIF);
                    }
                    if !oifs.is_empty() || stream_alive {
                        Some(InstalledMfc { iif, oifs })
                    } else {
                        None
                    }
                }
                None => None,
            };
            let entry = self.tib.get(&key).unwrap();
            if entry.installed != desired {
                match &desired {
                    Some(mfc) => self.fp.mfc_add(src, grp, mfc.iif, &mfc.oifs),
                    None => self.fp.mfc_del(src, grp),
                }
                self.tib.get_mut(&key).unwrap().installed = desired;
            }
        } else {
            self.tib_cascade(key);
        }
    }

    /// A (*,G) or (S,G,rpt) change feeds the inherited olists of the
    /// same-group (S,G) entries — re-evaluate them.
    fn tib_cascade(&mut self, key: SgKey) {
        if matches!(key, SgKey::Sg { .. }) {
            return;
        }
        let grp = key.grp();
        let sgs: Vec<SgKey> = self
            .tib
            .keys()
            .filter(|k| matches!(k, SgKey::Sg { .. }) && k.grp() == grp)
            .copied()
            .collect();
        for sg in sgs {
            self.tib_update(sg);
        }
    }

    /// Native source-tree traffic confirmed for a joined (S,G): mark
    /// the SPT bit and send the triggered (S,G,rpt) prune toward the
    /// shared tree when the paths diverge.
    fn spt_bit_set(&mut self, key: SgKey) {
        let SgKey::Sg { src, grp } = key else {
            return;
        };
        let Some(entry) = self.tib.get_mut(&key) else {
            return;
        };
        if entry.spt_bit || entry.join_state != JoinState::Joined {
            return;
        }
        entry.spt_bit = true;
        let sg_rpf = entry.rpf;
        // The prune goes toward RPF'(*,G) — only when it differs from
        // RPF'(S,G) (same path ⇒ no duplicates to cut).
        let star = SgKey::StarG { grp };
        let Some(star_entry) = self.tib.get(&star) else {
            return;
        };
        if star_entry.rpf == sg_rpf {
            return;
        }
        if let RpfState::Gateway { ifindex, nexthop } = star_entry.rpf {
            tracing::info!(
                "pim: {} SPT bit set — pruning ({}, {}) off the RPT",
                key,
                src,
                grp
            );
            self.jp_send_entry(ifindex, nexthop, SgKey::SgRpt { src, grp }, false);
        }
    }

    // ---- deadline plumbing ----

    pub(crate) fn tib_next_wakeup(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| {
            earliest = Some(earliest.map_or(t, |e| e.min(t)));
        };
        for entry in self.tib.values() {
            if let Some(t) = entry.stream_expires {
                consider(t);
            }
            match entry.reg_state {
                RegState::Prune { until } | RegState::JoinPending { until } => consider(until),
                _ => {}
            }
            for ds in entry.downstream.values() {
                consider(ds.expires);
                if let DsState::PrunePending { until } = ds.state {
                    consider(until);
                }
            }
            for a in entry.asserts.values() {
                consider(a.expires);
            }
        }
        for t in self.jp_refresh.values() {
            consider(*t);
        }
        earliest
    }

    pub(crate) fn tib_tick(&mut self, now: Instant) {
        let mut touched: Vec<SgKey> = vec![];
        for (key, entry) in self.tib.iter_mut() {
            let before = entry.downstream.len();
            entry.downstream.retain(|_, ds| {
                if ds.expires <= now {
                    return false;
                }
                !matches!(ds.state, DsState::PrunePending { until } if until <= now)
            });
            let mut changed = entry.downstream.len() != before;
            if let Some(t) = entry.stream_expires
                && t <= now
            {
                entry.stream_expires = None;
                changed = true;
            }
            if changed {
                touched.push(*key);
            }
        }
        for key in touched {
            self.tib_update(key);
        }
        self.assert_tick(now);
        self.register_tick(now);
        self.jp_tick(now);
    }
}
