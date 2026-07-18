//! The Tree Information Base: (S,G) entries combining upstream
//! Join/Prune state, downstream per-interface state, local (IGMP)
//! membership, and the installed-MFC shadow. `tib_update` is the
//! single reconvergence point: every input event mutates one facet
//! and calls it; it re-evaluates the RFC 7761 predicates
//! (`super::macros`) and diffs the result against the running
//! upstream state and the kernel MFC.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::inst::Pim;
use super::macros::{join_desired, mfc_oifs};
use super::mroute::{Upcall, UpcallKind};
use super::rpf::RpfState;

/// Join/Prune holdtime we advertise and the downstream expiry we run
/// (3.5 × the 60 s J/P period).
pub const JP_HOLDTIME: u16 = 210;

/// (S,G) keepalive for traffic-created (NOCACHE) state without
/// receivers.
pub const KEEPALIVE_PERIOD: Duration = Duration::from_secs(210);

/// Prune-pending delay on a LAN with other neighbors: propagation
/// delay (500 ms) + override interval (2500 ms).
pub const PRUNE_PENDING_DELAY: Duration = Duration::from_millis(3000);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sg {
    pub src: Ipv4Addr,
    pub grp: Ipv4Addr,
}

impl fmt::Display for Sg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.src, self.grp)
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
    /// Expiry Timer (ET): holdtime from the last Join.
    pub expires: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledMfc {
    pub iif: u16,
    pub oifs: Vec<u16>,
}

pub struct TibEntry {
    pub sg: Sg,
    pub join_state: JoinState,
    /// RPF snapshot this entry currently operates on; refreshed by
    /// `tib_rpf_change` so a change can prune the old upstream first.
    pub rpf: RpfState,
    /// Interfaces with local IGMP (S,G) membership.
    pub local: BTreeSet<u32>,
    /// Downstream per-interface Join/Prune state, keyed by ifindex.
    pub downstream: BTreeMap<u32, Downstream>,
    /// Kernel MFC shadow — `Some` while installed.
    pub installed: Option<InstalledMfc>,
    /// Keepalive deadline for traffic-created state (NOCACHE); the
    /// entry survives without receivers until this passes.
    pub stream_expires: Option<Instant>,
    pub uptime: Instant,
}

impl TibEntry {
    pub fn new(sg: Sg) -> Self {
        Self {
            sg,
            join_state: JoinState::NotJoined,
            rpf: RpfState::Unresolved,
            local: BTreeSet::new(),
            downstream: BTreeMap::new(),
            installed: None,
            stream_expires: None,
            uptime: Instant::now(),
        }
    }
}

impl Pim {
    fn tib_get_or_create(&mut self, sg: Sg) -> &mut TibEntry {
        if !self.tib.contains_key(&sg) {
            let rpf = self.rpf_acquire(sg.src);
            let mut entry = TibEntry::new(sg);
            entry.rpf = rpf;
            self.tib.insert(sg, entry);
            tracing::info!("pim: {} created", sg);
        }
        self.tib.get_mut(&sg).unwrap()
    }

    // ---- TIB bridge (IGMP membership → PIM state) ----

    pub(crate) fn tib_local_join(&mut self, sg: Sg, ifindex: u32) {
        self.tib_get_or_create(sg).local.insert(ifindex);
        self.tib_update(sg);
    }

    pub(crate) fn tib_local_prune(&mut self, sg: Sg, ifindex: u32) {
        if let Some(entry) = self.tib.get_mut(&sg) {
            entry.local.remove(&ifindex);
            self.tib_update(sg);
        }
    }

    // ---- downstream Join/Prune RX (per-interface FSM) ----

    pub(crate) fn downstream_join(&mut self, ifindex: u32, sg: Sg, holdtime: u16) {
        let now = Instant::now();
        let entry = self.tib_get_or_create(sg);
        entry.downstream.insert(
            ifindex,
            Downstream {
                state: DsState::Join,
                expires: now + Duration::from_secs(holdtime as u64),
            },
        );
        self.tib_update(sg);
    }

    pub(crate) fn downstream_prune(&mut self, ifindex: u32, sg: Sg) {
        let Some(entry) = self.tib.get_mut(&sg) else {
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
        // it; on a point-to-point-ish link (no other neighbors would
        // override their own prune) act on the next tick.
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

    // ---- upcalls from the kernel dataplane ----

    pub(crate) fn process_upcall(&mut self, upcall: Upcall) {
        match upcall.kind {
            UpcallKind::Nocache => {
                if !upcall.grp.is_multicast() || upcall.grp.octets()[..3] == [224, 0, 0] {
                    return;
                }
                let sg = Sg {
                    src: upcall.src,
                    grp: upcall.grp,
                };
                let entry = self.tib_get_or_create(sg);
                // Traffic keeps punting until an MFC entry exists;
                // stamp/refresh the keepalive and (re)install — with
                // no receivers this is a "negative" empty-OIL entry
                // that silences the punts until KAT expiry.
                entry.stream_expires = Some(Instant::now() + KEEPALIVE_PERIOD);
                self.tib_update(sg);
            }
            UpcallKind::WrongVif | UpcallKind::WrVifWhole => {
                // Assert machinery arrives in a later phase.
                tracing::debug!(
                    "pim: wrong-vif upcall for ({}, {}) on vif {} (assert not yet implemented)",
                    upcall.src,
                    upcall.grp,
                    upcall.vif
                );
            }
            UpcallKind::WholePkt => {
                tracing::debug!(
                    "pim: wholepkt upcall for ({}, {}) (register not yet implemented)",
                    upcall.src,
                    upcall.grp
                );
            }
        }
    }

    // ---- RPF change propagation ----

    pub(crate) fn tib_rpf_change(&mut self, sg: Sg, state: RpfState) {
        let Some(entry) = self.tib.get_mut(&sg) else {
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
            self.jp_send_single(ifindex, nexthop, sg, false);
        }
        if let Some(entry) = self.tib.get_mut(&sg) {
            entry.rpf = state;
        }
        tracing::info!("pim: {} RPF change {:?} -> {:?}", sg, old, state);
        self.tib_update(sg);
    }

    // ---- neighbor hooks ----

    /// A new PIM neighbor appeared: entries parked for lack of an
    /// upstream neighbor on that (interface, address) can join now.
    pub(crate) fn tib_neighbor_up(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let sgs: Vec<Sg> = self
            .tib
            .iter()
            .filter(|(_, e)| {
                e.join_state == JoinState::NotJoined
                    && e.rpf
                        == RpfState::Gateway {
                            ifindex,
                            nexthop: addr,
                        }
            })
            .map(|(sg, _)| *sg)
            .collect();
        for sg in sgs {
            self.tib_update(sg);
        }
    }

    /// A PIM neighbor vanished: entries joined through it fall back
    /// to NotJoined (no prune TX — the peer is gone).
    pub(crate) fn tib_neighbor_down(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let sgs: Vec<Sg> = self
            .tib
            .iter()
            .filter(|(_, e)| {
                e.rpf
                    == RpfState::Gateway {
                        ifindex,
                        nexthop: addr,
                    }
            })
            .map(|(sg, _)| *sg)
            .collect();
        for sg in sgs {
            if let Some(entry) = self.tib.get_mut(&sg) {
                entry.join_state = JoinState::NotJoined;
            }
            self.tib_update(sg);
        }
    }

    /// PIM stopped on an interface: drop every per-interface facet
    /// that references it.
    pub(crate) fn tib_iface_purge(&mut self, ifindex: u32) {
        let sgs: Vec<Sg> = self.tib.keys().copied().collect();
        for sg in sgs {
            if let Some(entry) = self.tib.get_mut(&sg) {
                let touched = entry.local.remove(&ifindex)
                    | entry.downstream.remove(&ifindex).is_some()
                    | (entry.rpf.ifindex() == Some(ifindex));
                if touched {
                    self.tib_update(sg);
                }
            }
        }
    }

    // ---- the reconvergence point ----

    /// Re-evaluate one entry end-to-end: lifetime, upstream
    /// Join/Prune state, kernel MFC. Every mutation path funnels
    /// through here.
    pub(crate) fn tib_update(&mut self, sg: Sg) {
        let Some(entry) = self.tib.get(&sg) else {
            return;
        };

        // Lifetime: no receivers, no live traffic keepalive → delete.
        let now = Instant::now();
        let stream_alive = entry.stream_expires.map(|t| t > now).unwrap_or(false);
        if entry.local.is_empty() && entry.downstream.is_empty() && !stream_alive {
            let was = entry.join_state;
            let rpf = entry.rpf;
            let installed = entry.installed.is_some();
            if installed {
                self.fp.mfc_del(sg.src, sg.grp);
            }
            if was == JoinState::Joined
                && let RpfState::Gateway { ifindex, nexthop } = rpf
            {
                self.jp_send_single(ifindex, nexthop, sg, false);
            }
            self.tib.remove(&sg);
            self.rpf_release(sg.src);
            tracing::info!("pim: {} deleted", sg);
            return;
        }

        // Upstream FSM: Joined iff JoinDesired and the RPF gateway is
        // a live PIM neighbor. Connected sources need no Join.
        let entry = self.tib.get(&sg).unwrap();
        let jd = join_desired(entry);
        let upstream_nbr = match entry.rpf {
            RpfState::Gateway { ifindex, nexthop } => self
                .links
                .get(&ifindex)
                .filter(|l| l.enabled && l.nbrs.contains_key(&nexthop))
                .map(|_| (ifindex, nexthop)),
            _ => None,
        };
        let want_joined = jd && upstream_nbr.is_some();
        let is_joined = entry.join_state == JoinState::Joined;
        if want_joined && !is_joined {
            let (ifindex, nexthop) = upstream_nbr.unwrap();
            self.tib.get_mut(&sg).unwrap().join_state = JoinState::Joined;
            self.jp_send_single(ifindex, nexthop, sg, true);
            self.jp_refresh_arm(ifindex, nexthop);
            tracing::info!("pim: {} joined toward {}", sg, nexthop);
        } else if !want_joined && is_joined {
            self.tib.get_mut(&sg).unwrap().join_state = JoinState::NotJoined;
            if let Some((ifindex, nexthop)) = upstream_nbr {
                self.jp_send_single(ifindex, nexthop, sg, false);
                tracing::info!("pim: {} pruned toward {}", sg, nexthop);
            }
        }

        // Kernel MFC: (iif, oifs) from the current predicates; install
        // when the IIF resolves and there is either an OIF or live
        // traffic state (negative cache), else uninstall.
        let entry = self.tib.get(&sg).unwrap();
        let iif_vif = entry.rpf.ifindex().and_then(|ifindex| self.fp.vif(ifindex));
        let desired = match iif_vif {
            Some(iif) => {
                let oifs: Vec<u16> = mfc_oifs(entry, entry.rpf.ifindex())
                    .iter()
                    .filter_map(|ifindex| self.fp.vif(*ifindex))
                    .collect();
                if !oifs.is_empty() || stream_alive {
                    Some(InstalledMfc { iif, oifs })
                } else {
                    None
                }
            }
            None => None,
        };
        if entry.installed != desired {
            match &desired {
                Some(mfc) => self.fp.mfc_add(sg.src, sg.grp, mfc.iif, &mfc.oifs),
                None => self.fp.mfc_del(sg.src, sg.grp),
            }
            self.tib.get_mut(&sg).unwrap().installed = desired;
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
            for ds in entry.downstream.values() {
                consider(ds.expires);
                if let DsState::PrunePending { until } = ds.state {
                    consider(until);
                }
            }
        }
        for t in self.jp_refresh.values() {
            consider(*t);
        }
        earliest
    }

    pub(crate) fn tib_tick(&mut self, now: Instant) {
        let mut touched: Vec<Sg> = vec![];
        for (sg, entry) in self.tib.iter_mut() {
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
                touched.push(*sg);
            }
        }
        for sg in touched {
            self.tib_update(sg);
        }
        self.jp_tick(now);
    }
}
