//! Per-interface PIM state: desired configuration, runtime state,
//! enable/disable reconciliation and DR election (RFC 7761 §4.3.2).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::{IpNet, Ipv4Net};
use rand::RngExt;

use crate::context::Timer;
use crate::rib::Link;
use crate::rib::link::LinkAddr;

use super::igmp::{IgmpConfig, IgmpIf};
use super::inst::{Message, Pim};
use super::neighbor::Neighbor;
use super::socket::{igmp_join_if, igmp_leave_if, pim_join_if, pim_leave_if};

pub const PIM_HELLO_PERIOD: u16 = 30;
pub const PIM_DEFAULT_DR_PRIORITY: u32 = 1;
pub const PIM_PROPAGATION_DELAY_MSEC: u16 = 500;
pub const PIM_OVERRIDE_INTERVAL_MSEC: u16 = 2500;

/// Desired per-interface configuration, keyed by interface name in
/// [`Pim::if_config`]. Presence of an entry (the interface is listed
/// under `router pim`) is what enables PIM on the interface.
#[derive(Debug, Clone, Default)]
pub struct LinkConfig {
    pub dr_priority: Option<u32>,
    pub hello_interval: Option<u16>,
    pub holdtime: Option<u16>,
    pub passive: Option<bool>,
    pub igmp: IgmpConfig,
}

impl LinkConfig {
    pub fn hello_interval(&self) -> u16 {
        self.hello_interval.unwrap_or(PIM_HELLO_PERIOD)
    }

    /// Advertised holdtime: explicit config, else 3.5 × hello.
    pub fn holdtime(&self) -> u16 {
        self.holdtime
            .unwrap_or_else(|| self.hello_interval().saturating_mul(7) / 2)
    }

    pub fn dr_priority(&self) -> u32 {
        self.dr_priority.unwrap_or(PIM_DEFAULT_DR_PRIORITY)
    }

    pub fn passive(&self) -> bool {
        self.passive.unwrap_or(false)
    }
}

/// Runtime per-interface state, keyed by ifindex in [`Pim::links`].
pub struct PimLink {
    pub ifindex: u32,
    pub name: String,
    pub link_up: bool,
    /// IPv4 addresses on the link; the first is the primary address
    /// used as our Hello source identity and DR candidate.
    pub addrs: Vec<Ipv4Net>,
    /// PIM is running on this interface (group joined, hello timer
    /// armed). Derived state — see [`Pim::reconcile`].
    pub enabled: bool,
    pub gen_id: u32,
    pub dr: Option<Ipv4Addr>,
    pub nbrs: BTreeMap<Ipv4Addr, Neighbor>,
    pub hello_timer: Option<Timer>,
    /// IGMP runtime state — `Some` while IGMP runs on this interface.
    pub igmp: Option<IgmpIf>,
}

impl PimLink {
    pub fn from_link(link: &Link) -> Self {
        let addrs = link
            .addr4
            .iter()
            .filter_map(|a| match a.addr {
                IpNet::V4(v4) => Some(v4),
                IpNet::V6(_) => None,
            })
            .collect();
        Self {
            ifindex: link.index,
            name: link.name.clone(),
            link_up: link.is_up(),
            addrs,
            enabled: false,
            gen_id: 0,
            dr: None,
            nbrs: BTreeMap::new(),
            hello_timer: None,
            igmp: None,
        }
    }

    pub fn primary_addr(&self) -> Option<Ipv4Addr> {
        self.addrs.first().map(|p| p.addr())
    }

    pub fn is_my_addr(&self, addr: &Ipv4Addr) -> bool {
        self.addrs.iter().any(|p| p.addr() == *addr)
    }

    /// Is `addr` a live PIM neighbor on this link — matching either a
    /// neighbor's hello source or one of its advertised secondary
    /// addresses (RFC 7761 §4.3.4)? The RIB's resolved RPF nexthop
    /// may be any address the neighbor owns, not just its hello
    /// source.
    pub fn neighbor_covers(&self, addr: &Ipv4Addr) -> bool {
        self.nbrs.contains_key(addr) || self.nbrs.values().any(|n| n.secondary.contains(addr))
    }
}

fn hello_timer(tx: &tokio::sync::mpsc::UnboundedSender<Message>, ifindex: u32, sec: u16) -> Timer {
    let tx = tx.clone();
    Timer::repeat(sec as u64, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::HelloTimer(ifindex));
        }
    })
}

impl Pim {
    /// Converge one interface's running state onto its desired state.
    /// Called from every input that can change either side: config
    /// set/delete, LinkAdd/Up/Down/Del, AddrAdd/AddrDel. PIM runs on
    /// an interface iff it is listed under `router pim`, the link is
    /// up, and it has an IPv4 address.
    pub(crate) fn reconcile(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let usable = link.link_up && !link.addrs.is_empty();
        let entry = self.if_config.get(&link.name);
        let desired = entry.is_some() && usable;
        let igmp_desired = entry.map(|c| c.igmp.enabled()).unwrap_or(false) && usable;
        let igmp_running = link.igmp.is_some();
        match (desired, link.enabled) {
            (true, false) => self.link_enable(ifindex),
            (false, true) => self.link_disable(ifindex),
            (true, true) => {
                // Config knobs changed on a running interface: re-run
                // the election with the new DR priority and advertise
                // the new values right away.
                self.dr_election(ifindex);
                self.hello_send(ifindex);
            }
            (false, false) => {}
        }
        match (igmp_desired, igmp_running) {
            (true, false) => self.igmp_enable(ifindex),
            (false, true) => self.igmp_disable(ifindex),
            _ => {}
        }
    }

    fn igmp_enable(&mut self, ifindex: u32) {
        igmp_join_if(&self.igmp_sock, ifindex);
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.igmp = Some(IgmpIf::new(std::time::Instant::now()));
        tracing::info!("igmp: interface {} enabled", link.name);
        // The startup general query goes out on the next event-loop
        // pass — IgmpIf::new schedules it at `now`.
    }

    fn igmp_disable(&mut self, ifindex: u32) {
        igmp_leave_if(&self.igmp_sock, ifindex);
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        // Withdraw every local membership this interface fed into
        // the TIB before dropping the state.
        let mut prune: Vec<super::tib::SgKey> = vec![];
        if let Some(igmp) = link.igmp.take() {
            for (grp, group) in igmp.groups {
                for src in group.synced {
                    prune.push(super::tib::SgKey::Sg { src, grp });
                }
                if group.asm_synced {
                    prune.push(super::tib::SgKey::StarG { grp });
                }
            }
        }
        tracing::info!("igmp: interface {} disabled", link.name);
        for key in prune {
            self.tib_local_prune(key, ifindex);
        }
    }

    /// Are we the Designated Router on this interface? (RFC 7761
    /// §4.3.2 — gates first-hop register duty.)
    pub(crate) fn i_am_dr(&self, ifindex: u32) -> bool {
        let Some(link) = self.links.get(&ifindex) else {
            return false;
        };
        match (link.dr, link.primary_addr()) {
            (Some(dr), Some(me)) => dr == me,
            _ => false,
        }
    }

    /// Re-arm a running interface's hello timer after a hello-interval
    /// change; no-op when the interface is not enabled.
    pub(crate) fn rearm_hello_timer(&mut self, name: &str) {
        let Some((ifindex, enabled)) = self
            .links
            .values()
            .find(|l| l.name == name)
            .map(|l| (l.ifindex, l.enabled))
        else {
            return;
        };
        if !enabled {
            return;
        }
        let interval = self.link_config(name).hello_interval();
        let timer = hello_timer(&self.tx, ifindex, interval);
        if let Some(link) = self.links.get_mut(&ifindex) {
            link.hello_timer = Some(timer);
        }
    }

    pub(crate) fn reconcile_by_name(&mut self, name: &str) {
        let ifindex = self
            .links
            .values()
            .find(|l| l.name == name)
            .map(|l| l.ifindex);
        if let Some(ifindex) = ifindex {
            self.reconcile(ifindex);
        }
    }

    fn link_enable(&mut self, ifindex: u32) {
        let interval = {
            let Some(link) = self.links.get(&ifindex) else {
                return;
            };
            self.link_config(&link.name).hello_interval()
        };
        pim_join_if(&self.sock, ifindex);
        self.fp.vif_add(ifindex);
        let timer = hello_timer(&self.tx, ifindex, interval);
        let link = self.links.get_mut(&ifindex).unwrap();
        link.enabled = true;
        link.gen_id = rand::rng().random();
        link.hello_timer = Some(timer);
        tracing::info!("pim: interface {} enabled", link.name);
        // Triggered hello so neighbors learn us without waiting a
        // full hello period, then elect (initially ourselves).
        self.hello_send(ifindex);
        self.dr_election(ifindex);
    }

    fn link_disable(&mut self, ifindex: u32) {
        // Goodbye hello (holdtime 0) so neighbors expire us at once.
        self.hello_send_holdtime_zero(ifindex);
        pim_leave_if(&self.sock, ifindex);
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.enabled = false;
        link.hello_timer = None;
        link.nbrs.clear();
        link.dr = None;
        tracing::info!("pim: interface {} disabled", link.name);
        // Drop every TIB facet on this interface, then the VIF (MFC
        // entries referencing it were just rewritten).
        self.tib_iface_purge(ifindex);
        self.fp.vif_del(ifindex);
    }

    /// Effective config for an interface: the configured entry, or
    /// defaults when only runtime state needs values (goodbye path).
    pub(crate) fn link_config(&self, name: &str) -> LinkConfig {
        self.if_config.get(name).cloned().unwrap_or_default()
    }

    /// DR election per RFC 7761 §4.3.2: if every neighbor advertised
    /// the DR-Priority option, elect by (priority, address); as soon
    /// as one neighbor omitted it, fall back to highest address.
    pub(crate) fn dr_election(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let Some(my_addr) = link.primary_addr() else {
            return;
        };
        let my_pri = self
            .if_config
            .get(&link.name)
            .map(|c| c.dr_priority())
            .unwrap_or(PIM_DEFAULT_DR_PRIORITY);

        let use_priority = link.nbrs.values().all(|n| n.dr_priority.is_some());
        let mut best = (my_pri, my_addr);
        for nbr in link.nbrs.values() {
            let cand = (nbr.dr_priority.unwrap_or(0), nbr.addr);
            let better = if use_priority {
                cand > best
            } else {
                cand.1 > best.1
            };
            if better {
                best = cand;
            }
        }
        let dr = Some(best.1);
        if link.dr != dr {
            tracing::info!(
                "pim: interface {} DR changed {:?} -> {:?}",
                link.name,
                link.dr,
                dr
            );
            link.dr = dr;
            // Only the DR turns local (IGMP) membership into upstream
            // PIM/OIF state, so a DR change must re-evaluate every
            // group on this interface (RFC 7761 §4.3.2).
            self.dr_membership_reeval(ifindex);
        }
    }

    /// Push (as DR) or withdraw (as non-DR) the TIB reflection of
    /// every group learned on this interface, after a DR transition.
    /// Membership tracking in `IgmpIf` is kept warm regardless, so
    /// failover is immediate.
    pub(crate) fn dr_membership_reeval(&mut self, ifindex: u32) {
        let groups: Vec<Ipv4Addr> = match self.links.get(&ifindex).and_then(|l| l.igmp.as_ref()) {
            Some(igmp) => igmp.groups.keys().copied().collect(),
            None => return,
        };
        for grp in groups {
            self.igmp_tib_sync(ifindex, grp);
        }
    }

    // ---- RibRx handlers ----

    pub(crate) fn link_add(&mut self, link: Link) {
        let ifindex = link.index;
        match self.links.get_mut(&ifindex) {
            Some(existing) => {
                existing.name = link.name.clone();
                existing.link_up = link.is_up();
            }
            None => {
                self.links.insert(ifindex, PimLink::from_link(&link));
            }
        }
        self.reconcile(ifindex);
    }

    pub(crate) fn link_up_down(&mut self, ifindex: u32, up: bool) {
        if let Some(link) = self.links.get_mut(&ifindex) {
            link.link_up = up;
            self.reconcile(ifindex);
        }
    }

    pub(crate) fn link_del(&mut self, ifindex: u32) {
        if let Some(link) = self.links.get(&ifindex)
            && link.enabled
        {
            self.link_disable(ifindex);
        }
        self.links.remove(&ifindex);
    }

    pub(crate) fn addr_add(&mut self, addr: LinkAddr) {
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = addr.addr else {
            return;
        };
        if !link.addrs.contains(&prefix) {
            link.addrs.push(prefix);
        }
        self.reconcile(addr.ifindex);
    }

    pub(crate) fn addr_del(&mut self, addr: LinkAddr) {
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = addr.addr else {
            return;
        };
        link.addrs.retain(|p| *p != prefix);
        self.reconcile(addr.ifindex);
        // Losing the primary address changes our DR candidate.
        self.dr_election(addr.ifindex);
    }
}
