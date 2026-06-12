use std::cmp::Ordering;
use std::time::Instant;

use crate::fib::FibHandle;

use super::nexthop::{GroupTrait, NexthopUni};
use super::{Nexthop, NexthopMap, NexthopMember, NexthopMulti, RibSubType, RibType};

pub type RibEntries = Vec<RibEntry>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RibEntry {
    pub rtype: RibType,
    pub rsubtype: RibSubType,
    pub selected: bool,
    pub fib: bool,
    pub valid: bool,
    pub distance: u8,
    pub metric: u32,
    pub nexthop: Nexthop,

    // Connected RIB's ifindex.
    pub ifindex: u32,

    /// Wall-clock-ish stamp of when this entry was first created in
    /// the RIB. Used by the show callback to render the "uptime"
    /// column (`02:41:03` / `2d18h29m`). Replacing the entry resets
    /// it; in-place mutation does not. `Instant` is monotonic, so we
    /// don't claim it survives suspend/resume — that's an acceptable
    /// approximation for operator-facing route ages.
    #[serde(skip)]
    pub time: Instant,
}

impl RibEntry {
    pub fn new(rtype: RibType) -> Self {
        Self {
            rtype,
            rsubtype: RibSubType::Default,
            selected: false,
            fib: false,
            valid: false,
            distance: 0,
            metric: 0,
            nexthop: Nexthop::default(),
            ifindex: 0,
            time: Instant::now(),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.rtype == RibType::Connected
    }

    pub fn set_valid(&mut self, valid: bool) {
        self.valid = valid;
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn is_protocol(&self) -> bool {
        matches!(
            self.rtype,
            RibType::Static | RibType::Ospf | RibType::Isis | RibType::Bgp
        )
    }

    pub fn is_fib(&self) -> bool {
        self.fib
    }

    pub fn set_fib(&mut self, fib: bool) {
        self.fib = fib;
    }

    pub fn is_selected(&self) -> bool {
        self.selected
    }

    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    pub fn selected(&self) -> String {
        let selected = if self.selected { '>' } else { ' ' };
        let fib = if self.fib { '*' } else { ' ' };
        format!("{}{}", fib, selected)
    }

    pub fn is_valid_nexthop(&self, nmap: &NexthopMap) -> bool {
        match &self.nexthop {
            Nexthop::Uni(uni) => nmap.get(uni.gid).is_some_and(|group| group.is_valid()),
            Nexthop::Multi(multi) => multi
                .nexthops
                .iter()
                .any(|nhop| nmap.get(nhop.gid).is_some_and(|group| group.is_valid())),
            Nexthop::List(pro) => pro
                .iter_unis()
                .any(|nhop| nmap.get(nhop.gid).is_some_and(|group| group.is_valid())),
            Nexthop::Protect(pro) => pro
                .iter_unis()
                .any(|nhop| nmap.get(nhop.gid).is_some_and(|group| group.is_valid())),
            _ => false,
        }
    }

    pub async fn nexthop_sync(&mut self, nmap: &mut NexthopMap, fib: &FibHandle) {
        if let Nexthop::Uni(uni) = &mut self.nexthop {
            uni_group_sync(uni, nmap, fib).await;
        }
        if let Nexthop::Multi(multi) = &mut self.nexthop {
            for uni in multi.nexthops.iter_mut() {
                uni_group_sync(uni, nmap, fib).await;
            }
            multi_group_sync(multi, nmap, fib).await;
        }
        if let Nexthop::List(pro) = &mut self.nexthop {
            for member in pro.nexthops.iter_mut() {
                member_group_sync(member, nmap, fib).await;
            }
        }
        if let Nexthop::Protect(pro) = &mut self.nexthop {
            for member in pro.members_mut() {
                member_group_sync(member, nmap, fib).await;
            }
            // The indirection group references the primary member's
            // kernel object, so it must install after the members.
            protect_group_sync(pro.gid, nmap, fib).await;
        }
    }

    pub async fn nexthop_unsync(&mut self, nmap: &mut NexthopMap, fib: &FibHandle) {
        if !self.is_protocol() {
            return;
        }
        match &self.nexthop {
            Nexthop::Link(_) => {}
            Nexthop::Uni(uni) => {
                // println!(" uni {}", uni.addr);
                self.handle_nexthop_group(nmap, fib, uni.gid).await;
            }
            Nexthop::Multi(multi) => {
                // println!(" multi");
                self.handle_nexthop_group(nmap, fib, multi.gid).await;
                for uni in &multi.nexthops {
                    // println!(" multi {}", uni.addr);
                    self.handle_nexthop_group(nmap, fib, uni.gid).await;
                }
            }
            Nexthop::List(pro) => {
                for member in &pro.nexthops {
                    self.member_nexthop_unsync(member, nmap, fib).await;
                }
            }
            Nexthop::Protect(pro) => {
                // Drop the indirection group before its members so
                // member deletion can't cascade-empty it in the
                // kernel out from under the explicit delete.
                if pro.gid != 0 {
                    self.handle_nexthop_group(nmap, fib, pro.gid).await;
                }
                for member in pro.members() {
                    self.member_nexthop_unsync(member, nmap, fib).await;
                }
            }
        }
    }

    async fn member_nexthop_unsync(
        &self,
        member: &NexthopMember,
        nmap: &mut NexthopMap,
        fib: &FibHandle,
    ) {
        match member {
            NexthopMember::Uni(uni) => {
                self.handle_nexthop_group(nmap, fib, uni.gid).await;
            }
            NexthopMember::Multi(multi) => {
                self.handle_nexthop_group(nmap, fib, multi.gid).await;
                for uni in &multi.nexthops {
                    self.handle_nexthop_group(nmap, fib, uni.gid).await;
                }
            }
        }
    }

    async fn handle_nexthop_group(&self, nmap: &mut NexthopMap, fib: &FibHandle, gid: usize) {
        if let Some(group) = nmap.get_mut(gid) {
            // println!(" refcnt {} -> {}", group.refcnt(), group.refcnt() - 1);
            group.refcnt_dec();
            if group.refcnt() == 0 {
                // If ref count is zero and the nexthop is installed, remove it from FIB
                if group.is_installed() {
                    fib.nexthop_del(group).await;
                }
                // Remove nexthop group since it's no longer referenced
                nmap.groups[gid] = None;
            }
        }
    }
}

async fn uni_group_sync(uni: &NexthopUni, nmap: &mut NexthopMap, fib: &FibHandle) {
    let Some(group) = nmap.get_mut(uni.gid) else {
        return;
    };
    if !group.is_valid() || group.is_installed() {
        return;
    }
    fib.nexthop_add(group).await;
    group.set_installed(true);
}

/// Install the protection indirection group once it's valid — same
/// gate as the Uni/Multi sync helpers. `gid == 0` means no
/// indirection was allocated (Multi primary).
async fn protect_group_sync(gid: usize, nmap: &mut NexthopMap, fib: &FibHandle) {
    if gid == 0 {
        return;
    }
    let Some(group) = nmap.get_mut(gid) else {
        return;
    };
    if !group.is_valid() || group.is_installed() {
        return;
    }
    fib.nexthop_add(group).await;
    group.set_installed(true);
}

async fn member_group_sync(member: &mut NexthopMember, nmap: &mut NexthopMap, fib: &FibHandle) {
    match member {
        NexthopMember::Uni(uni) => uni_group_sync(uni, nmap, fib).await,
        NexthopMember::Multi(multi) => {
            for uni in multi.nexthops.iter_mut() {
                uni_group_sync(uni, nmap, fib).await;
            }
            multi_group_sync(multi, nmap, fib).await;
        }
    }
}

async fn multi_group_sync(multi: &NexthopMulti, nmap: &mut NexthopMap, fib: &FibHandle) {
    let Some(group) = nmap.get_mut(multi.gid) else {
        return;
    };
    if !group.is_valid() || group.is_installed() {
        return;
    }
    fib.nexthop_add(group).await;
    group.set_installed(true);
}

impl PartialEq for RibEntry {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance && self.metric == other.metric
    }
}

impl PartialOrd for RibEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.distance.partial_cmp(&other.distance).and_then(|ord| {
            if ord == Ordering::Equal {
                self.metric.partial_cmp(&other.metric)
            } else {
                Some(ord)
            }
        })
    }
}
