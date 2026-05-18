use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use isis_packet::srv6::EncapType;

use crate::rib::SidBehavior;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum Label {
    Implicit(u32),
    Explicit(u32),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct NexthopUni {
    pub addr: IpAddr,
    pub metric: u32,
    pub weight: u8,

    /// What the source said the egress ifindex was — `Some` for IGP
    /// adjacencies, kernel dump, connected routes, configured static
    /// routes that name an interface, seg6local installs that
    /// pre-resolve to loopback / per-adjacency. `None` means "the
    /// source didn't know; please resolve via the RIB."
    ///
    /// Origin is the source of truth for FIB install and show output;
    /// the resolver must never overwrite it. Future work will give
    /// `addr` the same origin/resolved split for static routes that
    /// recurse through a chain of nexthop addresses.
    pub ifindex_origin: Option<u32>,
    /// What the RIB resolver looked up when origin was `None`.
    /// `None` means "not resolved yet" or "no covering route found."
    pub ifindex_resolved: Option<u32>,

    pub valid: bool,
    pub mpls: Vec<Label>,
    pub mpls_label: Vec<u32>,

    // SRv6 segments. Non-empty marks this nexthop as SRv6-encapsulated.
    pub segs: Vec<Ipv6Addr>,

    // SRv6 endpoint behavior chosen for the encap (e.g. H.Encap, H.Encap.Red).
    // None when segs is empty.
    pub encap_type: Option<EncapType>,

    // SRv6 seg6local action — set when this nexthop installs a local
    // SID (End / End.X). For End.X, `addr` carries the IPv6 nexthop and
    // `ifindex_origin` the outgoing link; for End, the ifindex is the
    // sr0 dummy and `addr` is unused.
    pub seg6local_action: Option<SidBehavior>,

    // Action.
    pub gid: usize,
}

impl NexthopUni {
    /// Egress ifindex to use, with origin winning over resolved.
    /// Returns `None` only when neither the source nor the resolver
    /// produced one — callers that need a u32 (FIB / netlink) should
    /// `.unwrap_or(0)`.
    pub fn ifindex(&self) -> Option<u32> {
        self.ifindex_origin.or(self.ifindex_resolved)
    }
}

impl NexthopUni {
    pub fn new(addr: IpAddr, metric: u32, mpls: Vec<Label>) -> Self {
        let mpls_label = mpls
            .iter()
            .filter_map(|label| match label {
                Label::Implicit(_) => None,
                Label::Explicit(label) => Some(*label),
            })
            .collect();
        Self {
            addr,
            metric,
            mpls,
            mpls_label,
            weight: 1,
            ..Default::default()
        }
    }

    // Backward compatibility method for IPv4
    pub fn from(addr: Ipv4Addr, metric: u32, mpls: Vec<Label>) -> Self {
        Self::new(IpAddr::V4(addr), metric, mpls)
    }
}

impl Default for NexthopUni {
    fn default() -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ifindex_origin: None,
            ifindex_resolved: None,
            metric: 0,
            weight: 1,
            mpls: vec![],
            mpls_label: vec![],
            segs: vec![],
            encap_type: None,
            seg6local_action: None,
            gid: 0,
            valid: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum Nexthop {
    Link(u32),
    Uni(NexthopUni),
    Multi(NexthopMulti),
    List(NexthopList),
}

impl Default for Nexthop {
    fn default() -> Self {
        Self::Link(0)
    }
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
pub struct NexthopList {
    pub nexthops: Vec<NexthopMember>,
}

// A path within a NexthopList. Uni is a single nexthop at one metric
// (the only shape produced today, since every existing caller is the
// inter-protocol merge that combines two single-nexthop entries at
// different distances). Multi is an ECMP group at one shared metric —
// the slot TI-LFA's "ECMP primary + per-primary repair" install fills.
// `#[serde(untagged)]` so JSON output preserves the pre-refactor flat
// shape: each member serializes as its inner type.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum NexthopMember {
    Uni(NexthopUni),
    // Multi is constructed in tests but no production code path
    // emits one yet — TI-LFA's "ECMP primary + per-primary repair"
    // install will be the first real user. Drop the allow when that
    // lands.
    #[allow(dead_code)]
    Multi(NexthopMulti),
}

impl NexthopMember {
    pub fn metric(&self) -> u32 {
        match self {
            Self::Uni(u) => u.metric,
            Self::Multi(m) => m.metric,
        }
    }

    /// Wrap the member back into a top-level `Nexthop`, used by the
    /// FIB writer to re-dispatch member install through the existing
    /// per-variant install paths.
    pub fn as_nexthop(&self) -> Nexthop {
        match self {
            Self::Uni(u) => Nexthop::Uni(u.clone()),
            Self::Multi(m) => Nexthop::Multi(m.clone()),
        }
    }
}

impl NexthopList {
    pub fn metric(&self) -> u32 {
        self.nexthops.first().map_or(0, |m| m.metric())
    }

    /// Walk every `NexthopUni` leaf in member order. Uni members
    /// yield once; Multi members yield each inner uni in turn.
    pub fn iter_unis(&self) -> impl Iterator<Item = &NexthopUni> + '_ {
        self.nexthops.iter().flat_map(|m| match m {
            NexthopMember::Uni(u) => std::slice::from_ref(u).iter(),
            NexthopMember::Multi(grp) => grp.nexthops.iter(),
        })
    }

    /// Mutable counterpart of `iter_unis`, used by the resolver.
    pub fn iter_unis_mut(&mut self) -> impl Iterator<Item = &mut NexthopUni> + '_ {
        self.nexthops.iter_mut().flat_map(|m| match m {
            NexthopMember::Uni(u) => std::slice::from_mut(u).iter_mut(),
            NexthopMember::Multi(grp) => grp.nexthops.iter_mut(),
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]
pub struct NexthopMulti {
    // ECMP or UCMP multipath.  metric will be the same.
    pub metric: u32,

    // For UCMP, we have weight.
    pub nexthops: Vec<NexthopUni>,

    // Nexthop Group id for multipath.
    pub gid: usize,
}

/// Either a single nexthop or an ECMP group at one metric. Used as
/// the primary / backup slot inside `NexthopProtect` — restricted
/// (vs `Nexthop`) so nested protection and protect-inside-list are
/// disallowed by construction.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
#[allow(dead_code)] // wired into `Nexthop` in a follow-up commit
pub enum NexthopPath {
    Uni(NexthopUni),
    Multi(NexthopMulti),
}

#[allow(dead_code)]
impl NexthopPath {
    pub fn metric(&self) -> u32 {
        match self {
            Self::Uni(u) => u.metric,
            Self::Multi(m) => m.metric,
        }
    }

    pub fn iter_unis(&self) -> impl Iterator<Item = &NexthopUni> + '_ {
        match self {
            Self::Uni(u) => std::slice::from_ref(u).iter(),
            Self::Multi(m) => m.nexthops.iter(),
        }
    }

    pub fn iter_unis_mut(&mut self) -> impl Iterator<Item = &mut NexthopUni> + '_ {
        match self {
            Self::Uni(u) => std::slice::from_mut(u).iter_mut(),
            Self::Multi(m) => m.nexthops.iter_mut(),
        }
    }
}

/// IP/MPLS Fast-ReRoute (FRR): forward over `primary`; on primary
/// link-down the kernel fails over to `backup` without waiting for
/// the next SPF.
///
/// This is the slot TI-LFA repair install will fill, replacing the
/// `BACKUP_METRIC_OFFSET` trick that currently piggybacks repair
/// paths onto a `NexthopList` and distinguishes them by metric
/// ordering. A dedicated variant makes the FRR relationship explicit
/// (no metric sentinel), bounds the shape to exactly two slots, and
/// gives the FIB installer a clear hook to emit a kernel FRR nexthop
/// group (`NEXTHOP_GRP_TYPE_FRR`) rather than two separate
/// metric-distinguished routes.
///
/// Both slots are `NexthopPath`, so ECMP-primary + ECMP-backup is
/// expressible. The per-primary "each primary link has its own
/// backup that excludes that link" association is *not* preserved at
/// this level — primaries fail over collectively to backups, which
/// matches what `build_rib_nexthop` already produces today.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[allow(dead_code)] // wired into `Nexthop` in a follow-up commit
pub struct NexthopProtect {
    pub primary: NexthopPath,
    pub backup: NexthopPath,
}

#[allow(dead_code)]
impl NexthopProtect {
    /// Primary's metric — the route's metric for sorting / display.
    /// Backup carries no meaningful metric in the FRR model.
    pub fn metric(&self) -> u32 {
        self.primary.metric()
    }

    /// Walk every `NexthopUni` leaf — primaries first, then backups.
    pub fn iter_unis(&self) -> impl Iterator<Item = &NexthopUni> + '_ {
        self.primary.iter_unis().chain(self.backup.iter_unis())
    }

    /// Mutable counterpart of `iter_unis`. Destructured up-front so
    /// the borrow checker sees two disjoint mutable borrows.
    pub fn iter_unis_mut(&mut self) -> impl Iterator<Item = &mut NexthopUni> + '_ {
        let Self { primary, backup } = self;
        primary.iter_unis_mut().chain(backup.iter_unis_mut())
    }

    pub fn iter_primary_unis(&self) -> impl Iterator<Item = &NexthopUni> + '_ {
        self.primary.iter_unis()
    }

    pub fn iter_backup_unis(&self) -> impl Iterator<Item = &NexthopUni> + '_ {
        self.backup.iter_unis()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_uni(addr: &str, metric: u32) -> NexthopUni {
        NexthopUni::new(addr.parse().unwrap(), metric, vec![])
    }

    #[test]
    fn list_metric_returns_first_member_metric() {
        // Primary (metric 20) sorted ahead of backup (metric 21):
        // NexthopList::metric() returns 20.
        let list = NexthopList {
            nexthops: vec![
                NexthopMember::Uni(mk_uni("10.0.0.1", 20)),
                NexthopMember::Uni(mk_uni("10.0.0.5", 21)),
            ],
        };
        assert_eq!(list.metric(), 20);
    }

    #[test]
    fn list_metric_returns_zero_when_empty() {
        let list = NexthopList::default();
        assert_eq!(list.metric(), 0);
    }

    #[test]
    fn member_metric_delegates_to_inner() {
        let uni_member = NexthopMember::Uni(mk_uni("10.0.0.1", 20));
        let multi = NexthopMulti {
            metric: 30,
            nexthops: vec![mk_uni("10.0.0.2", 30), mk_uni("10.0.0.3", 30)],
            ..Default::default()
        };
        let multi_member = NexthopMember::Multi(multi);
        assert_eq!(uni_member.metric(), 20);
        assert_eq!(multi_member.metric(), 30);
    }

    #[test]
    fn iter_unis_flattens_multi_members() {
        // A list with a Uni primary and a 2-uni Multi backup yields
        // three NexthopUni references — caller doesn't need to know
        // about the grouping.
        let multi = NexthopMulti {
            metric: 21,
            nexthops: vec![mk_uni("10.0.0.5", 21), mk_uni("10.0.0.6", 21)],
            ..Default::default()
        };
        let list = NexthopList {
            nexthops: vec![
                NexthopMember::Uni(mk_uni("10.0.0.1", 20)),
                NexthopMember::Multi(multi),
            ],
        };
        let addrs: Vec<_> = list.iter_unis().map(|u| u.addr.to_string()).collect();
        assert_eq!(addrs, vec!["10.0.0.1", "10.0.0.5", "10.0.0.6"]);
    }

    #[test]
    fn as_nexthop_redispatches_to_top_level_variant() {
        // FIB writer relies on this to reuse the existing per-variant
        // install paths for each member.
        let uni = mk_uni("10.0.0.1", 20);
        let uni_member = NexthopMember::Uni(uni.clone());
        assert_eq!(uni_member.as_nexthop(), Nexthop::Uni(uni));

        let multi = NexthopMulti {
            metric: 21,
            nexthops: vec![mk_uni("10.0.0.5", 21)],
            ..Default::default()
        };
        let multi_member = NexthopMember::Multi(multi.clone());
        assert_eq!(multi_member.as_nexthop(), Nexthop::Multi(multi));
    }

    #[test]
    fn protect_metric_returns_primary_metric() {
        // The backup's "metric" is irrelevant in the FRR model;
        // sort / display use the primary's.
        let protect = NexthopProtect {
            primary: NexthopPath::Uni(mk_uni("10.0.0.1", 20)),
            backup: NexthopPath::Uni(mk_uni("10.0.0.5", 99)),
        };
        assert_eq!(protect.metric(), 20);
    }

    #[test]
    fn protect_iter_unis_visits_primary_then_backup() {
        // ECMP-primary + ECMP-backup: order is all primaries, then
        // all backups — what the netlink FRR group emit needs.
        let primary_multi = NexthopMulti {
            metric: 20,
            nexthops: vec![mk_uni("10.0.0.1", 20), mk_uni("10.0.0.2", 20)],
            ..Default::default()
        };
        let backup_multi = NexthopMulti {
            metric: 20,
            nexthops: vec![mk_uni("10.0.0.5", 20), mk_uni("10.0.0.6", 20)],
            ..Default::default()
        };
        let protect = NexthopProtect {
            primary: NexthopPath::Multi(primary_multi),
            backup: NexthopPath::Multi(backup_multi),
        };
        let addrs: Vec<_> = protect.iter_unis().map(|u| u.addr.to_string()).collect();
        assert_eq!(addrs, vec!["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.6"]);
    }

    #[test]
    fn protect_primary_and_backup_iters_are_disjoint() {
        let protect = NexthopProtect {
            primary: NexthopPath::Uni(mk_uni("10.0.0.1", 20)),
            backup: NexthopPath::Uni(mk_uni("10.0.0.5", 20)),
        };
        let pri: Vec<_> = protect
            .iter_primary_unis()
            .map(|u| u.addr.to_string())
            .collect();
        let bkp: Vec<_> = protect
            .iter_backup_unis()
            .map(|u| u.addr.to_string())
            .collect();
        assert_eq!(pri, vec!["10.0.0.1"]);
        assert_eq!(bkp, vec!["10.0.0.5"]);
    }

    #[test]
    fn protect_iter_unis_mut_writes_through_both_slots() {
        // Resolver path will use this to set ifindex_resolved /
        // valid on every leaf; both primary and backup must receive
        // the updates.
        let mut protect = NexthopProtect {
            primary: NexthopPath::Uni(mk_uni("10.0.0.1", 20)),
            backup: NexthopPath::Uni(mk_uni("10.0.0.5", 20)),
        };
        for u in protect.iter_unis_mut() {
            u.valid = true;
        }
        assert!(matches!(&protect.primary, NexthopPath::Uni(u) if u.valid));
        assert!(matches!(&protect.backup, NexthopPath::Uni(u) if u.valid));
    }

    #[test]
    fn path_metric_and_iter_match_inner() {
        let uni_path = NexthopPath::Uni(mk_uni("10.0.0.1", 20));
        assert_eq!(uni_path.metric(), 20);
        assert_eq!(uni_path.iter_unis().count(), 1);

        let multi_path = NexthopPath::Multi(NexthopMulti {
            metric: 30,
            nexthops: vec![mk_uni("10.0.0.2", 30), mk_uni("10.0.0.3", 30)],
            ..Default::default()
        });
        assert_eq!(multi_path.metric(), 30);
        assert_eq!(multi_path.iter_unis().count(), 2);
    }
}
