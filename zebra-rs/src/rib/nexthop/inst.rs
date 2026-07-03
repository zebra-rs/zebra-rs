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
    Protect(NexthopProtect),
    /// A discard route — packets to the prefix are dropped in the
    /// forwarding plane (kernel `RTN_BLACKHOLE`) with no gateway or
    /// nexthop group. Used for aggregate summarization discards
    /// (OSPF `area range` / BGP `aggregate-address`) so component
    /// traffic that no more-specific route covers is dropped at the
    /// aggregator instead of looping. Carries only the route metric.
    Blackhole(u32),
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

// A path within a NexthopList or NexthopProtect. Uni is a single
// nexthop at one metric (NexthopList's only shape today, since its
// remaining caller is the inter-protocol merge that combines two
// single-nexthop entries at different distances). Multi is an ECMP
// group at one shared metric — the slot TI-LFA's "ECMP primary +
// per-primary repair" install fills via NexthopProtect.
// `#[serde(untagged)]` so JSON output preserves the pre-refactor flat
// shape: each member serializes as its inner type.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum NexthopMember {
    Uni(NexthopUni),
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

    /// Walk this member's `NexthopUni` leaves: a Uni yields itself,
    /// a Multi yields each ECMP leg in turn.
    pub fn iter_unis(&self) -> std::slice::Iter<'_, NexthopUni> {
        match self {
            Self::Uni(u) => std::slice::from_ref(u).iter(),
            Self::Multi(m) => m.nexthops.iter(),
        }
    }

    /// Mutable counterpart of `iter_unis`, used by the resolver.
    pub fn iter_unis_mut(&mut self) -> std::slice::IterMut<'_, NexthopUni> {
        match self {
            Self::Uni(u) => std::slice::from_mut(u).iter_mut(),
            Self::Multi(m) => m.nexthops.iter_mut(),
        }
    }
}

/// A primary path with its TI-LFA repair. Where `NexthopList` is an
/// ordered set of paths at distinct metrics whose roles are inferred
/// from sort position (member 0 = primary), the two roles here are
/// explicit fields. Produced by the IS-IS / OSPF TI-LFA install; the
/// backup goes into the kernel alongside the primary at a higher
/// route metric and takes over when the primary's nexthop group is
/// invalidated. Either member may be an ECMP group (`Multi`).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct NexthopProtect {
    pub primary: NexthopMember,
    pub backup: NexthopMember,

    // Kernel id of the protection indirection group (a 1-member
    // NHA_GROUP holding the primary) that protected routes reference
    // instead of the member's own gid — the handle the phase-2
    // switchover swaps. 0 = no indirection: producers always emit 0
    // and the resolver allocates one only for a Uni primary (groups
    // can't nest, so a Multi primary's ECMP group is itself the
    // switch point). See docs/design/nexthop-protect-kernel-failover.md.
    pub gid: usize,
}

impl NexthopProtect {
    /// Members in install order with their protection role, as
    /// `(member, is_backup)`. Keeps the role decision in one place
    /// for the show / JSON renderers.
    pub fn roles(&self) -> [(&NexthopMember, bool); 2] {
        [(&self.primary, false), (&self.backup, true)]
    }

    /// Members in install order, primary first.
    pub fn members(&self) -> [&NexthopMember; 2] {
        [&self.primary, &self.backup]
    }

    /// Mutable counterpart of `members`.
    pub fn members_mut(&mut self) -> [&mut NexthopMember; 2] {
        [&mut self.primary, &mut self.backup]
    }

    /// Walk every `NexthopUni` leaf, primary member first.
    pub fn iter_unis(&self) -> impl Iterator<Item = &NexthopUni> + '_ {
        self.primary.iter_unis().chain(self.backup.iter_unis())
    }

    /// Mutable counterpart of `iter_unis`, used by the resolver.
    pub fn iter_unis_mut(&mut self) -> impl Iterator<Item = &mut NexthopUni> + '_ {
        self.primary
            .iter_unis_mut()
            .chain(self.backup.iter_unis_mut())
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
    fn protect_iter_unis_walks_primary_then_backup() {
        // ECMP primary + Uni backup: leaves come out primary-first so
        // the resolver's "first valid uni wins" keeps preferring the
        // primary, matching the sorted NexthopList behavior.
        let multi = NexthopMulti {
            metric: 20,
            nexthops: vec![mk_uni("10.0.0.1", 20), mk_uni("10.0.0.2", 20)],
            ..Default::default()
        };
        let pro = NexthopProtect {
            primary: NexthopMember::Multi(multi),
            backup: NexthopMember::Uni(mk_uni("10.0.0.5", 21)),
            gid: 0,
        };
        let addrs: Vec<_> = pro.iter_unis().map(|u| u.addr.to_string()).collect();
        assert_eq!(addrs, vec!["10.0.0.1", "10.0.0.2", "10.0.0.5"]);
    }

    #[test]
    fn protect_roles_tags_backup_member() {
        let pro = NexthopProtect {
            primary: NexthopMember::Uni(mk_uni("10.0.0.1", 20)),
            backup: NexthopMember::Uni(mk_uni("10.0.0.5", 21)),
            gid: 0,
        };
        let roles: Vec<bool> = pro.roles().iter().map(|(_, b)| *b).collect();
        assert_eq!(roles, vec![false, true]);
        assert_eq!(pro.roles()[0].0, &pro.primary);
        assert_eq!(pro.roles()[1].0, &pro.backup);
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
}
