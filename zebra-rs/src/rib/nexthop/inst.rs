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
    pub nexthops: Vec<NexthopUni>,
}

impl NexthopList {
    pub fn metric(&self) -> u32 {
        match self.nexthops.first() {
            Some(nhop) => nhop.metric,
            None => 0,
        }
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
