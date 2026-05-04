use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr},
};

use isis_packet::srv6::EncapType;

use crate::fib::FibHandle;

use super::{Group, GroupMulti, GroupTrait, GroupUni, NexthopUni};

// Dedupe key for SRv6-encapsulated nexthops. Two NexthopUnis with the same
// outer destination, segment list, and endpoint behavior share one entry —
// so N routes with the same SRv6 policy point at one kernel nhid.
type Seg6Key = (IpAddr, Vec<Ipv6Addr>, Option<EncapType>);

// Dedupe key for SRv6 seg6local nexthops (End / End.X). Two SID installs
// pointing at the same {action, oif, nh6} share one nhid — uncommon today
// (each adjacency has its own End.X) but the structure is the same as
// every other dedupe table here.
type Seg6LocalKey = (crate::rib::SidBehavior, u32, Option<std::net::Ipv6Addr>);

pub struct NexthopMap {
    map: BTreeMap<IpAddr, usize>,
    set: BTreeMap<BTreeSet<(usize, u8)>, usize>,
    mpls: BTreeMap<(IpAddr, Vec<u32>), usize>,
    seg6: BTreeMap<Seg6Key, usize>,
    seg6local: BTreeMap<Seg6LocalKey, usize>,
    pub groups: Vec<Option<Group>>,
}

impl Group {
    pub fn from_nexthop_uni(uni: &NexthopUni, gid: usize) -> Self {
        Group::Uni(GroupUni::new(gid, uni))
    }
}

impl Default for NexthopMap {
    fn default() -> Self {
        let mut nmap = Self {
            map: BTreeMap::new(),
            set: BTreeMap::new(),
            mpls: BTreeMap::new(),
            seg6: BTreeMap::new(),
            seg6local: BTreeMap::new(),
            groups: Vec::new(),
        };
        nmap.groups.push(None);
        nmap
    }
}

impl NexthopMap {
    pub fn get(&self, index: usize) -> Option<&Group> {
        if let Some(grp) = self.groups.get(index) {
            grp.as_ref()
        } else {
            None
        }
    }

    pub fn get_uni(&self, index: usize) -> Option<&GroupUni> {
        self.groups
            .get(index)
            .and_then(|grp| grp.as_ref())
            .and_then(|grp| {
                if let Group::Uni(uni) = grp {
                    Some(uni)
                } else {
                    None
                }
            })
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Group> {
        if let Some(grp) = self.groups.get_mut(index) {
            grp.as_mut()
        } else {
            None
        }
    }

    fn new_gid(&self) -> usize {
        self.groups.len()
    }

    pub fn fetch_uni(&mut self, uni: &NexthopUni) -> Option<&mut Group> {
        if let Some(&gid) = self.map.get(&uni.addr) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid);

        self.map.insert(uni.addr, gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    pub fn fetch_mpls(&mut self, uni: &NexthopUni) -> Option<&mut Group> {
        if let Some(&gid) = self.mpls.get(&(uni.addr, uni.mpls_label.clone())) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid);

        self.mpls.insert((uni.addr, uni.mpls_label.clone()), gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    /// Fetch (or create) the dedup'd nexthop entry for an SRv6-encapsulated
    /// nexthop. Two NexthopUnis with the same (addr, segs, encap_type) share
    /// one Group — one kernel nhid is shared across every route that uses
    /// the same SRv6 policy.
    pub fn fetch_seg6(&mut self, uni: &NexthopUni) -> Option<&mut Group> {
        let key: Seg6Key = (uni.addr, uni.segs.clone(), uni.encap_type);
        if let Some(&gid) = self.seg6.get(&key) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid);

        self.seg6.insert(key, gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    /// Fetch (or create) the dedup'd nexthop entry for an SRv6 seg6local
    /// nexthop (End / End.X). Keyed on (action, oif, nh6) so two SIDs
    /// pointing at the same install target share one Group.
    pub fn fetch_seg6local(&mut self, uni: &NexthopUni) -> Option<&mut Group> {
        let action = uni.seg6local_action?;
        let nh6 = match uni.addr {
            IpAddr::V6(a) if !a.is_unspecified() => Some(a),
            _ => None,
        };
        let key: Seg6LocalKey = (action, uni.ifindex().unwrap_or(0), nh6);
        if let Some(&gid) = self.seg6local.get(&key) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid);

        self.seg6local.insert(key, gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    pub fn fetch(&mut self, uni: &NexthopUni) -> Option<&mut Group> {
        // seg6local takes priority over plain unicast — `addr` for an
        // End SID is unspecified and would route through fetch_uni
        // otherwise, collapsing every End SID into a single shared
        // entry by accident.
        if uni.seg6local_action.is_some() {
            self.fetch_seg6local(uni)
        } else if !uni.segs.is_empty() {
            // SRv6 encap — the segment list is the dedup dimension,
            // and we want SRv6 nexthops in their own table so the FIB
            // nexthop_add path can emit seg6 attributes without
            // re-inspecting NexthopUni.
            self.fetch_seg6(uni)
        } else if uni.mpls_label.is_empty() {
            self.fetch_uni(uni)
        } else {
            self.fetch_mpls(uni)
        }
    }

    pub fn fetch_multi(&mut self, set: &BTreeSet<(usize, u8)>) -> Option<&mut Group> {
        let gid = if let Some(&gid) = self.set.get(set) {
            let update = self.groups.get_mut(gid)?;
            if update.is_none() {
                let mut multi = GroupMulti::new(gid);
                multi.set = set.clone();
                *update = Some(Group::Multi(multi));
            }
            gid
        } else {
            let gid = self.new_gid();
            let mut multi = GroupMulti::new(gid);
            multi.set = set.clone();

            self.set.insert(set.clone(), gid);
            self.groups.push(Some(Group::Multi(multi)));

            gid
        };
        self.get_mut(gid)
    }

    pub async fn shutdown(&mut self, fib: &FibHandle) {
        for (_, id) in self.set.iter() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for (_, id) in self.map.iter() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for (_, id) in self.mpls.iter() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for (_, id) in self.seg6.iter() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for (_, id) in self.seg6local.iter() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv6_uni(first: &str, segs: &[&str], encap_type: EncapType) -> NexthopUni {
        let parsed: Vec<Ipv6Addr> = segs.iter().map(|s| s.parse().unwrap()).collect();
        NexthopUni {
            addr: IpAddr::V6(first.parse().unwrap()),
            segs: parsed,
            encap_type: Some(encap_type),
            ..Default::default()
        }
    }

    fn plain_uni(addr: &str) -> NexthopUni {
        NexthopUni {
            addr: addr.parse().unwrap(),
            ..Default::default()
        }
    }

    fn group_gid(grp: &Group) -> usize {
        match grp {
            Group::Uni(uni) => uni.gid(),
            Group::Multi(multi) => multi.gid(),
        }
    }

    #[test]
    fn fetch_seg6_dedupes_identical_policy() {
        // The headline win: two routes with the same SRv6 policy should
        // share one nhid, not allocate two.
        let mut nmap = NexthopMap::default();
        let uni = srv6_uni(
            "fcbb:bbbb:2:3:2::",
            &["fcbb:bbbb:2:3:2::", "fcbb:bbbb:2:3:3::"],
            EncapType::HEncap,
        );
        let gid_a = group_gid(nmap.fetch(&uni).expect("group"));
        let gid_b = group_gid(nmap.fetch(&uni).expect("group"));
        assert_eq!(gid_a, gid_b);
    }

    #[test]
    fn fetch_seg6_distinguishes_different_segments() {
        let mut nmap = NexthopMap::default();
        let one = srv6_uni(
            "fcbb:bbbb:2:3:2::",
            &["fcbb:bbbb:2:3:2::"],
            EncapType::HEncap,
        );
        let two = srv6_uni(
            "fcbb:bbbb:2:3:2::",
            &["fcbb:bbbb:2:3:2::", "fcbb:bbbb:2:3:3::"],
            EncapType::HEncap,
        );
        let gid_one = group_gid(nmap.fetch(&one).expect("group"));
        let gid_two = group_gid(nmap.fetch(&two).expect("group"));
        assert_ne!(gid_one, gid_two);
    }

    #[test]
    fn fetch_seg6_distinguishes_encap_type() {
        // Same outer destination + segments but different encap behavior
        // (H.Encap vs H.Encap.Red) is operationally a different policy and
        // must not share a kernel nexthop.
        let mut nmap = NexthopMap::default();
        let h_encap = srv6_uni(
            "fcbb:bbbb:2:3:2::",
            &["fcbb:bbbb:2:3:2::", "fcbb:bbbb:2:3:3::"],
            EncapType::HEncap,
        );
        let h_red = srv6_uni(
            "fcbb:bbbb:2:3:2::",
            &["fcbb:bbbb:2:3:2::", "fcbb:bbbb:2:3:3::"],
            EncapType::HEncapRed,
        );
        let gid_a = group_gid(nmap.fetch(&h_encap).expect("group"));
        let gid_b = group_gid(nmap.fetch(&h_red).expect("group"));
        assert_ne!(gid_a, gid_b);
    }

    #[test]
    fn fetch_uni_unaffected_by_seg6_path() {
        // Plain (non-SRv6) NexthopUnis still go through fetch_uni — no
        // accidental routing through the seg6 table.
        let mut nmap = NexthopMap::default();
        let plain_a = plain_uni("2001:db8::1");
        let plain_b = plain_uni("2001:db8::1");
        let gid_a = group_gid(nmap.fetch(&plain_a).expect("group"));
        let gid_b = group_gid(nmap.fetch(&plain_b).expect("group"));
        assert_eq!(gid_a, gid_b);

        // The seg6 dedupe table stays empty.
        assert!(nmap.seg6.is_empty());

        // And a Nexthop::Uni constructed from a plain uni surfaces empty
        // segs / None encap_type on the resulting GroupUni.
        let grp = nmap.fetch(&plain_a).expect("group");
        if let Group::Uni(uni) = grp {
            assert!(uni.segs.is_empty());
            assert_eq!(uni.encap_type, None);
        } else {
            panic!("expected Group::Uni");
        }
    }

    #[test]
    fn fetch_seg6_carries_addr_and_policy_to_group() {
        let mut nmap = NexthopMap::default();
        let uni = srv6_uni(
            "fcbb:bbbb:2:3:2::",
            &["fcbb:bbbb:2:3:2::", "fcbb:bbbb:2:3:3::"],
            EncapType::HEncap,
        );
        let grp = nmap.fetch(&uni).expect("group");
        if let Group::Uni(g) = grp {
            assert_eq!(g.addr, IpAddr::V6("fcbb:bbbb:2:3:2::".parse().unwrap()));
            assert_eq!(g.segs.len(), 2);
            assert_eq!(g.encap_type, Some(EncapType::HEncap));
        } else {
            panic!("expected Group::Uni");
        }
    }

    #[test]
    fn nexthop_dispatch_keys_into_correct_table() {
        // After fetching one of each kind, exactly the right dedupe map
        // holds the entry — no cross-pollination.
        let mut nmap = NexthopMap::default();

        // Plain.
        nmap.fetch(&plain_uni("2001:db8::1"));
        assert_eq!(nmap.map.len(), 1);
        assert!(nmap.mpls.is_empty());
        assert!(nmap.seg6.is_empty());

        // MPLS.
        let mpls_uni = NexthopUni {
            addr: "10.0.0.1".parse().unwrap(),
            mpls_label: vec![100, 200],
            ..Default::default()
        };
        nmap.fetch(&mpls_uni);
        assert_eq!(nmap.mpls.len(), 1);
        assert!(nmap.seg6.is_empty());

        // SRv6.
        nmap.fetch(&srv6_uni(
            "fcbb:bbbb:2:3:2::",
            &["fcbb:bbbb:2:3:2::"],
            EncapType::HEncap,
        ));
        assert_eq!(nmap.seg6.len(), 1);
    }

    fn end_uni(ifindex: u32) -> NexthopUni {
        NexthopUni {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ifindex_origin: Some(ifindex),
            seg6local_action: Some(crate::rib::SidBehavior::End),
            ..Default::default()
        }
    }

    fn endx_uni(ifindex: u32, nh6: &str) -> NexthopUni {
        NexthopUni {
            addr: IpAddr::V6(nh6.parse().unwrap()),
            ifindex_origin: Some(ifindex),
            seg6local_action: Some(crate::rib::SidBehavior::EndX),
            ..Default::default()
        }
    }

    #[test]
    fn fetch_seg6local_dedupes_identical_install_target() {
        // Two End SIDs install against the same loopback ifindex; the
        // dedup table should hand back the same gid both times so we
        // create only one kernel nhid.
        let mut nmap = NexthopMap::default();
        let gid_a = group_gid(nmap.fetch(&end_uni(1)).expect("group"));
        let gid_b = group_gid(nmap.fetch(&end_uni(1)).expect("group"));
        assert_eq!(gid_a, gid_b);
    }

    #[test]
    fn fetch_seg6local_distinguishes_endx_neighbors() {
        // Distinct adjacencies (different nh6 link-locals) must NOT
        // share an nh_id — each End.X install is its own kernel entry.
        let mut nmap = NexthopMap::default();
        let gid_a = group_gid(nmap.fetch(&endx_uni(2, "fe80::1")).expect("group"));
        let gid_b = group_gid(nmap.fetch(&endx_uni(2, "fe80::2")).expect("group"));
        assert_ne!(gid_a, gid_b);
    }

    #[test]
    fn fetch_seg6local_distinguishes_action_kinds() {
        // End and End.X with otherwise-identical dedup-key fields are
        // still different actions on the wire — keep them separate so
        // we don't accidentally emit one kernel encap for both.
        let mut nmap = NexthopMap::default();
        let gid_end = group_gid(nmap.fetch(&end_uni(2)).expect("group"));
        // End.X with empty/unspec nh6 is invalid in practice but the
        // dedup key must still discriminate by action so a bug-y caller
        // can't collapse the two.
        let endx = NexthopUni {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ifindex_origin: Some(2),
            seg6local_action: Some(crate::rib::SidBehavior::EndX),
            ..Default::default()
        };
        let gid_endx = group_gid(nmap.fetch(&endx).expect("group"));
        assert_ne!(gid_end, gid_endx);
    }

    #[test]
    fn fetch_dispatches_seg6local_before_seg6_or_uni() {
        // An End SID has addr=:: and segs=[] — without the seg6local
        // priority gate it would route through fetch_uni and pollute
        // the plain-unicast map.
        let mut nmap = NexthopMap::default();
        nmap.fetch(&end_uni(1));
        assert_eq!(nmap.seg6local.len(), 1);
        assert!(nmap.map.is_empty());
        assert!(nmap.seg6.is_empty());
    }
}
