use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr},
};

use isis_packet::srv6::EncapType;

use crate::fib::FibHandle;

use super::{Group, GroupMulti, GroupProtect, GroupTrait, GroupUni, NexthopUni};

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
    map: BTreeMap<(u32, IpAddr), usize>,
    set: BTreeMap<BTreeSet<(usize, u8)>, usize>,
    mpls: BTreeMap<(IpAddr, Vec<u32>), usize>,
    seg6: BTreeMap<Seg6Key, usize>,
    seg6local: BTreeMap<Seg6LocalKey, usize>,
    // Dedupe key for protection indirection groups: (primary gid,
    // backup gid). Two prefixes sharing a primary but with different
    // repairs get distinct groups so each switches to its own repair.
    protect: BTreeMap<(usize, usize), usize>,
    pub groups: Vec<Option<Group>>,
}

impl Group {
    pub fn from_nexthop_uni(uni: &NexthopUni, gid: usize, table_id: u32) -> Self {
        Group::Uni(GroupUni::new(gid, uni, table_id))
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
            protect: BTreeMap::new(),
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

    pub fn fetch_uni(&mut self, uni: &NexthopUni, table_id: u32) -> Option<&mut Group> {
        if let Some(&gid) = self.map.get(&(table_id, uni.addr)) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid, table_id));
            } else if let Some(Group::Uni(g)) = entry
                && g.ifindex_origin.is_none()
                && uni.ifindex_origin.is_some()
            {
                // A later install pinned an on-link egress the cached
                // group was created without (the VRF-static on-link
                // stamp — see `Rib::stamp_vrf_onlink`). Adopt it so the
                // shared group resolves on-link instead of re-walking a
                // table whose connected route the VRF enslave flushed.
                g.ifindex_origin = uni.ifindex_origin;
                g.set_valid(true);
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid, table_id);

        self.map.insert((table_id, uni.addr), gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    pub fn fetch_mpls(&mut self, uni: &NexthopUni, table_id: u32) -> Option<&mut Group> {
        if let Some(&gid) = self.mpls.get(&(uni.addr, uni.mpls_label.clone())) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid, table_id));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid, table_id);

        self.mpls.insert((uni.addr, uni.mpls_label.clone()), gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    /// Fetch (or create) the dedup'd nexthop entry for an SRv6-encapsulated
    /// nexthop. Two NexthopUnis with the same (addr, segs, encap_type) share
    /// one Group — one kernel nhid is shared across every route that uses
    /// the same SRv6 policy.
    pub fn fetch_seg6(&mut self, uni: &NexthopUni, table_id: u32) -> Option<&mut Group> {
        let key: Seg6Key = (uni.addr, uni.segs.clone(), uni.encap_type);
        if let Some(&gid) = self.seg6.get(&key) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid, table_id));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid, table_id);

        self.seg6.insert(key, gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    /// Fetch (or create) the dedup'd nexthop entry for an SRv6 seg6local
    /// nexthop (End / End.X). Keyed on (action, oif, nh6) so two SIDs
    /// pointing at the same install target share one Group.
    pub fn fetch_seg6local(&mut self, uni: &NexthopUni, table_id: u32) -> Option<&mut Group> {
        let action = uni.seg6local_action?;
        let nh6 = match uni.addr {
            IpAddr::V6(a) if !a.is_unspecified() => Some(a),
            _ => None,
        };
        let key: Seg6LocalKey = (action, uni.ifindex().unwrap_or(0), nh6);
        if let Some(&gid) = self.seg6local.get(&key) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid, table_id));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid, table_id);

        self.seg6local.insert(key, gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    pub fn fetch(&mut self, uni: &NexthopUni, table_id: u32) -> Option<&mut Group> {
        // seg6local takes priority over plain unicast — `addr` for an
        // End SID is unspecified and would route through fetch_uni
        // otherwise, collapsing every End SID into a single shared
        // entry by accident.
        if uni.seg6local_action.is_some() {
            self.fetch_seg6local(uni, table_id)
        } else if !uni.segs.is_empty() {
            // SRv6 encap — the segment list is the dedup dimension,
            // and we want SRv6 nexthops in their own table so the FIB
            // nexthop_add path can emit seg6 attributes without
            // re-inspecting NexthopUni.
            self.fetch_seg6(uni, table_id)
        } else if uni.mpls_label.is_empty() {
            self.fetch_uni(uni, table_id)
        } else {
            self.fetch_mpls(uni, table_id)
        }
    }

    /// Fetch (or create) the protection indirection group for a
    /// (primary, backup) member pair. Protected routes reference this
    /// gid; phase 2's switchover replaces its membership in place.
    pub fn fetch_protect(&mut self, primary_gid: usize, backup_gid: usize) -> Option<&mut Group> {
        let key = (primary_gid, backup_gid);
        if let Some(&gid) = self.protect.get(&key) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::Protect(GroupProtect::new(
                    gid,
                    primary_gid,
                    backup_gid,
                )));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::Protect(GroupProtect::new(gid, primary_gid, backup_gid));

        self.protect.insert(key, gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    /// Protection groups eligible for a fast-reroute switchover onto
    /// their repair because their ACTIVE side rides the failed
    /// primary `(table_id, addr)`. Pure selection — the caller flips
    /// the state and issues the kernel replace. A candidate must:
    ///
    ///   - still be on its primary (an already-switched group has
    ///     nothing left to protect with),
    ///   - have a Uni backup member (a Multi backup can't be a group
    ///     member — kernel groups don't nest; ECMP primaries are
    ///     served by leg eviction instead),
    ///   - have that backup's kernel object alive (valid +
    ///     installed), or the swap would point routes at nothing.
    ///
    /// SRv6 backups are eligible like any other: seg6 lwtunnel
    /// members forward correctly through groups (the earlier
    /// "inline-in-group black-hole" claim was refuted by kfree_skb
    /// drop-reason tracing — see the design doc correction).
    pub fn protect_switch_candidates(&self, table_id: u32, addr: IpAddr) -> Vec<usize> {
        self.groups
            .iter()
            .flatten()
            .filter_map(|grp| {
                let Group::Protect(pro) = grp else {
                    return None;
                };
                if pro.active != super::ProtectActive::Primary {
                    return None;
                }
                let primary = self.get_uni(pro.primary_gid)?;
                if primary.table_id != table_id || primary.addr != addr {
                    return None;
                }
                let backup = self.get_uni(pro.backup_gid)?;
                if !backup.is_valid() || !backup.is_installed() {
                    return None;
                }
                Some(pro.gid())
            })
            .collect()
    }

    /// ECMP groups eligible for leg eviction on a BFD-detected
    /// failure of `(table_id, addr)`: every `Multi` whose LIVE
    /// membership still carries a member uni at that address.
    /// Returns `(multi_gid, member_gid)` pairs.
    ///
    /// TI-LFA deliberately computes no repair for SPF-level ECMP
    /// destinations — the surviving legs ARE the protection — so for
    /// Multi nexthops the fast path is eviction, not a repair swap.
    /// This intentionally covers Multi groups shared with routes the
    /// caller didn't know about: they lose the same dead leg, which
    /// is the correct outcome (design doc, shared-group note).
    pub fn protect_evict_candidates(&self, table_id: u32, addr: IpAddr) -> Vec<(usize, usize)> {
        self.groups
            .iter()
            .flatten()
            .filter_map(|grp| {
                let Group::Multi(multi) = grp else {
                    return None;
                };
                for (m, _w) in multi.valid.iter() {
                    if let Some(uni) = self.get_uni(*m)
                        && uni.table_id == table_id
                        && uni.addr == addr
                    {
                        return Some((multi.gid(), *m));
                    }
                }
                None
            })
            .collect()
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
        // Indirection groups first — a group must leave the kernel
        // before its members so member deletion can't cascade-empty
        // it behind our back.
        for (_, id) in self.protect.iter() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
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
            Group::Protect(pro) => pro.gid(),
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
        let gid_a = group_gid(nmap.fetch(&uni, 0).expect("group"));
        let gid_b = group_gid(nmap.fetch(&uni, 0).expect("group"));
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
        let gid_one = group_gid(nmap.fetch(&one, 0).expect("group"));
        let gid_two = group_gid(nmap.fetch(&two, 0).expect("group"));
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
        let gid_a = group_gid(nmap.fetch(&h_encap, 0).expect("group"));
        let gid_b = group_gid(nmap.fetch(&h_red, 0).expect("group"));
        assert_ne!(gid_a, gid_b);
    }

    #[test]
    fn fetch_uni_unaffected_by_seg6_path() {
        // Plain (non-SRv6) NexthopUnis still go through fetch_uni — no
        // accidental routing through the seg6 table.
        let mut nmap = NexthopMap::default();
        let plain_a = plain_uni("2001:db8::1");
        let plain_b = plain_uni("2001:db8::1");
        let gid_a = group_gid(nmap.fetch(&plain_a, 0).expect("group"));
        let gid_b = group_gid(nmap.fetch(&plain_b, 0).expect("group"));
        assert_eq!(gid_a, gid_b);

        // The seg6 dedupe table stays empty.
        assert!(nmap.seg6.is_empty());

        // And a Nexthop::Uni constructed from a plain uni surfaces empty
        // segs / None encap_type on the resulting GroupUni.
        let grp = nmap.fetch(&plain_a, 0).expect("group");
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
        let grp = nmap.fetch(&uni, 0).expect("group");
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
        nmap.fetch(&plain_uni("2001:db8::1"), 0);
        assert_eq!(nmap.map.len(), 1);
        assert!(nmap.mpls.is_empty());
        assert!(nmap.seg6.is_empty());

        // MPLS.
        let mpls_uni = NexthopUni {
            addr: "10.0.0.1".parse().unwrap(),
            mpls_label: vec![100, 200],
            ..Default::default()
        };
        nmap.fetch(&mpls_uni, 0);
        assert_eq!(nmap.mpls.len(), 1);
        assert!(nmap.seg6.is_empty());

        // SRv6.
        nmap.fetch(
            &srv6_uni(
                "fcbb:bbbb:2:3:2::",
                &["fcbb:bbbb:2:3:2::"],
                EncapType::HEncap,
            ),
            0,
        );
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
        let gid_a = group_gid(nmap.fetch(&end_uni(1), 0).expect("group"));
        let gid_b = group_gid(nmap.fetch(&end_uni(1), 0).expect("group"));
        assert_eq!(gid_a, gid_b);
    }

    #[test]
    fn fetch_seg6local_distinguishes_endx_neighbors() {
        // Distinct adjacencies (different nh6 link-locals) must NOT
        // share an nh_id — each End.X install is its own kernel entry.
        let mut nmap = NexthopMap::default();
        let gid_a = group_gid(nmap.fetch(&endx_uni(2, "fe80::1"), 0).expect("group"));
        let gid_b = group_gid(nmap.fetch(&endx_uni(2, "fe80::2"), 0).expect("group"));
        assert_ne!(gid_a, gid_b);
    }

    #[test]
    fn fetch_seg6local_distinguishes_action_kinds() {
        // End and End.X with otherwise-identical dedup-key fields are
        // still different actions on the wire — keep them separate so
        // we don't accidentally emit one kernel encap for both.
        let mut nmap = NexthopMap::default();
        let gid_end = group_gid(nmap.fetch(&end_uni(2), 0).expect("group"));
        // End.X with empty/unspec nh6 is invalid in practice but the
        // dedup key must still discriminate by action so a bug-y caller
        // can't collapse the two.
        let endx = NexthopUni {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ifindex_origin: Some(2),
            seg6local_action: Some(crate::rib::SidBehavior::EndX),
            ..Default::default()
        };
        let gid_endx = group_gid(nmap.fetch(&endx, 0).expect("group"));
        assert_ne!(gid_end, gid_endx);
    }

    #[test]
    fn fetch_dispatches_seg6local_before_seg6_or_uni() {
        // An End SID has addr=:: and segs=[] — without the seg6local
        // priority gate it would route through fetch_uni and pollute
        // the plain-unicast map.
        let mut nmap = NexthopMap::default();
        nmap.fetch(&end_uni(1), 0);
        assert_eq!(nmap.seg6local.len(), 1);
        assert!(nmap.map.is_empty());
        assert!(nmap.seg6.is_empty());
    }
}
