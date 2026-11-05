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

// Dedupe keys for plain and labeled nexthops carry the egress the source
// named (`ifindex_origin`), not just the gateway. An address identifies a
// neighbor only on its own link: link-locals repeat across links, and OSPF
// hands over every attached route as 0.0.0.0 on its interface. Without it,
// the first route's interface was copied onto every route sharing the
// address.
type UniKey = (u32, IpAddr, Option<u32>);
type MplsKey = (IpAddr, Option<u32>, Vec<u32>);

pub struct NexthopMap {
    map: BTreeMap<UniKey, usize>,
    set: BTreeMap<BTreeSet<(usize, u8)>, usize>,
    mpls: BTreeMap<MplsKey, usize>,
    seg6: BTreeMap<Seg6Key, usize>,
    seg6local: BTreeMap<Seg6LocalKey, usize>,
    // Dedupe key for protection indirection groups: (primary gid,
    // backup gid). Two prefixes sharing a primary but with different
    // repairs get distinct groups so each switches to its own repair.
    protect: BTreeMap<(usize, usize), usize>,
    // Indexed by gid, which is also the kernel next-hop id. Only
    // `new_gid` may pick the next index, because it skips `reserved`
    // ids; that is why this stays private. A `None` slot is either a
    // freed group (its dedupe key still names it) or a kernel object's
    // id that was skipped, and the two look alike: never hand a `None`
    // slot out again.
    groups: Vec<Option<Group>>,
    // Ids of kernel next-hop objects we must not take, all at or above
    // `groups.len()`.
    reserved: BTreeSet<u32>,
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
            reserved: BTreeSet::new(),
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

    /// Every group, by ascending gid.
    pub fn iter(&self) -> impl Iterator<Item = &Group> {
        self.groups.iter().flatten()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Group> {
        self.groups.iter_mut().flatten()
    }

    /// Drop group `gid`. Its dedupe key keeps the gid, so the same
    /// next hop later gets the same gid back.
    pub fn remove(&mut self, gid: usize) {
        if let Some(slot) = self.groups.get_mut(gid) {
            *slot = None;
        }
    }

    fn new_gid(&mut self) -> usize {
        // `reserve` keeps every reserved id at or above the table's
        // length, so the smallest is the only one the next gid can be.
        while self
            .reserved
            .first()
            .is_some_and(|&id| id as usize == self.groups.len())
        {
            self.reserved.pop_first();
            self.groups.push(None);
        }
        self.groups.len()
    }

    /// Never hand out `id`, a kernel next-hop object that exists already.
    /// Groups are installed with `NLM_F_REPLACE`, so one of ours given
    /// that id would take the object over, and every route still
    /// forwarding through it — an earlier run's, say — would follow ours.
    /// The id is skipped only when the gids reach it, because other
    /// programs pick ids anywhere in the u32 range: systemd-networkd hashes
    /// the ids of the objects it makes for RA routes.
    pub fn reserve(&mut self, id: u32) {
        if id as usize >= self.groups.len() {
            self.reserved.insert(id);
        }
    }

    /// Another program made kernel next-hop object `id` while we run.
    /// Returns the gid of our group that has its id, if one does: that
    /// group's install would take the object over, or already did.
    ///
    /// An id past the gids is reserved, as one found at startup is. A
    /// freed gid is handed out again only to the next hop it was freed
    /// from, whose dedupe key still names it; that key is dropped, so the
    /// next hop gets a new gid when it comes back.
    pub fn foreign_object(&mut self, id: u32) -> Option<usize> {
        let gid = id as usize;
        match self.groups.get(gid) {
            None => self.reserve(id),
            Some(Some(_)) => return Some(gid),
            Some(None) => {
                self.map.retain(|_, named| *named != gid);
                self.set.retain(|_, named| *named != gid);
                self.mpls.retain(|_, named| *named != gid);
                self.seg6.retain(|_, named| *named != gid);
                self.seg6local.retain(|_, named| *named != gid);
                self.protect.retain(|_, named| *named != gid);
            }
        }
        None
    }

    pub fn fetch_uni(&mut self, uni: &NexthopUni, table_id: u32) -> Option<&mut Group> {
        let key: UniKey = (table_id, uni.addr, uni.ifindex_origin);
        if let Some(&gid) = self.map.get(&key) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid, table_id));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid, table_id);

        self.map.insert(key, gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    pub fn fetch_mpls(&mut self, uni: &NexthopUni, table_id: u32) -> Option<&mut Group> {
        let key: MplsKey = (uni.addr, uni.ifindex_origin, uni.mpls_label.clone());
        if let Some(&gid) = self.mpls.get(&key) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid, table_id));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid, table_id);

        self.mpls.insert(key, gid);
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
    /// gid; the switchover replaces its membership in place.
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
        self.iter()
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
        self.iter()
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

    /// Multi groups whose kernel membership is missing a member that
    /// rides `(table_id, addr)` — the inverse of
    /// [`Self::protect_evict_candidates`], which is why it scans `set`
    /// (the group's full membership, and its identity) rather than
    /// `valid` (what the kernel currently holds): eviction removed the
    /// leg from `valid` precisely so it would stop matching there.
    ///
    /// A leg that is legitimately still down also shows up here; that
    /// is harmless, because the nexthop sync re-derives each member's
    /// validity from link and route state before deciding what to
    /// install, and leaves such a group alone.
    pub fn protect_restore_candidates(&self, table_id: u32, addr: IpAddr) -> Vec<(usize, usize)> {
        self.iter()
            .filter_map(|grp| {
                let Group::Multi(multi) = grp else {
                    return None;
                };
                for (m, w) in multi.set.iter() {
                    if multi.valid.contains(&(*m, *w)) {
                        continue;
                    }
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
        for id in self.protect.values() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for id in self.set.values() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for id in self.map.values() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for id in self.mpls.values() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for id in self.seg6.values() {
            let entry = self.get(*id);
            if let Some(grp) = entry
                && grp.is_installed()
            {
                fib.nexthop_del(grp).await;
            }
        }
        for id in self.seg6local.values() {
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

    /// A gateway address on two interfaces is two nexthops: a link-local
    /// repeated on two links, or OSPF's 0.0.0.0 attached routes. Each keeps
    /// its own egress, with or without labels; the same address on the
    /// same interface still shares one group.
    #[test]
    fn fetch_keeps_one_group_per_egress() {
        let on = |addr: &str, ifindex: Option<u32>, labels: &[u32]| NexthopUni {
            ifindex_origin: ifindex,
            mpls_label: labels.to_vec(),
            ..plain_uni(addr)
        };
        let egress = |nmap: &mut NexthopMap, uni: &NexthopUni| match nmap.fetch(uni, 0) {
            Some(Group::Uni(g)) => (g.gid(), g.ifindex_origin),
            _ => panic!("no uni group"),
        };
        for labels in [&[][..], &[16004][..]] {
            let mut nmap = NexthopMap::default();
            let (a, a_if) = egress(&mut nmap, &on("fe80::1", Some(2), labels));
            let (b, b_if) = egress(&mut nmap, &on("fe80::1", Some(3), labels));
            let (c, c_if) = egress(&mut nmap, &on("fe80::1", None, labels));
            assert_eq!((a_if, b_if, c_if), (Some(2), Some(3), None));
            assert!(a != b && b != c && a != c, "{labels:?}");
            assert_eq!(egress(&mut nmap, &on("fe80::1", Some(3), labels)).0, b);
        }
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

    fn uni_to(last: u8) -> NexthopUni {
        NexthopUni {
            addr: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last)),
            ..Default::default()
        }
    }

    /// A reserved id — a kernel next-hop object that exists already — is
    /// never handed out. Reserving one below those already handed out
    /// changes nothing.
    #[test]
    fn a_reserved_id_is_not_handed_out() {
        let mut nmap = NexthopMap::default();
        nmap.reserve(1);
        nmap.reserve(2);
        let gid = nmap.fetch_uni(&uni_to(2), 254).map(|group| group.gid());
        assert_eq!(gid, Some(3), "past the reserved ids");
        nmap.reserve(1);
        let gid = nmap.fetch_uni(&uni_to(3), 254).map(|group| group.gid());
        assert_eq!(gid, Some(4), "the next one");
        nmap.reserve(5);
        let gid = nmap.fetch_uni(&uni_to(4), 254).map(|group| group.gid());
        assert_eq!(gid, Some(6), "not the one reserved next");
    }

    /// Other programs pick next-hop ids anywhere in the u32 range. Reserving
    /// a large one must not size the group table by it.
    #[test]
    fn a_large_reserved_id_takes_no_room() {
        let mut nmap = NexthopMap::default();
        nmap.reserve(1_000_000);
        assert_eq!(nmap.groups.len(), 1, "the table does not grow");
        let gid = nmap.fetch_uni(&uni_to(2), 254).map(|group| group.gid());
        assert_eq!(gid, Some(1), "ids below a reserved one are free");
    }

    /// A reserved id some way above the table is skipped only when the
    /// gids reach it, whichever kind of group is made then, and is
    /// skipped once.
    #[test]
    fn the_gids_step_over_a_reserved_id_when_they_reach_it() {
        let mut nmap = NexthopMap::default();
        nmap.reserve(5);
        nmap.reserve(7);
        let uni = group_gid(nmap.fetch(&uni_to(2), 254).expect("uni"));
        let labeled = NexthopUni {
            mpls_label: vec![100],
            ..uni_to(3)
        };
        let mpls = group_gid(nmap.fetch(&labeled, 254).expect("mpls"));
        let other = group_gid(nmap.fetch(&uni_to(4), 254).expect("uni"));
        let multi = nmap
            .fetch_multi(&BTreeSet::from([(uni, 1), (other, 1)]))
            .map(|group| group.gid());
        let protect = nmap.fetch_protect(uni, other).map(|group| group.gid());
        let next = group_gid(nmap.fetch(&uni_to(5), 254).expect("uni"));
        assert_eq!(
            [uni, mpls, other],
            [1, 2, 3],
            "below the reserved ids, nothing is skipped"
        );
        assert_eq!(multi, Some(4));
        assert_eq!(protect, Some(6), "5 is the kernel's");
        assert_eq!(next, 8, "and so is 7");
        assert!(nmap.reserved.is_empty(), "each is skipped once");
        assert!(nmap.get(5).is_none() && nmap.get(7).is_none());
    }

    /// An id below the gids already handed out is not kept: the gids
    /// never come back to it.
    #[test]
    fn a_reserved_id_below_the_gids_is_not_kept() {
        let mut nmap = NexthopMap::default();
        nmap.fetch(&uni_to(2), 254);
        nmap.fetch(&uni_to(3), 254);
        nmap.reserve(1);
        nmap.reserve(2);
        assert!(nmap.reserved.is_empty());
        nmap.reserve(3);
        assert_eq!(nmap.reserved, BTreeSet::from([3]));
    }

    /// An object another program makes past the gids keeps its id, as
    /// one found at startup does.
    #[test]
    fn a_foreign_object_past_the_gids_is_skipped() {
        let mut nmap = NexthopMap::default();
        assert_eq!(nmap.foreign_object(2), None);
        let gids: Vec<_> = (2..5)
            .map(|last| group_gid(nmap.fetch(&uni_to(last), 254).expect("uni")))
            .collect();
        assert_eq!(gids, [1, 3, 4]);
    }

    /// A freed gid goes back to the next hop it was freed from, unless
    /// another program has made an object with its id meanwhile.
    #[test]
    fn a_freed_gid_another_program_took_is_not_given_back() {
        let mut nmap = NexthopMap::default();
        let gid = group_gid(nmap.fetch(&uni_to(2), 254).expect("uni"));
        nmap.remove(gid);
        let again = group_gid(nmap.fetch(&uni_to(2), 254).expect("uni"));
        assert_eq!(again, gid, "the same next hop gets its gid back");
        nmap.remove(gid);
        assert_eq!(nmap.foreign_object(gid as u32), None);
        let moved = group_gid(nmap.fetch(&uni_to(2), 254).expect("uni"));
        assert_ne!(moved, gid, "not once another program has it");
        assert!(nmap.get(gid).is_none());
    }

    /// An object with the gid of a group we have is reported.
    #[test]
    fn a_foreign_object_with_a_live_gid_is_reported() {
        let mut nmap = NexthopMap::default();
        let gid = group_gid(nmap.fetch(&uni_to(2), 254).expect("uni"));
        assert_eq!(nmap.foreign_object(gid as u32), Some(gid));
    }
}
