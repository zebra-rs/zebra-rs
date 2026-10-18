use std::collections::BTreeMap;
use std::net::IpAddr;

use bgp_packet::{Afi, AfiSafi, Safi};

use super::membership::PeerMembership;
use super::peer::Peer;
use super::peer_key::PeerKey;

#[derive(Debug, Default)]
pub struct PeerMap {
    map: BTreeMap<PeerKey, usize>,
    /// Live peers by ident, each beside the key it is stored under so
    /// the mutable walk needs no reverse lookup. Removal drops both
    /// entries: a peer table under link or dynamic-neighbor churn stays
    /// the size of its live peers.
    peers: BTreeMap<usize, (PeerKey, Peer)>,
    /// The next ident to hand out. Idents are never reused, not even
    /// for a re-added key: a timer event, policy reply or group member
    /// still naming a removed peer's ident finds no peer, instead of
    /// landing on whichever peer took the slot next.
    next_ident: usize,
    /// Per-AFI/SAFI index of Established peers, maintained at the FSM
    /// Established boundary and purged on removal — see
    /// [`super::membership`] for why it lives inside `PeerMap`.
    membership: PeerMembership,
}

impl PeerMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, addr: &IpAddr) -> Option<&Peer> {
        self.get_by_key(&PeerKey::Addr(*addr))
    }

    pub fn get_mut(&mut self, addr: &IpAddr) -> Option<&mut Peer> {
        self.get_mut_by_key(&PeerKey::Addr(*addr))
    }

    pub fn get_by_key(&self, key: &PeerKey) -> Option<&Peer> {
        let &idx = self.map.get(key)?;
        self.get_by_idx(idx)
    }

    pub fn get_mut_by_key(&mut self, key: &PeerKey) -> Option<&mut Peer> {
        let &idx = self.map.get(key)?;
        self.get_mut_by_idx(idx)
    }

    pub fn get_by_idx(&self, idx: usize) -> Option<&Peer> {
        self.peers.get(&idx).map(|(_, peer)| peer)
    }

    pub fn get_mut_by_idx(&mut self, idx: usize) -> Option<&mut Peer> {
        self.peers.get_mut(&idx).map(|(_, peer)| peer)
    }

    pub fn addr_of(&self, idx: usize) -> Option<IpAddr> {
        self.get_by_idx(idx).map(|p| p.address)
    }

    pub fn insert(&mut self, addr: IpAddr, peer: Peer) {
        self.insert_with_key(PeerKey::Addr(addr), peer);
    }

    /// Store `peer` under `key`. Replacing a live peer keeps its ident,
    /// so an in-place upgrade (an RA filling in a dormant
    /// interface-neighbor's link-local) or an idempotent re-add stays
    /// the same peer to everything that holds the ident. A key with no
    /// live peer gets a fresh ident.
    pub fn insert_with_key(&mut self, key: PeerKey, mut peer: Peer) {
        let idx = match self.map.get(&key) {
            Some(&idx) => {
                // Any membership held under this ident belongs to the
                // previous session, not the new peer.
                self.membership.withdraw(idx);
                idx
            }
            None => {
                let idx = self.next_ident;
                self.next_ident += 1;
                self.map.insert(key, idx);
                idx
            }
        };
        peer.ident = idx;
        self.peers.insert(idx, (key, peer));
    }

    pub fn remove(&mut self, addr: &IpAddr) -> Option<Peer> {
        self.remove_by_key(&PeerKey::Addr(*addr))
    }

    pub fn remove_by_key(&mut self, key: &PeerKey) -> Option<Peer> {
        let idx = self.map.remove(key)?;
        // The ident is never handed out again, but the index must
        // only ever hold live Established peers.
        self.membership.withdraw(idx);
        self.peers.remove(&idx).map(|(_, peer)| peer)
    }

    /// Read access for fan-outs: walk `membership().family(afi,
    /// safi)`, snapshot the idents, then re-look-up mutably via
    /// [`Self::get_mut_by_idx`].
    pub fn membership(&self) -> &PeerMembership {
        &self.membership
    }

    /// Snapshot of every live peer's ident, regardless of key variant
    /// — the general, interface-keyed-safe replacement for the
    /// addr-only `keys()` sweep. Whole-peer-set reconcilers (BFD,
    /// listener TCP-MSS / MD5 / TCP-AO) must use this and re-look-up
    /// via [`Self::get_by_idx`] / [`Self::get_mut_by_idx`]: a
    /// `PeerKey::Interface` (IPv6 unnumbered) peer cannot be
    /// round-tripped through `get(&peer.address)` — its stored key is
    /// the ifindex, not the link-local — so any helper that re-looks-up
    /// by address silently drops it. `keys()` stays for the few
    /// genuinely addr-only consumers (CLI completion of typeable
    /// neighbor addresses).
    pub fn idents(&self) -> Vec<usize> {
        self.map.values().copied().collect()
    }

    /// Snapshot of every Established peer that negotiated `(afi,
    /// safi)` — both AddPath-send and plain members. The fan-out
    /// idiom: iterate this, re-look-up mutably via
    /// [`Self::get_mut_by_idx`].
    pub fn established_idents(&self, afi: Afi, safi: Safi) -> Vec<usize> {
        self.membership
            .family(afi, safi)
            .map(|fam| fam.iter_all().collect())
            .unwrap_or_default()
    }

    /// Established `(afi, safi)` peers WITHOUT AddPath Send — the
    /// best-path-only pipeline's audience.
    pub fn established_plain_idents(&self, afi: Afi, safi: Safi) -> Vec<usize> {
        self.membership
            .family(afi, safi)
            .map(|fam| {
                fam.plain
                    .iter()
                    .copied()
                    .filter(|&idx| !self.regroup_frozen(idx, afi, safi))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether `idx` is frozen in `(afi, safi)` by a pending update-group
    /// move (`Peer::regroup_frozen`): the fan-outs skip it — it must be
    /// neither the canonical member nor a recipient of the shared cache
    /// under its changed settings — until `flush_done_*` has moved and
    /// re-synced it.
    fn regroup_frozen(&self, idx: usize, afi: Afi, safi: Safi) -> bool {
        self.get_by_idx(idx)
            .is_some_and(|p| p.regroup_frozen.contains(&AfiSafi::new(afi, safi)))
    }

    /// Established `(afi, safi)` peers WITH AddPath Send negotiated —
    /// the per-candidate pipeline's audience (every NLRI to them
    /// carries a path-id, RFC 7911 §3).
    pub fn established_addpath_idents(&self, afi: Afi, safi: Safi) -> Vec<usize> {
        self.membership
            .family(afi, safi)
            .map(|fam| {
                fam.addpath_tx
                    .iter()
                    .copied()
                    .filter(|&idx| !self.regroup_frozen(idx, afi, safi))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// (Re)compute `idx`'s family membership from its negotiated
    /// capabilities. Called from the FSM chokepoint when the session
    /// enters Established — the criteria (capability intersection,
    /// AddPath Send) are session constants fixed by the OPEN exchange,
    /// so enrolling once per session is sound.
    pub fn membership_enroll(&mut self, idx: usize) {
        let Some(peer) = self.get_by_idx(idx) else {
            return;
        };
        let families: Vec<(AfiSafi, bool)> = peer
            .cap_map
            .entries
            .iter()
            .filter(|(_, sr)| sr.send && sr.recv)
            .map(|(mp, _)| {
                (
                    AfiSafi::new(mp.afi, mp.safi),
                    peer.opt.is_add_path_send(mp.afi, mp.safi),
                )
            })
            .collect();
        // Withdraw first: a re-enroll (a new session of the same peer)
        // must not retain families only the previous session
        // negotiated.
        self.membership.withdraw(idx);
        for (afi_safi, addpath_tx) in families {
            self.membership.enroll(afi_safi, idx, addpath_tx);
        }
    }

    /// Drop `idx` from every family. Called from the FSM chokepoint on
    /// leaving Established; removal paths purge automatically.
    pub fn membership_withdraw(&mut self, idx: usize) {
        self.membership.withdraw(idx);
    }

    /// Cross-check the membership index against ground truth: every
    /// enrolled ident must be a live Established peer with the family
    /// negotiated and the AddPath half matching, and every Established
    /// peer's negotiated families must be enrolled. Runtime no-op in
    /// release builds; called from the FSM chokepoint while the
    /// fan-outs migrate from scan-and-filter to the index.
    pub fn debug_verify_membership(&self) {
        if !cfg!(debug_assertions) {
            return;
        }
        // Index → peers.
        for (afi_safi, fam) in self.membership().iter() {
            for ident in fam.iter_all() {
                let peer = self
                    .get_by_idx(ident)
                    .unwrap_or_else(|| panic!("membership {afi_safi:?} holds dead ident {ident}"));
                assert!(
                    peer.state.is_established(),
                    "membership {afi_safi:?} holds non-Established peer {}",
                    peer.address
                );
                assert!(
                    peer.is_afi_safi(afi_safi.afi, afi_safi.safi),
                    "membership {afi_safi:?} holds peer {} without the family negotiated",
                    peer.address
                );
                assert_eq!(
                    fam.classification(ident),
                    Some(peer.opt.is_add_path_send(afi_safi.afi, afi_safi.safi)),
                    "membership {afi_safi:?} AddPath half disagrees for peer {}",
                    peer.address
                );
            }
        }
        // Peers → index.
        for (_, peer) in self.peers.values() {
            if !peer.state.is_established() {
                continue;
            }
            for (mp, sr) in peer.cap_map.entries.iter() {
                if !(sr.send && sr.recv) {
                    continue;
                }
                let expected = peer.opt.is_add_path_send(mp.afi, mp.safi);
                let got = self
                    .membership()
                    .family(mp.afi, mp.safi)
                    .and_then(|fam| fam.classification(peer.ident));
                assert_eq!(
                    got,
                    Some(expected),
                    "Established peer {} negotiated {}/{} but the index disagrees",
                    peer.address,
                    mp.afi,
                    mp.safi
                );
            }
        }
    }

    // NOTE: there is deliberately no addr-only `iter()`/`iter_mut()`.
    // Both existed and were a recurring trap: they silently skipped
    // `PeerKey::Interface` (IPv6 unnumbered) peers, which excluded
    // those sessions from show output, config sweeps, and — worst —
    // the entire incremental advertise fan-out. All-peers walks must
    // use [`Self::iter_all`] / [`Self::iter_mut_all`]; addr-keyed
    // lookups go through [`Self::get`] / [`Self::keys`].

    /// Iterate every peer regardless of key variant, including
    /// `PeerKey::Interface` (IPv6 unnumbered) peers — `show bgp
    /// neighbors` needs them so an operator can observe an
    /// interface-keyed session whose remote link-local address isn't
    /// something they can name.
    pub fn iter_all(&self) -> impl Iterator<Item = (&PeerKey, &Peer)> {
        self.map
            .iter()
            .filter_map(move |(key, &idx)| self.get_by_idx(idx).map(|peer| (key, peer)))
    }

    /// Iterate every peer regardless of key variant, mutable, in ident
    /// (creation) order.
    pub fn iter_mut_all(&mut self) -> impl Iterator<Item = (&PeerKey, &mut Peer)> {
        self.peers.values_mut().map(|(key, peer)| (&*key, peer))
    }

    pub fn keys(&self) -> impl Iterator<Item = &IpAddr> {
        self.map.keys().filter_map(|key| match key {
            PeerKey::Addr(addr) => Some(addr),
            _ => None,
        })
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::peer::{Peer, State};
    use bgp_packet::{Afi, CapMultiProtocol, Direct, Safi};
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    fn make_peer(addr: IpAddr) -> Peer {
        let (tx, _rx) = mpsc::channel(1);
        // PeerMap tests don't exercise socket creation, so a parked
        // ProtoContext over a leaked inbound channel is enough.
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::unbounded_channel();
        Box::leak(Box::new(inbound_rx));
        let rib = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        let ctx = crate::context::ProtoContext::default_table(rib);
        Peer::new(0, 65000, Ipv4Addr::new(1, 1, 1, 1), 0, addr, None, tx, ctx)
    }

    #[test]
    fn insert_then_get_by_addr() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        m.insert(a, make_peer(a));
        assert!(m.get(&a).is_some());
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn iter_all_includes_interface_keyed_peers() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        m.insert(a, make_peer(a));
        m.insert_with_key(
            PeerKey::Interface(7),
            make_peer(Ipv4Addr::UNSPECIFIED.into()),
        );

        assert_eq!(m.iter_all().count(), 2, "iter_all includes interface peer");
        assert_eq!(m.iter_mut_all().count(), 2, "iter_mut_all includes both");
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn remove_by_key_clears_slot() {
        let mut m = PeerMap::new();
        let k = PeerKey::Interface(3);
        m.insert_with_key(k, make_peer(Ipv4Addr::UNSPECIFIED.into()));
        assert!(m.get_by_key(&k).is_some());

        let removed = m.remove_by_key(&k);
        assert!(removed.is_some());
        assert!(m.get_by_key(&k).is_none());
    }

    /// Mark `(afi, safi)` negotiated on the peer (cap intersection),
    /// optionally with AddPath Send — the two inputs
    /// `membership_enroll` classifies on.
    fn negotiate(peer: &mut Peer, afi: Afi, safi: Safi, addpath_tx: bool) {
        let key = CapMultiProtocol::new(&afi, &safi);
        let entry = peer
            .cap_map
            .entries
            .get_mut(&key)
            .expect("family pre-seeded in CapAfiMap");
        entry.send = true;
        entry.recv = true;
        if addpath_tx {
            peer.opt.add_path.insert(
                AfiSafi::new(afi, safi),
                Direct {
                    send: true,
                    recv: false,
                },
            );
        }
    }

    #[test]
    fn membership_enroll_classifies_per_negotiated_family() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let mut peer = make_peer(a);
        peer.state = State::Established;
        negotiate(&mut peer, Afi::Ip, Safi::Unicast, true);
        negotiate(&mut peer, Afi::Ip6, Safi::Unicast, false);
        m.insert(a, peer);
        let idx = m.get(&a).unwrap().ident;

        m.membership_enroll(idx);
        m.debug_verify_membership();

        let v4 = m.membership().family(Afi::Ip, Safi::Unicast).unwrap();
        assert_eq!(v4.classification(idx), Some(true), "AddPath-send half");
        let v6 = m.membership().family(Afi::Ip6, Safi::Unicast).unwrap();
        assert_eq!(v6.classification(idx), Some(false), "plain half");
        assert!(
            m.membership().family(Afi::Ip, Safi::MplsVpn).is_none(),
            "non-negotiated family must not be enrolled"
        );
    }

    /// The fan-out entry points: `established_addpath_idents` /
    /// `established_plain_idents` partition the family,
    /// `established_idents` is their union, and a family nobody
    /// negotiated yields an empty Vec (not a panic).
    #[test]
    fn established_ident_snapshots_partition_by_addpath() {
        let mut m = PeerMap::new();

        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let mut peer = make_peer(a);
        peer.state = State::Established;
        negotiate(&mut peer, Afi::Ip, Safi::Unicast, true);
        m.insert(a, peer);
        let a_idx = m.get(&a).unwrap().ident;
        m.membership_enroll(a_idx);

        let b: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        let mut peer = make_peer(b);
        peer.state = State::Established;
        negotiate(&mut peer, Afi::Ip, Safi::Unicast, false);
        m.insert(b, peer);
        let b_idx = m.get(&b).unwrap().ident;
        m.membership_enroll(b_idx);

        assert_eq!(
            m.established_addpath_idents(Afi::Ip, Safi::Unicast),
            vec![a_idx]
        );
        assert_eq!(
            m.established_plain_idents(Afi::Ip, Safi::Unicast),
            vec![b_idx]
        );
        let mut all = m.established_idents(Afi::Ip, Safi::Unicast);
        all.sort_unstable();
        assert_eq!(all, vec![a_idx, b_idx]);

        // A family nobody negotiated: every snapshot is empty.
        assert!(m.established_idents(Afi::Ip6, Safi::Unicast).is_empty());
        assert!(
            m.established_plain_idents(Afi::Ip6, Safi::Unicast)
                .is_empty()
        );
        assert!(
            m.established_addpath_idents(Afi::Ip6, Safi::Unicast)
                .is_empty()
        );
    }

    #[test]
    fn membership_withdraw_clears_every_family() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let mut peer = make_peer(a);
        peer.state = State::Established;
        negotiate(&mut peer, Afi::Ip, Safi::Unicast, false);
        negotiate(&mut peer, Afi::Ip6, Safi::Unicast, false);
        m.insert(a, peer);
        let idx = m.get(&a).unwrap().ident;
        m.membership_enroll(idx);

        // What the FSM chokepoint does on leaving Established.
        m.get_mut(&a).unwrap().state = State::Idle;
        m.membership_withdraw(idx);
        m.debug_verify_membership();

        assert!(m.membership().family(Afi::Ip, Safi::Unicast).is_none());
        assert!(m.membership().family(Afi::Ip6, Safi::Unicast).is_none());
    }

    #[test]
    fn remove_purges_membership() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let mut peer = make_peer(a);
        peer.state = State::Established;
        negotiate(&mut peer, Afi::Ip, Safi::Unicast, true);
        m.insert(a, peer);
        let idx = m.get(&a).unwrap().ident;
        m.membership_enroll(idx);

        // Remove WITHOUT an explicit withdraw — the purge must be
        // structural, or the index keeps a dead ident.
        m.remove(&a);
        assert!(
            m.membership().family(Afi::Ip, Safi::Unicast).is_none(),
            "removal must purge membership"
        );

        // The fresh (non-Established, nothing negotiated) peer must
        // start with no membership.
        m.insert(a, make_peer(a));
        m.debug_verify_membership();
        assert!(m.membership().family(Afi::Ip, Safi::Unicast).is_none());
    }

    /// A removed peer's ident is never handed out again, not even to
    /// the same key: anything still holding it (a queued timer event,
    /// a policy reply, a group member) must find no peer rather than
    /// the next occupant.
    #[test]
    fn readded_key_gets_a_fresh_ident() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let b: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        m.insert(a, make_peer(a));
        let old = m.get(&a).unwrap().ident;

        m.remove(&a);
        m.insert(b, make_peer(b));
        m.insert(a, make_peer(a));
        let new = m.get(&a).unwrap().ident;

        assert_ne!(new, old, "same key, new ident");
        assert_ne!(m.get(&b).unwrap().ident, old, "other key, new ident");
        assert!(m.get_by_idx(old).is_none(), "the old ident names no peer");
    }

    /// Replacing a live peer keeps its ident: the dormant
    /// interface-neighbor's RA upgrade and the VRF's idempotent re-add
    /// both rely on it.
    #[test]
    fn insert_over_live_key_keeps_the_ident() {
        let mut m = PeerMap::new();
        let k = PeerKey::Interface(7);
        m.insert_with_key(k, make_peer(Ipv4Addr::UNSPECIFIED.into()));
        let idx = m.get_by_key(&k).unwrap().ident;

        m.insert_with_key(k, make_peer(Ipv4Addr::UNSPECIFIED.into()));
        assert_eq!(m.get_by_key(&k).unwrap().ident, idx);
        assert_eq!(m.len(), 1);
    }

    /// Removal frees the peer's entries, so a table under churn (an
    /// interface-neighbor link re-created on a new ifindex each time,
    /// dynamic neighbors from ever-new source addresses) holds only
    /// its live peers.
    #[test]
    fn removal_frees_the_entries() {
        let mut m = PeerMap::new();
        for ifindex in 0..100 {
            let k = PeerKey::Interface(ifindex);
            m.insert_with_key(k, make_peer(Ipv4Addr::UNSPECIFIED.into()));
            m.remove_by_key(&k);
        }
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        m.insert(a, make_peer(a));

        assert_eq!(m.map.len(), 1);
        assert_eq!(m.peers.len(), 1);
        assert_eq!(m.iter_mut_all().count(), 1);
    }

    #[test]
    fn insert_over_live_slot_purges_membership() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let mut peer = make_peer(a);
        peer.state = State::Established;
        negotiate(&mut peer, Afi::Ip, Safi::Unicast, false);
        m.insert(a, peer);
        let idx = m.get(&a).unwrap().ident;
        m.membership_enroll(idx);

        // Re-insert over the live slot (no remove in between) — the
        // replacement must not inherit the old session's membership.
        m.insert(a, make_peer(a));
        m.debug_verify_membership();
        assert!(m.membership().family(Afi::Ip, Safi::Unicast).is_none());
    }

    #[test]
    fn keys_only_yields_addr_variants() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        m.insert(a, make_peer(a));
        m.insert_with_key(
            PeerKey::Interface(11),
            make_peer(Ipv4Addr::UNSPECIFIED.into()),
        );

        let keys: Vec<IpAddr> = m.keys().copied().collect();
        assert_eq!(keys, vec![a]);
    }

    /// `idents()` is the general, interface-keyed-safe sweep accessor:
    /// unlike `keys()` it must include `PeerKey::Interface` peers, and
    /// it must drop removed peers. This is the contract the
    /// transport reconcilers (BFD / TCP-MSS / MD5 / TCP-AO) rely on.
    #[test]
    fn idents_includes_interface_keyed_and_skips_removed() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        m.insert(a, make_peer(a));
        let a_idx = m.get(&a).unwrap().ident;
        m.insert_with_key(
            PeerKey::Interface(11),
            make_peer(Ipv4Addr::UNSPECIFIED.into()),
        );
        let if_idx = m.get_by_key(&PeerKey::Interface(11)).unwrap().ident;

        let mut idents = m.idents();
        idents.sort_unstable();
        assert_eq!(
            idents,
            {
                let mut v = vec![a_idx, if_idx];
                v.sort_unstable();
                v
            },
            "idents() must include both addr- and interface-keyed peers"
        );

        // Remove the addr-keyed peer: its ident must drop out.
        m.remove(&a);
        assert_eq!(m.idents(), vec![if_idx], "idents() must skip removed peers");
    }
}
