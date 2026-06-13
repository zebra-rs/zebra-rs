use std::collections::BTreeMap;
use std::net::IpAddr;

use bgp_packet::AfiSafi;

use super::membership::PeerMembership;
use super::peer::Peer;
use super::peer_key::PeerKey;

#[derive(Debug, Default)]
pub struct PeerMap {
    map: BTreeMap<PeerKey, usize>,
    peers: Vec<Option<Peer>>,
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
        self.peers[idx].as_ref()
    }

    pub fn get_mut_by_key(&mut self, key: &PeerKey) -> Option<&mut Peer> {
        let &idx = self.map.get(key)?;
        self.peers[idx].as_mut()
    }

    pub fn get_by_idx(&self, idx: usize) -> Option<&Peer> {
        self.peers.get(idx)?.as_ref()
    }

    pub fn get_mut_by_idx(&mut self, idx: usize) -> Option<&mut Peer> {
        self.peers.get_mut(idx)?.as_mut()
    }

    pub fn addr_of(&self, idx: usize) -> Option<IpAddr> {
        self.peers.get(idx)?.as_ref().map(|p| p.address)
    }

    pub fn insert(&mut self, addr: IpAddr, peer: Peer) {
        self.insert_with_key(PeerKey::Addr(addr), peer);
    }

    pub fn insert_with_key(&mut self, key: PeerKey, mut peer: Peer) {
        if let Some(&idx) = self.map.get(&key) {
            peer.ident = idx;
            // Replacing the slot's occupant: any membership held under
            // this ident belongs to the previous session, not the new
            // peer.
            self.membership.withdraw(idx);
            self.peers[idx] = Some(peer);
        } else {
            let idx = self.peers.len();
            peer.ident = idx;
            self.map.insert(key, idx);
            self.peers.push(Some(peer));
        }
    }

    pub fn remove(&mut self, addr: &IpAddr) -> Option<Peer> {
        self.remove_by_key(&PeerKey::Addr(*addr))
    }

    pub fn remove_by_key(&mut self, key: &PeerKey) -> Option<Peer> {
        let &idx = self.map.get(key)?;
        let removed = self.peers[idx].take();
        if removed.is_some() {
            // The slot's ident is reused by a same-key re-insert;
            // purge here so the next occupant can't inherit the old
            // session's membership (the ABA hazard).
            self.membership.withdraw(idx);
        }
        removed
    }

    /// Read access for fan-outs: walk `membership().family(afi,
    /// safi)`, snapshot the idents, then re-look-up mutably via
    /// [`Self::get_mut_by_idx`].
    pub fn membership(&self) -> &PeerMembership {
        &self.membership
    }

    /// (Re)compute `idx`'s family membership from its negotiated
    /// capabilities. Called from the FSM chokepoint when the session
    /// enters Established — the criteria (capability intersection,
    /// AddPath Send) are session constants fixed by the OPEN exchange,
    /// so enrolling once per session is sound.
    pub fn membership_enroll(&mut self, idx: usize) {
        let Some(peer) = self.peers.get(idx).and_then(|slot| slot.as_ref()) else {
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
        // Withdraw first: a re-enroll (new session on a reused slot)
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
                    .peers
                    .get(ident)
                    .and_then(|slot| slot.as_ref())
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
        for peer in self.peers.iter().flatten() {
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
    /// `PeerKey::Interface` (IPv6 unnumbered) peers — `show ip bgp
    /// neighbors` needs them so an operator can observe an
    /// interface-keyed session whose remote link-local address isn't
    /// something they can name.
    pub fn iter_all(&self) -> impl Iterator<Item = (&PeerKey, &Peer)> {
        self.map
            .iter()
            .filter_map(move |(key, &idx)| self.peers[idx].as_ref().map(|peer| (key, peer)))
    }

    /// Iterate every peer regardless of key variant, mutable.
    pub fn iter_mut_all(&mut self) -> impl Iterator<Item = (&PeerKey, &mut Peer)> {
        let map = &self.map;
        self.peers
            .iter_mut()
            .enumerate()
            .filter_map(move |(idx, slot)| {
                let peer = slot.as_mut()?;
                map.iter()
                    .find(|(_, mapped_idx)| **mapped_idx == idx)
                    .map(|(key, _)| (key, peer))
            })
    }

    pub fn keys(&self) -> impl Iterator<Item = &IpAddr> {
        self.map.iter().filter_map(move |(key, &idx)| match key {
            PeerKey::Addr(addr) if self.peers[idx].is_some() => Some(addr),
            _ => None,
        })
    }

    pub fn len(&self) -> usize {
        self.map
            .values()
            .filter(|&&idx| self.peers[idx].is_some())
            .count()
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
    fn remove_purges_membership_against_slot_reuse() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let mut peer = make_peer(a);
        peer.state = State::Established;
        negotiate(&mut peer, Afi::Ip, Safi::Unicast, true);
        m.insert(a, peer);
        let idx = m.get(&a).unwrap().ident;
        m.membership_enroll(idx);

        // Remove WITHOUT an explicit withdraw — the purge must be
        // structural, or the reused ident below inherits membership.
        m.remove(&a);
        assert!(
            m.membership().family(Afi::Ip, Safi::Unicast).is_none(),
            "removal must purge membership"
        );

        // Same key → same slot/ident. The fresh (non-Established,
        // nothing negotiated) peer must start with no membership.
        m.insert(a, make_peer(a));
        assert_eq!(m.get(&a).unwrap().ident, idx, "slot is reused");
        m.debug_verify_membership();
        assert!(m.membership().family(Afi::Ip, Safi::Unicast).is_none());
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
}
