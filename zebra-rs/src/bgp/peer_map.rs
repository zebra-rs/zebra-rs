use std::collections::BTreeMap;
use std::net::IpAddr;

use super::peer::Peer;
use super::peer_key::PeerKey;

#[derive(Debug, Default)]
pub struct PeerMap {
    map: BTreeMap<PeerKey, usize>,
    peers: Vec<Option<Peer>>,
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
        self.peers[idx].take()
    }

    /// Iterate over peers keyed by remote address. Interface-keyed
    /// peers (when they exist) are skipped — use [`Self::iter_all`]
    /// for full iteration including those.
    pub fn iter(&self) -> impl Iterator<Item = (&IpAddr, &Peer)> {
        self.map.iter().filter_map(move |(key, &idx)| match key {
            PeerKey::Addr(addr) => self.peers[idx].as_ref().map(|peer| (addr, peer)),
            PeerKey::Interface(_) => None,
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&IpAddr, &mut Peer)> {
        let map = &self.map;
        self.peers
            .iter_mut()
            .enumerate()
            .filter_map(move |(idx, slot)| {
                let peer = slot.as_mut()?;
                map.iter()
                    .find(|(_, mapped_idx)| **mapped_idx == idx)
                    .and_then(|(key, _)| match key {
                        PeerKey::Addr(addr) => Some((addr, peer)),
                        PeerKey::Interface(_) => None,
                    })
            })
    }

    /// Iterate every peer regardless of key variant. Unlike
    /// [`Self::iter`], this includes `PeerKey::Interface` (IPv6
    /// unnumbered) peers — `show ip bgp neighbors` needs them so an
    /// operator can observe an interface-keyed session whose remote
    /// link-local address isn't something they can name.
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
    use crate::bgp::peer::Peer;
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
    fn insert_with_interface_key_does_not_appear_in_iter() {
        let mut m = PeerMap::new();
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        m.insert(a, make_peer(a));
        m.insert_with_key(
            PeerKey::Interface(7),
            make_peer(Ipv4Addr::UNSPECIFIED.into()),
        );

        assert_eq!(m.iter().count(), 1, "addr-only iter skips interface peer");
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
