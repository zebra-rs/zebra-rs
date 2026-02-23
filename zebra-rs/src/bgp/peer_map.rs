use std::collections::BTreeMap;
use std::net::IpAddr;

use super::peer::Peer;

#[derive(Debug, Default)]
pub struct PeerMap {
    map: BTreeMap<IpAddr, usize>,
    peers: Vec<Option<Peer>>,
}

impl PeerMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, addr: &IpAddr) -> Option<&Peer> {
        let &idx = self.map.get(addr)?;
        self.peers[idx].as_ref()
    }

    pub fn get_mut(&mut self, addr: &IpAddr) -> Option<&mut Peer> {
        let &idx = self.map.get(addr)?;
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

    pub fn insert(&mut self, addr: IpAddr, mut peer: Peer) {
        if let Some(&idx) = self.map.get(&addr) {
            peer.ident = idx;
            self.peers[idx] = Some(peer);
        } else {
            let idx = self.peers.len();
            peer.ident = idx;
            self.map.insert(addr, idx);
            self.peers.push(Some(peer));
        }
    }

    pub fn remove(&mut self, addr: &IpAddr) -> Option<Peer> {
        let &idx = self.map.get(addr)?;
        self.peers[idx].take()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IpAddr, &Peer)> {
        self.map
            .iter()
            .filter_map(move |(addr, &idx)| self.peers[idx].as_ref().map(|peer| (addr, peer)))
    }

    pub fn keys(&self) -> impl Iterator<Item = &IpAddr> {
        self.map.iter().filter_map(move |(addr, &idx)| {
            if self.peers[idx].is_some() {
                Some(addr)
            } else {
                None
            }
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
