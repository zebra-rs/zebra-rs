//! PFCP node-association table for the MUP controller.
//!
//! Tracks the N4 associations (one per control-plane peer / SMF) the
//! controller has accepted. PFCP requires an established association
//! before any session message is valid; the controller answers
//! Association Setup / Release and Heartbeat to keep it alive.

use std::collections::BTreeMap;
use std::net::SocketAddr;

/// One PFCP association (N4) with a control-plane peer (SMF).
#[derive(Debug, Clone)]
pub struct MupAssocInfo {
    /// Human form of the peer's PFCP Node ID (IP or FQDN).
    pub node_id: String,
}

/// Associations keyed by PFCP peer transport address.
#[derive(Debug, Default)]
pub struct AssocTable {
    peers: BTreeMap<SocketAddr, MupAssocInfo>,
}

impl AssocTable {
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }

    pub fn upsert(&mut self, peer: SocketAddr, info: MupAssocInfo) {
        self.peers.insert(peer, info);
    }

    pub fn remove(&mut self, peer: &SocketAddr) -> Option<MupAssocInfo> {
        self.peers.remove(peer)
    }
}
