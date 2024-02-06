use crate::Peer;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub peers: Vec<Peer>,
}

impl Bgp {
    pub fn new() -> Bgp {
        Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: Vec::new(),
        }
    }

    pub fn new_instance() -> BgpInstance {
        Arc::new(RwLock::new(Self::new()))
    }
}

impl Default for Bgp {
    fn default() -> Self {
        Self::new()
    }
}

pub type BgpInstance = Arc<RwLock<Bgp>>;
