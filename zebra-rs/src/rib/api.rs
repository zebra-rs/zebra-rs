use std::net::Ipv4Addr;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::{Link, MacAddr, Rib, link::LinkAddr};

/// One bridge-FDB row, distilled from the larger `FibNeighbor` so
/// subscribers don't need to drag the full address-family / state
/// surface around. Sent on `Rib::neighbors` insert / remove for
/// AF_BRIDGE entries whose master maps to a known VNI.
///
/// `flags` carries the kernel's `NTF_*` bits — most importantly
/// `NTF_EXT_LEARNED` (bit 0x10), which an EVPN advertise consumer
/// must check to avoid re-advertising MACs that this same daemon
/// just installed from a remote peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdbEntry {
    pub vni: u32,
    pub mac: MacAddr,
    pub ifindex: u32,
    pub bridge_ifindex: u32,
    pub flags: u8,
}

#[allow(dead_code)]
pub struct RibRxChannel {
    pub tx: UnboundedSender<RibRx>,
    pub rx: UnboundedReceiver<RibRx>,
}

impl RibRxChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

// Message from rib to protocol module.
#[derive(Debug, PartialEq)]
pub enum RibRx {
    LinkAdd(Link),
    LinkUp(u32),
    LinkDown(u32),
    AddrAdd(LinkAddr),
    AddrDel(LinkAddr),
    RouterIdUpdate(Ipv4Addr),
    /// Bridge FDB entry just learned (or installed) on this host —
    /// emitted by RIB when a `FibMessage::NewNeighbor` for an
    /// AF_BRIDGE entry resolves to a known VNI. The EVPN advertise
    /// path consumes this to originate Type-2 routes.
    FdbAdd(FdbEntry),
    /// Inverse of `FdbAdd` — emitted on `FibMessage::DelNeighbor`.
    FdbDel(FdbEntry),
    EoR,
}

impl Rib {
    pub fn api_link_add(&self, link: &Link) {
        for tx in self.redists.iter() {
            let link = RibRx::LinkAdd(link.clone());
            let _ = tx.send(link);
        }
    }

    pub fn api_link_up(&self, ifindex: u32) {
        for tx in self.redists.iter() {
            let _ = tx.send(RibRx::LinkUp(ifindex));
        }
    }

    pub fn api_link_down(&self, ifindex: u32) {
        for tx in self.redists.iter() {
            let _ = tx.send(RibRx::LinkDown(ifindex));
        }
    }

    pub fn api_addr_add(&self, addr: &LinkAddr) {
        for tx in self.redists.iter() {
            let link = RibRx::AddrAdd(addr.clone());
            let _ = tx.send(link);
        }
    }

    pub fn api_router_id_update(&self, router_id: Ipv4Addr) {
        for tx in self.redists.iter() {
            let _ = tx.send(RibRx::RouterIdUpdate(router_id));
        }
    }

    pub fn api_fdb_add(&self, entry: &FdbEntry) {
        for tx in self.redists.iter() {
            let _ = tx.send(RibRx::FdbAdd(entry.clone()));
        }
    }

    pub fn api_fdb_del(&self, entry: &FdbEntry) {
        for tx in self.redists.iter() {
            let _ = tx.send(RibRx::FdbDel(entry.clone()));
        }
    }
}
