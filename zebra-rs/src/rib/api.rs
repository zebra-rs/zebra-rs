use std::net::{IpAddr, Ipv4Addr};

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
    /// Local VTEP source IP — the `local` address configured on the
    /// VXLAN slave of `bridge_ifindex` (`IFLA_VXLAN_LOCAL` /
    /// `IFLA_VXLAN_LOCAL6`). The EVPN advertise path uses this as
    /// the BGP MP_REACH nexthop per RFC 8365 §5.1.3 — that's the IP
    /// remote peers will encapsulate VXLAN packets to. None when the
    /// VXLAN was created without an explicit `local` (kernel uses
    /// 0.0.0.0 / :: in that case); callers fall back to router-id.
    pub vxlan_local: Option<IpAddr>,
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
    /// Local VXLAN device with `IFLA_VXLAN_LOCAL` set. Emitted by
    /// RIB when a VXLAN slave is registered (`register_vxlan_ifindex`
    /// path in `link_add`) and replayed at subscribe time. The EVPN
    /// advertise path uses it to originate one Type-3 (Inclusive
    /// Multicast) route per local VTEP×VNI pair.
    VxlanAdd {
        vni: u32,
        vtep_local: IpAddr,
    },
    /// Inverse of `VxlanAdd` — emitted when the VXLAN device is
    /// removed or its VNI changes.
    VxlanDel {
        vni: u32,
    },
    EoR,
}

impl Rib {
    pub fn api_link_add(&self, link: &Link) {
        for tx in self.redists.values() {
            let link = RibRx::LinkAdd(link.clone());
            let _ = tx.send(link);
        }
    }

    pub fn api_link_up(&self, ifindex: u32) {
        for tx in self.redists.values() {
            let _ = tx.send(RibRx::LinkUp(ifindex));
        }
    }

    pub fn api_link_down(&self, ifindex: u32) {
        for tx in self.redists.values() {
            let _ = tx.send(RibRx::LinkDown(ifindex));
        }
    }

    pub fn api_addr_add(&self, addr: &LinkAddr) {
        for tx in self.redists.values() {
            let link = RibRx::AddrAdd(addr.clone());
            let _ = tx.send(link);
        }
    }

    pub fn api_router_id_update(&self, router_id: Ipv4Addr) {
        for tx in self.redists.values() {
            let _ = tx.send(RibRx::RouterIdUpdate(router_id));
        }
    }

    pub fn api_fdb_add(&self, entry: &FdbEntry) {
        for tx in self.redists.values() {
            let _ = tx.send(RibRx::FdbAdd(entry.clone()));
        }
    }

    pub fn api_fdb_del(&self, entry: &FdbEntry) {
        for tx in self.redists.values() {
            let _ = tx.send(RibRx::FdbDel(entry.clone()));
        }
    }

    pub fn api_vxlan_add(&self, vni: u32, vtep_local: IpAddr) {
        for tx in self.redists.values() {
            let _ = tx.send(RibRx::VxlanAdd { vni, vtep_local });
        }
    }

    pub fn api_vxlan_del(&self, vni: u32) {
        for tx in self.redists.values() {
            let _ = tx.send(RibRx::VxlanDel { vni });
        }
    }
}
