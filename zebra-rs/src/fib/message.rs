use std::net::IpAddr;

use ipnet::IpNet;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::neighbour::{NeighbourFlags, NeighbourState};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::rib::{MacAddr, entry::RibEntry};

use super::LinkType;

#[derive(Debug)]
pub struct FibChannel {
    pub tx: UnboundedSender<FibMessage>,
    pub rx: UnboundedReceiver<FibMessage>,
}

impl FibChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

#[derive(Default, Debug, Clone)]
pub struct FibLink {
    pub index: u32,
    pub name: String,
    pub flags: LinkFlags,
    pub link_type: LinkType,
    pub mtu: u32,
    pub mac: Option<MacAddr>,
}

impl FibLink {
    pub fn new() -> FibLink {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Default, Debug)]
pub struct FibAddr {
    pub addr: IpNet,
    pub link_index: u32,
    pub secondary: bool,
}

impl FibAddr {
    #[allow(dead_code)]
    pub fn new() -> FibAddr {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct FibRoute {
    pub prefix: IpNet,
    pub entry: RibEntry,
}

/// One row from the kernel's neighbor table — covers IPv4 ARP, IPv6
/// NDP, and bridge FDB. The `family` field tells the consumer which
/// of those it is:
///
/// - `AddressFamily::Inet` — ARP entry; `dst` is the IPv4 protocol
///   address, `lladdr` is the MAC.
/// - `AddressFamily::Inet6` — NDP entry; `dst` is the IPv6 protocol
///   address, `lladdr` is the MAC.
/// - `AddressFamily::Bridge` — FDB entry; `lladdr` is the MAC, `dst`
///   is the remote VTEP IP for VXLAN-bridged entries (empty for
///   ordinary bridge ports).
///
/// `vni` is set on AF_BRIDGE entries that came in with `NDA_VNI`
/// (per-FDB-entry override of the device-wide VNI). `vlan` is the
/// 802.1Q tag on traditional bridge entries. `master` is the bridge /
/// VRF ifindex when the kernel sent `NDA_MASTER` (renamed
/// `NDA_CONTROLLER` in current uapi).
///
/// Fields are read by `Rib::neighbor_key` (for keying the `Rib::neighbors`
/// map) and by `l2_neighbor_show` (for the `show l2 neighbor` command).
/// EVPN Type-2 advertise will iterate the same map in a follow-up.
#[derive(Default, Debug, Clone)]
pub struct FibNeighbor {
    pub family: AddressFamily,
    pub ifindex: u32,
    pub state: NeighbourState,
    /// `NTF_*` flags. `NTF_EXT_LEARNED` matters for EVPN — a MAC the
    /// kernel learned from a remote VTEP (often via this very daemon's
    /// own `mac_add` push) shouldn't be re-advertised back into BGP.
    pub flags: NeighbourFlags,
    pub lladdr: Option<MacAddr>,
    pub dst: Option<IpAddr>,
    pub vlan: Option<u16>,
    pub vni: Option<u32>,
    pub master: Option<u32>,
}

#[derive(Debug)]
pub enum FibMessage {
    NewLink(FibLink),
    DelLink(FibLink),
    NewAddr(FibAddr),
    DelAddr(FibAddr),
    NewRoute(FibRoute),
    DelRoute(FibRoute),
    NewNeighbor(FibNeighbor),
    DelNeighbor(FibNeighbor),
}
