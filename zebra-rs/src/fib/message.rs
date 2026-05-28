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
    /// `IFLA_MASTER` ifindex for slave interfaces — the bridge or VRF
    /// this link is enslaved to. None for top-level links.
    pub master: Option<u32>,
    /// VNI from `LinkInfo::Data(InfoData::Vxlan(InfoVxlan::Id(_)))` on
    /// VXLAN links. Used by the EVPN advertise path to map a bridge
    /// (via its VXLAN slave) to the L2VPN VNI it carries.
    pub vni: Option<u32>,
    /// Local VTEP source IP from `IFLA_VXLAN_LOCAL` (4 bytes IPv4) or
    /// `IFLA_VXLAN_LOCAL6` (16 bytes IPv6) on VXLAN links — i.e. the
    /// `local` address shown by `ip -d link show <vxlan>`. Used by
    /// the EVPN advertise path as the BGP nexthop in MP_REACH_NLRI
    /// per RFC 8365 §5.1.3 (egress PE = local VTEP). None on
    /// non-VXLAN links and on VXLANs configured without a local IP.
    pub vxlan_local: Option<std::net::IpAddr>,
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
    /// Kernel routing-table id the route belongs to (`rtm_table`, or
    /// the `RTA_TABLE` attribute for ids > 255). `RT_TABLE_MAIN` (254)
    /// for the default table; a VRF's table id otherwise. Lets the RIB
    /// dispatch a learned route into the matching `vrf_tables` entry.
    pub table_id: u32,
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
    /// Kernel nexthop-object id from RTM_NEWNEXTHOP — usually the echo
    /// of our own install; reconciled in `Rib::process_fib_msg`.
    NewNexthop(u32),
    /// Kernel nexthop-object id from RTM_DELNEXTHOP. Signals the kernel
    /// dropped a nexthop (link down / gateway unreachable / manual
    /// delete); drives `NexthopMap` reconciliation so the group gets
    /// reinstalled.
    DelNexthop(u32),
    NewNeighbor(FibNeighbor),
    DelNeighbor(FibNeighbor),
}
