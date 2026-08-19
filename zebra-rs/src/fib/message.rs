use std::net::IpAddr;

use ipnet::IpNet;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::neighbour::{NeighbourFlags, NeighbourState};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::rib::{
    MacAddr,
    entry::RibEntry,
    link::{AddrFlags, AddrScope},
};

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
    /// Kernel routing table from `IFLA_VRF_TABLE`
    /// (`LinkInfo::Data(InfoData::Vrf(InfoVrf::TableId(_)))`) on VRF
    /// master devices. None for every other link type. Lets an
    /// all-VRF consumer (the cradle port reconcile) resolve a slave's
    /// `master` to its VRF table without the RIB's registry.
    pub vrf_table: Option<u32>,
    /// This device is a kernel bridge (`LinkInfo::Kind(InfoKind::Bridge)`).
    /// The cradle port reconcile uses it to classify a slave's `master`:
    /// bridge ⇒ L2 port in the bridge's flood domain, VRF ⇒ routed port
    /// in that table.
    pub bridge: bool,
    /// Lower-device ifindex from `IFLA_LINK` — set on stacked devices
    /// such as 802.1Q VLAN sub-interfaces, where it is the interface
    /// the VLAN rides on. None for top-level links.
    pub parent: Option<u32>,
    /// 802.1Q VLAN id from `IFLA_VLAN_ID`
    /// (`LinkInfo::Data(InfoData::Vlan(InfoVlan::Id(_)))`). Presence is
    /// what marks the link as a VLAN sub-interface — the name is never
    /// parsed; `eth0.100` is only a convention.
    pub vlan_id: Option<u16>,
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
    /// Kernel `ifa_scope` from the address message header.
    pub scope: AddrScope,
    /// Normalized `IFA_FLAGS` state (tentative/deprecated/temporary/…).
    pub flags: AddrFlags,
    /// Remaining valid lifetime from `IFA_CACHEINFO`; `u32::MAX` =
    /// forever, `None` = the platform didn't report one.
    pub valid_lft: Option<u32>,
    /// Remaining preferred lifetime; see `valid_lft`.
    pub preferred_lft: Option<u32>,
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

/// The forwarding plane's verdict on a route we installed.
///
/// SONiC's `fpmsyncd` reports this over FPM once a route is programmed
/// (or, with `suppress-fib-pending` off, optimistically on receipt), and
/// it is what `bgp suppress-fib-pending` waits on before advertising a
/// prefix. Deliberately named for the concept rather than for FPM: any
/// forwarding agent that can confirm programming reports the same thing.
///
/// The field set is dictated by what the wire actually carries. FPM's
/// acknowledgement has no nexthop and no correlation id in either of its
/// two shapes, so `(prefix, vrf_ifindex, protocol)` is the whole match
/// key available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOffload {
    pub prefix: IpNet,
    /// VRF device ifindex; 0 for the default VRF.
    pub vrf_ifindex: u32,
    /// The route's protocol byte, echoed back.
    pub protocol: u8,
    /// `false` when the agent reported the programming *failed*.
    pub success: bool,
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
    /// Bridge multicast database entry from kernel IGMP/MLD snooping
    /// (`RTM_NEWMDB`). Drives EVPN SMET (Type-6) origination.
    NewMdb(FibMdbEntry),
    /// Inverse of `NewMdb` (`RTM_DELMDB`).
    DelMdb(FibMdbEntry),
    /// The forwarding plane confirmed (or rejected) a route install.
    /// Raised by the FPM tee; see [`RouteOffload`].
    RouteOffload(RouteOffload),
    /// The kernel netlink monitor socket overran (`ENOBUFS`): its
    /// receive queue was full, so the kernel dropped an unknown number
    /// of notifications before we could read them. Multicast netlink
    /// has no flow control — this is the only signal that our mirrors
    /// of kernel state may have silently diverged. Handled by
    /// `Rib::netlink_overrun_resync`, which re-dumps the replay-safe
    /// kernel tables.
    Overrun,
}

/// One kernel bridge MDB entry, reduced to the fields EVPN cares about.
/// `group`/`source` are IP (L2 MAC groups are filtered out upstream);
/// `bridge_ifindex` is the bridge the group was learned on (mapped to a
/// VNI by the RIB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibMdbEntry {
    pub bridge_ifindex: u32,
    pub vid: u16,
    pub group: IpAddr,
    pub source: Option<IpAddr>,
}
