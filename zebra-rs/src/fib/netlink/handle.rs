use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

use futures::stream::{StreamExt, TryStreamExt};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use netlink_packet_route::link::{
    AfSpecInet6, AfSpecUnspec, InfoBridgePort, InfoData, InfoKind, InfoPortData, InfoPortKind,
    InfoVlan, InfoVrf, InfoVxlan, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage,
};
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage};
use netlink_packet_route::nexthop::{NexthopAttribute, NexthopFlags, NexthopGroup, NexthopMessage};
use netlink_packet_route::route::{
    MplsLabel, RouteAddress, RouteAttribute, RouteHeader, RouteLwEnCapType, RouteLwTunnelEncap,
    RouteMessage, RouteMplsIpTunnel, RouteNextHop, RouteProtocol, RouteScope, RouteType, RouteVia,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    LinkDummy, LinkVlan, LinkVrf,
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_LINK,
        RTMGRP_NEIGH,
    },
    new_connection,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::fib::cradle::CradleFib;
use crate::fib::fpm::{FpmFib, RouteOp, encode_route};
use crate::fib::{FibAddr, FibLink, FibMdbEntry, FibMessage, FibNeighbor, FibNexthop, FibRoute};
use crate::rib::entry::RibEntry;
use crate::rib::inst::{IlmEntry, IlmType};
use crate::rib::tracing::{fib_l2_fdb, fib_l2_mdb, fib_l2_vxlan, fib_nexthop, fib_route, fib_srv6};
use crate::rib::{
    AddrGenMode, Bridge, Group, GroupTrait, MacAddr, Nexthop, NexthopMulti, NexthopUni, RibType,
    Vxlan, link,
    link::{AddrFlags, AddrScope},
    nexthop::NexthopMember,
};

/// Pull the nexthop-object id (`NHA_ID`) out of an inbound
/// RTM_NEWNEXTHOP / RTM_DELNEXTHOP. The id is the same value RIB hands
/// to the kernel as the route's `Nhid`, so it indexes `NexthopMap`
/// directly. Returns `None` for a malformed message with no id.
fn nexthop_id_from_msg(msg: &NexthopMessage) -> Option<u32> {
    msg.attributes.iter().find_map(|attr| {
        if let NexthopAttribute::Id(id) = attr {
            Some(*id)
        } else {
            None
        }
    })
}

/// Compact one-line dump of a `Nexthop` for diagnostic logging.
/// Surfaces the fields that matter when the kernel rejects an
/// install — `gid` (so we can spot `Nhid(0)` mistakes), per-leg
/// address + resolved ifindex, MPLS label stack, and per-leg
/// weight on Multi.
fn fmt_nexthop_for_trace(nh: &Nexthop) -> String {
    fn fmt_uni(u: &NexthopUni) -> String {
        format!(
            "{{addr={} ifindex={:?} gid={} metric={} mpls={:?} weight={}}}",
            u.addr,
            u.ifindex(),
            u.gid,
            u.metric,
            u.mpls,
            u.weight,
        )
    }
    fn fmt_multi(m: &NexthopMulti) -> String {
        let legs: Vec<String> = m.nexthops.iter().map(fmt_uni).collect();
        format!(
            "Multi{{gid={} metric={} legs=[{}]}}",
            m.gid,
            m.metric,
            legs.join(", ")
        )
    }
    match nh {
        Nexthop::Uni(u) => format!("Uni{}", fmt_uni(u)),
        Nexthop::Multi(m) => fmt_multi(m),
        Nexthop::List(l) => {
            let members: Vec<String> = l
                .nexthops
                .iter()
                .enumerate()
                .map(|(i, m)| match m {
                    NexthopMember::Uni(u) => format!("#{i}=Uni{}", fmt_uni(u)),
                    NexthopMember::Multi(mm) => format!("#{i}={}", fmt_multi(mm)),
                })
                .collect();
            format!("List[{}]", members.join(", "))
        }
        Nexthop::Protect(p) => {
            let fmt_member = |m: &NexthopMember| match m {
                NexthopMember::Uni(u) => format!("Uni{}", fmt_uni(u)),
                NexthopMember::Multi(mm) => fmt_multi(mm),
            };
            format!(
                "Protect[primary={} backup={}]",
                fmt_member(&p.primary),
                fmt_member(&p.backup)
            )
        }
        Nexthop::Link(ifindex) => format!("Link(ifindex={ifindex})"),
        Nexthop::Blackhole(metric) => format!("Blackhole(metric={metric})"),
    }
}

/// Compact one-line dump of a kernel-side `Group` (the
/// nexthop-table object referenced by `Nhid`). Surfaces the gid,
/// for a Uni leg the (addr, ifindex), for a Multi the member-id
/// list — enough to correlate an `RTM_NEWNEXTHOP` ENODEV with the
/// stale link that produced it.
fn fmt_group_for_trace(group: &Group) -> String {
    match group {
        Group::Uni(u) => format!(
            "Group::Uni{{gid={} addr={} ifindex={:?} valid={} installed={}}}",
            u.gid(),
            u.addr,
            u.ifindex(),
            u.is_valid(),
            u.is_installed(),
        ),
        Group::Multi(m) => {
            let members: Vec<String> = m
                .valid
                .iter()
                .map(|(id, w)| format!("({id}, w={w})"))
                .collect();
            format!(
                "Group::Multi{{gid={} members=[{}]}}",
                m.gid(),
                members.join(", ")
            )
        }
        Group::Protect(p) => format!(
            "Group::Protect{{gid={} primary={} backup={} active={:?} valid={} installed={}}}",
            p.gid(),
            p.primary_gid,
            p.backup_gid,
            p.active,
            p.is_valid(),
            p.is_installed(),
        ),
    }
}

/// The primary member of a `NexthopProtect` as the `Nexthop` the
/// per-route install/delete paths consume. When the resolver
/// allocated a protection indirection group, the route must reference
/// *its* gid instead of the member's own — that id is the handle the
/// switchover swaps. Only the gid changes; address, metric, and encap
/// stay the member's (and on `use_nhid == false` kernels the gid is
/// never read, so this is inert there).
fn protect_primary_nexthop(pro: &crate::rib::nexthop::NexthopProtect) -> Nexthop {
    let mut nh = pro.primary.as_nexthop();
    if pro.gid != 0
        && let Nexthop::Uni(u) = &mut nh
    {
        u.gid = pro.gid;
    }
    nh
}

/// Modern rtnetlink multicast group for nexthop objects
/// (`RTNLGRP_NEXTHOP`, linux/rtnetlink.h). Numbered past the legacy
/// `RTMGRP_*` bind mask, so it's joined via `add_membership`.
const RTNLGRP_NEXTHOP: u32 = 32;

/// `RTNLGRP_MDB` (linux/rtnetlink.h) — bridge multicast database
/// notifications (`RTM_{NEW,DEL}MDB`) from IGMP/MLD snooping. Past the
/// legacy `RTMGRP_*` bind mask, so joined via `add_membership`. Drives
/// EVPN SMET (RFC 9251) origination.
const RTNLGRP_MDB: u32 = 26;

/// Mask the lower (128 - prefix_len) bits of an IPv6 address. The
/// kernel ignores bits past the prefix length on install, but masking
/// keeps the netlink trace honest and the address shape predictable
/// for unit tests.
fn mask_v6(addr: std::net::Ipv6Addr, prefix_len: u8) -> std::net::Ipv6Addr {
    if prefix_len >= 128 {
        return addr;
    }
    let bits = u128::from(addr);
    let shift = 128 - u32::from(prefix_len);
    let mask = !0u128 << shift;
    std::net::Ipv6Addr::from(bits & mask)
}

/// Pick the (table, kind, prefix_len, dest_addr) the kernel needs for
/// a SID install / uninstall. Behavior-driven so install and uninstall
/// stay in lock-step:
///
///   End  : table main, kind=Unicast, /128, sid.addr
///          (`ip -6 route add <SID>/128
///           encap seg6local action End dev sr0`)
///   End.X: table main, kind=Unicast, /128, sid.addr
///   uN   : table main, kind=Unicast, /(LB+LN), masked sid.addr
///          (prefix install — the NEXT-C-SID flavor strips and shifts
///          at runtime, so any function under the locator hits this.
///          Same dummy-device trick as End: pointing the install at sr0
///          instead of lo lets us stay in table=main + kind=Unicast.)
///   uA   : table main, kind=Unicast, /128, sid.addr
///          (per-adjacency function is unique; longest-prefix match
///          picks uA over the wider uN entry)
///
/// uN with no SidStructure falls back to /128 — a degenerate state
/// (uSID locator without a derived structure shouldn't happen), but
/// keeps the call total.
///
/// Both End and uN previously hung off table=local + kind=Local + dev=lo
/// to work around the kernel rejecting unicast routes that point at the
/// loopback. Routing the seg6local action through a dummy (sr0) instead
/// gets us back into table=main with kind=Unicast across the board, which
/// keeps `ip -6 route show` honest and avoids the host-local route quirks
/// (e.g. ip-rule lookup local).
/// Stamp a `RouteMessage` with the destination routing-table id.
///
/// Kernel `rtm_table` is a single byte. Table ids `0..=255` fit
/// there; `RT_TABLE_MAIN` (254) is the historical default. Ids
/// greater than 255 — Linux VRF allocators happily hand out
/// 1000+-range ids — must travel in the `RTA_TABLE` netlink
/// attribute instead, with `rtm_table` set to `RT_TABLE_UNSPEC`
/// (0) so the kernel knows to consult the attribute.
fn set_route_table(msg: &mut RouteMessage, table_id: u32) {
    if table_id <= u8::MAX as u32 {
        msg.header.table = table_id as u8;
    } else {
        msg.header.table = RouteHeader::RT_TABLE_UNSPEC;
        msg.attributes.push(RouteAttribute::Table(table_id));
    }
}

/// The `rtm_protocol` a SID host route carries — the SID's owning
/// protocol. Shared by install and uninstall: the kernel matches
/// RTM_DELROUTE on the protocol when it is set, so a delete built with
/// a different protocol than the install returns ESRCH and the
/// seg6local route leaks in the FIB (an OSPFv3 SID uninstall did
/// exactly that while this was hard-coded to Isis on the delete side).
fn sid_route_protocol(sid: &crate::rib::Sid) -> RouteProtocol {
    match sid.owner.rib_type() {
        crate::rib::RibType::Ospf => RouteProtocol::Ospf,
        crate::rib::RibType::Bgp => RouteProtocol::Bgp,
        _ => RouteProtocol::Isis,
    }
}

fn sid_route_target(
    behavior: crate::rib::SidBehavior,
    addr: std::net::Ipv6Addr,
    structure: Option<crate::rib::SidStructure>,
) -> (u8, RouteType, u8, std::net::Ipv6Addr) {
    use crate::rib::SidBehavior;
    match behavior {
        SidBehavior::End | SidBehavior::EndT | SidBehavior::EndDX4 | SidBehavior::EndDX6 => {
            (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr)
        }
        SidBehavior::EndX => (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr),
        SidBehavior::UN | SidBehavior::UT => {
            let plen = structure
                .map(|s| s.lb_bits.saturating_add(s.ln_bits))
                .unwrap_or(128);
            (
                RouteHeader::RT_TABLE_MAIN,
                RouteType::Unicast,
                plen,
                mask_v6(addr, plen),
            )
        }
        SidBehavior::UA => (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr),
        // REPLACE-C-SID (cradle-only — never reaches the kernel): the
        // /(LB+LN+Fun) prefix leaves the index argument wild; the tee
        // takes its prefix_len from here.
        SidBehavior::EndRep | SidBehavior::EndXRep => {
            let plen = structure
                .map(|s| {
                    s.lb_bits
                        .saturating_add(s.ln_bits)
                        .saturating_add(s.fun_bits)
                })
                .unwrap_or(128);
            (
                RouteHeader::RT_TABLE_MAIN,
                RouteType::Unicast,
                plen,
                mask_v6(addr, plen),
            )
        }
        // LIB twin of a uA: a block:function prefix entry that matches
        // the uA when it is the carrier's *active* uSID (post-uN-shift
        // DA). /(LB+Fun) with the NEXT-CSID flavor — verified live on
        // 6.8 (shift while uSIDs remain, classic End.X at end-of-
        // carrier).
        SidBehavior::UALib => {
            let plen = structure
                .map(|s| s.lb_bits.saturating_add(s.fun_bits))
                .unwrap_or(128);
            (
                RouteHeader::RT_TABLE_MAIN,
                RouteType::Unicast,
                plen,
                mask_v6(addr, plen),
            )
        }
        // End.DT4 / End.DT6 / End.DT46 / End.M are terminal decap+lookup
        // actions. Same FIB shape as End.X — a /128 host route in
        // table=main with kind=Unicast, pointed at sr0 by the static
        // route's ifindex_origin. (The inner decap lookup table — a VRF
        // for End.DT*, the mirror context for End.M — rides inside the
        // seg6local encap, not here.)
        SidBehavior::EndDT4 | SidBehavior::EndDT6 | SidBehavior::EndDT46 | SidBehavior::EndM => {
            (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr)
        }
        // EVPN-over-SRv6 L2 service SIDs: same /128 host-route shape, but
        // they never reach the kernel (no End.DT2U/DT2M seg6local action) —
        // `route_sid_install` returns after the cradle tee. The target is
        // computed anyway so the tee gets the right prefix length.
        SidBehavior::EndDT2U
        | SidBehavior::EndDT2M
        | SidBehavior::EndDX2
        | SidBehavior::EndDX2V
        | SidBehavior::EndReplicate => (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr),
        // End.B6.Encaps (SR Policy Binding SID): a /128 host route in
        // table=main; the SRH it pushes rides inside the seg6local
        // encap, not in the route header.
        SidBehavior::EndB6Encap => (RouteHeader::RT_TABLE_MAIN, RouteType::Unicast, 128, addr),
    }
}

/// Check if the kernel supports nexthop ID (kernel >= 5.3).
/// Nexthop table was introduced in Linux kernel 5.3.
fn kernel_supports_nhid() -> bool {
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        // Parse "Linux version X.Y.Z-..."
        let parts: Vec<&str> = version.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "Linux" && parts[1] == "version" {
            let version_str = parts[2];
            let version_parts: Vec<&str> = version_str.split('.').collect();
            if version_parts.len() >= 2
                && let (Ok(major), Ok(minor)) = (
                    version_parts[0].parse::<u32>(),
                    version_parts[1].parse::<u32>(),
                )
            {
                // Nexthop table introduced in kernel 5.3
                return major > 5 || (major == 5 && minor >= 3);
            }
        }
    }
    // Default to false for safety
    false
}

pub struct FibHandle {
    pub handle: rtnetlink::Handle,
    pub use_nhid: bool,
    /// Install VXLAN Type-5 routes through their Linux L3-VNI bridges.
    pub kernel_route_exchange: bool,
    /// Desired bridge Type-5 routes, `(table, prefix)` → encap and kernel
    /// priority. Owns the RMAC FDB entry and VTEP neighbors each adjacency
    /// shares across prefixes. A route stays here even if the kernel
    /// rejected it (e.g. the bridge was down), so `evpn_l3vni_reassert`
    /// can install it once the bridge recovers.
    evpn_prefix_routes: std::sync::Mutex<BTreeMap<(u32, IpNet), (crate::rib::VxlanL3Encap, u32)>>,
    /// The VTEP each `(L3 VNI, RMAC)` FDB entry currently points at.
    /// Several VTEPs can advertise one RMAC; the FDB holds only one, so a
    /// withdrawal of that VTEP must re-point it at a remaining one.
    evpn_rmac_vtep: std::sync::Mutex<BTreeMap<(u32, [u8; 6]), Ipv4Addr>>,
    /// The bridge each L3 VNI's Type-5 state was installed on, so a move
    /// to another bridge can remove what was left on the old one.
    evpn_l3vni_bridge: std::sync::Mutex<BTreeMap<u32, u32>>,
    /// VNI to VXLAN interface index mapping
    /// Used to resolve VNI to the correct VXLAN device for FDB operations
    pub vni_ifindex_map: BTreeMap<u32, u32>,
    pub vni_bridge_map: BTreeMap<u32, u32>,
    pub vni_metadata_map: BTreeMap<u32, bool>,
    /// Kernel routing-table id → VRF *device ifindex*.
    ///
    /// Needed because FPM's table field is not a table id: the SONiC
    /// dplane plugin substitutes the VRF device's ifindex for it
    /// ("Put vrf if_index instead of table id", dplane_fpm_sonic.c:1232),
    /// and `fpmsyncd` resolves the value with getIfName(). The RIB owns
    /// both numbers on its `Vrf` rows; this mirrors just the mapping the
    /// FIB layer needs, the same way `vni_ifindex_map` does for VXLAN.
    pub vrf_ifindex_map: BTreeMap<u32, u32>,
    /// Optional tee of route installs into the cradle eBPF data plane. Driven by
    /// the `system cradle grpc-endpoint <endpoint>` config leaf (`set_cradle`, dispatched
    /// from `Rib::cradle_grpc_config_exec`), with `CRADLE_GRPC` as an env
    /// fallback.
    pub cradle: Option<CradleFib>,
    /// Optional tee of route installs into SONiC's FPM southbound
    /// (`fpmsyncd` -> APPL_DB -> orchagent -> SAI). Enabled by
    /// `SONIC_FPM=host:port` for now; a config leaf follows.
    pub fpm: Option<FpmFib>,
}

/// A cradle-tee route member — mirrors `crate::fib::cradle::Member`:
/// `(link gateway, oif, MPLS out-labels, SRv6 segment list, SRv6 encap mode)`.
/// A non-empty `segs` makes it an SRv6 (v6-underlay) nexthop; MPLS labels and
/// SRv6 segs are mutually exclusive per nexthop.
type CradleMember = (
    Option<IpAddr>,
    u32,
    Vec<u32>,
    Vec<std::net::Ipv6Addr>,
    u32,
    Option<crate::fib::cradle::VxlanLeg>,
    Option<crate::fib::cradle::Leaf>,
);

/// Extract a nexthop's cradle-tee members. The gateway is passed as the raw
/// `IpAddr` (v4 for plain/MPLS legs, v6 for the SRv6 underlay), plus the MPLS
/// out-label stack and the SRv6 segment list + encap mode. (Protect/backup
/// nexthops are not teed.)
fn cradle_members(nexthop: &Nexthop) -> Vec<CradleMember> {
    fn leaf(u: &NexthopUni) -> crate::fib::cradle::Leaf {
        let oif = u.ifindex().unwrap_or(0);
        let gw = match u.addr {
            a if a.is_unspecified() => None,
            a => Some(a),
        };
        let encap_mode = crate::fib::cradle::srv6_encap_mode(u.encap_type);
        let vxlan = u.vxlan.map(|v| (v.remote_vtep, v.l3vni, v.remote_rmac));
        (
            gw,
            oif,
            u.mpls_label.clone(),
            u.segs.clone(),
            encap_mode,
            vxlan,
        )
    }
    fn member(u: &NexthopUni) -> CradleMember {
        let (gw, oif, labels, segs, encap_mode, vxlan) = leaf(u);
        (gw, oif, labels, segs, encap_mode, vxlan, None)
    }
    match nexthop {
        Nexthop::Uni(u) => vec![member(u)],
        // Connected routes: an interface-only (gateway-less) member. The
        // eBPF forward falls back to `bpf_redirect_neigh` on the
        // destination itself, which also drives kernel ND — so delivery
        // to directly-connected hosts needs no pinned neighbors.
        Nexthop::Link(ifindex) => vec![(None, *ifindex, vec![], vec![], 0, None, None)],
        Nexthop::Multi(m) => m.nexthops.iter().map(member).collect(),
        Nexthop::List(l) => l
            .nexthops
            .iter()
            .filter_map(|m| match m {
                NexthopMember::Uni(u) => Some(member(u)),
                _ => None,
            })
            .collect(),
        // Fast-reroute: the primary rides with its backup leaf attached (the
        // TI-LFA repair — packed uSID carriers + H.Insert for SRv6, the
        // repair label stack for SR-MPLS), so cradle programs a protected
        // nexthop pair. ECMP primaries are teed unprotected (MVP).
        Nexthop::Protect(pro) => {
            let backup = match &pro.backup {
                NexthopMember::Uni(u) => Some(leaf(u)),
                _ => None,
            };
            match &pro.primary {
                NexthopMember::Uni(u) => {
                    let mut m = member(u);
                    m.6 = backup;
                    vec![m]
                }
                NexthopMember::Multi(mm) => mm.nexthops.iter().map(member).collect(),
            }
        }
        _ => vec![],
    }
}

/// The access VLAN of the single-VXLAN-device EVPN datapath: VLAN 1 is
/// mapped to the VNI on every VXLAN bridge port (`vxlan_svd_datapath`),
/// and the bridge-master FDB entries for remote MACs are scoped to it.
/// Scoping matters on a `vlan_filtering` bridge: an FDB add carrying no
/// `NDA_VLAN` is expanded by the kernel to VLAN 0 *plus every VLAN on
/// the port*, which both litters `bridge fdb show` with a useless VLAN-0
/// duplicate per MAC and would poison unrelated VLANs the moment a port
/// carries more than one.
const EVPN_SVD_VLAN: u16 = 1;

/// Op selector for `fdb_neigh_send`. The kernel netlink flag set
/// differs per scenario:
///
/// - `Upsert` — `NLM_F_CREATE | NLM_F_REPLACE`. Right for unicast
///   MAC entries where (ifindex, MAC) is unique; replacing the prior
///   entry on a re-advertise (e.g. MAC mobility) is correct.
///
/// - `Append` — `NLM_F_CREATE | NLM_F_APPEND`. Right for VXLAN
///   ingress-replication entries (zero-MAC with per-peer `dst`).
///   Multiple peers each contribute a `dst` on the same MAC; APPEND
///   adds without erasing the existing remote list, REPLACE would
///   clobber it.
///
/// - `Delete` — plain `NLM_F_REQUEST | NLM_F_ACK` with RTM_DELNEIGH.
#[derive(Clone, Copy)]
enum FdbOp {
    Upsert,
    Append,
    Delete,
}

/// Receive-buffer size (bytes) requested for the FIB monitor socket.
///
/// The socket subscribes to seven multicast groups below, and multicast
/// netlink has no flow control: once the receive queue is full the
/// kernel drops the notification and the next recv fails with ENOBUFS.
/// The kernel default (`net.core.rmem_default`, 208 KiB ≈ a few hundred
/// queued messages at skb-truesize accounting) is far too small for a
/// busy segment — the cold-start ARP burst of a few thousand BGP peers
/// overruns it in well under a second. 16 MiB rides out such bursts and
/// costs memory only while messages are actually queued.
const MONITOR_RCVBUF_BYTES: libc::c_int = 16 * 1024 * 1024;

/// `setsockopt(SOL_SOCKET, opt)` with [`MONITOR_RCVBUF_BYTES`], where
/// `opt` is `SO_RCVBUF` or `SO_RCVBUFFORCE` (netlink-sys only wraps the
/// former).
fn set_rcvbuf(fd: std::os::fd::RawFd, opt: libc::c_int) -> std::io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &MONITOR_RCVBUF_BYTES as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Enlarge the monitor socket's kernel receive buffer. `SO_RCVBUFFORCE`
/// first — it ignores the `net.core.rmem_max` cap but wants
/// CAP_NET_ADMIN, which the daemon holds anyway for route installs.
/// Falls back to plain `SO_RCVBUF` (silently clamped to `rmem_max`)
/// when that is denied. Quiet on success, warns when the buffer ends up
/// smaller than requested — the daemon keeps running either way, just
/// with a higher overrun risk under event bursts.
fn monitor_rcvbuf_enlarge(sock: &netlink_sys::Socket) {
    let fd = sock.as_raw_fd();
    if set_rcvbuf(fd, libc::SO_RCVBUFFORCE).is_ok() {
        return;
    }
    if let Err(e) = set_rcvbuf(fd, libc::SO_RCVBUF) {
        tracing::warn!(
            "fib: could not enlarge monitor socket receive buffer to {MONITOR_RCVBUF_BYTES} \
             bytes ({e}); netlink overruns are likely under event bursts"
        );
        return;
    }
    // getsockopt reports double the effective setting (socket(7));
    // under the doubled request it means rmem_max clamped us.
    if let Ok(effective) = sock.get_rx_buf_sz()
        && (effective as i64) < 2 * MONITOR_RCVBUF_BYTES as i64
    {
        tracing::warn!(
            "fib: monitor socket receive buffer clamped to {} bytes by net.core.rmem_max \
             (wanted {}); raise rmem_max or grant CAP_NET_ADMIN to reduce netlink overrun risk",
            effective,
            2 * MONITOR_RCVBUF_BYTES as i64,
        );
    }
}

impl FibHandle {
    pub fn new(rib_tx: UnboundedSender<FibMessage>, no_nhid: bool) -> anyhow::Result<Self> {
        // Baseline sysctls are applied (and any per-knob failures warned
        // about) by `Rib::event_loop`, which runs right after `Rib::new`
        // constructs this handle and before any FIB interaction — so there
        // is no need to enable them here too.
        let (mut connection, handle, mut messages) = new_connection()?;

        // Before subscribing to any multicast group, enlarge the
        // receive buffer past the kernel default — see
        // `monitor_rcvbuf_enlarge` for why the default overruns.
        monitor_rcvbuf_enlarge(connection.socket_mut().socket_mut());

        let mgroup_flags = RTMGRP_LINK
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_ROUTE
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV6_IFADDR
            // Covers RTM_NEWNEIGH / RTM_DELNEIGH for AF_INET (ARP),
            // AF_INET6 (NDP), and AF_BRIDGE (FDB) — all three flow
            // through the same group.
            | RTMGRP_NEIGH;

        let addr = SocketAddr::new(0, mgroup_flags);
        connection.socket_mut().socket_mut().bind(&addr)?;

        // RTM_NEWNEXTHOP / RTM_DELNEXTHOP aren't covered by the legacy
        // RTMGRP_* bind mask (it only spans the first ~20 groups). Join
        // the modern multicast group so the kernel delivers nexthop
        // add/del notifications — `process_fib_msg` uses RTM_DELNEXTHOP
        // to reconcile NexthopMap when the kernel drops a nexthop. Needs
        // netlink-packet-route's group-nexthop decode fix (see the
        // `decodes_rtm_newnexthop_group` test). Non-fatal on join error.
        match connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTNLGRP_NEXTHOP)
        {
            Ok(()) => tracing::debug!("fib: joined RTNLGRP_NEXTHOP for nexthop reconciliation"),
            Err(e) => tracing::warn!(
                "fib: could not join RTNLGRP_NEXTHOP ({e}); nexthop reconciliation disabled"
            ),
        }

        // Bridge MDB group — kernel IGMP/MLD snooping notifications that
        // drive EVPN SMET origination. Non-fatal on join error (the host
        // may not have a snooping bridge).
        match connection
            .socket_mut()
            .socket_mut()
            .add_membership(RTNLGRP_MDB)
        {
            Ok(()) => tracing::debug!("fib: joined RTNLGRP_MDB for EVPN IGMP/MLD snooping"),
            Err(e) => {
                tracing::warn!("fib: could not join RTNLGRP_MDB ({e}); EVPN SMET snooping disabled")
            }
        }

        tokio::spawn(connection);

        let tx = rib_tx.clone();
        tokio::spawn(async move {
            while let Some((message, _)) = messages.next().await {
                process_msg(message, tx.clone());
            }
        });

        // Use nhid unless explicitly disabled or kernel doesn't support it
        let use_nhid = if no_nhid {
            // tracing::info!("Nexthop ID disabled by --no-nhid flag, using embedded nexthop");
            false
        } else if kernel_supports_nhid() {
            // tracing::info!("Kernel supports nexthop ID (>= 5.3)");
            true
        } else {
            // tracing::info!("Kernel does not support nexthop ID (< 5.3), using embedded nexthop");
            false
        };

        Ok(Self {
            handle,
            use_nhid,
            kernel_route_exchange: false,
            evpn_prefix_routes: std::sync::Mutex::new(BTreeMap::new()),
            evpn_rmac_vtep: std::sync::Mutex::new(BTreeMap::new()),
            evpn_l3vni_bridge: std::sync::Mutex::new(BTreeMap::new()),
            vni_ifindex_map: BTreeMap::new(),
            vni_bridge_map: BTreeMap::new(),
            vni_metadata_map: BTreeMap::new(),
            vrf_ifindex_map: BTreeMap::new(),
            cradle: CradleFib::from_env(),
            fpm: FpmFib::from_env(rib_tx),
        })
    }

    /// Enable/re-point (`Some`) or disable (`None`) the cradle eBPF tee at
    /// runtime. Driven by the `system cradle grpc-endpoint` config leaf.
    pub fn set_cradle(&mut self, endpoint: Option<&str>) {
        self.cradle = endpoint.map(CradleFib::new);
        match &self.cradle {
            Some(cradle) => tracing::info!("fib: cradle eBPF tee enabled -> {}", cradle.endpoint()),
            None => tracing::info!("fib: cradle eBPF tee disabled"),
        }
    }

    /// Enable (`Some`) or disable (`None`) the SONiC FPM tee at runtime,
    /// driven by the `system fpm` config leaves.
    ///
    /// Re-pointing builds a fresh tee with an empty mirror, so routes
    /// installed before the change would never reach the new endpoint.
    /// The caller re-tees them (see `Rib::fpm_apply`), mirroring how the
    /// cradle tee handles enable-after-routes.
    pub fn set_fpm(
        &mut self,
        endpoint: Option<std::net::SocketAddr>,
        rib_tx: UnboundedSender<FibMessage>,
    ) {
        // Stop the old tee's connection task first. Dropping the handle
        // is not enough — the task holds its own clone — and an
        // orphaned task keeps reconnecting to the old endpoint and
        // replaying its frozen mirror over that fpmsyncd forever.
        if let Some(old) = self.fpm.take() {
            old.shutdown();
        }
        self.fpm = endpoint.map(|addr| FpmFib::new(addr, rib_tx));
        match &self.fpm {
            Some(fpm) => tracing::info!("fib: FPM tee enabled -> {}", fpm.endpoint()),
            None => tracing::info!("fib: FPM tee disabled"),
        }
    }

    /// Flush every FPM-mirrored route of a deleted VRF — see
    /// `FpmFib::flush_vrf`. A no-op when the tee is off.
    pub async fn fpm_flush_vrf(&self, vrf_ifindex: u32) {
        if let Some(fpm) = &self.fpm {
            fpm.flush_vrf(vrf_ifindex).await;
        }
    }

    /// Tee-only add for a route the kernel owns: a connected route
    /// needs no netlink install (the kernel creates the prefix route
    /// with the address), but SONiC's APPL_DB still needs it — FRR
    /// sends subnet routes over FPM, and without them the ASIC cannot
    /// deliver to directly-attached hosts. A no-op when the tee is off
    /// or the entry is not tee-able (`fpm_prepare` gates).
    pub async fn fpm_tee_add(&self, prefix: ipnet::IpNet, entry: &RibEntry, table_id: u32) {
        self.fpm_tee(RouteOp::Add, prefix, entry, table_id).await;
    }

    /// Tee one route to SONiC's FPM southbound.
    ///
    /// Connected routes ride along with protocol routes: the kernel
    /// originates them, but the ASIC still needs them or the switch
    /// cannot deliver to directly-attached hosts — the same reasoning as
    /// the cradle tee. Kernel-learned routes stay out; they would echo
    /// back what SONiC itself installed.
    async fn fpm_tee(&self, op: RouteOp, prefix: ipnet::IpNet, entry: &RibEntry, table_id: u32) {
        if self.fpm.is_none() {
            return;
        }
        let Some((vrf_ifindex, msg)) = self.fpm_prepare(op, prefix, entry, table_id) else {
            return;
        };
        let fpm = self.fpm.as_ref().expect("checked above");
        match op {
            RouteOp::Add => fpm.route_add(prefix, vrf_ifindex, msg).await,
            RouteOp::Del => fpm.route_del(&prefix, vrf_ifindex, msg).await,
        }
    }

    /// The gating + encoding half of [`fpm_tee`](Self::fpm_tee),
    /// synchronous and side-effect free, so the enable-time reseed walk
    /// can prepare its whole batch inline and hand the sends to a
    /// spawned task instead of stalling the RIB event loop on one
    /// mirror-lock round trip per route.
    pub fn fpm_prepare(
        &self,
        op: RouteOp,
        prefix: ipnet::IpNet,
        entry: &RibEntry,
        table_id: u32,
    ) -> Option<(u32, Vec<u8>)> {
        if !entry.is_protocol() && !matches!(entry.rtype, RibType::Connected) {
            return None;
        }

        // FPM's table field is a VRF *device ifindex*, not a kernel
        // routing-table id (dplane_fpm_sonic.c:1232 — "Put vrf if_index
        // instead of table id"), and `fpmsyncd` resolves it with
        // getIfName(), rejecting anything whose name does not start with
        // "Vrf". Confirmed on the wire: golden/vrf.fpm has table=6 for a
        // VRF on kernel table 100.
        //
        // A table with no mapping is skipped rather than sent with the
        // table id in place of the ifindex: fpmsyncd would resolve that
        // to some unrelated interface, and a missing route is recoverable
        // where a misattributed one is not.
        let vrf_ifindex = match table_id {
            0 | crate::rib::inst::RT_TABLE_MAIN => 0,
            other => match self.vrf_ifindex_map.get(&other) {
                Some(ifindex) => *ifindex,
                None => {
                    tracing::debug!(
                        "fib: FPM tee skipping {prefix} in table {other} (no VRF ifindex known)"
                    );
                    return None;
                }
            },
        };

        let msg = encode_route(op, &prefix, entry, vrf_ifindex)?;
        Some((vrf_ifindex, msg))
    }

    /// Push the RFC 3443 MPLS TTL model (`set mpls ttl propagate`) into the
    /// live tee. `pipe` = true (default) hides the LSP; `false` = uniform.
    /// A no-op when the tee is off; re-applied by `cradle_apply` after any tee
    /// (re)creation since a fresh `CradleFib` starts at the pipe default.
    pub fn set_cradle_mpls_pipe(&self, pipe: bool) {
        if let Some(cradle) = &self.cradle {
            cradle.set_mpls_pipe(pipe);
        }
    }

    /// Set (or clear, with `None`) a per-VRF MPLS TTL-model override
    /// (`vrf <name> mpls ttl propagate`) on the live tee, keyed by kernel
    /// `table_id`. A no-op when the tee is off; re-applied by `cradle_apply`.
    pub fn set_cradle_vrf_mpls_pipe(&self, table_id: u32, pipe: Option<bool>) {
        if let Some(cradle) = &self.cradle {
            cradle.set_vrf_mpls_pipe(table_id, pipe);
        }
    }

    /// Replay the tee's entire mirrored state into a freshly-(re)started
    /// cradle engine (see `CradleFib::replay`). Triggered by the
    /// `system ebpf` supervisor's `Message::CradleEngineUp`; a no-op when
    /// the tee is off.
    pub async fn cradle_replay(&self) {
        if let Some(cradle) = &self.cradle {
            cradle.replay().await;
        }
    }

    /// Tee an EVPN BUM replication slot to cradle (Type-3 with an SRv6
    /// End.DT2M SID). No kernel counterpart — cradle is the L2 data plane.
    pub async fn cradle_repl_add(&self, vni: u32, sid: std::net::Ipv6Addr) {
        if let Some(cradle) = &self.cradle {
            cradle.repl_slot_add(vni, sid).await;
        }
    }

    pub async fn cradle_repl_del(&self, vni: u32, sid: std::net::Ipv6Addr) {
        if let Some(cradle) = &self.cradle {
            cradle.repl_slot_del(vni, sid).await;
        }
    }

    /// The MPLS flavor (RFC 7432 ingress replication): a BUM replication slot
    /// toward PE `pe`, whose copies carry that PE's `label`.
    pub async fn cradle_repl_add_mpls(&self, bd: u32, pe: IpAddr, label: u32) {
        if let Some(cradle) = &self.cradle {
            cradle.repl_slot_add_mpls(bd, pe, label).await;
        }
    }

    pub async fn cradle_repl_del_mpls(&self, bd: u32, pe: IpAddr) {
        if let Some(cradle) = &self.cradle {
            cradle.repl_slot_del_mpls(bd, pe).await;
        }
    }

    /// RFC 7432 §8.3 (EVPN over MPLS): a replication slot toward `pe` that
    /// serves Ethernet Segment `esi` alone, its copies carrying `pe`'s ESI
    /// label for the segment under its BUM `label`.
    pub async fn cradle_repl_add_mpls_es(
        &self,
        bd: u32,
        pe: IpAddr,
        label: u32,
        esi: &str,
        esi_label: u32,
    ) {
        if let Some(cradle) = &self.cradle {
            cradle
                .repl_slot_add_mpls_es(bd, pe, label, esi, esi_label)
                .await;
        }
    }

    pub async fn cradle_repl_del_mpls_es(&self, bd: u32, pe: IpAddr, esi: &str) {
        if let Some(cradle) = &self.cradle {
            cradle.repl_slot_del_mpls_es(bd, pe, esi).await;
        }
    }

    /// Tee an RFC 9524 Replication segment (operator `replication-segment`
    /// config) to cradle: the local End.Replicate SID and its downstream
    /// branches. No kernel counterpart — cradle's `REPL_SEG` is the SR-P2MP
    /// replication data plane.
    pub async fn cradle_repl_seg_set(
        &self,
        sid: std::net::Ipv6Addr,
        hop_limit_threshold: u8,
        branches: Vec<(std::net::Ipv6Addr, u32, bool)>,
    ) {
        if let Some(cradle) = &self.cradle {
            cradle
                .repl_seg_set(sid, hop_limit_threshold, branches)
                .await;
        }
    }

    pub async fn cradle_repl_seg_del(&self, sid: std::net::Ipv6Addr) {
        if let Some(cradle) = &self.cradle {
            cradle.repl_seg_del(sid).await;
        }
    }

    /// Declare an EVPN/VXLAN L2VNI to the cradle data plane when its VXLAN
    /// device appears: bind the VNI to its bridge domain (`bd == vni`) and
    /// set the local VTEP source for the device-local's address family
    /// (cradle keeps one slot per family — a v6-local device is a
    /// v6-underlay VTEP). An EVPN-over-SRv6 deployment declares the same
    /// device shape (its VNI declaration); registering it too is inert —
    /// nothing sends VXLAN/UDP 4789 to an SRv6 PE, so the decap match
    /// never claims a packet and the VNI binding is only consulted by
    /// VXLAN decap. No-op when cradle is disabled.
    pub async fn cradle_vni_register(&self, vni: u32, local: IpAddr) {
        if let Some(cradle) = &self.cradle {
            cradle.set_vni(vni, vni).await;
            cradle.set_vtep_source(local).await;
        }
    }

    /// Declare an EVPN/VXLAN L3VNI (symmetric IRB, RFC 9135) to the cradle
    /// data plane: bind the VNI to a tenant `vrf_table_id` with this PE's
    /// router-MAC so a received VXLAN frame on `vni` routes its inner IP in
    /// that VRF, and set the fabric-wide local VTEP source. The symmetric-IRB
    /// VXLAN L3 encap is an IPv4-only cradle capability (`VxlanEncap` carries
    /// a 4-byte VTEP), so an IPv6-local device is a no-op here — unlike the
    /// L2VNI register, which serves either family. No-op when cradle is
    /// disabled.
    pub async fn cradle_vni_register_l3(
        &self,
        vni: u32,
        local: IpAddr,
        vrf_table_id: u32,
        rmac: [u8; 6],
    ) {
        if let Some(cradle) = &self.cradle
            && let IpAddr::V4(v4) = local
        {
            cradle.set_vni_l3(vni, vrf_table_id, rmac).await;
            cradle.set_vtep_source(IpAddr::V4(v4)).await;
        }
    }

    /// Withdraw an L2VNI binding from cradle when its VXLAN device is
    /// removed (the counterpart of `cradle_vni_register`). Harmless for an
    /// SRv6 device, which never registered one. No-op when cradle is off.
    pub async fn cradle_vni_unregister(&self, vni: u32) {
        if let Some(cradle) = &self.cradle {
            cradle.del_vni(vni).await;
        }
    }

    /// Install a GTP-U decap PDR (`H.M.GTP4.D`) into the cradle data plane: a
    /// G-PDU on (`dst`, `teid`), arriving on a port bound to VRF table
    /// `match_vrf` (0 = global), is stripped and its inner packet forwarded in
    /// VRF `table_id`. No kernel counterpart — the mainline kernel has no GTP
    /// action, so cradle is the only forwarder for the MUP `dataplane gtp` mode.
    pub async fn cradle_gtp_pdr_add(
        &self,
        dst: std::net::IpAddr,
        teid: u32,
        table_id: u32,
        match_vrf: u32,
    ) {
        if let Some(cradle) = &self.cradle {
            cradle.gtp_pdr_add(dst, teid, table_id, match_vrf).await;
        }
    }

    pub async fn cradle_gtp_pdr_del(&self, dst: std::net::IpAddr, teid: u32, match_vrf: u32) {
        if let Some(cradle) = &self.cradle {
            cradle.gtp_pdr_del(dst, teid, match_vrf).await;
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn cradle_gtp_encap_add(
        &self,
        prefix: ipnet::IpNet,
        table_id: u32,
        gtp_src: std::net::IpAddr,
        gtp_dst: std::net::IpAddr,
        teid: u32,
        gw: Option<std::net::IpAddr>,
        oif: u32,
    ) {
        if let Some(cradle) = &self.cradle {
            cradle
                .gtp_encap_install(prefix, table_id, gtp_src, gtp_dst, teid, gw, oif)
                .await;
        }
    }
    pub async fn cradle_gtp_encap_del(&self, prefix: ipnet::IpNet, table_id: u32) {
        if let Some(cradle) = &self.cradle {
            cradle.gtp_encap_del(prefix, table_id).await;
        }
    }

    /// Tee an EVPN VPWS cross-connect to cradle (RFC 8214 Type-1 with an
    /// SRv6 End.DX2/DX2V SID, a VXLAN VTEP+VNI or an MPLS PE+label): bind
    /// AC `port` to the remote service endpoint, and install the local
    /// decap for the return direction — the `local_sid` LocalSid on the
    /// same AC (SRv6), the `local_vni` E-Line VNI binding (VXLAN), or the
    /// `local_label` pop-to-AC ILM (MPLS). A non-zero `vid` scopes the
    /// binding to that 802.1Q VID (demuxed over VLAN table `table`). No
    /// kernel counterpart — cradle is the L2 data plane.
    #[allow(clippy::too_many_arguments)]
    pub async fn cradle_xconnect_add(
        &self,
        port: &str,
        remote: crate::rib::XconnectRemote,
        local_sid: Option<std::net::Ipv6Addr>,
        local_vni: Option<u32>,
        local_vtep: Option<IpAddr>,
        local_label: Option<u32>,
        vid: u16,
        table: u32,
    ) {
        if let Some(cradle) = &self.cradle {
            match &remote {
                crate::rib::XconnectRemote::Vxlan { .. } => {
                    if let Some(local) = local_vtep {
                        // The fabric-wide VXLAN source — decap match and
                        // outer source — must be the address our Type-1
                        // told the remote to send to. Idempotent; one
                        // VTEP per PE.
                        cradle.set_vtep_source(local).await;
                    }
                }
                crate::rib::XconnectRemote::Mpls { .. } | crate::rib::XconnectRemote::Srv6(_) => {}
            }
            cradle
                .xconnect_add(port, remote, local_sid, local_vni, local_label, vid, table)
                .await;
        }
    }

    /// EVPN multihoming tee (RFC 7432 §5): an Ethernet Segment's local
    /// access ports. cradle-only — the kernel bridge has no non-DF /
    /// split-horizon filter, so the kernel VXLAN backend stays single-homed
    /// and there is no kernel counterpart here.
    pub async fn cradle_es_set(&self, esi: &str, ports: &[String], esi_label: u32) {
        if let Some(cradle) = &self.cradle {
            cradle.set_ethernet_segment(esi, ports, esi_label).await;
        }
    }

    /// Inverse of [`Self::cradle_es_set`].
    pub async fn cradle_es_del(&self, esi: &str) {
        if let Some(cradle) = &self.cradle {
            cradle.del_ethernet_segment(esi).await;
        }
    }

    /// EVPN multihoming tee (RFC 7432 §8.5): this PE's Designated Forwarder
    /// role for segment `esi` in bridge domain `bd` — `df == false` makes
    /// cradle withhold BUM from the segment's ports there.
    pub async fn cradle_es_role(&self, esi: &str, bd: u32, df: bool, single_active: bool) {
        if let Some(cradle) = &self.cradle {
            cradle.set_es_role(esi, bd, df, single_active).await;
        }
    }

    /// EVPN multihoming tee (RFC 8365 §8.3.1): the other PEs on segment
    /// `esi` — cradle withholds overlay BUM arriving from any of them from
    /// the segment's ports (split horizon / local bias).
    pub async fn cradle_es_peers(&self, esi: &str, vteps: &[IpAddr]) {
        if let Some(cradle) = &self.cradle {
            cradle.set_es_peers(esi, vteps).await;
        }
    }

    /// EVPN multihoming tee (RFC 7432 §8.4): the nexthop group for segment
    /// `esi` in bridge domain `bd` — the PEs a MAC behind the segment may be
    /// sent to (empty = no group).
    pub async fn cradle_es_nhg(
        &self,
        esi: &[u8; 10],
        bd: u32,
        members: &[crate::rib::EsNhgMember],
        single_active: bool,
    ) {
        if let Some(cradle) = &self.cradle {
            cradle
                .set_es_nhg(&bgp_packet::esi_display(esi), bd, members, single_active)
                .await;
        }
    }

    /// EVPN multihoming tee: `mac` in `vni` sits behind segment `esi` —
    /// install it through the segment's nexthop group (a member per flow).
    pub async fn cradle_fdb_es(&self, vni: u32, mac: &MacAddr, esi: &[u8; 10]) {
        if let Some(cradle) = &self.cradle {
            cradle
                .fdb_add_es(vni, mac.octets(), &bgp_packet::esi_display(esi))
                .await;
        }
    }

    /// EVPN multihoming tee: `mac` in `vni` is on a segment this node is
    /// attached to — a static local entry on our access port `port`.
    pub async fn cradle_fdb_local(&self, vni: u32, mac: &MacAddr, port: &str) {
        if let Some(cradle) = &self.cradle {
            cradle.fdb_add_local(vni, mac.octets(), port).await;
        }
    }

    pub async fn cradle_xconnect_del(
        &self,
        port: &str,
        local_sid: Option<std::net::Ipv6Addr>,
        local_vni: Option<u32>,
        local_label: Option<u32>,
        vid: u16,
        table: u32,
    ) {
        if let Some(cradle) = &self.cradle {
            cradle
                .xconnect_del(port, local_sid, local_vni, local_label, vid, table)
                .await;
        }
    }

    /// Tee a resolved neighbor (ARP/ND) into the cradle data plane — its MPLS
    /// egress rewrite resolves destination MACs from this state. No-op when
    /// the tee is disabled.
    pub async fn cradle_neighbor_add(&self, ip: IpAddr, oif_index: u32, mac: [u8; 6]) {
        if let Some(cradle) = &self.cradle {
            cradle.neighbor_add(ip, oif_index, mac).await;
        }
    }

    pub async fn route_ipv4_add_uni(
        &self,
        prefix: &Ipv4Net,
        entry: &RibEntry,
        nexthop: &Nexthop,
        table_id: u32,
    ) -> bool {
        if self.kernel_route_exchange
            && let Nexthop::Uni(uni) = nexthop
            && let Some(encap) = uni.vxlan
        {
            return self
                .evpn_prefix_route(IpNet::V4(*prefix), table_id, uni.metric, encap, true)
                .await;
        }
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();

        set_route_table(&mut msg, table_id);
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };

        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet(prefix.addr()));
        msg.attributes.push(attr);

        if let Nexthop::Uni(uni) = &nexthop
            && !uni.segs.is_empty()
            && uni.addr.is_unspecified()
        {
            // Oif-only recursive seg6 H.Encaps (e.g. a MUP ST1 UE prefix
            // steered into a *local* End.DT46 ISD segment): there is no
            // on-link underlay next-hop — the encapped packet's outer DA is
            // the SID, which the kernel re-routes via the (local) locator
            // route. So emit `dev <oif> encap seg6 …` with NO gateway, and
            // embed the seg6 encap on the route: an unspecified-addr nexthop
            // has no kernel nh_id, so the Nhid path can't carry it. Mirrors
            // the seg6local oif-only branch in `route_ipv6_add_uni`.
            if let Some(ifindex) = uni.ifindex() {
                msg.attributes.push(RouteAttribute::Oif(ifindex));
            }
            let encap_type = uni
                .encap_type
                .unwrap_or(isis_packet::srv6::EncapType::HEncap);
            match super::srv6::build_seg6_attrs(&uni.segs, encap_type) {
                Ok((encap, encap_type_attr)) => {
                    msg.attributes.push(encap);
                    msg.attributes.push(encap_type_attr);
                }
                Err(e) => {
                    tracing::warn!("SRv6 oif-only encap build failed for {prefix}: {e:#}");
                    return false;
                }
            }
            msg.attributes.push(RouteAttribute::Priority(uni.metric));
        } else if self.use_nhid {
            // Kernel >= 5.3: use nexthop ID
            if let Nexthop::Uni(uni) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        } else {
            // Kernel < 5.3: embed nexthop directly
            if let Nexthop::Uni(uni) = &nexthop {
                match uni.addr {
                    IpAddr::V4(ipv4) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet(ipv4)));
                    }
                    // Cross-family gateway (RFC 5549 / RFC 8950: v4
                    // prefix via a v6 next-hop) must ride RTA_VIA —
                    // the kernel rejects an RTA_GATEWAY whose length
                    // doesn't match the route's address family.
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Via(RouteVia::Inet6(ipv6)));
                    }
                }
                if let Some(ifindex) = uni.ifindex() {
                    msg.attributes.push(RouteAttribute::Oif(ifindex));
                }
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();
                    let attr = match uni.addr {
                        IpAddr::V4(ipv4) => RouteAttribute::Gateway(RouteAddress::Inet(ipv4)),
                        // Cross-family gateway — RTA_VIA, as above.
                        IpAddr::V6(ipv6) => RouteAttribute::Via(RouteVia::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);
                    if let Some(ifindex) = uni.ifindex() {
                        nhop.attributes.push(RouteAttribute::Oif(ifindex));
                    }
                    mpath.push(nhop);
                }
                msg.attributes.push(RouteAttribute::MultiPath(mpath));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        // Upsert (`NLM_F_REPLACE`), not `NLM_F_EXCL`: the kernel keys a
        // route on (table, dst, priority), NOT on its nexthop — a
        // re-resolved route (e.g. a recursive static whose underlay
        // moved to a TI-LFA promoted repair) keeps its key but changes
        // its nhid. With EXCL that re-add came back EEXIST — swallowed
        // as success below — and the stale nexthop stayed in the FIB.
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        // Pre-send dump — `tracing::debug!` so production stays
        // quiet; enable via `RUST_LOG=zebra_rs::fib=debug` when
        // chasing an install failure.
        tracing::debug!(
            "RTM_NEWROUTE v4 {prefix} use_nhid={} nh={}",
            self.use_nhid,
            fmt_nexthop_for_trace(nexthop),
        );

        let mut ok = true;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                // EEXIST means the route is already in the FIB — treat it
                // as installed. Otherwise the self-heal would keep
                // re-adding it every resolve cycle, forever.
                if e.to_io().raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                ok = false;
                if fib_route() {
                    tracing::info!(
                        "NewRoute error: {prefix} {e} table={table_id} rtype={:?} metric={} use_nhid={} nh={}",
                        entry.rtype,
                        entry.metric,
                        self.use_nhid,
                        fmt_nexthop_for_trace(nexthop),
                    );
                }
            }
        }
        ok
    }

    /// Returns whether the route ended up in the kernel FIB. `true` also
    /// covers EEXIST (already present). `false` means a real netlink
    /// error — commonly EINVAL "nexthop id does not exist" when use_nhid
    /// points at a nexthop the kernel silently dropped on link down. The
    /// caller leaves the route's `fib` flag
    /// clear and forces the nexthop's recreation so the next resolve
    /// pass re-adds it.
    /// Re-emit one v4 route's cradle tee only (no kernel side) — the
    /// enable-after-routes resync unit. **Protocol routes only**: unlike
    /// the inline tee (which also mirrors connected routes), the walk
    /// skips `Connected`, because cradle derives a port's connected +
    /// local routes itself from the kernel addresses when `SetPort`
    /// attaches it (`kernel::derive_port`, with the real oif). The
    /// stored connected `RibEntry` carries only `entry.ifindex` and a
    /// `Nexthop::Link(0)`, so re-teeing it here would clobber cradle's
    /// correct entry with an oif-0 one. A disabled tee is a no-op.
    pub async fn cradle_route_resync_v4(
        &self,
        prefix: &Ipv4Net,
        entry: &RibEntry,
        table_id: u32,
    ) -> bool {
        if entry.is_protocol()
            && let Some(cradle) = &self.cradle
        {
            let members = cradle_members(&entry.nexthop);
            if !members.is_empty() {
                cradle.route_install(*prefix, table_id, members).await;
                return true;
            }
        }
        false
    }

    /// Re-tee one selected ILM into a freshly-(re)connected cradle engine.
    ///
    /// The cradle branch of [`Self::ilm_install`] is a no-op when the tee is
    /// not up yet, and unlike IP routes an ILM does not churn afterwards — a
    /// service label is programmed once, at config load, which is exactly
    /// when the tee is still connecting. Without this the label FIB stays
    /// permanently empty for anything installed in that window.
    pub async fn cradle_ilm_resync(&self, label: u32, ilm: &IlmEntry) -> bool {
        if self.cradle.is_none() {
            return false;
        }
        self.cradle_ilm_program(label, ilm).await;
        true
    }

    /// v6 sibling of [`Self::cradle_route_resync_v4`].
    pub async fn cradle_route_resync_v6(
        &self,
        prefix: &Ipv6Net,
        entry: &RibEntry,
        table_id: u32,
    ) -> bool {
        if entry.is_protocol()
            && let Some(cradle) = &self.cradle
        {
            let members = cradle_members(&entry.nexthop);
            if !members.is_empty() {
                cradle.route_install6(*prefix, table_id, members).await;
                return true;
            }
        }
        false
    }

    /// Is the cradle eBPF tee currently attached?
    pub fn cradle_active(&self) -> bool {
        self.cradle.is_some()
    }

    pub async fn route_ipv4_add(&self, prefix: &Ipv4Net, entry: &RibEntry, table_id: u32) -> bool {
        // Tee protocol AND connected routes — see the v6 sibling.
        if (entry.is_protocol() || matches!(entry.rtype, RibType::Connected))
            && let Some(cradle) = &self.cradle
        {
            let members = cradle_members(&entry.nexthop);
            if !members.is_empty() {
                cradle.route_install(*prefix, table_id, members).await;
            }
        }
        self.fpm_tee(RouteOp::Add, (*prefix).into(), entry, table_id)
            .await;
        if !entry.is_protocol() {
            return true;
        }
        match &entry.nexthop {
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv4_add_uni(prefix, entry, &entry.nexthop, table_id)
                    .await
            }
            Nexthop::List(pro) => {
                let mut ok = true;
                for member in pro.nexthops.iter() {
                    ok &= self
                        .route_ipv4_add_uni(prefix, entry, &member.as_nexthop(), table_id)
                        .await;
                }
                ok
            }
            Nexthop::Protect(pro) => {
                // Primary and backup install as two kernel routes at
                // their own metrics. The primary references the
                // protection indirection group (when allocated) so a
                // future membership swap rewires every protected
                // prefix at once; the backup keeps its member gid.
                let mut ok = true;
                ok &= self
                    .route_ipv4_add_uni(prefix, entry, &protect_primary_nexthop(pro), table_id)
                    .await;
                ok &= self
                    .route_ipv4_add_uni(prefix, entry, &pro.backup.as_nexthop(), table_id)
                    .await;
                ok
            }
            Nexthop::Blackhole(metric) => {
                self.route_ipv4_blackhole(prefix, entry, *metric, table_id, true)
                    .await
            }
            _ => true,
        }
    }

    /// Install (or delete) a discard route (`RTN_BLACKHOLE`): kernel
    /// drops packets to `prefix` with no gateway or nexthop group.
    /// `add` selects `RTM_NEWROUTE` vs `RTM_DELROUTE`.
    pub async fn route_ipv4_blackhole(
        &self,
        prefix: &Ipv4Net,
        entry: &RibEntry,
        metric: u32,
        table_id: u32,
        add: bool,
    ) -> bool {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();
        set_route_table(&mut msg, table_id);
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::BlackHole;
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(
                prefix.addr(),
            )));
        msg.attributes.push(RouteAttribute::Priority(metric));

        let inner = if add {
            RouteNetlinkMessage::NewRoute(msg)
        } else {
            RouteNetlinkMessage::DelRoute(msg)
        };
        let mut req = NetlinkMessage::from(inner);
        req.header.flags = if add {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        } else {
            NLM_F_REQUEST | NLM_F_ACK
        };

        let mut ok = true;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                let errno = e.to_io().raw_os_error();
                // EEXIST on add / ESRCH|ENOENT on delete: the kernel
                // is already in the desired state — treat as success.
                if (add && errno == Some(libc::EEXIST))
                    || (!add && matches!(errno, Some(libc::ESRCH) | Some(libc::ENOENT)))
                {
                    continue;
                }
                ok = false;
                if fib_route() {
                    tracing::info!(
                        "Blackhole {} error: {prefix} {e} table={table_id} rtype={:?}",
                        if add { "add" } else { "del" },
                        entry.rtype,
                    );
                }
            }
        }
        ok
    }

    pub async fn route_ipv4_del_uni(
        &self,
        prefix: &Ipv4Net,
        entry: &RibEntry,
        nexthop: &Nexthop,
        table_id: u32,
    ) {
        // Follow what was installed, not the knob: it may have been
        // toggled since, and the bridge route only matches this path.
        if matches!(nexthop, Nexthop::Uni(uni) if uni.vxlan.is_some())
            && let Some((encap, metric)) = self.evpn_prefix_tracked(table_id, IpNet::V4(*prefix))
        {
            self.evpn_prefix_route(IpNet::V4(*prefix), table_id, metric, encap, false)
                .await;
            return;
        }
        if !entry.is_protocol() {
            return;
        }
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = prefix.prefix_len();

        set_route_table(&mut msg, table_id);
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet(prefix.addr()));
        msg.attributes.push(attr);

        let attr = RouteAttribute::Priority(entry.metric);
        msg.attributes.push(attr);

        if let Nexthop::Uni(uni) = &nexthop
            && !uni.segs.is_empty()
            && uni.addr.is_unspecified()
        {
            // Oif-only recursive seg6 encap: delete by {dest, table, oif}.
            // The route carries no gateway / nh_id, so pushing either would
            // stop the kernel from matching it (see the add-path branch).
            if let Some(ifindex) = uni.ifindex() {
                msg.attributes.push(RouteAttribute::Oif(ifindex));
            }
        } else if self.use_nhid {
            // Kernel >= 5.3: use nexthop ID
            if let Nexthop::Uni(uni) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        } else {
            // Kernel < 5.3: embed nexthop directly
            if let Nexthop::Uni(uni) = &nexthop {
                match uni.addr {
                    IpAddr::V4(ipv4) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet(ipv4)));
                    }
                    // Cross-family gateway (RFC 5549 / RFC 8950) —
                    // RTA_VIA, mirroring the add path so the delete
                    // matches what was installed.
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Via(RouteVia::Inet6(ipv6)));
                    }
                }
                if let Some(ifindex) = uni.ifindex() {
                    msg.attributes.push(RouteAttribute::Oif(ifindex));
                }
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();
                    let attr = match uni.addr {
                        IpAddr::V4(ipv4) => RouteAttribute::Gateway(RouteAddress::Inet(ipv4)),
                        // Cross-family gateway — RTA_VIA, as above.
                        IpAddr::V6(ipv6) => RouteAttribute::Via(RouteVia::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);
                    if let Some(ifindex) = uni.ifindex() {
                        nhop.attributes.push(RouteAttribute::Oif(ifindex));
                    }
                    mpath.push(nhop);
                }
                msg.attributes.push(RouteAttribute::MultiPath(mpath));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload
                && fib_route()
            {
                tracing::info!(
                    "DelRoute error: {prefix} {e} table={table_id} rtype={:?} metric={} use_nhid={} nh={}",
                    entry.rtype,
                    entry.metric,
                    self.use_nhid,
                    fmt_nexthop_for_trace(nexthop),
                );
            }
        }
    }

    /// Delete a route an earlier run of zebra-rs left in the kernel
    /// (`RibEntry::stale`), matched on its destination, table, protocol
    /// and priority alone. It may forward through a next-hop object, and
    /// the kernel refuses a delete that names a gateway or interface for
    /// such a route; the object's id is the earlier run's, not ours.
    pub async fn route_del_leftover(&self, prefix: IpNet, entry: &RibEntry, table_id: u32) {
        let mut msg = RouteMessage::default();
        let dst = match prefix {
            IpNet::V4(prefix) => {
                msg.header.address_family = AddressFamily::Inet;
                RouteAddress::Inet(prefix.addr())
            }
            IpNet::V6(prefix) => {
                msg.header.address_family = AddressFamily::Inet6;
                RouteAddress::Inet6(prefix.addr())
            }
        };
        msg.header.destination_prefix_length = prefix.prefix_len();
        set_route_table(&mut msg, table_id);
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;
        msg.attributes.push(RouteAttribute::Destination(dst));
        msg.attributes.push(RouteAttribute::Priority(entry.metric));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload
                && e.code.is_some()
            {
                tracing::info!(
                    "DelRoute (an earlier run's) error: {prefix} {e} table={table_id} metric={}",
                    entry.metric,
                );
            }
        }
    }

    pub async fn route_ipv4_del(&self, prefix: &Ipv4Net, entry: &RibEntry, table_id: u32) {
        if (entry.is_protocol() || matches!(entry.rtype, RibType::Connected))
            && let Some(cradle) = &self.cradle
        {
            cradle.route_del(*prefix, table_id).await;
        }
        self.fpm_tee(RouteOp::Del, (*prefix).into(), entry, table_id)
            .await;
        if !entry.is_protocol() {
            return;
        }

        match &entry.nexthop {
            Nexthop::Link(_) => {}
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv4_del_uni(prefix, entry, &entry.nexthop, table_id)
                    .await;
            }
            Nexthop::List(list) => {
                for member in &list.nexthops {
                    self.route_ipv4_del_uni(prefix, entry, &member.as_nexthop(), table_id)
                        .await;
                }
            }
            Nexthop::Protect(pro) => {
                // Mirror the add path: the primary route was keyed to
                // the indirection gid, so the delete must name it too.
                self.route_ipv4_del_uni(prefix, entry, &protect_primary_nexthop(pro), table_id)
                    .await;
                self.route_ipv4_del_uni(prefix, entry, &pro.backup.as_nexthop(), table_id)
                    .await;
            }
            Nexthop::Blackhole(metric) => {
                self.route_ipv4_blackhole(prefix, entry, *metric, table_id, false)
                    .await;
            }
        }
    }

    pub async fn route_ipv6_add_uni(
        &self,
        prefix: &Ipv6Net,
        entry: &RibEntry,
        nexthop: &Nexthop,
        table_id: u32,
    ) -> bool {
        if self.kernel_route_exchange
            && let Nexthop::Uni(uni) = nexthop
            && let Some(encap) = uni.vxlan
        {
            return self
                .evpn_prefix_route(IpNet::V6(*prefix), table_id, uni.metric, encap, true)
                .await;
        }
        if fib_route() {
            tracing::info!(
                "[IPv6 route_add_uni] prefix={} prefixlen={} rtype={:?} use_nhid={}",
                prefix,
                prefix.prefix_len(),
                entry.rtype,
                self.use_nhid,
            );
        }

        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.destination_prefix_length = prefix.prefix_len();

        set_route_table(&mut msg, table_id);
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };

        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet6(prefix.addr()));
        msg.attributes.push(attr);

        // Seg6local install (operator-configured End.DT6 / End.DT4 /
        // End / uN on a static IPv6 prefix). The seg6local lwtunnel
        // encap can't ride in the kernel nexthop table, so we always
        // embed it on the route — independently of `use_nhid`. The
        // protocol-allocated SID install path goes through
        // `route_sid_install`, which has the same shape; this branch
        // is the static counterpart so user-configured action routes
        // travel the standard `Message::Ipv6Add` pipeline.
        if let Nexthop::Uni(uni) = &nexthop
            && let Some(action) = uni.seg6local_action
        {
            if let Some(ifindex) = uni.ifindex() {
                msg.attributes.push(RouteAttribute::Oif(ifindex));
            }
            // Tee the static action SID to cradle — these never pass
            // through the SID registry (route-embedded install), so the
            // eBPF datapath would otherwise not know them.
            if let Some(cradle) = &self.cradle {
                cradle
                    .static_sid_install(*prefix, action, Some(uni.addr), uni.ifindex().unwrap_or(0))
                    .await;
            }
            // The DX cross-connect adjacency rides on the uni's addr
            // (End.DX6 / End.X families in `nh6`, End.DX4 in `nh4`).
            let (nh6, nh4) = match uni.addr {
                std::net::IpAddr::V6(a) if !a.is_unspecified() => (Some(a), None),
                std::net::IpAddr::V4(a) if !a.is_unspecified() => (None, Some(a)),
                _ => (None, None),
            };
            if let Some((encap, encap_type)) =
                // Static seg6local action routes keep the legacy
                // RT_TABLE_MAIN decap (table_id 0); per-VRF table
                // selection arrives via the protocol SID path.
                super::srv6::build_seg6local_attrs(action, nh6, nh4, None, 0, &[], 0)
            {
                msg.attributes.push(encap);
                msg.attributes.push(encap_type);
            }
            msg.attributes.push(RouteAttribute::Priority(uni.metric));

            let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
            req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            let mut ok = true;
            let mut response = self.handle.clone().request(req).unwrap();
            while let Some(m) = response.next().await {
                if let NetlinkPayload::Error(e) = m.payload {
                    ok = false;
                    tracing::warn!(
                        "NewRoute seg6local install error: prefix={prefix} action={action:?} err={e}"
                    );
                }
            }
            return ok;
        }

        if let Nexthop::Uni(uni) = &nexthop
            && !uni.segs.is_empty()
            && uni.addr.is_unspecified()
        {
            // Oif-only recursive seg6 H.Encaps — see the same branch in
            // `route_ipv4_add_uni` for the rationale. No gateway; embed the
            // seg6 encap and let the kernel re-route by the outer SID DA.
            // Must precede the `use_nhid` arm: an unspecified-addr nexthop
            // has gid 0, which the sanity check below would reject.
            if let Some(ifindex) = uni.ifindex() {
                msg.attributes.push(RouteAttribute::Oif(ifindex));
            }
            let encap_type = uni
                .encap_type
                .unwrap_or(isis_packet::srv6::EncapType::HEncap);
            match super::srv6::build_seg6_attrs(&uni.segs, encap_type) {
                Ok((encap, encap_type_attr)) => {
                    msg.attributes.push(encap);
                    msg.attributes.push(encap_type_attr);
                }
                Err(e) => {
                    tracing::warn!("SRv6 oif-only encap build failed for {prefix}: {e:#}");
                    return false;
                }
            }
            msg.attributes.push(RouteAttribute::Priority(uni.metric));
        } else if self.use_nhid {
            // Pre-send sanity check — mirror of route_ipv4_add_uni.
            let gid_for_check = match &nexthop {
                Nexthop::Uni(u) => Some(u.gid),
                Nexthop::Multi(m) => Some(m.gid),
                _ => None,
            };
            if let Some(0) = gid_for_check {
                tracing::warn!(
                    "RTM_NEWROUTE v6 skipped for {prefix}: nexthop gid is 0 (would Nhid(0) -> ENODEV); nh={}",
                    fmt_nexthop_for_trace(nexthop),
                );
                return false;
            }
            if let Nexthop::Uni(uni) = &nexthop {
                if fib_route() {
                    tracing::info!(
                        "[IPv6 route_add_uni] using nhid: gid={} metric={}",
                        uni.gid,
                        uni.metric
                    );
                }
                msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                if fib_route() {
                    tracing::info!(
                        "[IPv6 route_add_uni] using nhid (multi): gid={} metric={}",
                        multi.gid,
                        multi.metric
                    );
                }
                msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        } else {
            if let Nexthop::Uni(uni) = &nexthop {
                if fib_route() {
                    tracing::info!(
                        "[IPv6 route_add_uni] embed nexthop: addr={} ifindex={:?} metric={}",
                        uni.addr,
                        uni.ifindex(),
                        uni.metric
                    );
                }
                match uni.addr {
                    IpAddr::V4(ipv4) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet(ipv4)));
                    }
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)));
                    }
                }
                if let Some(ifindex) = uni.ifindex() {
                    msg.attributes.push(RouteAttribute::Oif(ifindex));
                }
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);

                // Embedded seg6 encap fallback for kernels < 5.3 that don't
                // support nexthop-table lwtunnel encap. The seg6 attributes
                // ride directly on the route message instead of via Nhid.
                if !uni.segs.is_empty() {
                    let encap_type = uni
                        .encap_type
                        .unwrap_or(isis_packet::srv6::EncapType::HEncap);
                    match super::srv6::build_seg6_attrs(&uni.segs, encap_type) {
                        Ok((encap, encap_type_attr)) => {
                            msg.attributes.push(encap);
                            msg.attributes.push(encap_type_attr);
                        }
                        Err(e) => {
                            tracing::warn!("SRv6 embedded encap build failed for {prefix}: {e:#}");
                            return false;
                        }
                    }
                }
            }
            if let Nexthop::Multi(multi) = &nexthop {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();
                    let attr = match uni.addr {
                        IpAddr::V4(ipv4) => RouteAttribute::Gateway(RouteAddress::Inet(ipv4)),
                        IpAddr::V6(ipv6) => RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);
                    if let Some(ifindex) = uni.ifindex() {
                        nhop.attributes.push(RouteAttribute::Oif(ifindex));
                    }
                    mpath.push(nhop);
                }
                msg.attributes.push(RouteAttribute::MultiPath(mpath));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        }

        if fib_route() {
            tracing::info!(
                "[IPv6 route_add_uni] netlink request: af={:?} dest_prefix_len={} attrs={:?}",
                msg.header.address_family,
                msg.header.destination_prefix_length,
                msg.attributes
            );
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        // Upsert (`NLM_F_REPLACE`) — see the v4 sibling: a re-resolved
        // route keeps its (table, dst, priority) key but changes its
        // nhid; EXCL + the EEXIST-swallow left the stale nexthop in
        // the FIB.
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        // Pre-send dump — `tracing::debug!` so production stays
        // quiet; enable via `RUST_LOG=zebra_rs::fib=debug` when
        // chasing an install failure.
        tracing::debug!(
            "RTM_NEWROUTE v6 {prefix} use_nhid={} nh={}",
            self.use_nhid,
            fmt_nexthop_for_trace(nexthop),
        );

        let mut ok = true;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                // EEXIST means the route is already in the FIB — treat it
                // as installed so the self-heal doesn't re-add it forever.
                if e.to_io().raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                ok = false;
                if fib_route() {
                    tracing::info!(
                        "NewRoute IPv6 error: {prefix} {e} use_nhid={} nh={}",
                        self.use_nhid,
                        fmt_nexthop_for_trace(nexthop),
                    );
                }
            }
        }
        ok
    }

    /// IPv6 sibling of [`Self::route_ipv4_add`]; returns whether the
    /// kernel accepted the install.
    pub async fn route_ipv6_add(&self, prefix: &Ipv6Net, entry: &RibEntry, table_id: u32) -> bool {
        // The kernel originates connected routes itself, so they never
        // take the netlink-install path below — but the cradle datapath
        // still needs them or a zebra-driven node cannot deliver to
        // directly-connected hosts. Tee protocol AND connected routes;
        // kernel-learned ones stay out (they would echo).
        if (entry.is_protocol() || matches!(entry.rtype, RibType::Connected))
            && let Some(cradle) = &self.cradle
        {
            let members = cradle_members(&entry.nexthop);
            if !members.is_empty() {
                cradle.route_install6(*prefix, table_id, members).await;
            }
        }
        self.fpm_tee(RouteOp::Add, (*prefix).into(), entry, table_id)
            .await;
        if !entry.is_protocol() {
            return true;
        }
        match &entry.nexthop {
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv6_add_uni(prefix, entry, &entry.nexthop, table_id)
                    .await
            }
            Nexthop::List(pro) => {
                let mut ok = true;
                for member in pro.nexthops.iter() {
                    ok &= self
                        .route_ipv6_add_uni(prefix, entry, &member.as_nexthop(), table_id)
                        .await;
                }
                ok
            }
            Nexthop::Protect(pro) => {
                // Primary and backup install as two kernel routes at
                // their own metrics. The primary references the
                // protection indirection group (when allocated) so a
                // future membership swap rewires every protected
                // prefix at once; the backup keeps its member gid.
                let mut ok = true;
                ok &= self
                    .route_ipv6_add_uni(prefix, entry, &protect_primary_nexthop(pro), table_id)
                    .await;
                ok &= self
                    .route_ipv6_add_uni(prefix, entry, &pro.backup.as_nexthop(), table_id)
                    .await;
                ok
            }
            Nexthop::Blackhole(metric) => {
                self.route_ipv6_blackhole(prefix, entry, *metric, table_id, true)
                    .await
            }
            _ => true,
        }
    }

    /// IPv6 sibling of [`Self::route_ipv4_blackhole`].
    pub async fn route_ipv6_blackhole(
        &self,
        prefix: &Ipv6Net,
        entry: &RibEntry,
        metric: u32,
        table_id: u32,
        add: bool,
    ) -> bool {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.destination_prefix_length = prefix.prefix_len();
        set_route_table(&mut msg, table_id);
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::BlackHole;
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(
                prefix.addr(),
            )));
        msg.attributes.push(RouteAttribute::Priority(metric));

        let inner = if add {
            RouteNetlinkMessage::NewRoute(msg)
        } else {
            RouteNetlinkMessage::DelRoute(msg)
        };
        let mut req = NetlinkMessage::from(inner);
        req.header.flags = if add {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        } else {
            NLM_F_REQUEST | NLM_F_ACK
        };

        let mut ok = true;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                let errno = e.to_io().raw_os_error();
                if (add && errno == Some(libc::EEXIST))
                    || (!add && matches!(errno, Some(libc::ESRCH) | Some(libc::ENOENT)))
                {
                    continue;
                }
                ok = false;
                if fib_route() {
                    tracing::info!(
                        "Blackhole {} error: {prefix} {e} table={table_id} rtype={:?}",
                        if add { "add" } else { "del" },
                        entry.rtype,
                    );
                }
            }
        }
        ok
    }

    pub async fn route_ipv6_del_uni(
        &self,
        prefix: &Ipv6Net,
        entry: &RibEntry,
        nexthop: &Nexthop,
        table_id: u32,
    ) {
        // Follow what was installed, not the knob: it may have been
        // toggled since, and the bridge route only matches this path.
        if matches!(nexthop, Nexthop::Uni(uni) if uni.vxlan.is_some())
            && let Some((encap, metric)) = self.evpn_prefix_tracked(table_id, IpNet::V6(*prefix))
        {
            self.evpn_prefix_route(IpNet::V6(*prefix), table_id, metric, encap, false)
                .await;
            return;
        }
        if !entry.is_protocol() {
            return;
        }

        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.destination_prefix_length = prefix.prefix_len();

        set_route_table(&mut msg, table_id);
        msg.header.protocol = match entry.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Inet6(prefix.addr()));
        msg.attributes.push(attr);

        let attr = RouteAttribute::Priority(entry.metric);
        msg.attributes.push(attr);

        // Mirror the seg6local install: when the route was a
        // seg6local route, the kernel matches del on
        // {prefix, table, kind} alone — no encap attrs needed in
        // the del message. Sending the Oif still helps when the
        // user has stacked multiple actions on the same prefix
        // (rare, but harmless to include).
        if let Nexthop::Uni(uni) = &nexthop
            && uni.seg6local_action.is_some()
        {
            if let Some(ifindex) = uni.ifindex() {
                msg.attributes.push(RouteAttribute::Oif(ifindex));
            }
            let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
            req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
            let mut response = self.handle.clone().request(req).unwrap();
            while let Some(m) = response.next().await {
                if let NetlinkPayload::Error(e) = m.payload {
                    tracing::warn!("DelRoute seg6local error: prefix={prefix} err={e}");
                }
            }
            return;
        }

        if let Nexthop::Uni(uni) = &nexthop
            && !uni.segs.is_empty()
            && uni.addr.is_unspecified()
        {
            // Oif-only recursive seg6 encap: delete by {dest, table, oif}
            // (no gateway / nh_id — see route_ipv4_del_uni).
            if let Some(ifindex) = uni.ifindex() {
                msg.attributes.push(RouteAttribute::Oif(ifindex));
            }
        } else if self.use_nhid {
            if let Nexthop::Uni(uni) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(uni.gid as u32));
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                msg.attributes.push(RouteAttribute::Nhid(multi.gid as u32));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        } else {
            if let Nexthop::Uni(uni) = &nexthop {
                match uni.addr {
                    IpAddr::V4(ipv4) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet(ipv4)));
                    }
                    IpAddr::V6(ipv6) => {
                        msg.attributes
                            .push(RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)));
                    }
                }
                if let Some(ifindex) = uni.ifindex() {
                    msg.attributes.push(RouteAttribute::Oif(ifindex));
                }
                let attr = RouteAttribute::Priority(uni.metric);
                msg.attributes.push(attr);
            }
            if let Nexthop::Multi(multi) = &nexthop {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();
                    let attr = match uni.addr {
                        IpAddr::V4(ipv4) => RouteAttribute::Gateway(RouteAddress::Inet(ipv4)),
                        IpAddr::V6(ipv6) => RouteAttribute::Gateway(RouteAddress::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);
                    if let Some(ifindex) = uni.ifindex() {
                        nhop.attributes.push(RouteAttribute::Oif(ifindex));
                    }
                    mpath.push(nhop);
                }
                msg.attributes.push(RouteAttribute::MultiPath(mpath));
                let attr = RouteAttribute::Priority(multi.metric);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload
                && fib_route()
            {
                tracing::info!(
                    "DelRoute IPv6 error: {prefix} {e} table={table_id} rtype={:?} metric={} use_nhid={} nh={}",
                    entry.rtype,
                    entry.metric,
                    self.use_nhid,
                    fmt_nexthop_for_trace(nexthop),
                );
            }
        }
    }

    pub async fn route_ipv6_del(&self, prefix: &Ipv6Net, entry: &RibEntry, table_id: u32) {
        if (entry.is_protocol() || matches!(entry.rtype, RibType::Connected))
            && let Some(cradle) = &self.cradle
        {
            cradle.route_del6(*prefix, table_id).await;
            // A static seg6local action route also teed a local SID
            // on install — withdraw it or the eBPF entry goes stale.
            if let Nexthop::Uni(uni) = &entry.nexthop
                && uni.seg6local_action.is_some()
            {
                cradle.static_sid_uninstall(*prefix).await;
            }
        }
        self.fpm_tee(RouteOp::Del, (*prefix).into(), entry, table_id)
            .await;
        if !entry.is_protocol() {
            return;
        }

        match &entry.nexthop {
            Nexthop::Link(_) => {}
            Nexthop::Uni(_) | Nexthop::Multi(_) => {
                self.route_ipv6_del_uni(prefix, entry, &entry.nexthop, table_id)
                    .await;
            }
            Nexthop::List(list) => {
                for member in &list.nexthops {
                    self.route_ipv6_del_uni(prefix, entry, &member.as_nexthop(), table_id)
                        .await;
                }
            }
            Nexthop::Protect(pro) => {
                // Mirror the add path: the primary route was keyed to
                // the indirection gid, so the delete must name it too.
                self.route_ipv6_del_uni(prefix, entry, &protect_primary_nexthop(pro), table_id)
                    .await;
                self.route_ipv6_del_uni(prefix, entry, &pro.backup.as_nexthop(), table_id)
                    .await;
            }
            Nexthop::Blackhole(metric) => {
                self.route_ipv6_blackhole(prefix, entry, *metric, table_id, false)
                    .await;
            }
        }
    }

    pub async fn nexthop_add(&self, nexthop: &Group) {
        // Skip nexthop table management for kernels < 5.3
        if !self.use_nhid {
            return;
        }

        // Nexthop message.
        let mut msg = NexthopMessage::default();
        msg.header.protocol = RouteProtocol::Zebra;
        msg.header.flags = NexthopFlags::Onlink;

        // Logging purpose.
        let gid: usize;
        let refcnt: usize;

        match nexthop {
            Group::Uni(uni) => {
                // Logging.
                gid = uni.gid();
                refcnt = uni.refcnt();

                if fib_nexthop() {
                    tracing::info!(
                        "[nexthop_add Uni] gid={} addr={} ifindex={:?} valid={} installed={}",
                        gid,
                        uni.addr,
                        uni.ifindex(),
                        uni.is_valid(),
                        uni.is_installed(),
                    );
                }

                // seg6local can't be advertised via the kernel nexthop
                // table — only seg6 (encap) and mpls are supported as
                // lwtunnel encaps under nh_id. The route install path
                // embeds the encap on the route message instead, so
                // there's nothing to push here. NexthopMap still
                // refcounts the logical group for dedup / cleanup
                // bookkeeping inside zebra-rs.
                if uni.seg6local_action.is_some() {
                    if fib_srv6() {
                        tracing::info!(
                            "[nexthop_add seg6local] gid={} skipped — seg6local \
                             install rides on the route, not the nh_id",
                            uni.gid(),
                        );
                    }
                    return;
                }

                // On-link nexthops with an unspecified gateway
                // (0.0.0.0 / ::) have no representation in the kernel
                // nexthop table — NHA_GATEWAY can't carry the
                // wildcard address and an interface-only nh_id needs
                // a gateway anyway under our address_family setup.
                // RIB only allocates these as the resolved nexthop
                // for OSPF stub-network LSAs and other intra-segment
                // routes that lose to the Connected route, so they
                // never need a kernel nh_id. NexthopMap still tracks
                // them for logical bookkeeping inside zebra-rs.
                if uni.addr.is_unspecified() {
                    tracing::debug!(
                        "[nexthop_add Uni] gid={gid} skipped — addr={} is unspecified, no kernel nh_id needed",
                        uni.addr,
                    );
                    return;
                }

                // Address family follows the gateway address.
                msg.header.address_family = match uni.addr {
                    std::net::IpAddr::V4(_) => AddressFamily::Inet,
                    std::net::IpAddr::V6(_) => AddressFamily::Inet6,
                };

                // Nexthop group ID.
                let attr = NexthopAttribute::Id(uni.gid() as u32);
                msg.attributes.push(attr);

                // Gateway address.
                let attr = match uni.addr {
                    std::net::IpAddr::V4(ipv4) => {
                        NexthopAttribute::Gateway(RouteAddress::Inet(ipv4))
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        NexthopAttribute::Gateway(RouteAddress::Inet6(ipv6))
                    }
                };
                msg.attributes.push(attr);

                // Outgoing if. Origin wins over resolved; fall back to 0
                // ("no Oif attribute") if neither was filled, which is a
                // bug case the kernel will reject — we want it loud.
                let attr = NexthopAttribute::Oif(uni.ifindex().unwrap_or(0));
                msg.attributes.push(attr);

                if fib_nexthop() {
                    tracing::info!(
                        "[nexthop_add Uni] netlink: af={:?} attrs={:?}",
                        msg.header.address_family,
                        msg.attributes
                    );
                }

                // MPLS.
                if !uni.labels.is_empty() {
                    let attr = NexthopAttribute::EncapType(RouteLwEnCapType::Mpls.into());
                    msg.attributes.push(attr);

                    let last = uni.labels.len() - 1;
                    let stack: Vec<MplsLabel> = uni
                        .labels
                        .iter()
                        .enumerate()
                        .map(|(i, &label)| MplsLabel {
                            label,
                            traffic_class: 0,
                            bottom_of_stack: i == last,
                            ttl: 0,
                        })
                        .collect();
                    let mpls = RouteMplsIpTunnel::Destination(stack);
                    let encap = RouteLwTunnelEncap::Mpls(mpls);
                    let attr = NexthopAttribute::Encap(vec![encap]);
                    msg.attributes.push(attr);
                }

                // SRv6 H.Encap. Mutually exclusive with the MPLS branch
                // above — a NexthopUni won't carry both labels and segs.
                if !uni.segs.is_empty() {
                    let encap_type = uni
                        .encap_type
                        .unwrap_or(isis_packet::srv6::EncapType::HEncap);
                    match super::srv6::build_seg6_lwtunnel(&uni.segs, encap_type) {
                        Ok(lwencap) => {
                            msg.attributes
                                .push(NexthopAttribute::EncapType(RouteLwEnCapType::Seg6.into()));
                            msg.attributes.push(NexthopAttribute::Encap(vec![lwencap]));
                        }
                        Err(e) => {
                            tracing::warn!(
                                "SRv6 nexthop encap build failed for gid {}: {:#}",
                                uni.gid(),
                                e
                            );
                            return;
                        }
                    }
                }
            }
            Group::Multi(multi) => {
                // Logging.
                gid = multi.gid();
                refcnt = multi.refcnt();

                // Unspec.
                msg.header.address_family = AddressFamily::Unspec;

                let attr = NexthopAttribute::Id(multi.gid() as u32);
                msg.attributes.push(attr);

                let attr = NexthopAttribute::GroupType(0);
                msg.attributes.push(attr);

                let mut vec = Vec::<NexthopGroup>::new();
                for (id, weight) in multi.valid.iter() {
                    let mut grp = NexthopGroup::default();
                    let weight = if *weight > 0 { *weight - 1 } else { 0 };
                    grp.id = *id as u32;
                    grp.weight = weight;
                    vec.push(grp);
                }
                let attr = NexthopAttribute::Group(vec);
                msg.attributes.push(attr);
            }
            Group::Protect(pro) => {
                // Protection indirection: a 1-member mpath group
                // holding the ACTIVE member (primary in steady state,
                // repair after a switchover). Same encoding as Multi —
                // GroupType 0, kernel weight is value+1 so 0 = 1. The
                // request carries NLM_F_REPLACE, so re-sending after
                // an `active` flip IS the atomic switchover: every
                // route referencing this gid moves in one message.
                gid = pro.gid();
                refcnt = pro.refcnt();

                msg.header.address_family = AddressFamily::Unspec;

                let attr = NexthopAttribute::Id(pro.gid() as u32);
                msg.attributes.push(attr);

                let attr = NexthopAttribute::GroupType(0);
                msg.attributes.push(attr);

                let grp = NexthopGroup {
                    id: pro.active_gid() as u32,
                    weight: 0,
                    ..Default::default()
                };
                let attr = NexthopAttribute::Group(vec![grp]);
                msg.attributes.push(attr);
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let group_summary = fmt_group_for_trace(nexthop);
        tracing::debug!("RTM_NEWNEXTHOP {}", group_summary);

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            match msg.payload {
                NetlinkPayload::Error(e) => {
                    if fib_nexthop() {
                        tracing::info!(
                            "NewNexthop error: {e} gid: {gid} refcnt: {refcnt} {}",
                            group_summary,
                        );
                    }
                }
                // Non-error payloads here are mostly the RTNLGRP_NEXTHOP
                // multicast echoes the kernel delivers on the shared
                // socket while our request is in flight — not real
                // responses. Keep them at debug so steady-state churn
                // doesn't flood the log.
                NetlinkPayload::Done(m) => {
                    tracing::debug!("NewNexthop done {m:?}");
                }
                NetlinkPayload::InnerMessage(e) => {
                    tracing::debug!("NewNexthop inner message {:?}", e);
                }
                NetlinkPayload::Noop => {
                    tracing::debug!("NewNexthop noop");
                }
                NetlinkPayload::Overrun(e) => {
                    tracing::debug!("NewNexthop Overrun {:?}", e);
                }
                _ => {
                    tracing::debug!("NewNexthop other return");
                }
            }
        }
    }

    pub async fn nexthop_del(&self, nexthop: &Group) {
        // Skip nexthop table management for kernels < 5.3
        if !self.use_nhid {
            return;
        }

        // Mirror the unspecified-addr skip in nexthop_add: we never
        // installed a kernel nh_id for these, so don't ask the
        // kernel to delete one (it would just log ENOENT).
        if let Group::Uni(uni) = nexthop
            && uni.addr.is_unspecified()
        {
            return;
        }

        // Nexthop message.
        let mut msg = NexthopMessage::default();
        msg.header.address_family = AddressFamily::Unspec;

        // Nexthop group ID.
        let attr = NexthopAttribute::Id(nexthop.gid() as u32);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelNexthop(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload
                && fib_nexthop()
            {
                tracing::info!(
                    "DelNexthop error: {e} gid: {gid} refcnt: {refcnt} nhop: {nexthop:?}",
                    gid = nexthop.gid(),
                    refcnt = nexthop.refcnt(),
                    nexthop = nexthop,
                );
            }
        }
    }

    /// Install an SRv6 SID into the FIB as a local /128 host route.
    /// Uses the nh_id allocated from NexthopMap when the kernel supports
    /// it, otherwise falls back to embedded seg6local encap on the route
    /// itself (kernels < 5.3).
    pub async fn route_sid_install(&self, sid: &crate::rib::Sid, gid: usize, ifindex: u32) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        // {table, kind, prefix_length, dest_addr} all derive from the
        // behavior. The kernel matches install + uninstall on these
        // four header values, so route_sid_uninstall mirrors the same
        // computation.
        //
        //   End  : table main, kind=unicast, /128, sid.addr
        //          (`ip -6 route add <SID>/128
        //           encap seg6local action End dev sr0`)
        //   End.X: table main, kind=unicast, /128, sid.addr
        //          (`ip -6 route add <SID>/128
        //           encap seg6local action End.X nh6 ... dev ...`)
        //   uN   : table main, kind=unicast, /(LB+LN), masked addr
        //          (`ip -6 route add <locator>/<LB+LN>
        //           encap seg6local action End flavors next-csid
        //           lblen <LB> nflen <LN+Fun> dev sr0`)
        //          uN is a *prefix* install so any function value
        //          under the locator hits this entry; the kernel's
        //          NEXT-C-SID flavor strips and shifts at runtime.
        //   uA   : table main, kind=unicast, /128, sid.addr
        //          Each adjacency function is a unique address;
        //          longest-prefix match picks uA over the wider uN
        //          entry. /128 keeps it simple and matches iproute2.
        // RT_TABLE_LOCAL (255) — the fork doesn't expose a named
        // constant for it, so hard-code. See linux/rtnetlink.h.
        let (table, kind, prefix_len, dest_addr) =
            sid_route_target(sid.behavior, sid.addr, sid.structure);
        // Tee the local SID to the cradle eBPF data plane (mirrors the netlink
        // install below) — the SRv6 analogue of the ILM tee. End.DX2/DX2V are
        // registry-only here: their cradle entries are owned by the
        // AddXconnect tee (which knows the AC / VLAN-table binding);
        // installing from the Sid — whose ifindex is 0 — would clobber a
        // live cross-connect on replay.
        if let Some(cradle) = &self.cradle
            && !matches!(
                sid.behavior,
                crate::rib::SidBehavior::EndDX2 | crate::rib::SidBehavior::EndDX2V
            )
        {
            cradle.local_sid_install(sid, prefix_len, ifindex).await;
        }
        // EVPN-over-SRv6 L2 SIDs are cradle-only: the kernel has no
        // End.DT2U/DT2M/DX2/DX2V seg6local actions, so there is nothing to
        // install via netlink. Same for REPLACE-C-SID (RFC 9800 §4.2): no kernel
        // flavor op exists through 6.8, and a plain-End fallback would
        // misread the packed containers as full SIDs — worse than no entry.
        if matches!(
            sid.behavior,
            crate::rib::SidBehavior::EndDT2U
                | crate::rib::SidBehavior::EndDT2M
                | crate::rib::SidBehavior::EndDX2
                | crate::rib::SidBehavior::EndDX2V
                | crate::rib::SidBehavior::EndRep
                | crate::rib::SidBehavior::EndXRep
                | crate::rib::SidBehavior::EndReplicate
                | crate::rib::SidBehavior::UT
        ) {
            return;
        }
        msg.header.table = table;
        msg.header.destination_prefix_length = prefix_len;
        // Stamp the SID's owning protocol (an OSPFv3 SID used to land
        // as `proto isis` in the kernel regardless of owner).
        msg.header.protocol = sid_route_protocol(sid);
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = kind;

        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(dest_addr)));

        // seg6local always rides as embedded encap on the route — the
        // kernel nh_id table doesn't accept seg6local lwtunnel encaps
        // even when use_nhid is true for the rest of the FIB. Set Oif
        // so the kernel knows where to bind the action; for End / uN
        // that's loopback, for End.X / uA the outgoing link.
        let _ = gid;
        if ifindex != 0 {
            msg.attributes.push(RouteAttribute::Oif(ifindex));
        }
        let Some((encap, encap_type)) = super::srv6::build_seg6local_attrs(
            sid.behavior,
            sid.nh6,
            None,
            sid.structure,
            sid.table_id,
            &sid.segs,
            sid.flavors,
        ) else {
            tracing::warn!(
                "seg6local route encap build skipped for {} (End.X / uA without IPv6 nexthop)",
                sid.addr
            );
            return;
        };
        msg.attributes.push(encap);
        msg.attributes.push(encap_type);

        if fib_srv6() {
            tracing::info!(
                "[route_sid_install] addr={}/{} behavior={:?} ifindex={} nh6={:?} gid={} \
                 use_nhid={} kind={:?} protocol={:?} attrs={:?}",
                sid.addr,
                msg.header.destination_prefix_length,
                sid.behavior,
                ifindex,
                sid.nh6,
                gid,
                self.use_nhid,
                msg.header.kind,
                msg.header.protocol,
                msg.attributes,
            );
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                // warn level so kernel rejections show up without
                // requiring `system tracing fib srv6` — silent failures
                // here are how a misshaped seg6local install slips through.
                tracing::warn!(
                    "NewRoute SID install error: addr={} behavior={:?} \
                     prefix_len={} table={} kind={:?} ifindex={} nh6={:?} \
                     gid={} use_nhid={} err={}",
                    sid.addr,
                    sid.behavior,
                    prefix_len,
                    table,
                    kind,
                    ifindex,
                    sid.nh6,
                    gid,
                    self.use_nhid,
                    e
                );
            }
        }
    }

    /// Replace a local End.DT46 service SID's `/128` with a Mirror SID
    /// redirect: `ip -6 route replace <sid>/128 encap seg6 mode encap
    /// segs [<mirror_sid>] via <nh6> dev <ifindex>`. Used by egress link
    /// protection — when the protected egress's PE-CE link fails it
    /// re-encapsulates traffic for its own service SID toward the
    /// protector's Mirror SID (End.M) instead of decapping locally.
    ///
    /// This is a *route-level* seg6 H.Encaps (not a seg6local endpoint
    /// action): the incoming packet arrives with an already-exhausted SRH
    /// (`segleft=0`), which `End.B6.Encaps` rejects, and the SID address
    /// is no longer a local seg6local binding, so the kernel forwards +
    /// encapsulates it. `NLM_F_REPLACE` swaps the seg6local decap in place;
    /// `route_sid_install` with the original SID restores it.
    pub async fn route_sid_redirect_install(
        &self,
        sid_prefix: &Ipv6Net,
        mirror_sid: Ipv6Addr,
        nh6: Ipv6Addr,
        ifindex: u32,
    ) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.destination_prefix_length = 128;
        msg.header.protocol = RouteProtocol::Isis;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(
                sid_prefix.addr(),
            )));
        msg.attributes.push(RouteAttribute::Oif(ifindex));
        msg.attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet6(nh6)));

        match super::srv6::build_seg6_attrs(&[mirror_sid], isis_packet::srv6::EncapType::HEncap) {
            Ok((encap, encap_type)) => {
                msg.attributes.push(encap);
                msg.attributes.push(encap_type);
            }
            Err(e) => {
                tracing::warn!("mirror redirect encap build failed for {sid_prefix}: {e}");
                return;
            }
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                tracing::warn!(
                    "mirror redirect install error: sid={} mirror_sid={} nh6={} ifindex={} err={}",
                    sid_prefix.addr(),
                    mirror_sid,
                    nh6,
                    ifindex,
                    e
                );
            }
        }
    }

    /// Remove a previously-installed SID host route. Idempotent against
    /// the kernel — a missing entry surfaces as an error in the trace
    /// but doesn't propagate.
    pub async fn route_sid_uninstall(&self, sid: &crate::rib::Sid) {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        // Same {table, kind, prefix_len, dest_addr} the install used
        // — the kernel matches RTM_DELROUTE on (table, family, dst,
        // prefixlen, kind).
        let (table, kind, prefix_len, dest_addr) =
            sid_route_target(sid.behavior, sid.addr, sid.structure);
        if let Some(cradle) = &self.cradle {
            cradle.local_sid_uninstall(sid, prefix_len).await;
        }
        // Cradle-only SIDs (see route_sid_install): nothing in the kernel.
        if matches!(
            sid.behavior,
            crate::rib::SidBehavior::EndDT2U
                | crate::rib::SidBehavior::EndDT2M
                | crate::rib::SidBehavior::EndDX2
                | crate::rib::SidBehavior::EndDX2V
                | crate::rib::SidBehavior::EndRep
                | crate::rib::SidBehavior::EndXRep
                | crate::rib::SidBehavior::EndReplicate
                | crate::rib::SidBehavior::UT
        ) {
            return;
        }
        msg.header.table = table;
        msg.header.destination_prefix_length = prefix_len;
        // Same owner-protocol stamp as the install: the kernel matches
        // RTM_DELROUTE on rtm_protocol, so a hard-coded Isis here left
        // OSPFv3/BGP-owned seg6local routes behind (ESRCH on delete).
        msg.header.protocol = sid_route_protocol(sid);
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = kind;

        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(dest_addr)));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                tracing::info!(
                    "DelRoute SID uninstall error: addr={} behavior={:?} err={}",
                    sid.addr,
                    sid.behavior,
                    e
                );
            }
        }
    }

    /// Install a mirror-context route (draft-ietf-rtgwg-srv6-egress-
    /// protection): in `context_table`, route the protected egress's
    /// locator `prefix` to a `seg6local End.DT46 vrftable=<vrf_table>`.
    /// End.M decapsulates the redirected packet and looks the inner
    /// packet (the protected egress's service SID) up in `context_table`,
    /// where this route re-instantiates that egress's End.DT46 behavior
    /// into the protector's local CE-facing VRF. `ifindex` is the seg6
    /// device (sr0 / lo) the kernel binds the action to.
    pub async fn route_mirror_context_install(
        &self,
        prefix: &Ipv6Net,
        context_table: u32,
        vrf_table: u32,
        ifindex: u32,
    ) {
        if let Some(cradle) = &self.cradle {
            cradle
                .mirror_route_add(context_table, *prefix, vrf_table)
                .await;
        }
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        set_route_table(&mut msg, context_table);
        msg.header.destination_prefix_length = prefix.prefix_len();
        msg.header.protocol = RouteProtocol::Isis;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(
                prefix.addr(),
            )));
        if ifindex != 0 {
            msg.attributes.push(RouteAttribute::Oif(ifindex));
        }
        let Some((encap, encap_type)) = super::srv6::build_seg6local_attrs(
            crate::rib::SidBehavior::EndDT46,
            None,
            None,
            None,
            vrf_table,
            &[],
            0,
        ) else {
            return;
        };
        msg.attributes.push(encap);
        msg.attributes.push(encap_type);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                tracing::warn!(
                    "NewRoute mirror-context install error: prefix={} context_table={} \
                     vrf_table={} ifindex={} err={}",
                    prefix,
                    context_table,
                    vrf_table,
                    ifindex,
                    e
                );
            }
        }
    }

    /// Remove a previously-installed mirror-context route. The kernel
    /// matches RTM_DELROUTE on (table, family, dst, prefixlen, kind), so
    /// only the prefix and context table are needed.
    pub async fn route_mirror_context_uninstall(&self, prefix: &Ipv6Net, context_table: u32) {
        if let Some(cradle) = &self.cradle {
            cradle.mirror_route_del(context_table, *prefix).await;
        }
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        set_route_table(&mut msg, context_table);
        msg.header.destination_prefix_length = prefix.prefix_len();
        msg.header.protocol = RouteProtocol::Isis;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(
                prefix.addr(),
            )));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                tracing::info!(
                    "DelRoute mirror-context uninstall error: prefix={} context_table={} err={}",
                    prefix,
                    context_table,
                    e
                );
            }
        }
    }

    pub async fn bridge_add(&self, bridge: &Bridge) {
        // First create the bridge interface. Bring it up at creation
        // (`ip link add ... up`) so the device is operational without a
        // separate operator step.
        let mut msg = LinkMessage::default();
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;

        let name = LinkAttribute::IfName(bridge.name.clone());
        msg.attributes.push(name);

        let kind = InfoKind::Bridge;
        let link_kind = LinkInfo::Kind(kind);

        let link_info = LinkAttribute::LinkInfo(vec![link_kind]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("NewLink bridge error: {e}");
                return;
            }
        }

        // Set the IPv6 address generation mode as a second operation.
        // Defaults to `none` (no kernel-generated link-local on the
        // bridge) when the operator hasn't configured one.
        let addr_gen_mode = bridge.addr_gen_mode.clone().unwrap_or(AddrGenMode::None);
        self.bridge_set_addr_gen_mode(&bridge.name, &addr_gen_mode)
            .await;
    }

    pub async fn bridge_set_addr_gen_mode(&self, name: &str, addr_gen_mode: &AddrGenMode) {
        let mut msg = LinkMessage::default();

        let link_name = LinkAttribute::IfName(name.to_string());
        msg.attributes.push(link_name);

        let mode =
            LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(vec![AfSpecInet6::AddrGenMode(
                u8::from(addr_gen_mode.clone()),
            )])]);
        msg.attributes.push(mode);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink addr-gen-mode error: {e}");
            }
        }
    }

    pub async fn bridge_del(&self, bridge: &Bridge) {
        let mut msg = LinkMessage::default();

        let name = LinkAttribute::IfName(bridge.name.clone());
        msg.attributes.push(name);

        let kind = InfoKind::Bridge;
        let link_kind = LinkInfo::Kind(kind);

        let link_info = LinkAttribute::LinkInfo(vec![link_kind]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelLink error: {}", e);
            }
        }
    }

    pub async fn vxlan_add(&self, vxlan: &Vxlan) {
        // VNI.
        let Some(vni) = vxlan.vni else {
            return;
        };

        // First create the vxlan interface. Bring it up at creation
        // (`ip link add ... up`) so the device is operational without a
        // separate operator step.
        let mut msg = LinkMessage::default();
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;

        let name = LinkAttribute::IfName(vxlan.name.clone());
        msg.attributes.push(name);

        // Link kind is VxLAN.
        let kind = InfoKind::Vxlan;
        let link_kind = LinkInfo::Kind(kind);

        // EVPN VXLAN device model: `external vnifilter`. The device
        // carries no fixed VNI (`IFLA_VXLAN_ID` = 0); each VNI it serves
        // is registered separately with `bridge vni add` and stamped on
        // every FDB/MDB entry as `src_vni`. This VNI-aware model is what
        // unlocks the kernel VXLAN MDB (per-VTEP `dst` for RFC 9251
        // SMET) — a plain fixed-`id` device cannot carry an MDB `dst`.
        let mut vxlan_info = vec![InfoVxlan::CollectMetadata(true), InfoVxlan::Vnifilter(true)];

        // Destination port. Defaults to the IANA-assigned VXLAN port
        // (4789) when the operator hasn't configured one — Linux would
        // otherwise fall back to the legacy 8472.
        let dport = vxlan.dport.unwrap_or(4789);
        vxlan_info.push(InfoVxlan::Port(dport));

        // Local address.
        if let Some(local_addr) = vxlan.local_addr {
            let info = match local_addr {
                IpAddr::V4(addr) => InfoVxlan::Local(addr.octets().to_vec()),
                IpAddr::V6(addr) => InfoVxlan::Local6(addr.octets().to_vec()),
            };
            vxlan_info.push(info);
        }

        // Disable data-plane MAC learning by default (`nolearning`).
        // EVPN populates the FDB from the BGP control plane, so kernel
        // flood-and-learn must be off.
        vxlan_info.push(InfoVxlan::Learning(false));

        let link_info = LinkInfo::Data(InfoData::Vxlan(vxlan_info));

        let attr = LinkAttribute::LinkInfo(vec![link_kind, link_info]);
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("NewLink vxlan error: {e}");
                return;
            }
        }

        // Register the VNI on the vnifilter device so the kernel accepts
        // and encapsulates traffic for it (`bridge vni add vni N dev X`).
        // The device must exist first, so resolve its ifindex now.
        if let Some(ifindex) = self.link_index_by_name(&vxlan.name).await {
            self.vni_filter_add(ifindex, vni).await;
        }

        // Set the IPv6 address generation mode as a second operation.
        // Defaults to `none` (no kernel-generated link-local on the
        // VXLAN device) when the operator hasn't configured one.
        let addr_gen_mode = vxlan.addr_gen_mode.clone().unwrap_or(AddrGenMode::None);
        self.vxlan_set_addr_gen_mode(&vxlan.name, &addr_gen_mode)
            .await;
    }

    pub async fn vxlan_set_addr_gen_mode(&self, name: &str, addr_gen_mode: &AddrGenMode) {
        let mut msg = LinkMessage::default();

        let link_name = LinkAttribute::IfName(name.to_string());
        msg.attributes.push(link_name);

        let mode =
            LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(vec![AfSpecInet6::AddrGenMode(
                u8::from(addr_gen_mode.clone()),
            )])]);
        msg.attributes.push(mode);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink addr-gen-mode error: {e}");
            }
        }
    }

    /// Apply the VXLAN bridge-slave defaults to the port at `ifindex`:
    /// neighbour suppression on (ARP/ND answered locally from the FDB
    /// instead of flooded), bridge-port MAC learning off (EVPN's BGP
    /// control plane owns the FDB), and per-VLAN tunnel mapping enabled
    /// only for collect-metadata VXLAN (see `vxlan_svd_datapath`).
    /// For metadata devices, equivalent to:
    ///   ip link set <dev> type bridge_slave \
    ///     neigh_suppress on learning off vlan_tunnel on
    /// Called when the RIB observes a VXLAN device gaining a bridge
    /// master; a no-op error is logged if the master is not a bridge.
    pub async fn vxlan_bridge_port_defaults(&self, ifindex: u32, metadata: bool) {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;

        let port_data = InfoPortData::BridgePort(vec![
            InfoBridgePort::NeighSupress(true),
            InfoBridgePort::Learning(false),
            InfoBridgePort::VlanTunnel(metadata),
        ]);
        let link_info = LinkAttribute::LinkInfo(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(port_data),
        ]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink bridge-port defaults error: {e}");
            }
        }
    }

    /// Wire the single-VXLAN-device (external / vnifilter) kernel
    /// datapath for a VXLAN port that joined a bridge, so bridged
    /// traffic actually encapsulates:
    ///
    /// (The access VLAN is [`EVPN_SVD_VLAN`]; the bridge-master FDB
    /// entries `mac_add`/`mac_del` install are scoped to the same VLAN.)
    ///   1. enable `vlan_filtering` on the bridge master — the per-VLAN
    ///      machinery (and thus the tunnel mapping) is dormant without
    ///      it; other ports keep the kernel's `default_pvid 1` untagged
    ///      behaviour, so a flat bridge forwards exactly as before;
    ///   2. add VLAN 1 on the VXLAN port as a TAGGED member (deliberately
    ///      NOT `untagged`: `br_handle_vlan` strips the tag *before* the
    ///      egress tunnel hook runs, and a tag-less frame makes
    ///      `br_handle_egress_vlan_tunnel` bail without attaching the
    ///      tunnel metadata — the hook itself pops the tag);
    ///   3. map VLAN 1 -> the VNI (`bridge vlan add dev <vxlan> vid 1
    ///      tunnel_info id <vni>`), which the bridge egress hook turns
    ///      into `IP_TUNNEL_INFO_BRIDGE|TX` dst-metadata. Without that
    ///      metadata a COLLECT_METADATA device drops every bridged frame
    ///      in `vxlan_xmit` with SKB_DROP_REASON_TUNNEL_TXINFO.
    ///
    /// The decap direction needs no PVID: `br_handle_ingress_vlan_tunnel`
    /// maps the received tunnel id back to VLAN 1 through the same table.
    /// `vlan_tunnel on` for the port is set by
    /// `vxlan_bridge_port_defaults`.
    pub async fn vxlan_svd_datapath(&self, ifindex: u32, bridge_ifindex: u32, vni: u32) {
        use netlink_packet_route::AddressFamily;
        use netlink_packet_route::link::{AfSpecBridge, BridgeVlanInfo, InfoBridge, InfoData};
        use netlink_packet_utils::nla::DefaultNla;

        // 1. vlan_filtering on the bridge master.
        let mut msg = LinkMessage::default();
        msg.header.index = bridge_ifindex;
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Bridge),
            LinkInfo::Data(InfoData::Bridge(vec![InfoBridge::VlanFiltering(true)])),
        ]));
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink bridge vlan_filtering error: {e}");
            }
        }

        // 2. VLAN 1 on the VXLAN port, tagged (flags = 0).
        let mut vinfo = BridgeVlanInfo::default();
        vinfo.flags = 0;
        vinfo.vid = EVPN_SVD_VLAN;
        let mut msg = LinkMessage::default();
        msg.header.interface_family = AddressFamily::Bridge;
        msg.header.index = ifindex;
        msg.attributes
            .push(LinkAttribute::AfSpecBridge(vec![AfSpecBridge::VlanInfo(
                vinfo,
            )]));
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::SetLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink vxlan port vlan error: {e}");
            }
        }

        // 3. VLAN 1 -> VNI tunnel mapping. The crate has no typed
        // IFLA_BRIDGE_VLAN_TUNNEL_INFO (3) support, so hand-encode the
        // nest exactly as iproute2 does:
        //   IFLA_BRIDGE_VLAN_TUNNEL_ID   (1): u32 vni
        //   IFLA_BRIDGE_VLAN_TUNNEL_VID  (2): u16 1
        const NLA_F_NESTED: u16 = 0x8000;
        const IFLA_BRIDGE_VLAN_TUNNEL_INFO: u16 = 3;
        let mut nest: Vec<u8> = Vec::new();
        // TUNNEL_ID: nla_len 8, type 1, u32 payload.
        nest.extend_from_slice(&8u16.to_ne_bytes());
        nest.extend_from_slice(&1u16.to_ne_bytes());
        nest.extend_from_slice(&vni.to_ne_bytes());
        // TUNNEL_VID: nla_len 6, type 2, u16 payload + 2 pad bytes.
        nest.extend_from_slice(&6u16.to_ne_bytes());
        nest.extend_from_slice(&2u16.to_ne_bytes());
        nest.extend_from_slice(&EVPN_SVD_VLAN.to_ne_bytes());
        nest.extend_from_slice(&[0u8; 2]);

        let mut msg = LinkMessage::default();
        msg.header.interface_family = AddressFamily::Bridge;
        msg.header.index = ifindex;
        msg.attributes
            .push(LinkAttribute::AfSpecBridge(vec![AfSpecBridge::Other(
                DefaultNla::new(IFLA_BRIDGE_VLAN_TUNNEL_INFO | NLA_F_NESTED, nest),
            )]));
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::SetLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("SetLink vxlan vlan-tunnel map error: {e}");
            }
        }
    }

    pub async fn vxlan_del(&self, vxlan: &Vxlan) {
        let mut msg = LinkMessage::default();

        let name = LinkAttribute::IfName(vxlan.name.clone());
        msg.attributes.push(name);

        let kind = InfoKind::Vxlan;
        let link_kind = LinkInfo::Kind(kind);

        let link_info = LinkAttribute::LinkInfo(vec![link_kind]);
        msg.attributes.push(link_info);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelLink error: {}", e);
            }
        }
    }

    /// Register a VNI on a `vnifilter` VXLAN device — the netlink
    /// equivalent of `bridge vni add vni <vni> dev <ifindex>`. Required
    /// before an `external vnifilter` device will accept or originate
    /// traffic for that VNI (and before VXLAN-MDB / FDB entries can bind
    /// to it via `src_vni`). Emits `RTM_NEWTUNNEL` carrying one
    /// `VXLAN_VNIFILTER_ENTRY`. (Removal rides on device deletion, which
    /// the kernel cascades, so there is no explicit del counterpart.)
    pub async fn vni_filter_add(&self, ifindex: u32, vni: u32) {
        use netlink_packet_route::RouteNetlinkMessage;
        use netlink_packet_route::tunnel::TunnelMessage;

        let msg = TunnelMessage::vni(ifindex, vni);
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewTunnel(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(rsp) = response.next().await {
            if let NetlinkPayload::Error(e) = rsp.payload
                && e.code.is_some()
            {
                tracing::info!(
                    "vni_filter_add: netlink error vni {} ifindex {}: {}",
                    vni,
                    ifindex,
                    e
                );
            }
        }
    }

    pub async fn link_set_up(&self, ifindex: u32) {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("link_set_up error: {}", e);
            }
        }
    }

    /// Look up a link's ifindex by name via RTM_GETLINK. Returns None on
    /// kernel rejection (most often "device not found").
    pub async fn link_index_by_name(&self, name: &str) -> Option<u32> {
        use futures::TryStreamExt;
        let mut stream = self
            .handle
            .clone()
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match stream.try_next().await {
            Ok(Some(msg)) => Some(msg.header.index),
            _ => None,
        }
    }

    /// Create a dummy link with the given name. Returns the ifindex the
    /// kernel assigned, or None if creation failed (already exists with a
    /// conflicting type, etc.). Mirrors `ip link add <name> type dummy`.
    pub async fn dummy_add(&self, name: &str) -> Option<u32> {
        let result = self
            .handle
            .clone()
            .link()
            .add(LinkDummy::new(name).build())
            .execute()
            .await;
        if let Err(e) = result {
            tracing::warn!("dummy_add({}) error: {}", name, e);
            return None;
        }
        self.link_index_by_name(name).await
    }

    /// Delete a link by name. Idempotent — missing names log at info but
    /// don't propagate.
    pub async fn dummy_del(&self, name: &str) {
        let Some(ifindex) = self.link_index_by_name(name).await else {
            tracing::info!("dummy_del({}) skipped — not present", name);
            return;
        };
        if let Err(e) = self.handle.clone().link().del(ifindex).execute().await {
            tracing::warn!("dummy_del({}) error: {}", name, e);
        }
    }

    /// Create an 802.1Q VLAN sub-interface `name` on the parent link
    /// `parent`, brought up at creation. Mirrors
    /// `ip link add link <parent> name <name> type vlan id <vlan_id>`
    /// followed by `ip link set <name> up`. Returns the ifindex the
    /// kernel assigned, or None if creation failed (name collision,
    /// duplicate vid on the same parent, etc.).
    pub async fn vlan_add(&self, name: &str, parent: u32, vlan_id: u16) -> Option<u32> {
        let result = self
            .handle
            .clone()
            .link()
            .add(LinkVlan::new(name, parent, vlan_id).up().build())
            .execute()
            .await;
        if let Err(e) = result {
            tracing::warn!(
                "vlan_add({}, parent={}, id={}) error: {}",
                name,
                parent,
                vlan_id,
                e
            );
            return None;
        }
        self.link_index_by_name(name).await
    }

    /// Delete a VLAN sub-interface by name. Idempotent — missing names
    /// log at info but don't propagate.
    pub async fn vlan_del(&self, name: &str) {
        let Some(ifindex) = self.link_index_by_name(name).await else {
            tracing::info!("vlan_del({}) skipped — not present", name);
            return;
        };
        if let Err(e) = self.handle.clone().link().del(ifindex).execute().await {
            tracing::warn!("vlan_del({}) error: {}", name, e);
        }
    }

    /// Look up an existing kernel link by name and, if it is a VRF
    /// master device, return `(ifindex, table_id)`. Returns `None` if
    /// the link is absent or isn't a VRF. Lets the daemon adopt a VRF
    /// master left over from a previous run (or pre-created by the
    /// operator) instead of failing the create with EEXIST.
    pub async fn vrf_index_table_by_name(&self, name: &str) -> Option<(u32, u32)> {
        use futures::TryStreamExt;
        let mut stream = self
            .handle
            .clone()
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        let msg = match stream.try_next().await {
            Ok(Some(msg)) => msg,
            _ => return None,
        };
        let ifindex = msg.header.index;
        for attr in msg.attributes.iter() {
            let LinkAttribute::LinkInfo(infos) = attr else {
                continue;
            };
            let is_vrf = infos
                .iter()
                .any(|i| matches!(i, LinkInfo::Kind(InfoKind::Vrf)));
            let table = infos.iter().find_map(|i| match i {
                LinkInfo::Data(InfoData::Vrf(data)) => data.iter().find_map(|d| match d {
                    InfoVrf::TableId(t) => Some(*t),
                    _ => None,
                }),
                _ => None,
            });
            if is_vrf && let Some(t) = table {
                return Some((ifindex, t));
            }
        }
        None
    }

    /// Create a Linux VRF master interface bound to `table_id`. Returns
    /// the ifindex the kernel assigned, or None if creation failed
    /// (table-id collision with another VRF master, name collision with
    /// an existing interface, etc.). Mirrors
    /// `ip link add <name> type vrf table <table_id>` followed by
    /// `ip link set <name> up`.
    pub async fn vrf_add(&self, name: &str, table_id: u32) -> Option<u32> {
        let result = self
            .handle
            .clone()
            .link()
            .add(LinkVrf::new(name, table_id).up().build())
            .execute()
            .await;
        if let Err(e) = result {
            tracing::warn!("vrf_add({}, table={}) error: {}", name, table_id, e);
            return None;
        }
        self.link_index_by_name(name).await
    }

    /// Delete a VRF master interface by name. Idempotent — missing names
    /// log at info but don't propagate. Slave interfaces enslaved to this
    /// VRF are detached by the kernel automatically; per-VRF routes in
    /// the associated table are flushed.
    pub async fn vrf_del(&self, name: &str) {
        let Some(ifindex) = self.link_index_by_name(name).await else {
            tracing::info!("vrf_del({}) skipped — not present", name);
            return;
        };
        if let Err(e) = self.handle.clone().link().del(ifindex).execute().await {
            tracing::warn!("vrf_del({}) error: {}", name, e);
        }
    }

    /// Set or clear the IFLA_MASTER (renamed to `Controller` in
    /// netlink-packet-route) of `ifindex`. Pass `master == 0` to detach
    /// (equivalent to `ip link set <link> nomaster`); a non-zero value
    /// enslaves the link to that master device. Used for VRF interface
    /// binding.
    pub async fn link_set_master(&self, ifindex: u32, master: u32) {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;
        msg.attributes.push(LinkAttribute::Controller(master));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                tracing::warn!(
                    "link_set_master(ifindex={}, master={}) error: {}",
                    ifindex,
                    master,
                    e
                );
            }
        }
    }

    /// Set the MTU of `ifindex` via `RTM_NEWLINK` carrying
    /// `IFLA_MTU`. Mirrors `ip link set <link> mtu <n>`. Returns the
    /// kernel error on rejection (e.g. EINVAL when the value is below
    /// the IPv6 minimum of 1280 on a v6-enabled link) so the caller can
    /// surface the reason; the success path relies on the kernel's
    /// echoed `RTM_NEWLINK` to update the cached `Link::mtu`.
    pub async fn link_set_mtu(&self, ifindex: u32, mtu: u32) -> anyhow::Result<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = ifindex;
        msg.attributes.push(LinkAttribute::Mtu(mtu));

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req)?;
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                return Err(anyhow::anyhow!("{}", e));
            }
        }
        Ok(())
    }

    /// Add an IPv4 address via `RTM_NEWADDR`. No `IFA_F_SECONDARY` is
    /// ever requested: the kernel clears the userspace flag and
    /// recomputes it itself (secondary iff same mask+subnet as an
    /// existing primary), so the flag is read back, never written.
    pub async fn addr_add_ipv4(&self, ifindex: u32, prefix: &Ipv4Net) -> anyhow::Result<()> {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;
        msg.header.scope = AddressScope::Universe;
        let attr = AddressAttribute::Local(IpAddr::V4(prefix.addr()));
        msg.attributes.push(attr);

        // If interface is p2p.
        if false {
            let attr = AddressAttribute::Address(IpAddr::V4(prefix.addr()));
            msg.attributes.push(attr);
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self.handle.clone().request(req)?;
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload
                && let Some(code) = e.code
            {
                // EEXIST: the address is already installed (added outside
                // zebra-rs, or it survived a primary delete because the
                // host runs promote_secondaries=1). The intent — address
                // present in the kernel — holds, so report success.
                if code.get() == -libc::EEXIST {
                    return Ok(());
                }
                return Err(anyhow::anyhow!("NewAddress netlink error: {}", e));
            }
        }
        Ok(())
    }

    pub async fn addr_del_ipv4(&self, ifindex: u32, prefix: &Ipv4Net) {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;

        let attr = AddressAttribute::Local(IpAddr::V4(prefix.addr()));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelAddress error: {}", e);
            }
        }
    }

    /// Add an IPv6 address via `RTM_NEWADDR`. Never sets header flag
    /// bit 0x01: on IPv6 it is `IFA_F_TEMPORARY` (privacy address),
    /// not "secondary" — IPv6 has no secondary concept.
    pub async fn addr_add_ipv6(&self, ifindex: u32, prefix: &Ipv6Net) -> anyhow::Result<()> {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet6;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;
        msg.header.scope = AddressScope::Universe;
        let attr = AddressAttribute::Local(IpAddr::V6(prefix.addr()));
        msg.attributes.push(attr);

        // If interface is p2p.
        if false {
            let attr = AddressAttribute::Address(IpAddr::V6(prefix.addr()));
            msg.attributes.push(attr);
        }

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self.handle.clone().request(req)?;
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload
                && let Some(code) = e.code
            {
                // Same EEXIST tolerance as the IPv4 twin.
                if code.get() == -libc::EEXIST {
                    return Ok(());
                }
                return Err(anyhow::anyhow!("NewAddress IPv6 netlink error: {}", e));
            }
        }
        Ok(())
    }

    pub async fn addr_del_ipv6(&self, ifindex: u32, prefix: &Ipv6Net) {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet6;
        msg.header.prefix_len = prefix.prefix_len();
        msg.header.index = ifindex;

        let attr = AddressAttribute::Local(IpAddr::V6(prefix.addr()));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelAddress(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelAddress IPv6 error: {}", e);
            }
        }
    }

    pub async fn ilm_add(&self, label: u32, ilm: &IlmEntry) {
        self.ilm_install(label, ilm, false).await;
    }

    /// Install an ILM **replacing** any existing route at `label`
    /// (`NLM_F_REPLACE`) instead of failing on collision. Used by the
    /// Mirror Context egress redirect to swap a BGP `DecapVrf` VPN-label
    /// route for a redirect swap (and to restore it), since the kernel
    /// holds one route per label and a plain add is `CREATE | EXCL`.
    pub async fn ilm_replace(&self, label: u32, ilm: &IlmEntry) {
        self.ilm_install(label, ilm, true).await;
    }

    /// Tee an ILM to the cradle eBPF data plane. `DecapVrf`/`ContextLabel`
    /// decap to IP in a VRF, `DecapBd` pops into a bridge domain, and every
    /// other type is a swap whose out stack rides the nexthop — an empty
    /// stack is PHP, popped by the data plane on the packet's S bit.
    /// Multi-member ILM ECMP is not teed yet (first member only).
    ///
    /// Split out of [`Self::ilm_install`] so the post-connect resync can
    /// replay it without re-running the netlink half.
    async fn cradle_ilm_program(&self, label: u32, ilm: &IlmEntry) {
        if let Some(cradle) = &self.cradle {
            match &ilm.ilm_type {
                IlmType::DecapVrf { table_id, .. } | IlmType::ContextLabel { table_id, .. } => {
                    cradle
                        .ilm_install(
                            label,
                            crate::fib::cradle::MPLS_OP_POP_L3,
                            *table_id,
                            None,
                            0,
                            &[],
                        )
                        .await;
                }
                // EVPN-over-MPLS EVI service label: pop and bridge in `bd`.
                IlmType::DecapBd { bd } => {
                    cradle
                        .ilm_install(label, crate::fib::cradle::MPLS_OP_POP_L2, *bd, None, 0, &[])
                        .await;
                }
                // Self prefix-SID (UHP local pop): the loopback nexthop is
                // for the kernel LFIB only — teeing it would make the eBPF
                // pop-and-forward resolve an L2 neighbor on `lo` and punt.
                // A nexthop-less pop takes the chained-pop path instead:
                // whatever sits underneath (a further label, or the IP
                // payload) is also this node's to process.
                _ if ilm.local_pop => {
                    cradle
                        .ilm_install(label, crate::fib::cradle::MPLS_OP_SWAP, 0, None, 0, &[])
                        .await;
                }
                _ => {
                    let uni = match &ilm.nexthop {
                        Nexthop::Uni(u) => Some(u),
                        Nexthop::Multi(m) => m.nexthops.first(),
                        _ => None,
                    };
                    if let Some(u) = uni {
                        let gw = if u.addr.is_unspecified() {
                            None
                        } else {
                            Some(u.addr)
                        };
                        cradle
                            .ilm_install(
                                label,
                                crate::fib::cradle::MPLS_OP_SWAP,
                                0,
                                gw,
                                u.ifindex().unwrap_or(0),
                                &u.mpls_label,
                            )
                            .await;
                    }
                }
            }
        }
    }

    async fn ilm_install(&self, label: u32, ilm: &IlmEntry, replace: bool) {
        self.cradle_ilm_program(label, ilm).await;

        // EVPN-over-MPLS decap is cradle-only. Linux has no action that pops
        // a label and hands the exposed Ethernet frame to a bridge, so there
        // is nothing to program here — and falling through would install a
        // bogus pure-swap route at the EVI's service label. Mirrors
        // `route_sid_install` skipping netlink for the End.DT2U/DT2M SIDs.
        if matches!(ilm.ilm_type, IlmType::DecapBd { .. }) {
            return;
        }

        let create_flags = if replace {
            NLM_F_REPLACE | NLM_F_CREATE
        } else {
            NLM_F_EXCL | NLM_F_CREATE
        };
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Mpls;
        msg.header.destination_prefix_length = 20;

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = match ilm.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };

        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        // BGP/MPLS-VPN per-VRF decap: emit a pure-pop AF_MPLS
        // route — no NEW_DESTINATION (= no swap), just an
        // `Oif(vrf_ifindex)` so the kernel routes the popped
        // packet via the VRF master, which lands in
        // `vrf_tables[table_id]`. Skips the per-`Nexthop` branch
        // because `IlmEntry::nexthop` is `Nexthop::default()` for
        // this variant.
        // The Mirror Context label (RFC 8679) decaps identically to a
        // BGP VPN label: pop + route the inner packet through the VRF.
        if let IlmType::DecapVrf {
            table_id: _,
            vrf_ifindex,
        }
        | IlmType::ContextLabel {
            table_id: _,
            vrf_ifindex,
        } = ilm.ilm_type
        {
            msg.attributes.push(RouteAttribute::Oif(vrf_ifindex));
            let attr = RouteAttribute::Destination(RouteAddress::Mpls(MplsLabel {
                label,
                traffic_class: 0,
                bottom_of_stack: true,
                ttl: 0,
            }));
            msg.attributes.push(attr);
            let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
            req.header.flags = NLM_F_REQUEST | NLM_F_ACK | create_flags;
            let mut response = self.handle.clone().request(req).unwrap();
            while let Some(msg) = response.next().await {
                if let NetlinkPayload::Error(e) = msg.payload {
                    tracing::info!("ilm_add DecapVrf error: {}", e);
                }
            }
            return;
        }

        match ilm.nexthop {
            Nexthop::Uni(ref uni) => {
                let attr = match uni.addr {
                    std::net::IpAddr::V4(ipv4) => RouteAttribute::Via(RouteVia::Inet(ipv4)),
                    std::net::IpAddr::V6(ipv6) => RouteAttribute::Via(RouteVia::Inet6(ipv6)),
                };
                msg.attributes.push(attr);

                if let Some(ifindex) = uni.ifindex() {
                    let attr = RouteAttribute::Oif(ifindex);
                    msg.attributes.push(attr);
                }

                // The outgoing label stack rides a single RTA_NEWDST:
                // one attribute carrying every label (outermost first),
                // BoS set only on the bottom label. Emitting one
                // NewDestination per label would leave the kernel with
                // just the last (duplicate RTA_NEWDST overwrites), which
                // drops the transport label under a swap-and-push — e.g.
                // an Inter-AS Option B VPNv4 transit `local → [SR, VPN]`.
                if !uni.mpls_label.is_empty() {
                    let last = uni.mpls_label.len() - 1;
                    let stack: Vec<MplsLabel> = uni
                        .mpls_label
                        .iter()
                        .enumerate()
                        .map(|(i, &label)| MplsLabel {
                            label,
                            traffic_class: 0,
                            bottom_of_stack: i == last,
                            ttl: 0,
                        })
                        .collect();
                    msg.attributes.push(RouteAttribute::NewDestination(stack));
                }
            }
            Nexthop::Multi(ref multi) => {
                let mut mpath = vec![];
                for uni in multi.nexthops.iter() {
                    let mut nhop = RouteNextHop::default();

                    let attr = match uni.addr {
                        std::net::IpAddr::V4(ipv4) => RouteAttribute::Via(RouteVia::Inet(ipv4)),
                        std::net::IpAddr::V6(ipv6) => RouteAttribute::Via(RouteVia::Inet6(ipv6)),
                    };
                    nhop.attributes.push(attr);

                    if let Some(ifindex) = uni.ifindex() {
                        let attr = RouteAttribute::Oif(ifindex);
                        nhop.attributes.push(attr);
                    }

                    // Full label stack in one RTA_NEWDST (see the Uni arm).
                    if !uni.mpls_label.is_empty() {
                        let last = uni.mpls_label.len() - 1;
                        let stack: Vec<MplsLabel> = uni
                            .mpls_label
                            .iter()
                            .enumerate()
                            .map(|(i, &label)| MplsLabel {
                                label,
                                traffic_class: 0,
                                bottom_of_stack: i == last,
                                ttl: 0,
                            })
                            .collect();
                        nhop.attributes.push(RouteAttribute::NewDestination(stack));
                    }

                    mpath.push(nhop);
                }
                let attr = RouteAttribute::MultiPath(mpath);
                msg.attributes.push(attr);
            }
            _ => {
                // no supoort.
                return;
            }
        }

        let attr = RouteAttribute::Destination(RouteAddress::Mpls(MplsLabel {
            label,
            traffic_class: 0,
            bottom_of_stack: true,
            ttl: 0,
        }));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | create_flags;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("NewRoute error: {label}: {e}");
            }
        }
    }

    pub async fn ilm_del(&self, label: u32, ilm: &IlmEntry) {
        if let Some(cradle) = &self.cradle {
            cradle.ilm_uninstall(label).await;
        }
        // Never installed into the kernel (see `ilm_install`), so there is
        // nothing to delete — and asking would log a spurious ESRCH.
        if matches!(ilm.ilm_type, IlmType::DecapBd { .. }) {
            return;
        }

        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Mpls;
        msg.header.destination_prefix_length = 20;

        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = match ilm.rtype {
            RibType::Static => RouteProtocol::Static,
            RibType::Bgp => RouteProtocol::Bgp,
            RibType::Ospf => RouteProtocol::Ospf,
            RibType::Isis => RouteProtocol::Isis,
            _ => RouteProtocol::Static,
        };

        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let attr = RouteAttribute::Destination(RouteAddress::Mpls(MplsLabel {
            label,
            traffic_class: 0,
            bottom_of_stack: true,
            ttl: 0,
        }));
        msg.attributes.push(attr);

        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(e) = msg.payload {
                tracing::info!("DelRoute error: {}", e);
            }
        }
    }

    /// Register VXLAN interface with its VNI for FDB operations
    /// Called when a VXLAN interface is created to establish VNI→ifindex mapping
    /// Record a VRF's table-id → device-ifindex mapping, so routes in
    /// that table can be teed to FPM with the ifindex it expects.
    pub fn register_vrf_ifindex(&mut self, table_id: u32, ifindex: u32) {
        self.vrf_ifindex_map.insert(table_id, ifindex);
    }

    pub fn unregister_vrf_ifindex(&mut self, table_id: u32) {
        self.vrf_ifindex_map.remove(&table_id);
    }

    pub fn register_vxlan_ifindex(&mut self, vni: u32, ifindex: u32) {
        if fib_l2_vxlan() {
            tracing::info!(
                "[FIB] Registered VXLAN VNI {} with ifindex {}",
                vni,
                ifindex
            );
        }
        self.vni_ifindex_map.insert(vni, ifindex);
    }

    /// Unregister VXLAN interface mapping
    pub fn unregister_vxlan_ifindex(&mut self, vni: u32) {
        if fib_l2_vxlan() {
            tracing::info!("[FIB] Unregistered VXLAN VNI {}", vni);
        }
        self.vni_ifindex_map.remove(&vni);
        self.vni_bridge_map.remove(&vni);
        self.vni_metadata_map.remove(&vni);
    }

    /// The encap and priority a bridge Type-5 route was installed with.
    fn evpn_prefix_tracked(
        &self,
        table_id: u32,
        prefix: IpNet,
    ) -> Option<(crate::rib::VxlanL3Encap, u32)> {
        self.evpn_prefix_routes
            .lock()
            .unwrap()
            .get(&(table_id, prefix))
            .copied()
    }

    /// Withdraw every bridge Type-5 route and its RMAC adjacency. These do
    /// not ride on next-hop objects, so nothing else removes them when the
    /// daemon stops, and the adjacency lives on operator-owned devices.
    pub async fn evpn_prefix_cleanup(&self) {
        let routes: Vec<_> = self
            .evpn_prefix_routes
            .lock()
            .unwrap()
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        for ((table_id, prefix), (encap, metric)) in routes {
            self.evpn_prefix_route(prefix, table_id, metric, encap, false)
                .await;
        }
    }

    /// Install Type-5 prefixes in the tenant kernel table, resolving the
    /// next hop through RMAC neighbor/FDB state on the L3-VNI bridge.
    async fn evpn_prefix_route(
        &self,
        prefix: IpNet,
        table_id: u32,
        metric: u32,
        encap: crate::rib::VxlanL3Encap,
        add: bool,
    ) -> bool {
        // Linux normalizes an IPv6 metric of zero to its default, 1024.
        // Use the same concrete priority for install and withdrawal.
        let metric = if matches!(prefix, IpNet::V6(_)) && metric == 0 {
            1024
        } else {
            metric
        };
        let Some(bridge) = self.evpn_bridge(encap.l3vni).await else {
            tracing::warn!("EVPN Type-5 {prefix}: no bridge for L3 VNI {}", encap.l3vni);
            // Desired state either way: an add is installed when the
            // L3-VNI VXLAN joins a bridge (`evpn_l3vni_reassert`).
            let release = {
                let mut routes = self.evpn_prefix_routes.lock().unwrap();
                if add {
                    routes.insert((table_id, prefix), (encap, metric))
                } else {
                    routes.remove(&(table_id, prefix))
                }
            };
            if let Some((old, _)) = release {
                self.evpn_adjacency_release(&old).await;
            }
            return false;
        };
        // Install the adjacency only for its first prefix; every other
        // prefix behind the same (L3 VNI, VTEP, RMAC) reuses it.
        let shared = add
            && self
                .evpn_prefix_routes
                .lock()
                .unwrap()
                .values()
                .any(|(route, _)| same_evpn_adjacency(route, &encap));
        let mac = MacAddr::from(encap.remote_rmac);
        if add && !shared {
            self.evpn_rmac_install(encap.l3vni, encap.remote_rmac, encap.remote_vtep)
                .await;
            self.evpn_neighbor(encap.l3vni, encap.remote_vtep.into(), mac, true)
                .await;
            // IPv6 routes name the mapped VTEP as their gateway. Linux
            // resolves that in the IPv6 neighbor table, independently of
            // the IPv4 adjacency used by IPv4 routes on the same bridge.
            self.evpn_neighbor(
                encap.l3vni,
                encap.remote_vtep.to_ipv6_mapped().into(),
                mac,
                true,
            )
            .await;
        }
        let success = self
            .evpn_prefix_route_send(prefix, table_id, metric, &encap, bridge, add)
            .await;
        // The map is desired state. An add is recorded even when the kernel
        // rejected it: the usual cause is a down bridge (an onlink route
        // needs its device up), and `evpn_l3vni_reassert` installs it on
        // link up. A delete always forgets the route: a failed one means
        // the kernel no longer has it, and keeping the entry would pin the
        // adjacency.
        let release = {
            let mut routes = self.evpn_prefix_routes.lock().unwrap();
            if add {
                routes.insert((table_id, prefix), (encap, metric))
            } else {
                routes.remove(&(table_id, prefix))
            }
        };
        if let Some((old, old_metric)) = release {
            // The kernel keys a route by its priority too, so an add with a
            // new metric created a second route; remove the old one.
            if add && old_metric != metric {
                self.evpn_prefix_route_send(prefix, table_id, old_metric, &old, bridge, false)
                    .await;
            }
            self.evpn_adjacency_release(&old).await;
        }
        if add && let Some(old_bridge) = self.evpn_note_bridge(encap.l3vni, bridge) {
            // The L3 VNI moved bridges without the link hook seeing it.
            self.evpn_bridge_moved(encap.l3vni, old_bridge).await;
            self.evpn_l3vni_reassert(encap.l3vni, true).await;
        }
        success
    }

    /// Record `bridge` as the one holding `l3vni`'s Type-5 state. Returns
    /// the previous bridge when it differs.
    fn evpn_note_bridge(&self, l3vni: u32, bridge: u32) -> Option<u32> {
        self.evpn_l3vni_bridge
            .lock()
            .unwrap()
            .insert(l3vni, bridge)
            .filter(|old| *old != bridge)
    }

    /// `l3vni`'s state moved off `old_bridge`: remove the VTEP neighbors
    /// left there. Routes need no cleanup; reinstalling them replaces the
    /// same kernel keys with the new device.
    async fn evpn_bridge_moved(&self, l3vni: u32, old_bridge: u32) {
        let adjacencies = {
            let tracked = self.evpn_prefix_routes.lock().unwrap();
            let recorded = self.evpn_rmac_vtep.lock().unwrap();
            evpn_reassert_plan(&tracked, &recorded, l3vni).adjacencies
        };
        for (vtep, rmac) in adjacencies {
            let mac = MacAddr::from(rmac);
            self.evpn_neighbor_on(old_bridge, vtep.into(), mac, false)
                .await;
            self.evpn_neighbor_on(old_bridge, vtep.to_ipv6_mapped().into(), mac, false)
                .await;
        }
    }

    /// The kernel deleted the bridge Type-5 route `(table_id, prefix)` at
    /// priority `metric`. Returns its L3 VNI when it is still desired with
    /// that priority, i.e. someone other than us removed it. Our own
    /// withdrawals and metric changes update the map before the
    /// notification is processed, so they never match.
    pub fn evpn_prefix_deleted(&self, table_id: u32, prefix: IpNet, metric: u32) -> Option<u32> {
        self.evpn_prefix_routes
            .lock()
            .unwrap()
            .get(&(table_id, prefix))
            .filter(|(_, tracked)| *tracked == metric)
            .map(|(encap, _)| encap.l3vni)
    }

    /// Reinstall one desired bridge Type-5 route.
    pub async fn evpn_prefix_reinstall(&self, table_id: u32, prefix: IpNet) {
        let Some((encap, metric)) = self.evpn_prefix_tracked(table_id, prefix) else {
            return;
        };
        let Some(bridge) = self.evpn_bridge(encap.l3vni).await else {
            return;
        };
        self.evpn_prefix_route_send(prefix, table_id, metric, &encap, bridge, true)
            .await;
    }

    /// Send the bridge Type-5 route itself: `prefix` via the remote VTEP
    /// (IPv4-mapped for IPv6) onlink on the L3-VNI `bridge`.
    async fn evpn_prefix_route_send(
        &self,
        prefix: IpNet,
        table_id: u32,
        metric: u32,
        encap: &crate::rib::VxlanL3Encap,
        bridge: u32,
        add: bool,
    ) -> bool {
        use netlink_packet_route::route::RouteFlags;
        let mut msg = RouteMessage::default();
        msg.header.address_family = match prefix {
            IpNet::V4(_) => AddressFamily::Inet,
            IpNet::V6(_) => AddressFamily::Inet6,
        };
        msg.header.destination_prefix_length = prefix.prefix_len();
        msg.header.protocol = RouteProtocol::Bgp;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;
        msg.header.flags = RouteFlags::Onlink;
        set_route_table(&mut msg, table_id);
        let (dst, gateway) = match prefix {
            IpNet::V4(prefix) => (
                RouteAddress::Inet(prefix.addr()),
                RouteAddress::Inet(encap.remote_vtep),
            ),
            IpNet::V6(prefix) => (
                RouteAddress::Inet6(prefix.addr()),
                RouteAddress::Inet6(encap.remote_vtep.to_ipv6_mapped()),
            ),
        };
        msg.attributes.extend([
            RouteAttribute::Destination(dst),
            RouteAttribute::Gateway(gateway),
            RouteAttribute::Oif(bridge),
            RouteAttribute::Priority(metric),
        ]);
        let mut request = NetlinkMessage::from(if add {
            RouteNetlinkMessage::NewRoute(msg)
        } else {
            RouteNetlinkMessage::DelRoute(msg)
        });
        request.header.flags =
            NLM_F_REQUEST | NLM_F_ACK | if add { NLM_F_CREATE | NLM_F_REPLACE } else { 0 };
        let mut success = false;
        if let Ok(mut response) = self.handle.clone().request(request) {
            success = true;
            while let Some(response) = response.next().await {
                if let NetlinkPayload::Error(err) = response.payload {
                    tracing::warn!("EVPN Type-5 {prefix} in table {table_id}: {err}");
                    success = false;
                }
            }
        }
        success
    }

    /// Reinstall the tracked Type-5 state of `l3vni` after the kernel
    /// dropped some of it: the RMAC FDB entries and VTEP neighbors, and
    /// with `routes` the routes too. Every write is an idempotent replace.
    ///
    /// Linux removes these without telling us in a usable way: admin-down
    /// deletes IPv4 routes through the device with no `RTM_DELROUTE`,
    /// carrier loss flushes neighbors (NOARP included), and detaching the
    /// VXLAN port from its bridge flushes its FDB. FRR re-installs on L3VNI
    /// oper-up for the same reason.
    pub async fn evpn_l3vni_reassert(&self, l3vni: u32, routes: bool) {
        let plan = {
            let tracked = self.evpn_prefix_routes.lock().unwrap();
            let recorded = self.evpn_rmac_vtep.lock().unwrap();
            evpn_reassert_plan(&tracked, &recorded, l3vni)
        };
        if plan.routes.is_empty() {
            return;
        }
        let Some(bridge) = self.evpn_bridge(l3vni).await else {
            return;
        };
        if let Some(old_bridge) = self.evpn_note_bridge(l3vni, bridge) {
            self.evpn_bridge_moved(l3vni, old_bridge).await;
        }
        for (rmac, vtep) in &plan.rmacs {
            self.evpn_rmac_install(l3vni, *rmac, *vtep).await;
        }
        for (vtep, rmac) in &plan.adjacencies {
            let mac = MacAddr::from(*rmac);
            self.evpn_neighbor(l3vni, (*vtep).into(), mac, true).await;
            self.evpn_neighbor(l3vni, vtep.to_ipv6_mapped().into(), mac, true)
                .await;
        }
        if routes {
            for ((table_id, prefix), (encap, metric)) in &plan.routes {
                self.evpn_prefix_route_send(*prefix, *table_id, *metric, encap, bridge, true)
                    .await;
            }
        }
    }

    /// The L3 VNIs with tracked Type-5 state whose bridge or VXLAN device
    /// is `ifindex`.
    fn evpn_l3vnis_on(&self, ifindex: u32) -> Vec<u32> {
        let tracked: BTreeSet<u32> = self
            .evpn_prefix_routes
            .lock()
            .unwrap()
            .values()
            .map(|(encap, _)| encap.l3vni)
            .collect();
        tracked
            .into_iter()
            .filter(|vni| {
                self.vni_bridge_map.get(vni) == Some(&ifindex)
                    || self.vni_ifindex_map.get(vni) == Some(&ifindex)
            })
            .collect()
    }

    /// `ifindex` came up: reinstall every L3 VNI it carries.
    pub async fn evpn_link_up(&self, ifindex: u32) {
        for l3vni in self.evpn_l3vnis_on(ifindex) {
            self.evpn_l3vni_reassert(l3vni, true).await;
        }
    }

    /// The kernel deleted a neighbor or FDB row. If it was an RMAC entry
    /// or VTEP neighbor a tracked route still needs, put the adjacency
    /// back. Our own releases forget the state before deleting it, so they
    /// never match here.
    pub async fn evpn_neighbor_deleted(&self, nbr: &crate::fib::FibNeighbor) {
        for l3vni in self.evpn_l3vnis_on(nbr.ifindex) {
            let owned = {
                let tracked = self.evpn_prefix_routes.lock().unwrap();
                evpn_tracked_adjacency_row(tracked.values().map(|(encap, _)| encap), l3vni, nbr)
            };
            if owned {
                self.evpn_l3vni_reassert(l3vni, false).await;
            }
        }
    }

    /// Remove an RMAC adjacency once no tracked Type-5 route uses it.
    async fn evpn_adjacency_release(&self, old: &crate::rib::VxlanL3Encap) {
        let adjacency_used = self
            .evpn_prefix_routes
            .lock()
            .unwrap()
            .values()
            .any(|(route, _)| same_evpn_adjacency(route, old));
        if adjacency_used {
            return;
        }
        let mac = MacAddr::from(old.remote_rmac);
        self.evpn_neighbor(old.l3vni, old.remote_vtep.into(), mac, false)
            .await;
        self.evpn_neighbor(
            old.l3vni,
            old.remote_vtep.to_ipv6_mapped().into(),
            mac,
            false,
        )
        .await;
        // Several VTEPs can share an RMAC; see `evpn_rmac_after_release`.
        let key = (old.l3vni, old.remote_rmac);
        let current = self.evpn_rmac_vtep.lock().unwrap().get(&key).copied();
        let action = {
            let routes = self.evpn_prefix_routes.lock().unwrap();
            evpn_rmac_after_release(routes.values().map(|(route, _)| route), old, current)
        };
        match action {
            RmacAction::Keep => {}
            RmacAction::Repoint(vtep) => {
                self.evpn_rmac_install(old.l3vni, old.remote_rmac, vtep)
                    .await;
            }
            RmacAction::Remove => {
                self.evpn_rmac_vtep.lock().unwrap().remove(&key);
                self.mac_del(old.l3vni, &mac).await;
            }
        }
        let l3vni_used = self
            .evpn_prefix_routes
            .lock()
            .unwrap()
            .values()
            .any(|(route, _)| route.l3vni == old.l3vni);
        if !l3vni_used {
            self.evpn_l3vni_bridge.lock().unwrap().remove(&old.l3vni);
        }
    }

    /// Point the `(l3vni, rmac)` FDB entry at `vtep` and remember it. A
    /// failed write leaves the previous entry in place, so the previous
    /// record stays too; otherwise a later release could trust a VTEP the
    /// kernel never pointed at and leave the entry on a withdrawn one.
    async fn evpn_rmac_install(&self, l3vni: u32, rmac: [u8; 6], vtep: Ipv4Addr) {
        let installed = self
            .mac_add(
                l3vni,
                &MacAddr::from(rmac),
                Some(vtep.into()),
                0,
                0,
                None,
                None,
                None,
            )
            .await;
        if installed {
            self.evpn_rmac_vtep
                .lock()
                .unwrap()
                .insert((l3vni, rmac), vtep);
        }
    }

    /// Resolve the bridge owning an adopted fixed-VNI VXLAN device.
    pub async fn evpn_bridge(&self, vni: u32) -> Option<u32> {
        if let Some(bridge) = self.vni_bridge_map.get(&vni) {
            return Some(*bridge);
        }
        let index = *self.vni_ifindex_map.get(&vni)?;
        let mut links = self.handle.link().get().match_index(index).execute();
        while let Ok(Some(link)) = links.try_next().await {
            for attr in link.attributes {
                if let LinkAttribute::Controller(master) = attr {
                    return Some(master);
                }
            }
        }
        None
    }

    /// Remote MAC/IP bindings are externally learned, non-aging neighbors
    /// on the bridge. On withdrawal protect a binding since replaced locally.
    pub async fn evpn_neighbor(&self, vni: u32, ip: IpAddr, mac: MacAddr, add: bool) {
        let Some(ifindex) = self.evpn_bridge(vni).await else {
            return;
        };
        self.evpn_neighbor_on(ifindex, ip, mac, add).await;
    }

    /// [`Self::evpn_neighbor`] on an explicit bridge.
    async fn evpn_neighbor_on(&self, ifindex: u32, ip: IpAddr, mac: MacAddr, add: bool) {
        use netlink_packet_route::neighbour::{NeighbourFlags, NeighbourState};
        let dst = match ip {
            IpAddr::V4(a) => NeighbourAddress::Inet(a),
            IpAddr::V6(a) => NeighbourAddress::Inet6(a),
        };
        if !add {
            // A point lookup keeps withdrawals independent of table size.
            let mut query = NeighbourMessage::default();
            query.header.family = match ip {
                IpAddr::V4(_) => AddressFamily::Inet,
                IpAddr::V6(_) => AddressFamily::Inet6,
            };
            query.header.ifindex = ifindex;
            query
                .attributes
                .push(NeighbourAttribute::Destination(dst.clone()));
            let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetNeighbour(query));
            request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
            let Ok(mut response) = self.handle.clone().request(request) else {
                return;
            };
            let mut owned = false;
            while let Some(response) = response.next().await {
                if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(row)) =
                    response.payload
                    && row.header.flags.contains(NeighbourFlags::ExtLearned)
                    && row
                        .attributes
                        .contains(&NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()))
                {
                    owned = true;
                }
            }
            if !owned {
                return;
            }
        }
        let mut msg = NeighbourMessage::default();
        msg.header.family = match ip {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        msg.header.ifindex = ifindex;
        msg.header.state = NeighbourState::Noarp;
        msg.header.flags = NeighbourFlags::ExtLearned;
        msg.attributes.push(NeighbourAttribute::Destination(dst));
        msg.attributes
            .push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));
        let mut request = NetlinkMessage::from(if add {
            RouteNetlinkMessage::NewNeighbour(msg)
        } else {
            RouteNetlinkMessage::DelNeighbour(msg)
        });
        request.header.flags =
            NLM_F_REQUEST | NLM_F_ACK | if add { NLM_F_CREATE | NLM_F_REPLACE } else { 0 };
        let Ok(mut response) = self.handle.clone().request(request) else {
            return;
        };
        while let Some(response) = response.next().await {
            if let NetlinkPayload::Error(err) = response.payload {
                tracing::warn!("EVPN neighbor {ip} on bridge {ifindex}: {err}");
            }
        }
    }

    /// Add EVPN remote MAC to the bridge / VXLAN FDB.
    ///
    /// Linux EVPN-VXLAN forwarding requires **two** FDB entries per
    /// remote MAC, both attached to the VXLAN slave interface but
    /// landing in different kernel tables (selected by the netlink
    /// `NTF_*` flag):
    ///
    ///   1. Bridge master FDB — `NTF_MASTER | NTF_EXT_LEARNED`.
    ///      "MAC X is reachable via this slave port." Without this
    ///      entry, frames arriving at the bridge from a local port
    ///      destined for the remote MAC are flooded to every bridge
    ///      port instead of unicast to the VXLAN slave.
    ///
    ///   2. VXLAN self FDB — `NTF_SELF | NTF_EXT_LEARNED`.
    ///      "When a frame is being forwarded out this VXLAN device,
    ///      encapsulate to remote VTEP `dst`." Carries `NDA_DST`,
    ///      `NDA_VNI`, `NDA_SRC_VNI`, `NDA_PORT`.
    ///
    /// Installing only entry 1 leaves no encap target; installing
    /// only entry 2 causes flooding because the bridge can't learn
    /// from BGP. Both are required and FRR programs both. The third
    /// VLAN-tagged variant FRR sometimes adds is only needed when the
    /// bridge is `vlan_filtering 1`; not implemented here yet.
    ///
    /// Returns whether both kernel FDB writes succeeded (`false` with no
    /// VXLAN device for `vni`). The cradle paths hand off and return `true`.
    #[allow(clippy::too_many_arguments)]
    pub async fn mac_add(
        &self,
        vni: u32,
        mac: &MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        _seq: u32,
        esi: Option<[u8; 10]>,
        srv6_sid: Option<std::net::Ipv6Addr>,
        mpls_label: Option<u32>,
    ) -> bool {
        // EVPN over SRv6 (RFC 9252): the MAC sits behind a remote L2 service
        // SID (End.DT2U; the all-ones BUM sentinel behind End.DT2M). The
        // cradle eBPF tee is the L2 data plane — there is no kernel VXLAN
        // FDB row to install (and no VXLAN device is required).
        if let Some(sid) = srv6_sid {
            if let Some(cradle) = &self.cradle {
                cradle.fdb_add(vni, mac.octets(), sid).await;
            }
            return true;
        }
        // EVPN over MPLS (RFC 7432): the MAC sits behind a remote PE, reached
        // by imposing that PE's EVI service label under the transport LSP.
        // cradle-only for the same reason the decap ILM is — the kernel has
        // no MPLS-to-bridge data path — so a label with no cradle tee means
        // this MAC simply is not forwardable, and installing a kernel VXLAN
        // row for it would be worse than doing nothing.
        if let Some(label) = mpls_label {
            if let (Some(cradle), Some(pe)) = (&self.cradle, tunnel_endpoint) {
                cradle.fdb_add_mpls(vni, mac.octets(), pe, label).await;
            }
            return true;
        }
        // EVPN over VXLAN + cradle: the MAC sits behind a remote VTEP of
        // either address family, and the eBPF datapath is the forwarder —
        // install the overlay FDB entry there and skip the kernel VXLAN FDB
        // (cradle owns it). Fires whether or not a kernel VXLAN device
        // exists.
        if let Some(cradle) = &self.cradle
            && let Some(vtep) = tunnel_endpoint
        {
            cradle.fdb_add_vxlan(vni, mac.octets(), vtep).await;
            return true;
        }
        let Some(&vxlan_ifindex) = self.vni_ifindex_map.get(&vni) else {
            if fib_l2_fdb() {
                tracing::info!(
                    "mac_add: no local VXLAN for VNI {} — skipping (mac {})",
                    vni,
                    mac
                );
            }
            return false;
        };

        if fib_l2_fdb() {
            tracing::info!(
                "mac_add: VNI {} mac {} ifindex {} dst {}",
                vni,
                mac,
                vxlan_ifindex,
                tunnel_endpoint
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "-".into()),
            );
        }

        // Entry 1 — bridge master FDB. No VXLAN-specific attrs.
        // NUD_REACHABLE matches what Linux records for kernel-learned
        // entries and what FRR sets on its master-side install.
        const NTF_MASTER: u8 = 0x04;
        const NTF_SELF: u8 = 0x02;
        const NTF_EXT_LEARNED: u8 = 0x10;
        const NTF_STICKY: u8 = 0x40;
        const NUD_REACHABLE: u16 = 0x02;
        const NUD_PERMANENT: u16 = 0x80;

        let master_ok = self
            .fdb_neigh_send(
                vxlan_ifindex,
                mac,
                NTF_MASTER | NTF_EXT_LEARNED,
                NUD_REACHABLE,
                None,
                None,
                self.vni_metadata_map
                    .get(&vni)
                    .copied()
                    .unwrap_or(false)
                    .then_some(EVPN_SVD_VLAN),
                FdbOp::Upsert,
                "mac_add(master)",
            )
            .await;

        // Entry 2 — VXLAN self FDB. Carries the encap target and VNI.
        let mut self_flags: u8 = NTF_SELF | NTF_EXT_LEARNED;
        if (flags & 0x01) != 0 {
            // BGP signaled MAC mobility "sticky" (RFC 7432 §10.6).
            self_flags |= NTF_STICKY;
        }
        let self_ok = self
            .fdb_neigh_send(
                vxlan_ifindex,
                mac,
                self_flags,
                NUD_PERMANENT,
                Some(vni),
                tunnel_endpoint,
                None,
                FdbOp::Upsert,
                "mac_add(self)",
            )
            .await;

        // ESI received and stored. Kernel multi-homing via NDA_NH_ID
        // will be wired when ECMP nexthop groups are supported.
        if let Some(esi_val) = esi
            && esi_val != [0u8; 10]
            && fib_l2_fdb()
        {
            tracing::info!("mac_add: ESI type {} for MAC {}", esi_val[0], mac);
        }
        master_ok && self_ok
    }

    /// Build and send a single AF_BRIDGE FDB neighbour message.
    /// `is_add` selects RTM_NEWNEIGH (with `NLM_F_CREATE | NLM_F_REPLACE`
    /// upsert flags) vs RTM_DELNEIGH. `vni` adds NDA_VNI/NDA_SRC_VNI/
    /// NDA_PORT (only meaningful for VXLAN self entries). `dst` adds
    /// NDA_DST (the remote VTEP IP, also self-only). `vlan` adds
    /// NDA_VLAN, scoping a bridge-master entry to one VLAN — without it
    /// a `vlan_filtering` bridge expands the add to VLAN 0 plus every
    /// VLAN on the port (see [`EVPN_SVD_VLAN`]).
    #[allow(clippy::too_many_arguments)]
    async fn fdb_neigh_send(
        &self,
        ifindex: u32,
        mac: &MacAddr,
        ntf_flags: u8,
        nud_state: u16,
        vni: Option<u32>,
        dst: Option<IpAddr>,
        vlan: Option<u16>,
        op: FdbOp,
        log_label: &str,
    ) -> bool {
        use netlink_packet_route::RouteNetlinkMessage;
        use netlink_packet_route::neighbour::{
            NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
        };

        let mut msg = NeighbourMessage::default();
        msg.header.family = AddressFamily::Bridge;
        msg.header.ifindex = ifindex;
        msg.header.state = NeighbourState::Other(nud_state);
        msg.header.flags = NeighbourFlags::from_bits_retain(ntf_flags);

        msg.attributes
            .push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));

        if let Some(vni) = vni {
            msg.attributes.push(NeighbourAttribute::Vni(vni));
            msg.attributes.push(NeighbourAttribute::SourceVni(vni));
            msg.attributes.push(NeighbourAttribute::Port(4789));
        }
        if let Some(endpoint) = dst {
            let addr = match endpoint {
                IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
                IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
            };
            msg.attributes
                .push(NeighbourAttribute::TunnelEndpoint(addr));
        }
        if let Some(vid) = vlan {
            msg.attributes.push(NeighbourAttribute::Vlan(vid));
        }

        let req = match op {
            FdbOp::Upsert => {
                let mut r = NetlinkMessage::from(RouteNetlinkMessage::NewNeighbour(msg));
                r.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
                r
            }
            FdbOp::Append => {
                // Used for VXLAN BUM ingress-replication entries
                // (zero-MAC + per-peer dst). Multiple peers each
                // contribute their own dst on the same MAC; APPEND
                // adds without clobbering the existing remote list,
                // unlike REPLACE which would erase prior peers' dsts.
                let mut r = NetlinkMessage::from(RouteNetlinkMessage::NewNeighbour(msg));
                r.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;
                r
            }
            FdbOp::Delete => {
                let mut r = NetlinkMessage::from(RouteNetlinkMessage::DelNeighbour(msg));
                r.header.flags = NLM_F_REQUEST | NLM_F_ACK;
                r
            }
        };

        let mut response = self.handle.clone().request(req).unwrap();
        // ACKs are not forwarded (netlink-proto `forward_ack` is off), so
        // any error payload is a failure.
        let mut ok = true;
        while let Some(rsp) = response.next().await {
            if let NetlinkPayload::Error(e) = rsp.payload {
                ok = false;
                tracing::info!(
                    "{}: netlink error mac {} ifindex {} flags 0x{:02x}: {}",
                    log_label,
                    mac,
                    ifindex,
                    ntf_flags,
                    e
                );
            }
        }
        ok
    }

    /// Install (`add`) or remove (`!add`) a selective EVPN multicast
    /// forwarding entry in the kernel bridge MDB: forward `group`
    /// (optionally `source`-filtered) out the VXLAN `port_ifindex`
    /// toward the remote VTEP `dst`. Built from a received Type-6 SMET
    /// route — the kernel snooping bridge then delivers that registered
    /// group selectively to `dst` instead of flooding (RFC 9251).
    /// `bridge_ifindex` is the bridge (`dev`); `port_ifindex` its VXLAN
    /// slave (`port`). Emits `RTM_{NEW,DEL}MDB` with the
    /// `MDBA_SET_ENTRY` / `MDBA_SET_ENTRY_ATTRS` layout
    /// (linux/if_bridge.h).
    pub async fn mdb_install(
        &self,
        bridge_ifindex: u32,
        port_ifindex: u32,
        vid: u16,
        group: IpAddr,
        source: Option<IpAddr>,
        dst: IpAddr,
        vni: u32,
        add: bool,
    ) {
        use netlink_packet_route::mdb::MdbAttribute;
        use netlink_packet_utils::nla::DefaultNla;

        // (1) Bridge MDB — register the group on the bridge toward the
        // VXLAN port (`dev = bridge`, `port = vxlan`) so the snooping
        // bridge forwards it into the overlay. (*,G) is the bare
        // br_mdb_entry; (S,G) nests MDBE_ATTR_SOURCE. No `dst` here — the
        // bridge MDB rejects MDBE_ATTR_DST; per-VTEP selectivity is the
        // VXLAN MDB below.
        let entry = br_mdb_entry_bytes(port_ifindex, vid, group);
        let mut bridge_attrs = vec![MdbAttribute::Other(DefaultNla::new(
            MDBA_SET_ENTRY,
            entry.to_vec(),
        ))];
        if let Some(src) = source {
            bridge_attrs.push(MdbAttribute::Other(DefaultNla::new(
                MDBA_SET_ENTRY_ATTRS | NLA_F_NESTED,
                mdb_nla_bytes(MDBE_ATTR_SOURCE, &ip_octets(src)),
            )));
        }
        self.mdb_send(bridge_ifindex, bridge_attrs, group, dst, add, "bridge")
            .await;

        // (2) VXLAN MDB — per-VTEP overlay selectivity (`dev = port =
        // vxlan`). The nested MDBA_SET_ENTRY_ATTRS carries MDBE_ATTR_DST
        // (the remote VTEP the SMET came from) + MDBE_ATTR_SRC_VNI, plus
        // MDBE_ATTR_SOURCE for (S,G). The kernel then replicates the
        // group only to `dst` instead of BUM-flooding to every VTEP
        // (RFC 9251). Requires an `external vnifilter` VXLAN device (P1b).
        let mut nested = Vec::new();
        if let Some(src) = source {
            nested.extend_from_slice(&mdb_nla_bytes(MDBE_ATTR_SOURCE, &ip_octets(src)));
        }
        nested.extend_from_slice(&mdb_nla_bytes(MDBE_ATTR_DST, &ip_octets(dst)));
        nested.extend_from_slice(&mdb_nla_bytes(MDBE_ATTR_SRC_VNI, &vni.to_ne_bytes()));
        let vxlan_attrs = vec![
            MdbAttribute::Other(DefaultNla::new(
                MDBA_SET_ENTRY,
                br_mdb_entry_bytes(port_ifindex, vid, group).to_vec(),
            )),
            MdbAttribute::Other(DefaultNla::new(MDBA_SET_ENTRY_ATTRS | NLA_F_NESTED, nested)),
        ];
        self.mdb_send(port_ifindex, vxlan_attrs, group, dst, add, "vxlan")
            .await;
    }

    /// Send one `RTM_{NEW,DEL}MDB` for `dev_ifindex` with the supplied
    /// `MDBA_SET_ENTRY` (+ optional nested `MDBA_SET_ENTRY_ATTRS`).
    /// Shared by the bridge-MDB and VXLAN-MDB installs in `mdb_install`.
    async fn mdb_send(
        &self,
        dev_ifindex: u32,
        attributes: Vec<netlink_packet_route::mdb::MdbAttribute>,
        group: IpAddr,
        dst: IpAddr,
        add: bool,
        kind: &str,
    ) {
        use netlink_packet_route::RouteNetlinkMessage;
        use netlink_packet_route::mdb::{MdbHeader, MdbMessage};

        let msg = MdbMessage {
            header: MdbHeader {
                family: AddressFamily::Bridge,
                index: dev_ifindex,
            },
            attributes,
        };

        let req = if add {
            let mut r = NetlinkMessage::from(RouteNetlinkMessage::NewMdb(msg));
            r.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            r
        } else {
            let mut r = NetlinkMessage::from(RouteNetlinkMessage::DelMdb(msg));
            r.header.flags = NLM_F_REQUEST | NLM_F_ACK;
            r
        };

        if fib_l2_mdb() {
            tracing::info!(
                "mdb_install[{}](add={}): dev {} grp {} dst {}",
                kind,
                add,
                dev_ifindex,
                group,
                dst
            );
        }

        let mut response = self.handle.clone().request(req).unwrap();
        while let Some(rsp) = response.next().await {
            if let NetlinkPayload::Error(e) = rsp.payload
                && e.code.is_some()
            {
                tracing::info!(
                    "mdb_install[{}]: netlink error grp {} dst {} (add={}): {}",
                    kind,
                    group,
                    dst,
                    add,
                    e
                );
            }
        }
    }

    /// Delete EVPN MAC entry from bridge FDB
    pub async fn mac_del(&self, vni: u32, mac: &MacAddr) {
        // Tee the delete to cradle first (harmless when the entry was never
        // teed): `MacDel` doesn't say whether the add was VXLAN or SRv6.
        if let Some(cradle) = &self.cradle {
            cradle.fdb_del(vni, mac.octets()).await;
        }
        // Mirror `mac_add` — skip when no local VXLAN registered for
        // this VNI. With `mac_add` skipping installs in the same case,
        // there's nothing in the kernel to delete; the old
        // `unwrap_or(vni)` would have issued a stray RTM_DELNEIGH
        // against a random interface.
        let Some(&vxlan_ifindex) = self.vni_ifindex_map.get(&vni) else {
            if fib_l2_fdb() {
                tracing::info!(
                    "mac_del: no local VXLAN for VNI {} — skipping (mac {})",
                    vni,
                    mac
                );
            }
            return;
        };

        if fib_l2_fdb() {
            tracing::info!("mac_del: VNI {} mac {} ifindex {}", vni, mac, vxlan_ifindex);
        }

        // Mirror `mac_add` — remove BOTH the bridge master entry and
        // the VXLAN self entry. NUD state is irrelevant on delete
        // (kernel matches by family/ifindex/MAC + the NTF flag that
        // selects which FDB table to look in); pass 0.
        const NTF_MASTER: u8 = 0x04;
        const NTF_SELF: u8 = 0x02;

        self.fdb_neigh_send(
            vxlan_ifindex,
            mac,
            NTF_MASTER,
            0,
            None,
            None,
            self.vni_metadata_map
                .get(&vni)
                .copied()
                .unwrap_or(false)
                .then_some(EVPN_SVD_VLAN),
            FdbOp::Delete,
            "mac_del(master)",
        )
        .await;
        self.fdb_neigh_send(
            vxlan_ifindex,
            mac,
            NTF_SELF,
            0,
            Some(vni),
            None,
            None,
            FdbOp::Delete,
            "mac_del(self)",
        )
        .await;
    }

    /// Install a remote VTEP for VXLAN BUM ingress replication
    /// (EVPN Type-3 Inclusive Multicast).
    ///
    /// **Implementation note**: despite the historical name (`mdb_add`),
    /// this does NOT use kernel MDB. RTM_NEWMDB is for IGMP/MLD
    /// snooping on the bridge — completely separate machinery. The
    /// correct kernel mechanism for VXLAN BUM head-end replication
    /// is an FDB entry on the VXLAN device with a zero MAC and the
    /// remote VTEP IP as `dst`:
    ///
    ///     bridge fdb add 00:00:00:00:00:00 dev <vxlan> dst <peer-VTEP> self
    ///
    /// When the VXLAN device forwards BUM (broadcast / unknown
    /// unicast / multicast) it replicates to every `dst` listed
    /// across its zero-MAC FDB rows. Each peer's Type-3 contributes
    /// one row; we use `NLM_F_APPEND` so multiple peers' `dst`s
    /// coexist instead of clobbering one another.
    ///
    /// The `source` and `seq` parameters from the original MDB
    /// signature are accepted for ABI compatibility but unused here.
    /// Renaming the function and message are a follow-up.
    pub async fn mdb_add(
        &self,
        vni: u32,
        group: IpAddr,
        _source: Option<IpAddr>,
        _ifindex: u32,
        _seq: u32,
    ) {
        // EVPN over VXLAN + cradle: the remote VTEP `group` — either
        // address family — joins the VNI's eBPF flood set (ingress
        // replication); cradle owns the datapath, so skip the kernel
        // zero-MAC FDB.
        if let Some(cradle) = &self.cradle {
            cradle.repl_slot_add_vxlan(vni, group).await;
            return;
        }
        let Some(&vxlan_ifindex) = self.vni_ifindex_map.get(&vni) else {
            if fib_l2_mdb() {
                tracing::info!(
                    "mdb_add: no local VXLAN for VNI {} — skipping (group {})",
                    vni,
                    group
                );
            }
            return;
        };

        if fib_l2_mdb() {
            tracing::info!(
                "mdb_add: VNI {} dst {} ifindex {} (zero-MAC FDB / ingress replication)",
                vni,
                group,
                vxlan_ifindex,
            );
        }

        const NTF_SELF: u8 = 0x02;
        const NTF_EXT_LEARNED: u8 = 0x10;
        const NUD_PERMANENT: u16 = 0x80;

        // Zero-MAC entry on the VXLAN device. Under the `external
        // vnifilter` model the device has no fixed VNI, so the BUM
        // ingress-replication row must carry `src_vni` (NDA_SRC_VNI) to
        // bind it to this VNI; NDA_VNI sets the VNI used when
        // encapsulating the replicated BUM traffic to `group` (the
        // remote VTEP).
        self.fdb_neigh_send(
            vxlan_ifindex,
            &MacAddr::from([0u8; 6]),
            NTF_SELF | NTF_EXT_LEARNED,
            NUD_PERMANENT,
            Some(vni),
            Some(group),
            None,
            FdbOp::Append,
            "mdb_add(zero-mac)",
        )
        .await;
    }

    /// Remove a remote VTEP from VXLAN BUM ingress replication.
    /// Counterpart of `mdb_add`; same rationale on naming.
    pub async fn mdb_del(&self, vni: u32, group: IpAddr, _source: Option<IpAddr>, _ifindex: u32) {
        if let Some(cradle) = &self.cradle {
            cradle.repl_slot_del_vxlan(vni, group).await;
            return;
        }
        let Some(&vxlan_ifindex) = self.vni_ifindex_map.get(&vni) else {
            if fib_l2_mdb() {
                tracing::info!(
                    "mdb_del: no local VXLAN for VNI {} — skipping (group {})",
                    vni,
                    group
                );
            }
            return;
        };

        if fib_l2_mdb() {
            tracing::info!(
                "mdb_del: VNI {} dst {} ifindex {} (zero-MAC FDB / ingress replication)",
                vni,
                group,
                vxlan_ifindex,
            );
        }

        const NTF_SELF: u8 = 0x02;

        self.fdb_neigh_send(
            vxlan_ifindex,
            &MacAddr::from([0u8; 6]),
            NTF_SELF,
            0,
            Some(vni),
            Some(group),
            None,
            FdbOp::Delete,
            "mdb_del(zero-mac)",
        )
        .await;
    }
}

fn link_type_msg(link_type: LinkLayerType) -> link::LinkType {
    match link_type {
        LinkLayerType::Ether => link::LinkType::Ethernet,
        LinkLayerType::Loopback => link::LinkType::Loopback,
        _ => link::LinkType::Ethernet,
    }
}

pub fn link_from_msg(msg: LinkMessage) -> FibLink {
    let mut link = FibLink::new();
    link.index = msg.header.index;
    link.link_type = link_type_msg(msg.header.link_layer_type);
    link.flags = msg.header.flags;
    for attr in msg.attributes.into_iter() {
        match attr {
            LinkAttribute::IfName(name) => {
                link.name = name;
            }
            LinkAttribute::Mtu(mtu) => {
                link.mtu = mtu;
            }
            LinkAttribute::Address(addr) => {
                link.mac = MacAddr::from_vec(addr);
            }
            LinkAttribute::Controller(idx) => {
                // `IFLA_MASTER` (kernel constant; rtnetlink renamed
                // the variant to `Controller`). Slave-of-bridge /
                // slave-of-VRF membership.
                link.master = Some(idx);
            }
            LinkAttribute::Link(idx) => {
                // `IFLA_LINK` — the lower device of a stacked link
                // (the parent of a VLAN sub-interface). Distinct from
                // `IFLA_MASTER` above, which is enslavement.
                link.parent = Some(idx);
            }
            LinkAttribute::LinkInfo(infos) => {
                // VXLAN link data carries both the VNI (`IFLA_VXLAN_ID`)
                // and the local VTEP source IP (`IFLA_VXLAN_LOCAL` or
                // `IFLA_VXLAN_LOCAL6`); VRF master devices carry their
                // kernel routing table (`IFLA_VRF_TABLE`); VLAN
                // sub-interfaces carry their 802.1Q id
                // (`IFLA_VLAN_ID`). Walk every sub-attr and capture
                // them. Other link types contribute nothing.
                for info in infos {
                    if let LinkInfo::Data(InfoData::Vxlan(vxlan_attrs)) = info {
                        for v in vxlan_attrs {
                            match v {
                                InfoVxlan::Id(vni) => link.vni = Some(vni),
                                InfoVxlan::CollectMetadata(metadata) => {
                                    link.vxlan_metadata = Some(metadata)
                                }
                                InfoVxlan::Local(bytes) if bytes.len() == 4 => {
                                    link.vxlan_local = Some(IpAddr::V4(std::net::Ipv4Addr::new(
                                        bytes[0], bytes[1], bytes[2], bytes[3],
                                    )));
                                }
                                InfoVxlan::Local6(bytes) if bytes.len() == 16 => {
                                    let mut octets = [0u8; 16];
                                    octets.copy_from_slice(&bytes);
                                    link.vxlan_local =
                                        Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                                }
                                _ => {}
                            }
                        }
                    } else if let LinkInfo::Data(InfoData::Vrf(vrf_attrs)) = info {
                        for v in vrf_attrs {
                            if let InfoVrf::TableId(t) = v {
                                link.vrf_table = Some(t);
                            }
                        }
                    } else if let LinkInfo::Data(InfoData::Vlan(vlan_attrs)) = info {
                        for v in vlan_attrs {
                            if let InfoVlan::Id(id) = v {
                                link.vlan_id = Some(id);
                            }
                        }
                    } else if let LinkInfo::Kind(InfoKind::Bridge) = info {
                        link.bridge = true;
                    }
                }
            }
            _ => {}
        }
    }

    link
}

pub fn addr_from_msg(msg: AddressMessage) -> FibAddr {
    let mut os_addr = FibAddr::new();
    os_addr.link_index = msg.header.index;
    os_addr.scope = AddrScope::from_kernel(u8::from(msg.header.scope));
    // The header byte is the truncated legacy copy of the flags; the
    // 32-bit `IFA_FLAGS` attribute below supersedes it when present.
    let mut flag_bits = msg.header.flags.bits() as u32;
    for attr in msg.attributes.into_iter() {
        match attr {
            AddressAttribute::Address(addr) => match addr {
                IpAddr::V4(v4) => {
                    if let Ok(v4) = Ipv4Net::new(v4, msg.header.prefix_len) {
                        os_addr.addr = IpNet::V4(v4);
                    }
                }
                IpAddr::V6(v6) => {
                    if let Ok(v6) = Ipv6Net::new(v6, msg.header.prefix_len) {
                        os_addr.addr = IpNet::V6(v6);
                    }
                }
            },
            AddressAttribute::Flags(flags) => {
                flag_bits = flags.bits();
            }
            AddressAttribute::CacheInfo(ci) => {
                os_addr.valid_lft = Some(ci.ifa_valid);
                os_addr.preferred_lft = Some(ci.ifa_preferred);
            }
            _ => {
                //
            }
        }
    }
    // IFA_F_SECONDARY is kernel-computed for IPv4: the kernel sets it
    // when an address shares mask+subnet with an existing primary on
    // the device. The same bit on an IPv6 address is IFA_F_TEMPORARY
    // (a privacy address), so it must not map to `secondary`.
    let is_v6 = msg.header.family == AddressFamily::Inet6;
    os_addr.secondary = msg.header.family == AddressFamily::Inet && flag_bits & 0x01 != 0;
    os_addr.flags = AddrFlags::from_kernel(is_v6, flag_bits);
    os_addr
}

struct RouteBuilder {
    pub prefix: Option<IpNet>,
    pub entry: RibEntry,
}

impl RouteBuilder {
    pub fn new() -> Self {
        let mut entry = RibEntry::new(RibType::Kernel);
        entry.set_valid(true);
        Self {
            prefix: None,
            entry,
        }
    }

    pub fn build(mut self) -> (IpNet, RibEntry) {
        match &mut self.entry.nexthop {
            Nexthop::Uni(uni) => {
                // Kernel-dump path: the entry.ifindex is what netlink
                // reported, so it's an origin (the kernel's source of
                // truth). 0 means "no Oif attribute on this route" —
                // record as None rather than fabricate an origin.
                uni.ifindex_origin = (self.entry.ifindex != 0).then_some(self.entry.ifindex);
                uni.metric = self.entry.metric;
            }
            Nexthop::Blackhole(metric) => {
                // System-route withdrawal matches the next-hop metric.
                // In particular, Linux supplies metric 1024 for IPv6
                // discard routes even when no priority was configured.
                *metric = self.entry.metric;
            }
            _ => {
                //
            }
        }
        (self.prefix.unwrap(), self.entry)
    }

    pub fn ipv4_prefix(mut self, prefix: Ipv4Net) -> Self {
        self.prefix = Some(IpNet::V4(prefix));
        self
    }

    pub fn ipv6_prefix(mut self, prefix: Ipv6Net) -> Self {
        self.prefix = Some(IpNet::V6(prefix));
        self
    }

    pub fn rtype(mut self, rtype: RibType) -> Self {
        self.entry.rtype = rtype;
        self
    }

    pub fn nexthop(mut self, nexthop: Nexthop) -> Self {
        self.entry.nexthop = nexthop;
        self
    }

    pub fn oif(mut self, oif: u32) -> Self {
        self.entry.ifindex = oif;
        self
    }

    pub fn metric(mut self, metric: u32) -> Self {
        self.entry.metric = metric;
        self
    }
}

/// `(table, prefix, priority)` of a protocol-BGP unicast route in a VRF
/// table: the shape of a bridge Type-5 route. IPv6 priority 0 reads as
/// Linux's 1024, matching what `evpn_prefix_route` records.
fn bgp_vrf_route_key(msg: &RouteMessage) -> Option<(u32, IpNet, u32)> {
    if msg.header.protocol != RouteProtocol::Bgp || msg.header.kind != RouteType::Unicast {
        return None;
    }
    let mut table_id = msg.header.table as u32;
    let mut metric = 0;
    let mut dst = None;
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Table(t) => table_id = *t,
            RouteAttribute::Priority(p) => metric = *p,
            RouteAttribute::Destination(RouteAddress::Inet(a)) => dst = Some(IpAddr::V4(*a)),
            RouteAttribute::Destination(RouteAddress::Inet6(a)) => dst = Some(IpAddr::V6(*a)),
            _ => {}
        }
    }
    if table_id == RouteHeader::RT_TABLE_MAIN as u32 {
        return None;
    }
    let len = msg.header.destination_prefix_length;
    let prefix = match (msg.header.address_family, dst) {
        (AddressFamily::Inet, dst) => IpNet::V4(
            Ipv4Net::new(
                match dst {
                    Some(IpAddr::V4(a)) => a,
                    None => Ipv4Addr::UNSPECIFIED,
                    _ => return None,
                },
                len,
            )
            .ok()?,
        ),
        (AddressFamily::Inet6, dst) => {
            if metric == 0 {
                metric = 1024;
            }
            IpNet::V6(
                Ipv6Net::new(
                    match dst {
                        Some(IpAddr::V6(a)) => a,
                        None => Ipv6Addr::UNSPECIFIED,
                        _ => return None,
                    },
                    len,
                )
                .ok()?,
            )
        }
        _ => return None,
    };
    Some((table_id, prefix, metric))
}

/// What `evpn_l3vni_reassert` reinstalls for one L3 VNI.
#[derive(Debug, Default, PartialEq, Eq)]
struct EvpnReassertPlan {
    /// RMAC → the VTEP its FDB entry should point at: the recorded one
    /// while a tracked route still uses it, else the lowest user.
    rmacs: BTreeMap<[u8; 6], Ipv4Addr>,
    /// `(VTEP, RMAC)` neighbor adjacencies.
    adjacencies: BTreeSet<(Ipv4Addr, [u8; 6])>,
    routes: Vec<((u32, IpNet), (crate::rib::VxlanL3Encap, u32))>,
}

fn evpn_reassert_plan(
    tracked: &BTreeMap<(u32, IpNet), (crate::rib::VxlanL3Encap, u32)>,
    recorded: &BTreeMap<(u32, [u8; 6]), Ipv4Addr>,
    l3vni: u32,
) -> EvpnReassertPlan {
    let mut plan = EvpnReassertPlan::default();
    for (key, (encap, metric)) in tracked {
        if encap.l3vni != l3vni {
            continue;
        }
        plan.routes.push((*key, (*encap, *metric)));
        plan.adjacencies
            .insert((encap.remote_vtep, encap.remote_rmac));
    }
    for (vtep, rmac) in &plan.adjacencies {
        let current = recorded.get(&(l3vni, *rmac)).copied();
        let users = plan.adjacencies.iter().filter(|(_, mac)| mac == rmac);
        let keep = current.filter(|cur| users.clone().any(|(v, _)| v == cur));
        plan.rmacs
            .entry(*rmac)
            .and_modify(|chosen| {
                if keep.is_none() && *vtep < *chosen {
                    *chosen = *vtep;
                }
            })
            .or_insert(keep.unwrap_or(*vtep));
    }
    plan
}

/// Whether a deleted kernel row is state a tracked route in `l3vni` needs:
/// an RMAC FDB row, or a VTEP neighbor (IPv4 or IPv4-mapped IPv6) whose
/// MAC is that adjacency's RMAC.
fn evpn_tracked_adjacency_row<'a>(
    mut tracked: impl Iterator<Item = &'a crate::rib::VxlanL3Encap>,
    l3vni: u32,
    nbr: &crate::fib::FibNeighbor,
) -> bool {
    let Some(mac) = nbr.lladdr.map(|m| m.octets()) else {
        return false;
    };
    tracked.any(|encap| {
        encap.l3vni == l3vni
            && encap.remote_rmac == mac
            && match nbr.family {
                AddressFamily::Bridge => true,
                _ => nbr.dst.is_some_and(|dst| {
                    dst == IpAddr::V4(encap.remote_vtep)
                        || dst == IpAddr::V6(encap.remote_vtep.to_ipv6_mapped())
                }),
            }
    })
}

/// What to do with an `(L3 VNI, RMAC)` FDB entry once the adjacency `old`
/// is released.
#[derive(Debug, PartialEq, Eq)]
enum RmacAction {
    /// It still points at a VTEP in use.
    Keep,
    /// It pointed at the released VTEP; another VTEP still uses the RMAC.
    Repoint(Ipv4Addr),
    /// No remaining route uses the RMAC in this VNI.
    Remove,
}

/// Several VTEPs can advertise one RMAC, but the FDB holds a single
/// destination. Remove the entry with its last user; if it pointed at the
/// released VTEP, re-point it at a remaining one (the lowest, for
/// determinism), as FRR's `zl3vni_remote_rmac_del` does.
fn evpn_rmac_after_release<'a>(
    remaining: impl Iterator<Item = &'a crate::rib::VxlanL3Encap>,
    old: &crate::rib::VxlanL3Encap,
    current: Option<Ipv4Addr>,
) -> RmacAction {
    let next = remaining
        .filter(|route| route.l3vni == old.l3vni && route.remote_rmac == old.remote_rmac)
        .map(|route| route.remote_vtep)
        .min();
    match next {
        None => RmacAction::Remove,
        Some(_) if current.is_some_and(|vtep| vtep != old.remote_vtep) => RmacAction::Keep,
        Some(vtep) => RmacAction::Repoint(vtep),
    }
}

/// Whether two Type-5 encaps resolve through the same RMAC adjacency.
fn same_evpn_adjacency(a: &crate::rib::VxlanL3Encap, b: &crate::rib::VxlanL3Encap) -> bool {
    a.l3vni == b.l3vni && a.remote_vtep == b.remote_vtep && a.remote_rmac == b.remote_rmac
}

/// Translate a kernel next-hop object (`RTM_NEWNEXTHOP`, as a dump
/// returns it) into a [`FibNexthop`]. None without an id.
pub fn nexthop_from_msg(msg: &NexthopMessage) -> Option<FibNexthop> {
    let mut nexthop = FibNexthop {
        id: nexthop_id_from_msg(msg)?,
        ours: msg.header.protocol == RouteProtocol::Zebra,
        gateway: None,
        ifindex: None,
        group: Vec::new(),
    };
    for attr in &msg.attributes {
        match attr {
            NexthopAttribute::Gateway(RouteAddress::Inet(addr)) => {
                nexthop.gateway = Some(std::net::IpAddr::V4(*addr));
            }
            NexthopAttribute::Gateway(RouteAddress::Inet6(addr)) => {
                nexthop.gateway = Some(std::net::IpAddr::V6(*addr));
            }
            NexthopAttribute::Oif(ifindex) => nexthop.ifindex = Some(*ifindex),
            NexthopAttribute::Group(members) => {
                nexthop.group = members.iter().map(|member| member.id).collect();
            }
            _ => {}
        }
    }
    Some(nexthop)
}

/// The next hop a route forwarding through kernel next-hop object `id`
/// has, as `nexthops` (the startup dump) describe it: a gateway, or a
/// group's member gateways. None for an object not found, or one without
/// a gateway (a blackhole, an interface route).
fn nexthop_of_object(id: u32, nexthops: &BTreeMap<u32, FibNexthop>) -> Option<Nexthop> {
    let uni = |id: &u32| {
        let nexthop = nexthops.get(id)?;
        let addr = nexthop.gateway?;
        Some(NexthopUni {
            addr,
            ifindex_origin: nexthop.ifindex,
            ..Default::default()
        })
    };
    let nexthop = nexthops.get(&id)?;
    if nexthop.group.is_empty() {
        return uni(&id).map(Nexthop::Uni);
    }
    let nexthops: Vec<NexthopUni> = nexthop.group.iter().filter_map(uni).collect();
    (!nexthops.is_empty()).then(|| {
        Nexthop::Multi(NexthopMulti {
            nexthops,
            ..Default::default()
        })
    })
}

pub fn route_from_msg(msg: RouteMessage) -> Option<FibRoute> {
    route_from_msg_with(msg, &BTreeMap::new(), false)
}

/// [`route_from_msg`] for a route the startup dump found (`dump`): one
/// naming a kernel next-hop object (`RTA_NH_ID`) gets that object's
/// gateway, from `nexthops`; it used to come in with no next hop at all.
/// One of OSPF's (`RTPROT_OSPF`) was left by an earlier run of zebra-rs,
/// and comes in as a stale OSPF entry (`RibEntry::stale`), IPv6 too; it
/// used to come in as a kernel route, which outranked OSPF's own.
pub fn route_from_msg_with(
    msg: RouteMessage,
    nexthops: &BTreeMap<u32, FibNexthop>,
    dump: bool,
) -> Option<FibRoute> {
    let mut builder = RouteBuilder::new();
    let leftover = dump && msg.header.protocol == RouteProtocol::Ospf;

    if msg.header.scope == RouteScope::Host {
        return None;
    }
    let protocol = msg.header.protocol;
    if msg.header.address_family == AddressFamily::Inet6 && !leftover {
        // IPv6 interface prefix routes (fe80::/64 included) are scope
        // universe, so the Link-scope test below does not catch them. The
        // RIB already derives connected routes from the addresses. An
        // RTPROT_ISIS route can only be an earlier run's leftover, which
        // must not come back as a distance-0 kernel route that outranks
        // the fresh IS-IS route.
        if matches!(protocol, RouteProtocol::Kernel | RouteProtocol::Isis) {
            return None;
        }
    }
    // Discard prefixes can be redistributed just like unicast prefixes.
    // Their originating protocol does not identify a particular consumer.
    let blackhole = msg.header.kind == RouteType::BlackHole;
    if msg.header.kind != RouteType::Unicast && !blackhole {
        return None;
    }
    if blackhole {
        builder = builder.nexthop(Nexthop::Blackhole(0));
    }
    if msg.header.protocol == RouteProtocol::Dhcp {
        builder = builder.rtype(RibType::Dhcp);
    }
    if msg.header.scope == RouteScope::Link {
        builder = builder.rtype(RibType::Connected);
    }
    if leftover {
        builder = builder.rtype(RibType::Ospf);
    }
    if msg.header.destination_prefix_length == 0 && msg.header.address_family == AddressFamily::Inet
    {
        let prefix = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        builder = builder.ipv4_prefix(prefix);
    }

    if msg.header.destination_prefix_length == 0
        && msg.header.address_family == AddressFamily::Inet6
    {
        builder = builder.ipv6_prefix(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap());
    }

    // `rtm_table` is a single byte; ids > 255 arrive as
    // `RT_TABLE_UNSPEC` in the header with the real id in `RTA_TABLE`.
    let mut table_id = msg.header.table as u32;

    for attr in msg.attributes.into_iter() {
        match attr {
            RouteAttribute::Table(t) => {
                table_id = t;
            }
            RouteAttribute::Priority(metric) => {
                builder = builder.metric(metric);
            }
            RouteAttribute::Destination(RouteAddress::Inet(n)) => {
                let prefix = Ipv4Net::new(n, msg.header.destination_prefix_length).unwrap();
                builder = builder.ipv4_prefix(prefix);
            }
            RouteAttribute::Destination(RouteAddress::Inet6(n)) => {
                let prefix = Ipv6Net::new(n, msg.header.destination_prefix_length).unwrap();
                builder = builder.ipv6_prefix(prefix);
            }
            RouteAttribute::Oif(ifindex) => {
                builder = builder.oif(ifindex);
            }
            RouteAttribute::Nhid(id) => {
                if let Some(nexthop) = nexthop_of_object(id, nexthops) {
                    // `build` takes a single next hop's interface from the
                    // route's, which a route through an object leaves to it.
                    if let Nexthop::Uni(uni) = &nexthop
                        && let Some(ifindex) = uni.ifindex_origin
                    {
                        builder = builder.oif(ifindex);
                    }
                    builder = builder.nexthop(nexthop);
                }
            }
            RouteAttribute::Gateway(RouteAddress::Inet(n)) => {
                let uni = NexthopUni {
                    addr: std::net::IpAddr::V4(n),
                    ..Default::default()
                };
                builder = builder.nexthop(Nexthop::Uni(uni));
            }
            RouteAttribute::Gateway(RouteAddress::Inet6(n)) => {
                let uni = NexthopUni {
                    addr: std::net::IpAddr::V6(n),
                    ..Default::default()
                };
                builder = builder.nexthop(Nexthop::Uni(uni));
            }
            RouteAttribute::MultiPath(e) => {
                let mut multi = NexthopMulti::default();
                for nhop in e.iter() {
                    for attr in nhop.attributes.iter() {
                        let addr = match attr {
                            RouteAttribute::Gateway(RouteAddress::Inet(n)) => IpAddr::V4(*n),
                            RouteAttribute::Gateway(RouteAddress::Inet6(n)) => IpAddr::V6(*n),
                            _ => continue,
                        };
                        multi.nexthops.push(NexthopUni {
                            addr,
                            ifindex_origin: (nhop.interface_index != 0)
                                .then_some(nhop.interface_index),
                            ..Default::default()
                        });
                    }
                }
                builder = builder.nexthop(Nexthop::Multi(multi));
            }
            RouteAttribute::EncapType(_e) => {
                // tracing::info!("XXX EncapType {}", e);
            }
            RouteAttribute::Encap(_e) => {
                // tracing::info!("XXX Encap {:?}", e);
            }

            _ => {
                //
            }
        }
    }
    // BGP routes in a VRF table are our own EVPN/VPN imports: never
    // redistribute them back. Main-table BGP routes can belong to another
    // daemon, such as an underlay bgpd, so NHT and redistribution keep them.
    if protocol == RouteProtocol::Bgp && table_id != RouteHeader::RT_TABLE_MAIN as u32 {
        return None;
    }
    match builder.prefix? {
        IpNet::V6(v6) if v6.addr().is_unicast_link_local() => return None,
        _ => {}
    }

    let (prefix, mut entry) = builder.build();
    if leftover {
        entry.stale = true;
        entry.distance = 110;
    }

    let msg = FibRoute {
        prefix,
        entry,
        table_id,
    };

    Some(msg)
}

/// Translate a kernel `RTM_NEWNEIGH` / `RTM_DELNEIGH` payload into the
/// internal [`FibNeighbor`] form. Supports the three address families
/// the consumer cares about today:
///
/// - `AF_INET` — ARP entries (NDA_DST = IPv4 protocol address,
///   NDA_LLADDR = MAC).
/// - `AF_INET6` — NDP entries (NDA_DST = IPv6 protocol address,
///   NDA_LLADDR = MAC).
/// - `AF_BRIDGE` — FDB entries (NDA_LLADDR = MAC, NDA_DST optional =
///   remote VTEP IP for VXLAN, NDA_VNI optional, NDA_VLAN optional).
///
/// Other families fall through with the header populated and the
/// attribute fields left at their defaults — easier to debug than
/// silently dropping them.
pub fn neighbor_from_msg(msg: NeighbourMessage) -> FibNeighbor {
    let mut nbr = FibNeighbor {
        family: msg.header.family,
        ifindex: msg.header.ifindex,
        state: msg.header.state,
        flags: msg.header.flags,
        ..Default::default()
    };

    for attr in msg.attributes.into_iter() {
        match attr {
            NeighbourAttribute::Destination(addr) => match addr {
                NeighbourAddress::Inet(v4) => nbr.dst = Some(IpAddr::V4(v4)),
                NeighbourAddress::Inet6(v6) => nbr.dst = Some(IpAddr::V6(v6)),
                NeighbourAddress::Other(_) => {}
                // Non-exhaustive enum; future-proof against new variants.
                _ => {}
            },
            NeighbourAttribute::LinkLocalAddress(bytes) => {
                nbr.lladdr = MacAddr::from_vec(bytes);
            }
            NeighbourAttribute::Vlan(vlan) => nbr.vlan = Some(vlan),
            NeighbourAttribute::Vni(vni) => nbr.vni = Some(vni),
            NeighbourAttribute::Controller(idx) => nbr.master = Some(idx),
            _ => {}
        }
    }

    nbr
}

fn process_msg(msg: NetlinkMessage<RouteNetlinkMessage>, tx: UnboundedSender<FibMessage>) {
    // netlink-proto synthesizes an `Overrun` payload when recv fails
    // with ENOBUFS — the kernel dropped an unknown number of
    // notifications because the receive queue was full. Surface it so
    // the RIB can re-dump kernel state instead of silently drifting.
    if matches!(msg.payload, NetlinkPayload::Overrun(_)) {
        let _ = tx.send(FibMessage::Overrun);
        return;
    }
    // Every arm forwards a parsed event to the RIB inbox. If RIB has
    // already shut down (or panicked) the receiver is dropped and the
    // send returns `SendError`; that is benign here — we don't want a
    // closing channel to take down the netlink reader task with a
    // secondary panic.
    if let NetlinkPayload::InnerMessage(msg) = msg.payload {
        match msg {
            RouteNetlinkMessage::NewLink(msg) => {
                if msg.header.interface_family != AddressFamily::Unspec {
                    return;
                }
                let link = link_from_msg(msg);
                let _ = tx.send(FibMessage::NewLink(link));
            }
            RouteNetlinkMessage::DelLink(msg) => {
                if msg.header.interface_family != AddressFamily::Unspec {
                    return;
                }
                let link = link_from_msg(msg);
                let _ = tx.send(FibMessage::DelLink(link));
            }
            RouteNetlinkMessage::NewAddress(msg) => {
                let addr = addr_from_msg(msg);
                let _ = tx.send(FibMessage::NewAddr(addr));
            }
            RouteNetlinkMessage::DelAddress(msg) => {
                let addr = addr_from_msg(msg);
                let _ = tx.send(FibMessage::DelAddr(addr));
            }
            RouteNetlinkMessage::NewRoute(msg) => {
                if let Some(route) = route_from_msg(msg) {
                    let _ = tx.send(FibMessage::NewRoute(route));
                }
            }
            RouteNetlinkMessage::DelRoute(msg) => {
                // Our own VRF BGP routes are filtered out of the RIB feed
                // below, but a deletion by someone else must still reach
                // the bridge Type-5 owner so it can reinstall the route.
                if let Some((table_id, prefix, metric)) = bgp_vrf_route_key(&msg) {
                    let _ = tx.send(FibMessage::EvpnRouteDeleted {
                        table_id,
                        prefix,
                        metric,
                    });
                }
                if let Some(route) = route_from_msg(msg) {
                    let _ = tx.send(FibMessage::DelRoute(route));
                }
            }
            RouteNetlinkMessage::NewNexthop(msg) => {
                if let Some(id) = nexthop_id_from_msg(&msg) {
                    let _ = tx.send(FibMessage::NewNexthop(id));
                }
            }
            RouteNetlinkMessage::DelNexthop(msg) => {
                if let Some(id) = nexthop_id_from_msg(&msg) {
                    let _ = tx.send(FibMessage::DelNexthop(id));
                }
            }
            RouteNetlinkMessage::NewNeighbour(msg) => {
                let neighbor = neighbor_from_msg(msg);
                let _ = tx.send(FibMessage::NewNeighbor(neighbor));
            }
            RouteNetlinkMessage::DelNeighbour(msg) => {
                let neighbor = neighbor_from_msg(msg);
                let _ = tx.send(FibMessage::DelNeighbor(neighbor));
            }
            RouteNetlinkMessage::NewMdb(msg) => {
                for entry in mdb_entries_from_msg(&msg) {
                    let _ = tx.send(FibMessage::NewMdb(entry));
                }
            }
            RouteNetlinkMessage::DelMdb(msg) => {
                for entry in mdb_entries_from_msg(&msg) {
                    let _ = tx.send(FibMessage::DelMdb(entry));
                }
            }
            _ => {}
        }
    }
}

/// Convert a kernel `RTM_{NEW,DEL}MDB` message into per-group
/// [`FibMdbEntry`] events. Only IP multicast groups are surfaced —
/// statically-added L2 MAC groups carry no IGMP/MLD membership and are
/// skipped. The bridge ifindex (`header.index`) is mapped to a VNI by
/// the RIB.
// MDB SET request attribute kinds (linux/if_bridge.h). The top-level
// container is MDBA_SET_ENTRY (the br_mdb_entry struct) + the nested
// MDBA_SET_ENTRY_ATTRS holding per-entry MDBE_ATTR_* attributes.
const MDBA_SET_ENTRY: u16 = 1;
const MDBA_SET_ENTRY_ATTRS: u16 = 2;
const MDBE_ATTR_SOURCE: u16 = 1;
/// VXLAN-MDB per-entry attributes (linux/if_bridge.h): the remote VTEP
/// (`MDBE_ATTR_DST`) and the source VNI (`MDBE_ATTR_SRC_VNI`). Only
/// accepted on a VNI-aware `external vnifilter` VXLAN device.
const MDBE_ATTR_DST: u16 = 5;
const MDBE_ATTR_SRC_VNI: u16 = 9;
/// `NLA_F_NESTED` (linux/netlink.h) — the kernel expects it on the
/// `MDBA_SET_ENTRY_ATTRS` container (matches what iproute2 sets).
const NLA_F_NESTED: u16 = 0x8000;
const MDB_PERMANENT: u8 = 1;
const ETH_P_IP_BE: u16 = 0x0800;
const ETH_P_IPV6_BE: u16 = 0x86dd;

/// Build a `struct br_mdb_entry` (28 octets) for an MDB SET request.
/// Integer fields (`ifindex`, `vid`) are host byte order; the address
/// union and `proto` are network byte order.
fn br_mdb_entry_bytes(port_ifindex: u32, vid: u16, group: IpAddr) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..4].copy_from_slice(&port_ifindex.to_ne_bytes());
    b[4] = MDB_PERMANENT;
    b[6..8].copy_from_slice(&vid.to_ne_bytes());
    match group {
        IpAddr::V4(g) => {
            b[8..12].copy_from_slice(&g.octets());
            b[24..26].copy_from_slice(&ETH_P_IP_BE.to_be_bytes());
        }
        IpAddr::V6(g) => {
            b[8..24].copy_from_slice(&g.octets());
            b[24..26].copy_from_slice(&ETH_P_IPV6_BE.to_be_bytes());
        }
    }
    b
}

/// Encode one netlink attribute (host-endian header) with 4-byte tail
/// padding: `[len u16][kind u16][value][pad]`.
fn mdb_nla_bytes(kind: u16, value: &[u8]) -> Vec<u8> {
    let len = 4 + value.len();
    let mut out = Vec::with_capacity((len + 3) & !3);
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn ip_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

pub(crate) fn mdb_entries_from_msg(
    msg: &netlink_packet_route::mdb::MdbMessage,
) -> Vec<FibMdbEntry> {
    use netlink_packet_route::mdb::MdbGroup;
    let bridge_ifindex = msg.header.index;
    msg.entries()
        .into_iter()
        .filter_map(|e| {
            let group = match e.group {
                MdbGroup::V4(g) => IpAddr::V4(g),
                MdbGroup::V6(g) => IpAddr::V6(g),
                MdbGroup::Mac(_) => return None,
            };
            Some(FibMdbEntry {
                bridge_ifindex,
                vid: e.vid,
                group,
                source: e.source,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evpn_shared_rmac_follows_remaining_vtep() {
        let encap = |vtep: &str| crate::rib::VxlanL3Encap {
            remote_vtep: vtep.parse().unwrap(),
            l3vni: 2000,
            remote_rmac: [2, 0, 0, 0, 0x20, 1],
        };
        let (a, b, c) = (encap("192.0.2.1"), encap("192.0.2.2"), encap("192.0.2.3"));
        let other_vni = crate::rib::VxlanL3Encap { l3vni: 3000, ..a };
        // The FDB points at the released VTEP: move it to a remaining one.
        assert_eq!(
            evpn_rmac_after_release([&c, &b].into_iter(), &a, Some(a.remote_vtep)),
            RmacAction::Repoint(b.remote_vtep)
        );
        // It points at a VTEP still in use: leave it.
        assert_eq!(
            evpn_rmac_after_release([&b].into_iter(), &a, Some(b.remote_vtep)),
            RmacAction::Keep
        );
        // Last user of the RMAC in this VNI: remove it. Another VNI's use
        // of the same RMAC does not keep it.
        assert_eq!(
            evpn_rmac_after_release([&other_vni].into_iter(), &a, Some(a.remote_vtep)),
            RmacAction::Remove
        );
    }

    #[test]
    fn evpn_reassert_plan_covers_every_tracked_piece() {
        let rmac = [2, 0, 0, 0, 0x20, 1];
        let encap = |vtep: &str, l3vni: u32| crate::rib::VxlanL3Encap {
            remote_vtep: vtep.parse().unwrap(),
            l3vni,
            remote_rmac: rmac,
        };
        let (a, b) = (encap("192.0.2.1", 2000), encap("192.0.2.2", 2000));
        let mut tracked = BTreeMap::new();
        tracked.insert((100, "10.20.1.0/24".parse().unwrap()), (a, 0));
        tracked.insert((100, "2001:db8:20:1::/64".parse().unwrap()), (a, 1024));
        tracked.insert((100, "10.20.2.0/24".parse().unwrap()), (b, 0));
        tracked.insert(
            (300, "10.30.0.0/24".parse().unwrap()),
            (encap("192.0.2.1", 3000), 0),
        );

        // The FDB follows its recorded VTEP while that VTEP is still used.
        let recorded = BTreeMap::from([((2000, rmac), b.remote_vtep)]);
        let plan = evpn_reassert_plan(&tracked, &recorded, 2000);
        assert_eq!(plan.routes.len(), 3, "only this L3 VNI's routes");
        assert_eq!(
            plan.adjacencies,
            BTreeSet::from([(a.remote_vtep, rmac), (b.remote_vtep, rmac)])
        );
        assert_eq!(plan.rmacs, BTreeMap::from([(rmac, b.remote_vtep)]));

        // No usable record: the lowest VTEP using the RMAC.
        let stale = BTreeMap::from([((2000, rmac), "192.0.2.9".parse().unwrap())]);
        let plan = evpn_reassert_plan(&tracked, &stale, 2000);
        assert_eq!(plan.rmacs, BTreeMap::from([(rmac, a.remote_vtep)]));

        assert_eq!(
            evpn_reassert_plan(&tracked, &BTreeMap::new(), 9999),
            EvpnReassertPlan::default()
        );
    }

    #[test]
    fn evpn_deleted_row_matches_only_tracked_adjacencies() {
        use crate::fib::FibNeighbor;
        let rmac = [2, 0, 0, 0, 0x20, 1];
        let vtep: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let tracked = [crate::rib::VxlanL3Encap {
            remote_vtep: vtep,
            l3vni: 2000,
            remote_rmac: rmac,
        }];
        let row = |family, dst: Option<IpAddr>, mac: [u8; 6]| FibNeighbor {
            family,
            dst,
            lladdr: Some(MacAddr::from(mac)),
            ..Default::default()
        };
        let other_mac = [2, 0, 0, 0, 0x99, 1];
        let owned =
            |nbr: &FibNeighbor, l3vni| evpn_tracked_adjacency_row(tracked.iter(), l3vni, nbr);
        // The RMAC FDB row and both VTEP neighbors are ours.
        assert!(owned(&row(AddressFamily::Bridge, None, rmac), 2000));
        assert!(owned(
            &row(AddressFamily::Inet, Some(vtep.into()), rmac),
            2000
        ));
        assert!(owned(
            &row(
                AddressFamily::Inet6,
                Some(vtep.to_ipv6_mapped().into()),
                rmac
            ),
            2000
        ));
        // A neighbor for a VTEP we released, another MAC, or another VNI
        // is not.
        assert!(!owned(
            &row(
                AddressFamily::Inet,
                Some("192.0.2.2".parse().unwrap()),
                rmac
            ),
            2000
        ));
        assert!(!owned(&row(AddressFamily::Bridge, None, other_mac), 2000));
        assert!(!owned(&row(AddressFamily::Bridge, None, rmac), 3000));
        assert!(!owned(
            &FibNeighbor {
                lladdr: None,
                ..row(AddressFamily::Bridge, None, rmac)
            },
            2000
        ));
    }

    #[test]
    fn bgp_vrf_route_key_matches_bridge_type5_routes_only() {
        let msg = |family, dst: RouteAddress, len, table, protocol, priority: Option<u32>| {
            let mut msg = RouteMessage::default();
            msg.header.address_family = family;
            msg.header.destination_prefix_length = len;
            msg.header.kind = RouteType::Unicast;
            msg.header.protocol = protocol;
            set_route_table(&mut msg, table);
            msg.attributes.push(RouteAttribute::Destination(dst));
            if let Some(priority) = priority {
                msg.attributes.push(RouteAttribute::Priority(priority));
            }
            msg
        };
        let v4 = RouteAddress::Inet("10.20.1.0".parse().unwrap());
        let v6 = RouteAddress::Inet6("2001:db8:20:1::".parse().unwrap());
        // IPv4 metric 0 carries no RTA_PRIORITY.
        assert_eq!(
            bgp_vrf_route_key(&msg(
                AddressFamily::Inet,
                v4.clone(),
                24,
                100,
                RouteProtocol::Bgp,
                None
            )),
            Some((100, "10.20.1.0/24".parse().unwrap(), 0))
        );
        // A table id above 255 rides in RTA_TABLE.
        assert_eq!(
            bgp_vrf_route_key(&msg(
                AddressFamily::Inet6,
                v6.clone(),
                64,
                1000,
                RouteProtocol::Bgp,
                Some(1024)
            )),
            Some((1000, "2001:db8:20:1::/64".parse().unwrap(), 1024))
        );
        // Not ours: main table, or another protocol.
        assert!(
            bgp_vrf_route_key(&msg(
                AddressFamily::Inet,
                v4.clone(),
                24,
                254,
                RouteProtocol::Bgp,
                None
            ))
            .is_none()
        );
        assert!(
            bgp_vrf_route_key(&msg(
                AddressFamily::Inet,
                v4,
                24,
                100,
                RouteProtocol::Static,
                None
            ))
            .is_none()
        );
    }

    #[test]
    fn kernel_blackholes_and_bgp_feedback_filter() {
        for (family, prefix, destination) in [
            (
                AddressFamily::Inet,
                "10.20.0.0/24",
                RouteAddress::Inet("10.20.0.0".parse().unwrap()),
            ),
            (
                AddressFamily::Inet6,
                "2001:db8:20::/64",
                RouteAddress::Inet6("2001:db8:20::".parse().unwrap()),
            ),
        ] {
            let prefix: IpNet = prefix.parse().unwrap();
            let mut msg = RouteMessage::default();
            msg.header.address_family = family;
            msg.header.destination_prefix_length = prefix.prefix_len();
            msg.header.kind = RouteType::BlackHole;
            msg.header.protocol = RouteProtocol::Static;
            set_route_table(&mut msg, 100);
            msg.attributes
                .push(RouteAttribute::Destination(destination));
            msg.attributes.push(RouteAttribute::Priority(1024));
            for protocol in [
                RouteProtocol::Static,
                RouteProtocol::Boot,
                RouteProtocol::Other(200),
            ] {
                msg.header.protocol = protocol;
                for dump in [true, false] {
                    let route = route_from_msg_with(msg.clone(), &BTreeMap::new(), dump).unwrap();
                    assert_eq!(route.prefix, prefix);
                    assert_eq!(route.table_id, 100);
                    assert_eq!(route.entry.rtype, RibType::Kernel);
                    assert!(matches!(route.entry.nexthop, Nexthop::Blackhole(1024)));
                }
            }
            for kind in [RouteType::Unreachable, RouteType::Prohibit] {
                msg.header.kind = kind;
                assert!(route_from_msg(msg.clone()).is_none());
            }
            msg.header.protocol = RouteProtocol::Bgp;
            msg.header.kind = RouteType::Unicast;
            for dump in [true, false] {
                assert!(
                    route_from_msg_with(msg.clone(), &BTreeMap::new(), dump).is_none(),
                    "BGP output must not feed back as kernel input"
                );
            }
            // Another daemon's main-table BGP route (an underlay bgpd)
            // stays visible to NHT.
            let mut main = msg.clone();
            set_route_table(&mut main, RouteHeader::RT_TABLE_MAIN as u32);
            let route = route_from_msg(main).expect("main-table BGP route");
            assert_eq!(route.entry.rtype, RibType::Kernel);
        }
    }

    #[test]
    fn ipv6_prefix_link_local_and_isis_leftover_routes_not_mirrored() {
        let v6_route = |dest: &str, len: u8, protocol: RouteProtocol| {
            let mut msg = RouteMessage::default();
            msg.header.address_family = AddressFamily::Inet6;
            msg.header.destination_prefix_length = len;
            msg.header.kind = RouteType::Unicast;
            msg.header.protocol = protocol;
            set_route_table(&mut msg, RouteHeader::RT_TABLE_MAIN as u32);
            msg.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet6(
                    dest.parse().unwrap(),
                )));
            msg.attributes.push(RouteAttribute::Oif(3));
            msg
        };
        for dump in [true, false] {
            for msg in [
                v6_route("2001:db8:1::", 64, RouteProtocol::Kernel),
                v6_route("fe80::", 64, RouteProtocol::Kernel),
                v6_route("fe80::", 64, RouteProtocol::Boot),
                v6_route("2001:db8:2::", 64, RouteProtocol::Isis),
            ] {
                assert!(route_from_msg_with(msg, &BTreeMap::new(), dump).is_none());
            }
            let route = route_from_msg_with(
                v6_route("2001:db8:3::", 64, RouteProtocol::Boot),
                &BTreeMap::new(),
                dump,
            )
            .expect("operator IPv6 route");
            assert_eq!(route.entry.rtype, RibType::Kernel);
        }
    }

    #[test]
    fn link_decode_distinguishes_fixed_vni_and_metadata_vxlan() {
        for metadata in [false, true] {
            let mut msg = LinkMessage::default();
            msg.attributes.push(LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Vxlan),
                LinkInfo::Data(InfoData::Vxlan(vec![
                    InfoVxlan::Id(if metadata { 0 } else { 1000 }),
                    InfoVxlan::CollectMetadata(metadata),
                ])),
            ]));
            let link = link_from_msg(msg);
            assert_eq!(link.vxlan_metadata, Some(metadata));
            assert_eq!(link.vni, Some(if metadata { 0 } else { 1000 }));
        }
        // A partial link notification must not change the cached mode.
        assert_eq!(link_from_msg(LinkMessage::default()).vxlan_metadata, None);
    }

    // Guards the netlink-packet-route group-nexthop decode fix our
    // RTNLGRP_NEXTHOP reconciliation depends on. These are the exact
    // bytes of a kernel group notification (RTM_NEWNEXTHOP, id 15,
    // mpath, members {2, 7}) that the unfixed library dropped with
    // "failed to decode packet ... type 104". If this fails, the dep
    // regressed and reconciliation is silently broken again.
    #[test]
    fn decodes_rtm_newnexthop_group() {
        let bytes: &[u8] = &[
            0x3c, 0x00, 0x00, 0x00, 0x68, 0x00, 0x05, 0x05, 0x59, 0x00, 0x00, 0x00, 0xff, 0x1f,
            0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
            0x0f, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,
            0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = netlink_packet_core::NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes);
        assert!(
            parsed.is_ok(),
            "RTM_NEWNEXTHOP decode regressed: {:?}",
            parsed.err()
        );
    }

    use netlink_packet_route::address::AddressHeaderFlags;

    fn addr_msg(family: AddressFamily, flags: AddressHeaderFlags, addr: IpAddr) -> AddressMessage {
        let mut msg = AddressMessage::default();
        msg.header.family = family;
        msg.header.prefix_len = 24;
        msg.header.index = 3;
        msg.header.flags = flags;
        msg.attributes.push(AddressAttribute::Address(addr));
        msg
    }

    #[test]
    fn addr_from_msg_reads_v4_secondary_flag() {
        use std::net::Ipv4Addr;
        let msg = addr_msg(
            AddressFamily::Inet,
            AddressHeaderFlags::Secondary,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        );
        let addr = addr_from_msg(msg);
        assert!(addr.secondary);
        assert_eq!(addr.link_index, 3);
        assert_eq!(addr.addr.to_string(), "10.0.0.2/24");
    }

    #[test]
    fn addr_from_msg_v4_primary_is_not_secondary() {
        use std::net::Ipv4Addr;
        let msg = addr_msg(
            AddressFamily::Inet,
            AddressHeaderFlags::empty(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        assert!(!addr_from_msg(msg).secondary);
    }

    #[test]
    fn addr_from_msg_v6_temporary_bit_is_not_secondary() {
        // On IPv6 the 0x01 header flag is IFA_F_TEMPORARY (a privacy
        // address), not "secondary" — it must never map to the flag.
        use std::net::Ipv6Addr;
        let msg = addr_msg(
            AddressFamily::Inet6,
            AddressHeaderFlags::Secondary,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        );
        let addr = addr_from_msg(msg);
        assert!(!addr.secondary);
        assert!(addr.flags.temporary, "v6 0x01 is IFA_F_TEMPORARY");
    }

    #[test]
    fn addr_from_msg_reads_ifa_flags_attribute() {
        // The 32-bit IFA_FLAGS attribute supersedes the truncated
        // header byte. A fresh static v6 address arrives tentative
        // (DAD running) and permanent.
        use netlink_packet_route::address::AddressFlags;
        use std::net::Ipv6Addr;
        let mut msg = addr_msg(
            AddressFamily::Inet6,
            AddressHeaderFlags::empty(),
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        );
        msg.attributes.push(AddressAttribute::Flags(
            AddressFlags::Tentative | AddressFlags::Permanent,
        ));
        let addr = addr_from_msg(msg);
        assert!(addr.flags.tentative);
        assert!(addr.flags.permanent);
        assert!(!addr.flags.temporary);
        assert!(!addr.secondary);
    }

    #[test]
    fn addr_from_msg_header_flags_are_the_fallback() {
        // No IFA_FLAGS attribute → the legacy 8-bit header copy is
        // still honored.
        use std::net::Ipv6Addr;
        let msg = addr_msg(
            AddressFamily::Inet6,
            AddressHeaderFlags::Deprecated,
            IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        );
        assert!(addr_from_msg(msg).flags.deprecated);
    }

    #[test]
    fn addr_from_msg_reads_scope_and_cacheinfo() {
        use netlink_packet_route::address::{CacheInfo, CacheInfoBuffer};
        use netlink_packet_utils::Parseable;
        use std::net::Ipv6Addr;
        let mut msg = addr_msg(
            AddressFamily::Inet6,
            AddressHeaderFlags::empty(),
            IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
        );
        msg.header.scope = netlink_packet_route::address::AddressScope::Link;
        // struct ifa_cacheinfo: preferred, valid, cstamp, tstamp.
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&14400u32.to_ne_bytes());
        bytes[4..8].copy_from_slice(&86400u32.to_ne_bytes());
        let ci = CacheInfo::parse(&CacheInfoBuffer::new(&bytes)).unwrap();
        msg.attributes.push(AddressAttribute::CacheInfo(ci));
        let addr = addr_from_msg(msg);
        assert_eq!(addr.scope, crate::rib::link::AddrScope::Link);
        assert_eq!(addr.valid_lft, Some(86400));
        assert_eq!(addr.preferred_lft, Some(14400));
    }

    #[test]
    fn br_mdb_entry_v4_layout() {
        use std::net::Ipv4Addr;
        let b = br_mdb_entry_bytes(7, 0, IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)));
        assert_eq!(b.len(), 28);
        assert_eq!(&b[0..4], &7u32.to_ne_bytes(), "port ifindex (host order)");
        assert_eq!(b[4], 1, "MDB_PERMANENT");
        assert_eq!(&b[6..8], &0u16.to_ne_bytes(), "vid");
        assert_eq!(&b[8..12], &[239, 1, 1, 1], "group v4");
        assert_eq!(&b[24..26], &[0x08, 0x00], "proto ETH_P_IP (big-endian)");
    }

    #[test]
    fn br_mdb_entry_v6_proto() {
        use std::net::Ipv6Addr;
        let g: Ipv6Addr = "ff05::1:3".parse().unwrap();
        let b = br_mdb_entry_bytes(3, 10, IpAddr::V6(g));
        assert_eq!(&b[6..8], &10u16.to_ne_bytes(), "vid 10");
        assert_eq!(&b[8..24], &g.octets(), "group v6");
        assert_eq!(&b[24..26], &[0x86, 0xdd], "proto ETH_P_IPV6");
    }

    #[test]
    fn mdb_nla_bytes_header_and_pad() {
        // IPv4 value: [len=8][kind][4 bytes] — already 4-aligned.
        let n = mdb_nla_bytes(MDBE_ATTR_SOURCE, &[192, 0, 2, 1]);
        assert_eq!(n.len(), 8);
        assert_eq!(&n[0..2], &8u16.to_ne_bytes(), "nla len");
        assert_eq!(&n[2..4], &MDBE_ATTR_SOURCE.to_ne_bytes(), "nla kind");
        assert_eq!(&n[4..8], &[192, 0, 2, 1], "value");
        // IPv6 value: 4 + 16 = 20, aligned.
        assert_eq!(mdb_nla_bytes(MDBE_ATTR_SOURCE, &[0u8; 16]).len(), 20);
    }

    #[test]
    fn set_route_table_uses_rtm_table_byte_for_ids_under_256() {
        let mut msg = RouteMessage::default();
        set_route_table(&mut msg, RouteHeader::RT_TABLE_MAIN as u32);
        assert_eq!(msg.header.table, RouteHeader::RT_TABLE_MAIN);
        // No RTA_TABLE attribute is emitted for the byte-sized case.
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Table(_)))
        );
    }

    #[test]
    fn set_route_table_falls_back_to_rta_table_attribute_for_large_ids() {
        // Linux VRF allocators routinely hand out ids > 255; the
        // single-byte `rtm_table` overflows, so the kernel relies on
        // `RTA_TABLE` instead. `rtm_table` must be `RT_TABLE_UNSPEC`
        // so the kernel reads the attribute.
        let mut msg = RouteMessage::default();
        set_route_table(&mut msg, 1000);
        assert_eq!(msg.header.table, RouteHeader::RT_TABLE_UNSPEC);
        let table_attr = msg
            .attributes
            .iter()
            .find_map(|a| match a {
                RouteAttribute::Table(v) => Some(*v),
                _ => None,
            })
            .expect("RTA_TABLE attribute emitted");
        assert_eq!(table_attr, 1000);
    }

    #[test]
    fn link_from_msg_parses_vlan_sub_interface() {
        let mut msg = LinkMessage::default();
        msg.attributes
            .push(LinkAttribute::IfName("eth0.100".into()));
        msg.attributes.push(LinkAttribute::Link(2));
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vlan),
            LinkInfo::Data(InfoData::Vlan(vec![InfoVlan::Id(100)])),
        ]));
        let link = link_from_msg(msg);
        assert_eq!(link.name, "eth0.100");
        assert_eq!(link.parent, Some(2), "IFLA_LINK parent ifindex");
        assert_eq!(link.vlan_id, Some(100), "IFLA_VLAN_ID");
        assert!(!link.bridge);
    }

    #[test]
    fn link_from_msg_without_linkinfo_leaves_vlan_fields_unset() {
        // A partial RTM_NEWLINK (e.g. an enslave notification) carries
        // no IFLA_LINKINFO; the parser must report absence, letting the
        // RIB's adopt-if-present update keep the previously learned
        // values instead of clearing them.
        let mut msg = LinkMessage::default();
        msg.attributes
            .push(LinkAttribute::IfName("eth0.100".into()));
        let link = link_from_msg(msg);
        assert_eq!(link.parent, None);
        assert_eq!(link.vlan_id, None);
    }

    fn nexthop_msg(protocol: RouteProtocol, attributes: Vec<NexthopAttribute>) -> NexthopMessage {
        let mut msg = NexthopMessage::default();
        msg.header.protocol = protocol;
        msg.attributes = attributes;
        msg
    }

    /// A next-hop object as the startup dump returns it: its id, gateway,
    /// interface and group members, and whether zebra-rs made it
    /// (`RTPROT_ZEBRA`). One without an id is none.
    #[test]
    fn nexthop_from_msg_reads_an_object() {
        let gw = Ipv4Addr::new(192, 0, 2, 2);
        let msg = nexthop_msg(
            RouteProtocol::Zebra,
            vec![
                NexthopAttribute::Id(7),
                NexthopAttribute::Gateway(RouteAddress::Inet(gw)),
                NexthopAttribute::Oif(3),
            ],
        );
        let nexthop = nexthop_from_msg(&msg).expect("an object");
        assert_eq!(nexthop.id, 7);
        assert!(nexthop.ours, "RTPROT_ZEBRA");
        assert_eq!(nexthop.gateway, Some(IpAddr::V4(gw)));
        assert_eq!(nexthop.ifindex, Some(3));
        assert!(nexthop.group.is_empty());

        let members = [7, 8].map(|id| NexthopGroup {
            id,
            ..Default::default()
        });
        let msg = nexthop_msg(
            RouteProtocol::Kernel,
            vec![
                NexthopAttribute::Id(9),
                NexthopAttribute::Group(members.to_vec()),
            ],
        );
        let group = nexthop_from_msg(&msg).expect("a group");
        assert!(!group.ours, "another's");
        assert_eq!(group.group, vec![7, 8]);

        let msg = nexthop_msg(RouteProtocol::Zebra, vec![NexthopAttribute::Oif(3)]);
        assert!(nexthop_from_msg(&msg).is_none(), "no id");
    }

    /// A route the startup dump finds forwarding through a kernel next-hop
    /// object gets that object's gateway, or its group members' gateways.
    /// It used to come in with no next hop. An object not dumped gives it
    /// none.
    #[test]
    fn a_dumped_route_gets_its_objects_gateway() {
        let gw = |last| Ipv4Addr::new(192, 0, 2, last);
        let object = |id, gateway: Option<Ipv4Addr>, group: Vec<u32>| FibNexthop {
            id,
            ours: true,
            gateway: gateway.map(IpAddr::V4),
            ifindex: Some(3),
            group,
        };
        let nexthops = BTreeMap::from([
            (7, object(7, Some(gw(2)), vec![])),
            (8, object(8, Some(gw(3)), vec![])),
            (9, object(9, None, vec![7, 8])),
        ]);
        let route = |nhid| {
            let mut msg = RouteMessage::default();
            msg.header.address_family = AddressFamily::Inet;
            msg.header.destination_prefix_length = 24;
            msg.header.kind = RouteType::Unicast;
            msg.header.scope = RouteScope::Universe;
            msg.header.protocol = RouteProtocol::Ospf;
            msg.header.table = RouteHeader::RT_TABLE_MAIN;
            msg.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(
                    Ipv4Addr::new(203, 0, 113, 0),
                )));
            msg.attributes.push(RouteAttribute::Nhid(nhid));
            route_from_msg_with(msg, &nexthops, true)
                .expect("a route")
                .entry
                .nexthop
        };
        let gateway = |uni: &NexthopUni| (uni.addr, uni.ifindex_origin);
        match route(7) {
            Nexthop::Uni(uni) => assert_eq!(gateway(&uni), (IpAddr::V4(gw(2)), Some(3))),
            other => panic!("one gateway: {other:?}"),
        }
        match route(9) {
            Nexthop::Multi(multi) => assert_eq!(
                multi.nexthops.iter().map(gateway).collect::<Vec<_>>(),
                vec![(IpAddr::V4(gw(2)), Some(3)), (IpAddr::V4(gw(3)), Some(3))]
            ),
            other => panic!("the group's gateways: {other:?}"),
        }
        assert_eq!(route(5), Nexthop::default(), "not dumped");
    }

    /// A route of OSPF's (`RTPROT_OSPF`) the startup dump finds was left
    /// by an earlier run of zebra-rs: it comes in as a stale OSPF entry,
    /// at OSPF's distance, IPv6 too, which OSPF's own routes replace. It
    /// used to come in as a kernel route, which outranked them. A route
    /// learned later, or another protocol's IPv6 one, stays as it was.
    #[test]
    fn an_earlier_runs_ospf_route_comes_in_stale() {
        let route = |dst: IpAddr, gw: IpAddr, protocol, dump| {
            let mut msg = RouteMessage::default();
            let (family, dst, gw) = match (dst, gw) {
                (IpAddr::V4(dst), IpAddr::V4(gw)) => (
                    AddressFamily::Inet,
                    RouteAddress::Inet(dst),
                    RouteAddress::Inet(gw),
                ),
                (IpAddr::V6(dst), IpAddr::V6(gw)) => (
                    AddressFamily::Inet6,
                    RouteAddress::Inet6(dst),
                    RouteAddress::Inet6(gw),
                ),
                _ => unreachable!(),
            };
            msg.header.address_family = family;
            msg.header.destination_prefix_length = if dst_is_v6(&dst) { 64 } else { 24 };
            msg.header.kind = RouteType::Unicast;
            msg.header.scope = RouteScope::Universe;
            msg.header.protocol = protocol;
            msg.header.table = RouteHeader::RT_TABLE_MAIN;
            msg.attributes.push(RouteAttribute::Destination(dst));
            msg.attributes.push(RouteAttribute::Gateway(gw));
            msg.attributes.push(RouteAttribute::Priority(20));
            route_from_msg_with(msg, &BTreeMap::new(), dump)
        };
        fn dst_is_v6(dst: &RouteAddress) -> bool {
            matches!(dst, RouteAddress::Inet6(_))
        }
        let v4 = (
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        );
        let v6 = (
            IpAddr::V6("2001:db8:1::".parse().unwrap()),
            IpAddr::V6("fe80::2".parse().unwrap()),
        );

        let entry = route(v4.0, v4.1, RouteProtocol::Ospf, true)
            .expect("v4")
            .entry;
        assert_eq!(
            (entry.rtype, entry.stale, entry.distance),
            (RibType::Ospf, true, 110)
        );
        assert!(!entry.is_protocol(), "never programmed");

        let stale = route(v6.0, v6.1, RouteProtocol::Ospf, true).expect("v6");
        assert_eq!(stale.prefix, "2001:db8:1::/64".parse::<IpNet>().unwrap());
        assert!(stale.entry.stale, "v6 stale");
        match stale.entry.nexthop {
            Nexthop::Uni(uni) => assert_eq!(uni.addr, v6.1, "v6 gateway"),
            other => panic!("a gateway: {other:?}"),
        }

        let live = route(v4.0, v4.1, RouteProtocol::Ospf, false)
            .expect("live")
            .entry;
        assert_eq!(
            (live.rtype, live.stale),
            (RibType::Kernel, false),
            "not the dump's"
        );
        assert!(
            route(v6.0, v6.1, RouteProtocol::Kernel, true).is_none(),
            "v6 RTPROT_KERNEL routes are interface prefix routes, already connected"
        );
        assert!(
            route(v6.0, v6.1, RouteProtocol::Boot, true).is_some(),
            "operator IPv6 routes are redistribution sources"
        );
    }
}
