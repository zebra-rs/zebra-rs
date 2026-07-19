//! PIM control socket: one raw IPv4 socket (IP protocol 103) per
//! instance, `IP_PKTINFO` for ingress-interface demux, per-interface
//! ALL-PIM-ROUTERS (224.0.0.13) group joins. Mirrors
//! `crate::ospf::socket`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

use libc::c_int;
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket};
use tokio::io::unix::AsyncFd;

use crate::context::ProtoContext;

/// ALL-PIM-ROUTERS group (RFC 7761 §4.3.1).
pub const ALL_PIM_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

/// ALL-PIM-ROUTERS for IPv6: `ff02::d` (RFC 7761 §4.3.1).
pub const ALL_PIM_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000d);

/// PIM is IP protocol 103.
pub const PIM_IP_PROTO: i32 = 103;

/// IGMP is IP protocol 2.
pub const IGMP_IP_PROTO: i32 = 2;

/// All-routers group — IGMPv2 Leaves are sent here.
pub const IGMP_ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);

/// IGMPv3 membership reports are sent here (RFC 3376 §4.2.14).
pub const IGMP_V3_REPORT_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

pub fn pim_socket(ctx: &ProtoContext) -> Result<AsyncFd<Socket>, std::io::Error> {
    // Through the context so VRF binding via `SO_BINDTODEVICE`
    // applies automatically once per-VRF instances exist.
    let socket = ctx.raw_socket(Domain::IPV4, Protocol::from(PIM_IP_PROTO))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(false)?;
    // Hellos, Join/Prunes and Asserts are link-local.
    socket.set_multicast_ttl_v4(1)?;
    socket.set_tos_v4(libc::IPTOS_PREC_INTERNETCONTROL as u32)?;
    set_ipv4_pktinfo(&socket)?;

    AsyncFd::new(socket)
}

/// The raw IPv6 socket for PIMv6 (protocol 103), mirroring
/// `ospf_socket_ipv6`: multicast loopback off, hop limit pinned to 1
/// (PIM control is link-local), and `IPV6_RECVPKTINFO` so the read
/// task recovers the ingress ifindex and the destination address the
/// pseudo-header checksum needs. `IPV6_V6ONLY` is not set — it is
/// invalid on a raw v6 socket and redundant (raw v6 never surfaces
/// v4-mapped sources).
pub fn pim_socket_v6(ctx: &ProtoContext) -> Result<AsyncFd<Socket>, std::io::Error> {
    let socket = ctx.raw_socket(Domain::IPV6, Protocol::from(PIM_IP_PROTO))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v6(false)?;
    socket.set_multicast_hops_v6(1)?;
    set_ipv6_pktinfo(&socket);

    AsyncFd::new(socket)
}

fn set_ipv6_pktinfo(socket: &Socket) {
    let optval = true as c_int;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    };
}

/// MLDv2 report destination (`ff02::16`): the querier joins it per
/// interface to receive membership reports (RFC 3810 §5.2.14).
pub const MLD_V2_REPORT_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0016);

/// ICMPv6 protocol number.
const IPPROTO_ICMPV6: i32 = 58;
/// `ICMP6_FILTER` sockopt name (kernel ABI value 1 on Linux; not in
/// libc as a constant on all targets).
const ICMP6_FILTER_OPT: c_int = 1;

/// The raw ICMPv6 socket for MLD (RFC 2710 / RFC 3810). `ICMP6_FILTER`
/// passes only the four MLD types (130/131/132/143); multicast hop
/// limit 1 (MLD is link-local); `IPV6_ROUTER_ALERT` adds the hop-by-hop
/// Router Alert option to every send (mandatory for MLD); and
/// `IPV6_RECVPKTINFO` / `IPV6_RECVHOPLIMIT` recover the destination,
/// ingress ifindex and hop limit the receive path validates.
pub fn mld_socket(ctx: &ProtoContext) -> Result<AsyncFd<Socket>, std::io::Error> {
    let socket = ctx.raw_socket(Domain::IPV6, Protocol::from(IPPROTO_ICMPV6))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v6(false)?;
    socket.set_multicast_hops_v6(1)?;
    set_ipv6_pktinfo(&socket);
    set_int_sockopt(&socket, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, 1);
    // Router Alert value 0 = MLD (RFC 2711); adds the hop-by-hop option
    // to every outgoing MLD message so on-path routers snoop it.
    set_int_sockopt(&socket, libc::IPPROTO_IPV6, libc::IPV6_ROUTER_ALERT, 0);
    apply_mld_icmp6_filter(&socket)?;

    AsyncFd::new(socket)
}

fn set_int_sockopt(socket: &Socket, level: c_int, name: c_int, value: c_int) {
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const c_int as *const libc::c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        );
    };
}

/// `struct icmp6_filter` (8 × u32, one bit per type; a set bit blocks).
/// Start all-block, then clear the four MLD types to pass only them.
fn apply_mld_icmp6_filter(socket: &Socket) -> Result<(), std::io::Error> {
    let mut filt: [u32; 8] = [0xffff_ffff; 8];
    for t in [130u8, 131, 132, 143] {
        let word = (t as usize) >> 5;
        let bit = (t as usize) & 0x1f;
        filt[word] &= !(1u32 << bit);
    }
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            IPPROTO_ICMPV6,
            ICMP6_FILTER_OPT,
            filt.as_ptr() as *const libc::c_void,
            std::mem::size_of::<[u32; 8]>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Join `ff02::16` (MLDv2 report destination) on the given interface.
pub fn mld_join_if(socket: &AsyncFd<Socket>, ifindex: u32) {
    if let Err(e) = socket
        .get_ref()
        .join_multicast_v6(&MLD_V2_REPORT_GROUP, ifindex)
        && !is_eaddrinuse(&e)
    {
        tracing::warn!("mld: join ff02::16 on ifindex {ifindex} failed: {e}");
    }
}

/// Leave `ff02::16` on the given interface.
pub fn mld_leave_if(socket: &AsyncFd<Socket>, ifindex: u32) {
    if let Err(e) = socket
        .get_ref()
        .leave_multicast_v6(&MLD_V2_REPORT_GROUP, ifindex)
        && !is_not_member(&e)
    {
        tracing::warn!("mld: leave ff02::16 on ifindex {ifindex} failed: {e}");
    }
}

/// Join `ff02::d` (AllPIMRouters, v6) on the given interface.
pub fn pim_join_if_v6(socket: &AsyncFd<Socket>, ifindex: u32) {
    if let Err(e) = socket
        .get_ref()
        .join_multicast_v6(&ALL_PIM_ROUTERS_V6, ifindex)
    {
        if is_eaddrinuse(&e) {
            tracing::debug!("pim: AllPIMRouters (v6) already joined on ifindex {ifindex}");
        } else {
            tracing::warn!("pim: join AllPIMRouters (v6) on ifindex {ifindex} failed: {e}");
        }
    }
}

/// Leave `ff02::d` on the given interface.
pub fn pim_leave_if_v6(socket: &AsyncFd<Socket>, ifindex: u32) {
    if let Err(e) = socket
        .get_ref()
        .leave_multicast_v6(&ALL_PIM_ROUTERS_V6, ifindex)
    {
        if is_not_member(&e) {
            tracing::debug!("pim: AllPIMRouters (v6) not joined on ifindex {ifindex}");
        } else {
            tracing::warn!("pim: leave AllPIMRouters (v6) on ifindex {ifindex} failed: {e}");
        }
    }
}

fn set_ipv4_pktinfo(socket: &Socket) -> Result<(), std::io::Error> {
    let optval = true as c_int;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The IGMP socket: queries out, reports/leaves in. Until the mroute
/// socket exists (SSM phase), reception relies on per-interface joins
/// of the fixed report destinations (224.0.0.22, 224.0.0.2) — v3
/// receivers are fully covered; v2 reports (addressed to the reported
/// group itself) arrive once mroute VIFs put interfaces in
/// multicast-forwarding mode.
pub fn igmp_socket(ctx: &ProtoContext) -> Result<AsyncFd<Socket>, std::io::Error> {
    let socket = ctx.raw_socket(Domain::IPV4, Protocol::from(IGMP_IP_PROTO))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(false)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_tos_v4(libc::IPTOS_PREC_INTERNETCONTROL as u32)?;
    set_ipv4_pktinfo(&socket)?;
    set_ipv4_router_alert(&socket)?;

    AsyncFd::new(socket)
}

/// RFC 3376 §4: IGMP messages are sent with the IP Router Alert
/// option. Applied socket-wide via `IP_OPTIONS` — this socket only
/// ever transmits IGMP.
fn set_ipv4_router_alert(socket: &Socket) -> Result<(), std::io::Error> {
    let ra: [u8; 4] = [148, 4, 0, 0];
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_OPTIONS,
            ra.as_ptr() as *const libc::c_void,
            ra.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn is_eaddrinuse(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EADDRINUSE)
}

fn is_not_member(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EADDRNOTAVAIL)
}

pub fn pim_join_if(socket: &AsyncFd<Socket>, ifindex: u32) {
    if let Err(e) = socket
        .get_ref()
        .join_multicast_v4_n(&ALL_PIM_ROUTERS, &InterfaceIndexOrAddress::Index(ifindex))
    {
        if is_eaddrinuse(&e) {
            tracing::debug!("pim: AllPIMRouters already joined on ifindex {ifindex}");
        } else {
            tracing::warn!("pim: join AllPIMRouters on ifindex {ifindex} failed: {e}");
        }
    }
}

pub fn pim_leave_if(socket: &AsyncFd<Socket>, ifindex: u32) {
    if let Err(e) = socket
        .get_ref()
        .leave_multicast_v4_n(&ALL_PIM_ROUTERS, &InterfaceIndexOrAddress::Index(ifindex))
    {
        if is_not_member(&e) {
            tracing::debug!("pim: AllPIMRouters not joined on ifindex {ifindex}");
        } else {
            tracing::warn!("pim: leave AllPIMRouters on ifindex {ifindex} failed: {e}");
        }
    }
}

pub fn igmp_join_if(socket: &AsyncFd<Socket>, ifindex: u32) {
    for maddr in [IGMP_V3_REPORT_GROUP, IGMP_ALL_ROUTERS] {
        if let Err(e) = socket
            .get_ref()
            .join_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(ifindex))
            && !is_eaddrinuse(&e)
        {
            tracing::warn!("igmp: join {maddr} on ifindex {ifindex} failed: {e}");
        }
    }
}

pub fn igmp_leave_if(socket: &AsyncFd<Socket>, ifindex: u32) {
    for maddr in [IGMP_V3_REPORT_GROUP, IGMP_ALL_ROUTERS] {
        if let Err(e) = socket
            .get_ref()
            .leave_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(ifindex))
            && !is_not_member(&e)
        {
            tracing::warn!("igmp: leave {maddr} on ifindex {ifindex} failed: {e}");
        }
    }
}
