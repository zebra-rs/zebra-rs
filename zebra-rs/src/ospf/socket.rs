use std::os::fd::AsRawFd;
use std::os::raw::c_int;

use socket2::InterfaceIndexOrAddress;
use socket2::{Domain, Protocol, Socket};
use tokio::io::unix::AsyncFd;

use crate::context::ProtoContext;

use super::{OspfVersion, Ospfv2, Ospfv3};

pub fn ospf_socket_ipv4(ctx: &ProtoContext) -> Result<Socket, std::io::Error> {
    // Initial socket through the context so VRF binding (when
    // step 8 lights up `SO_BINDTODEVICE`) applies automatically.
    let socket = ctx.raw_socket(Domain::IPV4, Protocol::from(Ospfv2::IP_PROTO as i32))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(false)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_tos_v4(libc::IPTOS_PREC_INTERNETCONTROL as u32)?;
    set_ipv4_pktinfo(&socket);

    Ok(socket)
}

pub fn set_ipv4_pktinfo(socket: &Socket) {
    let optval = true as c_int;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    };
}

/// EADDRINUSE from `IP_ADD_MEMBERSHIP` / `IPV6_JOIN_GROUP` is the
/// kernel telling us the (group, ifindex) is already on this
/// socket's mc_list. That's the *desired* end state — the IFSM
/// guard in `ospf_ifsm_interface_up` avoids the syscall when we
/// know we're a member, but it can still fire on paths that race
/// with `interface_down` (which currently clears the bookkeeping
/// flag without issuing an explicit `IP_DROP_MEMBERSHIP`). Treat
/// it as informational rather than warning the operator.
fn is_eaddrinuse(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EADDRINUSE)
}

pub fn ospf_join_if(socket: &AsyncFd<Socket>, ifindex: u32) {
    let maddr = Ospfv2::ALL_SPF_ROUTERS;
    if let Err(e) = socket
        .get_ref()
        .join_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(ifindex))
    {
        if is_eaddrinuse(&e) {
            tracing::debug!("ospf: AllSPFRouters already joined on ifindex {ifindex}");
        } else {
            tracing::warn!("ospf: join AllSPFRouters on ifindex {ifindex} failed: {e}");
        }
    }
}

pub fn ospf_join_alldrouters(socket: &AsyncFd<Socket>, ifindex: u32) {
    let maddr = Ospfv2::ALL_DROUTERS;
    if let Err(e) = socket
        .get_ref()
        .join_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(ifindex))
    {
        if is_eaddrinuse(&e) {
            tracing::debug!("ospf: AllDRouters already joined on ifindex {ifindex}");
        } else {
            tracing::warn!("ospf: join AllDRouters on ifindex {ifindex} failed: {e}");
        }
    }
}

pub fn ospf_leave_alldrouters(socket: &AsyncFd<Socket>, ifindex: u32) {
    let maddr = Ospfv2::ALL_DROUTERS;
    if let Err(e) = socket
        .get_ref()
        .leave_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(ifindex))
    {
        tracing::warn!("ospf: leave AllDRouters on ifindex {ifindex} failed: {e}");
    }
}

/// Create the raw IPv6 socket used by an OSPFv3 instance.
///
/// Mirrors `ospf_socket_ipv4`'s setup but for v6: same protocol
/// number (89; OSPFv2 and v3 share it), multicast loop off,
/// multicast hop limit pinned to 1 (RFC 5340 §A.1 — OSPFv3 packets
/// MUST NOT cross a router), and `IPV6_RECVPKTINFO` so the rx loop
/// can recover the ingress ifindex and the destination v6 address
/// used for the IPv6 pseudo-header checksum.
///
/// `IPV6_V6ONLY` is intentionally not set: on Linux that option is
/// only valid on TCP / UDP sockets, and `setsockopt` on a raw v6
/// socket (`IPPROTO_OSPF`) returns `EINVAL`. Raw v6 sockets do not
/// surface v4-mapped sources anyway, so the option is redundant.
pub fn ospf_socket_ipv6(ctx: &ProtoContext) -> Result<Socket, std::io::Error> {
    let socket = ctx.raw_socket(Domain::IPV6, Protocol::from(Ospfv3::IP_PROTO as i32))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v6(false)?;
    socket.set_multicast_hops_v6(1)?;
    set_ipv6_pktinfo(&socket);

    Ok(socket)
}

/// Enable `IPV6_RECVPKTINFO` on the raw v6 socket. socket2 doesn't
/// expose this directly, so set it via raw `setsockopt`. The rx
/// loop reads the resulting `in6_pktinfo` ancillary data to recover
/// (a) the ingress ifindex, used to dispatch the packet to the
/// matching `OspfLink<Ospfv3>`, and (b) the destination v6 address,
/// needed when verifying the IPv6 pseudo-header checksum (§4.4) on
/// receive.
#[allow(dead_code)]
pub fn set_ipv6_pktinfo(socket: &Socket) {
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

/// Join `ff02::5` (AllSPFRouters) on the given interface.
#[allow(dead_code)]
pub fn ospf_join_if_v6(socket: &AsyncFd<Socket>, ifindex: u32) {
    let maddr = Ospfv3::ALL_SPF_ROUTERS;
    if let Err(e) = socket.get_ref().join_multicast_v6(&maddr, ifindex) {
        if is_eaddrinuse(&e) {
            tracing::debug!("ospf: AllSPFRouters (v6) already joined on ifindex {ifindex}");
        } else {
            tracing::warn!("ospf: join AllSPFRouters (v6) on ifindex {ifindex} failed: {e}");
        }
    }
}

/// Join `ff02::6` (AllDRouters) on the given interface. Called when
/// the v3 interface FSM transitions a router into the DR or BDR
/// role on a broadcast / NBMA segment.
#[allow(dead_code)]
pub fn ospf_join_alldrouters_v6(socket: &AsyncFd<Socket>, ifindex: u32) {
    let maddr = Ospfv3::ALL_DROUTERS;
    if let Err(e) = socket.get_ref().join_multicast_v6(&maddr, ifindex) {
        if is_eaddrinuse(&e) {
            tracing::debug!("ospf: AllDRouters (v6) already joined on ifindex {ifindex}");
        } else {
            tracing::warn!("ospf: join AllDRouters (v6) on ifindex {ifindex} failed: {e}");
        }
    }
}

/// Leave `ff02::6` on the given interface. Called when the v3 FSM
/// drops out of the DR / BDR role.
#[allow(dead_code)]
pub fn ospf_leave_alldrouters_v6(socket: &AsyncFd<Socket>, ifindex: u32) {
    let maddr = Ospfv3::ALL_DROUTERS;
    if let Err(e) = socket.get_ref().leave_multicast_v6(&maddr, ifindex) {
        tracing::warn!("ospf: leave AllDRouters (v6) on ifindex {ifindex} failed: {e}");
    }
}
