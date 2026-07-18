//! PIM control socket: one raw IPv4 socket (IP protocol 103) per
//! instance, `IP_PKTINFO` for ingress-interface demux, per-interface
//! ALL-PIM-ROUTERS (224.0.0.13) group joins. Mirrors
//! `crate::ospf::socket`.

use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use libc::c_int;
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket};
use tokio::io::unix::AsyncFd;

use crate::context::ProtoContext;

/// ALL-PIM-ROUTERS group (RFC 7761 §4.3.1).
pub const ALL_PIM_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

/// PIM is IP protocol 103.
pub const PIM_IP_PROTO: i32 = 103;

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
