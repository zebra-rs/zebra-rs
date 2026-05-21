use std::os::fd::AsRawFd;
use std::os::raw::c_int;

use socket2::InterfaceIndexOrAddress;
use socket2::{Domain, Protocol, Socket};
use tokio::io::unix::AsyncFd;

use crate::context::ProtoContext;

use super::{OspfVersion, Ospfv2};

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

pub fn ospf_join_if(socket: &AsyncFd<Socket>, ifindex: u32) {
    let maddr = Ospfv2::ALL_SPF_ROUTERS;
    if let Err(e) = socket
        .get_ref()
        .join_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(ifindex))
    {
        tracing::warn!("ospf: join AllSPFRouters on ifindex {ifindex} failed: {e}");
    }
}

pub fn ospf_join_alldrouters(socket: &AsyncFd<Socket>, ifindex: u32) {
    let maddr = Ospfv2::ALL_DROUTERS;
    if let Err(e) = socket
        .get_ref()
        .join_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(ifindex))
    {
        tracing::warn!("ospf: join AllDRouters on ifindex {ifindex} failed: {e}");
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
