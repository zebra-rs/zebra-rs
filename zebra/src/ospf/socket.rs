use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::str::FromStr;

use socket2::InterfaceIndexOrAddress;
use socket2::{Domain, Protocol, Socket, Type};

const OSPF_IP_PROTO: i32 = 89;

pub fn ospf_socket_ipv4() -> Result<Socket, std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(OSPF_IP_PROTO)))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    set_ipv4_pktinfo(&socket);

    Ok(socket)
}

pub fn ospf_socket_ipv6() -> Result<Socket, std::io::Error> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(OSPF_IP_PROTO)))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    set_ipv6_pktinfo(&socket);

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

pub fn ospf_join_if(socket: &Socket, ifindex: u32) {
    let maddr: Ipv4Addr = Ipv4Addr::from_str("224.0.0.5").unwrap();
    socket.join_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(3));
}

pub fn ospf_leave_if(socket: &Socket, ifindex: u32) {
    let maddr: Ipv4Addr = Ipv4Addr::from_str("224.0.0.5").unwrap();
    socket.leave_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(3));
}
