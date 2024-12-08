use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::str::FromStr;

use socket2::InterfaceIndexOrAddress;
use socket2::{Domain, Protocol, Socket, Type};

const OSPF_IP_PROTO: i32 = 89;

pub fn ospf_socket() -> Result<Socket, std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(OSPF_IP_PROTO)))?;

    let maddr: Ipv4Addr = Ipv4Addr::from_str("224.0.0.5").unwrap();
    socket.join_multicast_v4_n(&maddr, &InterfaceIndexOrAddress::Index(3));

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

    Ok(socket)
}
