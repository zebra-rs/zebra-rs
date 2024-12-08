use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::str::FromStr;

use socket2::InterfaceIndexOrAddress;
use socket2::{Domain, Protocol, Socket, Type};

pub const OSPF_IP_PROTO: i32 = 89;

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

use std::io::IoSliceMut;

use bytes::Bytes;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn, SockaddrLike};
use std::io::{Error, ErrorKind};
use std::ops::Deref;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub fn reader(sock: &Socket) -> Result<(Ipv4Addr, i32, Ipv4Addr), Error> {
    let mut buf = [0u8; 16384];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo);

    let msg = socket::recvmsg::<SockaddrIn>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsgspace),
        socket::MsgFlags::empty(),
    )?;

    let mut cmsgs = msg.cmsgs()?;

    let Some(ControlMessageOwned::Ipv4PacketInfo(pktinfo)) = cmsgs.next() else {
        return Err(ErrorKind::AddrNotAvailable.into());
    };

    let dst: Ipv4Addr = Ipv4Addr::from(pktinfo.ipi_spec_dst.s_addr.to_be());
    let addr: Ipv4Addr = Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_be());

    let Some(packet) = msg.iovs().next() else {
        return Err(ErrorKind::UnexpectedEof.into());
    };

    let ret = ospf_packet::parse(&packet[20..]);
    println!("{:?}", ret);

    Ok((dst, pktinfo.ipi_ifindex, addr))
}

pub async fn read_packet(sock: Socket) {
    let sock = AsyncFd::new(sock).unwrap();

    loop {
        let ret = sock.async_io(Interest::READABLE, reader).await;
        println!("{:?}", ret);
    }
}
