use std::os::fd::AsRawFd;

use nix::sys::socket::{self, LinkAddr, SockaddrLike};
use socket2::{Domain, Protocol, Socket, Type};

const ISIS_BPF_FILTER: [libc::sock_filter; 10] = [
    // l0: ldh [0]
    bpf_filter_block(0x28, 0, 0, 0x00000000),
    // l1: jeq #0xfefe, l2, l4
    bpf_filter_block(0x15, 0, 2, 0x0000fefe),
    // l2: ldb [3]
    bpf_filter_block(0x30, 0, 0, 0x00000003),
    // l3: jmp l7
    bpf_filter_block(0x05, 0, 0, 0x00000003),
    // l4: ldh proto
    bpf_filter_block(0x28, 0, 0, 0xfffff000),
    // l5: jeq #0x00fe, l6, l9
    bpf_filter_block(0x15, 0, 3, 0x000000fe),
    // l6: ldb [0]
    bpf_filter_block(0x30, 0, 0, 0x00000000),
    // l7: jeq #0x83, l8, l9
    bpf_filter_block(0x15, 0, 1, 0x00000083),
    // l8: ret #0x40000
    bpf_filter_block(0x06, 0, 0, 0x00040000),
    // l9: ret #0
    bpf_filter_block(0x06, 0, 0, 0x00000000),
];

const fn bpf_filter_block(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

pub fn isis_socket() -> Result<Socket, std::io::Error> {
    let socket = Socket::new(
        Domain::PACKET,
        Type::DGRAM,
        Some(Protocol::from(libc::ETH_P_ALL)),
    )?;

    socket.set_nonblocking(true);

    let ifindex: u32 = 3;
    let sockaddr = link_addr(libc::ETH_P_ALL as u16, ifindex);

    socket::bind(socket.as_raw_fd(), &sockaddr)?;

    socket.attach_filter(&ISIS_BPF_FILTER)?;

    Ok(socket)
}

fn link_addr(protocol: u16, ifindex: u32) -> LinkAddr {
    let mut sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocol.to_be(),
        sll_ifindex: ifindex as _,
        sll_halen: 0,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_addr: [0; 8],
    };
    let ssl_len = std::mem::size_of_val(&sll) as libc::socklen_t;
    unsafe { LinkAddr::from_raw(&sll as *const _ as *const _, Some(ssl_len)) }.unwrap()
}
