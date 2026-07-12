use std::os::fd::AsRawFd;

use nix::sys::socket::{self, LinkAddr, SockaddrLike};
use socket2::{Domain, Protocol, SockFilter, Socket, Type};

use super::network::{L1_ISS, L2_ISS, P2P_ISS};

const ISIS_BPF_FILTER: [SockFilter; 10] = [
    // l0: ldh [0]
    SockFilter::new(0x28, 0, 0, 0x00000000),
    // l1: jeq #0xfefe, l2, l4
    SockFilter::new(0x15, 0, 2, 0x0000fefe),
    // l2: ldb [3]
    SockFilter::new(0x30, 0, 0, 0x00000003),
    // l3: jmp l7
    SockFilter::new(0x05, 0, 0, 0x00000003),
    // l4: ldh proto
    SockFilter::new(0x28, 0, 0, 0xfffff000),
    // l5: jeq #0x00fe, l6, l9
    SockFilter::new(0x15, 0, 3, 0x000000fe),
    // l6: ldb [0]
    SockFilter::new(0x30, 0, 0, 0x00000000),
    // l7: jeq #0x83, l8, l9
    SockFilter::new(0x15, 0, 1, 0x00000083),
    // l8: ret #0x40000
    SockFilter::new(0x06, 0, 0, 0x00040000),
    // l9: ret #0
    SockFilter::new(0x06, 0, 0, 0x00000000),
];

pub fn isis_socket(ifindex: u32) -> Result<Socket, std::io::Error> {
    let socket = Socket::new(
        Domain::PACKET,
        Type::DGRAM,
        Some(Protocol::from(libc::ETH_P_ALL)),
    )?;

    let _ = socket.set_nonblocking(true);

    let sockaddr = link_addr(libc::ETH_P_ALL as u16, ifindex, None);

    socket::bind(socket.as_raw_fd(), &sockaddr)?;

    socket.attach_filter(&ISIS_BPF_FILTER)?;

    join_isis_multicast(socket.as_raw_fd(), ifindex);

    Ok(socket)
}

/// Join the IS-IS L2 multicast groups on this interface's `AF_PACKET`
/// socket.
///
/// IS-IS runs directly over IEEE 802.3 and addresses its Hellos / SNPs /
/// LSPs to well-known L2 multicast MACs: AllL1ISs (`01:80:c2:00:00:14`)
/// and AllL2ISs (`01:80:c2:00:00:15`) on a LAN, and AllISs
/// (`09:00:2b:00:00:05`) on a point-to-point circuit. A physical NIC
/// applies a hardware multicast filter, so a raw `AF_PACKET` socket
/// receives these frames only if the interface has joined the group (or
/// is in promiscuous / all-multicast mode). Without the join, adjacencies
/// come up only while some other tool holds the NIC promiscuous (e.g.
/// `tcpdump`), then go silent — the neighbour hold timer stops being
/// refreshed and the adjacency is reaped ~hold-time later. A veth pair
/// delivers all multicast to its peer regardless of membership, which is
/// why the veth-based BDD suite never exercised this path.
///
/// All three groups are joined unconditionally at socket creation. The
/// socket is level- and circuit-type agnostic — the BPF filter already
/// accepts any IS-IS NLPID and the receive handlers gate by PDU type and
/// level — so joining every group up front also means a live
/// `network-type` (P2P↔LAN) or `is-type` (L1/L2) change needs no re-join.
///
/// A failed join is logged but non-fatal: it must not tear down the link
/// (e.g. a non-multicast circuit such as a passive loopback, where RX of
/// these groups is irrelevant), and it keeps the previous "warn and skip
/// on socket error" contract of the caller intact for the fatal cases
/// (bind / filter) only.
fn join_isis_multicast(fd: i32, ifindex: u32) {
    for group in [L1_ISS, L2_ISS, P2P_ISS] {
        let mreq = isis_mreq(ifindex, &group);
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq as *const libc::packet_mreq as *const libc::c_void,
                std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                "isis: PACKET_ADD_MEMBERSHIP for {:02x?} on ifindex {} failed: {}",
                group,
                ifindex,
                err
            );
        }
    }
}

/// Build the `PACKET_MR_MULTICAST` membership request for one group MAC on
/// `ifindex`. Split out from the syscall so the wire-level fields can be
/// unit-tested without `CAP_NET_RAW`.
fn isis_mreq(ifindex: u32, group: &[u8; 6]) -> libc::packet_mreq {
    let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
    mreq.mr_ifindex = ifindex as i32;
    mreq.mr_type = libc::PACKET_MR_MULTICAST as u16;
    mreq.mr_alen = 6;
    mreq.mr_address[..6].copy_from_slice(group);
    mreq
}

pub fn link_addr(protocol: u16, ifindex: u32, addr: Option<[u8; 6]>) -> LinkAddr {
    let mut sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocol.to_be(),
        sll_ifindex: ifindex as i32,
        sll_halen: 0,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_addr: [0; 8],
    };
    if let Some(addr) = addr {
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&addr);
    }
    let ssl_len = std::mem::size_of_val(&sll) as libc::socklen_t;
    unsafe { LinkAddr::from_raw(&sll as *const _ as *const _, Some(ssl_len)) }.unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The membership request must name the interface, ask for a specific
    /// multicast group (PACKET_MR_MULTICAST, not ALLMULTI/PROMISC), and
    /// carry the exact 6-byte group MAC in the low bytes with alen=6. A
    /// wrong alen or a byte-swapped MAC would make the kernel program the
    /// wrong hardware filter and silently drop IS-IS frames.
    #[test]
    fn mreq_targets_the_group_mac() {
        for group in [L1_ISS, L2_ISS, P2P_ISS] {
            let mreq = isis_mreq(7, &group);
            assert_eq!(mreq.mr_ifindex, 7);
            assert_eq!(mreq.mr_type, libc::PACKET_MR_MULTICAST as u16);
            assert_eq!(mreq.mr_alen, 6);
            assert_eq!(&mreq.mr_address[..6], &group[..]);
            // Padding bytes past the address length stay zero.
            assert_eq!(&mreq.mr_address[6..], &[0, 0]);
        }
    }

    /// Guard the exact IS-IS group MACs — AllL1ISs, AllL2ISs, AllISs.
    /// These are what the send path targets; the join must match or RX
    /// and TX diverge.
    #[test]
    fn isis_group_macs_are_well_known() {
        assert_eq!(L1_ISS, [0x01, 0x80, 0xC2, 0x00, 0x00, 0x14]);
        assert_eq!(L2_ISS, [0x01, 0x80, 0xC2, 0x00, 0x00, 0x15]);
        assert_eq!(P2P_ISS, [0x09, 0x00, 0x2B, 0x00, 0x00, 0x05]);
    }
}
