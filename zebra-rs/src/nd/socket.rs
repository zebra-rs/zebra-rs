//! Raw `IPPROTO_ICMPV6` socket bring-up for Neighbor Discovery.
//!
//! All knobs follow RFC 4861 §6.1:
//!   * Outgoing hop limit = 255 (both unicast and multicast). Routers
//!     receiving NDP messages MUST silently drop any frame whose hop
//!     limit isn't 255, which is how we get on-link guarantees.
//!   * `IPV6_RECVHOPLIMIT` on so the receive side can enforce the
//!     same check on inbound packets.
//!   * `IPV6_RECVPKTINFO` on so the receive side learns the
//!     destination address and arriving ifindex.
//!   * `ICMP6_FILTER` scoped to RS (133) + RA (134) so neighbor
//!     solicitation / advertisement (135 / 136) and the kernel's NDP
//!     cache are left alone.
//!
//! Note: there is no `IPV6_CHECKSUM` setsockopt here on purpose. Linux
//! returns `EINVAL` for `IPV6_CHECKSUM` on raw `IPPROTO_ICMPV6`
//! sockets (see `net/ipv6/raw.c::do_rawv6_setsockopt`) because
//! RFC 3542 §3.1 reserves checksum handling on ICMPv6 sockets to the
//! kernel — and the kernel always computes it for us. Setting the
//! offset is therefore a no-op at best and a hard failure on Linux.
//!
//! Errors from each setsockopt are surfaced via the [`SocketError`]
//! enum so callers can distinguish "no CAP_NET_RAW" from a knob the
//! kernel rejected.
#![allow(dead_code)]

use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

/// ICMPv6 protocol number per RFC 4443.
const IPPROTO_ICMPV6: i32 = 58;

/// `ICMP6_FILTER` is not in libc as a constant on all targets; the
/// kernel ABI value is 1 on Linux.
const ICMP6_FILTER_OPT: c_int = 1;

#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    #[error("create raw ICMPv6 socket failed (need CAP_NET_RAW): {0}")]
    Create(io::Error),
    #[error("set IPV6_MULTICAST_HOPS=255 failed: {0}")]
    MulticastHops(io::Error),
    #[error("set IPV6_MULTICAST_LOOP=0 failed: {0}")]
    MulticastLoop(io::Error),
    #[error("set IPV6_UNICAST_HOPS=255 failed: {0}")]
    UnicastHops(io::Error),
    #[error("set IPV6_RECVHOPLIMIT failed: {0}")]
    RecvHopLimit(io::Error),
    #[error("set IPV6_RECVPKTINFO failed: {0}")]
    RecvPktInfo(io::Error),
    #[error("set ICMP6_FILTER failed: {0}")]
    Filter(io::Error),
    #[error("wrap socket in AsyncFd failed: {0}")]
    AsyncFd(io::Error),
}

/// Build a configured ICMPv6 ND socket and wrap it for tokio I/O.
pub fn nd_socket() -> Result<AsyncFd<Socket>, SocketError> {
    let socket = Socket::new(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(IPPROTO_ICMPV6)),
    )
    .map_err(SocketError::Create)?;
    socket.set_nonblocking(true).map_err(SocketError::Create)?;

    set_multicast_hops_255(&socket).map_err(SocketError::MulticastHops)?;
    // Disable loopback of our own multicast sends. The ND engine uses
    // this single raw socket for both RA transmit and receive; with the
    // kernel default (loop ON) every unsolicited RA we multicast to
    // ff02::1 is delivered straight back to us, and the receive path
    // then emits a `NeighborDiscovered` for our *own* link-local. For
    // BGP unnumbered that materializes a bogus peer pointing at
    // ourselves (and, since the peer address is refreshed on each RA,
    // the real peer races the self-RA non-deterministically) — so the
    // session never reliably establishes. A router must not consume its
    // own RAs; turn the loopback off.
    set_multicast_loop_off(&socket).map_err(SocketError::MulticastLoop)?;
    set_unicast_hops_255(&socket).map_err(SocketError::UnicastHops)?;
    set_recv_hop_limit(&socket).map_err(SocketError::RecvHopLimit)?;
    set_recv_pkt_info(&socket).map_err(SocketError::RecvPktInfo)?;
    // Note: no `IPV6_CHECKSUM` here — Linux returns EINVAL for that
    // option on raw ICMPv6 sockets; the kernel does the checksum for
    // us. See module-level docs.
    let filter = Icmp6Filter::pass_only(&[133, 134]);
    apply_icmp6_filter(&socket, &filter).map_err(SocketError::Filter)?;

    AsyncFd::new(socket).map_err(SocketError::AsyncFd)
}

fn set_multicast_hops_255(s: &Socket) -> io::Result<()> {
    let v: c_int = 255;
    unsafe {
        setsockopt_int(
            s.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            v,
        )
    }
}

fn set_multicast_loop_off(s: &Socket) -> io::Result<()> {
    let v: c_int = 0;
    unsafe {
        setsockopt_int(
            s.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_LOOP,
            v,
        )
    }
}

fn set_unicast_hops_255(s: &Socket) -> io::Result<()> {
    let v: c_int = 255;
    unsafe {
        setsockopt_int(
            s.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            v,
        )
    }
}

fn set_recv_hop_limit(s: &Socket) -> io::Result<()> {
    let v: c_int = 1;
    unsafe {
        setsockopt_int(
            s.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVHOPLIMIT,
            v,
        )
    }
}

fn set_recv_pkt_info(s: &Socket) -> io::Result<()> {
    let v: c_int = 1;
    unsafe { setsockopt_int(s.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, v) }
}

fn apply_icmp6_filter(s: &Socket, filter: &Icmp6Filter) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            IPPROTO_ICMPV6,
            ICMP6_FILTER_OPT,
            filter.as_ptr(),
            mem::size_of::<Icmp6Filter>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

unsafe fn setsockopt_int(fd: i32, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const c_int as *const libc::c_void,
            mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `struct icmp6_filter` from `<netinet/icmp6.h>`. 8 × 32 bits, one
/// bit per ICMPv6 type — a set bit means BLOCK, a clear bit means
/// PASS (when used with the "block list" semantics). We always start
/// from an all-block state and clear bits for the types we want.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Icmp6Filter {
    filt: [u32; 8],
}

impl Icmp6Filter {
    /// Build a filter that passes only the ICMPv6 types in `types`.
    /// Everything else is blocked.
    pub fn pass_only(types: &[u8]) -> Self {
        let mut f = Self {
            filt: [0xffff_ffff; 8],
        };
        for &t in types {
            // Clear the bit at position `t` — the kernel macro
            // `ICMP6_FILTER_SETPASS` indexes filt[type >> 5] and
            // clears bit `type & 0x1f`.
            let word = (t as usize) >> 5;
            let bit = (t as usize) & 0x1f;
            f.filt[word] &= !(1u32 << bit);
        }
        f
    }

    fn as_ptr(&self) -> *const libc::c_void {
        self as *const Self as *const libc::c_void
    }

    /// Test helper: would this filter pass an ICMPv6 message of type
    /// `t`? Mirrors the `ICMP6_FILTER_WILLPASS` kernel macro.
    pub fn will_pass(&self, t: u8) -> bool {
        let word = (t as usize) >> 5;
        let bit = (t as usize) & 0x1f;
        (self.filt[word] & (1u32 << bit)) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_pass_only_passes_listed_types() {
        let f = Icmp6Filter::pass_only(&[133, 134]);
        assert!(f.will_pass(133));
        assert!(f.will_pass(134));
        assert!(!f.will_pass(135));
        assert!(!f.will_pass(136));
        assert!(!f.will_pass(128));
        assert!(!f.will_pass(0));
    }

    #[test]
    fn filter_empty_list_blocks_everything() {
        let f = Icmp6Filter::pass_only(&[]);
        for t in 0u8..=255 {
            assert!(!f.will_pass(t), "type {} unexpectedly passed", t);
        }
    }

    #[test]
    fn filter_struct_layout_matches_kernel() {
        // The kernel ABI is a 32-byte struct of 8 little-endian u32s.
        // Rust's #[repr(C)] on a primitive-array struct matches that
        // on Linux. Asserting the size catches accidental drift.
        assert_eq!(mem::size_of::<Icmp6Filter>(), 32);
    }
}
