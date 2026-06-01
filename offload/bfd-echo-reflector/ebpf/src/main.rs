#![no_std]
#![no_main]

//! XDP BFD Echo reflector (RFC 5880 §6.4 / RFC 5881 §4).
//!
//! BFD Echo is a stateless data-plane "hairpin": a peer sends an Echo frame to
//! UDP/3785 crafted so that our forwarding plane loops it straight back, and the
//! peer alone times the round trip. This program is that loopback, done in XDP:
//! a matching IPv4 UDP/3785 frame has its Ethernet source/destination MAC
//! swapped, its IPv4 TTL decremented (header checksum patched), and is sent back
//! out the same interface with `XDP_TX`.
//!
//! The TTL decrement is REQUIRED, not cosmetic: the loop is the remote's
//! forwarding plane — which is a hop — and FRR's fp-echo receiver
//! (`bfd_recv_ipv4_fp`) drops any looped frame whose TTL isn't 254. Only the
//! IPv4 header checksum is recomputed (incrementally, RFC 1141); the UDP checksum
//! is unaffected since TTL isn't in its pseudo-header. Everything that is not an
//! IPv4 UDP/3785 frame is `XDP_PASS`ed, so normal traffic — including BFD
//! *control* on UDP/3784 — is untouched.
//!
//! First slice: IPv4 only. IPv6 (EtherType 0x86DD) is a follow-up.

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

/// Ethernet II header layout.
const ETH_HLEN: usize = 14;
const ETH_DST_OFF: usize = 0; // [u8; 6] destination MAC
const ETH_SRC_OFF: usize = 6; // [u8; 6] source MAC
const ETH_TYPE_OFF: usize = 12; // u16 (big-endian) EtherType
const ETHERTYPE_IPV4: u16 = 0x0800;

/// IPv4 fixed-header fields (relative to the start of the frame). Only
/// option-less headers (IHL=5) are handled; see `try_reflect`.
const IP_OFF: usize = ETH_HLEN;
const IP_VER_IHL_OFF: usize = IP_OFF; // u8: high nibble = version, low = IHL
const IP_TTL_OFF: usize = IP_OFF + 8; // u8 TTL
const IP_PROTO_OFF: usize = IP_OFF + 9; // u8
const IP_CHECK_OFF: usize = IP_OFF + 10; // u16 (big-endian) header checksum
const IPPROTO_UDP: u8 = 17;
const IPV4_VER_IHL_NOOPTS: u8 = 0x45; // version 4, IHL 5 (20-byte header)

/// UDP header (assumes a 20-byte IPv4 header, i.e. IHL=5).
const UDP_OFF: usize = IP_OFF + 20;
const UDP_DST_OFF: usize = UDP_OFF + 2; // u16 (big-endian) destination port

/// BFD Echo destination port (RFC 5881 §4). BFD control is 3784; multihop 4784.
const BFD_ECHO_PORT: u16 = 3785;

/// Read a `u8` at `off` bytes into the frame, after a verifier-friendly bounds
/// check against `data_end`.
#[inline(always)]
unsafe fn load_u8(ctx: &XdpContext, off: usize) -> Result<u8, ()> {
    let ptr = ctx.data() + off;
    if ptr + 1 > ctx.data_end() {
        return Err(());
    }
    Ok(unsafe { *(ptr as *const u8) })
}

/// Read a big-endian `u16` at `off` bytes into the frame, with bounds check.
#[inline(always)]
unsafe fn load_u16_be(ctx: &XdpContext, off: usize) -> Result<u16, ()> {
    let ptr = ctx.data() + off;
    if ptr + 2 > ctx.data_end() {
        return Err(());
    }
    let hi = unsafe { *(ptr as *const u8) } as u16;
    let lo = unsafe { *((ptr + 1) as *const u8) } as u16;
    Ok((hi << 8) | lo)
}

/// Swap two packet bytes via volatile reads/writes. Done per byte rather than
/// as a `[u8; 6]` value-copy because the array copy can lower to a memcpy that
/// computes a pointer difference between the two operands — which the BPF
/// verifier rejects ("R4 pointer -= pointer prohibited"). Volatile single-byte
/// ops can't be coalesced into that memcpy.
#[inline(always)]
unsafe fn swap_byte(a: *mut u8, b: *mut u8) {
    unsafe {
        let tmp = core::ptr::read_volatile(a);
        core::ptr::write_volatile(a, core::ptr::read_volatile(b));
        core::ptr::write_volatile(b, tmp);
    }
}

/// Decrement the IPv4 TTL by one and patch the header checksum (RFC 1141:
/// checksum += 0x0100 with end-around carry, since the TTL byte is the high
/// half of the 16-bit word at IP offset 8; the UDP checksum is unaffected as
/// TTL is not in its pseudo-header). A forwarding-plane loopback IS a hop, and
/// FRR's fp-echo receiver (`bfd_recv_ipv4_fp`) drops any looped frame whose TTL
/// isn't 254 — both to confirm a real forwarding loop and to discard its own
/// egress copy. Returns Err on a truncated header or TTL 0.
#[inline(always)]
unsafe fn decrement_ttl(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    // Covers the TTL byte (off 22) and the 2-byte checksum (off 24..26).
    if start + IP_CHECK_OFF + 2 > ctx.data_end() {
        return Err(());
    }
    let ttl_ptr = (start + IP_TTL_OFF) as *mut u8;
    let sum_ptr = (start + IP_CHECK_OFF) as *mut u8;
    unsafe {
        let ttl = core::ptr::read_volatile(ttl_ptr);
        if ttl == 0 {
            return Err(());
        }
        core::ptr::write_volatile(ttl_ptr, ttl - 1);

        // IP checksum (big-endian numeric) += 0x0100, fold the carry once.
        let hi = core::ptr::read_volatile(sum_ptr) as u32;
        let lo = core::ptr::read_volatile(sum_ptr.add(1)) as u32;
        let mut sum = ((hi << 8) | lo) + 0x0100;
        sum = (sum & 0xffff) + (sum >> 16);
        core::ptr::write_volatile(sum_ptr, (sum >> 8) as u8);
        core::ptr::write_volatile(sum_ptr.add(1), (sum & 0xff) as u8);
    }
    Ok(())
}

#[xdp]
pub fn bfd_echo_reflect(ctx: XdpContext) -> u32 {
    match try_reflect(&ctx) {
        Ok(action) => action,
        // A truncated/short frame just falls through to the stack.
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_reflect(ctx: &XdpContext) -> Result<u32, ()> {
    // Ethernet II, IPv4 only for this first slice.
    if unsafe { load_u16_be(ctx, ETH_TYPE_OFF)? } != ETHERTYPE_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Only option-less IPv4 (IHL=5). BFD Echo frames carry no IP options; a
    // packet with options would shift the UDP header and is left to the stack.
    if unsafe { load_u8(ctx, IP_VER_IHL_OFF)? } != IPV4_VER_IHL_NOOPTS {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { load_u8(ctx, IP_PROTO_OFF)? } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    if unsafe { load_u16_be(ctx, UDP_DST_OFF)? } != BFD_ECHO_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    // Act as a forwarding hop: decrement TTL + patch the IP checksum, so the
    // looped Echo returns to the originator at TTL 254 (RFC 5880 §6.4 Echo is
    // looped by the remote's forwarding plane; FRR's fp-echo receiver requires
    // exactly TTL 254 and drops anything else).
    unsafe { decrement_ttl(ctx)? };

    // Prove the full 14-byte Ethernet header (both MACs) is in bounds, then swap
    // source/destination MAC in place and bounce the frame straight back out.
    // Swap byte-by-byte at constant offsets (see `swap_byte`) so the copy is
    // never lowered to a verifier-rejected memcpy.
    let start = ctx.data();
    if start + ETH_HLEN > ctx.data_end() {
        return Err(());
    }
    unsafe {
        let dst = (start + ETH_DST_OFF) as *mut u8;
        let src = (start + ETH_SRC_OFF) as *mut u8;
        swap_byte(dst, src);
        swap_byte(dst.add(1), src.add(1));
        swap_byte(dst.add(2), src.add(2));
        swap_byte(dst.add(3), src.add(3));
        swap_byte(dst.add(4), src.add(4));
        swap_byte(dst.add(5), src.add(5));
    }

    // No per-packet logging here: aya-log in XDP is heavyweight (and overflowed
    // its ringbuf record), and logging every reflected frame is undesirable at
    // line rate. Reflection is observable via tcpdump / the XDP_TX action.
    Ok(xdp_action::XDP_TX)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
