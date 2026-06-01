#![no_std]
#![no_main]

//! XDP BFD Echo reflector (RFC 5880 §6.4 / RFC 5881 §4).
//!
//! BFD Echo is a stateless data-plane "hairpin": a peer sends an Echo frame to
//! UDP/3785 crafted so that our forwarding plane loops it straight back, and the
//! peer alone times the round trip. This program is that loopback, done in XDP:
//! a matching frame has its Ethernet source/destination MAC swapped and is sent
//! back out the same interface with `XDP_TX`.
//!
//! It is a pure L2 reflect — no IP/UDP checksum recomputation and no TTL
//! decrement are needed, because nothing in the IP/UDP layers changes (notes
//! §2). Everything that is not an IPv4 UDP/3785 frame is passed through
//! untouched, so normal traffic — including BFD *control* on UDP/3784 — is
//! unaffected.
//!
//! First slice: IPv4 only. IPv6 (EtherType 0x86DD) is a follow-up.

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

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
const IP_PROTO_OFF: usize = IP_OFF + 9; // u8
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

    // Prove the full 14-byte Ethernet header (both MACs) is in bounds, then swap
    // source/destination MAC in place and bounce the frame straight back out.
    let start = ctx.data();
    if start + ETH_HLEN > ctx.data_end() {
        return Err(());
    }
    unsafe {
        let dst = (start + ETH_DST_OFF) as *mut [u8; 6];
        let src = (start + ETH_SRC_OFF) as *mut [u8; 6];
        let tmp = *dst;
        *dst = *src;
        *src = tmp;
    }

    info!(ctx, "BFD Echo udp/{} reflected (XDP_TX)", BFD_ECHO_PORT);
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
