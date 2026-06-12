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
//! IPv4 UDP/3785 frame is `XDP_PASS`ed; BFD *control* on UDP/3784 is also
//! passed, after optionally feeding the expiration watchdog (below).
//!
//! When zebra-rs also *originates* Echo on this interface, the loader fills the
//! `OUR_LOCAL_IPS` map. An inbound Echo whose source is one of our own addresses
//! is our frame returning (looped by the peer); rather than re-reflect it (which
//! would loop forever) the program drives the **in-kernel detector**: it arms a
//! per-session `bpf_timer` (re-armed on every return) and `XDP_DROP`s the frame.
//! If returns stop for `echo-interval × detect-mult`, the timer callback fires
//! in softirq and sets a `down` flag in the `ECHO_TIMERS` map; the userspace
//! helper polls that flag and reports `echo-down` to zebra-rs. This is the Echo
//! *sender*'s detection offload — no userspace packet RX in steady state.
//!
//! Both IPv4 (EtherType 0x0800) and IPv6 (0x86DD) Echo frames are handled, but
//! the IPv6 reflect path is NOT a pure analogue of IPv4. IPv4 Echo is
//! *self-addressed* (src == dst == originator) and looped by the peer's
//! forwarding plane, so reflecting it needs only a MAC swap. FRR's IPv6 Echo
//! (`ptm_bfd_echo_snd`) is instead *peer-addressed* — src = originator, dst = us
//! — and FRR loops the return in software (`bp_bfd_echo_in`): a link-local Echo
//! can't be self-addressed through a forwarding hop. So on IPv6 reflect we must
//! also swap the IPv6 source/destination, retargeting the frame at the
//! originator (dst = originator). Without that the frame keeps dst = us, the
//! originator's own forwarding plane bounces it back, and it ping-pongs until
//! the Hop Limit reaches 0 (exactly the symptom seen against FRR). The swap
//! needs no checksum fix-up: IPv6 has no header checksum, the UDP pseudo-header
//! sum (src + dst) is invariant under the swap, and Hop Limit isn't in it. The
//! Hop Limit is still decremented (255 -> 254) so the originator *processes* the
//! return rather than re-reflecting it (FRR reflects only Hop Limit 255) — that
//! decrement is what breaks the mutual-reflection loop. For our own
//! self-addressed Echo the address swap is a harmless no-op.
//!
//! Beyond Echo, the program also hosts the **control-packet expiration
//! watchdog** — standard async-mode detection (RFC 5880 §6.8.4) offloaded to
//! the kernel once a session is Up. An inbound BFD *control* packet (UDP/3784
//! at TTL/Hop-Limit 255, the RFC 5881 §5 GTSM requirement) is parsed just
//! enough to read its Your Discriminator; the matching `CONTROL_TIMERS`
//! entry's `bpf_timer` is re-armed and the frame is **passed** to the stack
//! untouched — the daemon still runs the full FSM on every packet, only the
//! liveness timing lives here. If control packets stop for the programmed
//! detection time, the timer fires in softirq and the helper reports
//! `detect-down`, so detection neither false-fires because the daemon was
//! scheduled out behind a full socket queue nor waits on its event loop.

use aya_ebpf::{
    bindings::{bpf_timer, xdp_action},
    btf_maps::HashMap as BtfHashMap,
    cty::c_void,
    helpers::{bpf_timer_init, bpf_timer_set_callback, bpf_timer_start},
    macros::{btf_map, map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

/// Local IPv4 addresses (big-endian numeric, as read off the wire) of sessions
/// for which *we* originate Echo. The userspace loader fills this. An inbound
/// Echo whose source is one of these is **our own** Echo looped back by the
/// peer — it must NOT be re-reflected (that would loop forever); instead it
/// feeds the in-kernel detector ([`record_return`]) and is dropped. Empty in
/// pure-responder deployments.
#[map]
static OUR_LOCAL_IPS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// IPv6 analogue of [`OUR_LOCAL_IPS`], keyed by the 16-byte address (as read off
/// the wire). Filled by the loader for sessions where we originate IPv6 Echo.
#[map]
static OUR_LOCAL_IPS_V6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// Per-session in-kernel detection state, keyed by our local BFD
/// discriminator. One value layout serves both detectors: Echo-return timing
/// ([`ECHO_TIMERS`]) and control-packet expiration ([`CONTROL_TIMERS`]).
///
/// Lives in a **BTF** map (not the legacy `#[map]` kind) because the kernel
/// locates the embedded `struct bpf_timer` by its BTF, so the value type's
/// layout must be described in BTF. The timer is field 0 (offset 0) — the
/// offset the kernel records and the address [`kick_timer`] passes to
/// `bpf_timer_init`. `align_of` is 8 (the `bpf_timer`'s `[u64; 2]`), within the
/// BTF hash map's 8-byte value-alignment ceiling.
#[repr(C)]
pub struct DetectState {
    /// Kernel-managed one-shot timer. Initialized lazily in-kernel on the first
    /// observed packet (userspace can't `bpf_timer_init`); userspace seeds the
    /// rest of the value zeroed and the kernel zeroes this field on update.
    timer: bpf_timer,
    /// Detection time in nanoseconds. Set by userspace at `echo-add` /
    /// `detect-add`; the re-arm delay on every observed packet.
    detect_ns: u64,
    /// 0 until the timer has been `bpf_timer_init`'d + callback-set in-kernel;
    /// then 1. Read by userspace to know the kernel detector has taken over.
    armed: u8,
    /// Set to 1 by the timer callback when the tracked packets stopped
    /// (detection fired). Polled and cleared by userspace, which then reports
    /// `echo-down` / `detect-down`.
    down: u8,
    _pad: [u8; 6],
}

/// Echo-return detection state per originating session. 256 single-hop echo
/// sessions on one interface is far beyond any real deployment.
#[btf_map]
static ECHO_TIMERS: BtfHashMap<u32, DetectState, 256> = BtfHashMap::new();

/// Control-packet expiration state per Up session — the in-kernel detection
/// timer for *standard* async BFD (RFC 5880 §6.8.4). The daemon seeds an
/// entry at `detect-add` once the session is Up (before establishment the
/// peer may send `Your Discriminator = 0`, which can't be keyed here) and
/// removes it on `detect-del`.
#[btf_map]
static CONTROL_TIMERS: BtfHashMap<u32, DetectState, 256> = BtfHashMap::new();

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
const IP_SRC_OFF: usize = IP_OFF + 12; // u32 (big-endian) source address
const IPPROTO_UDP: u8 = 17;
const IPV4_VER_IHL_NOOPTS: u8 = 0x45; // version 4, IHL 5 (20-byte header)

/// UDP header (assumes a 20-byte IPv4 header, i.e. IHL=5).
const UDP_OFF: usize = IP_OFF + 20;
const UDP_DST_OFF: usize = UDP_OFF + 2; // u16 (big-endian) destination port

/// BFD Echo destination port (RFC 5881 §4). BFD control is 3784; multihop 4784.
const BFD_ECHO_PORT: u16 = 3785;
/// BFD single-hop control destination port (RFC 5881 §4). Control packets are
/// only *observed* (expiration watchdog) and always passed to the stack.
const BFD_CTRL_PORT: u16 = 3784;

/// BFD control header (RFC 5880 §4.1), right after the 8-byte UDP header.
/// Byte 0 is version(3 bits)|diag(5 bits); Your Discriminator — the receiver's
/// session key, i.e. ours — is bytes 8..12, big-endian.
const CTRL_OFF: usize = UDP_OFF + 8; // after an option-less IPv4 header
const CTRL_VERS_DIAG: usize = 0;
const CTRL_YOUR_DISC: usize = 8;
const BFD_VERSION: u8 = 1;
/// TTL / Hop Limit required on a received single-hop control packet
/// (GTSM, RFC 5881 §5). The daemon enforces the same floor, so a packet that
/// fails it must not feed the watchdog either.
const CTRL_TTL: u8 = 255;

/// Our Echo payload (a "local matter", RFC 5880 §5) sits right after the 8-byte
/// UDP header: `{ magic:u32, discr:u32, seq:u32, tx_ts:u64 }`, big-endian. The
/// magic tags it as ours; `discr` keys [`ECHO_TIMERS`]. Must match the userspace
/// `build_echo` layout in `sender.rs`.
const PAYLOAD_OFF: usize = UDP_OFF + 8;
const PL_MAGIC_OFF: usize = PAYLOAD_OFF; // u32 (big-endian) "zbfd"
const PL_DISCR_OFF: usize = PAYLOAD_OFF + 4; // u32 (big-endian) our local discriminator
/// ASCII "zbfd" — tags our own Echo payload.
const ECHO_MAGIC: u32 = 0x7a62_6664;

const ETHERTYPE_IPV6: u16 = 0x86DD;

/// IPv6 fixed-header fields (relative to the start of the frame). Extension
/// headers are not expected on a BFD Echo frame; a non-UDP Next Header is
/// `XDP_PASS`ed. There is no header checksum (unlike IPv4).
const IP6_OFF: usize = ETH_HLEN;
const IP6_NEXTHDR_OFF: usize = IP6_OFF + 6; // u8 Next Header
const IP6_HOPLIMIT_OFF: usize = IP6_OFF + 7; // u8 Hop Limit
const IP6_SRC_OFF: usize = IP6_OFF + 8; // [u8; 16] source address
const IP6_DST_OFF: usize = IP6_OFF + 24; // [u8; 16] destination address
const IP6_HLEN: usize = 40;

/// UDP header after a 40-byte IPv6 header, and the Echo payload after it.
const UDP6_OFF: usize = IP6_OFF + IP6_HLEN;
const UDP6_DST_OFF: usize = UDP6_OFF + 2; // u16 (big-endian) destination port
const PAYLOAD6_OFF: usize = UDP6_OFF + 8;
const PL6_MAGIC_OFF: usize = PAYLOAD6_OFF; // u32 (big-endian) "zbfd"
const PL6_DISCR_OFF: usize = PAYLOAD6_OFF + 4; // u32 (big-endian) our discriminator
/// BFD control header after the fixed IPv6 header (cf. [`CTRL_OFF`]).
const CTRL6_OFF: usize = UDP6_OFF + 8;

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

/// Read a big-endian `u32` at `off` bytes into the frame, with bounds check.
/// Used for the IPv4 source address; the result matches `u32::from(Ipv4Addr)`
/// so it keys [`OUR_LOCAL_IPS`] directly.
#[inline(always)]
unsafe fn load_u32_be(ctx: &XdpContext, off: usize) -> Result<u32, ()> {
    let ptr = ctx.data() + off;
    if ptr + 4 > ctx.data_end() {
        return Err(());
    }
    unsafe {
        let b0 = *(ptr as *const u8) as u32;
        let b1 = *((ptr + 1) as *const u8) as u32;
        let b2 = *((ptr + 2) as *const u8) as u32;
        let b3 = *((ptr + 3) as *const u8) as u32;
        Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }
}

/// Read the 16-byte IPv6 address at `off`: one bounds check, then 16
/// constant-offset byte reads (so the verifier accepts each access against the
/// single `+ 16` check). Octets are in wire order, ready to key
/// [`OUR_LOCAL_IPS_V6`].
#[inline(always)]
unsafe fn load_ip6(ctx: &XdpContext, off: usize) -> Result<[u8; 16], ()> {
    let ptr = ctx.data() + off;
    if ptr + 16 > ctx.data_end() {
        return Err(());
    }
    unsafe {
        Ok([
            *(ptr as *const u8),
            *((ptr + 1) as *const u8),
            *((ptr + 2) as *const u8),
            *((ptr + 3) as *const u8),
            *((ptr + 4) as *const u8),
            *((ptr + 5) as *const u8),
            *((ptr + 6) as *const u8),
            *((ptr + 7) as *const u8),
            *((ptr + 8) as *const u8),
            *((ptr + 9) as *const u8),
            *((ptr + 10) as *const u8),
            *((ptr + 11) as *const u8),
            *((ptr + 12) as *const u8),
            *((ptr + 13) as *const u8),
            *((ptr + 14) as *const u8),
            *((ptr + 15) as *const u8),
        ])
    }
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

/// Decrement the IPv6 Hop Limit by one. Unlike IPv4 there is no header checksum
/// to patch, and the UDP checksum is unaffected (Hop Limit is not in the
/// pseudo-header). Returns Err on a truncated header or Hop Limit 0.
#[inline(always)]
unsafe fn decrement_hop_limit(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    if start + IP6_HOPLIMIT_OFF + 1 > ctx.data_end() {
        return Err(());
    }
    let hl_ptr = (start + IP6_HOPLIMIT_OFF) as *mut u8;
    unsafe {
        let hl = core::ptr::read_volatile(hl_ptr);
        if hl == 0 {
            return Err(());
        }
        core::ptr::write_volatile(hl_ptr, hl - 1);
    }
    Ok(())
}

/// `bpf_timer` callback: fires `detect_ns` after the last observed packet —
/// our originated Echo stopped coming back ([`ECHO_TIMERS`]) or the peer's
/// control packets stopped arriving ([`CONTROL_TIMERS`]). Runs in softirq with
/// the timed-out map element as `value`. It is one-shot (not re-armed here), so
/// it sets the `down` flag for userspace and returns; the next observed packet
/// (if any) re-arms via [`kick_timer`]. Signature is the kernel timer-callback
/// ABI `(map, key, value)`.
unsafe extern "C" fn detect_timeout(
    _map: *mut c_void,
    _key: *mut c_void,
    value: *mut c_void,
) -> i32 {
    if !value.is_null() {
        let st = value as *mut DetectState;
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*st).down), 1) };
    }
    0
}

/// A tracked packet for `st` just arrived: arm (first time) or re-arm the
/// session's detection timer. `map` must be the pointer of the map `st` lives
/// in — `bpf_timer_init` binds the timer to its owning map.
#[inline(always)]
unsafe fn kick_timer(st: *mut DetectState, map: *mut c_void) {
    unsafe {
        let timer = core::ptr::addr_of_mut!((*st).timer);
        if core::ptr::read_volatile(core::ptr::addr_of!((*st).armed)) == 0 {
            // First sighting: init the timer against its own map and bind the
            // callback. Userspace can't do this (no `bpf_timer_init` from the
            // syscall side), so it happens here, once.
            if bpf_timer_init(timer, map, 0) == 0 {
                let cb: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32 =
                    detect_timeout;
                bpf_timer_set_callback(timer, cb as *mut c_void);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*st).armed), 1);
            }
        }
        // Healthy packet: clear any stale down flag and (re)start the one-shot.
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*st).down), 0);
        let detect = core::ptr::read_volatile(core::ptr::addr_of!((*st).detect_ns));
        bpf_timer_start(timer, detect, 0);
    }
}

/// Our own Echo, looped back by the peer, just arrived. Verify the payload magic,
/// then arm (first time) or re-arm the per-session detection timer. Returning
/// `Ok` lets the caller `XDP_DROP` the frame — in steady state the userspace
/// sender never has to touch returns; the kernel times them.
#[inline(always)]
unsafe fn record_return(ctx: &XdpContext, magic_off: usize, discr_off: usize) -> Result<(), ()> {
    if unsafe { load_u32_be(ctx, magic_off)? } != ECHO_MAGIC {
        // Source is one of our IPs but the payload isn't ours — leave it alone.
        return Ok(());
    }
    let discr = unsafe { load_u32_be(ctx, discr_off)? };
    // Userspace seeds the entry at `echo-add`; a miss means we don't track this
    // discriminator (race or stale return) — nothing to do.
    let Some(st) = ECHO_TIMERS.get_ptr_mut(&discr) else {
        return Ok(());
    };
    let map = core::ptr::from_ref(&ECHO_TIMERS)
        .cast_mut()
        .cast::<c_void>();
    unsafe { kick_timer(st, map) };
    Ok(())
}

/// A BFD *control* packet (UDP/3784) is passing through: re-arm the session's
/// expiration watchdog. Purely an observation — the caller always `XDP_PASS`es
/// the frame so the daemon runs the full FSM on it; only the liveness timing is
/// taken over (RFC 5880 §6.8.4 evaluated in-kernel). The packet is matched by
/// its Your Discriminator against entries the daemon seeded at `detect-add`
/// (Up sessions only — before establishment the field may be 0). The TTL /
/// Hop-Limit must be 255 (GTSM, RFC 5881 §5): the daemon drops anything else,
/// so it must not feed the watchdog. Validation is deliberately loose beyond
/// that (version + discriminator match); the discriminator is random per
/// RFC 5880 §6.8.1, and the daemon remains the arbiter of packet validity.
#[inline(always)]
unsafe fn observe_control(ctx: &XdpContext, ttl_off: usize, ctrl_off: usize) -> Result<(), ()> {
    if unsafe { load_u8(ctx, ttl_off)? } != CTRL_TTL {
        return Ok(());
    }
    if unsafe { load_u8(ctx, ctrl_off + CTRL_VERS_DIAG)? } >> 5 != BFD_VERSION {
        return Ok(());
    }
    let discr = unsafe { load_u32_be(ctx, ctrl_off + CTRL_YOUR_DISC)? };
    if discr == 0 {
        // Bootstrap packet (the peer doesn't know our discriminator yet) —
        // only the daemon can demux it; nothing to time here.
        return Ok(());
    }
    let Some(st) = CONTROL_TIMERS.get_ptr_mut(&discr) else {
        return Ok(());
    };
    let map = core::ptr::from_ref(&CONTROL_TIMERS)
        .cast_mut()
        .cast::<c_void>();
    unsafe { kick_timer(st, map) };
    Ok(())
}

/// Prove the full 14-byte Ethernet header (both MACs) is in bounds, then swap
/// source/destination MAC in place so the frame bounces straight back out.
/// Byte-by-byte at constant offsets (see [`swap_byte`]) so the copy is never
/// lowered to a verifier-rejected memcpy.
#[inline(always)]
unsafe fn swap_macs(ctx: &XdpContext) -> Result<(), ()> {
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
    Ok(())
}

/// Prove both 16-byte IPv6 addresses are in bounds, then swap the source and
/// destination in place so a reflected Echo returns to its originator. Required
/// for FRR-style *peer-addressed* IPv6 Echo (dst = us, not self-addressed):
/// without retargeting, the reflected frame keeps dst = us and the originator's
/// forwarding plane bounces it back, looping until the Hop Limit hits 0. The UDP
/// checksum needs no fix-up — its IPv6 pseudo-header sum is src + dst, invariant
/// under the swap. For a self-addressed Echo (src == dst) the swap is a no-op.
/// Byte-by-byte at constant offsets (see [`swap_byte`]) so the copy is never
/// lowered to a verifier-rejected memcpy.
#[inline(always)]
unsafe fn swap_ip6(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    if start + IP6_DST_OFF + 16 > ctx.data_end() {
        return Err(());
    }
    unsafe {
        let src = (start + IP6_SRC_OFF) as *mut u8;
        let dst = (start + IP6_DST_OFF) as *mut u8;
        swap_byte(src, dst);
        swap_byte(src.add(1), dst.add(1));
        swap_byte(src.add(2), dst.add(2));
        swap_byte(src.add(3), dst.add(3));
        swap_byte(src.add(4), dst.add(4));
        swap_byte(src.add(5), dst.add(5));
        swap_byte(src.add(6), dst.add(6));
        swap_byte(src.add(7), dst.add(7));
        swap_byte(src.add(8), dst.add(8));
        swap_byte(src.add(9), dst.add(9));
        swap_byte(src.add(10), dst.add(10));
        swap_byte(src.add(11), dst.add(11));
        swap_byte(src.add(12), dst.add(12));
        swap_byte(src.add(13), dst.add(13));
        swap_byte(src.add(14), dst.add(14));
        swap_byte(src.add(15), dst.add(15));
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
    match unsafe { load_u16_be(ctx, ETH_TYPE_OFF)? } {
        ETHERTYPE_IPV4 => try_reflect_v4(ctx),
        ETHERTYPE_IPV6 => try_reflect_v6(ctx),
        // Anything that isn't IP is left for the stack. BFD *control* on 3784
        // is observed (expiration watchdog) inside the per-family handlers and
        // then passed too.
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn try_reflect_v4(ctx: &XdpContext) -> Result<u32, ()> {
    // Only option-less IPv4 (IHL=5). BFD Echo frames carry no IP options; a
    // packet with options would shift the UDP header and is left to the stack.
    if unsafe { load_u8(ctx, IP_VER_IHL_OFF)? } != IPV4_VER_IHL_NOOPTS {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { load_u8(ctx, IP_PROTO_OFF)? } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }
    match unsafe { load_u16_be(ctx, UDP_DST_OFF)? } {
        BFD_ECHO_PORT => {}
        // BFD control: feed the expiration watchdog, then ALWAYS hand the
        // packet to the stack — the daemon runs the FSM on it. A parse
        // failure (truncated frame) just skips the observation.
        BFD_CTRL_PORT => {
            let _ = unsafe { observe_control(ctx, IP_TTL_OFF, CTRL_OFF) };
            return Ok(xdp_action::XDP_PASS);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Our own originated Echo, looped back by the peer, is self-addressed to one
    // of our local IPs. Don't re-reflect it (that loops forever) — feed the
    // in-kernel detector (arm/re-arm this session's bpf_timer) and drop it. A
    // peer's Echo (any other source) falls through to the reflect path below.
    let src_ip = unsafe { load_u32_be(ctx, IP_SRC_OFF)? };
    if unsafe { OUR_LOCAL_IPS.get(&src_ip) }.is_some() {
        unsafe { record_return(ctx, PL_MAGIC_OFF, PL_DISCR_OFF)? };
        return Ok(xdp_action::XDP_DROP);
    }

    // Act as a forwarding hop: decrement TTL + patch the IP checksum, so the
    // looped Echo returns to the originator at TTL 254 (RFC 5880 §6.4 Echo is
    // looped by the remote's forwarding plane; FRR's fp-echo receiver requires
    // exactly TTL 254 and drops anything else).
    unsafe { decrement_ttl(ctx)? };
    unsafe { swap_macs(ctx)? };
    Ok(xdp_action::XDP_TX)
}

fn try_reflect_v6(ctx: &XdpContext) -> Result<u32, ()> {
    // Base IPv6 header only (no extension headers): Next Header must be UDP. A
    // BFD Echo frame carries none, so a chained header is left for the stack.
    if unsafe { load_u8(ctx, IP6_NEXTHDR_OFF)? } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }
    match unsafe { load_u16_be(ctx, UDP6_DST_OFF)? } {
        BFD_ECHO_PORT => {}
        // BFD control over IPv6: observe for the expiration watchdog (Hop
        // Limit takes the GTSM role), then pass to the stack.
        BFD_CTRL_PORT => {
            let _ = unsafe { observe_control(ctx, IP6_HOPLIMIT_OFF, CTRL6_OFF) };
            return Ok(xdp_action::XDP_PASS);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Our own originated Echo, looped back by the peer (self-addressed to one of
    // our link-locals): feed the in-kernel detector and drop, don't re-reflect.
    let src = unsafe { load_ip6(ctx, IP6_SRC_OFF)? };
    if unsafe { OUR_LOCAL_IPS_V6.get(&src) }.is_some() {
        unsafe { record_return(ctx, PL6_MAGIC_OFF, PL6_DISCR_OFF)? };
        return Ok(xdp_action::XDP_DROP);
    }

    // Reflect a peer's Echo back to its originator. FRR sends IPv6 Echo
    // peer-addressed (dst = us) and loops the return in bfdd, so we retarget the
    // frame: swap the IPv6 src/dst (no checksum fix-up — commutative in the UDP
    // pseudo-header; see swap_ip6) AND swap MACs. The Hop Limit decrement
    // (255 -> 254) makes the originator process the return instead of
    // re-reflecting it (FRR reflects only Hop Limit 255) — this is what stops
    // the ping-pong. A self-addressed Echo (src == dst) is unaffected: the
    // address swap is a no-op.
    unsafe { decrement_hop_limit(ctx)? };
    unsafe { swap_ip6(ctx)? };
    unsafe { swap_macs(ctx)? };
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
