#![no_std]
#![no_main]

//! EVPN BUM replication dataplane (RFC 9524 SR replication segment) — eBPF
//! TC/clsact `End.Replicate`.
//!
//! This is the SR P2MP / RFC 9524 replication forwarder the stock Linux kernel
//! cannot do natively: there is no `End.Replicate` seg6local action, no MPLS
//! P2MP, and no `End.DT2M` for the L2 leaf flood. Replication needs a *copy per
//! downstream branch, each with a different rewritten header* — which only the
//! TC layer can express (`bpf_clone_redirect` in a loop, mutating the skb
//! between clones). XDP has no per-copy clone, so this is a `#[classifier]`
//! (clsact) program, unlike the sibling `xdp-bfd-echo` offload.
//!
//! ## `End.Replicate` (this slice — root/bud, clsact ingress)
//!
//! A BUM packet arrives already SRv6-encapsulated, its outer IPv6 Destination
//! Address equal to the local replication SID for the tree (the loader indexes
//! that SID -> VNI in [`REPL_LOCAL_SID`]). For each downstream leaf the program:
//!   1. rewrites the outer IPv6 DA to the leaf's SID (no checksum fix-up — IPv6
//!      has no header checksum and the *outer* DA is not in any inner L4
//!      pseudo-header), and
//!   2. `bpf_clone_redirect`s the copy out the egress ifindex in [`CONFIG`].
//! The outer Hop Limit is decremented once up front (a replication node is a
//! forwarding hop); a packet that arrives with Hop Limit <= 1 is dropped rather
//! than replicated, so a misrouted copy can't storm. The original (which still
//! carries the replication SID, not a deliverable destination) is dropped with
//! `TC_ACT_SHOT` after the fan-out.
//!
//! Writes go through `bpf_skb_store_bytes` / `bpf_skb_load_bytes`
//! (`TcContext::store` / `::load`), never a raw `data` pointer, so nothing is
//! held across the `clone_redirect` calls that invalidate packet pointers.
//!
//! The leaf side — match the local `End.DT2M` SID, strip the outer IPv6+SRH and
//! redirect the inner frame to the bridge master — is the next slice (DP3c).

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};

/// Maximum replication leaves per VNI stored in the map. Beyond this the
/// loader truncates and warns (an EVPN BD with this many PEs is already
/// extreme for any ingress-style replication).
pub const MAX_LEAVES: usize = 32;

/// `ReplSeg` flag bits.
pub const REPL_FLAG_SRV6: u32 = 1 << 0; // SRv6 (vs SR-MPLS) encapsulation
pub const REPL_FLAG_ROOT_V4: u32 = 1 << 1; // `root` is an IPv4 address (first 4 bytes)

// `aya_ebpf::bindings::TC_ACT_*` are `u32`; a `#[classifier]` returns `i32`.
const ACT_PIPE: i32 = TC_ACT_PIPE as i32;
const ACT_SHOT: i32 = TC_ACT_SHOT as i32;

/// Ethernet II + IPv6 fixed-header offsets (from the start of the frame). Only
/// a base IPv6 header is parsed; the replication match is purely on the outer
/// Destination Address, so extension headers between it and any inner payload
/// are irrelevant here.
const ETH_HLEN: usize = 14;
const ETH_TYPE_OFF: usize = 12; // u16 (big-endian) EtherType
const ETHERTYPE_IPV6: u16 = 0x86DD;
const IP6_OFF: usize = ETH_HLEN;
const IP6_HOPLIMIT_OFF: usize = IP6_OFF + 7; // u8 Hop Limit
const IP6_DST_OFF: usize = IP6_OFF + 24; // [u8; 16] destination address

/// One VNI's SR P2MP replication segment (RFC 9524), keyed by VNI in
/// [`REPL_SEG`]. Addresses are stored as 16 bytes — IPv6 verbatim, or IPv4 in
/// the first 4 bytes with the corresponding family flag set. `#[repr(C)]` with
/// the 4-byte fields first so the layout is padding-free and matches the
/// loader's `aya::Pod` mirror byte-for-byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReplSeg {
    pub tree_id: u32,
    pub n_leaves: u32,
    pub flags: u32,
    pub root: [u8; 16],
    pub leaves: [[u8; 16]; MAX_LEAVES],
    /// Per-leaf family flag: 1 = `leaves[i]` is IPv4 (first 4 bytes).
    pub leaf_v4: [u8; MAX_LEAVES],
}

/// Per-VNI replication segments the loader programs from the control plane.
#[map]
static REPL_SEG: HashMap<u32, ReplSeg> = HashMap::with_max_entries(256, 0);

/// Local replication SID -> VNI index, so the datapath can demux an inbound
/// packet to its replication segment by the outer IPv6 Destination Address.
/// The loader fills this from each segment's root SID on `repl-add`.
#[map]
static REPL_LOCAL_SID: HashMap<[u8; 16], u32> = HashMap::with_max_entries(256, 0);

/// Single-entry config: index 0 holds the egress ifindex the replicated copies
/// are `bpf_clone_redirect`ed out of (the SR underlay-facing NIC). The loader
/// sets it from `--redirect-iface`.
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

#[classifier]
pub fn tc_evpn_replicate(ctx: TcContext) -> i32 {
    match try_replicate(&ctx) {
        Ok(action) => action,
        // A truncated/short frame or a transient map/helper failure: hand the
        // packet back to the stack untouched rather than dropping it.
        Err(()) => ACT_PIPE,
    }
}

fn try_replicate(ctx: &TcContext) -> Result<i32, ()> {
    // Only IPv6-framed packets carry an SRv6 replication SID. Anything else is
    // not ours; pass it on.
    let ethertype = u16::from_be(ctx.load::<u16>(ETH_TYPE_OFF).map_err(|_| ())?);
    if ethertype != ETHERTYPE_IPV6 {
        return Ok(ACT_PIPE);
    }

    // Demux by the outer Destination Address: is it one of our local
    // replication SIDs? If not, leave the frame for the stack.
    let da: [u8; 16] = ctx.load(IP6_DST_OFF).map_err(|_| ())?;
    let Some(vni) = (unsafe { REPL_LOCAL_SID.get(&da) }) else {
        return Ok(ACT_PIPE);
    };
    let Some(seg) = (unsafe { REPL_SEG.get(vni) }) else {
        // Indexed SID with no segment (racing withdraw): drop the original, it
        // carries a replication SID that isn't locally deliverable anyway.
        return Ok(ACT_SHOT);
    };

    // Egress device for the replicated copies. Unset (0) means the loader hasn't
    // configured one yet — don't replicate into the void; pass the frame on.
    let ifindex = match CONFIG.get(0) {
        Some(&v) if v != 0 => v,
        _ => return Ok(ACT_PIPE),
    };

    // A replication node is a forwarding hop: decrement the outer Hop Limit
    // once (shared by every copy). Hop Limit <= 1 can't be forwarded — drop
    // rather than replicate, so a misrouted packet can't loop/storm.
    let hop_limit = ctx.load::<u8>(IP6_HOPLIMIT_OFF).map_err(|_| ())?;
    if hop_limit <= 1 {
        return Ok(ACT_SHOT);
    }
    let next_hop_limit = hop_limit - 1;
    ctx.store(IP6_HOPLIMIT_OFF, &next_hop_limit, 0)
        .map_err(|_| ())?;

    // Fan out: one clone per leaf, each with the outer DA rewritten to that
    // leaf's SID. `n_leaves` is bounded by MAX_LEAVES at insert time; the
    // constant loop bound keeps the verifier happy.
    let n_leaves = seg.n_leaves;
    for i in 0..MAX_LEAVES {
        if i as u32 >= n_leaves {
            break;
        }
        let leaf = seg.leaves[i];
        // Rewrite the outer IPv6 Destination Address to this leaf's SID. No
        // checksum fix-up: IPv6 has no header checksum, and the outer DA is not
        // part of any inner L4 pseudo-header.
        if ctx.store(IP6_DST_OFF, &leaf, 0).is_err() {
            // Couldn't rewrite — abandon the fan-out; the original is dropped
            // below regardless (it still holds the replication SID).
            break;
        }
        // Clone the current skb (DA = leaf[i], Hop Limit decremented) and
        // transmit the copy out the egress device. Ignore per-copy errors so
        // one bad leaf doesn't sink the rest.
        let _ = ctx.clone_redirect(ifindex, 0);
    }

    // The original carries the replication SID, not a deliverable address —
    // consume it now that every branch copy has been emitted.
    Ok(ACT_SHOT)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// `bpf_clone_redirect` is a GPL-only helper, so declare a GPL-compatible
// license.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
