#![no_std]
#![no_main]

//! EVPN BUM replication dataplane (RFC 9524 SR replication segment) — eBPF
//! TC/clsact `End.Replicate` + leaf `End.DT2M`.
//!
//! This is the SR P2MP / RFC 9524 replication forwarder the stock Linux kernel
//! cannot do natively: there is no `End.Replicate` seg6local action, no MPLS
//! P2MP, and no `End.DT2M` for the L2 leaf flood. Replication needs a *copy per
//! downstream branch, each with a different rewritten header* — which only the
//! TC layer can express (`bpf_clone_redirect` in a loop, mutating the skb
//! between clones). XDP has no per-copy clone, so this is a `#[classifier]`
//! (clsact) program, unlike the sibling `xdp-bfd-echo` offload.
//!
//! One clsact-ingress classifier serves both replication roles, keyed by which
//! map the inbound packet's outer IPv6 Destination Address hits:
//!
//! ## `End.Replicate` (root/bud) — DA in [`REPL_LOCAL_SID`]
//!
//! A BUM packet arrives already SRv6-encapsulated, its outer IPv6 DA equal to
//! the local replication SID for the tree. For each downstream leaf the program
//! rewrites the outer DA to the leaf's SID (no checksum fix-up — IPv6 has no
//! header checksum and the *outer* DA is not in any inner L4 pseudo-header) and
//! `bpf_clone_redirect`s the copy out the egress ifindex in [`CONFIG`]`[0]`. The
//! outer Hop Limit is decremented once up front (a replication node is a
//! forwarding hop); a packet arriving with Hop Limit <= 1 is dropped rather
//! than replicated, so a misrouted copy can't storm. The original (which still
//! carries the replication SID) is dropped with `TC_ACT_SHOT` after fan-out.
//!
//! ## Leaf `End.DT2M` — DA in [`DT2M_SID`]
//!
//! A replicated copy arrives at a leaf PE addressed to its local `End.DT2M`
//! SID: outer IPv6 (reduced SRv6 encap, Next Header = Ethernet/143) wrapping the
//! inner Ethernet BUM frame. The program removes the outer encap (link Ethernet
//! + outer IPv6) by sliding the inner frame to the front and trimming the tail
//! (`bpf_skb_adjust_room` can't strip a full outer L3 — it preserves the
//! network header), then `bpf_redirect`s the inner frame to a bridge port's
//! ingress (`CONFIG[1]`) so the bridge floods it natively to the local
//! attachment circuits — the L2 flood the kernel has no SID behavior for. (Only
//! the reduced encap, no SRH, is handled here; the SRH-present form is a
//! follow-up.)
//!
//! ## Root `H.Encaps` from a bare frame — `tc_evpn_encap` (clsact egress)
//!
//! At the ingress PE a BUM frame arrives *bare* (just `[inner Ethernet][...]`)
//! from the local bridge — there is no outer SID to match on, so this is a
//! separate classifier attached at the overlay bridge-port's **egress**. For
//! every bare frame it prepends a reduced SRv6 encap (link Ethernet + outer
//! IPv6, Next Header = Ethernet/143, src = the root SID), then fans out exactly
//! like `End.Replicate`: one `clone_redirect` per leaf with the outer DA set to
//! that leaf's SID, out the underlay. `bpf_skb_adjust_room` can't prepend a full
//! outer L2+L3 in front of the frame, so — mirroring the leaf decap — the buffer
//! is grown at the tail (`bpf_skb_change_tail`) and the bare frame slid right to
//! open 54 bytes of headroom. Config (root SID, VNI, underlay ifindex, outer MAC
//! header) comes from [`ENCAP_CFG`]; the leaf set is `REPL_SEG[vni]`.
//!
//! Packet access goes through `bpf_skb_store_bytes` / `bpf_skb_load_bytes`
//! (`TcContext::store` / `::load`), never a raw `data` pointer, so nothing is
//! held across the `clone_redirect` / `change_tail` calls that invalidate
//! packet pointers.

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::{bpf_redirect, bpf_skb_change_tail},
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

/// `CONFIG` slots (egress devices the loader resolves once at attach).
const CFG_REPLICATE_IFINDEX: u32 = 0; // `End.Replicate` clone egress
const CFG_BRIDGE_IFINDEX: u32 = 1; // leaf `End.DT2M` flood target

/// `bpf_redirect` flag: deliver to the target's ingress (kernel
/// `BPF_F_INGRESS`). Redirecting a decapped frame to a bridge *port's* ingress
/// makes the bridge flood it to the other ports.
const BPF_F_INGRESS: u64 = 1;

/// Ethernet II + IPv6 fixed-header offsets (from the start of the frame).
const ETH_HLEN: usize = 14;
const ETH_TYPE_OFF: usize = 12; // u16 (big-endian) EtherType
const ETHERTYPE_IPV6: u16 = 0x86DD;
const IP6_OFF: usize = ETH_HLEN;
const IP6_HLEN: usize = 40;
const IP6_NEXTHDR_OFF: usize = IP6_OFF + 6; // u8 Next Header
const IP6_HOPLIMIT_OFF: usize = IP6_OFF + 7; // u8 Hop Limit
const IP6_DST_OFF: usize = IP6_OFF + 24; // [u8; 16] destination address

/// IANA protocol number for "Ethernet" (RFC 8986 §6.6) — the outer IPv6 Next
/// Header of a reduced SRv6 L2 (`End.DT2M`) encapsulation, indicating the
/// payload is an Ethernet frame.
const NH_ETHERNET: u8 = 143;
/// Bytes of outer encap to remove for a reduced `End.DT2M` frame: the link
/// Ethernet header + the outer IPv6 header. What follows is the inner Ethernet
/// BUM frame, which becomes the new link frame.
const DT2M_STRIP: usize = ETH_HLEN + IP6_HLEN; // 54
/// Bytes of reduced SRv6 encap the root prepends to a bare BUM frame: a new link
/// Ethernet header + the outer IPv6 header (mirror of [`DT2M_STRIP`]).
const ENCAP_OVERHEAD: usize = ETH_HLEN + IP6_HLEN; // 54
/// Upper bound on the inner frame length copied during decap/encap (a jumbo-free
/// Ethernet payload fits well under this). The verifier needs a constant loop
/// bound; a frame longer than this is left for the stack.
const MAX_INNER: usize = 2048;

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

/// Local `End.DT2M` SID -> VNI index for the leaf role: a packet whose outer DA
/// matches is decapsulated and the inner Ethernet frame flooded into the
/// bridge. The loader fills this on `leaf-add`.
#[map]
static DT2M_SID: HashMap<[u8; 16], u32> = HashMap::with_max_entries(256, 0);

/// Egress devices, by `CFG_*` index: `[0]` = `End.Replicate` clone egress,
/// `[1]` = leaf `End.DT2M` bridge-flood target. 0 = unset (role disabled).
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(2, 0);

/// Root `H.Encaps` config (single entry), filled by the loader for the
/// `tc_evpn_encap` role. `#[repr(C)]` with the `u32`s first so it is padding-free
/// and matches the loader's `aya::Pod` mirror byte-for-byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EncapCfg {
    /// VNI whose leaf set (`REPL_SEG[vni]`) the bare frame fans out to.
    pub vni: u32,
    /// Underlay ifindex the encapsulated copies are `clone_redirect`ed out of.
    /// 0 = the encap role is not configured.
    pub underlay_ifindex: u32,
    /// Outer IPv6 source address (this PE's root SID).
    pub root_sid: [u8; 16],
    /// Prebuilt outer link Ethernet header (dst MAC | src MAC | 0x86DD).
    pub link_eth: [u8; ETH_HLEN],
    pub _pad: [u8; 2],
}

/// Single-entry root `H.Encaps` config the loader fills from `encap-cfg`.
#[map]
static ENCAP_CFG: Array<EncapCfg> = Array::with_max_entries(1, 0);

#[classifier]
pub fn tc_evpn_replicate(ctx: TcContext) -> i32 {
    match try_forward(&ctx) {
        Ok(action) => action,
        // A truncated/short frame or a transient map/helper failure: hand the
        // packet back to the stack untouched rather than dropping it.
        Err(()) => ACT_PIPE,
    }
}

fn try_forward(ctx: &TcContext) -> Result<i32, ()> {
    // Only IPv6-framed packets carry an SRv6 replication / End.DT2M SID.
    let ethertype = u16::from_be(ctx.load::<u16>(ETH_TYPE_OFF).map_err(|_| ())?);
    if ethertype != ETHERTYPE_IPV6 {
        return Ok(ACT_PIPE);
    }

    // Demux by the outer Destination Address.
    let da: [u8; 16] = ctx.load(IP6_DST_OFF).map_err(|_| ())?;
    if unsafe { REPL_LOCAL_SID.get(&da) }.is_some() {
        // Root/bud: a replication SID -> clone + per-branch DA rewrite.
        return end_replicate(ctx, &da);
    }
    if unsafe { DT2M_SID.get(&da) }.is_some() {
        // Leaf: our End.DT2M SID -> decap + flood into the bridge.
        return end_dt2m(ctx);
    }
    // Not one of our SIDs; leave it for the stack.
    Ok(ACT_PIPE)
}

/// `End.Replicate` (root/bud): fan the packet out, one clone per leaf, each with
/// the outer IPv6 DA rewritten to that leaf's SID.
fn end_replicate(ctx: &TcContext, da: &[u8; 16]) -> Result<i32, ()> {
    // `da` already matched REPL_LOCAL_SID in the caller; re-fetch the VNI +
    // segment here so the borrows are local to this branch.
    let Some(vni) = (unsafe { REPL_LOCAL_SID.get(da) }) else {
        return Ok(ACT_PIPE);
    };
    let Some(seg) = (unsafe { REPL_SEG.get(vni) }) else {
        // Indexed SID with no segment (racing withdraw): drop the original, it
        // carries a replication SID that isn't locally deliverable anyway.
        return Ok(ACT_SHOT);
    };

    // Egress device for the replicated copies. Unset (0) means the loader hasn't
    // configured one yet — don't replicate into the void; pass the frame on.
    let ifindex = match CONFIG.get(CFG_REPLICATE_IFINDEX) {
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

/// Leaf `End.DT2M`: strip the reduced SRv6 encap and flood the inner Ethernet
/// frame into the bridge so the kernel replicates it to the local ACs.
fn end_dt2m(ctx: &TcContext) -> Result<i32, ()> {
    // Only the reduced encap (single SID in the DA, no SRH) is handled here:
    // the outer IPv6 Next Header is Ethernet(143) and the inner Ethernet frame
    // follows the fixed header directly. An SRH-present frame (Next Header 43)
    // is left for a follow-up; pass it on.
    if ctx.load::<u8>(IP6_NEXTHDR_OFF).map_err(|_| ())? != NH_ETHERNET {
        return Ok(ACT_PIPE);
    }

    // Bridge port to flood into. Unset (0) means the leaf role isn't configured.
    let bridge = match CONFIG.get(CFG_BRIDGE_IFINDEX) {
        Some(&v) if v != 0 => v,
        _ => return Ok(ACT_PIPE),
    };

    // Decap = remove the outer encap (link Ethernet + outer IPv6) from the front
    // of the frame, leaving the inner Ethernet BUM frame. `bpf_skb_adjust_room`
    // can't do this — it preserves the L3 header and refuses to shrink past it —
    // so shift the inner frame to the front and trim the tail. (`adjust_room`
    // also has no "remove the L2 header" mode.)
    let total = ctx.len() as usize;
    if total <= DT2M_STRIP {
        return Ok(ACT_PIPE); // no inner frame
    }
    let inner_len = total - DT2M_STRIP;

    // Slide the inner frame left by DT2M_STRIP bytes, ascending so the (lower)
    // destination never clobbers a not-yet-read (higher) source byte. The
    // constant `MAX_INNER` bound keeps the loop bounded for the verifier; a
    // frame longer than that is left for the stack.
    let mut i = 0usize;
    while i < inner_len && i < MAX_INNER {
        let b: u8 = ctx.load(DT2M_STRIP + i).map_err(|_| ())?;
        ctx.store(i, &b, 0).map_err(|_| ())?;
        i += 1;
    }
    if i < inner_len {
        return Ok(ACT_PIPE); // frame larger than MAX_INNER — don't truncate it
    }

    // Trim the now-duplicated trailing DT2M_STRIP bytes: the skb becomes exactly
    // the inner Ethernet frame. A real BUM frame is a full (>=60-byte) Ethernet
    // frame, so `inner_len` clears the kernel's change_tail minimum; if a runt
    // frame can't be trimmed, drop it rather than flood stale tail bytes.
    if unsafe { bpf_skb_change_tail(ctx.skb.skb, inner_len as u32, 0) } != 0 {
        return Ok(ACT_SHOT);
    }

    // Flood into the bridge (ingress on a bridge port): the bridge replicates
    // the inner BUM frame to the other local attachment circuits.
    Ok(unsafe { bpf_redirect(bridge, BPF_F_INGRESS) } as i32)
}

#[classifier]
pub fn tc_evpn_encap(ctx: TcContext) -> i32 {
    match try_encap(&ctx) {
        Ok(action) => action,
        Err(()) => ACT_PIPE,
    }
}

/// Root `H.Encaps`: wrap a bare BUM Ethernet frame in a reduced SRv6 encap and
/// fan it out, one `clone_redirect` per leaf with the outer DA set to that
/// leaf's SID.
fn try_encap(ctx: &TcContext) -> Result<i32, ()> {
    let Some(cfg) = ENCAP_CFG.get(0) else {
        return Ok(ACT_PIPE);
    };
    if cfg.underlay_ifindex == 0 {
        return Ok(ACT_PIPE); // encap role not configured
    }
    let Some(seg) = (unsafe { REPL_SEG.get(&cfg.vni) }) else {
        return Ok(ACT_PIPE); // no leaf set yet
    };
    let n_leaves = seg.n_leaves;
    if n_leaves == 0 {
        return Ok(ACT_PIPE);
    }

    // The bare BUM frame currently being transmitted out the overlay port.
    let inner_total = ctx.len() as usize;
    if inner_total < ETH_HLEN || inner_total > MAX_INNER {
        return Ok(ACT_PIPE);
    }

    // Open ENCAP_OVERHEAD bytes of headroom at the front: grow the buffer at the
    // tail, then slide the bare frame right. (`bpf_skb_adjust_room` can't prepend
    // a full outer L2+L3.) Descending copy so a not-yet-read lower byte is never
    // clobbered by an earlier (higher) write.
    let new_total = inner_total + ENCAP_OVERHEAD;
    if unsafe { bpf_skb_change_tail(ctx.skb.skb, new_total as u32, 0) } != 0 {
        return Ok(ACT_PIPE); // can't grow (MTU) — leave the frame for the stack
    }
    let mut k = 0usize;
    while k < inner_total && k < MAX_INNER {
        let src = inner_total - 1 - k;
        let b: u8 = ctx.load(src).map_err(|_| ())?;
        ctx.store(ENCAP_OVERHEAD + src, &b, 0).map_err(|_| ())?;
        k += 1;
    }
    if k < inner_total {
        return Ok(ACT_SHOT); // unreachable (inner_total <= MAX_INNER) — be safe
    }

    // Outer link Ethernet header (dst | src | 0x86DD), prebuilt by the loader.
    ctx.store(0, &cfg.link_eth, 0).map_err(|_| ())?;

    // Outer IPv6 header: version 6, payload length = the inner frame, Next Header
    // = Ethernet(143), Hop Limit 64, src = root SID. The DA is set per leaf below.
    let mut ip6 = [0u8; IP6_HLEN];
    ip6[0] = 0x60;
    ip6[4] = (inner_total >> 8) as u8;
    ip6[5] = inner_total as u8;
    ip6[6] = NH_ETHERNET;
    ip6[7] = 64;
    ip6[8..24].copy_from_slice(&cfg.root_sid);
    ctx.store(IP6_OFF, &ip6, 0).map_err(|_| ())?;

    // Fan out: per leaf, set the outer DA and clone a copy out the underlay.
    for i in 0..MAX_LEAVES {
        if i as u32 >= n_leaves {
            break;
        }
        let leaf = seg.leaves[i];
        if ctx.store(IP6_DST_OFF, &leaf, 0).is_err() {
            break;
        }
        let _ = ctx.clone_redirect(cfg.underlay_ifindex, 0);
    }

    // Drop the bare original — the encapsulated copies carry it onward.
    Ok(ACT_SHOT)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// `bpf_clone_redirect` / `bpf_redirect` are GPL-only helpers, so declare a
// GPL-compatible license.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
