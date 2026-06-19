#![no_std]
#![no_main]

//! EVPN BUM replication dataplane (RFC 9524 SR replication segment) — eBPF
//! TC/clsact skeleton.
//!
//! This is the load-and-attach skeleton for the SR P2MP / RFC 9524 replication
//! forwarder that the stock Linux kernel cannot do natively: there is no
//! `End.Replicate` seg6local action, no MPLS P2MP, and no `End.DT2M` for the L2
//! leaf flood. Replication needs a *copy per downstream branch, each with a
//! different rewritten header* — which only the TC layer can express
//! (`bpf_clone_redirect` in a loop, mutating the skb between clones). XDP has no
//! per-copy clone, so this is a `#[classifier]` (clsact) program, unlike the
//! sibling `xdp-bfd-echo` offload.
//!
//! Planned roles, all attached here via clsact:
//!   * root (egress)  — H.Encaps each copy toward a downstream SID / leaf;
//!   * bud  (ingress) — match the local Replication-SID, clone+rewrite per
//!                      branch (`End.Replicate`);
//!   * leaf (ingress) — match the local End.DT2M SID, strip the outer
//!                      IPv6+SRH, redirect the inner frame to the bridge.
//! The branch/leaf state comes from a BPF map the loader fills from the BGP
//! control plane (`ReplSeg`, fed by `EvpnFloodState::replication_leaves`).
//!
//! The per-VNI replication state lives in the `REPL_SEG` BPF map, populated by
//! the loader from the BGP control plane (`ReplSeg`, fed by
//! `EvpnFloodState::replication_leaves`). For now every frame is still passed
//! through untouched (`TC_ACT_PIPE`); the classifier reading the map to clone +
//! rewrite (`End.Replicate`) and decap (`End.DT2M`) lands in a follow-up slice.

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};

/// Maximum replication leaves per VNI stored in the map. Beyond this the
/// loader truncates and warns (an EVPN BD with this many PEs is already
/// extreme for any ingress-style replication).
pub const MAX_LEAVES: usize = 32;

/// `ReplSeg` flag bits.
pub const REPL_FLAG_SRV6: u32 = 1 << 0; // SRv6 (vs SR-MPLS) encapsulation
pub const REPL_FLAG_ROOT_V4: u32 = 1 << 1; // `root` is an IPv4 address (first 4 bytes)

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
/// Read by the (forthcoming) replication datapath to clone + rewrite copies.
#[map]
static REPL_SEG: HashMap<u32, ReplSeg> = HashMap::with_max_entries(256, 0);

#[classifier]
pub fn tc_evpn_replicate(_ctx: TcContext) -> i32 {
    // No-op skeleton: hand every frame back to the stack unchanged. The
    // replication datapath that reads REPL_SEG lands in a follow-up slice.
    TC_ACT_PIPE
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Replication will use GPL-only helpers (bpf_clone_redirect, bpf_redirect),
// so declare a GPL-compatible license up front.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
