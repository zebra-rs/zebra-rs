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
//! For now every frame is passed through untouched (`TC_ACT_PIPE`); the
//! replication logic and maps land in follow-up slices.

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};

#[classifier]
pub fn tc_evpn_replicate(_ctx: TcContext) -> i32 {
    // No-op skeleton: hand every frame back to the stack unchanged.
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
