// PR 1 ships the data model + commit plumbing ahead of any consumer.
// OSPF still parses `/key-chains/...` into its own `Ospf::key_chains`
// map (PR 2 migrates it); BGP still parses into `Bgp::key_chains`
// (PR 3 migrates it); IS-IS doesn't reference key-chains today (PR 4).
// Until those land, several types/variants/methods are declared but
// not yet referenced — silence dead_code at the module root so the
// workspace-wide `-D warnings` build stays green.
#![allow(dead_code)]

//! Shared RFC 8177 key-chain registry.
//!
//! This module owns the canonical `/key-chains/...` data model. Today
//! OSPF and BGP each parse the same YANG subtree into their own
//! `key_chains` HashMap; the consolidation goal is to make Policy the
//! single source of truth and have protocols subscribe to the same
//! Register / PolicyRx pattern used for prefix-set and policy-list.
//!
//! This file is the PR 1 skeleton: types + dispatch + commit + Syncer
//! wiring. No protocol consumes the new path yet — OSPF and BGP keep
//! their existing `/key-chains/...` callbacks until the per-protocol
//! migration PRs land. With no subscribers, the new commit path is a
//! quiet no-op, so behavior is unchanged.

pub mod set;
pub use set::{CryptoAlgorithm, Key, KeyChain, Lifetime, LifetimeEnd};

pub mod config;
pub use config::KeyChainSetConfig;

pub mod show;

/// Where a key-chain is referenced from. Carried in
/// `PolicyType::KeyChain` so a subscriber receiving a `PolicyRx::KeyChain`
/// can demultiplex updates back to the right per-protocol container
/// (per-link, per-neighbor, per-IS-IS-scope) using its own `ident`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyChainScope {
    /// OSPFv2/v3 per-interface `key-chain <name>` leaf.
    OspfInterface,
    /// BGP per-neighbor `tcp-ao/key-chain <name>` leaf.
    BgpNeighbor,
    /// IS-IS per-interface `hello-authentication/key-chain <name>`.
    IsisIih,
    /// IS-IS `/router/isis/area-password/key-chain <name>`.
    IsisAreaPw,
    /// IS-IS `/router/isis/domain-password/key-chain <name>`.
    IsisDomainPw,
}
