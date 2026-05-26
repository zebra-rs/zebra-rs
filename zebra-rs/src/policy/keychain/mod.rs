//! Shared RFC 8177 key-chain registry.
//!
//! Owns the canonical `/key-chains/...` data model. The policy actor
//! parses the YANG subtree once on commit and pushes per-name
//! snapshots to subscribed protocols via `PolicyRx::KeyChain`. OSPF
//! (per-interface `key-chain`), BGP (per-neighbor `tcp-ao/key-chain`),
//! and IS-IS (per-scope `area-password` / `domain-password` /
//! per-link `hello-authentication`) all consume from this registry.
//! Each protocol carries its own selection helpers (lowest active by
//! lifetime, key-id-matched receive, …) and projects the shared
//! `CryptoAlgorithm` enum down to its own supported subset.

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
