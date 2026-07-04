//! STAMP (RFC 8762) active link-delay measurement.
//!
//! Part of the SR-MPLS TE plan (`docs/design/stamp-sr-mpls-te-plan.md`,
//! steps in `docs/design/stamp-phase1-implementation-plan.md`): an
//! unauthenticated Session-Sender per measured P2P link plus an
//! implicit Session-Reflector for registered peers. The damped
//! per-link delay snapshots feed the IGPs' `te-metric` fields — IS-IS
//! (RFC 8570) and OSPFv2 (RFC 7471) link-delay sub-TLVs and
//! Flex-Algorithm metric-type-1 SPF.

pub mod client;
pub mod damping;
pub mod inst;
pub mod network;
pub mod reflector;
pub mod sender;
pub mod session;
pub mod show;
pub mod socket;
pub mod stats;
pub mod timestamp;

#[cfg(test)]
mod integration;
