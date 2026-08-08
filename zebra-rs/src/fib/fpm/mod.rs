//! FPM southbound — the SONiC integration.
//!
//! SONiC's forwarding path is
//!
//! ```text
//! zebra-rs RIB → FPM → fpmsyncd → APPL_DB → orchagent → ASIC_DB → syncd → SAI
//! ```
//!
//! so programming a SONiC ASIC needs no new dataplane story: it needs
//! zebra-rs to speak FPM the way SONiC's FRR does, and everything below
//! `fpmsyncd` keeps working untouched. This module is that tee —
//! structurally the same as [`super::cradle`]: the kernel install stays
//! primary and unchanged, because SONiC expects both a kernel route and
//! an ASIC route for every prefix.
//!
//! The dialect is not upstream FRR's. SONiC ships a forked dataplane
//! plugin, `dplane_fpm_sonic`, which adds private netlink message types
//! for SRv6 local SIDs, PIC contexts, SRv6 VPN routes and EVPN
//! multihoming. This covers plain IPv4/IPv6 unicast — the part every
//! deployment needs — and the private types come later.
//!
//! The encoding rules were read off captures of real SONiC FRR rather
//! than from documentation, using `tools/fpm-tap`; the recordings live in
//! `tools/fpm-tap/golden/` and are asserted against in both directions —
//! [`encode`]'s tests require byte-equality with what FRR sent, and
//! [`decode`]'s parse the acknowledgements FRR received. That matters
//! more than it might sound: `fpmsyncd` copies several fields straight
//! into APPL_DB, so an encoding that is merely *valid* rather than
//! *identical* is a behavioural change against the FRR being replaced.
//!
//! `tools/fpm-tap/rig/ab-diff.sh` closes the loop by replaying both
//! FRR's bytes and this encoder's into a real `fpmsyncd` and diffing the
//! APPL_DB each produces.

pub mod client;
pub mod decode;
pub mod encode;
pub mod frame;
pub mod mirror;

// Fixture generator for the A/B APPL_DB harness (rig/ab-diff.sh).
#[cfg(test)]
mod ab_emit;
#[cfg(test)]
mod testdata;

pub use client::FpmFib;
pub use encode::{RouteOp, encode_route};
