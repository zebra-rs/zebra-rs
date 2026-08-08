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
//! `fpmsyncd` keeps working untouched. This module is that encoder. It
//! is a **tee**, structurally the same as [`super::cradle`]: the kernel
//! install stays primary and unchanged, because SONiC expects both a
//! kernel route and an ASIC route for every prefix.
//!
//! The dialect is not upstream FRR's. SONiC ships a forked dataplane
//! plugin, `dplane_fpm_sonic`, which adds private netlink message types
//! for SRv6 local SIDs, PIC contexts, SRv6 VPN routes and EVPN
//! multihoming. This first slice covers plain IPv4/IPv6 unicast — the
//! part every deployment needs — and the private types come later.
//!
//! The encoding rules were read off captures of real SONiC FRR rather
//! than from documentation, using `tools/fpm-tap`; the recordings live in
//! `tools/fpm-tap/golden/` and [`encode`]'s tests assert byte-equality
//! against them. That matters more than it might sound: `fpmsyncd`
//! copies several fields straight into APPL_DB, so an encoding that is
//! merely *valid* rather than *identical* is a behavioural change
//! against the FRR being replaced.

// Nothing in the daemon calls the encoder yet — the TCP client to
// fpmsyncd and the `FibHandle` tee that drives it are the next slice, and
// landing them together with the encoder would have meant reviewing the
// wire format and the connection lifecycle in one go. `pub` does not
// exempt a binary crate's items from dead-code analysis, and the build
// runs with `--deny warnings`, so the allow stays until there is a
// caller. Remove it then; the encoder is fully exercised by its tests in
// the meantime.
#![allow(dead_code, unused_imports)]

pub mod encode;
// Fixture generator for the A/B APPL_DB harness (rig/ab-diff.sh).
#[cfg(test)]
mod ab_emit;
pub mod frame;

pub use encode::{RouteOp, encode_route};
pub use frame::FPM_DEFAULT_PORT;
