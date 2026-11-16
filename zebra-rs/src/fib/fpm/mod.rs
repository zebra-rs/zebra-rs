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

/// Whether a prefix belongs in the FPM stream at all.
///
/// The host loopback net (`127.0.0.0/8`, `::1`) and IPv6 link-local
/// (`fe80::/10`) never reach APPL_DB from SONiC's FRR: its zebra has no
/// connected route for the loopback net and does not hand link-local
/// prefixes to the dataplane. zebra-rs carries both as ordinary connected
/// routes, so without this gate they are teed, `fpmsyncd` accepts them,
/// and the ASIC is programmed with `127.0.0.0/16 -> lo`, `::1 -> lo` and
/// one `fe80::/64` — rows the FRR being replaced never produces. Seen as
/// an APPL_DB diff between an FRR and a zebra-rs SONiC VS on the same
/// config. A sub-prefix of either range is excluded too.
pub fn is_fpm_prefix(prefix: &ipnet::IpNet) -> bool {
    match prefix {
        ipnet::IpNet::V4(p) => !p.addr().is_loopback(),
        ipnet::IpNet::V6(p) => {
            let addr = p.addr();
            !addr.is_loopback() && (addr.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

#[cfg(test)]
mod prefix_gate_tests {
    use super::is_fpm_prefix;

    fn fpm(s: &str) -> bool {
        is_fpm_prefix(&s.parse().unwrap())
    }

    #[test]
    fn loopback_and_link_local_stay_out_of_fpm() {
        // What a SONiC box has on `lo` and on every L3 interface.
        assert!(!fpm("127.0.0.0/16"));
        assert!(!fpm("127.0.0.0/8"));
        assert!(!fpm("127.0.0.1/32"));
        assert!(!fpm("::1/128"));
        assert!(!fpm("fe80::/64"));
        assert!(!fpm("fe80::/10"));
        assert!(!fpm("febf::1/128"));
    }

    #[test]
    fn ordinary_prefixes_are_teed() {
        assert!(fpm("0.0.0.0/0"));
        assert!(fpm("::/0"));
        assert!(fpm("10.1.0.1/32"));
        assert!(fpm("10.0.0.0/31"));
        assert!(fpm("240.127.1.0/24"));
        assert!(fpm("fc00:1::/64"));
        // Just outside fe80::/10 on both sides.
        assert!(fpm("fe7f::/16"));
        assert!(fpm("fec0::/10"));
        assert!(fpm("2001:db8::1/128"));
    }
}
