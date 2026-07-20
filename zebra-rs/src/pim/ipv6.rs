//! The IPv6 [`PimAf`] marker and its address-family semantics
//! (RFC 7761 for PIMv6, RFC 4607 for the SSM range).

use std::net::{IpAddr, Ipv6Addr};

use ipnet::{IpNet, Ipv6Net};
use socket2::Socket;
use tokio::io::unix::AsyncFd;

use crate::rib::Link;

use super::af::PimAf;
use super::mroute::Mrt6;

/// IPv6 address-family marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv6;

/// `fe80::/10` — a unicast link-local address (the PIMv6 Hello source
/// and DR-candidate identity, RFC 7761 §4.3.1).
fn is_link_local(a: Ipv6Addr) -> bool {
    let o = a.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

impl PimAf for Ipv6 {
    type Addr = Ipv6Addr;
    type Prefix = Ipv6Net;
    type Fp = Mrt6;

    const ALL_PIM_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000d);
    const GENERAL_QUERY_DST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0001);

    // `is_ssm` is the authority for SSM classification (it honours any
    // scope nibble); this const is the documented representative range.
    const DEFAULT_SSM_RANGE: Ipv6Net =
        Ipv6Net::new_assert(Ipv6Addr::new(0xff30, 0, 0, 0, 0, 0, 0, 0), 12);
    const DEFAULT_RP_RANGE: Ipv6Net =
        Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8);

    fn is_unspecified(a: Ipv6Addr) -> bool {
        a.is_unspecified()
    }

    fn from_ip(ip: IpAddr) -> Option<Ipv6Addr> {
        match ip {
            IpAddr::V6(a) => Some(a),
            IpAddr::V4(_) => None,
        }
    }

    fn to_ip(a: Ipv6Addr) -> IpAddr {
        IpAddr::V6(a)
    }

    fn prefix_from_ipnet(net: IpNet) -> Option<Ipv6Net> {
        match net {
            IpNet::V6(p) => Some(p),
            IpNet::V4(_) => None,
        }
    }

    fn link_prefixes(link: &Link) -> Vec<Ipv6Net> {
        // Link-locals first: the primary (Hello source / DR identity)
        // is a link-local; globals follow as secondary addresses.
        let mut lls = Vec::new();
        let mut globals = Vec::new();
        for a in &link.addr6 {
            let Some(p) = Self::prefix_from_ipnet(a.addr) else {
                continue;
            };
            if is_link_local(p.addr()) {
                lls.push(p);
            } else {
                globals.push(p);
            }
        }
        lls.extend(globals);
        lls
    }

    fn join_pim_if(sock: &AsyncFd<Socket>, ifindex: u32) {
        super::socket::pim_join_if_v6(sock, ifindex);
    }

    fn leave_pim_if(sock: &AsyncFd<Socket>, ifindex: u32) {
        super::socket::pim_leave_if_v6(sock, ifindex);
    }

    fn is_multicast(a: Ipv6Addr) -> bool {
        a.is_multicast()
    }

    fn is_ssm(a: Ipv6Addr) -> bool {
        // FF3x::/32 (RFC 4607 §5): flags nibble 3, any scope nibble,
        // group-id bytes past the /32 boundary zero.
        let o = a.octets();
        o[0] == 0xff && (o[1] & 0xf0) == 0x30 && o[2] == 0 && o[3] == 0
    }

    fn is_reserved_group(a: Ipv6Addr) -> bool {
        // Interface-local (scope 1) and link-local (scope 2), plus the
        // reserved scope 0 — never forwarded off-link.
        let o = a.octets();
        o[0] == 0xff && (o[1] & 0x0f) <= 0x02
    }

    fn is_link_local(a: Ipv6Addr) -> bool {
        // fe80::/10 — the unicast link-local scope.
        let o = a.octets();
        o[0] == 0xfe && (o[1] & 0xc0) == 0x80
    }

    fn prefix_new(addr: Ipv6Addr, len: u8) -> Option<Ipv6Net> {
        Ipv6Net::new(addr, len).ok()
    }

    fn prefix_contains(p: &Ipv6Net, a: &Ipv6Addr) -> bool {
        p.contains(a)
    }

    fn prefix_len(p: &Ipv6Net) -> u8 {
        p.prefix_len()
    }

    fn prefix_addr(p: &Ipv6Net) -> Ipv6Addr {
        p.addr()
    }

    fn null_register_payload(src: Ipv6Addr, grp: Ipv6Addr) -> Vec<u8> {
        // A minimal inner IPv6 header naming (S,G): version 6, payload
        // length 0, next header NONE(59), hop limit 64.
        let mut header = vec![0u8; 40];
        header[0] = 0x60; // version 6
        header[6] = 59; // next header = NONE
        header[7] = 64; // hop limit
        header[8..24].copy_from_slice(&src.octets());
        header[24..40].copy_from_slice(&grp.octets());
        header
    }

    fn register_inner_sg(data: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
        if data.len() < 40 || data[0] >> 4 != 6 {
            return None;
        }
        let mut s = [0u8; 16];
        let mut g = [0u8; 16];
        s.copy_from_slice(&data[8..24]);
        g.copy_from_slice(&data[24..40]);
        Some((Ipv6Addr::from(s), Ipv6Addr::from(g)))
    }

    fn bsr_hash(group: Ipv6Addr, rp: Ipv6Addr, mask_len: u8) -> u32 {
        // Mask the 128-bit group, then XOR-fold both the masked group and
        // the RP to 32 bits before the RFC 2362 recurrence — a defined,
        // deterministic extension so every zebra-rs router agrees.
        let mask = if mask_len == 0 {
            0
        } else {
            u128::MAX << (128 - mask_len.min(128))
        };
        let fold =
            |x: u128| -> u32 { (x >> 96) as u32 ^ (x >> 64) as u32 ^ (x >> 32) as u32 ^ x as u32 };
        let gm = u128::from_be_bytes(group.octets()) & mask;
        let c = u128::from_be_bytes(rp.octets());
        super::af::bsr_hash_value(fold(gm), fold(c))
    }

    fn embedded_rp(group: Ipv6Addr) -> Option<Ipv6Addr> {
        // RFC 3956 §2 group layout:
        //   FF | flgs(4) | scop(4) | rsvd(4) | RIID(4) | plen(8)
        //      | network prefix(64) | group ID(32)
        let o = group.octets();
        // ff70::/12 — R-bit set (RFC 3956 also mandates P=1, T=1, so the
        // flags nibble is 0x7).
        if o[0] != 0xff || (o[1] & 0xf0) != 0x70 {
            return None;
        }
        let rsvd = o[2] >> 4;
        let riid = o[2] & 0x0f;
        let plen = o[3];
        // Reserved must be zero, RIID non-zero, and the prefix must fit in
        // the 64-bit network-prefix field.
        if rsvd != 0 || riid == 0 || plen == 0 || plen > 64 {
            return None;
        }
        // RP = the top `plen` bits of the network prefix (bytes 4..12),
        // zero-filled, with the RIID in the last 4 bits.
        let mut rp = [0u8; 16];
        rp[..8].copy_from_slice(&o[4..12]);
        let full = (plen / 8) as usize;
        let rem = plen % 8;
        if rem != 0 {
            rp[full] &= 0xffu8 << (8 - rem);
            rp[full + 1..8].fill(0);
        } else {
            rp[full..8].fill(0);
        }
        rp[15] = riid;
        Some(Ipv6Addr::from(rp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn multicast_and_ssm_classification() {
        assert!(Ipv6::is_multicast(a("ff3e::1")));
        assert!(!Ipv6::is_multicast(a("2001:db8::1")));
        // FF3x::/32 with any scope is SSM.
        assert!(Ipv6::is_ssm(a("ff3e::1234")));
        assert!(Ipv6::is_ssm(a("ff35::1")));
        // Non-zero group-id bytes past the /32 boundary are not SSM.
        assert!(!Ipv6::is_ssm(a("ff3e:1::1")));
        // ASM (flags nibble != 3) is not SSM.
        assert!(!Ipv6::is_ssm(a("ff0e::1")));
        assert!(!Ipv6::is_ssm(a("2001:db8::1")));
    }

    #[test]
    fn reserved_scopes_never_forward() {
        assert!(Ipv6::is_reserved_group(a("ff02::d"))); // link-local
        assert!(Ipv6::is_reserved_group(a("ff01::1"))); // interface-local
        assert!(!Ipv6::is_reserved_group(a("ff0e::1"))); // global
        assert!(!Ipv6::is_reserved_group(a("ff3e::1"))); // global SSM
    }

    #[test]
    fn prefix_ops_and_ranges() {
        let p = Ipv6::prefix_new(a("2001:db8::"), 32).unwrap();
        assert!(Ipv6::prefix_contains(&p, &a("2001:db8:1::1")));
        assert!(!Ipv6::prefix_contains(&p, &a("2001:db9::1")));
        assert_eq!(Ipv6::prefix_len(&p), 32);
        assert_eq!(Ipv6::prefix_addr(&Ipv6::DEFAULT_RP_RANGE), a("ff00::"));
        assert_eq!(Ipv6::prefix_len(&Ipv6::DEFAULT_RP_RANGE), 8);
    }

    #[test]
    fn wire_conversion_rejects_other_family() {
        assert_eq!(
            Ipv6::from_ip(IpAddr::V6(a("2001:db8::1"))),
            Some(a("2001:db8::1"))
        );
        assert_eq!(Ipv6::from_ip("10.0.0.1".parse().unwrap()), None);
        assert_eq!(Ipv6::to_ip(a("2001:db8::1")), IpAddr::V6(a("2001:db8::1")));
    }

    #[test]
    fn register_inner_round_trip() {
        let payload = Ipv6::null_register_payload(a("2001:db8::2"), a("ff3e::1"));
        assert_eq!(payload.len(), 40);
        assert_eq!(payload[0] >> 4, 6);
        assert_eq!(
            Ipv6::register_inner_sg(&payload),
            Some((a("2001:db8::2"), a("ff3e::1")))
        );
        // An IPv4 inner header is rejected by the IPv6 codec.
        assert_eq!(Ipv6::register_inner_sg(&[0x45; 40]), None);
    }

    #[test]
    fn embedded_rp_decodes_and_validates() {
        // RFC 3956 §5 example: FF7E:0140:2001:DB8::1234 embeds 2001:db8::1
        // (scope E, RIID 1, plen 64, network prefix 2001:db8::).
        assert_eq!(
            Ipv6::embedded_rp(a("ff7e:140:2001:db8::1234")),
            Some(a("2001:db8::1"))
        );
        // A shorter prefix keeps only `plen` bits and still carries RIID.
        assert_eq!(
            Ipv6::embedded_rp(a("ff7e:240:2001:db8:22::9")),
            Some(a("2001:db8:22::2"))
        );

        // Not an Embedded-RP group (R-bit clear): plain ASM / SSM.
        assert_eq!(Ipv6::embedded_rp(a("ff0e::1")), None);
        assert_eq!(Ipv6::embedded_rp(a("ff3e::1")), None);
        // RIID 0 is invalid.
        assert_eq!(Ipv6::embedded_rp(a("ff7e:040:2001:db8::1")), None);
        // A non-zero reserved nibble is invalid.
        assert_eq!(Ipv6::embedded_rp(a("ff7e:1140:2001:db8::1")), None);
        // plen > 64 (does not fit the network-prefix field) is invalid.
        assert_eq!(Ipv6::embedded_rp(a("ff7e:0180:2001:db8::1")), None);
    }
}
