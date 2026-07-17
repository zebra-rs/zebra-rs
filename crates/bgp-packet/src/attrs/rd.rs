use nom_derive::*;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use super::{asn_from_string, asn_to_string};

#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Default, NomBE, PartialEq, Debug, Clone, Ord, PartialOrd, Eq, Copy, Hash)]
pub enum RouteDistinguisherType {
    /// Type 0: 2-octet AS number : 4-octet assigned number.
    #[default]
    ASN = 0,
    /// Type 1: 4-octet IPv4 address : 2-octet assigned number.
    IP = 1,
    /// Type 2: 4-octet AS number : 2-octet assigned number (RFC 4364 §4.2),
    /// standard wherever the AS is 4-byte. The derived `NomBE` parser has no
    /// catch-all, so without this variant a type-2 RD fails to parse and the
    /// enclosing VPNv4/VPNv6/EVPN/MUP NLRI is silently dropped by
    /// `many0_complete`.
    ASN4 = 2,
}

#[derive(Default, NomBE, PartialEq, Debug, Clone, Ord, Eq, PartialOrd, Copy, Hash)]
pub struct RouteDistinguisher {
    pub typ: RouteDistinguisherType,
    pub val: [u8; 6],
}

impl RouteDistinguisher {
    pub fn new(typ: RouteDistinguisherType) -> Self {
        Self {
            typ,
            ..Default::default()
        }
    }
}

impl FromStr for RouteDistinguisher {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let strs: Vec<&str> = s.split(':').collect();
        if strs.len() != 2 {
            return Err(());
        }
        // Type 1: a 32-bit IP address, a colon, and a 16-bit number, for
        // example: 192.168.1.2:51. Tried first because an IPv4 address is also
        // dot-separated integers and must not be mistaken for asdot.
        if let Ok(addr) = strs[0].parse::<Ipv4Addr>()
            && let Ok(val) = strs[1].parse::<u16>()
        {
            let mut rd = RouteDistinguisher::new(RouteDistinguisherType::IP);
            rd.val[0..4].copy_from_slice(&addr.octets());
            rd.val[4..6].copy_from_slice(&val.to_be_bytes());
            return Ok(rd);
        }
        // Type 2 in asdot notation: <high16>.<low16>, a colon, and a 16-bit
        // number, for example 1.10:3 or 64086.59904:1 (RFC 5396) — the form
        // IOS-XR emits under `as-format asdot`, and the only form GoBGP emits.
        // The dot makes the 4-octet-AS encoding explicit, so it selects type 2
        // whatever the AS magnitude; this mirrors GoBGP's
        // `ParseRouteDistinguisher` and is the only way to spell a type-2 RD
        // whose AS happens to fit in 16 bits.
        if strs[0].contains('.')
            && let Some(asn) = asn_from_string(strs[0])
            && let Ok(val) = strs[1].parse::<u16>()
        {
            let mut rd = RouteDistinguisher::new(RouteDistinguisherType::ASN4);
            rd.val[0..4].copy_from_slice(&asn.to_be_bytes());
            rd.val[4..6].copy_from_slice(&val.to_be_bytes());
            return Ok(rd);
        }
        // Type 0: a 16-bit autonomous system number, a colon, and a 32-bit
        // number, for example: 65000:3. Tried before the asplain type-2 form so
        // an AS that fits in 16 bits keeps the conventional 2-octet-AS
        // encoding.
        if let Ok(asn) = strs[0].parse::<u16>()
            && let Ok(val) = strs[1].parse::<u32>()
        {
            let mut rd = RouteDistinguisher::new(RouteDistinguisherType::ASN);
            rd.val[0..2].copy_from_slice(&asn.to_be_bytes());
            rd.val[2..6].copy_from_slice(&val.to_be_bytes());
            return Ok(rd);
        }
        // Type 2 in asplain notation: a 32-bit autonomous system number above
        // 65535, a colon, and a 16-bit number, for example 4200000000:1 — the
        // form IOS-XR emits by default (`as-format asplain`, RFC 5396's
        // recommended notation).
        if let Ok(asn) = strs[0].parse::<u32>()
            && let Ok(val) = strs[1].parse::<u16>()
        {
            let mut rd = RouteDistinguisher::new(RouteDistinguisherType::ASN4);
            rd.val[0..4].copy_from_slice(&asn.to_be_bytes());
            rd.val[4..6].copy_from_slice(&val.to_be_bytes());
            return Ok(rd);
        }
        Err(())
    }
}

impl fmt::Display for RouteDistinguisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.typ {
            RouteDistinguisherType::ASN => {
                let asn = u16::from_be_bytes([self.val[0], self.val[1]]);
                let val = u32::from_be_bytes([self.val[2], self.val[3], self.val[4], self.val[5]]);
                write!(f, "{asn}:{val}")
            }
            RouteDistinguisherType::IP => {
                let ip = Ipv4Addr::new(self.val[0], self.val[1], self.val[2], self.val[3]);
                let val = u16::from_be_bytes([self.val[4], self.val[5]]);
                write!(f, "{ip}:{val}")
            }
            RouteDistinguisherType::ASN4 => {
                // asdot, matching `asn_to_string`'s AS_PATH rendering so the
                // same 4-byte AS is spelled identically everywhere in show
                // output. A type-2 AS below 65536 therefore prints undotted and
                // reads back as type 0 — the text form is inherently ambiguous,
                // while the wire parse preserves `typ` exactly.
                let asn = u32::from_be_bytes([self.val[0], self.val[1], self.val[2], self.val[3]]);
                let val = u16::from_be_bytes([self.val[4], self.val[5]]);
                write!(f, "{}:{}", asn_to_string(asn), val)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let rd: RouteDistinguisher = RouteDistinguisher::from_str("65000:3").unwrap();
        assert_eq!(rd.to_string(), "65000:3");

        let rd: RouteDistinguisher = RouteDistinguisher::from_str("192.168.1.2:51").unwrap();
        assert_eq!(rd.to_string(), "192.168.1.2:51");
    }

    /// A type-2 RD (4-octet AS : 2-octet number, RFC 4364 §4.2) must parse off
    /// the wire. Regression: the enum previously had no type-2 variant and no
    /// catch-all, so the derived parser returned a `Switch` error and the
    /// enclosing VPN NLRI was silently dropped by `many0_complete`.
    #[test]
    fn type2_rd_parses_from_wire() {
        // typ = 2, AS = 4200000000 (0xFA56EA00), assigned number = 1.
        let wire = [0x00u8, 0x02, 0xfa, 0x56, 0xea, 0x00, 0x00, 0x01];
        let (rest, rd) = RouteDistinguisher::parse_be(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(rd.typ, RouteDistinguisherType::ASN4);
        assert_eq!(rd.val, [0xfa, 0x56, 0xea, 0x00, 0x00, 0x01]);
        // asdot: 0xFA56 = 64086, 0xEA00 = 59904.
        assert_eq!(rd.to_string(), "64086.59904:1");
    }

    /// The pre-existing types keep parsing and rendering exactly as before.
    #[test]
    fn type0_and_type1_parse_from_wire() {
        let t0 = [0x00u8, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x03];
        let (_, rd) = RouteDistinguisher::parse_be(&t0).unwrap();
        assert_eq!(rd.typ, RouteDistinguisherType::ASN);
        assert_eq!(rd.to_string(), "65000:3");

        let t1 = [0x00u8, 0x01, 0xc0, 0xa8, 0x01, 0x02, 0x00, 0x33];
        let (_, rd) = RouteDistinguisher::parse_be(&t1).unwrap();
        assert_eq!(rd.typ, RouteDistinguisherType::IP);
        assert_eq!(rd.to_string(), "192.168.1.2:51");
    }

    /// Both vendor notations for the same 4-byte AS parse to the identical RD:
    /// asplain (IOS-XR's default, RFC 5396's recommendation) and asdot (IOS-XR
    /// under `as-format asdot`, and the only form GoBGP emits). A 4-byte AS
    /// previously failed `from_str` entirely, so such an RD/RT could not be
    /// configured at all.
    #[test]
    fn type2_rd_accepts_asplain_and_asdot() {
        let expect = [0xfa, 0x56, 0xea, 0x00, 0x00, 0x01];
        for s in ["4200000000:1", "64086.59904:1"] {
            let rd = RouteDistinguisher::from_str(s).unwrap();
            assert_eq!(rd.typ, RouteDistinguisherType::ASN4, "input {s}");
            assert_eq!(rd.val, expect, "input {s}");
            // Display is asdot regardless of the notation used on input.
            assert_eq!(rd.to_string(), "64086.59904:1", "input {s}");
        }
    }

    /// An AS that fits in 16 bits keeps the conventional type-0 encoding, so
    /// existing configs are unaffected by the new type-2 branches.
    #[test]
    fn sixteen_bit_as_still_prefers_type0() {
        let rd = RouteDistinguisher::from_str("65000:3").unwrap();
        assert_eq!(rd.typ, RouteDistinguisherType::ASN);
        // 65536 does not fit a u16 AS, so asplain takes the type-2 branch.
        let rd = RouteDistinguisher::from_str("65536:3").unwrap();
        assert_eq!(rd.typ, RouteDistinguisherType::ASN4);
        assert_eq!(rd.to_string(), "1.0:3");
    }

    /// The dot makes the 4-octet-AS form explicit, so asdot selects type 2 even
    /// when the AS would fit in 16 bits — the only way to spell such an RD.
    #[test]
    fn asdot_selects_type2_even_for_small_as() {
        let rd = RouteDistinguisher::from_str("0.100:1").unwrap();
        assert_eq!(rd.typ, RouteDistinguisherType::ASN4);
        assert_eq!(rd.val, [0x00, 0x00, 0x00, 0x64, 0x00, 0x01]);
    }

    /// An IPv4 RD must not be mistaken for asdot, and a malformed asdot half
    /// must be rejected rather than silently truncated.
    #[test]
    fn ipv4_rd_and_malformed_asdot_are_not_confused() {
        let rd = RouteDistinguisher::from_str("192.168.1.2:51").unwrap();
        assert_eq!(rd.typ, RouteDistinguisherType::IP);
        // 169031 exceeds a 16-bit asdot half.
        assert!(RouteDistinguisher::from_str("169031.1:1").is_err());
        assert!(RouteDistinguisher::from_str("1.2.3:1").is_err());
    }
}
