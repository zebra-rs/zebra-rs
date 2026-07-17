use bytes::{BufMut, BytesMut};
use nom_derive::NomBE;
use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use crate::ExtCommunitySubType;

use super::ext_ipv6_com_token::{Token, tokenizer};

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtIpv6Community(pub Vec<ExtIpv6CommunityValue>);

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtIpv6CommunityValue {
    pub high_type: u8,
    pub low_type: u8,
    pub val: [u8; 18],
}

#[derive(PartialEq)]
enum State {
    Unspec,
    Rt,
    Soo,
}

impl ExtIpv6CommunityValue {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.high_type);
        buf.put_u8(self.low_type);
        buf.put(&self.val[..]);
    }
}

use ExtCommunitySubType::*;

fn sub_type_str(sub_type: u8) -> &'static str {
    match sub_type {
        x if x == RouteTarget as u8 => "rt",
        x if x == RouteOrigin as u8 => "soo",
        _ => "unknown",
    }
}

impl fmt::Display for ExtIpv6CommunityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // RFC 5701 §2: type, sub-type, a 16-octet IPv6 Global Administrator and
        // a 2-octet Local Administrator — 20 octets, the layout `new()` writes.
        // This previously read the 8-octet AS/IPv4-specific layouts instead
        // (`val[0..2]` as an ASN, or `val[0..4]` as an IPv4 address), branching
        // on `high_type == 0`, which for this attribute distinguishes
        // transitive from non-transitive rather than naming an address family.
        // It rendered the first octets of the IPv6 address as an unrelated
        // number and never showed the Local Administrator at all.
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.val[0..16]);
        let ip = Ipv6Addr::from(addr);
        let local = u16::from_be_bytes([self.val[16], self.val[17]]);
        write!(f, "{} {ip}:{local}", sub_type_str(self.low_type))
    }
}

impl ExtIpv6CommunityValue {
    pub fn new(addr: Ipv6Addr, val: u16) -> Self {
        let mut com = Self {
            high_type: 0x00,
            low_type: RouteTarget as u8,
            val: [0u8; 18],
        };
        com.val[0..16].copy_from_slice(&addr.octets());
        // Big-endian: BGP is a network-byte-order protocol, and `encode()`
        // copies `val` to the wire verbatim. `to_ne_bytes` byte-swapped the
        // Local Administrator on every little-endian host, so a peer decoded
        // e.g. 100 as 25600.
        com.val[16..18].copy_from_slice(val.to_be_bytes().as_slice());
        com
    }
}

impl fmt::Display for ExtIpv6Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .0
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    /// The Local Administrator must reach the wire big-endian. Regression:
    /// `new()` used `to_ne_bytes`, so on any little-endian host the two octets
    /// were swapped and a peer read 100 as 25600.
    #[test]
    fn local_admin_is_big_endian_on_the_wire() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let com = ExtIpv6CommunityValue::new(addr, 100);
        assert_eq!(
            &com.val[16..18],
            &100u16.to_be_bytes(),
            "Local Administrator is network byte order"
        );

        // RFC 5701 §2: 20 octets — type, sub-type, 16-octet IPv6, 2-octet local.
        let mut buf = BytesMut::new();
        com.encode(&mut buf);
        assert_eq!(buf.len(), 20);
        assert_eq!(&buf[2..18], &addr.octets(), "Global Administrator");
        assert_eq!(&buf[18..20], &[0x00, 0x64], "Local Administrator = 100");
    }

    /// Display renders the RFC 5701 layout `new()` actually writes. Regression:
    /// it read the 8-octet AS/IPv4-specific layouts, so a value built by `new()`
    /// printed a number made of the IPv6 address's leading octets and never
    /// showed the Local Administrator.
    #[test]
    fn display_uses_the_rfc5701_layout() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut com = ExtIpv6CommunityValue::new(addr, 100);
        com.low_type = 0x02;
        assert_eq!(com.to_string(), "rt 2001:db8::1:100");

        com.low_type = 0x03;
        assert_eq!(com.to_string(), "soo 2001:db8::1:100");
    }

    /// `from_str` round-trips through the tokenizer for both keywords.
    #[test]
    fn from_str_round_trips() {
        let ecom: ExtIpv6Community = "rt [2001:db8::1]:100".parse().unwrap();
        assert_eq!(ecom.0.len(), 1);
        assert_eq!(ecom.0[0].low_type, 0x02);
        assert_eq!(ecom.0[0].to_string(), "rt 2001:db8::1:100");

        let ecom: ExtIpv6Community = "soo [2001:db8::1]:100".parse().unwrap();
        assert_eq!(ecom.0[0].low_type, 0x03);
    }

    /// Malformed input returns the declared `Err(())`. Regression: `from_str`
    /// called `tokenizer(..).unwrap()`, panicking the thread on any tokenizer
    /// error instead of honouring the `FromStr` contract.
    #[test]
    fn from_str_rejects_malformed_without_panicking() {
        for s in [
            "@@bad@@",               // unexpected character
            "bogus [2001:db8::1]:1", // unknown keyword
            "rt [zzzz]:1",           // unparseable address
            "rt [2001:db8::1]",      // no local administrator
            "[2001:db8::1]:1",       // value with no rt/soo keyword
        ] {
            assert!(
                s.parse::<ExtIpv6Community>().is_err(),
                "must return Err, not panic: {s:?}"
            );
        }
        // A bare keyword with no value tokenizes cleanly and yields an empty
        // list rather than an error — pre-existing behaviour, pinned here so the
        // distinction from the malformed cases above is deliberate.
        let ecom: ExtIpv6Community = "rt".parse().expect("bare keyword is not an error");
        assert!(ecom.0.is_empty());
    }
}

impl FromStr for ExtIpv6Community {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ecom = ExtIpv6Community::default();
        // Return the declared `Err(())` rather than panicking: the tokenizer
        // rejects an unknown keyword, an unexpected character or a malformed
        // address, all of which are reachable from operator input. `ExtCommunity`
        // already handles the same call this way.
        let tokens = tokenizer(String::from(s)).map_err(|_| ())?;
        let mut state = State::Unspec;

        for token in tokens.into_iter() {
            match token {
                Token::Rd(rd, num) => {
                    let mut val = ExtIpv6CommunityValue::new(rd, num);
                    match state {
                        State::Unspec => {
                            return Err(());
                        }
                        State::Rt => {
                            val.low_type = 0x02;
                        }
                        State::Soo => {
                            val.low_type = 0x03;
                        }
                    }
                    ecom.0.push(val);
                }
                Token::Rt => {
                    state = State::Rt;
                }
                Token::Soo => {
                    state = State::Soo;
                }
            }
        }
        Ok(ecom)
    }
}
