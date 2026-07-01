use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32, be_u128};

use crate::Afi;

/// SR Policy NLRI (RFC 9830 §2.1).
///
/// ```text
///   +------------------+
///   | NLRI Length      |  1 octet  — length in BITS: 96 (IPv4) / 192 (IPv6)
///   +------------------+
///   | Distinguisher    |  4 octets
///   +------------------+
///   | Color            |  4 octets
///   +------------------+
///   | Endpoint         |  4 octets (AFI 1) or 16 octets (AFI 2)
///   +------------------+
/// ```
///
/// The endpoint address family comes from the enclosing
/// MP_REACH/MP_UNREACH header AFI, not from the NLRI itself — the same
/// way BGP MUP (draft-ietf-bess-mup-safi) threads the outer AFI down to
/// `MupRoute::parse`. The candidate-path content (preference, binding
/// SID, segment lists, …) rides in the Tunnel Encapsulation attribute
/// (Tunnel-Type 15), decoded separately.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SrPolicyNlri {
    /// Add-Path identifier (0 when Add-Path is not negotiated).
    pub id: u32,
    /// Distinguisher — makes the NLRI unique within a `<color,
    /// endpoint>` tuple; maps to the candidate-path discriminator
    /// (RFC 9256 §2.5).
    pub distinguisher: u32,
    /// Color — non-zero on the wire (RFC 9256 §2.1); validated by the
    /// consumer, not the codec.
    pub color: u32,
    /// Endpoint — IPv4 or IPv6 per the header AFI; may be the null
    /// address (`0.0.0.0` / `::`) for a color-only policy.
    pub endpoint: IpAddr,
}

/// NLRI Length field value (in bits) for an IPv4 endpoint: (4 + 4 + 4) * 8.
const NLRI_LEN_BITS_V4: u8 = 96;
/// NLRI Length field value (in bits) for an IPv6 endpoint: (4 + 4 + 16) * 8.
const NLRI_LEN_BITS_V6: u8 = 192;

impl SrPolicyNlri {
    /// Parse one SR Policy NLRI. `afi` (from the MP header) selects the
    /// endpoint width and the value the 1-octet Length field must carry
    /// — RFC 9830 §2.1 mandates 96 for IPv4 and 192 for IPv6; any other
    /// value is malformed.
    pub fn parse(input: &[u8], add_path: bool, afi: Afi) -> IResult<&[u8], Self> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };
        let (input, len) = be_u8(input)?;
        let (input, distinguisher) = be_u32(input)?;
        let (input, color) = be_u32(input)?;
        let (input, endpoint) = match afi {
            Afi::Ip => {
                if len != NLRI_LEN_BITS_V4 {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
                }
                let (input, addr) = be_u32(input)?;
                (input, IpAddr::V4(Ipv4Addr::from(addr)))
            }
            Afi::Ip6 => {
                if len != NLRI_LEN_BITS_V6 {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
                }
                let (input, addr) = be_u128(input)?;
                (input, IpAddr::V6(Ipv6Addr::from(addr)))
            }
            _ => return Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf))),
        };
        Ok((
            input,
            SrPolicyNlri {
                id,
                distinguisher,
                color,
                endpoint,
            },
        ))
    }

    /// Serialize this NLRI. The Length byte and endpoint width are
    /// derived from the endpoint variant; the Add-Path id is prefixed
    /// only when `add_path` is set.
    pub fn nlri_emit(&self, buf: &mut BytesMut, add_path: bool) {
        if add_path {
            buf.put_u32(self.id);
        }
        match self.endpoint {
            IpAddr::V4(v4) => {
                buf.put_u8(NLRI_LEN_BITS_V4);
                buf.put_u32(self.distinguisher);
                buf.put_u32(self.color);
                buf.put(&v4.octets()[..]);
            }
            IpAddr::V6(v6) => {
                buf.put_u8(NLRI_LEN_BITS_V6);
                buf.put_u32(self.distinguisher);
                buf.put_u32(self.color);
                buf.put(&v6.octets()[..]);
            }
        }
    }

    /// The AFI implied by the endpoint address family.
    pub fn afi(&self) -> Afi {
        match self.endpoint {
            IpAddr::V4(_) => Afi::Ip,
            IpAddr::V6(_) => Afi::Ip6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_bytes(len: u8, dist: u32, color: u32, ep: [u8; 4]) -> Vec<u8> {
        let mut v = vec![len];
        v.extend_from_slice(&dist.to_be_bytes());
        v.extend_from_slice(&color.to_be_bytes());
        v.extend_from_slice(&ep);
        v
    }

    #[test]
    fn ipv4_nlri_parses() {
        let bytes = v4_bytes(96, 1, 100, [10, 0, 0, 9]);
        let (rest, nlri) = SrPolicyNlri::parse(&bytes, false, Afi::Ip).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(nlri.distinguisher, 1);
        assert_eq!(nlri.color, 100);
        assert_eq!(nlri.endpoint, IpAddr::V4("10.0.0.9".parse().unwrap()));
        assert_eq!(nlri.afi(), Afi::Ip);
    }

    #[test]
    fn ipv6_nlri_parses() {
        let ep: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let mut bytes = vec![192u8];
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&200u32.to_be_bytes());
        bytes.extend_from_slice(&ep.octets());
        let (rest, nlri) = SrPolicyNlri::parse(&bytes, false, Afi::Ip6).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(nlri.distinguisher, 7);
        assert_eq!(nlri.color, 200);
        assert_eq!(nlri.endpoint, IpAddr::V6(ep));
        assert_eq!(nlri.afi(), Afi::Ip6);
    }

    #[test]
    fn ipv4_round_trips_through_emit() {
        let nlri = SrPolicyNlri {
            id: 0,
            distinguisher: 42,
            color: 12345,
            endpoint: IpAddr::V4("192.0.2.1".parse().unwrap()),
        };
        let mut buf = BytesMut::new();
        nlri.nlri_emit(&mut buf, false);
        let (rest, back) = SrPolicyNlri::parse(&buf, false, Afi::Ip).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(back, nlri);
    }

    #[test]
    fn ipv6_round_trips_through_emit() {
        let nlri = SrPolicyNlri {
            id: 0,
            distinguisher: 1,
            color: 1,
            endpoint: IpAddr::V6("fc00::1".parse().unwrap()),
        };
        let mut buf = BytesMut::new();
        nlri.nlri_emit(&mut buf, false);
        let (rest, back) = SrPolicyNlri::parse(&buf, false, Afi::Ip6).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(back, nlri);
    }

    #[test]
    fn add_path_id_round_trips() {
        let nlri = SrPolicyNlri {
            id: 0xdead_beef,
            distinguisher: 9,
            color: 3,
            endpoint: IpAddr::V4("10.1.2.3".parse().unwrap()),
        };
        let mut buf = BytesMut::new();
        nlri.nlri_emit(&mut buf, true);
        let (_rest, back) = SrPolicyNlri::parse(&buf, true, Afi::Ip).expect("parse");
        assert_eq!(back.id, 0xdead_beef);
        assert_eq!(back, nlri);
    }

    #[test]
    fn ipv4_rejects_wrong_length_field() {
        // 192 is the IPv6 length; invalid for an IPv4 endpoint.
        let bytes = v4_bytes(192, 1, 100, [10, 0, 0, 9]);
        assert!(SrPolicyNlri::parse(&bytes, false, Afi::Ip).is_err());
    }

    #[test]
    fn ipv6_rejects_wrong_length_field() {
        let ep: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let mut bytes = vec![96u8]; // IPv4 length, invalid for IPv6
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&ep.octets());
        assert!(SrPolicyNlri::parse(&bytes, false, Afi::Ip6).is_err());
    }

    #[test]
    fn unknown_afi_rejected() {
        let bytes = v4_bytes(96, 1, 100, [10, 0, 0, 9]);
        assert!(SrPolicyNlri::parse(&bytes, false, Afi::L2vpn).is_err());
    }

    #[test]
    fn color_only_null_endpoint_parses() {
        // RFC 9256 §8.8.1 color-only: endpoint may be the null address.
        let bytes = v4_bytes(96, 0, 100, [0, 0, 0, 0]);
        let (_rest, nlri) = SrPolicyNlri::parse(&bytes, false, Afi::Ip).expect("parse");
        assert_eq!(nlri.endpoint, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
}
