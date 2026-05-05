use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u24};

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe, u32_u24};

/// PMSI Tunnel Attribute (RFC 6514 §5).
///
/// Wire layout:
/// ```text
///   Flags         (1 octet)
///   Tunnel Type   (1 octet)
///   MPLS Label    (3 octets, low 24 bits — the VXLAN VNI for EVPN
///                  per RFC 8365 §5.1.3)
///   Tunnel Identifier — variable per Tunnel Type. For Ingress
///                       Replication (type 6) it is the local PE's
///                       IP address: 4 octets for IPv4, 16 for IPv6.
///                       Family is implicit from the slice length;
///                       the BGP attribute header carries the
///                       overall length.
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PmsiTunnel {
    pub flags: u8,
    pub tunnel_type: u8,
    pub vni: u32,
    pub endpoint: IpAddr,
}

impl ParseBe<PmsiTunnel> for PmsiTunnel {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, tunnel_type) = be_u8(input)?;
        let (input, vni) = be_u24(input)?;
        let endpoint = match input.len() {
            4 => {
                let (_, bytes) = take(4usize)(input)?;
                IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            }
            16 => {
                let (_, bytes) = take(16usize)(input)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::LengthValue,
                )));
            }
        };
        Ok((
            &input[input.len()..],
            PmsiTunnel {
                flags,
                tunnel_type,
                vni,
                endpoint,
            },
        ))
    }
}

impl AttrEmitter for PmsiTunnel {
    fn attr_type(&self) -> AttrType {
        AttrType::PmsiTunnel
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true).with_transitive(true)
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.tunnel_type);
        buf.put(&u32_u24(self.vni)[..]);
        match self.endpoint {
            IpAddr::V4(v4) => buf.put(&v4.octets()[..]),
            IpAddr::V6(v6) => buf.put(&v6.octets()[..]),
        }
    }
}

impl fmt::Display for PmsiTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Flag: {}, Tunnel Type: {}, VNI: {}, Endpoint: {}",
            self.flags, self.tunnel_type, self.vni, self.endpoint,
        )
    }
}

impl fmt::Debug for PmsiTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " PMSI Tunnel; {}", self)
    }
}
