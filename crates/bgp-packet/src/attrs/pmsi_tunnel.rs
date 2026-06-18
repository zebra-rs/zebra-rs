use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u24};

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe, u32_u24};

/// PMSI Tunnel Type — the second octet of the PMSI Tunnel Attribute.
///
/// Values are the IANA "P-Multicast Service Interface (PMSI) Tunnel Types"
/// registry. Only [`PmsiTunnelType::IngressReplication`] (6) is realized by
/// the dataplane today (VXLAN head-end replication); the other variants are
/// carried verbatim so an RFC 9572 segmentation point can relay/transit a
/// tunnel type it does not itself terminate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PmsiTunnelType {
    /// 0 — No tunnel information present.
    NoTunnelInfo,
    /// 1 — RSVP-TE P2MP LSP.
    RsvpTeP2mp,
    /// 2 — mLDP P2MP LSP.
    LdpP2mp,
    /// 3 — PIM-SSM Tree.
    PimSsm,
    /// 4 — PIM-SM Tree.
    PimSm,
    /// 5 — BIDIR-PIM Tree.
    BidirPim,
    /// 6 — Ingress Replication (EVPN VXLAN head-end replication).
    IngressReplication,
    /// 7 — mLDP MP2MP LSP.
    LdpMp2mp,
    /// 11 — BIER (RFC 8556).
    Bier,
    /// Any other / future codepoint, preserved verbatim.
    Unknown(u8),
}

impl From<u8> for PmsiTunnelType {
    fn from(val: u8) -> Self {
        use PmsiTunnelType::*;
        match val {
            0 => NoTunnelInfo,
            1 => RsvpTeP2mp,
            2 => LdpP2mp,
            3 => PimSsm,
            4 => PimSm,
            5 => BidirPim,
            6 => IngressReplication,
            7 => LdpMp2mp,
            11 => Bier,
            other => Unknown(other),
        }
    }
}

impl From<PmsiTunnelType> for u8 {
    fn from(val: PmsiTunnelType) -> u8 {
        use PmsiTunnelType::*;
        match val {
            NoTunnelInfo => 0,
            RsvpTeP2mp => 1,
            LdpP2mp => 2,
            PimSsm => 3,
            PimSm => 4,
            BidirPim => 5,
            IngressReplication => 6,
            LdpMp2mp => 7,
            Bier => 11,
            Unknown(other) => other,
        }
    }
}

impl fmt::Display for PmsiTunnelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PmsiTunnelType::*;
        let s = match self {
            NoTunnelInfo => "no-tunnel-info",
            RsvpTeP2mp => "rsvp-te-p2mp",
            LdpP2mp => "mldp-p2mp",
            PimSsm => "pim-ssm",
            PimSm => "pim-sm",
            BidirPim => "bidir-pim",
            IngressReplication => "ingress-replication",
            LdpMp2mp => "mldp-mp2mp",
            Bier => "bier",
            Unknown(v) => return write!(f, "unknown({v})"),
        };
        f.write_str(s)
    }
}

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
    pub tunnel_type: PmsiTunnelType,
    pub vni: u32,
    pub endpoint: IpAddr,
}

impl PmsiTunnel {
    /// Leaf-Information-Required (L) flag — the low-order bit of the Flags
    /// octet (RFC 6514 §5). When set, downstream PEs/RBRs must originate a
    /// Leaf A-D route (EVPN route type 11) so the tunnel root can build an
    /// explicit leaf set.
    pub const FLAG_LEAF_INFO_REQUIRED: u8 = 0x01;

    /// True when the Leaf-Information-Required (L) flag is set.
    pub fn leaf_info_required(&self) -> bool {
        self.flags & Self::FLAG_LEAF_INFO_REQUIRED != 0
    }

    /// Set or clear the Leaf-Information-Required (L) flag.
    pub fn set_leaf_info_required(&mut self, on: bool) {
        if on {
            self.flags |= Self::FLAG_LEAF_INFO_REQUIRED;
        } else {
            self.flags &= !Self::FLAG_LEAF_INFO_REQUIRED;
        }
    }
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
                tunnel_type: tunnel_type.into(),
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
        buf.put_u8(u8::from(self.tunnel_type));
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

#[cfg(test)]
mod pmsi_tunnel_tests {
    use super::*;

    /// Every known codepoint round-trips u8 → enum → u8, and unknowns are
    /// preserved verbatim (so a segmentation point can relay them).
    #[test]
    fn tunnel_type_u8_roundtrip() {
        for v in 0u8..=12 {
            assert_eq!(u8::from(PmsiTunnelType::from(v)), v, "codepoint {v}");
        }
        // A reserved/future value survives as Unknown.
        assert_eq!(PmsiTunnelType::from(200), PmsiTunnelType::Unknown(200));
        assert_eq!(u8::from(PmsiTunnelType::Unknown(200)), 200);
        // 6 is the one the dataplane acts on.
        assert_eq!(PmsiTunnelType::from(6), PmsiTunnelType::IngressReplication);
    }

    /// The Leaf-Information-Required (L) flag is the low-order Flags bit and
    /// toggles independently of the other bits.
    #[test]
    fn leaf_info_required_flag() {
        let mut pt = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnelType::IngressReplication,
            vni: 100,
            endpoint: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        assert!(!pt.leaf_info_required());
        pt.set_leaf_info_required(true);
        assert_eq!(pt.flags, 0x01);
        assert!(pt.leaf_info_required());
        // Set an unrelated high bit, then clear only L — the high bit stays.
        pt.flags |= 0x80;
        pt.set_leaf_info_required(false);
        assert_eq!(pt.flags, 0x80);
        assert!(!pt.leaf_info_required());
    }

    /// Emit → parse round-trip over the full PTA wire layout (IR, IPv4
    /// endpoint), confirming the enum survives the wire untouched.
    #[test]
    fn emit_then_parse_roundtrip_v4() {
        let original = PmsiTunnel {
            flags: PmsiTunnel::FLAG_LEAF_INFO_REQUIRED,
            tunnel_type: PmsiTunnelType::IngressReplication,
            vni: 5000,
            endpoint: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let mut buf = BytesMut::new();
        original.emit(&mut buf);
        // Flags(1) + Type(1) + VNI(3) + IPv4(4) = 9 octets.
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0x01, "L flag");
        assert_eq!(buf[1], 6, "tunnel type 6 = ingress replication");
        assert_eq!(&buf[2..5], &[0x00, 0x13, 0x88], "VNI 5000 in 24 bits");

        let (_, parsed) = PmsiTunnel::parse_be(&buf).expect("parse what we emit");
        assert_eq!(parsed.tunnel_type, original.tunnel_type);
        assert!(parsed.leaf_info_required());
        assert_eq!(parsed.vni, original.vni);
        assert_eq!(parsed.endpoint, original.endpoint);
    }
}
