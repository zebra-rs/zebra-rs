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
///
/// The `flags` octet is decoded by the accessors below. RFC 9574 §4
/// redefines it for EVPN, packing the Assisted Replication Type (T) field
/// and the BM/U Pruned-Flood-List bits alongside the original RFC 6514
/// `L` (Leaf Information Required) bit.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PmsiTunnel {
    pub flags: u8,
    pub tunnel_type: u8,
    pub vni: u32,
    pub endpoint: IpAddr,
}

/// Assisted Replication Type (T) field of the PMSI Tunnel Attribute Flags,
/// RFC 9574 §4. Identifies a node's role in the optimized ingress
/// replication scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AssistedReplicationType {
    /// 0 — Regular Network Virtualization Edge: no AR support, plain
    /// ingress replication (RFC 7432).
    #[default]
    Rnve,
    /// 1 — AR-REPLICATOR: replicates BUM traffic on behalf of AR-LEAF nodes.
    Replicator,
    /// 2 — AR-LEAF: offloads BUM replication to an AR-REPLICATOR.
    Leaf,
    /// 3 — reserved (RFC 9574).
    Reserved,
}

impl From<u8> for AssistedReplicationType {
    fn from(val: u8) -> Self {
        match val & 0x3 {
            0 => Self::Rnve,
            1 => Self::Replicator,
            2 => Self::Leaf,
            _ => Self::Reserved,
        }
    }
}

impl From<AssistedReplicationType> for u8 {
    fn from(val: AssistedReplicationType) -> u8 {
        match val {
            AssistedReplicationType::Rnve => 0,
            AssistedReplicationType::Replicator => 1,
            AssistedReplicationType::Leaf => 2,
            AssistedReplicationType::Reserved => 3,
        }
    }
}

impl PmsiTunnel {
    /// Ingress Replication tunnel type (RFC 6514 / RFC 7432): BUM traffic is
    /// head-end replicated to each remote PE, and the Tunnel Identifier is
    /// the originating PE's IP address.
    pub const TUNNEL_INGRESS_REPLICATION: u8 = 6;

    /// Assisted Replication tunnel type (RFC 9574 §11 IANA allocation):
    /// advertised by an AR-REPLICATOR in its Replicator-AR IMET route; the
    /// Tunnel Identifier / next hop is the replicator's AR-IP.
    pub const TUNNEL_ASSISTED_REPLICATION: u8 = 0x0A;

    /// SR-MPLS P2MP Tree tunnel type (0x0C, IANA PMSI Tunnel Types /
    /// draft-ietf-bess-mvpn-evpn-sr-p2mp). Used to bind EVPN BUM delivery to
    /// an SR-MPLS P2MP / RFC 9524 replication tree. The Tunnel Identifier
    /// carries the tree's <Root, Tree-ID>; decoding it (the identifier is not
    /// a bare PE address) is a follow-up.
    pub const TUNNEL_SR_MPLS_P2MP: u8 = 0x0C;

    /// SRv6 P2MP Tree tunnel type (0x0D, same registry / draft). Binds EVPN
    /// BUM delivery to an SRv6 P2MP / RFC 9524 replication tree; the Tunnel
    /// Identifier carries the replication SID. Decoding is a follow-up.
    pub const TUNNEL_SRV6_P2MP: u8 = 0x0D;

    // PMSI Tunnel Attribute Flags bit layout, redefined for EVPN by
    // RFC 9574 §4 Figure 3. Bits are numbered with bit 0 = most significant
    // (leftmost), per the IANA PMSI Tunnel Attribute Flags registry:
    //
    //   0  1  2  3  4  5  6  7
    // +--+--+--+--+--+--+--+--+
    // |x |E |x |  T  |BM|U |L |
    // +--+--+--+--+--+--+--+--+

    /// E flag — Extension (RFC 7902), bit 1.
    pub const FLAG_E: u8 = 0x40;
    /// Mask of the 2-bit Assisted Replication Type (T) field, bits 3-4.
    pub const FLAG_AR_TYPE_MASK: u8 = 0x18;
    /// Right-shift placing the AR Type field into the low two bits.
    const FLAG_AR_TYPE_SHIFT: u8 = 3;
    /// BM flag — prune this node from the Broadcast/Multicast flood list
    /// (RFC 9574 Pruned-Flood-Lists), bit 5.
    pub const FLAG_BM: u8 = 0x04;
    /// U flag — prune this node from the unknown-unicast flood list, bit 6.
    pub const FLAG_U: u8 = 0x02;
    /// L flag — Leaf Information Required (RFC 6514), bit 7. Set by an
    /// AR-REPLICATOR in selective mode to solicit Leaf A-D routes.
    pub const FLAG_L: u8 = 0x01;

    /// The Assisted Replication Type (T) carried in the Flags field.
    pub fn ar_type(&self) -> AssistedReplicationType {
        ((self.flags & Self::FLAG_AR_TYPE_MASK) >> Self::FLAG_AR_TYPE_SHIFT).into()
    }

    /// Set the Assisted Replication Type (T) field, leaving the other flag
    /// bits untouched.
    pub fn set_ar_type(&mut self, ar_type: AssistedReplicationType) {
        let bits = (u8::from(ar_type) << Self::FLAG_AR_TYPE_SHIFT) & Self::FLAG_AR_TYPE_MASK;
        self.flags = (self.flags & !Self::FLAG_AR_TYPE_MASK) | bits;
    }

    /// Builder form of [`set_ar_type`](Self::set_ar_type).
    pub fn with_ar_type(mut self, ar_type: AssistedReplicationType) -> Self {
        self.set_ar_type(ar_type);
        self
    }

    /// BM flag — node requests pruning from the Broadcast/Multicast flood list.
    pub fn prune_bm(&self) -> bool {
        self.flags & Self::FLAG_BM != 0
    }

    /// U flag — node requests pruning from the unknown-unicast flood list.
    pub fn prune_unknown(&self) -> bool {
        self.flags & Self::FLAG_U != 0
    }

    /// Set or clear the BM (Broadcast/Multicast prune) flag.
    pub fn set_prune_bm(&mut self, on: bool) {
        if on {
            self.flags |= Self::FLAG_BM;
        } else {
            self.flags &= !Self::FLAG_BM;
        }
    }

    /// Set or clear the U (unknown-unicast prune) flag.
    pub fn set_prune_unknown(&mut self, on: bool) {
        if on {
            self.flags |= Self::FLAG_U;
        } else {
            self.flags &= !Self::FLAG_U;
        }
    }

    /// L flag — Leaf Information Required (RFC 6514).
    pub fn leaf_info_required(&self) -> bool {
        self.flags & Self::FLAG_L != 0
    }

    /// Set or clear the L (Leaf Information Required) flag.
    pub fn set_leaf_info_required(&mut self, on: bool) {
        if on {
            self.flags |= Self::FLAG_L;
        } else {
            self.flags &= !Self::FLAG_L;
        }
    }

    /// True when this is an Ingress Replication tunnel (type 6).
    pub fn is_ingress_replication(&self) -> bool {
        self.tunnel_type == Self::TUNNEL_INGRESS_REPLICATION
    }

    /// True when this is an Assisted Replication tunnel (type 0x0A, RFC 9574).
    pub fn is_assisted_replication(&self) -> bool {
        self.tunnel_type == Self::TUNNEL_ASSISTED_REPLICATION
    }

    /// True for an SR P2MP tree P-tunnel — either SR-MPLS (0x0C) or SRv6
    /// (0x0D) — i.e. an RFC 9524 replication tree bound to EVPN BUM.
    pub fn is_sr_p2mp(&self) -> bool {
        matches!(
            self.tunnel_type,
            Self::TUNNEL_SR_MPLS_P2MP | Self::TUNNEL_SRV6_P2MP
        )
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

#[cfg(test)]
mod pmsi_tunnel_tests {
    use super::*;
    use crate::{AttrEmitter, ParseBe};

    fn ir(flags: u8, tunnel_type: u8) -> PmsiTunnel {
        PmsiTunnel {
            flags,
            tunnel_type,
            vni: 100,
            endpoint: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        }
    }

    /// The named flag-bit constants must equal the values dictated by
    /// RFC 9574 §4 Figure 3 (bit 0 = MSB). These are the wire contract.
    #[test]
    fn flag_bit_masks() {
        assert_eq!(PmsiTunnel::FLAG_E, 0x40, "E = bit 1");
        assert_eq!(PmsiTunnel::FLAG_AR_TYPE_MASK, 0x18, "T = bits 3-4");
        assert_eq!(PmsiTunnel::FLAG_BM, 0x04, "BM = bit 5");
        assert_eq!(PmsiTunnel::FLAG_U, 0x02, "U = bit 6");
        assert_eq!(PmsiTunnel::FLAG_L, 0x01, "L = bit 7");
        assert_eq!(PmsiTunnel::TUNNEL_INGRESS_REPLICATION, 6);
        assert_eq!(PmsiTunnel::TUNNEL_ASSISTED_REPLICATION, 0x0A);
    }

    /// Each AR Type encodes to the exact flag-byte value on the wire:
    /// RNVE→0x00, REPLICATOR→0x08, LEAF→0x10, RESERVED→0x18.
    #[test]
    fn ar_type_wire_values() {
        let cases = [
            (AssistedReplicationType::Rnve, 0x00u8),
            (AssistedReplicationType::Replicator, 0x08),
            (AssistedReplicationType::Leaf, 0x10),
            (AssistedReplicationType::Reserved, 0x18),
        ];
        for (ar_type, want) in cases {
            let p = ir(0, PmsiTunnel::TUNNEL_ASSISTED_REPLICATION).with_ar_type(ar_type);
            assert_eq!(p.flags, want, "{ar_type:?} flag byte");
            assert_eq!(p.ar_type(), ar_type, "{ar_type:?} read back");
        }
    }

    /// `u8` ↔ `AssistedReplicationType` is a faithful round trip.
    #[test]
    fn ar_type_u8_roundtrip() {
        for v in 0u8..=3 {
            assert_eq!(u8::from(AssistedReplicationType::from(v)), v);
        }
    }

    /// Setting the AR Type must not disturb the BM/U/L bits, and vice versa.
    #[test]
    fn flag_fields_are_independent() {
        let mut p = ir(0, PmsiTunnel::TUNNEL_ASSISTED_REPLICATION);
        p.set_prune_bm(true);
        p.set_prune_unknown(true);
        p.set_leaf_info_required(true);
        p.set_ar_type(AssistedReplicationType::Leaf);
        assert_eq!(p.ar_type(), AssistedReplicationType::Leaf);
        assert!(p.prune_bm() && p.prune_unknown() && p.leaf_info_required());
        // LEAF (0x10) | BM (0x04) | U (0x02) | L (0x01) = 0x17.
        assert_eq!(p.flags, 0x17);

        // Re-stamping the AR Type leaves the other three bits intact.
        p.set_ar_type(AssistedReplicationType::Rnve);
        assert_eq!(p.flags, 0x07);
        assert!(p.prune_bm() && p.prune_unknown() && p.leaf_info_required());

        // Clearing a prune bit leaves the AR Type alone.
        p.set_ar_type(AssistedReplicationType::Replicator);
        p.set_prune_bm(false);
        assert_eq!(p.ar_type(), AssistedReplicationType::Replicator);
        assert!(!p.prune_bm() && p.prune_unknown());
    }

    #[test]
    fn tunnel_type_predicates() {
        assert!(ir(0, PmsiTunnel::TUNNEL_INGRESS_REPLICATION).is_ingress_replication());
        assert!(!ir(0, PmsiTunnel::TUNNEL_INGRESS_REPLICATION).is_assisted_replication());
        assert!(ir(0, PmsiTunnel::TUNNEL_ASSISTED_REPLICATION).is_assisted_replication());
        assert!(!ir(0, PmsiTunnel::TUNNEL_ASSISTED_REPLICATION).is_ingress_replication());
    }

    /// SR P2MP tree codepoints (RFC 9524 replication trees) and their
    /// predicate. The integer values are the IANA-assigned wire contract.
    #[test]
    fn sr_p2mp_tunnel_types() {
        assert_eq!(PmsiTunnel::TUNNEL_SR_MPLS_P2MP, 0x0C);
        assert_eq!(PmsiTunnel::TUNNEL_SRV6_P2MP, 0x0D);
        assert!(ir(0, PmsiTunnel::TUNNEL_SR_MPLS_P2MP).is_sr_p2mp());
        assert!(ir(0, PmsiTunnel::TUNNEL_SRV6_P2MP).is_sr_p2mp());
        // Ingress and Assisted Replication are not SR P2MP trees.
        assert!(!ir(0, PmsiTunnel::TUNNEL_INGRESS_REPLICATION).is_sr_p2mp());
        assert!(!ir(0, PmsiTunnel::TUNNEL_ASSISTED_REPLICATION).is_sr_p2mp());
    }

    /// A Replicator-AR tunnel with a BM prune flag survives an emit → parse
    /// round trip byte-for-byte, including the decoded role and flags.
    #[test]
    fn emit_parse_roundtrip_ar_replicator() {
        let mut original = ir(0, PmsiTunnel::TUNNEL_ASSISTED_REPLICATION)
            .with_ar_type(AssistedReplicationType::Replicator);
        original.set_prune_bm(true);
        original.vni = 5000;

        let mut buf = BytesMut::new();
        original.emit(&mut buf);
        // flags(1) + type(1) + vni(3) + IPv4(4).
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0x0C, "REPLICATOR (0x08) | BM (0x04)");
        assert_eq!(buf[1], PmsiTunnel::TUNNEL_ASSISTED_REPLICATION);

        let (_, parsed) = PmsiTunnel::parse_be(&buf).expect("parse our own bytes");
        assert_eq!(parsed, original);
        assert_eq!(parsed.ar_type(), AssistedReplicationType::Replicator);
        assert!(parsed.is_assisted_replication());
        assert!(parsed.prune_bm());
        assert!(!parsed.prune_unknown());
    }

    /// The legacy Ingress Replication encoding (flags = 0, type 6) is
    /// unchanged: RNVE role, no prune flags.
    #[test]
    fn ingress_replication_flags_are_zero() {
        let p = ir(0, PmsiTunnel::TUNNEL_INGRESS_REPLICATION);
        assert_eq!(p.ar_type(), AssistedReplicationType::Rnve);
        assert!(!p.prune_bm() && !p.prune_unknown() && !p.leaf_info_required());
    }
}
