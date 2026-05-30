use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16, be_u64};
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

// BGP Link-State NLRI codec (RFC 9552, obsoletes RFC 7752).
//
// BGP-LS distributes the IGP link-state topology in BGP using AFI 16388 and
// SAFI 71 (non-VPN) or SAFI 72 (VPN, not yet implemented here). Each
// Link-State NLRI is a TLV-encoded description of a Node, Link, or Prefix.
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |            NLRI Type           |     Total NLRI Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   //                  Link-State NLRI (variable)                 //
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The NLRI body (after the Total NLRI Length) carries:
//   Protocol-ID (1 octet), Identifier (8 octets), then descriptor TLVs.
//
// This module implements the non-VPN encoding only (no 8-octet Route
// Distinguisher prefix). VPN (SAFI 72) is intentionally deferred.

// ===== NLRI Type codes (RFC 9552 Section 5.2) =====
pub const LS_NLRI_NODE: u16 = 1;
pub const LS_NLRI_LINK: u16 = 2;
pub const LS_NLRI_IPV4_PREFIX: u16 = 3;
pub const LS_NLRI_IPV6_PREFIX: u16 = 4;

// ===== Node Descriptor container TLVs =====
pub const LS_TLV_LOCAL_NODE_DESC: u16 = 256;
pub const LS_TLV_REMOTE_NODE_DESC: u16 = 257;

// ===== Node Descriptor Sub-TLVs (RFC 9552 Section 5.2.1.4) =====
pub const LS_SUB_AUTONOMOUS_SYSTEM: u16 = 512;
pub const LS_SUB_BGP_LS_IDENTIFIER: u16 = 513;
pub const LS_SUB_OSPF_AREA_ID: u16 = 514;
pub const LS_SUB_IGP_ROUTER_ID: u16 = 515;
pub const LS_SUB_BGP_ROUTER_ID: u16 = 516; // RFC 9086 (EPE)
pub const LS_SUB_MEMBER_AS: u16 = 517; // RFC 9086 (EPE)

// ===== Link Descriptor TLVs (RFC 9552 Section 5.2.2) =====
pub const LS_TLV_LINK_LOCAL_REMOTE_ID: u16 = 258;
pub const LS_TLV_IPV4_INTERFACE_ADDR: u16 = 259;
pub const LS_TLV_IPV4_NEIGHBOR_ADDR: u16 = 260;
pub const LS_TLV_IPV6_INTERFACE_ADDR: u16 = 261;
pub const LS_TLV_IPV6_NEIGHBOR_ADDR: u16 = 262;
// Multi-Topology Identifier (263) is shared by Link and Prefix descriptors.
pub const LS_TLV_MULTI_TOPOLOGY_ID: u16 = 263;

// ===== Prefix Descriptor TLVs (RFC 9552 Section 5.2.3) =====
pub const LS_TLV_OSPF_ROUTE_TYPE: u16 = 264;
pub const LS_TLV_IP_REACHABILITY: u16 = 265;

// ----------------------------------------------------------------------------
// Protocol-ID
// ----------------------------------------------------------------------------

/// BGP-LS Protocol-ID (RFC 9552 Table 1). Identifies the IGP (and level for
/// IS-IS) that sourced the link-state object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum LsProtocolId {
    IsisL1,
    IsisL2,
    Ospfv2,
    Direct,
    Static,
    Ospfv3,
    Unknown(u8),
}

impl From<u8> for LsProtocolId {
    fn from(v: u8) -> Self {
        match v {
            1 => LsProtocolId::IsisL1,
            2 => LsProtocolId::IsisL2,
            3 => LsProtocolId::Ospfv2,
            4 => LsProtocolId::Direct,
            5 => LsProtocolId::Static,
            6 => LsProtocolId::Ospfv3,
            o => LsProtocolId::Unknown(o),
        }
    }
}

impl From<LsProtocolId> for u8 {
    fn from(p: LsProtocolId) -> Self {
        match p {
            LsProtocolId::IsisL1 => 1,
            LsProtocolId::IsisL2 => 2,
            LsProtocolId::Ospfv2 => 3,
            LsProtocolId::Direct => 4,
            LsProtocolId::Static => 5,
            LsProtocolId::Ospfv3 => 6,
            LsProtocolId::Unknown(o) => o,
        }
    }
}

// ----------------------------------------------------------------------------
// Descriptor sub-TLVs
// ----------------------------------------------------------------------------

/// A single Node Descriptor sub-TLV. Unknown/odd-length codepoints are
/// preserved verbatim so the NLRI round-trips and can be reflected unchanged.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum LsNodeDescSub {
    AutonomousSystem(u32),
    BgpLsIdentifier(u32),
    OspfAreaId(u32),
    /// IGP Router-ID. Variable length: 6 octets (IS-IS System-ID), 7 octets
    /// (IS-IS pseudonode), 4 octets (OSPF Router-ID), 8 octets (OSPF
    /// pseudonode). Stored verbatim.
    IgpRouterId(Vec<u8>),
    BgpRouterId(Ipv4Addr),
    MemberAs(u32),
    Unknown {
        typ: u16,
        value: Vec<u8>,
    },
}

impl LsNodeDescSub {
    fn from_tlv(typ: u16, val: &[u8]) -> Self {
        match typ {
            LS_SUB_AUTONOMOUS_SYSTEM if val.len() == 4 => {
                LsNodeDescSub::AutonomousSystem(be32(val))
            }
            LS_SUB_BGP_LS_IDENTIFIER if val.len() == 4 => LsNodeDescSub::BgpLsIdentifier(be32(val)),
            LS_SUB_OSPF_AREA_ID if val.len() == 4 => LsNodeDescSub::OspfAreaId(be32(val)),
            LS_SUB_IGP_ROUTER_ID => LsNodeDescSub::IgpRouterId(val.to_vec()),
            LS_SUB_BGP_ROUTER_ID if val.len() == 4 => LsNodeDescSub::BgpRouterId(be_ipv4(val)),
            LS_SUB_MEMBER_AS if val.len() == 4 => LsNodeDescSub::MemberAs(be32(val)),
            _ => LsNodeDescSub::Unknown {
                typ,
                value: val.to_vec(),
            },
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        match self {
            LsNodeDescSub::AutonomousSystem(v) => emit_tlv_u32(buf, LS_SUB_AUTONOMOUS_SYSTEM, *v),
            LsNodeDescSub::BgpLsIdentifier(v) => emit_tlv_u32(buf, LS_SUB_BGP_LS_IDENTIFIER, *v),
            LsNodeDescSub::OspfAreaId(v) => emit_tlv_u32(buf, LS_SUB_OSPF_AREA_ID, *v),
            LsNodeDescSub::IgpRouterId(v) => emit_tlv(buf, LS_SUB_IGP_ROUTER_ID, v),
            LsNodeDescSub::BgpRouterId(a) => emit_tlv(buf, LS_SUB_BGP_ROUTER_ID, &a.octets()),
            LsNodeDescSub::MemberAs(v) => emit_tlv_u32(buf, LS_SUB_MEMBER_AS, *v),
            LsNodeDescSub::Unknown { typ, value } => emit_tlv(buf, *typ, value),
        }
    }
}

/// A Node Descriptor (the set of sub-TLVs inside a Local/Remote Node
/// Descriptors container TLV, type 256/257).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct LsNodeDescriptor {
    pub subs: Vec<LsNodeDescSub>,
}

impl LsNodeDescriptor {
    fn parse(value: &[u8]) -> IResult<&[u8], Self> {
        let mut subs = Vec::new();
        let mut rest = value;
        while !rest.is_empty() {
            let (next, (typ, val)) = parse_raw_tlv(rest)?;
            subs.push(LsNodeDescSub::from_tlv(typ, val));
            rest = next;
        }
        Ok((rest, LsNodeDescriptor { subs }))
    }

    fn emit(&self, buf: &mut BytesMut, container_typ: u16) {
        let mut inner = BytesMut::new();
        for sub in &self.subs {
            sub.emit(&mut inner);
        }
        buf.put_u16(container_typ);
        buf.put_u16(inner.len() as u16);
        buf.put_slice(&inner);
    }
}

/// A Link Descriptor TLV (RFC 9552 Section 5.2.2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum LsLinkDescriptor {
    LinkLocalRemoteId {
        local: u32,
        remote: u32,
    },
    Ipv4InterfaceAddr(Ipv4Addr),
    Ipv4NeighborAddr(Ipv4Addr),
    Ipv6InterfaceAddr(Ipv6Addr),
    Ipv6NeighborAddr(Ipv6Addr),
    /// Multi-Topology Identifier (16-bit value; high 4 bits reserved).
    MultiTopologyId(u16),
    Unknown {
        typ: u16,
        value: Vec<u8>,
    },
}

impl LsLinkDescriptor {
    fn from_tlv(typ: u16, val: &[u8]) -> Self {
        match typ {
            LS_TLV_LINK_LOCAL_REMOTE_ID if val.len() == 8 => LsLinkDescriptor::LinkLocalRemoteId {
                local: be32(&val[0..4]),
                remote: be32(&val[4..8]),
            },
            LS_TLV_IPV4_INTERFACE_ADDR if val.len() == 4 => {
                LsLinkDescriptor::Ipv4InterfaceAddr(be_ipv4(val))
            }
            LS_TLV_IPV4_NEIGHBOR_ADDR if val.len() == 4 => {
                LsLinkDescriptor::Ipv4NeighborAddr(be_ipv4(val))
            }
            LS_TLV_IPV6_INTERFACE_ADDR if val.len() == 16 => {
                LsLinkDescriptor::Ipv6InterfaceAddr(be_ipv6(val))
            }
            LS_TLV_IPV6_NEIGHBOR_ADDR if val.len() == 16 => {
                LsLinkDescriptor::Ipv6NeighborAddr(be_ipv6(val))
            }
            LS_TLV_MULTI_TOPOLOGY_ID if val.len() == 2 => {
                LsLinkDescriptor::MultiTopologyId(be16(val))
            }
            _ => LsLinkDescriptor::Unknown {
                typ,
                value: val.to_vec(),
            },
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        match self {
            LsLinkDescriptor::LinkLocalRemoteId { local, remote } => {
                buf.put_u16(LS_TLV_LINK_LOCAL_REMOTE_ID);
                buf.put_u16(8);
                buf.put_u32(*local);
                buf.put_u32(*remote);
            }
            LsLinkDescriptor::Ipv4InterfaceAddr(a) => {
                emit_tlv(buf, LS_TLV_IPV4_INTERFACE_ADDR, &a.octets())
            }
            LsLinkDescriptor::Ipv4NeighborAddr(a) => {
                emit_tlv(buf, LS_TLV_IPV4_NEIGHBOR_ADDR, &a.octets())
            }
            LsLinkDescriptor::Ipv6InterfaceAddr(a) => {
                emit_tlv(buf, LS_TLV_IPV6_INTERFACE_ADDR, &a.octets())
            }
            LsLinkDescriptor::Ipv6NeighborAddr(a) => {
                emit_tlv(buf, LS_TLV_IPV6_NEIGHBOR_ADDR, &a.octets())
            }
            LsLinkDescriptor::MultiTopologyId(v) => {
                buf.put_u16(LS_TLV_MULTI_TOPOLOGY_ID);
                buf.put_u16(2);
                buf.put_u16(*v);
            }
            LsLinkDescriptor::Unknown { typ, value } => emit_tlv(buf, *typ, value),
        }
    }
}

/// A Prefix Descriptor TLV (RFC 9552 Section 5.2.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum LsPrefixDescriptor {
    MultiTopologyId(u16),
    OspfRouteType(u8),
    /// IP Reachability Information: prefix length (in bits) plus the minimum
    /// number of octets needed to carry the prefix.
    IpReachability {
        prefix_len: u8,
        prefix: Vec<u8>,
    },
    Unknown {
        typ: u16,
        value: Vec<u8>,
    },
}

impl LsPrefixDescriptor {
    fn from_tlv(typ: u16, val: &[u8]) -> Self {
        match typ {
            LS_TLV_MULTI_TOPOLOGY_ID if val.len() == 2 => {
                LsPrefixDescriptor::MultiTopologyId(be16(val))
            }
            LS_TLV_OSPF_ROUTE_TYPE if val.len() == 1 => LsPrefixDescriptor::OspfRouteType(val[0]),
            LS_TLV_IP_REACHABILITY if !val.is_empty() => LsPrefixDescriptor::IpReachability {
                prefix_len: val[0],
                prefix: val[1..].to_vec(),
            },
            _ => LsPrefixDescriptor::Unknown {
                typ,
                value: val.to_vec(),
            },
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        match self {
            LsPrefixDescriptor::MultiTopologyId(v) => {
                buf.put_u16(LS_TLV_MULTI_TOPOLOGY_ID);
                buf.put_u16(2);
                buf.put_u16(*v);
            }
            LsPrefixDescriptor::OspfRouteType(v) => {
                buf.put_u16(LS_TLV_OSPF_ROUTE_TYPE);
                buf.put_u16(1);
                buf.put_u8(*v);
            }
            LsPrefixDescriptor::IpReachability { prefix_len, prefix } => {
                buf.put_u16(LS_TLV_IP_REACHABILITY);
                buf.put_u16((1 + prefix.len()) as u16);
                buf.put_u8(*prefix_len);
                buf.put_slice(prefix);
            }
            LsPrefixDescriptor::Unknown { typ, value } => emit_tlv(buf, *typ, value),
        }
    }
}

// ----------------------------------------------------------------------------
// NLRI types
// ----------------------------------------------------------------------------

/// Node NLRI (RFC 9552 Section 5.2): a single Local Node Descriptor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct LsNodeNlri {
    pub protocol_id: LsProtocolId,
    pub identifier: u64,
    pub local_node: LsNodeDescriptor,
}

/// Link NLRI (RFC 9552 Section 5.2): Local + Remote Node Descriptors plus
/// Link Descriptors.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct LsLinkNlri {
    pub protocol_id: LsProtocolId,
    pub identifier: u64,
    pub local_node: LsNodeDescriptor,
    pub remote_node: LsNodeDescriptor,
    pub link_descs: Vec<LsLinkDescriptor>,
}

/// IPv4/IPv6 Topology Prefix NLRI (RFC 9552 Section 5.2): a Local Node
/// Descriptor plus Prefix Descriptors. The address family is carried by the
/// enclosing [`BgpLsNlri`] variant, not in this struct.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct LsPrefixNlri {
    pub protocol_id: LsProtocolId,
    pub identifier: u64,
    pub local_node: LsNodeDescriptor,
    pub prefix_descs: Vec<LsPrefixDescriptor>,
}

/// A BGP Link-State NLRI (RFC 9552 Section 5.2). Used as an exact-match key in
/// the BGP-LS RIB, hence the derived `Ord`/`Hash`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum BgpLsNlri {
    Node(LsNodeNlri),
    Link(LsLinkNlri),
    Ipv4Prefix(LsPrefixNlri),
    Ipv6Prefix(LsPrefixNlri),
}

impl BgpLsNlri {
    /// NLRI Type code (1=Node, 2=Link, 3=IPv4 Prefix, 4=IPv6 Prefix).
    pub fn nlri_type(&self) -> u16 {
        match self {
            BgpLsNlri::Node(_) => LS_NLRI_NODE,
            BgpLsNlri::Link(_) => LS_NLRI_LINK,
            BgpLsNlri::Ipv4Prefix(_) => LS_NLRI_IPV4_PREFIX,
            BgpLsNlri::Ipv6Prefix(_) => LS_NLRI_IPV6_PREFIX,
        }
    }

    pub fn protocol_id(&self) -> LsProtocolId {
        match self {
            BgpLsNlri::Node(n) => n.protocol_id,
            BgpLsNlri::Link(l) => l.protocol_id,
            BgpLsNlri::Ipv4Prefix(p) | BgpLsNlri::Ipv6Prefix(p) => p.protocol_id,
        }
    }

    /// Parse one Link-State NLRI (NLRI Type + Total NLRI Length header plus the
    /// body). `add_path` is accepted for signature parity with the other NLRI
    /// parsers; BGP-LS does not use a Path Identifier.
    pub fn parse(input: &[u8], _add_path: bool) -> IResult<&[u8], Self> {
        let (input, nlri_type) = be_u16(input)?;
        let (input, total_len) = be_u16(input)?;
        let (input, body) = take(total_len as usize)(input)?;
        let nlri = match nlri_type {
            LS_NLRI_NODE => BgpLsNlri::Node(parse_node_body(body)?.1),
            LS_NLRI_LINK => BgpLsNlri::Link(parse_link_body(body)?.1),
            LS_NLRI_IPV4_PREFIX => BgpLsNlri::Ipv4Prefix(parse_prefix_body(body)?.1),
            LS_NLRI_IPV6_PREFIX => BgpLsNlri::Ipv6Prefix(parse_prefix_body(body)?.1),
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Tag,
                )));
            }
        };
        Ok((input, nlri))
    }
}

fn parse_node_body(body: &[u8]) -> IResult<&[u8], LsNodeNlri> {
    let (body, protocol_id) = be_u8(body)?;
    let (body, identifier) = be_u64(body)?;
    let (body, local_node) = parse_node_desc_container(body)?;
    Ok((
        body,
        LsNodeNlri {
            protocol_id: protocol_id.into(),
            identifier,
            local_node,
        },
    ))
}

fn parse_link_body(body: &[u8]) -> IResult<&[u8], LsLinkNlri> {
    let (body, protocol_id) = be_u8(body)?;
    let (body, identifier) = be_u64(body)?;
    let (body, local_node) = parse_node_desc_container(body)?;
    let (body, remote_node) = parse_node_desc_container(body)?;
    let mut link_descs = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (next, (typ, val)) = parse_raw_tlv(rest)?;
        link_descs.push(LsLinkDescriptor::from_tlv(typ, val));
        rest = next;
    }
    Ok((
        rest,
        LsLinkNlri {
            protocol_id: protocol_id.into(),
            identifier,
            local_node,
            remote_node,
            link_descs,
        },
    ))
}

fn parse_prefix_body(body: &[u8]) -> IResult<&[u8], LsPrefixNlri> {
    let (body, protocol_id) = be_u8(body)?;
    let (body, identifier) = be_u64(body)?;
    let (body, local_node) = parse_node_desc_container(body)?;
    let mut prefix_descs = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (next, (typ, val)) = parse_raw_tlv(rest)?;
        prefix_descs.push(LsPrefixDescriptor::from_tlv(typ, val));
        rest = next;
    }
    Ok((
        rest,
        LsPrefixNlri {
            protocol_id: protocol_id.into(),
            identifier,
            local_node,
            prefix_descs,
        },
    ))
}

/// Parse one Local/Remote Node Descriptors container TLV (type 256 or 257) and
/// return its inner node descriptor. The container type is not retained; it is
/// re-emitted positionally (256 for local, 257 for remote).
fn parse_node_desc_container(input: &[u8]) -> IResult<&[u8], LsNodeDescriptor> {
    let (input, (_typ, val)) = parse_raw_tlv(input)?;
    let (_, nd) = LsNodeDescriptor::parse(val)?;
    Ok((input, nd))
}

// ----------------------------------------------------------------------------
// Emit
// ----------------------------------------------------------------------------

/// Serialize a Link-State NLRI (including the NLRI Type + Total NLRI Length
/// header) into `buf`.
pub fn bgpls_nlri_emit(buf: &mut BytesMut, nlri: &BgpLsNlri) {
    let mut body = BytesMut::new();
    match nlri {
        BgpLsNlri::Node(n) => emit_node_body(&mut body, n),
        BgpLsNlri::Link(l) => emit_link_body(&mut body, l),
        BgpLsNlri::Ipv4Prefix(p) | BgpLsNlri::Ipv6Prefix(p) => emit_prefix_body(&mut body, p),
    }
    buf.put_u16(nlri.nlri_type());
    buf.put_u16(body.len() as u16);
    buf.put_slice(&body);
}

fn emit_node_body(buf: &mut BytesMut, n: &LsNodeNlri) {
    buf.put_u8(n.protocol_id.into());
    buf.put_u64(n.identifier);
    n.local_node.emit(buf, LS_TLV_LOCAL_NODE_DESC);
}

fn emit_link_body(buf: &mut BytesMut, l: &LsLinkNlri) {
    buf.put_u8(l.protocol_id.into());
    buf.put_u64(l.identifier);
    l.local_node.emit(buf, LS_TLV_LOCAL_NODE_DESC);
    l.remote_node.emit(buf, LS_TLV_REMOTE_NODE_DESC);
    for d in &l.link_descs {
        d.emit(buf);
    }
}

fn emit_prefix_body(buf: &mut BytesMut, p: &LsPrefixNlri) {
    buf.put_u8(p.protocol_id.into());
    buf.put_u64(p.identifier);
    p.local_node.emit(buf, LS_TLV_LOCAL_NODE_DESC);
    for d in &p.prefix_descs {
        d.emit(buf);
    }
}

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------

/// Parse one raw TLV (Type: 2 octets, Length: 2 octets, Value), returning the
/// type and value slice.
fn parse_raw_tlv(input: &[u8]) -> IResult<&[u8], (u16, &[u8])> {
    let (input, typ) = be_u16(input)?;
    let (input, len) = be_u16(input)?;
    let (input, val) = take(len as usize)(input)?;
    Ok((input, (typ, val)))
}

fn emit_tlv(buf: &mut BytesMut, typ: u16, value: &[u8]) {
    buf.put_u16(typ);
    buf.put_u16(value.len() as u16);
    buf.put_slice(value);
}

fn emit_tlv_u32(buf: &mut BytesMut, typ: u16, value: u32) {
    buf.put_u16(typ);
    buf.put_u16(4);
    buf.put_u32(value);
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be_ipv4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn be_ipv6(b: &[u8]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(b);
    Ipv6Addr::from(o)
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(nlri: &BgpLsNlri) {
        let mut buf = BytesMut::new();
        bgpls_nlri_emit(&mut buf, nlri);
        let (rest, parsed) = BgpLsNlri::parse(&buf, false).expect("parse");
        assert!(rest.is_empty(), "trailing bytes after parse");
        assert_eq!(&parsed, nlri, "round-trip mismatch");
    }

    fn isis_l2_node(sysid: [u8; 6]) -> LsNodeDescriptor {
        LsNodeDescriptor {
            subs: vec![
                LsNodeDescSub::AutonomousSystem(65000),
                LsNodeDescSub::IgpRouterId(sysid.to_vec()),
            ],
        }
    }

    #[test]
    fn protocol_id_round_trip() {
        for v in [1u8, 2, 3, 4, 5, 6, 99] {
            assert_eq!(u8::from(LsProtocolId::from(v)), v);
        }
        assert_eq!(LsProtocolId::from(2), LsProtocolId::IsisL2);
    }

    #[test]
    fn node_nlri_round_trip() {
        let nlri = BgpLsNlri::Node(LsNodeNlri {
            protocol_id: LsProtocolId::IsisL2,
            identifier: 0,
            local_node: isis_l2_node([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
        });
        roundtrip(&nlri);
    }

    #[test]
    fn link_nlri_round_trip() {
        let nlri = BgpLsNlri::Link(LsLinkNlri {
            protocol_id: LsProtocolId::IsisL2,
            identifier: 0,
            local_node: isis_l2_node([0, 0, 0, 0, 0, 1]),
            remote_node: isis_l2_node([0, 0, 0, 0, 0, 2]),
            link_descs: vec![
                LsLinkDescriptor::Ipv4InterfaceAddr(Ipv4Addr::new(10, 0, 0, 1)),
                LsLinkDescriptor::Ipv4NeighborAddr(Ipv4Addr::new(10, 0, 0, 2)),
                LsLinkDescriptor::LinkLocalRemoteId {
                    local: 7,
                    remote: 9,
                },
            ],
        });
        roundtrip(&nlri);
    }

    #[test]
    fn link_nlri_v6_and_mt_round_trip() {
        let nlri = BgpLsNlri::Link(LsLinkNlri {
            protocol_id: LsProtocolId::IsisL1,
            identifier: 1,
            local_node: isis_l2_node([0, 0, 0, 0, 0, 1]),
            remote_node: isis_l2_node([0, 0, 0, 0, 0, 2]),
            link_descs: vec![
                LsLinkDescriptor::MultiTopologyId(2),
                LsLinkDescriptor::Ipv6InterfaceAddr("2001:db8::1".parse().unwrap()),
                LsLinkDescriptor::Ipv6NeighborAddr("2001:db8::2".parse().unwrap()),
            ],
        });
        roundtrip(&nlri);
    }

    #[test]
    fn ipv4_prefix_nlri_round_trip() {
        let nlri = BgpLsNlri::Ipv4Prefix(LsPrefixNlri {
            protocol_id: LsProtocolId::IsisL2,
            identifier: 0,
            local_node: isis_l2_node([0, 0, 0, 0, 0, 1]),
            prefix_descs: vec![LsPrefixDescriptor::IpReachability {
                prefix_len: 24,
                prefix: vec![10, 1, 2],
            }],
        });
        roundtrip(&nlri);
    }

    #[test]
    fn ipv6_prefix_nlri_round_trip() {
        let nlri = BgpLsNlri::Ipv6Prefix(LsPrefixNlri {
            protocol_id: LsProtocolId::IsisL2,
            identifier: 0,
            local_node: isis_l2_node([0, 0, 0, 0, 0, 1]),
            prefix_descs: vec![
                LsPrefixDescriptor::MultiTopologyId(2),
                LsPrefixDescriptor::IpReachability {
                    prefix_len: 64,
                    prefix: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
                },
            ],
        });
        roundtrip(&nlri);
    }

    #[test]
    fn unknown_descriptor_preserved() {
        let nlri = BgpLsNlri::Node(LsNodeNlri {
            protocol_id: LsProtocolId::Ospfv2,
            identifier: 42,
            local_node: LsNodeDescriptor {
                subs: vec![
                    LsNodeDescSub::OspfAreaId(0),
                    LsNodeDescSub::Unknown {
                        typ: 9999,
                        value: vec![0xde, 0xad, 0xbe, 0xef],
                    },
                ],
            },
        });
        roundtrip(&nlri);
    }

    #[test]
    fn node_nlri_wire_format() {
        // Hand-built Node NLRI: IS-IS L2, identifier 0, one IGP Router-ID
        // sub-TLV (6-octet System-ID 0000.0000.0001).
        let nlri = BgpLsNlri::Node(LsNodeNlri {
            protocol_id: LsProtocolId::IsisL2,
            identifier: 0,
            local_node: LsNodeDescriptor {
                subs: vec![LsNodeDescSub::IgpRouterId(vec![0, 0, 0, 0, 0, 1])],
            },
        });
        let mut buf = BytesMut::new();
        bgpls_nlri_emit(&mut buf, &nlri);
        let expected: &[u8] = &[
            0x00, 0x01, // NLRI Type = 1 (Node)
            0x00, 0x17, // Total NLRI Length = 23 (1 + 8 + 14)
            0x02, // Protocol-ID = 2 (IS-IS L2)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Identifier
            0x01, 0x00, // Local Node Descriptors (TLV 256)
            0x00, 0x0a, // length 10
            0x02, 0x03, // IGP Router-ID sub-TLV (515)
            0x00, 0x06, // length 6
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // System-ID
        ];
        assert_eq!(&buf[..], expected);
    }

    #[test]
    fn parse_rejects_unknown_nlri_type() {
        let bytes: &[u8] = &[0x00, 0x09, 0x00, 0x00];
        assert!(BgpLsNlri::parse(bytes, false).is_err());
    }
}
