use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u24, be_u32};
use nom::{Err, IResult};
use nom_derive::*;
use serde::{Deserialize, Serialize, Serializer};
use strum_macros::Display;

use super::checksum_calc;
use super::error::{IsisIResult, IsisParseError};
use super::util::{ParseBe, TlvEmitter, u32_u8_3};
use super::{
    IsisTlvExtIpReach, IsisTlvExtIsReach, IsisTlvIpv6Reach, IsisTlvIpv6Srlg, IsisTlvMtIpReach,
    IsisTlvMtIpv6Reach, IsisTlvMtIsReach, IsisTlvMultiTopology, IsisTlvRestart, IsisTlvRouterCap,
    IsisTlvSidLabelBinding, IsisTlvSrlg, IsisTlvSrv6, IsisTlvType, IsisType, many0_complete,
};

// IS-IS discriminator.
const ISIS_IRDP_DISC: u8 = 0x83;

// Const for Ipv4Addr and Ipv6Addr lenght.
pub const IPV4_ADDR_LEN: u8 = 4;
pub const IPV6_ADDR_LEN: u8 = 16;

#[derive(Debug, NomBE, Clone)]
pub struct IsisPacket {
    #[nom(Verify = "*discriminator == ISIS_IRDP_DISC")]
    pub discriminator: u8,
    pub length_indicator: u8,
    pub id_extension: u8,
    pub id_length: u8,
    pub pdu_type: IsisType,
    pub version: u8,
    pub resvd: u8,
    pub max_area_addr: u8,
    #[nom(Parse = "{ |x| IsisPdu::parse_be(x, pdu_type) }")]
    pub pdu: IsisPdu,
    #[nom(Ignore)]
    pub bytes: Vec<u8>,
}

pub fn length_indicator(pdu_type: IsisType) -> u8 {
    use IsisType::*;
    match pdu_type {
        L1Hello => 27,
        L2Hello => 27,
        P2pHello => 20,
        L1Lsp => 27,
        L2Lsp => 27,
        L1Csnp => 33,
        L2Csnp => 33,
        L1Psnp => 17,
        L2Psnp => 17,
        _ => 27,
    }
}

impl IsisPacket {
    pub fn from(pdu_type: IsisType, pdu: IsisPdu) -> IsisPacket {
        IsisPacket {
            discriminator: 0x83,
            length_indicator: length_indicator(pdu_type),
            id_extension: 1,
            id_length: 0,
            pdu_type,
            version: 1,
            resvd: 0,
            max_area_addr: 0,
            pdu,
            bytes: vec![],
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisPdu::*;
        buf.put_u8(self.discriminator);
        buf.put_u8(self.length_indicator);
        buf.put_u8(self.id_extension);
        buf.put_u8(self.id_length);
        buf.put_u8(self.pdu_type.into());
        buf.put_u8(self.version);
        buf.put_u8(self.resvd);
        buf.put_u8(self.max_area_addr);
        match &self.pdu {
            L1Hello(v) => v.emit(buf),
            L2Hello(v) => v.emit(buf),
            P2pHello(v) => v.emit(buf),
            L1Lsp(v) => v.emit(buf),
            L2Lsp(v) => v.emit(buf),
            L1Csnp(v) => v.emit(buf),
            L2Csnp(v) => v.emit(buf),
            L1Psnp(v) => v.emit(buf),
            L2Psnp(v) => v.emit(buf),
            // The payload is preserved on parse — re-emit it verbatim
            // so a parsed-then-emitted unknown PDU keeps its body
            // (padding probes, mirror/replay tooling) instead of
            // silently becoming an empty-bodied header.
            Unknown(v) => v.emit(buf),
        }
        if self.pdu_type.is_lsp() && buf.len() >= 26 {
            let checksum = checksum_calc(&buf[12..]);
            buf[24..26].copy_from_slice(&checksum);
        }
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisType")]
pub enum IsisPdu {
    #[nom(Selector = "IsisType::L1Hello")]
    L1Hello(IsisHello),
    #[nom(Selector = "IsisType::L2Hello")]
    L2Hello(IsisHello),
    #[nom(Selector = "IsisType::P2pHello")]
    P2pHello(IsisP2pHello),
    #[nom(Selector = "IsisType::L1Lsp")]
    L1Lsp(IsisLsp),
    #[nom(Selector = "IsisType::L2Lsp")]
    L2Lsp(IsisLsp),
    #[nom(Selector = "IsisType::L1Csnp")]
    L1Csnp(IsisCsnp),
    #[nom(Selector = "IsisType::L2Csnp")]
    L2Csnp(IsisCsnp),
    #[nom(Selector = "IsisType::L1Psnp")]
    L1Psnp(IsisPsnp),
    #[nom(Selector = "IsisType::L2Psnp")]
    L2Psnp(IsisPsnp),
    #[nom(Selector = "_")]
    Unknown(IsisUnknown),
}

#[derive(
    Debug, Default, NomBE, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, Serialize, Deserialize,
)]
pub struct IsisSysId {
    pub id: [u8; 6],
}

impl IsisSysId {
    pub fn is_empty(&self) -> bool {
        self.id.iter().all(|&b| b == 0)
    }
}

#[derive(Debug, Default, NomBE, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, Deserialize)]
pub struct IsisNeighborId {
    pub id: [u8; 7],
}

impl IsisNeighborId {
    pub fn from_sys_id(sys_id: &IsisSysId, pseudo_id: u8) -> Self {
        Self {
            id: [
                sys_id.id[0],
                sys_id.id[1],
                sys_id.id[2],
                sys_id.id[3],
                sys_id.id[4],
                sys_id.id[5],
                pseudo_id,
            ],
        }
    }

    pub fn sys_id(&self) -> IsisSysId {
        IsisSysId {
            id: [
                self.id[0], self.id[1], self.id[2], self.id[3], self.id[4], self.id[5],
            ],
        }
    }

    pub fn pseudo_id(&self) -> u8 {
        self.id[6]
    }

    pub fn is_empty(&self) -> bool {
        self.id.iter().all(|&b| b == 0)
    }
}

impl Serialize for IsisNeighborId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Default, NomBE, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, Deserialize)]
pub struct IsisLspId {
    pub id: [u8; 8],
}

impl IsisLspId {
    pub fn start() -> Self {
        Self::default()
    }

    pub fn end() -> Self {
        Self {
            id: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        }
    }

    pub fn new(sys_id: IsisSysId, pseudo_id: u8, fragment_id: u8) -> Self {
        Self {
            id: [
                sys_id.id[0],
                sys_id.id[1],
                sys_id.id[2],
                sys_id.id[3],
                sys_id.id[4],
                sys_id.id[5],
                pseudo_id,
                fragment_id,
            ],
        }
    }

    pub fn from_neighbor_id(neighbor_id: IsisNeighborId, fragment_id: u8) -> Self {
        Self {
            id: [
                neighbor_id.id[0],
                neighbor_id.id[1],
                neighbor_id.id[2],
                neighbor_id.id[3],
                neighbor_id.id[4],
                neighbor_id.id[5],
                neighbor_id.id[6],
                fragment_id,
            ],
        }
    }

    pub fn sys_id(&self) -> IsisSysId {
        IsisSysId {
            id: [
                self.id[0], self.id[1], self.id[2], self.id[3], self.id[4], self.id[5],
            ],
        }
    }

    pub fn neighbor_id(&self) -> IsisNeighborId {
        IsisNeighborId {
            id: [
                self.id[0], self.id[1], self.id[2], self.id[3], self.id[4], self.id[5], self.id[6],
            ],
        }
    }

    pub fn pseudo_id(&self) -> u8 {
        self.id[6]
    }

    pub fn is_pseudo(&self) -> bool {
        self.id[6] != 0
    }

    pub fn fragment_id(&self) -> u8 {
        self.id[7]
    }

    pub fn is_fragment(&self) -> bool {
        self.id[7] != 0
    }
}

impl Serialize for IsisLspId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<IsisNeighborId> for IsisLspId {
    fn from(value: IsisNeighborId) -> Self {
        Self {
            id: [
                value.id[0],
                value.id[1],
                value.id[2],
                value.id[3],
                value.id[4],
                value.id[5],
                value.id[6],
                0,
            ],
        }
    }
}

#[bitfield(u8, debug = true)]
pub struct IsisLspTypes {
    #[bits(2)]
    pub is_bits: u8,
    pub ol_bits: bool,
    #[bits(4)]
    pub att_bits: u8,
    pub p_bits: bool,
}

impl ParseBe<IsisLspTypes> for IsisLspTypes {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, types) = be_u8(input)?;
        Ok((input, types.into()))
    }
}

impl IsisLspTypes {
    pub fn from(level: u8) -> Self {
        match level {
            1 => IsisLspTypes::new().with_is_bits(0x01),
            _ => IsisLspTypes::new().with_is_bits(0x03),
        }
    }
}

#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize)]
pub struct IsisLsp {
    pub pdu_len: u16,
    pub hold_time: u16,
    pub lsp_id: IsisLspId,
    pub seq_number: u32,
    pub checksum: u16,
    pub types: IsisLspTypes,
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisLsp {
    pub fn emit(&self, buf: &mut BytesMut) {
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put_u16(self.hold_time);
        buf.put(&self.lsp_id.id[..]);
        buf.put_u32(self.seq_number);
        buf.put_u16(self.checksum);
        buf.put_u8(self.types.into());
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }

    pub fn hostname_tlv(&self) -> Option<&IsisTlvHostname> {
        self.tlvs.iter().find_map(|tlv| {
            if let IsisTlv::Hostname(tlv) = tlv {
                Some(tlv)
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum IsLevel {
    L1,
    L2,
    #[default]
    L1L2,
}

impl IsLevel {
    pub fn capable(&self, typ: &IsisType) -> bool {
        match typ {
            IsisType::L1Hello => matches!(self, IsLevel::L1 | IsLevel::L1L2),
            IsisType::L2Hello => matches!(self, IsLevel::L2 | IsLevel::L1L2),
            IsisType::L1Lsp => matches!(self, IsLevel::L1 | IsLevel::L1L2),
            IsisType::L2Lsp => matches!(self, IsLevel::L2 | IsLevel::L1L2),
            IsisType::L1Csnp => matches!(self, IsLevel::L1 | IsLevel::L1L2),
            IsisType::L2Csnp => matches!(self, IsLevel::L2 | IsLevel::L1L2),
            IsisType::L1Psnp => matches!(self, IsLevel::L1 | IsLevel::L1L2),
            IsisType::L2Psnp => matches!(self, IsLevel::L2 | IsLevel::L1L2),
            _ => false,
        }
    }
}

impl From<IsLevel> for u8 {
    fn from(level: IsLevel) -> Self {
        match level {
            IsLevel::L1 => 0x01,
            IsLevel::L2 => 0x02,
            IsLevel::L1L2 => 0x03,
        }
    }
}

impl From<u8> for IsLevel {
    fn from(level: u8) -> Self {
        match level {
            0x01 => IsLevel::L1,
            0x02 => IsLevel::L2,
            _ => IsLevel::L1L2,
        }
    }
}

impl ParseBe<IsLevel> for IsLevel {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, level) = be_u8(input)?;
        Ok((input, level.into()))
    }
}

#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize)]
pub struct IsisHello {
    pub circuit_type: IsLevel,
    pub source_id: IsisSysId,
    pub hold_time: u16,
    pub pdu_len: u16,
    pub priority: u8,
    pub lan_id: IsisNeighborId,
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisHello {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.circuit_type.into());
        buf.put(&self.source_id.id[..]);
        buf.put_u16(self.hold_time);
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put_u8(self.priority);
        buf.put(&self.lan_id.id[..]);
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }
}

#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize)]
pub struct IsisP2pHello {
    pub circuit_type: IsLevel,
    pub source_id: IsisSysId,
    pub hold_time: u16,
    pub pdu_len: u16,
    pub circuit_id: u8,
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisP2pHello {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.circuit_type.into());
        buf.put(&self.source_id.id[..]);
        buf.put_u16(self.hold_time);
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put_u8(self.circuit_id);
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }
}

#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize)]
pub struct IsisCsnp {
    pub pdu_len: u16,
    pub source_id: IsisSysId,
    pub source_id_circuit: u8,
    pub start: IsisLspId,
    pub end: IsisLspId,
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisCsnp {
    pub fn emit(&self, buf: &mut BytesMut) {
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put(&self.source_id.id[..]);
        buf.put_u8(self.source_id_circuit);
        buf.put(&self.start.id[..]);
        buf.put(&self.end.id[..]);
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }
}

#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize)]
pub struct IsisPsnp {
    pub pdu_len: u16,
    pub source_id: IsisSysId,
    pub source_id_circuit: u8,
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisPsnp {
    pub fn emit(&self, buf: &mut BytesMut) {
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put(&self.source_id.id[..]);
        buf.put_u8(self.source_id_circuit);
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisTlvType")]
pub enum IsisTlv {
    #[nom(Selector = "IsisTlvType::AreaAddr")]
    AreaAddr(IsisTlvAreaAddr),
    #[nom(Selector = "IsisTlvType::IsNeighbor")]
    IsNeighbor(IsisTlvIsNeighbor),
    #[nom(Selector = "IsisTlvType::Padding")]
    Padding(IsisTlvPadding),
    #[nom(Selector = "IsisTlvType::LspEntries")]
    LspEntries(IsisTlvLspEntries),
    #[nom(Selector = "IsisTlvType::Auth")]
    Auth(IsisTlvAuth),
    #[nom(Selector = "IsisTlvType::PurgeOrigId")]
    PurgeOrigId(IsisTlvPurgeOrigId),
    #[nom(Selector = "IsisTlvType::LspBufferSize")]
    LspBufferSize(IsisTlvLspBufferSize),
    #[nom(Selector = "IsisTlvType::ExtIsReach")]
    ExtIsReach(IsisTlvExtIsReach),
    #[nom(Selector = "IsisTlvType::MtIsReach")]
    MtIsReach(IsisTlvMtIsReach),
    #[nom(Selector = "IsisTlvType::Srv6")]
    Srv6(IsisTlvSrv6),
    #[nom(Selector = "IsisTlvType::ProtSupported")]
    ProtoSupported(IsisTlvProtoSupported),
    #[nom(Selector = "IsisTlvType::Ipv4IfAddr")]
    Ipv4IfAddr(IsisTlvIpv4IfAddr),
    #[nom(Selector = "IsisTlvType::TeRouterId")]
    TeRouterId(IsisTlvTeRouterId),
    #[nom(Selector = "IsisTlvType::ExtIpReach")]
    ExtIpReach(IsisTlvExtIpReach),
    #[nom(Selector = "IsisTlvType::SidLabelBinding")]
    SidLabelBinding(IsisTlvSidLabelBinding),
    #[nom(Selector = "IsisTlvType::DynamicHostname")]
    Hostname(IsisTlvHostname),
    #[nom(Selector = "IsisTlvType::Srlg")]
    Srlg(IsisTlvSrlg),
    #[nom(Selector = "IsisTlvType::Ipv6Srlg")]
    Ipv6Srlg(IsisTlvIpv6Srlg),
    #[nom(Selector = "IsisTlvType::Ipv6TeRouterId")]
    Ipv6TeRouterId(IsisTlvIpv6TeRouterId),
    #[nom(Selector = "IsisTlvType::Ipv6IfAddr")]
    Ipv6IfAddr(IsisTlvIpv6IfAddr),
    #[nom(Selector = "IsisTlvType::Ipv6GlobalIfAddr")]
    Ipv6GlobalIfAddr(IsisTlvIpv6GlobalIfAddr),
    #[nom(Selector = "IsisTlvType::MultiTopology")]
    MultiTopology(IsisTlvMultiTopology),
    #[nom(Selector = "IsisTlvType::MtIpReach")]
    MtIpReach(IsisTlvMtIpReach),
    #[nom(Selector = "IsisTlvType::Ipv6Reach")]
    Ipv6Reach(IsisTlvIpv6Reach),
    #[nom(Selector = "IsisTlvType::MtIpv6Reach")]
    MtIpv6Reach(IsisTlvMtIpv6Reach),
    #[nom(Selector = "IsisTlvType::P2p3Way")]
    P2p3Way(IsisTlvP2p3Way),
    #[nom(Selector = "IsisTlvType::RouterCap")]
    RouterCap(IsisTlvRouterCap),
    #[nom(Selector = "IsisTlvType::Restart")]
    Restart(IsisTlvRestart),
    #[nom(Selector = "_")]
    Unknown(IsisTlvUnknown),
}

impl IsisTlv {
    /// On-wire byte cost of this TLV: 2 bytes of TL header plus the
    /// serialized value. Used by the send-side fragmentation packer
    /// to decide whether a TLV instance fits in the current
    /// fragment's remaining budget.
    ///
    /// `TlvEmitter::len()` returns the same byte count as a `u8`,
    /// which silently wraps for malformed TLVs whose value exceeds
    /// 255 bytes. This helper emits into a scratch buffer and
    /// reports the true length so the packer can detect oversize
    /// instances and split them at the entry boundary before they
    /// reach `tlv_emit`.
    pub fn wire_len(&self) -> usize {
        let mut buf = BytesMut::new();
        self.emit(&mut buf);
        buf.len()
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisTlv::*;
        match self {
            AreaAddr(v) => v.tlv_emit(buf),
            IsNeighbor(v) => v.tlv_emit(buf),
            Padding(v) => v.tlv_emit(buf),
            LspEntries(v) => v.tlv_emit(buf),
            Auth(v) => v.tlv_emit(buf),
            PurgeOrigId(v) => v.tlv_emit(buf),
            LspBufferSize(v) => v.tlv_emit(buf),
            ExtIsReach(v) => v.tlv_emit(buf),
            MtIsReach(v) => v.tlv_emit(buf),
            Srv6(v) => v.tlv_emit(buf),
            ProtoSupported(v) => v.tlv_emit(buf),
            Ipv4IfAddr(v) => v.tlv_emit(buf),
            TeRouterId(v) => v.tlv_emit(buf),
            ExtIpReach(v) => v.tlv_emit(buf),
            SidLabelBinding(v) => v.tlv_emit(buf),
            Hostname(v) => v.tlv_emit(buf),
            Srlg(v) => v.tlv_emit(buf),
            Ipv6Srlg(v) => v.tlv_emit(buf),
            Ipv6TeRouterId(v) => v.tlv_emit(buf),
            Ipv6IfAddr(v) => v.tlv_emit(buf),
            Ipv6GlobalIfAddr(v) => v.tlv_emit(buf),
            MultiTopology(v) => v.tlv_emit(buf),
            MtIpReach(v) => v.tlv_emit(buf),
            Ipv6Reach(v) => v.tlv_emit(buf),
            MtIpv6Reach(v) => v.tlv_emit(buf),
            P2p3Way(v) => v.tlv_emit(buf),
            RouterCap(v) => v.tlv_emit(buf),
            Restart(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

/// Area Addresses TLV (type 1). The value is a *sequence* of
/// {length, area-address} pairs — ISO 10589 allows up to
/// maxAreaAddresses (3) per IS — so the field is a list; a received
/// TLV packing several areas keeps every one, not just the first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvAreaAddr {
    pub area_addrs: Vec<Vec<u8>>,
}

impl TlvEmitter for IsisTlvAreaAddr {
    fn typ(&self) -> u8 {
        IsisTlvType::AreaAddr.into()
    }

    fn len(&self) -> u8 {
        // Mirror emit(): each pair is 1 length byte + up to 254 area
        // octets; stop before the pair that would overflow the TLV's
        // one-octet length budget.
        let mut total = 0usize;
        for addr in &self.area_addrs {
            let pair = 1 + addr.len().min(254);
            if total + pair > 255 {
                break;
            }
            total += pair;
        }
        total as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        let mut total = 0usize;
        for addr in &self.area_addrs {
            let alen = addr.len().min(254);
            if total + 1 + alen > 255 {
                break;
            }
            total += 1 + alen;
            buf.put_u8(alen as u8);
            buf.put(&addr[..alen]);
        }
    }
}

impl ParseBe<IsisTlvAreaAddr> for IsisTlvAreaAddr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, area_addrs) = many0_complete(|i| {
            let (i, len) = be_u8(i)?;
            let (i, addr) = take(len)(i)?;
            let addr: &[u8] = addr;
            Ok((i, addr.to_vec()))
        })
        .parse(input)?;
        Ok((input, Self { area_addrs }))
    }
}

impl From<IsisTlvAreaAddr> for IsisTlv {
    fn from(tlv: IsisTlvAreaAddr) -> Self {
        IsisTlv::AreaAddr(tlv)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct NeighborAddr {
    pub octets: [u8; 6],
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIsNeighbor {
    pub neighbors: Vec<NeighborAddr>,
}

impl IsisTlvIsNeighbor {
    /// Maximum number of neighbors that fit in a single TLV 6: the
    /// one-octet Length field spans 255 bytes and each neighbor SNPA
    /// is 6 bytes, so 255 / 6 = 42. `len`/`emit` truncate consistently
    /// at this bound (a 43rd neighbor used to wrap the length byte
    /// mod-256 while every neighbor was still emitted); Hello builders
    /// shard larger adjacency sets across multiple TLV 6 instances so
    /// no neighbor is silently dropped.
    pub const MAX_NEIGHBORS: usize = 42;
}

impl TlvEmitter for IsisTlvIsNeighbor {
    fn typ(&self) -> u8 {
        IsisTlvType::IsNeighbor.into()
    }

    fn len(&self) -> u8 {
        (self.neighbors.len().min(Self::MAX_NEIGHBORS) * 6) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        for neighbor in self.neighbors.iter().take(Self::MAX_NEIGHBORS) {
            buf.put(&neighbor.octets[..]);
        }
    }
}

impl From<IsisTlvIsNeighbor> for IsisTlv {
    fn from(tlv: IsisTlvIsNeighbor) -> Self {
        IsisTlv::IsNeighbor(tlv)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvPadding {
    pub padding: Vec<u8>,
}

impl TlvEmitter for IsisTlvPadding {
    fn typ(&self) -> u8 {
        IsisTlvType::Padding.into()
    }

    fn len(&self) -> u8 {
        self.padding.len().min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.padding[..self.padding.len().min(255)]);
    }
}

#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisLspEntry {
    pub hold_time: u16,
    pub lsp_id: IsisLspId,
    pub seq_number: u32,
    pub checksum: u16,
}

impl IsisLspEntry {
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.hold_time);
        buf.put(&self.lsp_id.id[..]);
        buf.put_u32(self.seq_number);
        buf.put_u16(self.checksum);
    }

    pub fn from_lsp(lsp: &IsisLsp) -> Self {
        Self {
            hold_time: lsp.hold_time,
            lsp_id: lsp.lsp_id,
            seq_number: lsp.seq_number,
            checksum: lsp.checksum,
        }
    }
}

#[derive(Debug, NomBE, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvLspEntries {
    pub entries: Vec<IsisLspEntry>,
}

impl IsisTlvLspEntries {
    /// Maximum number of LSP entries that fit in a single TLV. The TLV's
    /// one-octet Length field caps the value at 255 bytes and each
    /// `IsisLspEntry` is exactly 16 bytes on the wire (hold_time(2) +
    /// lsp_id(8) + seq_number(4) + checksum(2)), so 255 / 16 = 15.
    ///
    /// CSNP/PSNP builders MUST split larger entry sets across multiple
    /// TLVs (or PDUs) and keep each `IsisTlvLspEntries` at or below this
    /// count: an over-full TLV wraps the length byte in [`len`] mod-256
    /// while [`emit`] still writes every entry, so the emitted length
    /// disagrees with the value bytes and desyncs the receiver's TLV walk.
    ///
    /// [`len`]: IsisTlvLspEntries::len
    /// [`emit`]: IsisTlvLspEntries::emit
    pub const MAX_ENTRIES: usize = 15;
}

impl TlvEmitter for IsisTlvLspEntries {
    fn typ(&self) -> u8 {
        IsisTlvType::LspEntries.into()
    }

    fn len(&self) -> u8 {
        // Wire format: hold_time(2) + lsp_id(8) + seq_number(4) + checksum(2) = 16.
        // Callers must keep entries <= MAX_ENTRIES; beyond that this u8 wraps
        // while emit() still writes every entry (see MAX_ENTRIES).
        (self.entries.len() * 16) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        for entry in self.entries.iter() {
            entry.emit(buf);
        }
    }
}

impl From<IsisTlvLspEntries> for IsisTlv {
    fn from(tlv: IsisTlvLspEntries) -> Self {
        IsisTlv::LspEntries(tlv)
    }
}

/// Authentication Information TLV (type 10).
///
/// ISO 10589 §9.5 (cleartext, auth_type=1), RFC 5304 (HMAC-MD5,
/// auth_type=54), and RFC 5310 (generic crypto, auth_type=3 with a
/// 2-byte Key ID prefix on the value). The value layout is intentionally
/// modeled as `auth_type` + opaque `value` so all three forms share one
/// struct; callers interpret `value` per the auth-type registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvAuth {
    pub auth_type: u8,
    pub value: Vec<u8>,
}

pub const ISIS_AUTH_TYPE_CLEARTEXT: u8 = 1;
pub const ISIS_AUTH_TYPE_HMAC_MD5: u8 = 54;
pub const ISIS_AUTH_TYPE_GENERIC: u8 = 3;
pub const ISIS_AUTH_HMAC_MD5_LEN: usize = 16;
/// Generic-crypto (RFC 5310) Key ID is fixed 2 bytes between the
/// Auth-Type byte and the digest. The digest length depends on the
/// algorithm — RFC 5310 §3.1 enumerates 20/28/32/48/64 octets for
/// SHA-1/SHA-224/SHA-256/SHA-384/SHA-512.
pub const ISIS_AUTH_GENERIC_KEY_ID_LEN: usize = 2;
pub const ISIS_AUTH_HMAC_SHA1_LEN: usize = 20;
pub const ISIS_AUTH_HMAC_SHA256_LEN: usize = 32;
pub const ISIS_AUTH_HMAC_SHA384_LEN: usize = 48;
pub const ISIS_AUTH_HMAC_SHA512_LEN: usize = 64;

impl IsisTlvAuth {
    /// Build a placeholder Auth TLV with the digest area zero-filled.
    /// The signer emits this into the PDU first, then computes
    /// the HMAC over the serialized PDU and patches the digest bytes in
    /// place — RFC 5304 §3 / RFC 5310 §3.
    pub fn placeholder(auth_type: u8, value_len: usize) -> Self {
        Self {
            auth_type,
            value: vec![0u8; value_len],
        }
    }
}

impl TlvEmitter for IsisTlvAuth {
    fn typ(&self) -> u8 {
        IsisTlvType::Auth.into()
    }

    fn len(&self) -> u8 {
        (1 + self.value.len()).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.auth_type);
        let max = self.value.len().min(254);
        buf.put(&self.value[..max]);
    }
}

impl ParseBe<IsisTlvAuth> for IsisTlvAuth {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, auth_type) = be_u8(input)?;
        let value = input.to_vec();
        Ok((&input[input.len()..], Self { auth_type, value }))
    }
}

impl From<IsisTlvAuth> for IsisTlv {
    fn from(tlv: IsisTlvAuth) -> Self {
        IsisTlv::Auth(tlv)
    }
}

#[repr(u8)]
#[derive(Display, Serialize)]
pub enum IsisProto {
    #[strum(serialize = "IPv4")]
    Ipv4 = 0xcc,
    #[strum(serialize = "IPv6")]
    Ipv6 = 0x8e,
    #[strum(serialize = "Unknown")]
    Unknown,
}

impl From<u8> for IsisProto {
    fn from(proto: u8) -> Self {
        match proto {
            0xcc => IsisProto::Ipv4,
            0x8e => IsisProto::Ipv6,
            _ => IsisProto::Unknown,
        }
    }
}

impl From<IsisProto> for u8 {
    fn from(proto: IsisProto) -> Self {
        match proto {
            IsisProto::Ipv4 => 0xcc,
            IsisProto::Ipv6 => 0x8e,
            IsisProto::Unknown => 0xff,
        }
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvProtoSupported {
    pub nlpids: Vec<u8>,
}

impl TlvEmitter for IsisTlvProtoSupported {
    fn typ(&self) -> u8 {
        IsisTlvType::ProtSupported.into()
    }

    fn len(&self) -> u8 {
        self.nlpids.len().min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.nlpids[..self.nlpids.len().min(255)]);
    }
}

impl From<IsisTlvProtoSupported> for IsisTlv {
    fn from(tlv: IsisTlvProtoSupported) -> Self {
        IsisTlv::ProtoSupported(tlv)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIpv4IfAddr {
    pub addr: Ipv4Addr,
}

impl TlvEmitter for IsisTlvIpv4IfAddr {
    fn typ(&self) -> u8 {
        IsisTlvType::Ipv4IfAddr.into()
    }

    fn len(&self) -> u8 {
        IPV4_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..])
    }
}

impl From<IsisTlvIpv4IfAddr> for IsisTlv {
    fn from(tlv: IsisTlvIpv4IfAddr) -> Self {
        IsisTlv::Ipv4IfAddr(tlv)
    }
}

/// TLV 14 — Originating LSP Buffer Size (RFC 1195 / ISO 10589).
///
/// Advertises the originator's `originatingLSPBufferSize` so receivers
/// know the maximum PDU length to accept on the link. Two-byte
/// big-endian value; default 1492. Lives in fragment 0 of the
/// originator's LSP set per the convention used by Cisco/Juniper/FRR.
#[derive(Debug, Default, NomBE, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct IsisTlvLspBufferSize {
    pub size: u16,
}

impl TlvEmitter for IsisTlvLspBufferSize {
    fn typ(&self) -> u8 {
        IsisTlvType::LspBufferSize.into()
    }

    fn len(&self) -> u8 {
        2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.size);
    }
}

impl From<IsisTlvLspBufferSize> for IsisTlv {
    fn from(tlv: IsisTlvLspBufferSize) -> Self {
        IsisTlv::LspBufferSize(tlv)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvTeRouterId {
    pub router_id: Ipv4Addr,
}

impl TlvEmitter for IsisTlvTeRouterId {
    fn typ(&self) -> u8 {
        IsisTlvType::TeRouterId.into()
    }

    fn len(&self) -> u8 {
        IPV4_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.router_id.octets()[..])
    }
}

impl From<IsisTlvTeRouterId> for IsisTlv {
    fn from(tlv: IsisTlvTeRouterId) -> Self {
        IsisTlv::TeRouterId(tlv)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvHostname {
    pub hostname: String,
}

impl TlvEmitter for IsisTlvHostname {
    fn typ(&self) -> u8 {
        IsisTlvType::DynamicHostname.into()
    }

    fn len(&self) -> u8 {
        self.hostname.len().min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        let bytes = self.hostname.as_bytes();
        buf.put(&bytes[..bytes.len().min(255)]);
    }
}

impl From<IsisTlvHostname> for IsisTlv {
    fn from(tlv: IsisTlvHostname) -> Self {
        IsisTlv::Hostname(tlv)
    }
}

/// RFC 6232 — Purge Originator Identification (TLV 13).
///
/// Carried in purge LSPs (Remaining Lifetime == 0) so receivers
/// can attribute a phantom purge back to the IS that injected it,
/// and optionally the upstream IS the purge was learned from.
///
/// Wire value:
///   - 1 octet `Number of System IDs` (1 or 2)
///   - 6 octets `originator` system-id
///   - 6 octets `received_from` system-id (only when Number == 2)
///
/// Length on the wire is 7 (Num + originator) or 13 (Num + both).
/// An originating IS MUST set Number == 1 with just its own
/// system-id; a forwarding IS that receives a purge without a POI
/// MUST add Number == 2 with (own_sysid, upstream_sysid) before
/// re-flooding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvPurgeOrigId {
    pub originator: IsisSysId,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub received_from: Option<IsisSysId>,
}

impl ParseBe<IsisTlvPurgeOrigId> for IsisTlvPurgeOrigId {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u8(input)?;
        let (input, originator) = IsisSysId::parse_be(input)?;
        let (input, received_from) = match num {
            1 => (input, None),
            2 => {
                let (input, rcv) = IsisSysId::parse_be(input)?;
                (input, Some(rcv))
            }
            _ => {
                return Err(nom::Err::Error(nom::error::make_error(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
        };
        Ok((
            input,
            Self {
                originator,
                received_from,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvPurgeOrigId {
    fn typ(&self) -> u8 {
        IsisTlvType::PurgeOrigId.into()
    }

    fn len(&self) -> u8 {
        // 1 byte count + 6 (originator) [+ 6 (received_from)].
        if self.received_from.is_some() { 13 } else { 7 }
    }

    fn emit(&self, buf: &mut BytesMut) {
        if let Some(rcv) = self.received_from {
            buf.put_u8(2);
            buf.put(&self.originator.id[..]);
            buf.put(&rcv.id[..]);
        } else {
            buf.put_u8(1);
            buf.put(&self.originator.id[..]);
        }
    }
}

impl From<IsisTlvPurgeOrigId> for IsisTlv {
    fn from(tlv: IsisTlvPurgeOrigId) -> Self {
        IsisTlv::PurgeOrigId(tlv)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIpv6TeRouterId {
    pub router_id: Ipv6Addr,
}

impl TlvEmitter for IsisTlvIpv6TeRouterId {
    fn typ(&self) -> u8 {
        IsisTlvType::Ipv6TeRouterId.into()
    }

    fn len(&self) -> u8 {
        IPV6_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.router_id.octets()[..]);
    }
}

impl From<IsisTlvIpv6TeRouterId> for IsisTlv {
    fn from(tlv: IsisTlvIpv6TeRouterId) -> Self {
        IsisTlv::Ipv6TeRouterId(tlv)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIpv6IfAddr {
    pub addr: Ipv6Addr,
}

impl TlvEmitter for IsisTlvIpv6IfAddr {
    fn typ(&self) -> u8 {
        IsisTlvType::Ipv6IfAddr.into()
    }

    fn len(&self) -> u8 {
        IPV6_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..])
    }
}

impl From<IsisTlvIpv6IfAddr> for IsisTlv {
    fn from(tlv: IsisTlvIpv6IfAddr) -> Self {
        IsisTlv::Ipv6IfAddr(tlv)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIpv6GlobalIfAddr {
    pub addr: Ipv6Addr,
}

impl TlvEmitter for IsisTlvIpv6GlobalIfAddr {
    fn typ(&self) -> u8 {
        IsisTlvType::Ipv6GlobalIfAddr.into()
    }

    fn len(&self) -> u8 {
        IPV6_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..])
    }
}

impl From<IsisTlvIpv6GlobalIfAddr> for IsisTlv {
    fn from(tlv: IsisTlvIpv6GlobalIfAddr) -> Self {
        IsisTlv::Ipv6GlobalIfAddr(tlv)
    }
}

// RFC 5303 §3.2: only the Adjacency Three-Way State octet is mandatory;
// every following field is "if known". Classic Cisco IOS sends the legacy
// 1-octet form (state only), so each field below the state is optional.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvP2p3Way {
    pub state: u8,
    pub circuit_id: Option<u32>,
    pub neighbor_id: Option<IsisSysId>,
    pub neighbor_circuit_id: Option<u32>,
}

impl ParseBe<IsisTlvP2p3Way> for IsisTlvP2p3Way {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, state) = be_u8(input)?;
        let (input, circuit_id) = if input.len() >= 4 {
            let (input, circuit_id) = be_u32(input)?;
            (input, Some(circuit_id))
        } else {
            (input, None)
        };
        let (input, neighbor_id) = if input.len() >= 6 {
            let (input, neighbor_id) = IsisSysId::parse_be(input)?;
            (input, Some(neighbor_id))
        } else {
            (input, None)
        };
        let (input, neighbor_circuit_id) = if input.len() >= 4 {
            let (input, neighbor_circuit_id) = be_u32(input)?;
            (input, Some(neighbor_circuit_id))
        } else {
            (input, None)
        };
        let tlv = Self {
            state,
            circuit_id,
            neighbor_id,
            neighbor_circuit_id,
        };
        Ok((input, tlv))
    }
}

impl TlvEmitter for IsisTlvP2p3Way {
    fn typ(&self) -> u8 {
        IsisTlvType::P2p3Way.into()
    }

    fn len(&self) -> u8 {
        // Positional wire format: the parser assigns trailing bytes in
        // this fixed order, so a field can only be present when every
        // field before it is. Stop at the first None — matching emit()
        // — so a gapped struct (e.g. neighbor_id set with circuit_id
        // None) can never emit a byte layout the parser would
        // misassign (the system-id's first 4 bytes read as circuit id).
        let mut len = 1;
        if self.circuit_id.is_none() {
            return len;
        }
        len += 4;
        if self.neighbor_id.is_none() {
            return len;
        }
        len += 6;
        if self.neighbor_circuit_id.is_none() {
            return len;
        }
        len + 4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.state);
        // See len(): stop at the first None to keep the positional
        // layout parseable.
        let Some(circuit_id) = self.circuit_id else {
            return;
        };
        buf.put_u32(circuit_id);
        let Some(neighbor_id) = &self.neighbor_id else {
            return;
        };
        buf.put(&neighbor_id.id[..]);
        let Some(neighbor_circuit_id) = self.neighbor_circuit_id else {
            return;
        };
        buf.put_u32(neighbor_circuit_id);
    }
}

impl From<IsisTlvP2p3Way> for IsisTlv {
    fn from(tlv: IsisTlvP2p3Way) -> Self {
        IsisTlv::P2p3Way(tlv)
    }
}

impl From<IsisTlvRestart> for IsisTlv {
    fn from(tlv: IsisTlvRestart) -> Self {
        IsisTlv::Restart(tlv)
    }
}

#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvUnknown {
    pub typ: IsisTlvType,
    pub len: u8,
    pub values: Vec<u8>,
}

impl IsisTlvUnknown {
    pub fn parse_tlv(input: &[u8], tl: IsisTypeLen) -> IResult<&[u8], Self> {
        let tlv = IsisTlvUnknown {
            typ: tl.typ,
            len: tl.len,
            values: input.to_vec(),
        };
        Ok((&input[input.len()..], tlv))
    }
}

impl TlvEmitter for IsisTlvUnknown {
    fn typ(&self) -> u8 {
        self.typ.into()
    }

    fn len(&self) -> u8 {
        // Derive from the bytes actually emitted — the stored `len` is
        // parse metadata and could disagree on a hand-built value.
        self.values.len().min(255) as u8
    }

    // `TlvEmitter::emit` is value-only by contract — `tlv_emit` writes
    // the type/length header. This used to write the header itself
    // (unlike every other TLV and unlike `IsisSubTlvUnknown`), so a
    // caller using `tlv_emit()` produced a doubled [typ, len, ...]
    // header.
    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.values[..]);
    }
}

impl ParseBe<IsisTlvHostname> for IsisTlvHostname {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let hostname = Self {
            hostname: String::from_utf8_lossy(input).to_string(),
        };
        Ok((&input[input.len()..], hostname))
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize)]
pub struct IsisUnknown {
    #[nom(Ignore)]
    pub typ: IsisType,
    pub payload: Vec<u8>,
}

impl IsisUnknown {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.payload[..]);
    }
}

#[derive(NomBE)]
pub struct IsisTypeLen {
    pub typ: IsisTlvType,
    pub len: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SidLabelValue {
    Label(u32),
    Index(u32),
}

impl SidLabelValue {
    /// RFC 8667 §2.1.1.1: in the 3-octet form the 20 rightmost bits are
    /// the MPLS label; the top 4 are reserved. Mask on both parse and
    /// emit (FRR: `sid &= MPLS_LABEL_VALUE_MASK`) so a peer setting a
    /// reserved bit — or a mis-scaled local value — can't yield an
    /// illegal label ≥ 2^20 that gets re-advertised or programmed.
    pub const LABEL_MASK: u32 = 0x000F_FFFF;

    pub fn len(&self) -> u8 {
        use SidLabelValue::*;
        match self {
            Label(_) => 3,
            Index(_) => 4,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use SidLabelValue::*;
        match self {
            Label(v) => buf.put(&u32_u8_3(*v & Self::LABEL_MASK)[..]),
            Index(v) => buf.put_u32(*v),
        }
    }

    pub fn value(&self) -> u32 {
        use SidLabelValue::*;
        match self {
            Label(v) => *v,
            Index(v) => *v,
        }
    }
}

impl ParseBe<SidLabelValue> for SidLabelValue {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        match input.len() {
            3 => {
                let (input, label) = be_u24(input)?;
                Ok((
                    input,
                    SidLabelValue::Label(label & SidLabelValue::LABEL_MASK),
                ))
            }
            4 => {
                let (input, index) = be_u32(input)?;
                Ok((input, SidLabelValue::Index(index)))
            }
            _ => Err(Err::Error(nom::error::make_error(
                input,
                nom::error::ErrorKind::LengthValue,
            ))),
        }
    }
}

impl IsisTlv {
    pub fn parse_tlv(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = IsisTypeLen::parse_be(input)?;
        let (input, tlv) = packet_utils::safe_split_at(input, tl.len as usize)?;
        if tl.typ.is_known() {
            // A malformed value in a known TLV must not abort the PDU:
            // parse_tlvs runs under many0, which would silently stop here
            // and drop every TLV after this one. Degrade to Unknown so the
            // bytes are preserved and the rest of the PDU still parses.
            if let Ok((_, val)) = Self::parse_be(tlv, tl.typ) {
                return Ok((input, val));
            }
        }
        let (_, val) = IsisTlvUnknown::parse_tlv(tlv, tl)?;
        Ok((input, Self::Unknown(val)))
    }

    pub fn parse_tlvs(input: &[u8]) -> IResult<&[u8], Vec<Self>> {
        many0_complete(Self::parse_tlv).parse(input)
    }
}

/// Parse an IS-IS packet, returning IsisParseError on failure.
pub fn parse(input: &[u8]) -> IsisIResult<&[u8], IsisPacket> {
    IsisPacket::parse_be(input).map_err(|e| e.map(IsisParseError::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Finding #15: an unknown PDU's payload is preserved on parse and
    /// must be re-emitted verbatim — `IsisPacket::emit` used to map
    /// `Unknown(_) => {}`, producing an empty-bodied 8-byte header.
    #[test]
    fn unknown_pdu_payload_round_trips() {
        let mut raw = vec![0x83u8, 27, 1, 0, 0x05, 1, 0, 0];
        raw.extend([0xDE, 0xAD, 0xBE, 0xEF]);
        let (rest, pkt) = IsisPacket::parse_be(&raw).expect("parse");
        assert!(rest.is_empty());
        let IsisPdu::Unknown(u) = &pkt.pdu else {
            panic!("expected Unknown PDU, got {:?}", pkt.pdu);
        };
        assert_eq!(u.payload, [0xDE, 0xAD, 0xBE, 0xEF]);
        let mut buf = BytesMut::new();
        pkt.emit(&mut buf);
        assert_eq!(&buf[..], &raw[..]);
    }

    /// Finding #15: `TlvEmitter::emit` is value-only by contract —
    /// `IsisTlvUnknown` used to write its own type/length, so
    /// `tlv_emit()` produced a doubled [typ, len, typ, len, ...]
    /// header. Both `tlv_emit` and the `IsisTlv` dispatcher must now
    /// produce the single-header form.
    #[test]
    fn unknown_tlv_emits_single_header() {
        let tlv = IsisTlvUnknown {
            typ: 200.into(),
            len: 3,
            values: vec![1, 2, 3],
        };
        let mut buf = BytesMut::new();
        tlv.tlv_emit(&mut buf);
        assert_eq!(&buf[..], &[200, 3, 1, 2, 3]);

        let mut via_dispatch = BytesMut::new();
        IsisTlv::Unknown(tlv).emit(&mut via_dispatch);
        assert_eq!(&via_dispatch[..], &buf[..]);
    }

    /// Finding #12: TLV 240's wire format is positional (state, then
    /// circuit id, then neighbor id, then neighbor circuit id), so emit
    /// must stop at the first None. A gapped struct (neighbor_id set,
    /// circuit_id None) used to emit state + 6 bytes, which re-parsed
    /// with the system-id's first 4 bytes as the circuit id — the
    /// three-way handshake would compare the wrong neighbor identity.
    #[test]
    fn p2p3way_gapped_optionals_emit_prefix_closed() {
        let gapped = IsisTlvP2p3Way {
            state: 1,
            circuit_id: None,
            neighbor_id: Some(IsisSysId {
                id: [1, 2, 3, 4, 5, 6],
            }),
            neighbor_circuit_id: Some(7),
        };
        assert_eq!(gapped.len(), 1);
        let mut buf = BytesMut::new();
        gapped.emit(&mut buf);
        assert_eq!(&buf[..], &[1]);

        // Every prefix-closed form round-trips exactly.
        let forms = [
            IsisTlvP2p3Way {
                state: 2,
                circuit_id: None,
                neighbor_id: None,
                neighbor_circuit_id: None,
            },
            IsisTlvP2p3Way {
                state: 2,
                circuit_id: Some(9),
                neighbor_id: None,
                neighbor_circuit_id: None,
            },
            IsisTlvP2p3Way {
                state: 2,
                circuit_id: Some(9),
                neighbor_id: Some(IsisSysId {
                    id: [1, 2, 3, 4, 5, 6],
                }),
                neighbor_circuit_id: None,
            },
            IsisTlvP2p3Way {
                state: 2,
                circuit_id: Some(9),
                neighbor_id: Some(IsisSysId {
                    id: [1, 2, 3, 4, 5, 6],
                }),
                neighbor_circuit_id: Some(7),
            },
        ];
        for form in forms {
            let mut buf = BytesMut::new();
            form.emit(&mut buf);
            assert_eq!(buf.len() as u8, form.len());
            let (rest, parsed) = IsisTlvP2p3Way::parse_be(&buf).expect("parse");
            assert!(rest.is_empty());
            assert_eq!(parsed, form);
        }
    }

    /// RFC 8667: the 3-octet SID/Label form carries the MPLS label in
    /// the 20 rightmost bits; the top 4 are reserved and must be masked
    /// on parse (a peer setting them) and on emit (a mis-scaled local
    /// value) so an illegal label ≥ 2^20 never propagates.
    #[test]
    fn sid_label_value_masks_label_to_20_bits() {
        let raw = [0xFFu8, 0xFF, 0xFF];
        let (rest, v) = SidLabelValue::parse_be(&raw).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(v, SidLabelValue::Label(0x000F_FFFF));

        let mut buf = BytesMut::new();
        SidLabelValue::Label(0xFFFF_FFFF).emit(&mut buf);
        assert_eq!(&buf[..], &[0x0F, 0xFF, 0xFF]);

        // A 4-octet index is not a label and passes through unmasked.
        let raw = [0x00u8, 0x20, 0x00, 0x00];
        let (_, v) = SidLabelValue::parse_be(&raw).expect("parse");
        assert_eq!(v, SidLabelValue::Index(0x0020_0000));
    }

    /// TLV 6 (IS Neighbors) — `len` and `emit` truncate consistently at
    /// MAX_NEIGHBORS. 43 neighbors used to wrap the length byte to 2
    /// (43*6 = 258 mod 256) while emit still wrote all 258 bytes,
    /// desyncing the receiver's TLV walk; Hello builders shard larger
    /// sets across multiple TLV 6 instances instead.
    #[test]
    fn is_neighbor_len_and_emit_truncate_at_max() {
        let over = IsisTlvIsNeighbor {
            neighbors: vec![NeighborAddr { octets: [0xAA; 6] }; 43],
        };
        assert_eq!(over.len() as usize, IsisTlvIsNeighbor::MAX_NEIGHBORS * 6);
        let mut buf = BytesMut::new();
        over.emit(&mut buf);
        assert_eq!(buf.len(), IsisTlvIsNeighbor::MAX_NEIGHBORS * 6);

        // At the bound everything fits and len/emit agree exactly.
        let full = IsisTlvIsNeighbor {
            neighbors: (0..IsisTlvIsNeighbor::MAX_NEIGHBORS)
                .map(|i| NeighborAddr {
                    octets: [i as u8; 6],
                })
                .collect(),
        };
        assert_eq!(full.len(), 252);
        let mut buf = BytesMut::new();
        full.emit(&mut buf);
        assert_eq!(buf.len(), 252);
    }

    /// Sanity-check `IsisTlv::wire_len` for a small fixed-size TLV.
    /// The packer relies on this returning a stable 4 bytes (2-byte
    /// TL header + 2-byte value) for the buffer-size TLV so its
    /// per-fragment budget accounting is correct.
    #[test]
    fn wire_len_counts_tl_header_plus_value() {
        let tlv: IsisTlv = IsisTlvLspBufferSize { size: 1492 }.into();
        assert_eq!(tlv.wire_len(), 4);

        let host: IsisTlv = IsisTlvHostname {
            hostname: "router-7".to_string(),
        }
        .into();
        // 2 header + 8 chars of "router-7".
        assert_eq!(host.wire_len(), 10);
    }

    /// Round-trip the Restart TLV (type 211, RFC 5306) through the
    /// `IsisTlv` dispatcher: emit via tlv_emit, re-parse via parse_tlvs,
    /// verify the variant comes back with flags + RA-paired fields
    /// intact. Guards the `#[nom(Selector = "IsisTlvType::Restart")]`
    /// wiring on the enum.
    #[test]
    fn restart_tlv_dispatches_through_isis_tlv() {
        let original: IsisTlv = IsisTlvRestart {
            flags: 0x02, // RA only
            remaining_time: Some(42),
            restarting_neighbor: Some(IsisSysId {
                id: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            }),
        }
        .into();
        let mut buf = BytesMut::new();
        original.emit(&mut buf);
        // T(1) + L(1) + Flags(1) + RemainingTime(2) + SysId(6) = 11.
        assert_eq!(buf.len(), 11);
        assert_eq!(buf[0], u8::from(IsisTlvType::Restart));
        assert_eq!(buf[1], 9);

        let (rest, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
        assert!(rest.is_empty());
        assert_eq!(tlvs.len(), 1);
        match &tlvs[0] {
            IsisTlv::Restart(v) => {
                assert!(v.ra());
                assert!(!v.rr());
                assert!(!v.sa());
                assert_eq!(v.remaining_time, Some(42));
                assert_eq!(
                    v.restarting_neighbor.as_ref().map(|s| s.id),
                    Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
                );
            }
            other => panic!("expected Restart, got {:?}", other),
        }
    }

    /// Round-trip a TLV 14 LSP Buffer Size: emit through tlv_emit,
    /// then re-parse via parse_tlvs and recover the original size.
    /// Frags emitted by the send-side packer will rely on
    /// the type+length header being exactly 4 bytes (2 header + 2
    /// value) so reach packing math stays predictable.
    #[test]
    fn lsp_buffer_size_round_trip() {
        let original = IsisTlvLspBufferSize { size: 1492 };
        let mut buf = BytesMut::new();
        original.tlv_emit(&mut buf);
        // type (1) + length (1) + value (2) = 4 bytes on the wire.
        assert_eq!(buf.len(), 4);
        assert_eq!(buf[0], u8::from(IsisTlvType::LspBufferSize));
        assert_eq!(buf[1], 2);

        let (rest, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
        assert!(rest.is_empty(), "parser consumes the whole buffer");
        assert_eq!(tlvs.len(), 1);
        match &tlvs[0] {
            IsisTlv::LspBufferSize(v) => assert_eq!(v.size, 1492),
            other => panic!("expected LspBufferSize, got {:?}", other),
        }
    }

    #[test]
    fn hostname_len_truncates_at_255() {
        let short = IsisTlvHostname {
            hostname: "router1".to_string(),
        };
        assert_eq!(short.len(), 7);

        let exact = IsisTlvHostname {
            hostname: "a".repeat(255),
        };
        assert_eq!(exact.len(), 255);

        let long = IsisTlvHostname {
            hostname: "a".repeat(300),
        };
        assert_eq!(long.len(), 255);
    }

    #[test]
    fn hostname_emit_truncates_at_255() {
        let long = IsisTlvHostname {
            hostname: "a".repeat(300),
        };
        let mut buf = BytesMut::new();
        long.emit(&mut buf);
        assert_eq!(buf.len(), 255);
    }

    #[test]
    fn area_addr_len_truncates_at_255() {
        let short = IsisTlvAreaAddr {
            area_addrs: vec![vec![0x49, 0x00, 0x01]],
        };
        // 1 (length byte) + 3 (address) = 4.
        assert_eq!(short.len(), 4);

        let exact = IsisTlvAreaAddr {
            area_addrs: vec![vec![0xAA; 254]],
        };
        // 1 + 254 = 255.
        assert_eq!(exact.len(), 255);

        // A single over-long address is capped at 254 octets, and a
        // second address that no longer fits the 255-byte TLV budget
        // is dropped from the length — mirroring emit().
        let long = IsisTlvAreaAddr {
            area_addrs: vec![vec![0xAA; 300], vec![0x49, 0x00, 0x01]],
        };
        assert_eq!(long.len(), 255);
    }

    #[test]
    fn area_addr_emit_truncates_at_255() {
        let long = IsisTlvAreaAddr {
            area_addrs: vec![vec![0xAA; 300], vec![0x49, 0x00, 0x01]],
        };
        let mut buf = BytesMut::new();
        long.emit(&mut buf);
        // 1 (length byte) + 254 (address data) = 255; the second
        // address doesn't fit and is dropped, matching len().
        assert_eq!(buf.len(), 255);
        assert_eq!(buf[0], 254);
    }

    /// Finding #6: the TLV 1 value is a sequence of {len, area} pairs
    /// (maxAreaAddresses = 3); the parser used to keep only the first
    /// pair, so a neighbor packing two areas into one TLV lost its
    /// second area and L1 area matching failed.
    #[test]
    fn area_addr_parses_all_areas() {
        let raw = [3u8, 0x49, 0x00, 0x01, 3, 0x49, 0x00, 0x02];
        let (rest, tlv) = IsisTlvAreaAddr::parse_be(&raw).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(
            tlv.area_addrs,
            vec![vec![0x49, 0x00, 0x01], vec![0x49, 0x00, 0x02]]
        );

        // Round-trip: emit reproduces both pairs and len() agrees.
        let mut buf = BytesMut::new();
        tlv.emit(&mut buf);
        assert_eq!(&buf[..], &raw[..]);
        assert_eq!(tlv.len() as usize, raw.len());
    }

    #[test]
    fn padding_len_truncates_at_255() {
        let short = IsisTlvPadding {
            padding: vec![0u8; 100],
        };
        assert_eq!(short.len(), 100);

        let exact = IsisTlvPadding {
            padding: vec![0u8; 255],
        };
        assert_eq!(exact.len(), 255);

        let long = IsisTlvPadding {
            padding: vec![0u8; 300],
        };
        assert_eq!(long.len(), 255);
    }

    #[test]
    fn padding_emit_truncates_at_255() {
        let long = IsisTlvPadding {
            padding: vec![0u8; 300],
        };
        let mut buf = BytesMut::new();
        long.emit(&mut buf);
        assert_eq!(buf.len(), 255);
    }

    #[test]
    fn proto_supported_len_truncates_at_255() {
        let short = IsisTlvProtoSupported {
            nlpids: vec![0xCC, 0x8E],
        };
        assert_eq!(short.len(), 2);

        let exact = IsisTlvProtoSupported {
            nlpids: vec![0xCC; 255],
        };
        assert_eq!(exact.len(), 255);

        let long = IsisTlvProtoSupported {
            nlpids: vec![0xCC; 300],
        };
        assert_eq!(long.len(), 255);
    }

    #[test]
    fn proto_supported_emit_truncates_at_255() {
        let long = IsisTlvProtoSupported {
            nlpids: vec![0xCC; 300],
        };
        let mut buf = BytesMut::new();
        long.emit(&mut buf);
        assert_eq!(buf.len(), 255);
    }

    /// HMAC-MD5 Auth TLV (RFC 5304 §2): on-wire shape is
    /// type=10, length=17 (1-byte auth-type + 16-byte digest),
    /// auth-type=54. Round-trip through tlv_emit + parse_tlvs.
    #[test]
    fn auth_hmac_md5_round_trip() {
        let digest: Vec<u8> = (0u8..16).collect();
        let original = IsisTlvAuth {
            auth_type: ISIS_AUTH_TYPE_HMAC_MD5,
            value: digest.clone(),
        };
        let mut buf = BytesMut::new();
        original.tlv_emit(&mut buf);

        assert_eq!(buf[0], u8::from(IsisTlvType::Auth));
        assert_eq!(buf[1], 1 + ISIS_AUTH_HMAC_MD5_LEN as u8);
        assert_eq!(buf[2], ISIS_AUTH_TYPE_HMAC_MD5);
        assert_eq!(&buf[3..], &digest[..]);

        let (rest, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
        assert!(rest.is_empty());
        match &tlvs[0] {
            IsisTlv::Auth(v) => {
                assert_eq!(v.auth_type, ISIS_AUTH_TYPE_HMAC_MD5);
                assert_eq!(v.value, digest);
            }
            other => panic!("expected Auth, got {:?}", other),
        }
    }

    /// Cleartext Auth TLV (ISO 10589, auth-type 1): the value is the
    /// raw password bytes after the auth-type byte.
    #[test]
    fn auth_cleartext_round_trip() {
        let original = IsisTlvAuth {
            auth_type: ISIS_AUTH_TYPE_CLEARTEXT,
            value: b"hunter2".to_vec(),
        };
        let mut buf = BytesMut::new();
        original.tlv_emit(&mut buf);

        let (_, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
        match &tlvs[0] {
            IsisTlv::Auth(v) => {
                assert_eq!(v.auth_type, ISIS_AUTH_TYPE_CLEARTEXT);
                assert_eq!(v.value, b"hunter2");
            }
            other => panic!("expected Auth, got {:?}", other),
        }
    }

    /// RFC 5310 generic crypto: auth-type 3, value = 2-byte Key ID +
    /// variable-length digest. The TLV layer treats the value as
    /// opaque bytes, so the round-trip must preserve the Key ID and
    /// digest byte-for-byte.
    #[test]
    fn auth_generic_crypto_round_trip() {
        let mut value = Vec::new();
        value.extend_from_slice(&7u16.to_be_bytes()); // Key ID = 7
        value.extend(0u8..20); // HMAC-SHA1 digest (20 bytes)
        let original = IsisTlvAuth {
            auth_type: ISIS_AUTH_TYPE_GENERIC,
            value: value.clone(),
        };
        let mut buf = BytesMut::new();
        original.tlv_emit(&mut buf);

        // type(1) + len(1) + auth-type(1) + key-id(2) + digest(20) = 25
        assert_eq!(buf.len(), 25);
        assert_eq!(buf[1], 23);

        let (_, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
        match &tlvs[0] {
            IsisTlv::Auth(v) => {
                assert_eq!(v.auth_type, ISIS_AUTH_TYPE_GENERIC);
                assert_eq!(v.value, value);
            }
            other => panic!("expected Auth, got {:?}", other),
        }
    }

    /// The LSP signer builds the PDU with a zero-filled placeholder,
    /// then patches the digest in. Verify placeholder() shape and that
    /// the emitted bytes match `[type, len, auth_type, 0x00 * N]`.
    #[test]
    fn auth_placeholder_is_zero_filled() {
        let tlv = IsisTlvAuth::placeholder(ISIS_AUTH_TYPE_HMAC_MD5, ISIS_AUTH_HMAC_MD5_LEN);
        assert_eq!(tlv.auth_type, ISIS_AUTH_TYPE_HMAC_MD5);
        assert_eq!(tlv.value.len(), ISIS_AUTH_HMAC_MD5_LEN);
        assert!(tlv.value.iter().all(|b| *b == 0));

        let mut buf = BytesMut::new();
        tlv.tlv_emit(&mut buf);
        assert_eq!(buf[0], u8::from(IsisTlvType::Auth));
        assert_eq!(buf[1], 1 + ISIS_AUTH_HMAC_MD5_LEN as u8);
        assert_eq!(buf[2], ISIS_AUTH_TYPE_HMAC_MD5);
        assert!(buf[3..].iter().all(|b| *b == 0));
    }

    /// At exactly `MAX_ENTRIES` the LspEntries TLV is the largest whose
    /// one-octet Length field is still exact: emit + re-parse must
    /// round-trip and the length byte must equal 15*16 = 240, not a
    /// wrapped value. Guards the cap the CSNP/PSNP builders rely on.
    #[test]
    fn lsp_entries_at_max_round_trips_with_exact_length() {
        let mut tlv = IsisTlvLspEntries::default();
        for i in 0..IsisTlvLspEntries::MAX_ENTRIES {
            tlv.entries.push(IsisLspEntry {
                hold_time: 1200,
                lsp_id: IsisLspId::new(
                    IsisSysId {
                        id: [0, 0, 0, 0, 0, i as u8],
                    },
                    0,
                    0,
                ),
                seq_number: 1,
                checksum: 0,
            });
        }
        assert_eq!(tlv.len() as usize, IsisTlvLspEntries::MAX_ENTRIES * 16);

        let mut buf = BytesMut::new();
        tlv.tlv_emit(&mut buf);
        // T(1) + L(1) + 15 * 16 value bytes.
        assert_eq!(buf.len(), 2 + IsisTlvLspEntries::MAX_ENTRIES * 16);
        assert_eq!(buf[1] as usize, IsisTlvLspEntries::MAX_ENTRIES * 16);

        let (rest, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
        assert!(rest.is_empty());
        match &tlvs[0] {
            IsisTlv::LspEntries(v) => {
                assert_eq!(v.entries.len(), IsisTlvLspEntries::MAX_ENTRIES)
            }
            other => panic!("expected LspEntries, got {:?}", other),
        }
    }

    /// Documents *why* callers must cap at `MAX_ENTRIES`: one entry past
    /// the limit makes the one-octet length byte disagree with the value
    /// bytes emit() writes (16 entries = 256 bytes, len() wraps to 0),
    /// which is exactly the CSNP/PSNP wire-corruption this cap prevents.
    #[test]
    fn lsp_entries_over_max_wraps_length_byte() {
        let mut tlv = IsisTlvLspEntries::default();
        for _ in 0..(IsisTlvLspEntries::MAX_ENTRIES + 1) {
            tlv.entries.push(IsisLspEntry::default());
        }
        // 16 * 16 = 256 -> wraps to 0 in the u8 length, while emit() still
        // writes all 256 value bytes.
        assert_eq!(tlv.len(), 0);
        let mut buf = BytesMut::new();
        tlv.emit(&mut buf);
        assert_eq!(buf.len(), (IsisTlvLspEntries::MAX_ENTRIES + 1) * 16);
    }

    /// An auth-type value that this crate does not recognize must
    /// still survive parse+emit unchanged — the runtime layer is the
    /// one that decides whether to drop the PDU.
    #[test]
    fn auth_unknown_auth_type_preserved() {
        let original = IsisTlvAuth {
            auth_type: 42, // not in the IS-IS TLV-10 registry
            value: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let mut buf = BytesMut::new();
        original.tlv_emit(&mut buf);
        let (_, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
        match &tlvs[0] {
            IsisTlv::Auth(v) => {
                assert_eq!(v.auth_type, 42);
                assert_eq!(v.value, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            other => panic!("expected Auth, got {:?}", other),
        }
    }
}
