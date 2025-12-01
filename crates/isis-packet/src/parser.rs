use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u24, be_u32, be_u128};
use nom::{AsBytes, Err, IResult, Needed};
use nom_derive::*;
use serde::{Deserialize, Serialize, Serializer};
use strum_macros::Display;

use super::checksum_calc;
use super::util::{ParseBe, TlvEmitter, many0, u32_u8_3};
use super::{
    IsisTlvExtIpReach, IsisTlvExtIsReach, IsisTlvIpv6Reach, IsisTlvMtIpReach, IsisTlvMtIpv6Reach,
    IsisTlvRouterCap, IsisTlvSrv6, IsisTlvType, IsisType,
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
            Unknown(_) => {}
        }
        if self.pdu_type.is_lsp() {
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
#[derive(Serialize, Deserialize)]
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
        println!("IsisLsp emit");
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
    #[nom(Selector = "IsisTlvType::ExtIsReach")]
    ExtIsReach(IsisTlvExtIsReach),
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
    #[nom(Selector = "IsisTlvType::DynamicHostname")]
    Hostname(IsisTlvHostname),
    #[nom(Selector = "IsisTlvType::Ipv6TeRouterId")]
    Ipv6TeRouterId(IsisTlvIpv6TeRouterId),
    #[nom(Selector = "IsisTlvType::Ipv6IfAddr")]
    Ipv6IfAddr(IsisTlvIpv6IfAddr),
    #[nom(Selector = "IsisTlvType::Ipv6GlobalIfAddr")]
    Ipv6GlobalIfAddr(IsisTlvIpv6GlobalIfAddr),
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
    #[nom(Selector = "_")]
    Unknown(IsisTlvUnknown),
}

impl IsisTlv {
    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisTlv::*;
        match self {
            AreaAddr(v) => v.tlv_emit(buf),
            IsNeighbor(v) => v.tlv_emit(buf),
            Padding(v) => v.tlv_emit(buf),
            LspEntries(v) => v.tlv_emit(buf),
            ExtIsReach(v) => v.tlv_emit(buf),
            Srv6(v) => v.tlv_emit(buf),
            ProtoSupported(v) => v.tlv_emit(buf),
            Ipv4IfAddr(v) => v.tlv_emit(buf),
            TeRouterId(v) => v.tlv_emit(buf),
            ExtIpReach(v) => v.tlv_emit(buf),
            Hostname(v) => v.tlv_emit(buf),
            Ipv6TeRouterId(v) => v.tlv_emit(buf),
            Ipv6IfAddr(v) => v.tlv_emit(buf),
            Ipv6GlobalIfAddr(v) => v.tlv_emit(buf),
            MtIpReach(v) => v.tlv_emit(buf),
            Ipv6Reach(v) => v.tlv_emit(buf),
            MtIpv6Reach(v) => v.tlv_emit(buf),
            P2p3Way(v) => v.tlv_emit(buf),
            RouterCap(v) => v.tlv_emit(buf),
            Unknown(v) => v.emit(buf),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvAreaAddr {
    pub area_addr: Vec<u8>,
}

impl TlvEmitter for IsisTlvAreaAddr {
    fn typ(&self) -> u8 {
        IsisTlvType::AreaAddr.into()
    }

    fn len(&self) -> u8 {
        (self.area_addr.len() + 1) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.area_addr.len() as u8);
        buf.put(&self.area_addr[..]);
    }
}

impl ParseBe<IsisTlvAreaAddr> for IsisTlvAreaAddr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, len) = be_u8(input)?;
        let (input, addr) = take(len)(input)?;
        let area_addr = Self {
            area_addr: addr.to_vec(),
        };
        Ok((input, area_addr))
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

impl TlvEmitter for IsisTlvIsNeighbor {
    fn typ(&self) -> u8 {
        IsisTlvType::IsNeighbor.into()
    }

    fn len(&self) -> u8 {
        (self.neighbors.len() * 6) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        for neighbor in self.neighbors.iter() {
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
        self.padding.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.padding[..]);
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

impl TlvEmitter for IsisTlvLspEntries {
    fn typ(&self) -> u8 {
        IsisTlvType::LspEntries.into()
    }

    fn len(&self) -> u8 {
        (self.entries.len() * std::mem::size_of::<IsisLspEntry>()) as u8
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
        self.nlpids.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(self.nlpids.as_bytes());
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
        self.hostname.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(self.hostname.as_bytes());
    }
}

impl From<IsisTlvHostname> for IsisTlv {
    fn from(tlv: IsisTlvHostname) -> Self {
        IsisTlv::Hostname(tlv)
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvP2p3Way {
    pub state: u8,
    pub circuit_id: u32,
    pub neighbor_id: Option<IsisSysId>,
    pub neighbor_circuit_id: Option<u32>,
}

impl ParseBe<IsisTlvP2p3Way> for IsisTlvP2p3Way {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, state) = be_u8(input)?;
        let (input, circuit_id) = be_u32(input)?;
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
        let mut len = 1 + 4;
        if self.neighbor_id.is_some() {
            len += 6;
        }
        if self.neighbor_circuit_id.is_some() {
            len += 4;
        }
        len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.state);
        buf.put_u32(self.circuit_id);
        if let Some(neighbor_id) = &self.neighbor_id {
            buf.put(&neighbor_id.id[..]);
        }
        if let Some(neighbor_circuit_id) = self.neighbor_circuit_id {
            buf.put_u32(neighbor_circuit_id);
        }
    }
}

impl From<IsisTlvP2p3Way> for IsisTlv {
    fn from(tlv: IsisTlvP2p3Way) -> Self {
        IsisTlv::P2p3Way(tlv)
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
            values: Vec::new(),
        };
        Ok((input, tlv))
    }
}

impl TlvEmitter for IsisTlvUnknown {
    fn typ(&self) -> u8 {
        self.typ.into()
    }

    fn len(&self) -> u8 {
        self.len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ());
        buf.put_u8(self.len);
        buf.put(self.values.as_bytes());
    }
}

impl ParseBe<Ipv4Addr> for Ipv4Addr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 4 {
            return Err(Err::Incomplete(Needed::new(4)));
        }
        let (input, addr) = be_u32(input)?;
        Ok((input, Self::from(addr)))
    }
}

impl ParseBe<Ipv6Addr> for Ipv6Addr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 16 {
            return Err(Err::Incomplete(Needed::new(4)));
        }
        let (input, bits) = be_u128(input)?;
        Ok((input, Self::from_bits(bits)))
    }
}

impl ParseBe<IsisTlvHostname> for IsisTlvHostname {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let hostname = Self {
            hostname: String::from_utf8_lossy(input).to_string(),
        };
        Ok((input, hostname))
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize)]
pub struct IsisUnknown {
    #[nom(Ignore)]
    pub typ: IsisType,
    pub payload: Vec<u8>,
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
            Label(v) => buf.put(&u32_u8_3(*v)[..]),
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
                Ok((input, SidLabelValue::Label(label)))
            }
            4 => {
                let (input, index) = be_u32(input)?;
                Ok((input, SidLabelValue::Index(index)))
            }
            _ => Err(Err::Incomplete(Needed::new(input.len()))),
        }
    }
}

impl IsisTlv {
    pub fn parse_tlv(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = IsisTypeLen::parse_be(input)?;
        if input.len() < tl.len as usize {
            return Err(Err::Incomplete(Needed::new(tl.len as usize)));
        }
        let (tlv, input) = input.split_at(tl.len as usize);
        if tl.typ.is_known() {
            let (_, val) = Self::parse_be(tlv, tl.typ)?;
            Ok((input, val))
        } else {
            let (_, val) = IsisTlvUnknown::parse_tlv(tlv, tl)?;
            Ok((input, Self::Unknown(val)))
        }
    }

    pub fn parse_tlvs(input: &[u8]) -> IResult<&[u8], Vec<Self>> {
        many0(Self::parse_tlv)(input)
    }
}

pub fn parse(input: &[u8]) -> IResult<&[u8], IsisPacket> {
    IsisPacket::parse_be(input)
}
