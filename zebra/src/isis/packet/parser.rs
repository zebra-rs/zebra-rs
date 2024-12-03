use std::{
    fmt::{Display, Formatter, Result},
    net::Ipv4Addr,
    process::exit,
};

use nom::bytes::complete::take;
use nom::{
    error::{make_error, ErrorKind},
    number::complete::{be_u32, be_u8},
    {Err, IResult, Needed},
};
use nom_derive::*;

use crate::bgp::packet::many0;

const ISIS_IRDP_DISC: u8 = 0x83;

// IS-IS PDU Types.
const ISIS_L1LAN_IIH_PDU: u8 = 0x0F; // L1LAN IIH Pdu Type
const ISIS_L2LAN_IIH_PDU: u8 = 0x10; // L2LAN IIH Pdu Type
const ISIS_P2P_IIH_PDU: u8 = 0x11; // P2P IIH Pdu Type
const ISIS_L1LSP_PDU: u8 = 0x12; // L1LSP Pdu Type
const ISIS_L2LSP_PDU: u8 = 0x14; // L2LSP Pdu Type

#[derive(Debug, PartialEq, Eq, Clone, Copy, NomBE)]
pub struct IsisPduType(pub u8);

#[derive(Debug)]
pub enum IsisPacket {
    Hello(IsisHello),
    L1Lsp(IsisL1Lsp),
}

#[derive(Debug, NomBE)]
pub struct IsisHeader {
    discriminator: u8,
    length_indicator: u8,
    id_extension: u8,
    id_length: u8,
    pdu_type: IsisPduType,
    version: u8,
    reserved: u8,
    max_area_addr: u8,
}

impl Display for IsisHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"Interdomain Routing Protocol Discreminator: ISIS (0x{:x})
 Length Indicator: {}
 Version/Protocol ID Extension: {}
 ID Length: {}
 PDU Type: 0x{:x}
 Reserved: {}
 Maximum Area Address: {}"#,
            self.discriminator,
            self.length_indicator,
            self.id_extension,
            self.id_length,
            self.pdu_type.0,
            self.reserved,
            self.max_area_addr
        )
    }
}

// L1 LSP TLVs.
const ISIS_AREA_ADDR_TLV: u8 = 1;
const ISIS_EXT_IS_REACH_TLV: u8 = 22;
const ISIS_PROT_SUPPORTED_TLV: u8 = 129;
const ISIS_IPV4IF_ADDR_TLV: u8 = 132;
const ISIS_TE_ROUTER_ID_TLV: u8 = 134;
const ISIS_DYNAMIC_HOSTNAME_TLV: u8 = 137;
const ISIS_IPV6IF_ADDR_TLV: u8 = 232;
const ISIS_ROUTER_CAP_TLV: u8 = 242;

// L1 LSP.
#[derive(Debug, NomBE)]
pub struct IsisL1Lsp {
    header: IsisHeader,
    pdu_length: u16,
    lifetime: u16,
    lsp_id: [u8; 8],
    seq_number: u32,
    checksum: u16,
    types: u8,
}

impl Display for IsisL1Lsp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"{}
ISIS Link State Protocol:
 PDU length: {}
 Remaining lifetime: {}
 Sequence number: {}
 Types: 0x{:x}
"#,
            self.header, self.pdu_length, self.lifetime, self.seq_number, self.types
        )
    }
}

#[derive(Debug, NomBE)]
pub struct IsisHello {
    header: IsisHeader,
    pdu_length: u16,
    lifetime: u16,
    lsp_id: [u8; 8],
}

enum IsisTlv {
    AreaAddr(IsisTlvAreaAddr),
    ExtIsReach(IsisTlvExtIsReach),
    Hostname(IsisTlvHostname),
    TeRouterId(IsisTlvTeRouterId),
    Unknown(IsisTlvUnknown),
}

#[derive(Debug)]
enum IsisSubTlv {
    Ipv4IntfAddr(IsisSubTlvIpv4IntfAddr),
}

#[derive(Debug)]
struct IsisSubTlvIpv4IntfAddr {
    //
}

#[derive(Debug)]
struct IsisTlvAreaAddr {
    area_addr: [u8; 4],
}

#[derive(Debug)]
struct IsisTlvExtIsReach {
    sub_tlvs: Vec<IsisSubTlv>,
}

#[derive(Debug)]
struct IsisTlvHostname {
    hostname: String,
}

#[derive(Debug, NomBE)]
struct IsisTlvTeRouterId {
    router_id: Ipv4Addr,
}

#[derive(Default, Debug, NomBE)]
struct IsisTlvUnknown {
    typ: u8,
    length: u8,
    values: Vec<u8>,
}

pub trait ParseBe<T> {
    fn parse_be(input: &[u8]) -> IResult<&[u8], T>;
}

impl ParseBe<Ipv4Addr> for Ipv4Addr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() != 4 {
            return Err(Err::Incomplete(Needed::new(4)));
        }
        let (input, addr) = be_u32(input)?;
        Ok((input, Self::from(addr)))
    }
}

impl ParseBe<IsisTlvAreaAddr> for IsisTlvAreaAddr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() != 4 {
            return Err(Err::Incomplete(Needed::new(4)));
        }
        let (input, area_addr) = take(4usize)(input)?;
        let area_addr = Self {
            area_addr: [area_addr[0], area_addr[1], area_addr[2], area_addr[3]],
        };
        Ok((input, area_addr))
    }
}

impl ParseBe<IsisTlvHostname> for IsisTlvHostname {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let hostname = Self {
            hostname: String::from_utf8_lossy(&input).to_string(),
        };
        Ok((input, hostname))
    }
}

fn parse_tlvs(input: &[u8]) -> IResult<&[u8], IsisTlv> {
    if input.len() < 2 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    let (input, typ) = be_u8(input)?;
    let (input, len) = be_u8(input)?;
    if input.len() < len as usize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    let (tlv, input) = input.split_at(len as usize);
    println!("XX input len {}", input.len());
    match typ {
        ISIS_AREA_ADDR_TLV => {
            let (_, area_addr) = IsisTlvAreaAddr::parse_be(tlv)?;
            Ok((input, IsisTlv::AreaAddr(area_addr)))
        }
        ISIS_DYNAMIC_HOSTNAME_TLV => {
            let (_, hostname) = IsisTlvHostname::parse_be(tlv)?;
            Ok((input, IsisTlv::Hostname(hostname)))
        }
        ISIS_TE_ROUTER_ID_TLV => {
            let (_, router_id) = IsisTlvTeRouterId::parse_be(tlv)?;
            Ok((input, IsisTlv::TeRouterId(router_id)))
        }
        _ => {
            let tlv = IsisTlvUnknown::default();
            Ok((input, IsisTlv::Unknown(tlv)))
        }
    }
}

pub fn parse_l1_lsp(input: &[u8]) -> IResult<&[u8], IsisL1Lsp> {
    let (input, packet) = IsisL1Lsp::parse(input)?;
    println!("Remaining len {}", input.len());

    let (input, tlvs) = many0(parse_tlvs)(input)?;

    Ok((input, packet))
}

pub fn parse(input: &[u8]) -> IResult<&[u8], IsisPacket> {
    if input.len() < 5 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    let pdu_type = input[4];

    match pdu_type {
        ISIS_L1LSP_PDU => {
            let (input, packet) = parse_l1_lsp(input)?;
            println!("{}", packet);
            Ok((input, IsisPacket::L1Lsp(packet)))
        }
        _ => {
            let (input, packet) = IsisL1Lsp::parse(input)?;
            Ok((input, IsisPacket::L1Lsp(packet)))
        }
    }
}

pub fn parse_test() {
    //  ISIS-all-level-1: ISIS LSP.
    let binary_data: &[u8] = &[
        0x01, 0x80, 0xC2, 0x00, 0x00, 0x14, 0x00, 0x1C, 0x42, 0xE5, 0xC4, 0x21, 0x00, 0xCE, 0xFE,
        0xFE, 0x03, 0x83, 0x1B, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00, 0xCB, 0x04, 0x8F, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9A, 0x0F, 0x44, 0x01, 0x81,
        0x01, 0xCC, 0x01, 0x04, 0x03, 0x49, 0x00, 0x00, 0x89, 0x07, 0x75, 0x62, 0x75, 0x6E, 0x74,
        0x75, 0x31, 0xF2, 0x22, 0xAC, 0x13, 0x00, 0x01, 0x00, 0x02, 0x09, 0xC0, 0x00, 0x1F, 0x40,
        0x01, 0x03, 0x00, 0x3E, 0x80, 0x13, 0x01, 0x00, 0x16, 0x09, 0x00, 0x00, 0x03, 0xE8, 0x01,
        0x03, 0x00, 0x3A, 0x98, 0x17, 0x02, 0x01, 0x08, 0x86, 0x04, 0x01, 0x01, 0x01, 0x01, 0x16,
        0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x0A, 0x19, 0x06, 0x04, 0x0B,
        0x00, 0x00, 0x01, 0x08, 0x04, 0x0B, 0x00, 0x00, 0x02, 0x20, 0x0B, 0x30, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x3A, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
        0x00, 0x0A, 0x19, 0x06, 0x04, 0x0A, 0x00, 0x00, 0x01, 0x08, 0x04, 0x0A, 0x00, 0x00, 0x03,
        0x20, 0x0B, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3A, 0x99, 0x84, 0x04,
        0xAC, 0x13, 0x00, 0x01, 0x87, 0x22, 0x00, 0x00, 0x00, 0x0A, 0x60, 0x01, 0x01, 0x01, 0x01,
        0x08, 0x03, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x0A, 0x18, 0x0B,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x18, 0x0A, 0x00, 0x00,
    ];

    // Do something with the binary data
    let ret = parse(&binary_data[17..]);
    println!("{:?}", ret);

    exit(0);
}
