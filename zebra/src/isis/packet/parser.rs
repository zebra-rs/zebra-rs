use std::mem;
use std::{
    fmt::{Display, Formatter, Result},
    net::Ipv4Addr,
    process::exit,
};

use nom::bytes::complete::take;
use nom::error::{make_error, ErrorKind};
use nom::number::complete::{be_u32, be_u8};
use nom::{Err, IResult, Needed};
use nom_derive::*;

use crate::bgp::packet::many0;

// IS-IS discriminator.
const ISIS_IRDP_DISC: u8 = 0x83;

// IS-IS PDU Types.
const ISIS_L1LAN_HELLO_PDU: u8 = 0x0F;
const ISIS_L2LAN_HELLO_PDU: u8 = 0x10;
const ISIS_P2P_HELLO_PDU: u8 = 0x11;
const ISIS_L1LSP_PDU: u8 = 0x12;
const ISIS_L2LSP_PDU: u8 = 0x14;

#[derive(Debug, PartialEq, Eq, Clone, Copy, NomBE)]
pub struct IsisPduType(pub u8);

#[derive(Debug, NomBE)]
pub struct IsisPacket {
    discriminator: u8,
    length_indicator: u8,
    id_extension: u8,
    id_length: u8,
    pdu_type: IsisPduType,
    version: u8,
    reserved: u8,
    max_area_addr: u8,
    #[nom(Parse = "{ |x| IsisPdu::parse_be(x, pdu_type) }")]
    pdu: IsisPdu,
}

#[derive(Debug, NomBE)]
#[nom(Selector = "IsisPduType")]
pub enum IsisPdu {
    #[nom(Selector = "IsisPduType(ISIS_L1LAN_HELLO_PDU)")]
    L1Hello(IsisHello),
    #[nom(Selector = "IsisPduType(ISIS_L1LSP_PDU)")]
    L1Lsp(IsisL1Lsp),
}

impl Display for IsisPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"Interdomain Routing Protocol Discreminator: ISIS (0x{:x})
 Length Indicator: {}
 Version/Protocol ID Extension: {}
 ID Length: {}
 PDU Type: 0x{:x}
 Version: {}
 Reserved: {}
 Maximum Area Address: {}
{}"#,
            self.discriminator,
            self.length_indicator,
            self.id_extension,
            self.id_length,
            self.pdu_type.0,
            self.version,
            self.reserved,
            self.max_area_addr,
            self.pdu,
        )
    }
}

impl Display for IsisPdu {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisPdu::*;
        match self {
            L1Hello(v) => {
                write!(f, "hello")
            }
            L1Lsp(v) => {
                write!(f, "{}", v)
            }
        }
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

#[derive(Debug)]
pub struct IsisL1Lsp {
    h: IsisL1LspHead,
    tlvs: Vec<IsisTlv>,
}

#[derive(Debug, NomBE)]
pub struct IsisL1LspHead {
    pdu_length: u16,
    lifetime: u16,
    lsp_id: [u8; 8],
    seq_number: u32,
    checksum: u16,
    types: u8,
}

impl ParseBe<IsisL1Lsp> for IsisL1Lsp {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, h) = IsisL1LspHead::parse_be(input)?;
        let (input, tlvs) = many0(IsisTlv::parse_tlvs)(input)?;
        let packet = IsisL1Lsp { h, tlvs };
        Ok((input, packet))
    }
}

impl Display for IsisL1Lsp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"IS-IS L1 LSP
 PDU length: {}
 Lifetime: {}
 Sequence number: 0x{:x}
 Checksum: 0x{:x}
 Type block: {:x}"#,
            self.h.pdu_length, self.h.lifetime, self.h.seq_number, self.h.checksum, self.h.types,
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "\n{}", tlv)?;
        }
        Ok(())
    }
}

#[derive(Debug, NomBE)]
pub struct IsisHello {
    pdu_length: u16,
    lifetime: u16,
    lsp_id: [u8; 8],
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

impl Display for IsisTlvHostname {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Hostname: {}", self.hostname)
    }
}

#[derive(Debug, NomBE)]
struct IsisTlvTeRouterId {
    router_id: Ipv4Addr,
}

impl Display for IsisTlvTeRouterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  TE Router id: {}", self.router_id)
    }
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
        if input.len() < 4 {
            return Err(Err::Incomplete(Needed::new(4)));
        }
        let (input, addr) = be_u32(input)?;
        Ok((input, Self::from(addr)))
    }
}

impl ParseBe<IsisTlvAreaAddr> for IsisTlvAreaAddr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 4 {
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

#[derive(Debug, NomBE)]
pub struct IsisTlvType(pub u8);

impl IsisTlvType {
    pub fn is_known(&self) -> bool {
        match self.0 {
            ISIS_AREA_ADDR_TLV | ISIS_TE_ROUTER_ID_TLV | ISIS_DYNAMIC_HOSTNAME_TLV => true,
            _ => false,
        }
    }
}

#[derive(NomBE)]
struct TypeLen {
    pub typ: IsisTlvType,
    pub len: u8,
}

#[derive(Debug, NomBE)]
#[nom(Selector = "IsisTlvType")]
enum IsisTlv {
    #[nom(Selector = "IsisTlvType(ISIS_AREA_ADDR_TLV)")]
    AreaAddr(IsisTlvAreaAddr),
    // #[nom(Selector = "IsisTlvType(0x12u8)")]
    // ExtIsReach(IsisTlvExtIsReach),
    #[nom(Selector = "IsisTlvType(ISIS_DYNAMIC_HOSTNAME_TLV)")]
    Hostname(IsisTlvHostname),
    #[nom(Selector = "IsisTlvType(ISIS_TE_ROUTER_ID_TLV)")]
    TeRouterId(IsisTlvTeRouterId),
    #[nom(Selector = "IsisTlvType(_)")]
    Unknown(IsisTlvUnknown),
}

impl IsisTlv {
    pub fn parse_tlvs(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < mem::size_of::<TypeLen>() {
            return Err(Err::Incomplete(Needed::new(mem::size_of::<TypeLen>())));
        }
        let (input, tl) = TypeLen::parse_be(input)?;
        if input.len() < tl.len as usize {
            return Err(Err::Incomplete(Needed::new(tl.len as usize)));
        }
        let (tlv, input) = input.split_at(tl.len as usize);
        if tl.typ.is_known() {
            let (_, val) = Self::parse_be(tlv, tl.typ)?;
            Ok((input, val))
        } else {
            let tlv = IsisTlvUnknown::default();
            Ok((input, Self::Unknown(tlv)))
        }
    }
}

impl Display for IsisTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisTlv::*;
        match self {
            Hostname(v) => write!(f, "{}", v),
            TeRouterId(v) => write!(f, "{}", v),
            _ => {
                write!(f, "  Unknown")
            }
        }
    }
}

pub fn parse(input: &[u8]) -> IResult<&[u8], IsisPacket> {
    let (input, packet) = IsisPacket::parse_be(input)?;
    println!("{}", packet);
    Ok((input, packet))
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
    let _ = parse(&binary_data[17..]);

    exit(0);
}
