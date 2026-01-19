use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom::number::complete::{be_u8, be_u16, be_u24, be_u32};
use nom::{Err, IResult, Needed};
use nom_derive::*;
use serde::{Deserialize, Serialize};

use crate::util::{ParseBe, TlvEmitter, u32_u8_3};
use crate::{Algo, IsisTlv, IsisTlvType, many0_complete};

use super::{IsisCapCode, IsisCodeLen, IsisSubTlvUnknown};

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisCapCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisCapCode::SegmentRoutingCap")]
    SegmentRoutingCap(IsisSubSegmentRoutingCap),
    #[nom(Selector = "IsisCapCode::SegmentRoutingAlgo")]
    SegmentRoutingAlgo(IsisSubSegmentRoutingAlgo),
    #[nom(Selector = "IsisCapCode::SegmentRoutingLb")]
    SegmentRoutingLB(IsisSubSegmentRoutingLB),
    #[nom(Selector = "IsisCapCode::NodeMaxSidDepth")]
    NodeMaxSidDepth(IsisSubNodeMaxSidDepth),
    #[nom(Selector = "IsisCapCode::Srv6")]
    Srv6(IsisSubSrv6),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

impl IsisSubTlv {
    pub fn parse_subs(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cl) = IsisCodeLen::parse_be(input)?;
        if input.len() < cl.len as usize {
            return Err(Err::Incomplete(Needed::new(cl.len as usize)));
        }
        let (sub, input) = input.split_at(cl.len as usize);
        let (_, mut val) = Self::parse_be(sub, cl.code.into())?;
        if let IsisSubTlv::Unknown(ref mut v) = val {
            v.code = cl.code;
            v.len = cl.len;
        }
        Ok((input, val))
    }

    pub fn len(&self) -> u8 {
        use IsisSubTlv::*;
        match self {
            SegmentRoutingCap(v) => v.len(),
            SegmentRoutingAlgo(v) => v.len(),
            SegmentRoutingLB(v) => v.len(),
            NodeMaxSidDepth(v) => v.len(),
            Srv6(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            SegmentRoutingCap(v) => v.tlv_emit(buf),
            SegmentRoutingAlgo(v) => v.tlv_emit(buf),
            SegmentRoutingLB(v) => v.tlv_emit(buf),
            NodeMaxSidDepth(v) => v.tlv_emit(buf),
            Srv6(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SidLabelTlv {
    Label(u32),
    Index(u32),
}

impl SidLabelTlv {
    pub fn len(&self) -> u8 {
        use SidLabelTlv::*;
        match self {
            Label(_) => 3,
            Index(_) => 4,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use SidLabelTlv::*;
        buf.put_u8(1); // RFC8667 2.3. SID/Label Type is always 1.
        buf.put_u8(self.len());
        match self {
            Label(v) => buf.put(&u32_u8_3(*v)[..]),
            Index(v) => buf.put_u32(*v),
        }
    }
}

pub fn parse_sid_label(input: &[u8]) -> IResult<&[u8], SidLabelTlv> {
    let (input, _typ) = be_u8(input)?;
    let (input, len) = be_u8(input)?;
    match len {
        3 => {
            let (input, label) = be_u24(input)?;
            Ok((input, SidLabelTlv::Label(label)))
        }
        4 => {
            let (input, index) = be_u32(input)?;
            Ok((input, SidLabelTlv::Index(index)))
        }
        _ => Err(Err::Incomplete(Needed::new(len as usize))),
    }
}

#[bitfield(u8, debug = true)]
#[derive(Serialize, Deserialize, PartialEq)]
pub struct SegmentRoutingCapFlags {
    #[bits(6)]
    pub resvd: u8,
    pub v_flag: bool,
    pub i_flag: bool,
}

impl ParseBe<SegmentRoutingCapFlags> for SegmentRoutingCapFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSegmentRoutingCap {
    pub flags: SegmentRoutingCapFlags,
    #[nom(Parse = "be_u24")]
    pub range: u32,
    #[nom(Parse = "parse_sid_label")]
    pub sid_label: SidLabelTlv,
}

impl TlvEmitter for IsisSubSegmentRoutingCap {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingCap.into()
    }

    fn len(&self) -> u8 {
        // Flags: 1 + Range: 3 + SID Type:1 + SID Length: 1 + SID.
        1 + 3 + 1 + 1 + self.sid_label.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put(&u32_u8_3(self.range)[..]);
        self.sid_label.emit(buf);
    }
}

impl From<IsisSubSegmentRoutingCap> for IsisSubTlv {
    fn from(sub: IsisSubSegmentRoutingCap) -> Self {
        IsisSubTlv::SegmentRoutingCap(sub)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSegmentRoutingAlgo {
    pub algo: Vec<Algo>,
}

impl ParseBe<IsisSubSegmentRoutingAlgo> for IsisSubSegmentRoutingAlgo {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, algo) = many0_complete(Algo::parse_be).parse(input)?;
        Ok((input, Self { algo }))
    }
}

impl TlvEmitter for IsisSubSegmentRoutingAlgo {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingAlgo.into()
    }

    fn len(&self) -> u8 {
        self.algo.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        for algo in self.algo.clone() {
            buf.put_u8(algo.into());
        }
    }
}

impl From<IsisSubSegmentRoutingAlgo> for IsisSubTlv {
    fn from(sub: IsisSubSegmentRoutingAlgo) -> Self {
        IsisSubTlv::SegmentRoutingAlgo(sub)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSegmentRoutingLB {
    pub flags: u8,
    #[nom(Parse = "be_u24")]
    pub range: u32,
    #[nom(Parse = "parse_sid_label")]
    pub sid_label: SidLabelTlv,
}

impl TlvEmitter for IsisSubSegmentRoutingLB {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingLb.into()
    }

    fn len(&self) -> u8 {
        // Flags: 1 + Range: 3 + SID Type:1 + SID Length: 1 + SID.
        1 + 3 + 1 + 1 + self.sid_label.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put(&u32_u8_3(self.range)[..]);
        self.sid_label.emit(buf);
    }
}

impl From<IsisSubSegmentRoutingLB> for IsisSubTlv {
    fn from(sub: IsisSubSegmentRoutingLB) -> Self {
        IsisSubTlv::SegmentRoutingLB(sub)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubNodeMaxSidDepth {
    pub flags: u8,
    pub depth: u8,
}

impl TlvEmitter for IsisSubNodeMaxSidDepth {
    fn typ(&self) -> u8 {
        IsisCapCode::NodeMaxSidDepth.into()
    }

    fn len(&self) -> u8 {
        2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.depth);
    }
}

#[bitfield(u8, debug = true)]
#[derive(Serialize, Deserialize, PartialEq)]
pub struct RouterCapFlags {
    #[bits(6)]
    pub resvd: u8,
    pub d_flag: bool,
    pub s_flag: bool,
}

impl ParseBe<RouterCapFlags> for RouterCapFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvRouterCap {
    pub router_id: Ipv4Addr,
    pub flags: RouterCapFlags,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl ParseBe<IsisTlvRouterCap> for IsisTlvRouterCap {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, router_id) = Ipv4Addr::parse_be(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, subs) = many0_complete(IsisSubTlv::parse_subs).parse(input)?;
        let tlv = Self {
            router_id,
            flags: flags.into(),
            subs,
        };
        Ok((input, tlv))
    }
}

impl IsisTlvRouterCap {
    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
    }
}

impl TlvEmitter for IsisTlvRouterCap {
    fn typ(&self) -> u8 {
        IsisTlvType::RouterCap.into()
    }

    fn len(&self) -> u8 {
        5 + self.sub_len()
    }

    fn emit(&self, buf: &mut bytes::BytesMut) {
        buf.put(&self.router_id.octets()[..]);
        buf.put_u8(self.flags.into());
        self.subs.iter().for_each(|sub| sub.emit(buf));
    }
}

impl From<IsisTlvRouterCap> for IsisTlv {
    fn from(tlv: IsisTlvRouterCap) -> Self {
        IsisTlv::RouterCap(tlv)
    }
}

#[bitfield(u16, debug = true)]
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Srv6Flags {
    #[bits(14)]
    pub resvd2: u16,
    pub o_flag: bool,
    pub resvd1: bool,
}

impl ParseBe<Srv6Flags> for Srv6Flags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u16(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSrv6 {
    pub flags: Srv6Flags,
}

impl TlvEmitter for IsisSubSrv6 {
    fn typ(&self) -> u8 {
        IsisCapCode::Srv6.into()
    }

    fn len(&self) -> u8 {
        2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flags.into());
    }
}
