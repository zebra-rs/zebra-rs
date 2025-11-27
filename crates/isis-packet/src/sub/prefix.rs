use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{Err, IResult, Needed};
use nom_derive::*;
use serde::{Deserialize, Serialize};

use crate::util::{ParseBe, TlvEmitter, many0};
use crate::{Algo, IsisTlv, IsisTlvType, SidLabelValue};

use super::{Behavior, IsisCodeLen, IsisPrefixCode, IsisSrv6SidSub2Code, IsisSubTlvUnknown};

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisPrefixCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisPrefixCode::PrefixSid")]
    PrefixSid(IsisSubPrefixSid),
    #[nom(Selector = "IsisPrefixCode::Srv6EndSid")]
    Srv6EndSid(IsisSubSrv6EndSid),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

#[bitfield(u8, debug = true)]
#[derive(Serialize, Deserialize, PartialEq)]
pub struct PrefixSidFlags {
    #[bits(2)]
    pub resvd: u8,
    pub l_flag: bool,
    pub v_flag: bool,
    pub e_flag: bool,
    pub p_flag: bool,
    pub n_flag: bool,
    pub r_flag: bool,
}

impl ParseBe<PrefixSidFlags> for PrefixSidFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubPrefixSid {
    pub flags: PrefixSidFlags,
    pub algo: Algo,
    pub sid: SidLabelValue,
}

impl TlvEmitter for IsisSubPrefixSid {
    fn typ(&self) -> u8 {
        IsisPrefixCode::PrefixSid.into()
    }

    fn len(&self) -> u8 {
        2 + self.sid.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(self.algo.into());
        self.sid.emit(buf);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSrv6EndSid {
    pub flags: u8,
    pub behavior: Behavior,
    pub sid: Ipv6Addr,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub2s: Vec<IsisSub2Tlv>,
}

impl ParseBe<IsisSubSrv6EndSid> for IsisSubSrv6EndSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, behavior) = be_u16(input)?;
        let (input, sid) = Ipv6Addr::parse_be(input)?;
        let (input, sub2_len) = be_u8(input)?;
        let mut sub = Self {
            flags,
            behavior: behavior.into(),
            sid,
            sub2s: vec![],
        };
        if sub2_len == 0 {
            return Ok((input, sub));
        }
        let (_, sub2s) = many0(IsisSub2Tlv::parse_subs)(input)?;
        sub.sub2s = sub2s;
        Ok((input, sub))
    }
}

impl TlvEmitter for IsisSubSrv6EndSid {
    fn typ(&self) -> u8 {
        IsisPrefixCode::Srv6EndSid.into()
    }

    fn len(&self) -> u8 {
        // Flags(1)+Behavior(2)+Sid(16)+Sub2Len(1)+Sub2
        let len: u8 = self.sub2s.iter().map(|sub| sub.len() + 2).sum();
        1 + 2 + 16 + 1 + len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u16(self.behavior.into());
        buf.put(&self.sid.octets()[..]);
        // Temporary Sub-Sub TLVs.
        buf.put_u8(0);
        let pp = buf.len();
        for sub2 in &self.sub2s {
            sub2.emit(buf);
        }
        buf[pp - 1] = (buf.len() - pp) as u8;
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSub2SidStructure {
    pub lb_len: u8,
    pub ln_len: u8,
    pub fun_len: u8,
    pub arg_len: u8,
}

impl TlvEmitter for IsisSub2SidStructure {
    fn typ(&self) -> u8 {
        IsisSrv6SidSub2Code::SidStructure.into()
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.lb_len);
        buf.put_u8(self.ln_len);
        buf.put_u8(self.fun_len);
        buf.put_u8(self.arg_len);
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisSrv6SidSub2Code")]
pub enum IsisSub2Tlv {
    #[nom(Selector = "IsisSrv6SidSub2Code::SidStructure")]
    SidStructure(IsisSub2SidStructure),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

impl IsisSub2Tlv {
    pub fn parse_subs(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cl) = IsisCodeLen::parse_be(input)?;
        if input.len() < cl.len as usize {
            return Err(Err::Incomplete(Needed::new(cl.len as usize)));
        }
        let (sub, input) = input.split_at(cl.len as usize);
        let (_, mut val) = Self::parse_be(sub, cl.code.into())?;
        if let IsisSub2Tlv::Unknown(ref mut v) = val {
            v.code = cl.code;
            v.len = cl.len;
        }
        Ok((input, val))
    }

    pub fn len(&self) -> u8 {
        use IsisSub2Tlv::*;
        match self {
            SidStructure(v) => v.len(),
            Unknown(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSub2Tlv::*;
        match self {
            SidStructure(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
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
            PrefixSid(v) => v.len(),
            Srv6EndSid(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            PrefixSid(v) => v.tlv_emit(buf),
            Srv6EndSid(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

#[bitfield(u8, debug = true)]
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Ipv4ControlInfo {
    #[bits(6)]
    pub prefixlen: usize,
    pub sub_tlv: bool,
    pub distribution: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvExtIpReach {
    pub entries: Vec<IsisTlvExtIpReachEntry>,
}

impl ParseBe<IsisTlvExtIpReach> for IsisTlvExtIpReach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = many0(IsisTlvExtIpReachEntry::parse_be)(input)?;
        Ok((input, Self { entries }))
    }
}

impl TlvEmitter for IsisTlvExtIpReach {
    fn typ(&self) -> u8 {
        IsisTlvType::ExtIpReach.into()
    }

    fn len(&self) -> u8 {
        self.entries.iter().map(|entry| entry.len()).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        println!("IsisTlvExtIpReach emit");
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

impl From<IsisTlvExtIpReach> for IsisTlv {
    fn from(tlv: IsisTlvExtIpReach) -> Self {
        IsisTlv::ExtIpReach(tlv)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvMtIpReach {
    pub mt: MultiTopologyId,
    pub entries: Vec<IsisTlvExtIpReachEntry>,
}

impl ParseBe<IsisTlvMtIpReach> for IsisTlvMtIpReach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mt) = be_u16(input)?;
        let (input, entries) = many0(IsisTlvExtIpReachEntry::parse_be)(input)?;
        Ok((
            input,
            Self {
                mt: mt.into(),
                entries,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvMtIpReach {
    fn typ(&self) -> u8 {
        IsisTlvType::MtIpReach.into()
    }

    fn len(&self) -> u8 {
        let len: u8 = self.entries.iter().map(|entry| entry.len()).sum();
        len + 2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.mt.into());
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvExtIpReachEntry {
    pub metric: u32,
    pub flags: Ipv4ControlInfo,
    pub prefix: Ipv4Net,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl IsisTlvExtIpReachEntry {
    fn len(&self) -> u8 {
        if self.subs.is_empty() {
            // Metric:4 + Flags:1 + Prefix.
            4 + 1 + (psize(self.prefix.prefix_len()) as u8)
        } else {
            // Metric:4 + Flags:1 + Prefix + Sub TLV length + Sub TLV.
            4 + 1 + (psize(self.prefix.prefix_len()) as u8) + 1 + self.sub_len()
        }
    }

    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.metric);
        buf.put_u8(self.flags.into());
        let plen = psize(self.prefix.prefix_len());
        if plen != 0 {
            buf.put(&self.prefix.addr().octets()[..plen]);
        }
        if self.subs.is_empty() {
            return;
        }
        buf.put_u8(self.sub_len());
        for sub in self.subs.iter() {
            sub.emit(buf);
        }
    }

    pub fn prefix_sid(&self) -> Option<IsisSubPrefixSid> {
        for sub in self.subs.iter() {
            if let IsisSubTlv::PrefixSid(prefix_sid) = sub {
                return Some(prefix_sid.clone());
            }
        }
        None
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIpv6Reach {
    pub entries: Vec<IsisTlvIpv6ReachEntry>,
}

impl ParseBe<IsisTlvIpv6Reach> for IsisTlvIpv6Reach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = many0(IsisTlvIpv6ReachEntry::parse_be)(input)?;
        Ok((input, Self { entries }))
    }
}

impl TlvEmitter for IsisTlvIpv6Reach {
    fn typ(&self) -> u8 {
        IsisTlvType::Ipv6Reach.into()
    }

    fn len(&self) -> u8 {
        self.entries.iter().map(|entry| entry.len()).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

impl From<IsisTlvIpv6Reach> for IsisTlv {
    fn from(tlv: IsisTlvIpv6Reach) -> Self {
        IsisTlv::Ipv6Reach(tlv)
    }
}

#[bitfield(u16, debug = true)]
#[derive(Serialize, Deserialize, PartialEq)]
pub struct MultiTopologyId {
    #[bits(4)]
    pub resvd: u8,
    #[bits(12)]
    pub id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvMtIpv6Reach {
    pub mt: MultiTopologyId,
    pub entries: Vec<IsisTlvIpv6ReachEntry>,
}

impl ParseBe<IsisTlvMtIpv6Reach> for IsisTlvMtIpv6Reach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mt) = be_u16(input)?;
        let (input, entries) = many0(IsisTlvIpv6ReachEntry::parse_be)(input)?;
        Ok((
            input,
            Self {
                mt: mt.into(),
                entries,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvMtIpv6Reach {
    fn typ(&self) -> u8 {
        IsisTlvType::MtIpv6Reach.into()
    }

    fn len(&self) -> u8 {
        let len: u8 = self.entries.iter().map(|entry| entry.len()).sum();
        len + 2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.mt.into());
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

#[bitfield(u8, debug = true)]
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Ipv6ControlInfo {
    #[bits(5)]
    pub resvd: usize,
    pub sub_tlv: bool,
    pub dist_internal: bool,
    pub dist_up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIpv6ReachEntry {
    pub metric: u32,
    pub flags: Ipv6ControlInfo,
    pub prefix: Ipv6Net,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl IsisTlvIpv6ReachEntry {
    fn len(&self) -> u8 {
        if self.subs.is_empty() {
            // Metric:4 + Flags:1 + Prefixlen:1.
            4 + 1 + 1 + (psize(self.prefix.prefix_len()) as u8)
        } else {
            // Metric:4 + Flags:1 + Prefix len:1 + Sub TLV length + Sub TLV.
            4 + 1 + 1 + (psize(self.prefix.prefix_len()) as u8) + 1 + self.sub_len()
        }
    }

    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.metric);
        buf.put_u8(self.flags.into());
        buf.put_u8(self.prefix.prefix_len());
        let plen = psize(self.prefix.prefix_len());
        if plen != 0 {
            buf.put(&self.prefix.addr().octets()[..plen]);
        }
        if self.subs.is_empty() {
            return;
        }
        buf.put_u8(self.sub_len());
        for sub in &self.subs {
            sub.emit(buf);
        }
    }
}

pub fn psize(plen: u8) -> usize {
    // From Rust 1.73 we can use .dev_ceil()
    // ((plen + 7) / 8) as usize
    (plen as usize).div_ceil(8)
}

pub fn ptake(input: &[u8], prefixlen: u8) -> IResult<&[u8], Ipv4Net> {
    if prefixlen == 0 {
        return Ok((input, Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()));
    }
    let psize = psize(prefixlen);
    if input.len() < psize {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    }
    let mut addr = [0u8; 4];
    addr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let Ok(prefix) = Ipv4Net::new(Ipv4Addr::from(addr), prefixlen) else {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    };
    Ok((input, prefix))
}

pub fn ptakev6(input: &[u8], prefixlen: u8) -> IResult<&[u8], Ipv6Net> {
    if prefixlen == 0 {
        return Ok((input, Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()));
    }
    let psize = psize(prefixlen);
    if input.len() < psize {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    }
    let mut addr = [0u8; 16];
    addr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let Ok(prefix) = Ipv6Net::new(Ipv6Addr::from(addr), prefixlen) else {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    };
    Ok((input, prefix))
}

impl ParseBe<IsisTlvExtIpReachEntry> for IsisTlvExtIpReachEntry {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let flags: Ipv4ControlInfo = flags.into();
        let (input, prefix) = ptake(input, flags.prefixlen() as u8)?;
        let mut tlv = Self {
            metric,
            flags,
            prefix,
            subs: Vec::new(),
        };
        if !flags.sub_tlv() {
            return Ok((input, tlv));
        }
        let (input, sublen) = be_u8(input)?;
        let (sub, input) = input.split_at(sublen as usize);
        let (_, subs) = many0(IsisSubTlv::parse_subs)(sub)?;
        tlv.subs = subs;
        Ok((input, tlv))
    }
}

impl ParseBe<IsisTlvIpv6ReachEntry> for IsisTlvIpv6ReachEntry {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let flags: Ipv6ControlInfo = flags.into();
        let (input, prefixlen) = be_u8(input)?;
        let (input, prefix) = ptakev6(input, prefixlen)?;
        let mut tlv = Self {
            metric,
            flags,
            prefix,
            subs: Vec::new(),
        };
        if !flags.sub_tlv() {
            return Ok((input, tlv));
        }
        let (input, sublen) = be_u8(input)?;
        let (sub, input) = input.split_at(sublen as usize);
        let (_, subs) = many0(IsisSubTlv::parse_subs)(sub)?;
        tlv.subs = subs;
        Ok((input, tlv))
    }
}

#[bitfield(u16, debug = true)]
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Srv6TlvFlags {
    #[bits(4)]
    pub resvd: u8,
    #[bits(12)]
    pub v_flag: u16,
}

impl ParseBe<Srv6TlvFlags> for Srv6TlvFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u16(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Srv6Locator {
    pub metric: u32,
    pub flags: u8,
    pub algo: Algo,
    pub locator: Ipv6Net,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl Srv6Locator {
    fn len(&self) -> u8 {
        // Metric(4)+Flags(1)+Algo(1)+Locator(16)+SubLen(1)+Subs
        let sub_len: u8 = self.subs.iter().map(|sub| sub.len() + 2).sum();
        4 + 1 + 1 + 1 + (psize(self.locator.prefix_len()) as u8) + 1 + sub_len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.metric);
        buf.put_u8(self.flags);
        buf.put_u8(self.algo.into());
        buf.put_u8(self.locator.prefix_len());
        let plen = psize(self.locator.prefix_len());
        if plen != 0 {
            buf.put(&self.locator.addr().octets()[..plen]);
        }
        // Temporary sub TLVs len.
        buf.put_u8(0);
        let pp = buf.len();
        for sub in &self.subs {
            sub.emit(buf);
        }
        buf[pp - 1] = (buf.len() - pp) as u8;
    }
}

impl ParseBe<Srv6Locator> for Srv6Locator {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, algo) = be_u8(input)?;
        let (input, prefixlen) = be_u8(input)?;
        let (input, locator) = ptakev6(input, prefixlen)?;
        let mut tlv = Self {
            metric,
            flags,
            algo: algo.into(),
            locator,
            subs: Vec::new(),
        };
        let (input, sublen) = be_u8(input)?;
        if sublen == 0 {
            return Ok((input, tlv));
        }
        let (sub, input) = input.split_at(sublen as usize);
        let (_, subs) = many0(IsisSubTlv::parse_subs)(sub)?;
        tlv.subs = subs;
        Ok((input, tlv))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvSrv6 {
    pub flags: Srv6TlvFlags,
    pub locators: Vec<Srv6Locator>,
}

impl ParseBe<IsisTlvSrv6> for IsisTlvSrv6 {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u16(input)?;
        let (input, locators) = many0(Srv6Locator::parse_be)(input)?;
        Ok((
            input,
            Self {
                flags: flags.into(),
                locators,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvSrv6 {
    fn typ(&self) -> u8 {
        IsisTlvType::Srv6.into()
    }

    fn len(&self) -> u8 {
        let len: u8 = self.locators.iter().map(|locator| locator.len()).sum();
        len + 2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flags.into());
        for locator in &self.locators {
            locator.emit(buf);
        }
    }
}
