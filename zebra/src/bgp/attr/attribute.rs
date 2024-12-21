use crate::bgp::packet::{Afi2, Safi2};
use crate::bgp::{Afi, Safi};
use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::Ipv6Addr;

use super::{
    Aggregator2, Aggregator4, Aigp, As2Path, As4Path, AtomicAggregate, AttributeFlags, ClusterList,
    Community, ExtCommunity, ExtIpv6Community, LargeCommunity, LocalPref, Med, NextHopAttr, Origin,
    OriginatorId,
};

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct AttributeType(pub u8);

newtype_enum! {
    impl display AttributeType {
        Origin = 1,
        AsPath = 2,
        NextHop = 3,
        Med = 4,
        LocalPref = 5,
        AtomicAggregate = 6,
        Aggregator = 7,
        Community = 8,
        OriginatorId = 9,
        ClusterList = 10,
        MpReachNlri = 14,
        MpUnreachNlri = 15,
        ExtendedCom = 16,
        ExtendedIpv6Com = 25,
        Aigp = 26,
        LargeCom = 32,
    }
}

#[derive(Clone, Debug)]
pub enum Attribute {
    Origin(Origin),
    As2Path(As2Path),
    As4Path(As4Path),
    NextHop(NextHopAttr),
    Med(Med),
    LocalPref(LocalPref),
    AtomicAggregate(AtomicAggregate),
    Aggregator2(Aggregator2),
    Aggregator4(Aggregator4),
    Community(Community),
    OriginatorId(OriginatorId),
    ClusterList(ClusterList),
    MpReachNlri(MpNlriAttr),
    MpUnreachNlri(MpNlriAttr),
    ExtCommunity(ExtCommunity),
    ExtIpv6Community(ExtIpv6Community),
    Aigp(Aigp),
    LargeCom(LargeCommunity),
}

pub trait AttributeEncoder {
    fn attr_type() -> AttributeType;
    fn attr_flag() -> AttributeFlags;
}

pub fn encode_tlv<T: AttributeEncoder>(buf: &mut BytesMut, attr_buf: BytesMut) {
    if attr_buf.len() > 255 {
        buf.put_u8(T::attr_flag().bits() | AttributeFlags::EXTENDED.bits());
        buf.put_u8(T::attr_type().0);
        buf.put_u16(attr_buf.len() as u16)
    } else {
        buf.put_u8(T::attr_flag().bits());
        buf.put_u8(T::attr_type().0);
        buf.put_u8(attr_buf.len() as u8);
    }
    buf.put(&attr_buf[..]);
}

#[derive(Clone, Debug, NomBE)]
pub struct MpNlriReachHeader {
    pub afi: Afi2,
    pub safi: Safi2,
    pub nhop_len: u8,
}

#[derive(Clone, Debug, NomBE)]
pub struct MpNlriUnreachHeader {
    pub afi: Afi2,
    pub safi: Safi2,
}

#[derive(Clone, Debug)]
pub struct MpNlriAttr {
    pub next_hop: Option<Ipv6Addr>,
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub vpnv4_prefix: Vec<Ipv4Net>,
}
