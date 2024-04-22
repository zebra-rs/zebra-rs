#![allow(dead_code)]
use super::{Afi, As4PathAttr, AsPathAttr, CommunityAttr, Safi};
use ipnet::Ipv6Net;
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::Ipv6Addr;

pub const BGP_ATTR_FLAG_OPTIONAL: u8 = 0x80;
pub const BGP_ATTR_FLAG_TRNANSITIVE: u8 = 0x40;
pub const BGP_ATTR_FLAG_WELL_KNOWN: u8 = 0x20;
pub const BGP_ATTR_FLAG_EXTENDED_LENGTH: u8 = 0x10;

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
        MpReachNlri = 14,
        MpUnreachNlri = 15,
    }
}

#[derive(Debug)]
pub enum Attribute {
    Origin(OriginAttr),
    AsPath(AsPathAttr),
    As4Path(As4PathAttr),
    NextHop(NextHopAttr),
    Med(MedAttr),
    LocalPref(LocalPrefAttr),
    AtomicAggregate(AtomicAggregateAttr),
    Aggregator(AggregatorAttr),
    Aggregator4(Aggregator4Attr),
    Community(CommunityAttr),
    MpReachNlri(MpNlriAttr),
    MpUnreachNlri(MpNlriAttr),
}

pub type Attrs = Vec<Attribute>;

#[derive(Debug, NomBE)]
pub struct AttributeHeader {
    pub flags: u8,
    pub type_code: u8,
}

impl AttributeHeader {
    pub fn is_extended(&self) -> bool {
        (self.flags & BGP_ATTR_FLAG_EXTENDED_LENGTH) != 0
    }
}

#[derive(Debug, NomBE)]
pub struct OriginAttr {
    pub origin: u8,
}

#[derive(Debug, NomBE)]
pub struct NextHopAttr {
    pub next_hop: [u8; 4],
}

#[derive(Debug, NomBE)]
pub struct MedAttr {
    pub med: u32,
}

#[derive(Debug, NomBE)]
pub struct LocalPrefAttr {
    pub local_pref: u32,
}

#[derive(Debug, NomBE)]
pub struct AtomicAggregateAttr {}

#[derive(Debug, NomBE)]
pub struct AggregatorAttr {
    pub asn: u16,
    pub ip: u32,
}

#[derive(Debug, NomBE)]
pub struct Aggregator4Attr {
    pub asn: u32,
    pub ip: u32,
}

#[derive(Debug, NomBE)]
pub struct MpNlriReachHeader {
    pub afi: Afi,
    pub safi: Safi,
    pub nhop_len: u8,
}

#[derive(Debug, NomBE)]
pub struct MpNlriUnreachHeader {
    pub afi: Afi,
    pub safi: Safi,
}

#[derive(Debug)]
pub struct MpNlriAttr {
    pub next_hop: Option<Ipv6Addr>,
    pub prefix: Vec<Ipv6Net>,
}
