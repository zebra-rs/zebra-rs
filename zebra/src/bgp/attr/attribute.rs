#![allow(dead_code)]
use crate::bgp::{Afi, Safi};
use ipnet::Ipv6Net;
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::Ipv6Addr;

use super::{
    Aggregator2, Aggregator4, As2Path, As4Path, AtomicAggregate, Community, ExtCommunity,
    LargeCommunity, LocalPref, Med, NextHopAttr, Origin,
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
        MpReachNlri = 14,
        MpUnreachNlri = 15,
        ExtendedCom = 16,
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
    MpReachNlri(MpNlriAttr),
    MpUnreachNlri(MpNlriAttr),
    ExtCommunity(ExtCommunity),
    LargeCom(LargeCommunity),
}

#[derive(Clone, Debug, NomBE)]
pub struct MpNlriReachHeader {
    pub afi: Afi,
    pub safi: Safi,
    pub nhop_len: u8,
}

#[derive(Clone, Debug, NomBE)]
pub struct MpNlriUnreachHeader {
    pub afi: Afi,
    pub safi: Safi,
}

#[derive(Clone, Debug)]
pub struct MpNlriAttr {
    pub next_hop: Option<Ipv6Addr>,
    pub prefix: Vec<Ipv6Net>,
}
