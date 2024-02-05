use crate::{Afi, BgpHeader, Safi};
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, NomBE)]
pub struct OpenPacket {
    pub header: BgpHeader,
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub bgp_id: [u8; 4],
    pub opt_parm_len: u8,
    #[nom(Ignore)]
    pub caps: Vec<CapabilityPacket>,
}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct CapabilityType(pub u8);

newtype_enum! {
    impl display CapabilityType {
        MultiProtocol = 1,
        RouteRefresh = 2,
        GracefulRestart = 64,
        As4 = 65,
        RouteRefreshCisco = 128,
    }
}

#[derive(Debug, PartialEq)]
pub enum CapabilityPacket {
    MultiProtocol(CapabilityMultiProtocol),
    RouteRefresh(CapabilityRouteRefresh),
    As4(CapabilityAs4),
    GracefulRestart(CapabilityGracefulRestart),
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityHeader {
    pub code: u8,
    pub length: u8,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityPeekHeader {
    pub header: CapabilityHeader,
    pub typ: u8,
    pub length: u8,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityMultiProtocol {
    header: CapabilityHeader,
    typ: u8,
    length: u8,
    afi: Afi,
    res: u8,
    safi: Safi,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityRouteRefresh {
    header: CapabilityHeader,
    typ: u8,
    length: u8,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityAs4 {
    header: CapabilityHeader,
    typ: u8,
    length: u8,
    asn: u32,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityGracefulRestart {
    header: CapabilityHeader,
    restart_timers: u32,
}

impl OpenPacket {
    pub fn new(header: BgpHeader, asn: u16, bgp_id: &Ipv4Addr) -> OpenPacket {
        OpenPacket {
            header,
            version: 4,
            asn,
            hold_time: 180,
            bgp_id: bgp_id.octets(),
            opt_parm_len: 0,
            caps: Vec::new(),
        }
    }
}
