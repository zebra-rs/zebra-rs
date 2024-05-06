#![allow(dead_code)]
use super::{NotificationPacket, OpenPacket, UpdatePacket};
use nom_derive::*;
use rusticata_macros::newtype_enum;

pub const BGP_MAX_LEN: usize = 4096;
pub const BGP_HEADER_LEN: u16 = 19;

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct BgpType(u8);

newtype_enum! {
    impl display BgpType {
        Open = 1,
        Update = 2,
        Notification = 3,
        Keepalive = 4,
    RouteRefresh = 5,
    Capability = 6,
    }
}

impl From<BgpType> for u8 {
    fn from(typ: BgpType) -> u8 {
        match typ {
            BgpType(t) => t,
        }
    }
}

impl From<BgpType> for usize {
    fn from(typ: BgpType) -> usize {
        match typ {
            BgpType(t) => t as usize,
        }
    }
}

#[derive(Debug, PartialEq, NomBE)]
pub struct BgpHeader {
    pub marker: [u8; 16],
    pub length: u16,
    pub typ: BgpType,
}

impl BgpHeader {
    pub fn new(typ: BgpType, length: u16) -> Self {
        Self {
            marker: [0xffu8; 16],
            length,
            typ,
        }
    }
}

#[derive(Debug)]
pub enum BgpPacket {
    Open(OpenPacket),
    Keepalive(BgpHeader),
    Notification(NotificationPacket),
    Update(UpdatePacket),
}
