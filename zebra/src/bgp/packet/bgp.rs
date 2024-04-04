#![allow(dead_code)]
use super::{NotificationPacket, OpenPacket, UpdatePacket};
use nom_derive::*;
use rusticata_macros::newtype_enum;

pub const BGP_PACKET_MAX_LEN: usize = 4096;
pub const BGP_PACKET_HEADER_LEN: u16 = 19;

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct BgpPacketType(u8);

newtype_enum! {
    impl display BgpPacketType {
        Open = 1,
        Update = 2,
        Notification = 3,
        Keepalive = 4,
    }
}

impl From<BgpPacketType> for u8 {
    fn from(typ: BgpPacketType) -> u8 {
        match typ {
            BgpPacketType(t) => t,
        }
    }
}

#[derive(Debug, PartialEq, NomBE)]
pub struct BgpHeader {
    pub marker: [u8; 16],
    pub length: u16,
    pub typ: BgpPacketType,
}

impl BgpHeader {
    pub fn new(typ: BgpPacketType, length: u16) -> Self {
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
