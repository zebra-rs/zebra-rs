#![allow(dead_code)]
use super::{NotificationPacket, OpenPacket, UpdatePacket};
use nom_derive::*;

pub const BGP_PACKET_LEN: usize = 4096;
pub const BGP_HEADER_LEN: u16 = 19;

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, NomBE)]
pub enum BgpType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
    Capability = 6,
    Max = 7,
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
