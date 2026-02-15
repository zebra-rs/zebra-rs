use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::{NotificationPacket, OpenPacket, UpdatePacket};

pub const BGP_PACKET_LEN: usize = 4096;
pub const BGP_HEADER_LEN: u16 = 19;

#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, NomBE)]
pub enum BgpType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
    Capability = 6,
    Max = 7,
}

#[derive(Debug, Clone, PartialEq, NomBE)]
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

impl From<BgpHeader> for BytesMut {
    fn from(header: BgpHeader) -> Self {
        let mut buf = BytesMut::new();
        buf.put(&header.marker[..]);
        buf.put_u16(header.length);
        let typ: u8 = header.typ as u8;
        buf.put_u8(typ);
        buf
    }
}

#[derive(Debug)]
pub enum BgpPacket {
    Open(Box<OpenPacket>),
    Keepalive(BgpHeader),
    Notification(NotificationPacket),
    Update(Box<UpdatePacket>),
}
