use std::collections::BTreeMap;
use std::convert::TryInto;

use nom::combinator::peek;
use nom_derive::*;

use crate::{
    Afi, AfiSafi, BgpHeader, BgpPacket, BgpParseError, BgpType, NotificationPacket, OpenPacket,
    Safi, UpdatePacket,
};

#[derive(Default, Debug, Clone)]
pub struct Direct {
    pub recv: bool,
    pub send: bool,
}

#[derive(Default, Debug, Clone)]
pub struct ParseOption {
    // AS4
    pub as4: Direct,
    // AddPath
    pub add_path: BTreeMap<AfiSafi, Direct>,
}

impl ParseOption {
    pub fn is_as4(&self) -> bool {
        self.as4.send && self.as4.recv
    }

    pub fn is_add_path_recv(&self, afi: Afi, safi: Safi) -> bool {
        let key = AfiSafi { afi, safi };
        self.add_path.get(&key).is_some_and(|direct| direct.recv)
    }

    pub fn is_add_path_send(&self, afi: Afi, safi: Safi) -> bool {
        let key = AfiSafi { afi, safi };
        self.add_path.get(&key).is_some_and(|direct| direct.send)
    }

    pub fn clear(&mut self) {
        self.as4 = Direct::default();
        self.add_path.clear();
    }
}

pub fn nlri_psize(plen: u8) -> usize {
    plen.div_ceil(8).into()
}

pub fn peek_bgp_length(input: &[u8]) -> usize {
    if let Some(len) = input.get(16..18) {
        u16::from_be_bytes(len.try_into().unwrap()) as usize
    } else {
        0
    }
}

impl BgpPacket {
    pub fn parse_packet(
        input: &[u8],
        as4: bool,
        opt: Option<ParseOption>,
    ) -> Result<(&[u8], BgpPacket), BgpParseError> {
        let (_, header) = peek(BgpHeader::parse_be).parse(input)?;
        match header.typ {
            BgpType::Open => {
                let (input, packet) = OpenPacket::parse_packet(input)?;
                Ok((input, BgpPacket::Open(Box::new(packet))))
            }
            BgpType::Update => {
                let (input, p) = UpdatePacket::parse_packet(input, as4, opt)?;
                Ok((input, BgpPacket::Update(Box::new(p))))
            }
            BgpType::Notification => {
                let (input, packet) = NotificationPacket::parse_packet(input)?;
                Ok((input, BgpPacket::Notification(packet)))
            }
            BgpType::Keepalive => {
                let (input, header) = BgpHeader::parse_be(input)?;
                Ok((input, BgpPacket::Keepalive(header)))
            }
            _ => Err(BgpParseError::NomError(
                "Unknown BGP packet type".to_string(),
            )),
        }
    }
}
