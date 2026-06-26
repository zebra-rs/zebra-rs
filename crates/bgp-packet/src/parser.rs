use std::collections::BTreeMap;

use nom::combinator::peek;
use nom_derive::*;

use crate::{
    Afi, AfiSafi, BGP_EXTENDED_PACKET_LEN, BGP_HEADER_LEN, BGP_PACKET_LEN, BgpHeader, BgpPacket,
    BgpParseError, BgpType, NotificationPacket, OpenPacket, RouteRefreshPacket, Safi, UpdatePacket,
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
    // Extended Message (RFC 8654)
    pub extended_message: bool,
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

    pub fn max_message_len(&self) -> usize {
        if self.extended_message {
            BGP_EXTENDED_PACKET_LEN
        } else {
            BGP_PACKET_LEN
        }
    }

    pub fn clear(&mut self) {
        self.as4 = Direct::default();
        self.add_path.clear();
        self.extended_message = false;
    }
}

pub fn nlri_psize(plen: u8) -> usize {
    plen.div_ceil(8).into()
}

pub fn peek_bgp_length(input: &[u8]) -> Option<usize> {
    if input.len() < BGP_HEADER_LEN.into() {
        return None;
    }
    let length = u16::from_be_bytes([input[16], input[17]]) as usize;
    (input.len() >= length).then_some(length)
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
            BgpType::RouteRefresh => {
                let (input, packet) = RouteRefreshPacket::parse_packet(input)?;
                Ok((input, BgpPacket::RouteRefresh(packet)))
            }
            _ => Err(BgpParseError::NomError(
                "Unknown BGP packet type".to_string(),
            )),
        }
    }
}
