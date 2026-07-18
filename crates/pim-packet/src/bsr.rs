//! Bootstrap Router messages (RFC 5059): the Bootstrap Message
//! carrying the elected BSR's identity and the RP-set, and the
//! Candidate-RP-Advertisement unicast to the BSR.

use std::net::IpAddr;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16};

use crate::addr::{EncodedGroup, EncodedUnicast};

/// One RP inside a BSM group set (RFC 5059 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsmRp {
    pub addr: EncodedUnicast,
    pub holdtime: u16,
    pub priority: u8,
}

impl BsmRp {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, addr) = EncodedUnicast::parse_be(input)?;
        let (input, holdtime) = be_u16(input)?;
        let (input, priority) = be_u8(input)?;
        let (input, _reserved) = be_u8(input)?;
        Ok((
            input,
            Self {
                addr,
                holdtime,
                priority,
            },
        ))
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.addr.emit(buf);
        buf.put_u16(self.holdtime);
        buf.put_u8(self.priority);
        buf.put_u8(0);
    }
}

/// One group range with its candidate RPs (RFC 5059 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsmGroup {
    pub group: EncodedGroup,
    /// Total RPs for the range across all fragments.
    pub rp_count: u8,
    pub rps: Vec<BsmRp>,
}

impl BsmGroup {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, group) = EncodedGroup::parse_be(input)?;
        let (input, rp_count) = be_u8(input)?;
        let (mut input, frag_rp_count) = be_u8(input)?;
        let (rest, _reserved) = be_u16(input)?;
        input = rest;
        let mut rps = Vec::with_capacity(frag_rp_count as usize);
        for _ in 0..frag_rp_count {
            let (rest, rp) = BsmRp::parse_be(input)?;
            rps.push(rp);
            input = rest;
        }
        Ok((
            input,
            Self {
                group,
                rp_count,
                rps,
            },
        ))
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.group.emit(buf);
        buf.put_u8(self.rp_count);
        buf.put_u8(self.rps.len() as u8);
        buf.put_u16(0);
        for rp in &self.rps {
            rp.emit(buf);
        }
    }
}

/// Bootstrap Message (RFC 5059 §4.2), flooded hop-by-hop to
/// ALL-PIM-ROUTERS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimBootstrap {
    pub fragment_tag: u16,
    pub hash_mask_len: u8,
    pub bsr_priority: u8,
    pub bsr_addr: EncodedUnicast,
    pub groups: Vec<BsmGroup>,
}

impl PimBootstrap {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, fragment_tag) = be_u16(input)?;
        let (input, hash_mask_len) = be_u8(input)?;
        let (input, bsr_priority) = be_u8(input)?;
        let (mut input, bsr_addr) = EncodedUnicast::parse_be(input)?;
        let mut groups = Vec::new();
        while !input.is_empty() {
            let (rest, group) = BsmGroup::parse_be(input)?;
            groups.push(group);
            input = rest;
        }
        Ok((
            input,
            Self {
                fragment_tag,
                hash_mask_len,
                bsr_priority,
                bsr_addr,
                groups,
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.fragment_tag);
        buf.put_u8(self.hash_mask_len);
        buf.put_u8(self.bsr_priority);
        self.bsr_addr.emit(buf);
        for group in &self.groups {
            group.emit(buf);
        }
    }

    pub fn bsr_v4(&self) -> Option<std::net::Ipv4Addr> {
        match self.bsr_addr.addr {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        }
    }
}

/// Candidate-RP-Advertisement (RFC 5059 §4.3), unicast to the
/// elected BSR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimCandRpAdv {
    pub priority: u8,
    pub holdtime: u16,
    pub rp_addr: EncodedUnicast,
    pub groups: Vec<EncodedGroup>,
}

impl PimCandRpAdv {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, prefix_count) = be_u8(input)?;
        let (input, priority) = be_u8(input)?;
        let (input, holdtime) = be_u16(input)?;
        let (mut input, rp_addr) = EncodedUnicast::parse_be(input)?;
        let mut groups = Vec::with_capacity(prefix_count as usize);
        for _ in 0..prefix_count {
            let (rest, group) = EncodedGroup::parse_be(input)?;
            groups.push(group);
            input = rest;
        }
        Ok((
            input,
            Self {
                priority,
                holdtime,
                rp_addr,
                groups,
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.groups.len() as u8);
        buf.put_u8(self.priority);
        buf.put_u16(self.holdtime);
        self.rp_addr.emit(buf);
        for group in &self.groups {
            group.emit(buf);
        }
    }
}
