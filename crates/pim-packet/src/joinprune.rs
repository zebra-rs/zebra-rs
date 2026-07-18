//! PIM Join/Prune message (RFC 7761 §4.9.5).

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16};

use crate::addr::{EncodedGroup, EncodedSource, EncodedUnicast};

/// One group record: the group plus its joined and pruned source
/// lists. The (*,G) join is an `EncodedSource` carrying the RP with
/// the S/W/R bits set (`EncodedSource::star_g`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JpGroup {
    pub group: EncodedGroup,
    pub joins: Vec<EncodedSource>,
    pub prunes: Vec<EncodedSource>,
}

impl JpGroup {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, group) = EncodedGroup::parse_be(input)?;
        let (input, num_joins) = be_u16(input)?;
        let (mut input, num_prunes) = be_u16(input)?;
        let mut joins = Vec::with_capacity(num_joins as usize);
        for _ in 0..num_joins {
            let (rest, source) = EncodedSource::parse_be(input)?;
            joins.push(source);
            input = rest;
        }
        let mut prunes = Vec::with_capacity(num_prunes as usize);
        for _ in 0..num_prunes {
            let (rest, source) = EncodedSource::parse_be(input)?;
            prunes.push(source);
            input = rest;
        }
        Ok((
            input,
            Self {
                group,
                joins,
                prunes,
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        self.group.emit(buf);
        buf.put_u16(self.joins.len() as u16);
        buf.put_u16(self.prunes.len() as u16);
        for source in &self.joins {
            source.emit(buf);
        }
        for source in &self.prunes {
            source.emit(buf);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimJoinPrune {
    /// The upstream neighbor the message is addressed to (RFC 7761:
    /// the RPF neighbor; other routers on the LAN process it for
    /// suppression/override).
    pub upstream_neighbor: EncodedUnicast,
    pub holdtime: u16,
    pub groups: Vec<JpGroup>,
}

impl PimJoinPrune {
    pub fn new(upstream_neighbor: EncodedUnicast, holdtime: u16) -> Self {
        Self {
            upstream_neighbor,
            holdtime,
            groups: Vec::new(),
        }
    }

    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, upstream_neighbor) = EncodedUnicast::parse_be(input)?;
        let (input, _reserved) = be_u8(input)?;
        let (input, num_groups) = be_u8(input)?;
        let (mut input, holdtime) = be_u16(input)?;
        let mut groups = Vec::with_capacity(num_groups as usize);
        for _ in 0..num_groups {
            let (rest, group) = JpGroup::parse_be(input)?;
            groups.push(group);
            input = rest;
        }
        Ok((
            input,
            Self {
                upstream_neighbor,
                holdtime,
                groups,
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        self.upstream_neighbor.emit(buf);
        buf.put_u8(0);
        buf.put_u8(self.groups.len() as u8);
        buf.put_u16(self.holdtime);
        for group in &self.groups {
            group.emit(buf);
        }
    }
}
