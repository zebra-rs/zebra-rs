use std::fmt;
use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use itertools::Itertools;
use nom::IResult;
use nom::Parser;
use nom::number::complete::be_u32;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe, many0_complete};

#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct ClusterList {
    pub list: Vec<Ipv4Addr>,
}

impl ClusterList {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ParseBe<ClusterList> for ClusterList {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, ids) = many0_complete(be_u32).parse(input)?;
        let list = ids.into_iter().map(Ipv4Addr::from).collect();
        Ok((input, ClusterList { list }))
    }
}

impl AttrEmitter for ClusterList {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::ClusterList
    }

    fn len(&self) -> Option<usize> {
        Some(self.list.len() * 4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        for cluster_id in &self.list {
            buf.put(&cluster_id.octets()[..]);
        }
    }
}

impl fmt::Display for ClusterList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.list.iter().format(" "))
    }
}

impl fmt::Debug for ClusterList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cluster List: {}", self)
    }
}
