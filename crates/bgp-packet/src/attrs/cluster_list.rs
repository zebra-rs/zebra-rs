use std::fmt;
use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use itertools::Itertools;
use nom::IResult;
use nom::Parser;
use nom::error::{ErrorKind, make_error};
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
        // CLUSTER_LIST is a sequence of 4-octet cluster IDs (RFC 4456); a
        // payload whose length is not a multiple of 4 is malformed.
        if !input.len().is_multiple_of(4) {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cluster_list_accepts_multiple_of_four() {
        let input = [192, 0, 2, 1, 198, 51, 100, 2];
        let (rest, cl) = ClusterList::parse_be(&input).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            cl.list,
            vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2),]
        );
    }

    #[test]
    fn parse_cluster_list_rejects_non_multiple_of_four() {
        // 5 bytes: one cluster ID plus a stray trailing octet.
        let input = [192, 0, 2, 1, 0];
        assert!(ClusterList::parse_be(&input).is_err());
    }
}
