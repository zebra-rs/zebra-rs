use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32};
use nom_derive::*;
use std::collections::VecDeque;
use std::fmt;
use std::str::FromStr;

use crate::{AttrType, ParseBe, many0_complete};

use super::aspath_token::{Token, tokenizer};
use super::{AttrEmitter, AttrFlags};

pub const AS_SET: u8 = 1;
pub const AS_SEQ: u8 = 2;
pub const AS_CONFED_SEQ: u8 = 3;
pub const AS_CONFED_SET: u8 = 4;

#[allow(dead_code)]
pub const AS_TRANS: u16 = 23456;

/// Calculate AS Path segment length according to RFC 4271 and RFC 5065.
/// - AS_SEQUENCE: Each AS number counts as 1
/// - AS_SET: The entire set counts as 1 (regardless of size)
/// - AS_CONFED_SEQUENCE: Does NOT count (RFC 5065)
/// - AS_CONFED_SET: Does NOT count (RFC 5065)
fn calculate_segment_length(typ: u8, asn_count: usize) -> u32 {
    match typ {
        AS_SEQ => asn_count as u32,         // Each AS counts as 1
        AS_SET => 1,                        // Entire set counts as 1
        AS_CONFED_SEQ | AS_CONFED_SET => 0, // Confederation segments don't count
        _ => 0,
    }
}

#[derive(Debug, NomBE)]
pub struct AsSegmentHeader {
    pub typ: u8,
    pub length: u8,
}

#[derive(Clone, Debug)]
pub struct As2Segment {
    pub typ: u8,
    pub asn: Vec<u16>,
}

#[derive(Clone, Debug)]
pub struct As2Path {
    pub segs: Vec<As2Segment>,
    pub length: u32,
}

impl As2Path {
    /// Calculate AS Path length from segments according to RFC 4271 and RFC 5065.
    fn calculate_length(&self) -> u32 {
        self.segs
            .iter()
            .map(|seg| calculate_segment_length(seg.typ, seg.asn.len()))
            .sum()
    }
}

impl ParseBe<As2Path> for As2Path {
    fn parse_be(input: &[u8]) -> IResult<&[u8], As2Path> {
        let (input, segs) = many0_complete(parse_bgp_attr_as2_segment).parse(input)?;
        let mut path = As2Path { segs, length: 0 };
        path.length = path.calculate_length();
        Ok((input, path))
    }
}

fn parse_bgp_attr_as2_segment(input: &[u8]) -> IResult<&[u8], As2Segment> {
    let (input, header) = AsSegmentHeader::parse_be(input)?;
    let (input, asns) = count(be_u16, header.length as usize).parse(input)?;
    let segment = As2Segment {
        typ: header.typ,
        asn: asns.into_iter().collect(),
    };
    Ok((input, segment))
}

fn parse_bgp_attr_as4_segment(input: &[u8]) -> IResult<&[u8], As4Segment> {
    let (input, header) = AsSegmentHeader::parse_be(input)?;
    let (input, asns) = count(be_u32, header.length as usize).parse(input)?;
    let segment = As4Segment {
        typ: header.typ,
        asn: asns.into_iter().collect(),
    };
    Ok((input, segment))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct As4Segment {
    pub typ: u8,
    pub asn: Vec<u32>,
}

impl As4Segment {
    pub fn new(typ: u8) -> Self {
        Self {
            typ,
            asn: Vec::new(),
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ);
        buf.put_u8(self.asn.len() as u8);
        self.asn.iter().for_each(|x| buf.put_u32(*x));
    }
}

pub fn asn_to_string(val: u32) -> String {
    if val > 65535 {
        let hval: u32 = (val & 0xFFFF0000) >> 16;
        let lval: u32 = val & 0x0000FFFF;
        hval.to_string() + "." + &lval.to_string()
    } else {
        val.to_string()
    }
}

impl fmt::Display for As4Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .asn
            .iter()
            .map(|x| asn_to_string(*x))
            .collect::<Vec<String>>()
            .join(" ");
        match self.typ {
            AS_SET => write!(f, "{{{v}}}"),
            AS_CONFED_SEQ => write!(f, "({v})"),
            AS_CONFED_SET => write!(f, "[{v}]"),
            AS_SEQ => write!(f, "{v}"),
            _ => write!(f, "{v}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct As4Path {
    pub segs: VecDeque<As4Segment>,
    pub length: u32,
}

impl AttrEmitter for As4Path {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::AsPath
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.segs.iter().for_each(|x| x.emit(buf));
    }
}

impl ParseBe<As4Path> for As4Path {
    fn parse_be(input: &[u8]) -> IResult<&[u8], As4Path> {
        let (input, segs) = many0_complete(parse_bgp_attr_as4_segment).parse(input)?;
        let mut path = As4Path {
            segs: segs.into(),
            length: 0,
        };
        path.length = path.calculate_length();
        Ok((input, path))
    }
}

impl fmt::Display for As4Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .segs
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{v}")
    }
}

impl fmt::Debug for As4Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS Path: {}", self)
    }
}

macro_rules! segment_reset {
    ($typ:expr, $before:expr, $after:expr, $seg:expr, $aspath:expr) => {
        if $typ != $before {
            return Err(());
        }
        $typ = $after;
        if !$seg.asn.is_empty() {
            $aspath.segs.push_back($seg);
            $seg = As4Segment::new($typ);
        } else {
            $seg.typ = $typ;
        }
    };
}

impl FromStr for As4Path {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut aspath = As4Path::new();
        let tokens = tokenizer(String::from(s)).unwrap();
        let mut segment_type = AS_SEQ;
        let mut segment = As4Segment::new(segment_type);

        for token in tokens.iter() {
            match token {
                Token::As(asn) => {
                    segment.asn.push(*asn);
                }
                Token::AsSetStart => {
                    segment_reset!(segment_type, AS_SEQ, AS_SET, segment, aspath);
                }
                Token::AsSetEnd => {
                    segment_reset!(segment_type, AS_SET, AS_SEQ, segment, aspath);
                }
                Token::AsConfedSeqStart => {
                    segment_reset!(segment_type, AS_SEQ, AS_CONFED_SEQ, segment, aspath);
                }
                Token::AsConfedSeqEnd => {
                    segment_reset!(segment_type, AS_CONFED_SEQ, AS_SEQ, segment, aspath);
                }
                Token::AsConfedSetStart => {
                    segment_reset!(segment_type, AS_SEQ, AS_CONFED_SET, segment, aspath);
                }
                Token::AsConfedSetEnd => {
                    segment_reset!(segment_type, AS_CONFED_SET, AS_SEQ, segment, aspath);
                }
            }
        }

        if !segment.asn.is_empty() {
            aspath.segs.push_back(segment);
        }

        // Calculate total length after parsing
        aspath.length = aspath.calculate_length();

        Ok(aspath)
    }
}

impl As4Path {
    pub fn new() -> Self {
        Self {
            segs: VecDeque::new(),
            length: 0,
        }
    }

    // New As4Path with given asn as default values.
    pub fn from(asn: Vec<u32>) -> Self {
        let length = asn.len() as u32;
        let seg = As4Segment { typ: AS_SEQ, asn };
        As4Path {
            segs: VecDeque::from(vec![seg]),
            length,
        }
    }

    /// Calculate AS Path length from segments according to RFC 4271 and RFC 5065.
    fn calculate_length(&self) -> u32 {
        self.segs
            .iter()
            .map(|seg| calculate_segment_length(seg.typ, seg.asn.len()))
            .sum()
    }

    pub fn update_length(&mut self) {
        self.length = self
            .segs
            .iter()
            .map(|seg| calculate_segment_length(seg.typ, seg.asn.len()))
            .sum();
    }

    /// Returns the AS Path length according to RFC 4271 and RFC 5065.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Prepend an AS path to this path.
    /// Returns a new AS path with `other` prepended to `self`.
    pub fn prepend(&self, other: Self) -> Self {
        // Handle empty paths
        if self.segs.is_empty() {
            return other;
        }
        if other.segs.is_empty() {
            return self.clone();
        }

        // Try to merge if both paths have a single AS_SEQ segment
        if let Some(merged) = self.try_merge_single_seq(&other) {
            return merged;
        }

        // Default: concatenate segments
        self.concatenate_paths(other)
    }

    /// Prepend an AS path to this path (modifies self in place).
    /// Modifies `self` by prepending `other` to it.
    pub fn prepend_mut(&mut self, other: Self) {
        // Handle empty paths
        if self.segs.is_empty() {
            *self = other;
            return;
        }
        if other.segs.is_empty() {
            return;
        }

        // Try to merge if both paths have a single AS_SEQ segment
        if self.segs.len() == 1
            && other.segs.len() == 1
            && let (Some(self_seg), Some(other_seg)) = (self.segs.front(), other.segs.front())
            && self_seg.typ == AS_SEQ
            && other_seg.typ == AS_SEQ
        {
            // Merge the two AS_SEQ segments
            let mut merged_asn = other_seg.asn.clone();
            merged_asn.extend(&self_seg.asn);
            self.segs.clear();
            self.segs.push_back(As4Segment {
                typ: AS_SEQ,
                asn: merged_asn,
            });
            self.update_length();
            return;
        }

        // Default: concatenate segments
        let mut new_segs = other.segs.clone();
        new_segs.extend(self.segs.clone());
        self.segs = new_segs;
        self.update_length();
    }

    /// Try to merge two single-segment AS_SEQ paths into one segment.
    fn try_merge_single_seq(&self, other: &Self) -> Option<Self> {
        if self.segs.len() != 1 || other.segs.len() != 1 {
            return None;
        }

        let self_seg = self.segs.front()?;
        let other_seg = other.segs.front()?;

        if self_seg.typ != AS_SEQ || other_seg.typ != AS_SEQ {
            return None;
        }

        // Merge the two AS_SEQ segments
        let mut merged_seg = other_seg.clone();
        merged_seg.asn.extend(&self_seg.asn);

        let mut result = Self::new();
        result.segs.push_back(merged_seg);
        result.update_length();
        Some(result)
    }

    /// Concatenate two AS paths by appending self's segments to other's.
    fn concatenate_paths(&self, other: Self) -> Self {
        let mut result = other.clone();
        result.segs.extend(self.segs.clone());
        result.update_length();
        result
    }

    /// Find neighboring AS for MED comparison (RFC 4271).
    /// Returns the first AS number from the first AS_SEQ segment.
    pub fn neighboring_as(&self) -> Option<u32> {
        self.segs
            .iter()
            .find(|seg| seg.typ == AS_SEQ)
            .and_then(|seg| seg.asn.first().copied())
    }
}

impl Default for As4Path {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let aspath: As4Path = As4Path::from_str("1 2 3 65536").unwrap();
        assert_eq!(aspath.to_string(), "1 2 3 1.0");

        let aspath: As4Path = As4Path::from_str("1 2 3 {4} 4294967295").unwrap();
        assert_eq!(aspath.to_string(), "1 2 3 {4} 65535.65535");

        let aspath: As4Path = As4Path::from_str("1 2 3 [4 5] 6").unwrap();
        assert_eq!(aspath.to_string(), "1 2 3 [4 5] 6");

        let aspath: As4Path = As4Path::from_str("1 2 3 [4 5] 6 (7)").unwrap();
        assert_eq!(aspath.to_string(), "1 2 3 [4 5] 6 (7)");
    }

    #[test]
    fn prepend() {
        let aspath: As4Path = As4Path::from_str("10 11 12").unwrap();
        let prepend: As4Path = As4Path::from_str("1 2 3").unwrap();
        let result = aspath.prepend(prepend);
        assert_eq!(result.to_string(), "1 2 3 10 11 12");
        assert_eq!(result.length(), 6);
    }

    #[test]
    fn prepend_empty() {
        let aspath: As4Path = As4Path::new();
        let prepend: As4Path = As4Path::from_str("1 2 3").unwrap();
        let result = aspath.prepend(prepend);
        assert_eq!(result.to_string(), "1 2 3");
        assert_eq!(result.length(), 3);

        let aspath: As4Path = As4Path::from_str("1 2 3").unwrap();
        let prepend: As4Path = As4Path::new();
        let result = aspath.prepend(prepend);
        assert_eq!(result.to_string(), "1 2 3");
        assert_eq!(result.length(), 3);
    }

    #[test]
    fn prepend_seq() {
        let aspath: As4Path = As4Path::from_str("1").unwrap();
        let prepend: As4Path = As4Path::from_str("{1} 2 3").unwrap();
        let result = aspath.prepend(prepend);
        assert_eq!(result.to_string(), "{1} 2 3 1");
        assert_eq!(result.length(), 4);

        let aspath: As4Path = As4Path::from_str("1 {2}").unwrap();
        let prepend: As4Path = As4Path::from_str("2 {3} 4 5").unwrap();
        let result = aspath.prepend(prepend);
        assert_eq!(result.to_string(), "2 {3} 4 5 1 {2}");
        assert_eq!(result.length(), 6);
    }

    #[test]
    fn length_as_sequence() {
        // AS_SEQUENCE: Each AS counts as 1
        let aspath: As4Path = As4Path::from_str("1 2 3").unwrap();
        assert_eq!(aspath.length(), 3);
    }

    #[test]
    fn length_as_set() {
        // AS_SET: Entire set counts as 1
        let aspath: As4Path = As4Path::from_str("1 2 {3 4 5}").unwrap();
        assert_eq!(aspath.length(), 3); // 2 from sequence + 1 from set
    }

    #[test]
    fn length_confed_sequence() {
        // AS_CONFED_SEQUENCE: Does not count (RFC 5065)
        let aspath: As4Path = As4Path::from_str("1 (2 3) 4").unwrap();
        assert_eq!(aspath.length(), 2); // Only 1 and 4 count
    }

    #[test]
    fn length_confed_set() {
        // AS_CONFED_SET: Does not count (RFC 5065)
        let aspath: As4Path = As4Path::from_str("1 [2 3] 4").unwrap();
        assert_eq!(aspath.length(), 2); // Only 1 and 4 count
    }

    #[test]
    fn length_mixed() {
        // Mixed: AS_SEQ + AS_SET + AS_CONFED_SEQ + AS_CONFED_SET
        let aspath: As4Path = As4Path::from_str("1 2 {3 4} [5 6] (7 8) 9").unwrap();
        assert_eq!(aspath.length(), 4); // 1, 2 from seq + 1 from set + 9 = 4
    }

    #[test]
    fn length_empty() {
        let aspath: As4Path = As4Path::new();
        assert_eq!(aspath.length(), 0);
    }

    #[test]
    fn length_after_prepend() {
        let aspath: As4Path = As4Path::from_str("10 11 12").unwrap();
        assert_eq!(aspath.length(), 3);

        let prepend: As4Path = As4Path::from_str("1 2 3").unwrap();
        let result = aspath.prepend(prepend);
        assert_eq!(result.length(), 6); // 3 + 3 = 6
    }

    #[test]
    fn length_large_set() {
        // Large AS_SET still counts as 1
        let aspath: As4Path = As4Path::from_str("1 {2 3 4 5 6 7 8 9 10} 11").unwrap();
        assert_eq!(aspath.length(), 3); // 1 + 1 (set) + 11 = 3
    }

    #[test]
    fn from_empty() {
        let aspath = As4Path::from(vec![]);
        assert_eq!(aspath.to_string(), "");
        assert_eq!(aspath.length(), 0);
        assert_eq!(aspath.segs.len(), 1);
    }

    #[test]
    fn from_single() {
        let aspath = As4Path::from(vec![100]);
        assert_eq!(aspath.to_string(), "100");
        assert_eq!(aspath.length(), 1);
        assert_eq!(aspath.segs.len(), 1);
        assert_eq!(aspath.segs.front().unwrap().typ, AS_SEQ);
    }

    #[test]
    fn from_multiple() {
        let aspath = As4Path::from(vec![100, 200, 300]);
        assert_eq!(aspath.to_string(), "100 200 300");
        assert_eq!(aspath.length(), 3);
        assert_eq!(aspath.segs.len(), 1);
        assert_eq!(aspath.segs.front().unwrap().typ, AS_SEQ);
    }

    #[test]
    fn from_large_asn() {
        let aspath = As4Path::from(vec![65536, 4294967295]);
        assert_eq!(aspath.to_string(), "1.0 65535.65535");
        assert_eq!(aspath.length(), 2);
    }

    #[test]
    fn prepend_mut_basic() {
        let mut aspath: As4Path = As4Path::from_str("10 11 12").unwrap();
        let prepend: As4Path = As4Path::from_str("1 2 3").unwrap();
        aspath.prepend_mut(prepend);
        assert_eq!(aspath.to_string(), "1 2 3 10 11 12");
        assert_eq!(aspath.length(), 6);
    }

    #[test]
    fn prepend_mut_empty() {
        let mut aspath: As4Path = As4Path::new();
        let prepend: As4Path = As4Path::from_str("1 2 3").unwrap();
        aspath.prepend_mut(prepend);
        assert_eq!(aspath.to_string(), "1 2 3");
        assert_eq!(aspath.length(), 3);

        let mut aspath: As4Path = As4Path::from_str("1 2 3").unwrap();
        let prepend: As4Path = As4Path::new();
        aspath.prepend_mut(prepend);
        assert_eq!(aspath.to_string(), "1 2 3");
        assert_eq!(aspath.length(), 3);
    }

    #[test]
    fn prepend_mut_merge() {
        // Test merging two single AS_SEQ segments
        let mut aspath: As4Path = As4Path::from_str("10 11 12").unwrap();
        let prepend: As4Path = As4Path::from_str("1 2 3").unwrap();
        aspath.prepend_mut(prepend);
        assert_eq!(aspath.to_string(), "1 2 3 10 11 12");
        assert_eq!(aspath.length(), 6);
        assert_eq!(aspath.segs.len(), 1); // Should be merged into single segment
    }

    #[test]
    fn prepend_mut_no_merge() {
        // Test concatenation when segments can't be merged
        let mut aspath: As4Path = As4Path::from_str("1").unwrap();
        let prepend: As4Path = As4Path::from_str("{1} 2 3").unwrap();
        aspath.prepend_mut(prepend);
        assert_eq!(aspath.to_string(), "{1} 2 3 1");
        assert_eq!(aspath.length(), 4);

        let mut aspath: As4Path = As4Path::from_str("1 {2}").unwrap();
        let prepend: As4Path = As4Path::from_str("2 {3} 4 5").unwrap();
        aspath.prepend_mut(prepend);
        assert_eq!(aspath.to_string(), "2 {3} 4 5 1 {2}");
        assert_eq!(aspath.length(), 6);
    }
}
