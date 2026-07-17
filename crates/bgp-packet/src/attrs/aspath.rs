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

/// Most AS numbers expressible in one AS_PATH segment: the segment header's
/// Path Segment Length is a single octet (RFC 4271 §4.3). A longer run has to be
/// emitted as consecutive segments of the same type. Mirrors FRR's
/// `AS_SEGMENT_MAX`.
pub const AS_SEGMENT_MAX: usize = 255;

#[allow(dead_code)]
pub const AS_TRANS: u16 = 23456;

/// Inclusive bounds of the 16-bit private AS range (RFC 6996).
pub const PRIVATE_AS_MIN: u32 = 64512;
pub const PRIVATE_AS_MAX: u32 = 65535;

/// Inclusive bounds of the 32-bit private AS range (RFC 6996 / IANA
/// reserved-for-private-use; FRR's `BGP_PRIVATE_AS4_*`).
pub const PRIVATE_AS4_MIN: u32 = 4200000000;
pub const PRIVATE_AS4_MAX: u32 = 4294967294;

/// True if `asn` falls in either the 16-bit or 32-bit private AS range.
/// Mirrors FRR's `BGP_AS_IS_PRIVATE`. Drives `remove-private-as`.
pub fn is_private_as(asn: u32) -> bool {
    (PRIVATE_AS_MIN..=PRIVATE_AS_MAX).contains(&asn)
        || (PRIVATE_AS4_MIN..=PRIVATE_AS4_MAX).contains(&asn)
}

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
    pub fn update_length(&mut self) {
        self.length = self
            .segs
            .iter()
            .map(|seg| calculate_segment_length(seg.typ, seg.asn.len()))
            .sum();
    }
}

impl ParseBe<As2Path> for As2Path {
    fn parse_be(input: &[u8]) -> IResult<&[u8], As2Path> {
        let (input, segs) = many0_complete(parse_bgp_attr_as2_segment).parse(input)?;
        let mut path = As2Path { segs, length: 0 };
        path.update_length();
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
        // Split at the 1-octet Path Segment Length limit rather than letting
        // `len() as u8` wrap. `prepend_mut` and `consolidate` both merge into a
        // single segment without bounding it, so an inbound path whose segment
        // already held the maximum 255 reaches 256 after one prepend; the count
        // octet then wrapped to 0 while 256 ASNs were still written, and the
        // peer reparsed those ASN bytes as segment headers -> malformed AS_PATH
        // -> NOTIFICATION. Consecutive segments of the same type are equivalent
        // for AS_SEQUENCE (the hop counts add up); an AS_SET over 255 has no
        // single-segment encoding at all, so splitting is the only option there
        // too, at the cost of the receiver counting it as more than one hop.
        // Matches FRR's `aspath_put`.
        if self.asn.is_empty() {
            // Preserve the empty-segment encoding: `chunks` yields nothing for
            // an empty slice, which would emit no header at all.
            buf.put_u8(self.typ);
            buf.put_u8(0);
            return;
        }
        for chunk in self.asn.chunks(AS_SEGMENT_MAX) {
            buf.put_u8(self.typ);
            buf.put_u8(chunk.len() as u8);
            chunk.iter().for_each(|x| buf.put_u32(*x));
        }
    }
}

/// Render an AS number in asdot notation (RFC 5396): values below 65536 in
/// plain decimal, values at or above it as `<high16>.<low16>`.
pub fn asn_to_string(val: u32) -> String {
    if val > 65535 {
        let hval: u32 = (val & 0xFFFF0000) >> 16;
        let lval: u32 = val & 0x0000FFFF;
        hval.to_string() + "." + &lval.to_string()
    } else {
        val.to_string()
    }
}

/// Render an AS number in asdot+ notation (RFC 5396): always `<high16>.<low16>`,
/// including below 65536, where it yields `0.65526` rather than `65526`.
///
/// Prefer [`asn_to_string`] (asdot) for display. This form exists for callers
/// where the dot itself carries meaning rather than being cosmetic — a type-2
/// Route Distinguisher, where the dot is what separates the 4-octet-AS encoding
/// from the 2-octet one in the overlap where both the AS and the assigned number
/// fit in 16 bits. Identical to asdot for any AS >= 65536.
pub fn asn_to_asdot_plus(val: u32) -> String {
    format!("{}.{}", val >> 16, val & 0xFFFF)
}

/// Inverse of [`asn_to_string`]: accept an AS number written in either asplain
/// (`"65546"`) or asdot/asdot+ (`"1.10"`, `"0.65526"`) notation (RFC 5396), so
/// text copied from a peer running either convention parses. Both dotted halves
/// are 16-bit, so `"169031.1"` and `"1.2.3"` are rejected rather than silently
/// truncated. Returns `None` when the text is not a valid AS number.
pub fn asn_from_string(s: &str) -> Option<u32> {
    match s.split_once('.') {
        Some((high, low)) => {
            let high: u16 = high.parse().ok()?;
            let low: u16 = low.parse().ok()?;
            Some(((high as u32) << 16) | low as u32)
        }
        None => s.parse::<u32>().ok(),
    }
}

impl As4Segment {
    fn format_display(&self) -> String {
        let v = self
            .asn
            .iter()
            .map(|x| asn_to_string(*x))
            .collect::<Vec<String>>()
            .join(" ");
        match self.typ {
            AS_SET => format!("{{{v}}}"),
            AS_CONFED_SEQ => format!("({v})"),
            AS_CONFED_SET => format!("[{v}]"),
            _ => v,
        }
    }

    fn format_explicit(&self) -> String {
        let v = self
            .asn
            .iter()
            .map(|x| asn_to_string(*x))
            .collect::<Vec<String>>()
            .join(" ");
        match self.typ {
            AS_SET => format!("{{{v}}}"),
            AS_CONFED_SEQ => format!("({v})"),
            AS_CONFED_SET => format!("[{v}]"),
            AS_SEQ => format!("<{v}>"),
            _ => v,
        }
    }

    /// Render this segment exactly like FRR's `aspath_make_str_count`
    /// (`bgpd/bgp_aspath.c`), for AS-path regular-expression matching.
    ///
    /// FRR joins the members of an AS_SET / AS_CONFED_SET with a comma and
    /// an AS_SEQUENCE / AS_CONFED_SEQUENCE with a space, wrapping SET and
    /// CONFED segments in their delimiter characters. Matching against this
    /// exact form keeps zebra-rs byte-compatible with FRR AS-path regexes,
    /// including patterns that reference the internal `,` separator.
    fn format_frr(&self) -> String {
        let separator = match self.typ {
            AS_SET | AS_CONFED_SET => ",",
            _ => " ",
        };
        let v = self
            .asn
            .iter()
            .map(|x| asn_to_string(*x))
            .collect::<Vec<String>>()
            .join(separator);
        match self.typ {
            AS_SET => format!("{{{v}}}"),
            AS_CONFED_SEQ => format!("({v})"),
            AS_CONFED_SET => format!("[{v}]"),
            _ => v,
        }
    }
}

impl fmt::Display for As4Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_display())
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
        path.update_length();
        Ok((input, path))
    }
}

impl As4Path {
    /// Display AS-Path without delimiters for AS_SEQUENCE (conventional BGP CLI format).
    pub fn as_path_display(&self) -> String {
        self.segs
            .iter()
            .map(|x| x.format_display())
            .collect::<Vec<String>>()
            .join(" ")
    }

    /// Display AS-Path with explicit `<>` delimiters for AS_SEQUENCE.
    pub fn as_path_explicit(&self) -> String {
        self.segs
            .iter()
            .map(|x| x.format_explicit())
            .collect::<Vec<String>>()
            .join(" ")
    }

    /// AS-Path rendered exactly like FRR's `aspath->str`, the form FRR runs
    /// its AS-path access-list regexes against. Segments are space-joined;
    /// AS_SET / AS_CONFED_SET members are comma-separated inside their
    /// delimiters (e.g. `65001 {65010,65011} 65003`). Used only for policy
    /// AS-path matching so patterns behave identically to FRR; `show`
    /// output continues to use [`as_path_display`](Self::as_path_display).
    pub fn as_path_frr_string(&self) -> String {
        self.segs
            .iter()
            .map(|x| x.format_frr())
            .collect::<Vec<String>>()
            .join(" ")
    }
}

impl fmt::Display for As4Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_path_display())
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
                Token::AsSeqStart => {
                    segment_reset!(segment_type, AS_SEQ, AS_SEQ, segment, aspath);
                }
                Token::AsSeqEnd => {
                    if segment_type != AS_SEQ {
                        return Err(());
                    }
                    if !segment.asn.is_empty() {
                        aspath.segs.push_back(segment);
                        segment = As4Segment::new(AS_SEQ);
                    }
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

        aspath.update_length();

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

    /// True when the path carries an AS_SET or AS_CONFED_SET segment
    /// (RFC 9774 deprecated types).
    pub fn contains_as_set_or_confed_set(&self) -> bool {
        self.segs
            .iter()
            .any(|seg| seg.typ == AS_SET || seg.typ == AS_CONFED_SET)
    }

    /// Returns the count of distinct ASes across all segments
    /// (sequences, sets, confederation segments). Used by the
    /// policy engine for `match as-path-len-uniq`.
    pub fn unique_length(&self) -> u32 {
        use std::collections::HashSet;
        let mut seen: HashSet<u32> = HashSet::new();
        for seg in &self.segs {
            for asn in &seg.asn {
                seen.insert(*asn);
            }
        }
        seen.len() as u32
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

    /// Replace every occurrence of `from` with `to` across all segments
    /// (sequences, sets, confederation segments). Mirrors FRR's
    /// `aspath_replace_specific_asn`: a 1:1 substitution, so the
    /// RFC 4271 / RFC 5065 hop count is unchanged and `length` stays
    /// valid without recomputation. Used by per-neighbor `as-override`
    /// on the egress path, where the AS being advertised to has its own
    /// AS swapped out for ours so its loop check accepts the route.
    pub fn replace_as_mut(&mut self, from: u32, to: u32) {
        for seg in self.segs.iter_mut() {
            for asn in seg.asn.iter_mut() {
                if *asn == from {
                    *asn = to;
                }
            }
        }
    }

    /// True iff every AS in the path is a private AS (RFC 6996 / 32-bit
    /// IANA reserved ranges). Mirrors FRR's `aspath_private_as_check`,
    /// including its treatment of an empty path as *not* all-private
    /// (returns `false`). The bare `remove-private-as` form (without
    /// `all`) only acts when this holds.
    pub fn is_all_private(&self) -> bool {
        let mut seen_any = false;
        for seg in &self.segs {
            for &asn in &seg.asn {
                seen_any = true;
                if !is_private_as(asn) {
                    return false;
                }
            }
        }
        seen_any
    }

    /// Strip every private AS from all segments, except occurrences
    /// equal to `keep` — the eBGP neighbor's own AS, retained so the
    /// neighbor's RFC 4271 loop check still works (mirrors FRR's
    /// `aspath_remove_private_asns`, which preserves `peer_asn`).
    /// Segments left empty are dropped and the hop count (`length`) is
    /// recomputed, since removing ASNs changes it. Used by
    /// `remove-private-as` on the egress path.
    pub fn remove_private_as_mut(&mut self, keep: u32) {
        for seg in self.segs.iter_mut() {
            seg.asn.retain(|&asn| !is_private_as(asn) || asn == keep);
        }
        self.segs.retain(|seg| !seg.asn.is_empty());
        self.update_length();
    }

    /// Replace every private AS with `replacement` (the local AS),
    /// except occurrences equal to `keep` — the neighbor's own AS,
    /// preserved for loop prevention. A 1:1 substitution (mirrors FRR's
    /// `aspath_replace_private_asns`), so the hop count is unchanged and
    /// `length` stays valid without recomputation. Used by
    /// `remove-private-as replace-as` on the egress path.
    pub fn replace_private_as_mut(&mut self, replacement: u32, keep: u32) {
        for seg in self.segs.iter_mut() {
            for asn in seg.asn.iter_mut() {
                if is_private_as(*asn) && *asn != keep {
                    *asn = replacement;
                }
            }
        }
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

    /// Consolidate continuous AS_SEQUENCE segments into one.
    pub fn consolidate(&mut self) {
        let mut consolidated = VecDeque::new();
        for seg in self.segs.drain(..) {
            if seg.typ == AS_SEQ
                && let Some(last) = consolidated.back_mut()
            {
                let last: &mut As4Segment = last;
                if last.typ == AS_SEQ {
                    last.asn.extend(seg.asn);
                    continue;
                }
            }
            consolidated.push_back(seg);
        }
        self.segs = consolidated;
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

    /// Flatten an emitted AS_PATH back into its ASN sequence.
    fn emit_and_reparse(path: &As4Path) -> (usize, Vec<u32>) {
        let mut buf = BytesMut::new();
        path.segs.iter().for_each(|s| s.emit(&mut buf));
        let (rest, parsed) = As4Path::parse_be(&buf).unwrap();
        assert!(rest.is_empty(), "emitted AS_PATH must parse fully");
        let flat = parsed
            .segs
            .iter()
            .flat_map(|s| s.asn.iter().copied())
            .collect();
        (parsed.segs.len(), flat)
    }

    /// A segment longer than the 1-octet count splits into consecutive segments
    /// of the same type instead of wrapping. Regression: 256 ASNs emitted
    /// `count = 0` followed by 256 ASNs, so a peer read a 0-length AS_SEQ and
    /// reparsed the ASN bytes as segment headers — a malformed AS_PATH.
    #[test]
    fn oversized_segment_splits_at_limit() {
        let seg = As4Segment {
            typ: AS_SEQ,
            asn: (1..=256u32).collect(),
        };
        let mut buf = BytesMut::new();
        seg.emit(&mut buf);

        // Two headers, not one: 2 + 255*4 + 2 + 1*4.
        assert_eq!(buf.len(), 2 + 255 * 4 + 2 + 4);
        assert_eq!(
            (buf[0], buf[1]),
            (AS_SEQ, 255),
            "first segment fills the limit"
        );
        let second = 2 + 255 * 4;
        assert_eq!(
            (buf[second], buf[second + 1]),
            (AS_SEQ, 1),
            "remainder carries the same segment type"
        );

        // The ASN sequence a peer reconstructs is unchanged.
        let (_, parsed) = As4Path::parse_be(&buf).unwrap();
        let flat: Vec<u32> = parsed
            .segs
            .iter()
            .flat_map(|s| s.asn.iter().copied())
            .collect();
        assert_eq!(flat, (1..=256u32).collect::<Vec<u32>>());
    }

    /// Exactly at the limit still emits a single segment.
    #[test]
    fn segment_at_limit_emits_one_segment() {
        let seg = As4Segment {
            typ: AS_SEQ,
            asn: (1..=255u32).collect(),
        };
        let mut buf = BytesMut::new();
        seg.emit(&mut buf);
        assert_eq!(buf.len(), 2 + 255 * 4);
        assert_eq!((buf[0], buf[1]), (AS_SEQ, 255));
    }

    /// An empty segment keeps emitting its header (`chunks` yields nothing for
    /// an empty slice, which would otherwise drop the segment entirely).
    #[test]
    fn empty_segment_still_emits_header() {
        let seg = As4Segment::new(AS_SEQ);
        let mut buf = BytesMut::new();
        seg.emit(&mut buf);
        assert_eq!(&buf[..], &[AS_SEQ, 0]);
    }

    /// The realistic trigger: an inbound path whose single AS_SEQ already holds
    /// the maximum 255, re-advertised over eBGP so `prepend_mut` merges the
    /// local AS in, reaching 256 in one segment.
    #[test]
    fn prepend_past_limit_round_trips() {
        let mut path = As4Path::from((1..=255u32).collect::<Vec<u32>>());
        path.prepend_mut(As4Path::from(vec![65000u32]));
        assert_eq!(path.segs.len(), 1, "prepend_mut merges into one segment");
        assert_eq!(
            path.segs[0].asn.len(),
            256,
            "which now exceeds the wire limit"
        );

        let (segs, flat) = emit_and_reparse(&path);
        assert_eq!(segs, 2, "emit splits it for the wire");
        assert_eq!(flat.len(), 256, "no ASN lost or invented");
        assert_eq!(flat[0], 65000, "prepended AS stays leftmost");
        assert_eq!(flat[1..], (1..=255u32).collect::<Vec<u32>>()[..]);
    }

    /// An AS_SET over the limit also splits, keeping its type on every piece.
    #[test]
    fn oversized_as_set_splits_keeping_type() {
        let seg = As4Segment {
            typ: AS_SET,
            asn: (1..=300u32).collect(),
        };
        let mut buf = BytesMut::new();
        seg.emit(&mut buf);
        let (_, parsed) = As4Path::parse_be(&buf).unwrap();
        assert_eq!(parsed.segs.len(), 2);
        assert!(parsed.segs.iter().all(|s| s.typ == AS_SET));
        let flat: Vec<u32> = parsed
            .segs
            .iter()
            .flat_map(|s| s.asn.iter().copied())
            .collect();
        assert_eq!(flat, (1..=300u32).collect::<Vec<u32>>());
    }

    /// `asn_from_string` accepts both RFC 5396 notations and round-trips
    /// `asn_to_string` (which renders asdot).
    #[test]
    fn asn_string_notations_round_trip() {
        // (asplain, asdot) for the same AS.
        let cases = [
            (65526u32, "65526", "65526"),
            (65546, "65546", "1.10"),
            (65536, "65536", "1.0"),
            (4200000000, "4200000000", "64086.59904"),
        ];
        for (asn, asplain, asdot) in cases {
            assert_eq!(asn_to_string(asn), asdot, "asn_to_string({asn})");
            assert_eq!(asn_from_string(asplain), Some(asn), "asplain {asplain}");
            assert_eq!(asn_from_string(asdot), Some(asn), "asdot {asdot}");
        }
        // asdot+ spells a 2-byte AS with an explicit zero high half.
        assert_eq!(asn_from_string("0.65526"), Some(65526));
    }

    /// asdot+ always dots, including below 65536 where asdot does not, and
    /// agrees with asdot everywhere at/above it. `asn_from_string` reads both.
    #[test]
    fn asdot_plus_always_dots_and_round_trips() {
        let cases = [
            (100u32, "0.100"),
            (65526, "0.65526"),
            (65536, "1.0"),
            (65546, "1.10"),
            (4200000000, "64086.59904"),
        ];
        for (asn, asdot_plus) in cases {
            assert_eq!(asn_to_asdot_plus(asn), asdot_plus, "asdot+ of {asn}");
            assert_eq!(asn_from_string(asdot_plus), Some(asn), "parse {asdot_plus}");
        }
        // At or above 65536 asdot+ and asdot are the same string.
        for asn in [65536u32, 65546, 4200000000] {
            assert_eq!(asn_to_asdot_plus(asn), asn_to_string(asn), "asn {asn}");
        }
        // Below 65536 they differ: that dot is what marks a type-2 RD.
        assert_eq!(asn_to_string(100), "100");
        assert_eq!(asn_to_asdot_plus(100), "0.100");
    }

    /// Both dotted halves are 16-bit; anything wider or malformed is rejected
    /// rather than silently truncated.
    #[test]
    fn asn_from_string_rejects_malformed() {
        for s in ["169031.1", "1.65536", "1.2.3", "", ".", "1.", ".1", "abc"] {
            assert_eq!(asn_from_string(s), None, "must reject {s:?}");
        }
        // u32::MAX is the largest valid asplain AS.
        assert_eq!(asn_from_string("4294967295"), Some(u32::MAX));
        assert_eq!(asn_from_string("4294967296"), None);
    }

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
    fn parse_explicit_seq() {
        let aspath: As4Path = As4Path::from_str("<1 2 3>").unwrap();
        assert_eq!(aspath.as_path_display(), "1 2 3");
        assert_eq!(aspath.as_path_explicit(), "<1 2 3>");

        let aspath: As4Path = As4Path::from_str("<1 2> {3 4} <5> (6 7)").unwrap();
        assert_eq!(aspath.as_path_display(), "1 2 {3 4} 5 (6 7)");
        assert_eq!(aspath.as_path_explicit(), "<1 2> {3 4} <5> (6 7)");

        let aspath: As4Path = As4Path::from_str("<1 2> <5> (6 7)").unwrap();
        println!("{}", aspath.as_path_display());
    }

    #[test]
    fn consolidate_adjacent_seq() {
        // Two adjacent AS_SEQ segments merged into one.
        let mut aspath: As4Path = As4Path::from_str("<1 2> <3 4>").unwrap();
        assert_eq!(aspath.as_path_explicit(), "<1 2> <3 4>");
        aspath.consolidate();
        assert_eq!(aspath.as_path_explicit(), "<1 2 3 4>");
        assert_eq!(aspath.as_path_display(), "1 2 3 4");
    }

    #[test]
    fn consolidate_with_other_segments() {
        // AS_SEQ segments separated by other types are not merged.
        let mut aspath: As4Path = As4Path::from_str("<1> <2 2> {3} <4 5>").unwrap();
        aspath.consolidate();
        assert_eq!(aspath.as_path_explicit(), "<1 2 2> {3} <4 5>");

        // Adjacent AS_SEQ before and after non-SEQ are merged independently.
        let mut aspath: As4Path = As4Path::from_str("<1> <2> <2> {3} <4> <5>").unwrap();
        aspath.consolidate();
        assert_eq!(aspath.as_path_explicit(), "<1 2 2> {3} <4 5>");
    }

    #[test]
    fn consolidate_single_segment() {
        // Single segment: no change.
        let mut aspath: As4Path = As4Path::from_str("1 2 3").unwrap();
        aspath.consolidate();
        assert_eq!(aspath.as_path_display(), "1 2 3");
    }

    #[test]
    fn consolidate_no_seq() {
        // No AS_SEQ segments: no change.
        let mut aspath: As4Path = As4Path::from_str("{1 2} (3 4)").unwrap();
        aspath.consolidate();
        assert_eq!(aspath.as_path_explicit(), "{1 2} (3 4)");
    }

    #[test]
    fn frr_string_uses_comma_in_sets() {
        // FRR's aspath->str comma-joins AS_SET / AS_CONFED_SET members and
        // space-joins AS_SEQUENCE / AS_CONFED_SEQUENCE members. This is the
        // string AS-path regexes run against, so it must match FRR exactly.
        let aspath: As4Path = As4Path::from_str("1 2 3 {4 5} (6 7) [8 9]").unwrap();
        assert_eq!(aspath.as_path_display(), "1 2 3 {4 5} (6 7) [8 9]");
        assert_eq!(aspath.as_path_frr_string(), "1 2 3 {4,5} (6 7) [8,9]");

        // A plain AS_SEQUENCE is identical in both renderings.
        let aspath: As4Path = As4Path::from_str("65001 65002 65003").unwrap();
        assert_eq!(aspath.as_path_frr_string(), "65001 65002 65003");
    }

    #[test]
    fn display_vs_explicit() {
        let aspath: As4Path = As4Path::from_str("1 2 3 {4 5} (6) [7]").unwrap();
        assert_eq!(aspath.as_path_display(), "1 2 3 {4 5} (6) [7]");
        assert_eq!(aspath.as_path_explicit(), "<1 2 3> {4 5} (6) [7]");

        let aspath: As4Path = As4Path::from_str("100 200").unwrap();
        assert_eq!(aspath.as_path_display(), "100 200");
        assert_eq!(aspath.as_path_explicit(), "<100 200>");
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
        assert!(aspath.contains_as_set_or_confed_set());
    }

    #[test]
    fn contains_as_set_or_confed_set_detects_deprecated_segments() {
        let seq = As4Path::from_str("65001 65002").unwrap();
        assert!(!seq.contains_as_set_or_confed_set());

        let as_set = As4Path::from_str("65001 {65010 65011}").unwrap();
        assert!(as_set.contains_as_set_or_confed_set());

        let confed_set = As4Path::from_str("65001 [65010 65011]").unwrap();
        assert!(confed_set.contains_as_set_or_confed_set());

        let confed_seq = As4Path::from_str("65001 (65010)").unwrap();
        assert!(!confed_seq.contains_as_set_or_confed_set());
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

    #[test]
    fn replace_as_mut_single() {
        // The canonical `as-override` case: a one-AS path equal to the
        // peer's remote-as is rewritten to the local AS, length intact.
        let mut aspath: As4Path = As4Path::from_str("65001").unwrap();
        aspath.replace_as_mut(65001, 65002);
        assert_eq!(aspath.to_string(), "65002");
        assert_eq!(aspath.length(), 1);
    }

    #[test]
    fn replace_as_mut_multiple_occurrences() {
        // Every occurrence is swapped, in every position.
        let mut aspath: As4Path = As4Path::from_str("65001 100 65001 200 65001").unwrap();
        aspath.replace_as_mut(65001, 65002);
        assert_eq!(aspath.to_string(), "65002 100 65002 200 65002");
        assert_eq!(aspath.length(), 5);
    }

    #[test]
    fn replace_as_mut_across_segments() {
        // Substitution reaches into AS_SET segments too; the set still
        // counts as a single hop, so length is unchanged.
        let mut aspath: As4Path = As4Path::from_str("65001 {65001 300}").unwrap();
        aspath.replace_as_mut(65001, 65002);
        assert_eq!(aspath.to_string(), "65002 {65002 300}");
        assert_eq!(aspath.length(), 2);
    }

    #[test]
    fn replace_as_mut_absent_is_noop() {
        let mut aspath: As4Path = As4Path::from_str("100 200 300").unwrap();
        aspath.replace_as_mut(65001, 65002);
        assert_eq!(aspath.to_string(), "100 200 300");
        assert_eq!(aspath.length(), 3);
    }

    #[test]
    fn as_override_egress_sequence_is_replace_then_prepend() {
        // The full egress transform applied to a route bound for a peer
        // in AS 65001 from a local AS of 65002: replace the peer's AS
        // first, *then* prepend the local AS. Order matters — prepending
        // first would leave the peer's AS in the path and re-introduce
        // the loop the override exists to avoid.
        let mut aspath: As4Path = As4Path::from_str("65001").unwrap();
        aspath.replace_as_mut(65001, 65002);
        aspath.prepend_mut(As4Path::from(vec![65002]));
        assert_eq!(aspath.to_string(), "65002 65002");
    }

    #[test]
    fn is_private_as_ranges() {
        // 16-bit private band (RFC 6996).
        assert!(!is_private_as(64511));
        assert!(is_private_as(64512));
        assert!(is_private_as(65001));
        assert!(is_private_as(65535));
        assert!(!is_private_as(65536));
        // Public ASNs (65000 sits *inside* the private band, so the
        // public sample is well clear of it).
        assert!(!is_private_as(100));
        assert!(!is_private_as(13335));
        // 32-bit private band; 4294967295 (AS_TRANS-adjacent reserved) is
        // excluded, matching FRR's upper bound of 4294967294.
        assert!(!is_private_as(4199999999));
        assert!(is_private_as(4200000000));
        assert!(is_private_as(4294967294));
        assert!(!is_private_as(4294967295));
    }

    #[test]
    fn is_all_private_mixed_and_empty() {
        assert!(As4Path::from_str("65001 65002").unwrap().is_all_private());
        // A single public AS makes the path not all-private.
        assert!(!As4Path::from_str("65001 100").unwrap().is_all_private());
        // An empty path is not all-private (matches FRR).
        assert!(!As4Path::new().is_all_private());
    }

    #[test]
    fn remove_private_as_strips_and_keeps_peer() {
        // "100 65001 200 65002" toward a peer in AS 200: both private
        // ASNs are stripped, the public 100/200 stay, and the hop count
        // drops from 4 to 2.
        let mut aspath: As4Path = As4Path::from_str("100 65001 200 65002").unwrap();
        aspath.remove_private_as_mut(200);
        assert_eq!(aspath.to_string(), "100 200");
        assert_eq!(aspath.length(), 2);

        // The peer's own AS is preserved even though it is private, so
        // the neighbor's loop check still fires.
        let mut aspath: As4Path = As4Path::from_str("100 65001 65002").unwrap();
        aspath.remove_private_as_mut(65002);
        assert_eq!(aspath.to_string(), "100 65002");
        assert_eq!(aspath.length(), 2);
    }

    #[test]
    fn remove_private_as_drops_empty_segments() {
        // An all-private path with no kept AS collapses to empty; the
        // now-empty segment is dropped rather than emitted zero-length.
        let mut aspath: As4Path = As4Path::from_str("65001 65002").unwrap();
        aspath.remove_private_as_mut(100);
        assert_eq!(aspath.to_string(), "");
        assert_eq!(aspath.length(), 0);
        assert!(aspath.segs.is_empty());
    }

    #[test]
    fn remove_private_as_reaches_into_sets() {
        // Private ASNs inside an AS_SET are stripped; a set that still
        // has a member survives as one hop, an emptied one is dropped.
        let mut aspath: As4Path = As4Path::from_str("100 {65001 300} 65002").unwrap();
        aspath.remove_private_as_mut(400);
        assert_eq!(aspath.to_string(), "100 {300}");
        assert_eq!(aspath.length(), 2);
    }

    #[test]
    fn replace_private_as_substitutes_keeping_peer() {
        // "100 65001 200 65002" toward AS 200 from local AS 500: each
        // private AS becomes 500, length is unchanged (1:1 swap).
        let mut aspath: As4Path = As4Path::from_str("100 65001 200 65002").unwrap();
        aspath.replace_private_as_mut(500, 200);
        assert_eq!(aspath.to_string(), "100 500 200 500");
        assert_eq!(aspath.length(), 4);

        // The peer's own (private) AS is left as-is.
        let mut aspath: As4Path = As4Path::from_str("65001 65002").unwrap();
        aspath.replace_private_as_mut(500, 65002);
        assert_eq!(aspath.to_string(), "500 65002");
    }

    #[test]
    fn remove_private_as_egress_sequence_is_strip_then_prepend() {
        // Full egress transform for bare `remove-private-as` toward a
        // peer in public AS 200 from local AS 200: the all-private path
        // "65001" is stripped to empty, then 200 is prepended, so the
        // neighbor receives just "200" instead of "200 65001".
        let mut aspath: As4Path = As4Path::from_str("65001").unwrap();
        aspath.remove_private_as_mut(200);
        aspath.prepend_mut(As4Path::from(vec![200]));
        assert_eq!(aspath.to_string(), "200");
    }
}
