//! BGP Flow Specification NLRI codec (RFC 8955 for IPv4, RFC 8956 for
//! IPv6).
//!
//! A Flow Specification NLRI is an n-tuple of match *components* — a
//! packet matches the spec only if it matches every component. On the
//! wire each NLRI is `<length, value>` where `value` is a sequence of
//! components ordered by ascending component type (RFC 8955 §4.1):
//!
//! ```text
//!   +-------------------------------+
//!   | length (1 or 2 octets)        |   value length in octets
//!   +-------------------------------+
//!   | component(1) | component(2) | ...
//!   +-------------------------------+
//! ```
//!
//! Component types 1 and 2 (destination / source prefix) carry an IP
//! prefix; in IPv6 they gain an `offset` field (RFC 8956 §3.1). Types
//! 3–13 carry a list of `{operator, value}` terms using one of two
//! operator encodings — numeric (RFC 8955 §4.2.1.1) or bitmask
//! (§4.2.1.2). Type 13 (Flow Label) is IPv6-only.
//!
//! This module is codec-only: it parses, re-emits, orders (per the
//! §5.1 precedence rules — see [`FlowspecNlri`]'s `Ord`), and renders
//! flow specs. Validation, RIB storage, and dataplane install live in
//! the `zebra-rs` BGP module and land in later phases.

use std::cmp::Ordering;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;
use packet_utils::safe_split_at;

use crate::{Afi, nlri_psize};

// Operator byte bit masks, shared by the numeric and bitmask encodings
// (RFC 8955 §4.2.1.1 / §4.2.1.2). The high nibble carries control bits
// common to both; the low nibble's meaning depends on the component.
const OP_END: u8 = 0x80; // 'e': last {op,value} term in the list.
const OP_AND: u8 = 0x40; // 'a': AND with the previous term (OR when clear).
const OP_LEN_MASK: u8 = 0x30; // value spans `1 << ((op & 0x30) >> 4)` octets.
// Numeric comparison bits (low nibble).
const OP_LT: u8 = 0x04;
const OP_GT: u8 = 0x02;
const OP_EQ: u8 = 0x01;
// Bitmask bits (low nibble).
const OP_NOT: u8 = 0x02;
const OP_MATCH: u8 = 0x01;

/// Width in octets of the value following an operator byte: `1 << len`
/// where `len` is the two-bit field at `0x30` (00→1, 01→2, 10→4, 11→8).
fn op_value_len(op: u8) -> usize {
    1usize << ((op & OP_LEN_MASK) >> 4)
}

/// A single `{operator, value}` term inside a numeric- or bitmask-op
/// component list. The full operator byte is retained verbatim so the
/// term re-emits bit-for-bit; `value` holds the right-aligned numeric
/// value (the wire carries only the low `op_value_len(op)` octets).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowspecOp {
    pub op: u8,
    pub value: u64,
}

impl FlowspecOp {
    /// Build a numeric term (`lt`/`gt`/`eq` combinable) with the
    /// smallest value width that fits `value`. The end-of-list bit is
    /// never stored — `emit_op_list` sets it on the final term — so
    /// terms compose freely without bookkeeping.
    pub fn numeric(and: bool, lt: bool, gt: bool, eq: bool, value: u64) -> Self {
        let mut op = 0u8;
        if and {
            op |= OP_AND;
        }
        if lt {
            op |= OP_LT;
        }
        if gt {
            op |= OP_GT;
        }
        if eq {
            op |= OP_EQ;
        }
        op |= len_bits_for(value);
        Self { op, value }
    }

    /// Build a bitmask term (`not`/`match`).
    pub fn bitmask(and: bool, not: bool, m: bool, value: u64) -> Self {
        let mut op = 0u8;
        if and {
            op |= OP_AND;
        }
        if not {
            op |= OP_NOT;
        }
        if m {
            op |= OP_MATCH;
        }
        op |= len_bits_for(value);
        Self { op, value }
    }

    fn is_end(&self) -> bool {
        self.op & OP_END != 0
    }

    pub fn is_and(&self) -> bool {
        self.op & OP_AND != 0
    }
}

/// Choose the two-bit length field for the narrowest power-of-two octet
/// width holding `value` (1, 2, 4, or 8 octets).
fn len_bits_for(value: u64) -> u8 {
    let bits = if value == 0 {
        1
    } else {
        64 - value.leading_zeros()
    };
    if bits <= 8 {
        0x00
    } else if bits <= 16 {
        0x10
    } else if bits <= 32 {
        0x20
    } else {
        0x30
    }
}

fn parse_op(input: &[u8]) -> IResult<&[u8], FlowspecOp> {
    let (input, op) = be_u8(input)?;
    let vlen = op_value_len(op);
    let (input, vbytes) = take(vlen).parse(input)?;
    let mut buf = [0u8; 8];
    buf[8 - vlen..].copy_from_slice(vbytes);
    let value = u64::from_be_bytes(buf);
    Ok((input, FlowspecOp { op, value }))
}

/// Parse a list of operator terms, stopping after the term whose
/// end-of-list bit is set (or when the component slice is exhausted, so
/// a missing end bit can't run into the next component).
///
/// The end bit is positional — it only ever marks the final term — so
/// it is stripped from the stored ops to keep the in-memory form
/// canonical (`emit_op_list` re-derives it from position). This makes
/// equality independent of how the sender flagged the terminator.
fn parse_op_list(mut input: &[u8]) -> IResult<&[u8], Vec<FlowspecOp>> {
    let mut ops = Vec::new();
    loop {
        let (rest, op) = parse_op(input)?;
        let end = op.is_end();
        ops.push(FlowspecOp {
            op: op.op & !OP_END,
            value: op.value,
        });
        input = rest;
        if end || input.is_empty() {
            break;
        }
    }
    Ok((input, ops))
}

/// Emit an operator-term list, forcing the end bit onto the final term
/// (and clearing it elsewhere) so hand-built lists always serialise to
/// valid wire form.
fn emit_op_list(ops: &[FlowspecOp], buf: &mut BytesMut) {
    let last = ops.len().saturating_sub(1);
    for (i, o) in ops.iter().enumerate() {
        let mut op = o.op & !OP_END;
        if i == last {
            op |= OP_END;
        }
        buf.put_u8(op);
        let vlen = op_value_len(op);
        let bytes = o.value.to_be_bytes();
        buf.put(&bytes[8 - vlen..]);
    }
}

/// Render one operator-term list. `bitmask` selects the bit semantics
/// (`not`/`match` vs `lt`/`gt`/`eq`); terms are joined with `&` (AND)
/// or `|` (OR) per each term's `a` bit.
fn fmt_op_list(ops: &[FlowspecOp], bitmask: bool, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for (i, o) in ops.iter().enumerate() {
        if i != 0 {
            f.write_str(if o.is_and() { "&" } else { "|" })?;
        }
        if bitmask {
            if o.op & OP_NOT != 0 {
                f.write_str("!")?;
            }
            if o.op & OP_MATCH != 0 {
                f.write_str("=")?;
            }
            write!(f, "0x{:x}", o.value)?;
        } else {
            if o.op & OP_LT != 0 {
                f.write_str("<")?;
            }
            if o.op & OP_GT != 0 {
                f.write_str(">")?;
            }
            if o.op & OP_EQ != 0 {
                f.write_str("=")?;
            }
            write!(f, "{}", o.value)?;
        }
    }
    Ok(())
}

/// Destination / source prefix component value. IPv4 (RFC 8955) is a
/// plain prefix; IPv6 (RFC 8956 §3.1) adds a bit `offset` and carries
/// only the `length - offset` pattern bits, so the raw pattern octets
/// are retained for exact round-tripping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlowspecPrefix {
    V4(Ipv4Net),
    V6 {
        length: u8,
        offset: u8,
        pattern: Vec<u8>,
    },
}

impl FlowspecPrefix {
    fn emit_value(&self, buf: &mut BytesMut) {
        match self {
            FlowspecPrefix::V4(net) => {
                let len = net.prefix_len();
                buf.put_u8(len);
                let psize = nlri_psize(len);
                buf.put(&net.addr().octets()[..psize]);
            }
            FlowspecPrefix::V6 {
                length,
                offset,
                pattern,
            } => {
                buf.put_u8(*length);
                buf.put_u8(*offset);
                buf.put(&pattern[..]);
            }
        }
    }
}

impl fmt::Display for FlowspecPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowspecPrefix::V4(net) => write!(f, "{net}"),
            FlowspecPrefix::V6 {
                length,
                offset,
                pattern,
            } => {
                if *offset == 0 {
                    let mut octets = [0u8; 16];
                    let n = pattern.len().min(16);
                    octets[..n].copy_from_slice(&pattern[..n]);
                    match Ipv6Net::new(Ipv6Addr::from(octets), *length) {
                        Ok(net) => write!(f, "{net}"),
                        Err(_) => write!(f, "len={length}/off={offset}"),
                    }
                } else {
                    write!(f, "len={length}/off={offset}/0x")?;
                    for b in pattern {
                        write!(f, "{b:02x}")?;
                    }
                    Ok(())
                }
            }
        }
    }
}

fn parse_prefix(input: &[u8], afi: Afi) -> IResult<&[u8], FlowspecPrefix> {
    match afi {
        Afi::Ip6 => {
            let (input, length) = be_u8(input)?;
            if length > 128 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
            }
            let (input, offset) = be_u8(input)?;
            if offset > length {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
            }
            let psize = nlri_psize(length - offset);
            let (input, pbytes) = take(psize).parse(input)?;
            Ok((
                input,
                FlowspecPrefix::V6 {
                    length,
                    offset,
                    pattern: pbytes.to_vec(),
                },
            ))
        }
        _ => {
            let (input, length) = be_u8(input)?;
            if length > 32 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
            }
            let psize = nlri_psize(length);
            let (input, pbytes) = take(psize).parse(input)?;
            let mut octets = [0u8; 4];
            octets[..psize].copy_from_slice(pbytes);
            let net = Ipv4Net::new(Ipv4Addr::from(octets), length)
                .map_err(|_| nom::Err::Error(make_error(input, ErrorKind::Verify)))?;
            Ok((input, FlowspecPrefix::V4(net)))
        }
    }
}

/// One Flow Specification match component (RFC 8955 Table 1 / RFC 8956).
/// Variant order matches the component-type numbering so the derived
/// layout reads top-to-bottom in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlowspecComponent {
    /// Type 1 — Destination Prefix.
    DestinationPrefix(FlowspecPrefix),
    /// Type 2 — Source Prefix.
    SourcePrefix(FlowspecPrefix),
    /// Type 3 — IP Protocol (IPv4) / Upper-Layer Protocol (IPv6).
    IpProtocol(Vec<FlowspecOp>),
    /// Type 4 — Port (source or destination).
    Port(Vec<FlowspecOp>),
    /// Type 5 — Destination Port.
    DestinationPort(Vec<FlowspecOp>),
    /// Type 6 — Source Port.
    SourcePort(Vec<FlowspecOp>),
    /// Type 7 — ICMP / ICMPv6 Type.
    IcmpType(Vec<FlowspecOp>),
    /// Type 8 — ICMP / ICMPv6 Code.
    IcmpCode(Vec<FlowspecOp>),
    /// Type 9 — TCP Flags (bitmask).
    TcpFlags(Vec<FlowspecOp>),
    /// Type 10 — Packet Length.
    PacketLength(Vec<FlowspecOp>),
    /// Type 11 — DSCP.
    Dscp(Vec<FlowspecOp>),
    /// Type 12 — Fragment (bitmask).
    Fragment(Vec<FlowspecOp>),
    /// Type 13 — Flow Label (IPv6 only, RFC 8956 §3.1).
    FlowLabel(Vec<FlowspecOp>),
}

impl FlowspecComponent {
    /// Wire component-type number (1–13).
    pub fn component_type(&self) -> u8 {
        match self {
            FlowspecComponent::DestinationPrefix(_) => 1,
            FlowspecComponent::SourcePrefix(_) => 2,
            FlowspecComponent::IpProtocol(_) => 3,
            FlowspecComponent::Port(_) => 4,
            FlowspecComponent::DestinationPort(_) => 5,
            FlowspecComponent::SourcePort(_) => 6,
            FlowspecComponent::IcmpType(_) => 7,
            FlowspecComponent::IcmpCode(_) => 8,
            FlowspecComponent::TcpFlags(_) => 9,
            FlowspecComponent::PacketLength(_) => 10,
            FlowspecComponent::Dscp(_) => 11,
            FlowspecComponent::Fragment(_) => 12,
            FlowspecComponent::FlowLabel(_) => 13,
        }
    }

    /// Encode the component value only (no leading type byte).
    fn emit_value(&self, buf: &mut BytesMut) {
        match self {
            FlowspecComponent::DestinationPrefix(p) | FlowspecComponent::SourcePrefix(p) => {
                p.emit_value(buf)
            }
            FlowspecComponent::IpProtocol(ops)
            | FlowspecComponent::Port(ops)
            | FlowspecComponent::DestinationPort(ops)
            | FlowspecComponent::SourcePort(ops)
            | FlowspecComponent::IcmpType(ops)
            | FlowspecComponent::IcmpCode(ops)
            | FlowspecComponent::TcpFlags(ops)
            | FlowspecComponent::PacketLength(ops)
            | FlowspecComponent::Dscp(ops)
            | FlowspecComponent::Fragment(ops)
            | FlowspecComponent::FlowLabel(ops) => emit_op_list(ops, buf),
        }
    }

    /// Encode the full component (type byte + value).
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.component_type());
        self.emit_value(buf);
    }

    /// The component value as raw octets, used by the §5.1 precedence
    /// comparison for non-prefix components.
    fn value_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        self.emit_value(&mut buf);
        buf.to_vec()
    }
}

impl fmt::Display for FlowspecComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowspecComponent::DestinationPrefix(p) => write!(f, "dst {p}"),
            FlowspecComponent::SourcePrefix(p) => write!(f, "src {p}"),
            FlowspecComponent::IpProtocol(ops) => {
                f.write_str("proto ")?;
                fmt_op_list(ops, false, f)
            }
            FlowspecComponent::Port(ops) => {
                f.write_str("port ")?;
                fmt_op_list(ops, false, f)
            }
            FlowspecComponent::DestinationPort(ops) => {
                f.write_str("dport ")?;
                fmt_op_list(ops, false, f)
            }
            FlowspecComponent::SourcePort(ops) => {
                f.write_str("sport ")?;
                fmt_op_list(ops, false, f)
            }
            FlowspecComponent::IcmpType(ops) => {
                f.write_str("icmp-type ")?;
                fmt_op_list(ops, false, f)
            }
            FlowspecComponent::IcmpCode(ops) => {
                f.write_str("icmp-code ")?;
                fmt_op_list(ops, false, f)
            }
            FlowspecComponent::TcpFlags(ops) => {
                f.write_str("tcp-flags ")?;
                fmt_op_list(ops, true, f)
            }
            FlowspecComponent::PacketLength(ops) => {
                f.write_str("length ")?;
                fmt_op_list(ops, false, f)
            }
            FlowspecComponent::Dscp(ops) => {
                f.write_str("dscp ")?;
                fmt_op_list(ops, false, f)
            }
            FlowspecComponent::Fragment(ops) => {
                f.write_str("fragment ")?;
                fmt_op_list(ops, true, f)
            }
            FlowspecComponent::FlowLabel(ops) => {
                f.write_str("flow-label ")?;
                fmt_op_list(ops, false, f)
            }
        }
    }
}

fn parse_component(input: &[u8], afi: Afi) -> IResult<&[u8], FlowspecComponent> {
    let (input, typ) = be_u8(input)?;
    match typ {
        1 => {
            let (input, p) = parse_prefix(input, afi)?;
            Ok((input, FlowspecComponent::DestinationPrefix(p)))
        }
        2 => {
            let (input, p) = parse_prefix(input, afi)?;
            Ok((input, FlowspecComponent::SourcePrefix(p)))
        }
        3 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::IpProtocol(ops)))
        }
        4 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::Port(ops)))
        }
        5 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::DestinationPort(ops)))
        }
        6 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::SourcePort(ops)))
        }
        7 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::IcmpType(ops)))
        }
        8 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::IcmpCode(ops)))
        }
        9 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::TcpFlags(ops)))
        }
        10 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::PacketLength(ops)))
        }
        11 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::Dscp(ops)))
        }
        12 => {
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::Fragment(ops)))
        }
        13 => {
            // Flow Label is IPv6-only (RFC 8956 §3.1); reject it under
            // an IPv4 flow spec rather than silently accept.
            if afi != Afi::Ip6 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
            }
            let (input, ops) = parse_op_list(input)?;
            Ok((input, FlowspecComponent::FlowLabel(ops)))
        }
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf))),
    }
}

/// A parsed Flow Specification NLRI: an ordered list of match
/// components, tagged with the address family it belongs to (so a
/// prefix-less spec still distinguishes IPv4 from IPv6) and an optional
/// Add-Path identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowspecNlri {
    /// RFC 7911 Add-Path identifier; 0 when Add-Path is not in use.
    pub id: u32,
    pub afi: Afi,
    pub components: Vec<FlowspecComponent>,
}

impl FlowspecNlri {
    pub fn new(afi: Afi, components: Vec<FlowspecComponent>) -> Self {
        Self {
            id: 0,
            afi,
            components,
        }
    }

    /// Parse one Flow Specification NLRI. `afi` selects the IPv4
    /// (RFC 8955) vs IPv6 (RFC 8956) prefix encoding and gates the
    /// IPv6-only Flow Label component.
    pub fn parse(input: &[u8], add_path: bool, afi: Afi) -> IResult<&[u8], FlowspecNlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };
        let (input, len) = parse_length(input)?;
        let (rest, value) = safe_split_at(input, len)?;
        let mut value = value;
        let mut components = Vec::new();
        while !value.is_empty() {
            let (next, comp) = parse_component(value, afi)?;
            components.push(comp);
            value = next;
        }
        Ok((
            rest,
            FlowspecNlri {
                id,
                afi,
                components,
            },
        ))
    }

    /// Emit one Flow Specification NLRI (`<length, value>`, prefixed by
    /// the 4-octet Add-Path id when `id != 0`). The value is buffered
    /// first so the length field is computed from the real component
    /// encoding.
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        if self.id != 0 {
            buf.put_u32(self.id);
        }
        let mut value = BytesMut::new();
        for c in &self.components {
            c.emit(&mut value);
        }
        emit_length(value.len(), buf);
        buf.put(&value[..]);
    }
}

/// Compare two flow specs by RFC 8955 §5.1 precedence. The
/// higher-precedence spec sorts **first** (`Ordering::Less`), so a
/// `BTreeMap` keyed on `FlowspecNlri` iterates in the order rules must
/// be applied in the dataplane.
impl Ord for FlowspecNlri {
    fn cmp(&self, other: &Self) -> Ordering {
        match flow_cmp(&self.components, &other.components) {
            Ordering::Equal => {
                // Components identical ⇒ structurally equal but for the
                // family / Add-Path id. Tie-break so `Ord` stays
                // consistent with the derived `Eq` (within one family
                // `afi` is constant, so precedence is unaffected).
                (u16::from(self.afi), self.id).cmp(&(u16::from(other.afi), other.id))
            }
            ord => ord,
        }
    }
}

impl PartialOrd for FlowspecNlri {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for FlowspecNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.components.iter().enumerate() {
            if i != 0 {
                f.write_str(",")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

/// Walk two component lists in lockstep applying §5.1: lower component
/// type wins; for an equal type the per-component rule decides; the
/// spec with more components (a strict superset of conditions) is the
/// more specific and wins when the shared prefix is equal.
fn flow_cmp(a: &[FlowspecComponent], b: &[FlowspecComponent]) -> Ordering {
    let mut ai = a.iter();
    let mut bi = b.iter();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Greater, // b is more specific
            (Some(_), None) => return Ordering::Less,    // a is more specific
            (Some(ca), Some(cb)) => {
                let (ta, tb) = (ca.component_type(), cb.component_type());
                if ta != tb {
                    return ta.cmp(&tb); // lower type ⇒ Less ⇒ higher precedence
                }
                let ord = component_precedence(ca, cb);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Precedence between two components of the *same* type.
fn component_precedence(a: &FlowspecComponent, b: &FlowspecComponent) -> Ordering {
    use FlowspecComponent::*;
    match (a, b) {
        (DestinationPrefix(pa), DestinationPrefix(pb)) | (SourcePrefix(pa), SourcePrefix(pb)) => {
            prefix_precedence(pa, pb)
        }
        _ => memcmp_precedence(&a.value_bytes(), &b.value_bytes()),
    }
}

/// §5.1 string rule: compare the common prefix as a binary string
/// (lower value ⇒ higher precedence); if the common prefix is equal the
/// longer string is more specific and wins.
fn memcmp_precedence(a: &[u8], b: &[u8]) -> Ordering {
    let n = a.len().min(b.len());
    match a[..n].cmp(&b[..n]) {
        Ordering::Equal => b.len().cmp(&a.len()), // longer ⇒ Less ⇒ higher precedence
        other => other,
    }
}

/// §5.1 IP-prefix rule: precedence to the lowest IP value over the
/// common (shorter) prefix length; if those bits are equal the more
/// specific (longer) prefix wins.
fn prefix_precedence(a: &FlowspecPrefix, b: &FlowspecPrefix) -> Ordering {
    match (a, b) {
        (FlowspecPrefix::V4(na), FlowspecPrefix::V4(nb)) => {
            let (la, lb) = (na.prefix_len(), nb.prefix_len());
            let common = la.min(lb);
            let va = mask_v4(u32::from(na.addr()), common);
            let vb = mask_v4(u32::from(nb.addr()), common);
            match va.cmp(&vb) {
                Ordering::Equal => lb.cmp(&la), // longer ⇒ Less ⇒ more specific
                other => other,
            }
        }
        (
            FlowspecPrefix::V6 {
                length: la,
                offset: 0,
                pattern: pa,
            },
            FlowspecPrefix::V6 {
                length: lb,
                offset: 0,
                pattern: pb,
            },
        ) => {
            let common = (*la).min(*lb);
            let va = mask_v6(v6_from_pattern(pa), common);
            let vb = mask_v6(v6_from_pattern(pb), common);
            match va.cmp(&vb) {
                Ordering::Equal => lb.cmp(la),
                other => other,
            }
        }
        // Mixed family or non-zero IPv6 offset: fall back to the binary
        // string rule on the encoded value (total and deterministic;
        // exact §5.1 ordering for offset prefixes is unspecified).
        _ => {
            let (mut ba, mut bb) = (BytesMut::new(), BytesMut::new());
            a.emit_value(&mut ba);
            b.emit_value(&mut bb);
            memcmp_precedence(&ba, &bb)
        }
    }
}

fn mask_v4(addr: u32, len: u8) -> u32 {
    if len == 0 {
        0
    } else if len >= 32 {
        addr
    } else {
        addr & (u32::MAX << (32 - len))
    }
}

fn mask_v6(addr: u128, len: u8) -> u128 {
    if len == 0 {
        0
    } else if len >= 128 {
        addr
    } else {
        addr & (u128::MAX << (128 - len))
    }
}

fn v6_from_pattern(pattern: &[u8]) -> u128 {
    let mut octets = [0u8; 16];
    let n = pattern.len().min(16);
    octets[..n].copy_from_slice(&pattern[..n]);
    u128::from_be_bytes(octets)
}

/// Parse the variable-length NLRI length field (RFC 8955 §4.1): a
/// single octet for values < 240, else a 2-octet value whose top nibble
/// is `0xf`.
fn parse_length(input: &[u8]) -> IResult<&[u8], usize> {
    let (input, b0) = be_u8(input)?;
    if b0 & 0xf0 == 0xf0 {
        let (input, b1) = be_u8(input)?;
        let len = (((b0 & 0x0f) as usize) << 8) | (b1 as usize);
        Ok((input, len))
    } else {
        Ok((input, b0 as usize))
    }
}

fn emit_length(len: usize, buf: &mut BytesMut) {
    if len < 240 {
        buf.put_u8(len as u8);
    } else {
        // RFC 8955 §4.1 caps the encodable length at 0xfff (4095).
        buf.put_u8(0xf0 | ((len >> 8) as u8 & 0x0f));
        buf.put_u8((len & 0xff) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a flow spec through emit → parse and assert equality.
    fn round_trip(nlri: &FlowspecNlri) {
        let mut buf = BytesMut::new();
        nlri.nlri_emit(&mut buf);
        let (rest, parsed) = FlowspecNlri::parse(&buf, nlri.id != 0, nlri.afi).expect("must parse");
        assert!(rest.is_empty(), "trailing bytes after parse");
        assert_eq!(&parsed, nlri);
    }

    #[test]
    fn ipv4_dst_proto_dport_round_trip() {
        let nlri = FlowspecNlri::new(
            Afi::Ip,
            vec![
                FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                    "10.0.0.0/24".parse().unwrap(),
                )),
                FlowspecComponent::IpProtocol(vec![FlowspecOp::numeric(
                    false, false, false, true, 6,
                )]),
                FlowspecComponent::DestinationPort(vec![FlowspecOp::numeric(
                    false, false, false, true, 80,
                )]),
            ],
        );
        round_trip(&nlri);
    }

    #[test]
    fn ipv4_port_range_two_terms_round_trip() {
        // dport >= 1024 AND <= 2048 — two numeric terms, the second
        // ANDed onto the first.
        let nlri = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPort(vec![
                FlowspecOp::numeric(false, false, true, true, 1024),
                FlowspecOp::numeric(true, true, false, true, 2048),
            ])],
        );
        round_trip(&nlri);
    }

    #[test]
    fn ipv4_tcp_flags_bitmask_round_trip() {
        // Match the SYN bit (0x02).
        let nlri = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::TcpFlags(vec![FlowspecOp::bitmask(
                false, false, true, 0x02,
            )])],
        );
        round_trip(&nlri);
    }

    #[test]
    fn ipv6_dst_nextheader_flowlabel_round_trip() {
        let nlri = FlowspecNlri::new(
            Afi::Ip6,
            vec![
                FlowspecComponent::DestinationPrefix(FlowspecPrefix::V6 {
                    length: 64,
                    offset: 0,
                    pattern: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets()[..8].to_vec(),
                }),
                FlowspecComponent::IpProtocol(vec![FlowspecOp::numeric(
                    false, false, false, true, 58,
                )]),
                FlowspecComponent::FlowLabel(vec![FlowspecOp::numeric(
                    false, false, false, true, 1234,
                )]),
            ],
        );
        round_trip(&nlri);
    }

    #[test]
    fn ipv6_prefix_with_offset_round_trips() {
        // Offset matching is retained verbatim via the raw pattern.
        let nlri = FlowspecNlri::new(
            Afi::Ip6,
            vec![FlowspecComponent::SourcePrefix(FlowspecPrefix::V6 {
                length: 128,
                offset: 64,
                pattern: vec![0, 0, 0, 0, 0, 0, 0, 1],
            })],
        );
        round_trip(&nlri);
    }

    #[test]
    fn flow_label_rejected_under_ipv4() {
        // Type 13 under an IPv4 spec must fail to parse.
        let mut value = BytesMut::new();
        FlowspecComponent::FlowLabel(vec![FlowspecOp::numeric(false, false, false, true, 1)])
            .emit(&mut value);
        let mut nlri = BytesMut::new();
        emit_length(value.len(), &mut nlri);
        nlri.put(&value[..]);
        assert!(FlowspecNlri::parse(&nlri, false, Afi::Ip).is_err());
    }

    #[test]
    fn two_octet_length_round_trips() {
        // Build a spec whose value exceeds 240 octets, forcing the
        // extended 2-octet length encoding. ~80 port terms × 3 octets.
        let ops: Vec<FlowspecOp> = (0..80)
            .map(|i| FlowspecOp::numeric(i != 0, false, false, true, 1000 + i as u64))
            .collect();
        let nlri = FlowspecNlri::new(Afi::Ip, vec![FlowspecComponent::DestinationPort(ops)]);
        let mut buf = BytesMut::new();
        nlri.nlri_emit(&mut buf);
        // First length octet must carry the 0xf extended-length nibble.
        assert_eq!(buf[0] & 0xf0, 0xf0, "expected 2-octet length encoding");
        round_trip(&nlri);
    }

    #[test]
    fn precedence_lower_type_wins() {
        // A spec leading with a destination prefix (type 1) outranks one
        // leading with a protocol match (type 3).
        let a = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                "10.0.0.0/24".parse().unwrap(),
            ))],
        );
        let b = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::IpProtocol(vec![FlowspecOp::numeric(
                false, false, false, true, 6,
            )])],
        );
        assert!(a < b, "type 1 must outrank type 3");
    }

    #[test]
    fn precedence_more_specific_prefix_wins() {
        // /24 is more specific than /16 of the same network ⇒ higher
        // precedence ⇒ sorts first.
        let more = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                "10.0.0.0/24".parse().unwrap(),
            ))],
        );
        let less = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                "10.0.0.0/16".parse().unwrap(),
            ))],
        );
        assert!(more < less);
    }

    #[test]
    fn precedence_lower_ip_value_wins() {
        let lower = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                "10.0.0.0/24".parse().unwrap(),
            ))],
        );
        let higher = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                "10.0.1.0/24".parse().unwrap(),
            ))],
        );
        assert!(lower < higher);
    }

    #[test]
    fn precedence_superset_is_more_specific() {
        // Same leading component, but `more` adds a second condition ⇒
        // it is the more specific spec and sorts first.
        let dst = || {
            FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4("10.0.0.0/24".parse().unwrap()))
        };
        let less = FlowspecNlri::new(Afi::Ip, vec![dst()]);
        let more = FlowspecNlri::new(
            Afi::Ip,
            vec![
                dst(),
                FlowspecComponent::IpProtocol(vec![FlowspecOp::numeric(
                    false, false, false, true, 6,
                )]),
            ],
        );
        assert!(more < less);
    }

    #[test]
    fn ord_consistent_with_eq() {
        let a = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                "10.0.0.0/24".parse().unwrap(),
            ))],
        );
        let b = a.clone();
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert_eq!(a, b);
    }

    #[test]
    fn display_renders_components() {
        let nlri = FlowspecNlri::new(
            Afi::Ip,
            vec![
                FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                    "10.0.0.0/24".parse().unwrap(),
                )),
                FlowspecComponent::DestinationPort(vec![FlowspecOp::numeric(
                    false, false, false, true, 80,
                )]),
            ],
        );
        assert_eq!(nlri.to_string(), "dst 10.0.0.0/24,dport =80");
    }
}
