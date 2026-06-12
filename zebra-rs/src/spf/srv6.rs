//! Shared NEXT-C-SID (RFC 9800) carrier packing for TI-LFA SRv6
//! repair lists — used by every IGP that encodes repairs as SRv6 SID
//! lists (IS-IS, OSPFv3). The protocol-specific halves (extracting
//! `CsidBits` from each protocol's advertised SID wire formats) live
//! with their protocols; this module owns the encoding rules:
//! same-block runs collapse into 128-bit carriers, uA identifiers
//! require LIB continuity, zero identifiers and single-id carriers
//! fall back to the full SID, mixed lists degrade per-segment.

use std::net::Ipv6Addr;

/// One resolved SRv6 repair segment plus the NEXT-C-SID metadata the
/// carrier packer needs. `sid` is always the full advertised address,
/// usable verbatim when the segment can't ride in a carrier.
#[derive(Debug)]
pub(crate) struct RepairSeg {
    pub(crate) sid: Ipv6Addr,
    /// Vertex the packet sits on once this segment is consumed —
    /// the SID's owner for an End/uN, the adjacency's far end for an
    /// End.X/uA. Drives the LIB-continuity check below.
    pub(crate) landing: usize,
    /// `Some` when the SID was advertised with a NEXT-C-SID behavior
    /// and a usable structure; `None` forces full-SID encoding.
    pub(crate) csid: Option<CsidBits>,
}

/// The bits a segment contributes to a uSID carrier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CsidBits {
    /// The shared uSID block — the SID's first `lb` bits, masked.
    pub(crate) block: u128,
    pub(crate) lb: u8,
    /// The identifier consumed at the owner: locator-node bits for a
    /// uN, function bits for a uA. Right-aligned value.
    pub(crate) id: u128,
    pub(crate) width: u8,
    /// For a uA: the vertex that owns the adjacency. A LIB identifier
    /// is only locally significant, so it may only follow a segment
    /// that lands the packet on its owner; `None` for a uN, which is
    /// globally routable via the locator prefix.
    pub(crate) lib_owner: Option<usize>,
}

pub(crate) fn sid_bits(sid: Ipv6Addr, start: u32, width: u32) -> u128 {
    if width == 0 || start + width > 128 {
        return 0;
    }
    (u128::from(sid) >> (128 - start - width)) & ((1u128 << width) - 1)
}

pub(crate) fn sid_block(sid: Ipv6Addr, lb: u8) -> u128 {
    if lb == 0 {
        return 0;
    }
    u128::from(sid) & (u128::MAX << (128 - lb as u32))
}

/// In-progress uSID carrier: block bits up front, identifiers appended
/// left-to-right in traversal order, zero-padded tail (the zero
/// remainder is what triggers each node's end-of-carrier fallback).
struct Carrier {
    val: u128,
    block: u128,
    lb: u8,
    /// Next free bit position (starts at `lb`).
    pos: u32,
    /// Identifiers packed so far — a single-id carrier is re-emitted
    /// as the segment's full SID instead (identical forwarding, and it
    /// doesn't depend on the owner having LIB entries installed).
    ids: u8,
    first_sid: Ipv6Addr,
}

impl Carrier {
    fn flush(self, out: &mut Vec<Ipv6Addr>) {
        if self.ids == 1 {
            out.push(self.first_sid);
        } else {
            out.push(Ipv6Addr::from(self.val));
        }
    }
}

/// Pack a resolved SRv6 repair list into NEXT-C-SID carriers (RFC
/// 9800). Consecutive segments whose SIDs were advertised with uSID
/// behaviors and a shared locator block collapse into one 128-bit
/// carrier — block + 16-bit identifiers — instead of one full SID per
/// SRH segment. Anything that can't ride a carrier (classic behavior,
/// no structure, zero identifier, block change, LIB continuity break,
/// carrier full) is emitted as its full SID; mixed lists degrade
/// per-segment, never wholesale.
pub(crate) fn pack_carriers(parts: &[RepairSeg]) -> Vec<Ipv6Addr> {
    let mut out: Vec<Ipv6Addr> = Vec::with_capacity(parts.len());
    let mut cur: Option<Carrier> = None;
    let mut prev_landing: Option<usize> = None;

    for part in parts {
        let packable = part.csid.as_ref().filter(|c| {
            // A zero identifier would read as end-of-carrier on the
            // wire; never pack one. LIB (uA) identifiers additionally
            // require the previous segment to land on their owner —
            // that holds across carrier boundaries and full-SID
            // predecessors alike, since either way the packet sits on
            // the owner when the identifier becomes active.
            c.id != 0 && c.lib_owner.is_none_or(|owner| prev_landing == Some(owner))
        });
        match packable {
            Some(c) => {
                let fits = cur.as_ref().is_some_and(|car| {
                    car.block == c.block && car.lb == c.lb && car.pos + c.width as u32 <= 128
                });
                if !fits {
                    if let Some(car) = cur.take() {
                        car.flush(&mut out);
                    }
                    cur = Some(Carrier {
                        val: c.block,
                        block: c.block,
                        lb: c.lb,
                        pos: c.lb as u32,
                        ids: 0,
                        first_sid: part.sid,
                    });
                }
                let car = cur.as_mut().expect("carrier was just ensured");
                car.val |= c.id << (128 - car.pos - c.width as u32);
                car.pos += c.width as u32;
                car.ids += 1;
            }
            None => {
                if let Some(car) = cur.take() {
                    car.flush(&mut out);
                }
                out.push(part.sid);
            }
        }
        prev_landing = Some(part.landing);
    }
    if let Some(car) = cur.take() {
        car.flush(&mut out);
    }
    out
}
