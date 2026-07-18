//! RFC 7761 §4.9.1 encoded address formats, shared by Join/Prune,
//! Assert, Register-Stop, Bootstrap and Candidate-RP messages.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use nom::error::{ErrorKind, make_error};
use nom::number::complete::be_u8;
use nom::{Err, IResult};
use packet_utils::ParseBe;

/// Address family numbers (IANA), the subset PIM uses.
pub const PIM_AF_IPV4: u8 = 1;
pub const PIM_AF_IPV6: u8 = 2;

/// Native encoding — the only encoding type defined by RFC 7761.
const PIM_ENC_NATIVE: u8 = 0;

// Encoded-Source flag bits (Rsvd(5) | S | W | R).
const SOURCE_FLAG_SPARSE: u8 = 0x04;
const SOURCE_FLAG_WILDCARD: u8 = 0x02;
const SOURCE_FLAG_RPT: u8 = 0x01;

// Encoded-Group flag bits (B | Rsvd(6) | Z).
const GROUP_FLAG_BIDIR: u8 = 0x80;
const GROUP_FLAG_ZONE: u8 = 0x01;

fn parse_pim_addr(input: &[u8], family: u8) -> IResult<&[u8], IpAddr> {
    match family {
        PIM_AF_IPV4 => {
            let (input, addr) = Ipv4Addr::parse_be(input)?;
            Ok((input, IpAddr::V4(addr)))
        }
        PIM_AF_IPV6 => {
            let (input, addr) = Ipv6Addr::parse_be(input)?;
            Ok((input, IpAddr::V6(addr)))
        }
        _ => Err(Err::Error(make_error(input, ErrorKind::Tag))),
    }
}

fn family_of(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => PIM_AF_IPV4,
        IpAddr::V6(_) => PIM_AF_IPV6,
    }
}

fn put_pim_addr(buf: &mut BytesMut, addr: &IpAddr) {
    match addr {
        IpAddr::V4(v4) => buf.put(&v4.octets()[..]),
        IpAddr::V6(v6) => buf.put(&v6.octets()[..]),
    }
}

fn host_masklen(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// The PIM address-family value (`PIM_AF_IPV4`/`PIM_AF_IPV6`) of an
/// address — used to reject family mixing within a message.
pub fn addr_family(addr: &IpAddr) -> u8 {
    family_of(addr)
}

/// Encoded-Unicast address: family, encoding type, native address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedUnicast {
    pub addr: IpAddr,
}

impl EncodedUnicast {
    pub fn new(addr: IpAddr) -> Self {
        Self { addr }
    }

    pub fn wire_len(&self) -> usize {
        2 + match self.addr {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    }

    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, family) = be_u8(input)?;
        let (input, enc) = be_u8(input)?;
        if enc != PIM_ENC_NATIVE {
            return Err(Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (input, addr) = parse_pim_addr(input, family)?;
        Ok((input, Self { addr }))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(family_of(&self.addr));
        buf.put_u8(PIM_ENC_NATIVE);
        put_pim_addr(buf, &self.addr);
    }
}

/// Encoded-Group address: family, encoding type, B/Z flags, mask
/// length, group address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedGroup {
    pub bidir: bool,
    pub zone: bool,
    pub masklen: u8,
    pub addr: IpAddr,
}

impl EncodedGroup {
    /// A single group (host mask length), the common case in
    /// Join/Prune, Assert and Register-Stop.
    pub fn new(addr: IpAddr) -> Self {
        Self {
            bidir: false,
            zone: false,
            masklen: host_masklen(&addr),
            addr,
        }
    }

    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, family) = be_u8(input)?;
        let (input, enc) = be_u8(input)?;
        if enc != PIM_ENC_NATIVE {
            return Err(Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (input, flags) = be_u8(input)?;
        let (input, masklen) = be_u8(input)?;
        let (input, addr) = parse_pim_addr(input, family)?;
        Ok((
            input,
            Self {
                bidir: flags & GROUP_FLAG_BIDIR != 0,
                zone: flags & GROUP_FLAG_ZONE != 0,
                masklen,
                addr,
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(family_of(&self.addr));
        buf.put_u8(PIM_ENC_NATIVE);
        let mut flags = 0u8;
        if self.bidir {
            flags |= GROUP_FLAG_BIDIR;
        }
        if self.zone {
            flags |= GROUP_FLAG_ZONE;
        }
        buf.put_u8(flags);
        buf.put_u8(self.masklen);
        put_pim_addr(buf, &self.addr);
    }
}

/// Encoded-Source address: family, encoding type, S/W/R flags, mask
/// length, source address. The flag combinations map to the RFC 7761
/// join/prune kinds: S alone = (S,G); S+W+R = (*,G) — the address is
/// then the RP; S+R = (S,G,rpt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedSource {
    pub sparse: bool,
    pub wildcard: bool,
    pub rpt: bool,
    pub masklen: u8,
    pub addr: IpAddr,
}

impl EncodedSource {
    /// (S,G) source: S bit only.
    pub fn sg(addr: IpAddr) -> Self {
        Self {
            sparse: true,
            wildcard: false,
            rpt: false,
            masklen: host_masklen(&addr),
            addr,
        }
    }

    /// (*,G) "source" — the RP address with S, W and R set.
    pub fn star_g(rp: IpAddr) -> Self {
        Self {
            sparse: true,
            wildcard: true,
            rpt: true,
            masklen: host_masklen(&rp),
            addr: rp,
        }
    }

    /// (S,G,rpt) source: S and R set.
    pub fn sg_rpt(addr: IpAddr) -> Self {
        Self {
            sparse: true,
            wildcard: false,
            rpt: true,
            masklen: host_masklen(&addr),
            addr,
        }
    }

    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, family) = be_u8(input)?;
        let (input, enc) = be_u8(input)?;
        if enc != PIM_ENC_NATIVE {
            return Err(Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (input, flags) = be_u8(input)?;
        let (input, masklen) = be_u8(input)?;
        let (input, addr) = parse_pim_addr(input, family)?;
        Ok((
            input,
            Self {
                sparse: flags & SOURCE_FLAG_SPARSE != 0,
                wildcard: flags & SOURCE_FLAG_WILDCARD != 0,
                rpt: flags & SOURCE_FLAG_RPT != 0,
                masklen,
                addr,
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(family_of(&self.addr));
        buf.put_u8(PIM_ENC_NATIVE);
        let mut flags = 0u8;
        if self.sparse {
            flags |= SOURCE_FLAG_SPARSE;
        }
        if self.wildcard {
            flags |= SOURCE_FLAG_WILDCARD;
        }
        if self.rpt {
            flags |= SOURCE_FLAG_RPT;
        }
        buf.put_u8(flags);
        buf.put_u8(self.masklen);
        put_pim_addr(buf, &self.addr);
    }
}
