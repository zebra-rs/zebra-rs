use std::fmt;
use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::error::{ErrorKind, make_error};
use nom_derive::*;

use crate::{BgpCap, BgpHeader, CapabilityHeader, CapabilityPacket, many0_complete};

pub const BGP_VERSION: u8 = 4;

#[derive(Debug, PartialEq, NomBE)]
pub struct OpenPacket {
    pub header: BgpHeader,
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub bgp_id: [u8; 4],
    pub opt_param_len: u8,
    #[nom(Ignore)]
    pub bgp_cap: BgpCap,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct OpenExtended {
    pub non_ext_op_type: u8,
    pub ext_opt_parm_len: u16,
}

impl OpenPacket {
    pub fn new(
        header: BgpHeader,
        asn: u16,
        hold_time: u16,
        router_id: &Ipv4Addr,
        bgp_cap: BgpCap,
    ) -> OpenPacket {
        OpenPacket {
            header,
            version: BGP_VERSION,
            asn,
            hold_time,
            bgp_id: router_id.octets(),
            opt_param_len: 0,
            bgp_cap,
        }
    }

    pub fn parse_packet(input: &[u8]) -> IResult<&[u8], OpenPacket> {
        let (input, mut packet) = OpenPacket::parse_be(input)?;
        let (input, len) = if packet.opt_param_len == 255 {
            let (input, ext) = OpenExtended::parse_be(input)?;
            if ext.non_ext_op_type != 255 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
            }
            (input, ext.ext_opt_parm_len)
        } else {
            (input, packet.opt_param_len as u16)
        };
        if input.len() != len as usize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        let (opts, input) = input.split_at(len as usize);
        let (_, caps) = many0_complete(parse_caps).parse(opts)?;
        let bgp_cap = BgpCap::from(caps);
        packet.bgp_cap = bgp_cap;
        Ok((input, packet))
    }
}

fn parse_caps(input: &[u8]) -> IResult<&[u8], Vec<CapabilityPacket>> {
    let (input, header) = CapabilityHeader::parse_be(input)?;
    let (opts, input) = input.split_at(header.length as usize);
    let (_, caps) = many0_complete(CapabilityPacket::parse_cap).parse(opts)?;
    Ok((input, caps))
}

impl From<OpenPacket> for BytesMut {
    fn from(open: OpenPacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = open.header.into();
        buf.put(&header[..]);
        buf.put_u8(open.version);
        buf.put_u16(open.asn);
        buf.put_u16(open.hold_time);
        buf.put(&open.bgp_id[..]);

        // Opt param buffer.
        let mut opt_buf = BytesMut::new();
        open.bgp_cap.emit(&mut opt_buf);

        // Extended opt param length as defined in RFC9072.
        let opt_param_len = opt_buf.len();
        if opt_param_len < 255 {
            buf.put_u8(opt_param_len as u8);
        } else {
            buf.put_u8(255u8);
            buf.put_u8(255u8);
            buf.put_u16(opt_param_len as u16);
        }
        buf.put(&opt_buf[..]);

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}

impl fmt::Display for OpenPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Open Message:")?;
        write!(f, "{}", self.bgp_cap)?;
        Ok(())
    }
}
