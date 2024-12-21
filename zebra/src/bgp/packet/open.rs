use bytes::BufMut;
use bytes::BytesMut;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use nom_derive::*;
use std::net::Ipv4Addr;

use super::cap::CapabilityHeader;
use super::cap::CapabilityPacket;
use super::cap::Emit;
use super::BgpHeader;
use super::CapabilityCode;
use super::{Afi, Safi};

use crate::bgp::BGP_VERSION;

#[derive(Debug, PartialEq, NomBE)]
pub struct OpenPacket {
    pub header: BgpHeader,
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub bgp_id: [u8; 4],
    pub opt_param_len: u8,
    #[nom(Ignore)]
    pub caps: Vec<CapabilityPacket>,
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
        caps: Vec<CapabilityPacket>,
    ) -> OpenPacket {
        OpenPacket {
            header,
            version: BGP_VERSION,
            asn,
            hold_time,
            bgp_id: router_id.octets(),
            opt_param_len: 0,
            caps,
        }
    }
}
