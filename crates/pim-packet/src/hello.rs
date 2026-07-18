//! PIM Hello message (RFC 7761 §4.9.2): a sequence of option TLVs
//! with 16-bit type and length fields.

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u16, be_u32};
use nom::{Err, Parser};
use packet_utils::many0_complete;

use crate::addr::EncodedUnicast;

pub const PIM_HELLO_TLV_HOLDTIME: u16 = 1;
pub const PIM_HELLO_TLV_LAN_PRUNE_DELAY: u16 = 2;
pub const PIM_HELLO_TLV_DR_PRIORITY: u16 = 19;
pub const PIM_HELLO_TLV_GENERATION_ID: u16 = 20;
pub const PIM_HELLO_TLV_ADDRESS_LIST: u16 = 24;

/// LAN Prune Delay: T bit is the top bit of the propagation delay
/// field (RFC 7761 §4.3.3 — "can disable join suppression").
const LAN_PRUNE_DELAY_T_BIT: u16 = 0x8000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloTlv {
    Holdtime(u16),
    LanPruneDelay {
        t_bit: bool,
        propagation_delay: u16,
        override_interval: u16,
    },
    DrPriority(u32),
    GenerationId(u32),
    AddressList(Vec<EncodedUnicast>),
    Unknown {
        typ: u16,
        data: Vec<u8>,
    },
}

impl HelloTlv {
    /// Parse one TLV. A known option whose value has an unexpected
    /// length is preserved as `Unknown` rather than failing the whole
    /// Hello — receivers must ignore options they cannot use.
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u16(input)?;
        let (input, len) = be_u16(input)?;
        let (input, value) = take(len as usize)(input)?;
        let tlv = match (typ, value.len()) {
            (PIM_HELLO_TLV_HOLDTIME, 2) => {
                let (_, holdtime) = be_u16(value)?;
                Self::Holdtime(holdtime)
            }
            (PIM_HELLO_TLV_LAN_PRUNE_DELAY, 4) => {
                let (value, delay) = be_u16(value)?;
                let (_, override_interval) = be_u16(value)?;
                Self::LanPruneDelay {
                    t_bit: delay & LAN_PRUNE_DELAY_T_BIT != 0,
                    propagation_delay: delay & !LAN_PRUNE_DELAY_T_BIT,
                    override_interval,
                }
            }
            (PIM_HELLO_TLV_DR_PRIORITY, 4) => {
                let (_, priority) = be_u32(value)?;
                Self::DrPriority(priority)
            }
            (PIM_HELLO_TLV_GENERATION_ID, 4) => {
                let (_, gen_id) = be_u32(value)?;
                Self::GenerationId(gen_id)
            }
            (PIM_HELLO_TLV_ADDRESS_LIST, _) => {
                let (rest, addrs) = many0_complete(EncodedUnicast::parse_be).parse(value)?;
                if !rest.is_empty() {
                    return Err(Err::Error(make_error(rest, ErrorKind::LengthValue)));
                }
                Self::AddressList(addrs)
            }
            _ => Self::Unknown {
                typ,
                data: value.to_vec(),
            },
        };
        Ok((input, tlv))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        match self {
            Self::Holdtime(holdtime) => {
                buf.put_u16(PIM_HELLO_TLV_HOLDTIME);
                buf.put_u16(2);
                buf.put_u16(*holdtime);
            }
            Self::LanPruneDelay {
                t_bit,
                propagation_delay,
                override_interval,
            } => {
                buf.put_u16(PIM_HELLO_TLV_LAN_PRUNE_DELAY);
                buf.put_u16(4);
                let mut delay = propagation_delay & !LAN_PRUNE_DELAY_T_BIT;
                if *t_bit {
                    delay |= LAN_PRUNE_DELAY_T_BIT;
                }
                buf.put_u16(delay);
                buf.put_u16(*override_interval);
            }
            Self::DrPriority(priority) => {
                buf.put_u16(PIM_HELLO_TLV_DR_PRIORITY);
                buf.put_u16(4);
                buf.put_u32(*priority);
            }
            Self::GenerationId(gen_id) => {
                buf.put_u16(PIM_HELLO_TLV_GENERATION_ID);
                buf.put_u16(4);
                buf.put_u32(*gen_id);
            }
            Self::AddressList(addrs) => {
                buf.put_u16(PIM_HELLO_TLV_ADDRESS_LIST);
                let len: usize = addrs.iter().map(|a| a.wire_len()).sum();
                buf.put_u16(len as u16);
                for addr in addrs {
                    addr.emit(buf);
                }
            }
            Self::Unknown { typ, data } => {
                buf.put_u16(*typ);
                buf.put_u16(data.len() as u16);
                buf.put(&data[..]);
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PimHello {
    pub tlvs: Vec<HelloTlv>,
}

impl PimHello {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, tlvs) = many0_complete(HelloTlv::parse_be).parse(input)?;
        if !rest.is_empty() {
            // Trailing bytes that do not form a TLV header.
            return Err(Err::Error(make_error(rest, ErrorKind::LengthValue)));
        }
        Ok((rest, Self { tlvs }))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }

    pub fn holdtime(&self) -> Option<u16> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            HelloTlv::Holdtime(v) => Some(*v),
            _ => None,
        })
    }

    pub fn dr_priority(&self) -> Option<u32> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            HelloTlv::DrPriority(v) => Some(*v),
            _ => None,
        })
    }

    pub fn generation_id(&self) -> Option<u32> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            HelloTlv::GenerationId(v) => Some(*v),
            _ => None,
        })
    }

    /// (t_bit, propagation_delay_ms, override_interval_ms).
    pub fn lan_prune_delay(&self) -> Option<(bool, u16, u16)> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            HelloTlv::LanPruneDelay {
                t_bit,
                propagation_delay,
                override_interval,
            } => Some((*t_bit, *propagation_delay, *override_interval)),
            _ => None,
        })
    }

    pub fn address_list(&self) -> Option<&[EncodedUnicast]> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            HelloTlv::AddressList(v) => Some(v.as_slice()),
            _ => None,
        })
    }
}
