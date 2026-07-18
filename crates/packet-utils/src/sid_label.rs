use bytes::{BufMut, BytesMut};
use nom::number::complete::{be_u8, be_u24, be_u32};
use nom::{Err, IResult, Needed};
use serde::{Deserialize, Serialize};

use crate::u32_u8_3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SidLabelTlv {
    Label(u32),
    Index(u32),
}

impl SidLabelTlv {
    pub fn len(&self) -> u8 {
        match self {
            SidLabelTlv::Label(_) => 3,
            SidLabelTlv::Index(_) => 4,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(1); // SID/Label sub-TLV type is always 1.
        buf.put_u8(self.len());
        self.emit_value(buf);
    }

    /// Emit just the 3-byte Label / 4-byte Index value, without any TLV header.
    /// OSPF (RFC 8665/8666) frames the SID/Label with its own 2-byte type +
    /// 2-byte length header and emits the value via this method.
    pub fn emit_value(&self, buf: &mut BytesMut) {
        match self {
            SidLabelTlv::Label(v) => buf.put(&u32_u8_3(*v)[..]),
            SidLabelTlv::Index(v) => buf.put_u32(*v),
        }
    }

    /// Parse a SID/Label *value* whose length was read from a preceding header
    /// (3 = 24-bit Label, 4 = 32-bit Index). Used by the OSPF codecs, whose
    /// sub-TLV framing differs from IS-IS's `parse_sid_label`.
    pub fn parse_by_len(input: &[u8], len: usize) -> IResult<&[u8], SidLabelTlv> {
        match len {
            3 => {
                let (input, label) = be_u24(input)?;
                Ok((input, SidLabelTlv::Label(label)))
            }
            4 => {
                let (input, index) = be_u32(input)?;
                Ok((input, SidLabelTlv::Index(index)))
            }
            _ => Err(Err::Incomplete(Needed::new(len))),
        }
    }
}

pub fn parse_sid_label(input: &[u8]) -> IResult<&[u8], SidLabelTlv> {
    let (input, _typ) = be_u8(input)?;
    let (input, len) = be_u8(input)?;
    match len {
        3 => {
            let (input, label) = be_u24(input)?;
            Ok((input, SidLabelTlv::Label(label)))
        }
        4 => {
            let (input, index) = be_u32(input)?;
            Ok((input, SidLabelTlv::Index(index)))
        }
        _ => Err(Err::Incomplete(Needed::new(len as usize))),
    }
}
