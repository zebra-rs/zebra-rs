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
        match self {
            SidLabelTlv::Label(v) => buf.put(&u32_u8_3(*v)[..]),
            SidLabelTlv::Index(v) => buf.put_u32(*v),
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
