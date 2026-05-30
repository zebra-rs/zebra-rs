use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::Parser;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

use crate::many0_complete;

/// Extended Admin Group bitmap payload (RFC 7308): a sequence of
/// 32-bit big-endian words holding 32 group bits each. Word N covers
/// group ids `(N*32)..((N+1)*32)`; within a word, bit 0 is the LSB
/// and the word is serialized big-endian.
///
/// Lives in `packet-utils` because both IS-IS (RFC 9350 FAD admin-
/// group constraint sub-TLVs / RFC 9479 ASLA) and OSPF (RFC 9350 FAD
/// / RFC 8920 ASLA) carry the identical bitmap; the wire framing of
/// the enclosing TLV differs per protocol but this payload does not.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtAdminGroup {
    pub words: Vec<u32>,
}

impl ExtAdminGroup {
    /// Set bit `n` (RFC 7308 group id). Grows the bitmap as needed.
    pub fn set(&mut self, n: u16) {
        let word = (n / 32) as usize;
        let bit = (n % 32) as u32;
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= 1u32 << bit;
    }

    /// True iff bit `n` is set.
    pub fn get(&self, n: u16) -> bool {
        let word = (n / 32) as usize;
        let bit = (n % 32) as u32;
        self.words
            .get(word)
            .is_some_and(|w| (*w & (1u32 << bit)) != 0)
    }

    /// Byte length on the wire (4 per word).
    pub fn byte_len(&self) -> usize {
        self.words.len() * 4
    }

    /// Parse a bitmap payload: every remaining 32-bit word is one
    /// admin-group word. Callers slice the sub-TLV value first so the
    /// `many0` consumes exactly the bitmap.
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, words) = many0_complete(be_u32).parse(input)?;
        Ok((input, ExtAdminGroup { words }))
    }

    /// Emit the bitmap words big-endian into `buf`.
    pub fn emit(&self, buf: &mut BytesMut) {
        for w in &self.words {
            buf.put_u32(*w);
        }
    }
}
