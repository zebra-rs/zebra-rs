use bytes::{BufMut, BytesMut};
use nom::{IResult, Parser};
use packet_utils::{many0_complete, safe_split_at};

pub use packet_utils::{ParseBe, TlvEmitter, u32_u8_3, write_hold_time};

/// Parse a length-prefixed sub-TLV block: read the one-octet block
/// length, slice exactly that many bytes, and run `parse_one` to
/// exhaustion inside the slice. This is the shared shape behind every
/// reach-entry and SRv6-SID sub-TLV block (previously re-implemented
/// verbatim at eight sites).
pub fn parse_sub_block<T>(
    input: &[u8],
    parse_one: impl Fn(&[u8]) -> IResult<&[u8], T>,
) -> IResult<&[u8], Vec<T>> {
    let (input, sublen) = nom::number::complete::be_u8(input)?;
    if sublen == 0 {
        return Ok((input, Vec::new()));
    }
    let (input, sub) = safe_split_at(input, sublen as usize)?;
    let (_, subs) = many0_complete(parse_one).parse(sub)?;
    Ok((input, subs))
}

/// Emit sub-TLVs with a back-patched length byte.
///
/// Writes a placeholder `0u8`, calls `emit_fn` to write sub-TLV data, then
/// patches the placeholder with the actual length. A block larger than the
/// one-octet length field can express (255 bytes) is a builder bug — no
/// single entry may carry more sub-TLV bytes than fit — so it trips a debug
/// assert; in release the block is truncated to 255 bytes so the length
/// byte still matches the bytes present and the receiver's TLV walk stays
/// framed (the truncated tail parses as one malformed sub-TLV instead of
/// desyncing the rest of the PDU into phantom entries).
pub fn emit_sub_tlvs(buf: &mut BytesMut, emit_fn: impl FnOnce(&mut BytesMut)) {
    buf.put_u8(0);
    let pp = buf.len();
    emit_fn(buf);
    let block = buf.len() - pp;
    debug_assert!(
        block <= 255,
        "sub-TLV block overflows its one-octet length field: {block} bytes"
    );
    buf.truncate(pp + block.min(255));
    buf[pp - 1] = (buf.len() - pp) as u8;
}
