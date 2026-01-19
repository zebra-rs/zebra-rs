use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use nom::IResult;

pub fn u32_u8_3(value: u32) -> [u8; 3] {
    // Extract the three least significant bytes as big-endian
    [
        (value >> 16) as u8, // Most significant byte of the remaining 3 bytes
        (value >> 8) as u8,  // Middle byte
        value as u8,         // Least significant byte
    ]
}

pub trait ParseBe<T> {
    fn parse_be(input: &[u8]) -> IResult<&[u8], T>;
}

#[allow(clippy::len_without_is_empty)]
pub trait TlvEmitter {
    fn typ(&self) -> u8;
    fn len(&self) -> u8;
    fn emit(&self, buf: &mut BytesMut);

    fn tlv_emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ());
        buf.put_u8(self.len());
        self.emit(buf);
    }
}

pub fn write_hold_time(buf: &mut BytesMut, hold_time: u16) {
    BigEndian::write_u16(&mut buf[10..12], hold_time);
}
