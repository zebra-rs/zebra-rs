use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use nom::{IResult, error::ParseError};

// many0 which avoid passing empty input to the parser.
pub fn many0<'a, O, E: ParseError<&'a [u8]>>(
    parser: impl Fn(&'a [u8]) -> IResult<&'a [u8], O, E>,
) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Vec<O>, E> {
    move |input| {
        let mut res = Vec::new();
        let mut remaining = input;

        while !remaining.is_empty() {
            let (new_input, value) = parser(remaining)?;
            remaining = new_input;
            res.push(value);
        }

        Ok((remaining, res))
    }
}

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
