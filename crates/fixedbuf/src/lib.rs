use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FixedBufError {
    #[error("exceeds fixed capacity: need {need} bytes but only {remaining} remaining")]
    Overflow { need: usize, remaining: usize },
    #[error("out of bounds: pos {pos} + 2 exceeds length {len}")]
    OutOfBounds { pos: usize, len: usize },
}

pub struct FixedBuf {
    inner: BytesMut,
    capacity: usize,
}

impl FixedBuf {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: BytesMut::with_capacity(capacity),
            capacity,
        }
    }

    pub fn remaining(&self) -> usize {
        self.capacity - self.inner.len()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn get(self) -> BytesMut {
        self.inner
    }

    pub fn get_mut(&mut self) -> &mut BytesMut {
        &mut self.inner
    }

    pub fn put_u16(&mut self, val: u16) -> Result<(), FixedBufError> {
        let need = 2;
        if need > self.remaining() {
            return Err(FixedBufError::Overflow {
                need,
                remaining: self.remaining(),
            });
        }
        self.inner.put_u16(val);
        Ok(())
    }

    pub fn put(&mut self, src: &[u8]) -> Result<(), FixedBufError> {
        if src.len() > self.remaining() {
            return Err(FixedBufError::Overflow {
                need: src.len(),
                remaining: self.remaining(),
            });
        }
        self.inner.put_slice(src);
        Ok(())
    }

    pub fn put_u16_at(&mut self, pos: usize, val: u16) -> Result<(), FixedBufError> {
        if pos + 2 > self.inner.len() {
            return Err(FixedBufError::OutOfBounds {
                pos,
                len: self.inner.len(),
            });
        }
        BigEndian::write_u16(&mut self.inner[pos..], val);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_u16_within_capacity() {
        let mut buf = FixedBuf::new(4096);
        assert!(buf.put_u16(1233).is_ok());
        assert_eq!(buf.remaining(), 4094);
    }

    #[test]
    fn test_put_within_capacity() {
        let mut buf = FixedBuf::new(4096);
        assert!(buf.put(b"hello").is_ok());
        assert_eq!(buf.remaining(), 4091);
    }

    #[test]
    fn test_put_u16_exceeds_capacity() {
        let mut buf = FixedBuf::new(1);
        let err = buf.put_u16(1233).unwrap_err();
        assert!(matches!(
            err,
            FixedBufError::Overflow {
                need: 2,
                remaining: 1
            }
        ));
    }

    #[test]
    fn test_put_exceeds_capacity() {
        let mut buf = FixedBuf::new(3);
        let err = buf.put(b"hello").unwrap_err();
        assert!(matches!(
            err,
            FixedBufError::Overflow {
                need: 5,
                remaining: 3
            }
        ));
    }

    #[test]
    fn test_put_u16_at() {
        let mut buf = FixedBuf::new(4096);
        buf.put_u16(0).unwrap(); // placeholder
        buf.put(b"hello").unwrap();
        buf.put_u16_at(0, 0x1234).unwrap();
        let inner = buf.get();
        assert_eq!(inner[0], 0x12);
        assert_eq!(inner[1], 0x34);
    }

    #[test]
    fn test_put_u16_at_out_of_bounds() {
        let mut buf = FixedBuf::new(4096);
        buf.put(b"hi").unwrap();
        let err = buf.put_u16_at(1, 0x1234).unwrap_err();
        assert!(matches!(err, FixedBufError::OutOfBounds { pos: 1, len: 2 }));
    }
}
