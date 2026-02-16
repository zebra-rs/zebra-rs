use bytes::{BufMut, BytesMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FixedBufError {
    #[error("exceeds fixed capacity: need {need} bytes but only {remaining} remaining")]
    Overflow { need: usize, remaining: usize },
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

    pub fn put_slice(&mut self, src: &[u8]) -> Result<(), FixedBufError> {
        if src.len() > self.remaining() {
            return Err(FixedBufError::Overflow {
                need: src.len(),
                remaining: self.remaining(),
            });
        }
        self.inner.put_slice(src);
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
    fn test_put_slice_within_capacity() {
        let mut buf = FixedBuf::new(4096);
        assert!(buf.put_slice(b"hello").is_ok());
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
    fn test_put_slice_exceeds_capacity() {
        let mut buf = FixedBuf::new(3);
        let err = buf.put_slice(b"hello").unwrap_err();
        assert!(matches!(
            err,
            FixedBufError::Overflow {
                need: 5,
                remaining: 3
            }
        ));
    }
}
