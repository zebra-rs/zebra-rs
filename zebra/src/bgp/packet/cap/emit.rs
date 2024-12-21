use bytes::{BufMut, BytesMut};

use super::CapabilityCode;

const CAPABILITY_CODE: u8 = 2;

pub trait Emit {
    fn code(&self) -> CapabilityCode;

    fn len(&self) -> u8 {
        0
    }

    fn emit_value(&self, buf: &mut BytesMut) {}

    fn emit(&self, buf: &mut BytesMut, opt: bool) {
        if !opt {
            buf.put_u8(CAPABILITY_CODE);
            buf.put_u8(self.len() + 2);
        }
        buf.put_u8(self.code().into());
        buf.put_u8(self.len());
        self.emit_value(buf);
    }
}
