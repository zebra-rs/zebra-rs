use bytes::{BufMut, BytesMut};

use crate::{AttrFlags, AttrType};

pub trait AttrEmitter {
    fn attr_flags(&self) -> AttrFlags;

    fn attr_type(&self) -> AttrType;

    fn len(&self) -> Option<usize>;

    fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    fn emit(&self, buf: &mut BytesMut);

    fn attr_emit(&self, buf: &mut BytesMut) {
        // Helper to emit the header based on length.
        let emit_header = |buf: &mut BytesMut, len: usize, extended: bool| {
            if extended {
                buf.put_u8(self.attr_flags().with_extended(true).into());
                buf.put_u8(self.attr_type().into());
                buf.put_u16(len as u16);
            } else {
                buf.put_u8(self.attr_flags().into());
                buf.put_u8(self.attr_type().into());
                buf.put_u8(len as u8);
            }
        };

        if let Some(len) = self.len() {
            // Length is known.
            let extended = len > 255;
            emit_header(buf, len, extended);
            self.emit(buf);
        } else {
            // Buffer the attribute to determine its length.
            let mut attr_buf = BytesMut::new();
            self.emit(&mut attr_buf);
            let len = attr_buf.len();
            let extended = len > 255;
            emit_header(buf, len, extended);
            buf.put(&attr_buf[..]);
        }
    }
}
