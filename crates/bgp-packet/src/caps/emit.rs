use bytes::{BufMut, BytesMut};

use super::CapCode;

const CAPABILITY_CODE: u8 = 2;

pub trait CapEmit {
    fn code(&self) -> CapCode;

    fn len(&self) -> u8 {
        0
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn emit_value(&self, _buf: &mut BytesMut) {}

    fn emit(&self, buf: &mut BytesMut, opt: bool) {
        if !opt {
            buf.put_u8(CAPABILITY_CODE);
            // Optional-parameter length = code(1) + length(1) + value, so a
            // single classic optional parameter can only carry a value up to
            // 253 octets. Every `CapEmit` impl clamps its own `len()` to that
            // budget, so this add is exact in practice; `saturating_add` is a
            // final guard so a future capability whose `len()` reached 254–255
            // (unencodable here) can never overflow the u8 length octet.
            buf.put_u8(self.len().saturating_add(2));
        }
        buf.put_u8(self.code().into());
        buf.put_u8(self.len());
        self.emit_value(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal `CapEmit` whose value length is whatever we pass in, so we can
    /// exercise the shared framing at the budget boundary.
    struct DummyCap(u8);

    impl CapEmit for DummyCap {
        fn code(&self) -> CapCode {
            CapCode::Unknown(99)
        }
        fn len(&self) -> u8 {
            self.0
        }
        fn emit_value(&self, buf: &mut BytesMut) {
            buf.put_bytes(0, self.0 as usize);
        }
    }

    #[test]
    fn emit_max_value_param_length_is_exact() {
        // len() = 253 is the largest value a single classic optional parameter
        // can carry: the parameter length is 255, exactly filling the u8.
        let cap = DummyCap(253);
        let mut buf = BytesMut::new();
        cap.emit(&mut buf, false);
        let code: u8 = cap.code().into();
        assert_eq!(buf[0], CAPABILITY_CODE, "optional parameter type");
        assert_eq!(buf[1], 255, "optional-parameter length = len() + 2");
        assert_eq!(buf[2], code, "capability code");
        assert_eq!(buf[3], 253, "capability length");
        assert_eq!(buf.len(), 2 + 2 + 253);
    }

    #[test]
    fn emit_oversized_value_saturates_without_panic() {
        // No capability produces len() > 253 (each clamps its own value), but
        // emit() must not overflow the u8 length octet if one ever did.
        let cap = DummyCap(255);
        let mut buf = BytesMut::new();
        cap.emit(&mut buf, false); // must not panic
        assert_eq!(buf[1], 255, "parameter length saturates at u8::MAX");
    }

    #[test]
    fn emit_grouped_skips_param_framing() {
        // opt = true: the caller writes the optional-parameter framing, so
        // emit() writes only code + length + value.
        let cap = DummyCap(4);
        let mut buf = BytesMut::new();
        cap.emit(&mut buf, true);
        let code: u8 = cap.code().into();
        assert_eq!(buf[0], code, "capability code (no parameter framing)");
        assert_eq!(buf[1], 4, "capability length");
        assert_eq!(buf.len(), 2 + 4);
    }
}
