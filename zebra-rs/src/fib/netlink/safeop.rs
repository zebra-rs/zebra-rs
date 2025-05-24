// Not used anymore.
trait SafeOp {
    fn safe_sub(self, v: u8) -> u8;
}

impl SafeOp for u8 {
    fn safe_sub(self, v: u8) -> u8 {
        if self >= v {
            self - v
        } else {
            0
        }
    }
}
