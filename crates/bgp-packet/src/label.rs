// MPLS Label encoding (RFC 3032):
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Label (20 bits)                | Exp |S| TTL   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// In BGP MP_REACH_NLRI, only 3 octets are used (no TTL field):
// |                Label (20 bits)                | Exp |S|
#[derive(Debug, Clone, Copy)]
pub struct Label {
    pub label: u32,
    pub exp: u8,
    pub bos: bool,
}

impl From<&[u8]> for Label {
    fn from(val: &[u8]) -> Self {
        if val.len() < 3 {
            return Label {
                label: 0,
                exp: 0,
                bos: false,
            };
        }

        let label = ((val[0] as u32) << 12) | ((val[1] as u32) << 4) | ((val[2] as u32) >> 4);
        let exp = (val[2] >> 1) & 0x07;
        let bos = (val[2] & 0x01) == 1;

        Label { label, exp, bos }
    }
}

impl Label {
    pub fn new(label: u32, exp: u8, bos: bool) -> Self {
        Label { label, exp, bos }
    }

    pub fn to_bytes(&self) -> [u8; 3] {
        let mut bytes = [0u8; 3];
        bytes[0] = ((self.label >> 12) & 0xFF) as u8;
        bytes[1] = ((self.label >> 4) & 0xFF) as u8;
        bytes[2] = (((self.label & 0x0F) << 4)
            | ((self.exp as u32 & 0x07) << 1)
            | (self.bos as u32)) as u8;
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Label::from(bytes)
    }
}

impl Default for Label {
    fn default() -> Self {
        Self::new(0, 0, true)
    }
}
