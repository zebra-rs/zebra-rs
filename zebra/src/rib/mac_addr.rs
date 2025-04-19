#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MacAddr {
    octets: [u8; 6],
}

impl MacAddr {
    pub fn from_vec(vec: Vec<u8>) -> Option<Self> {
        if vec.len() != 6 {
            return None;
        }
        vec.try_into().ok().map(|octets| MacAddr { octets })
    }

    pub fn octets(&self) -> [u8; 6] {
        self.octets
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self { octets }
    }
}
