use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Serialize)]
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

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5],
        )
    }
}
