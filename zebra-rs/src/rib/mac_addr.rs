use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

    /// IEEE 802 group bit on the first octet — true for multicast
    /// and broadcast addresses (covers IPv4 multicast `01:00:5e:..`,
    /// IPv6 multicast `33:33:..`, broadcast `ff:ff:..`, and
    /// reserved-link L2 destinations like `01:80:c2:..`). EVPN
    /// Type-2 carries unicast host MACs only — multicast MACs that
    /// appear in the kernel FDB are reception filters on the local
    /// device, not remote hosts, and must not be originated to BGP
    /// peers nor installed from peer-advertised routes.
    pub fn is_multicast(&self) -> bool {
        (self.octets[0] & 0x01) != 0
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

#[cfg(test)]
mod tests {
    use super::MacAddr;

    #[test]
    fn is_multicast_covers_v4_v6_groups_and_broadcast() {
        // IPv4 multicast 01:00:5e:..
        assert!(MacAddr::from([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]).is_multicast());
        // IPv6 multicast 33:33:..
        assert!(MacAddr::from([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]).is_multicast());
        assert!(MacAddr::from([0x33, 0x33, 0xff, 0xca, 0x56, 0x57]).is_multicast());
        // Broadcast.
        assert!(MacAddr::from([0xff; 6]).is_multicast());
        // Reserved-link L2 (bridge BPDUs etc.) — group bit set.
        assert!(MacAddr::from([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]).is_multicast());
    }

    #[test]
    fn is_multicast_false_for_unicast() {
        assert!(!MacAddr::from([0x00, 0x1c, 0x42, 0x5f, 0x0b, 0x08]).is_multicast());
        assert!(!MacAddr::from([0xfe, 0xb2, 0x14, 0x6c, 0x11, 0x6e]).is_multicast());
        // Locally-administered unicast (U/L bit set, group bit clear).
        assert!(!MacAddr::from([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).is_multicast());
    }
}
