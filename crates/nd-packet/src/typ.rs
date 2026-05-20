/// ICMPv6 message types relevant to this codec (RFC 4443 + RFC 4861).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Icmp6Type {
    RouterSolicit = 133,
    RouterAdvert = 134,
}

impl Icmp6Type {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            133 => Some(Self::RouterSolicit),
            134 => Some(Self::RouterAdvert),
            _ => None,
        }
    }
}

impl From<Icmp6Type> for u8 {
    fn from(t: Icmp6Type) -> Self {
        t as u8
    }
}
