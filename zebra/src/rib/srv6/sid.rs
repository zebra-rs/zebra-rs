use ipnet::Ipv6Net;

pub enum SidFormat {
    /// Micro-SID (uSID) format. Block length 32bit and node length 16bit.
    #[allow(non_camel_case_types)]
    uSID_F3216,

    /// Full length SID format. Block length 40bit and node length 24bit.
    FullLength,
}

pub enum SidSource {
    Manager,
    OSPF,
    ISIS,
    BGP { asn: u32 },
}

pub struct Sid {
    prefix: Ipv6Net,
    format: SidFormat,
    source: SidSource,
}

impl Sid {
    pub fn new(prefix: &Ipv6Net) -> Self {
        Self {
            prefix: *prefix,
            format: SidFormat::uSID_F3216,
            source: SidSource::Manager,
        }
    }
}
