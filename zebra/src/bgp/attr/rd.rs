use nom_derive::*;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Default, NomBE, PartialEq, Debug)]
pub enum RouteDistinguisherType {
    #[default]
    ASN = 0,
    IP = 1,
}

#[derive(Default, NomBE, PartialEq, Debug)]
pub struct RouteDistinguisher {
    pub typ: RouteDistinguisherType,
    pub val: [u8; 6],
}

impl RouteDistinguisher {
    pub fn new(typ: RouteDistinguisherType) -> Self {
        Self {
            typ,
            ..Default::default()
        }
    }
}

impl FromStr for RouteDistinguisher {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let strs: Vec<&str> = s.split(':').collect();
        if strs.len() != 2 {
            return Err(());
        }
        // A 16-bit autonomous system number, a colon, and a 32-bit number, for
        // example: 65000:3
        if let Ok(addr) = strs[0].parse::<Ipv4Addr>() {
            if let Ok(val) = strs[1].parse::<u16>() {
                let mut rd = RouteDistinguisher::new(RouteDistinguisherType::IP);
                rd.val[0..4].copy_from_slice(&addr.octets());
                rd.val[4..6].copy_from_slice(&val.to_be_bytes());
                return Ok(rd);
            }
        }
        // A 32-bit IP address, a colon, and a 16-bit number, for example:
        // 192.168.1.2:51
        if let Ok(asn) = strs[0].parse::<u16>() {
            if let Ok(val) = strs[1].parse::<u32>() {
                let mut rd = RouteDistinguisher::new(RouteDistinguisherType::ASN);
                rd.val[0..2].copy_from_slice(&asn.to_be_bytes());
                rd.val[2..6].copy_from_slice(&val.to_be_bytes());
                return Ok(rd);
            }
        }
        Err(())
    }
}

impl fmt::Display for RouteDistinguisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.typ == RouteDistinguisherType::ASN {
            let asn = u16::from_be_bytes([self.val[0], self.val[1]]);
            let val = u32::from_be_bytes([self.val[2], self.val[3], self.val[4], self.val[5]]);
            write!(f, "{asn}:{val}")
        } else {
            let ip = Ipv4Addr::new(self.val[0], self.val[1], self.val[2], self.val[3]);
            let val = u16::from_be_bytes([self.val[4], self.val[5]]);
            write!(f, "{ip}:{val}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let rd: RouteDistinguisher = RouteDistinguisher::from_str("65000:3").unwrap();
        assert_eq!(rd.to_string(), "65000:3");

        let rd: RouteDistinguisher = RouteDistinguisher::from_str("192.168.1.2:51").unwrap();
        assert_eq!(rd.to_string(), "192.168.1.2:51");
    }
}
