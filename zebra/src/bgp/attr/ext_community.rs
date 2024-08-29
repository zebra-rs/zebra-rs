use bytes::{BufMut, BytesMut};
use nom_derive::NomBE;
use std::str::FromStr;
use std::{fmt, net::Ipv4Addr};

use super::{
    encode_tlv,
    ext_community_token::{tokenizer, Token},
    RouteDistinguisher, RouteDistinguisherType,
};
use super::{AttributeEncoder, AttributeFlags, AttributeType};

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtCommunity(pub Vec<ExtCommunityValue>);

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtCommunityValue {
    pub high_type: u8,
    pub low_type: u8,
    pub val: [u8; 6],
}

#[derive(PartialEq)]
enum State {
    Unspec,
    Rt,
    Soo,
}

impl ExtCommunityValue {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.high_type);
        buf.put_u8(self.low_type);
        buf.put(&self.val[..]);
    }
}

impl fmt::Display for ExtCommunityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.high_type == 0 {
            let asn = u16::from_be_bytes([self.val[0], self.val[1]]);
            let val = u32::from_be_bytes([self.val[2], self.val[3], self.val[4], self.val[5]]);
            if self.low_type == 0x02 {
                write!(f, "rt {asn}:{val}")
            } else {
                write!(f, "soo {asn}:{val}")
            }
        } else {
            let ip = Ipv4Addr::new(self.val[0], self.val[1], self.val[2], self.val[3]);
            let val = u16::from_be_bytes([self.val[4], self.val[5]]);
            if self.low_type == 0x02 {
                write!(f, "rt {ip}:{val}")
            } else {
                write!(f, "soo {ip}:{val}")
            }
        }
    }
}

impl AttributeEncoder for ExtCommunity {
    fn attr_type() -> AttributeType {
        AttributeType::ExtendedCom
    }

    fn attr_flag() -> AttributeFlags {
        AttributeFlags::OPTIONAL | AttributeFlags::TRANSITIVE
    }
}

impl ExtCommunity {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut attr_buf = BytesMut::new();
        self.0.iter().for_each(|x| x.encode(&mut attr_buf));
        encode_tlv::<Self>(buf, attr_buf);
    }
}

impl fmt::Display for ExtCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .0
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{v}")
    }
}

impl FromStr for ExtCommunity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ecom = ExtCommunity::default();
        let tokens = tokenizer(String::from(s)).unwrap();
        let mut state = State::Unspec;

        for token in tokens.into_iter() {
            match token {
                Token::Rd(rd) => {
                    let mut val: ExtCommunityValue = rd.into();
                    match state {
                        State::Unspec => {
                            return Err(());
                        }
                        State::Rt => {
                            val.low_type = 0x02;
                        }
                        State::Soo => {
                            val.low_type = 0x03;
                        }
                    }
                    ecom.0.push(val);
                }
                Token::Rt => {
                    state = State::Rt;
                }
                Token::Soo => {
                    state = State::Soo;
                }
            }
        }
        Ok(ecom)
    }
}

impl From<RouteDistinguisher> for ExtCommunityValue {
    fn from(from: RouteDistinguisher) -> Self {
        let mut to = ExtCommunityValue::default();
        to.val = from.val;
        match from.typ {
            RouteDistinguisherType::ASN => {
                to.high_type = 0;
            }
            RouteDistinguisherType::IP => {
                to.high_type = 1;
            }
        }
        to
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {
        let ecom: ExtCommunity = ExtCommunity::from_str("rt 100:200").unwrap();
        assert_eq!(ecom.to_string(), "rt 100:200");

        let ecom: ExtCommunity = ExtCommunity::from_str("soo 1.2.3.4:200").unwrap();
        assert_eq!(ecom.to_string(), "soo 1.2.3.4:200");
    }
}
