use bytes::{BufMut, BytesMut};
use nom_derive::NomBE;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use super::{
    encode_tlv,
    ext_community_token::{tokenizer, Token},
    AttributeEncoder, AttributeFlags, AttributeType, RouteDistinguisher, RouteDistinguisherType,
};

use super::ext_community_type::ExtCommunityType;

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

use super::ExtCommunitySubType::*;

fn sub_type_str(sub_type: u8) -> &'static str {
    match sub_type {
        x if x == RouteTarget as u8 => "rt",
        x if x == RouteOrigin as u8 => "soo",
        _ => "unknown",
    }
}

use ExtCommunityType::*;

impl fmt::Display for ExtCommunityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.high_type == TransTwoOctetAS as u8 {
            let asn = u16::from_be_bytes([self.val[0], self.val[1]]);
            let val = u32::from_be_bytes([self.val[2], self.val[3], self.val[4], self.val[5]]);
            write!(f, "{} {asn}:{val}", sub_type_str(self.low_type))
        } else {
            let ip = Ipv4Addr::new(self.val[0], self.val[1], self.val[2], self.val[3]);
            let val = u16::from_be_bytes([self.val[4], self.val[5]]);
            write!(f, "{} {ip}:{val}", sub_type_str(self.low_type))
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
                to.high_type = 0x00;
            }
            RouteDistinguisherType::IP => {
                to.high_type = 0x01;
            }
        }
        to
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let ecom: ExtCommunity = ExtCommunity::from_str("rt 100:200").unwrap();
        assert_eq!(ecom.to_string(), "rt 100:200");

        let ecom: ExtCommunity = ExtCommunity::from_str("soo 1.2.3.4:200").unwrap();
        assert_eq!(ecom.to_string(), "soo 1.2.3.4:200");

        let ecom: ExtCommunity = ExtCommunity::from_str("rt 1.2.3.4:100 soo 10:100").unwrap();
        assert_eq!(ecom.to_string(), "rt 1.2.3.4:100 soo 10:100");
    }
}
