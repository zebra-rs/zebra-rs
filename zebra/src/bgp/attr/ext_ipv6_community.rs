use super::{encode_tlv, AttributeEncoder, AttributeFlags, AttributeType, ExtCommunitySubType};
use bytes::{BufMut, BytesMut};
use nom_derive::NomBE;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::ext_ipv6_community_token::{tokenizer, Token};

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtIpv6Community(pub Vec<ExtIpv6CommunityValue>);

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtIpv6CommunityValue {
    pub high_type: u8,
    pub low_type: u8,
    pub val: [u8; 18],
}

#[derive(PartialEq)]
enum State {
    Unspec,
    Rt,
    Soo,
}

impl ExtIpv6CommunityValue {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.high_type);
        buf.put_u8(self.low_type);
        buf.put(&self.val[..]);
    }
}

use ExtCommunitySubType::*;

fn sub_type_str(sub_type: u8) -> &'static str {
    match sub_type {
        x if x == RouteTarget as u8 => "rt",
        x if x == RouteOrigin as u8 => "soo",
        _ => "unknown",
    }
}

impl fmt::Display for ExtIpv6CommunityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.high_type == 0 {
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

impl ExtIpv6CommunityValue {
    pub fn new(addr: Ipv6Addr, val: u16) -> Self {
        let mut com = Self {
            high_type: 0x00,
            low_type: RouteTarget as u8,
            val: [0u8; 18],
        };
        com.val[0..16].copy_from_slice(&addr.octets());
        com.val[16..18].copy_from_slice(val.to_ne_bytes().as_slice());
        com
    }
}

impl AttributeEncoder for ExtIpv6Community {
    fn attr_type() -> AttributeType {
        AttributeType::ExtendedIpv6Com
    }

    fn attr_flag() -> AttributeFlags {
        AttributeFlags::OPTIONAL | AttributeFlags::TRANSITIVE
    }
}

impl ExtIpv6Community {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut attr_buf = BytesMut::new();
        self.0.iter().for_each(|x| x.encode(&mut attr_buf));
        encode_tlv::<Self>(buf, attr_buf);
    }
}

impl fmt::Display for ExtIpv6Community {
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

impl FromStr for ExtIpv6Community {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ecom = ExtIpv6Community::default();
        let tokens = tokenizer(String::from(s)).unwrap();
        let mut state = State::Unspec;

        for token in tokens.into_iter() {
            match token {
                Token::Rd(rd, num) => {
                    let mut val = ExtIpv6CommunityValue::new(rd, num);
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
