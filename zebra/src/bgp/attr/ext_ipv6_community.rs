use bytes::{BufMut, BytesMut};
use nom_derive::NomBE;
use std::net::Ipv6Addr;
use std::str::FromStr;

use super::{encode_tlv, AttributeEncoder, AttributeFlags, AttributeType, ExtCommunitySubType};

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtIpv6Community(pub Vec<ExtIpv6CommunityValue>);

#[derive(Clone, Debug, Default, NomBE)]
pub struct ExtIpv6CommunityValue {
    pub high_type: u8,
    pub low_type: u8,
    pub val: [u8; 18],
}

impl AttributeEncoder for ExtIpv6Community {
    fn attr_type() -> AttributeType {
        AttributeType::ExtendedIpv6Com
    }

    fn attr_flag() -> AttributeFlags {
        AttributeFlags::OPTIONAL | AttributeFlags::TRANSITIVE
    }
}

impl ExtIpv6CommunityValue {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.high_type);
        buf.put_u8(self.low_type);
        buf.put(&self.val[..]);
    }
}

use ExtCommunitySubType::*;

impl ExtIpv6CommunityValue {
    pub fn new() -> Self {
        let addr: Ipv6Addr = Ipv6Addr::from_str("3001:2001::").unwrap();
        let mut com = Self {
            high_type: 0x00,
            low_type: RouteTarget as u8,
            val: [0u8; 18],
        };
        com.val[0..16].copy_from_slice(&addr.octets());
        com.val[16] = 0x00;
        com.val[17] = 0x05;
        com
    }
}

impl ExtIpv6Community {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut attr_buf = BytesMut::new();
        self.0.iter().for_each(|x| x.encode(&mut attr_buf));
        encode_tlv::<Self>(buf, attr_buf);
    }
}
