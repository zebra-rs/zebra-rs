// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

// SRv6 Locator.
#[derive(Debug)]
pub enum LocatorType {
    Classic,
    #[allow(non_camel_case_types)]
    uSID,
}

// Cisco IOS-XR LIB range for IGP-dynamic local SIDs (uA).
const LIB_START: u16 = 0xE000;
const LIB_END: u16 = 0xE063;

#[derive(Debug)]
pub struct Locator {
    pub name: String,
    pub typ: LocatorType,
    pub prefix: Ipv6Net,
    pub block_len: u8,
    pub node_len: u8,
    pub func_len: u8,
    pub arg_len: u8,
    allocated_funcs: BTreeSet<u16>,
}

impl Locator {
    pub fn new(name: String, typ: LocatorType, prefix: Ipv6Net) -> Self {
        let (block_len, node_len, func_len, arg_len) = match &typ {
            LocatorType::Classic => (40, 24, 16, 0),
            LocatorType::uSID => (32, 16, 16, 0),
        };
        Self {
            name,
            typ,
            prefix,
            block_len,
            node_len,
            func_len,
            arg_len,
            allocated_funcs: BTreeSet::new(),
        }
    }

    pub fn get_node_sid(&self) -> Ipv6Addr {
        self.prefix.addr()
    }

    fn func_shift(&self) -> u8 {
        128 - self.block_len - self.node_len - self.func_len
    }

    fn compose_sid(&self, func: u16) -> Ipv6Addr {
        let prefix_u128: u128 = self.prefix.addr().into();
        let sid_u128 = prefix_u128 | ((func as u128) << self.func_shift());
        sid_u128.into()
    }

    fn extract_func(&self, sid: Ipv6Addr) -> u16 {
        let sid_u128: u128 = sid.into();
        let mask: u128 = (1u128 << self.func_len) - 1;
        ((sid_u128 >> self.func_shift()) & mask) as u16
    }

    // Allocates a new uA (adjacency uSID) from the LIB range for uSID locators.
    // Returns None when the range is exhausted, or for Classic locators where
    // function-space allocation is operator-defined.
    pub fn alloc_adjacency_sid(&mut self) -> Option<Ipv6Addr> {
        match &self.typ {
            LocatorType::uSID => {
                for f in LIB_START..=LIB_END {
                    if self.allocated_funcs.insert(f) {
                        return Some(self.compose_sid(f));
                    }
                }
                None
            }
            LocatorType::Classic => None,
        }
    }

    pub fn free_adjacency_sid(&mut self, sid: Ipv6Addr) {
        let f = self.extract_func(sid);
        self.allocated_funcs.remove(&f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor() {
        let prefix: Ipv6Net = "fcbb:bbbb:1::/48".parse().unwrap();
        let loc = Locator::new("test".to_string(), LocatorType::uSID, prefix);

        assert_eq!(loc.block_len, 32);
        assert_eq!(loc.node_len, 16);
        assert_eq!(loc.func_len, 16);
        assert_eq!(loc.arg_len, 0);

        let addr: u128 = loc.prefix.addr().into();
        let block = (addr >> (128 - loc.block_len)) as u32;
        let node_shift = 128 - loc.block_len - loc.node_len;
        let node = ((addr >> node_shift) & ((1u128 << loc.node_len) - 1)) as u16;

        assert_eq!(block, 0xfcbb_bbbb);
        assert_eq!(node, 0x0001);
        assert_eq!(
            loc.get_node_sid(),
            "fcbb:bbbb:1::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn alloc_and_free_adjacency_sid() {
        let prefix: Ipv6Net = "fcbb:bbbb:1::/48".parse().unwrap();
        let mut loc = Locator::new("test".to_string(), LocatorType::uSID, prefix);

        let sid1 = loc.alloc_adjacency_sid().expect("first alloc");
        assert_eq!(sid1, "fcbb:bbbb:1:e000::".parse::<Ipv6Addr>().unwrap());

        let sid2 = loc.alloc_adjacency_sid().expect("second alloc");
        assert_eq!(sid2, "fcbb:bbbb:1:e001::".parse::<Ipv6Addr>().unwrap());

        loc.free_adjacency_sid(sid1);
        let sid3 = loc.alloc_adjacency_sid().expect("realloc after free");
        assert_eq!(sid3, "fcbb:bbbb:1:e000::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn alloc_adjacency_sid_classic_returns_none() {
        let prefix: Ipv6Net = "fc00:0:1::/48".parse().unwrap();
        let mut loc = Locator::new("classic".to_string(), LocatorType::Classic, prefix);
        assert!(loc.alloc_adjacency_sid().is_none());
    }
}
