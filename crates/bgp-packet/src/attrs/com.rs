use bytes::{BufMut, BytesMut};
use nom_derive::NomBE;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock; // If using Rust 1.70+, otherwise use once_cell::sync::Lazy

use crate::{AttrEmitter, AttrFlags, AttrType};

#[derive(Clone, Debug, Default, NomBE)]
pub struct Community(pub Vec<u32>);

impl Community {
    pub fn new() -> Self {
        Community(Vec::<u32>::new())
    }
    pub fn push(&mut self, value: u32) {
        self.0.push(value)
    }
    pub fn sort_uniq(&mut self) {
        let coms: BTreeSet<u32> = self.0.iter().cloned().collect();
        self.0 = coms.into_iter().collect();
    }
    pub fn contains(&self, val: &u32) -> bool {
        self.0.contains(val)
    }
    pub fn append(&mut self, other: &mut Self) {
        self.0.append(&mut other.0);
        self.sort_uniq();
    }
    pub fn is_no_export(&self) -> bool {
        self.contains(&CommunityValue::NO_EXPORT.value())
    }
}

impl AttrEmitter for Community {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true).with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::Community
    }

    fn len(&self) -> Option<usize> {
        None // Length is variable, let attr_emit buffer and calculate
    }

    fn emit(&self, buf: &mut BytesMut) {
        for &community in &self.0 {
            buf.put_u32(community);
        }
    }
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .0
            .iter()
            .map(|x| CommunityValue(*x).to_str())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{v}")
    }
}

impl FromStr for Community {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let com_strs: Vec<&str> = s.split_whitespace().collect();
        if com_strs.is_empty() {
            return Err(());
        }

        let mut coms = Community::new();

        for s in com_strs.iter() {
            match CommunityValue::from_readable_str(s) {
                Some(c) => coms.push(c.value()),
                None => return Err(()),
            }
        }
        coms.sort_uniq();
        Ok(coms)
    }
}

/// BGP Community 32 bit value.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, PartialOrd, Ord)]
pub struct CommunityValue(pub u32);

impl CommunityValue {
    pub const GRACEFUL_SHUTDOWN: Self = CommunityValue(0xFFFF_0000);
    pub const ACCEPT_OWN: Self = CommunityValue(0xFFFF_0001);
    pub const ROUTE_FILTER_TRANSLATED_V4: Self = CommunityValue(0xFFFF_0002);
    pub const ROUTE_FILTER_V4: Self = CommunityValue(0xFFFF_0003);
    pub const ROUTE_FILTER_TRANSLATED_V6: Self = CommunityValue(0xFFFF_0004);
    pub const ROUTE_FILTER_V6: Self = CommunityValue(0xFFFF_0005);
    pub const LLGR_STALE: Self = CommunityValue(0xFFFF_0006);
    pub const NO_LLGR: Self = CommunityValue(0xFFFF_0007);
    pub const ACCEPT_OWN_NEXTHOP: Self = CommunityValue(0xFFFF_0008);
    pub const BLACKHOLE: Self = CommunityValue(0xFFFF_029A);
    pub const NO_EXPORT: Self = CommunityValue(0xFFFF_FF01);
    pub const NO_ADVERTISE: Self = CommunityValue(0xFFFF_FF02);
    pub const NO_EXPORT_SUBCONFED: Self = CommunityValue(0xFFFF_FF03);
    pub const LOCAL_AS: Self = CommunityValue(0xFFFF_FF03); // Same value as NO_EXPORT_SUBCONFED
    pub const NO_PEER: Self = CommunityValue(0xFFFF_FF04);

    pub fn from_wellknown_str(s: &str) -> Option<Self> {
        STR_WELLKNOWN_MAP.get(s).cloned()
    }
    fn from_digit_str(s: &str) -> Option<Self> {
        let com_strs: Vec<&str> = s.split(':').collect();
        match com_strs.len() {
            // ASN:NN format.
            2 => {
                if let Ok(hval) = com_strs[0].parse::<u16>()
                    && let Ok(lval) = com_strs[1].parse::<u16>()
                {
                    return Some(Self(u32::from(hval) << 16 | u32::from(lval)));
                }
                None
            }
            // NN format.
            1 => {
                if let Ok(val) = com_strs[0].parse::<u32>() {
                    return Some(Self(val));
                }
                None
            }
            _ => None,
        }
    }
    pub fn from_readable_str(s: &str) -> Option<Self> {
        Self::from_wellknown_str(s).or(Self::from_digit_str(s))
    }
    pub fn to_wellknown_str(&self) -> Option<&'static str> {
        WELLKNOWN_STR_MAP.get(self).copied()
    }
    pub fn to_digit_str(&self) -> String {
        let hval: u32 = (self.0 & 0xFFFF_0000) >> 16;
        let lval: u32 = self.0 & 0x0000_FFFF;
        format!("{}:{}", hval, lval)
    }
    /// Returns a String: either a static str for well-known, or the digit-notation for unknown.
    pub fn to_str(&self) -> String {
        if let Some(s) = self.to_wellknown_str() {
            s.to_string()
        } else {
            self.to_digit_str()
        }
    }
    pub fn value(&self) -> u32 {
        self.0
    }
}

// Efficient mappings: value <-> static names
static WELLKNOWN_STR_MAP: LazyLock<HashMap<CommunityValue, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert(CommunityValue::GRACEFUL_SHUTDOWN, "graceful-shutdown");
    map.insert(CommunityValue::ACCEPT_OWN, "accept-own");
    map.insert(
        CommunityValue::ROUTE_FILTER_TRANSLATED_V4,
        "route-filter-translated-v4",
    );
    map.insert(CommunityValue::ROUTE_FILTER_V4, "route-filter-v4");
    map.insert(
        CommunityValue::ROUTE_FILTER_TRANSLATED_V6,
        "route-filter-translated-v6",
    );
    map.insert(CommunityValue::ROUTE_FILTER_V6, "route-filter-v6");
    map.insert(CommunityValue::LLGR_STALE, "llgr-stale");
    map.insert(CommunityValue::NO_LLGR, "no-llgr");
    map.insert(CommunityValue::ACCEPT_OWN_NEXTHOP, "accept-own-nexthop");
    map.insert(CommunityValue::BLACKHOLE, "blackhole");
    map.insert(CommunityValue::NO_EXPORT, "no-export");
    map.insert(CommunityValue::NO_ADVERTISE, "no-advertise");
    map.insert(CommunityValue::NO_EXPORT_SUBCONFED, "no-export-sub-confed");
    map.insert(CommunityValue::LOCAL_AS, "local-AS");
    map.insert(CommunityValue::NO_PEER, "no-peer");
    map
});

static STR_WELLKNOWN_MAP: LazyLock<HashMap<&'static str, CommunityValue>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert("graceful-shutdown", CommunityValue::GRACEFUL_SHUTDOWN);
    map.insert("accept-own", CommunityValue::ACCEPT_OWN);
    map.insert(
        "route-filter-translated-v4",
        CommunityValue::ROUTE_FILTER_TRANSLATED_V4,
    );
    map.insert("route-filter-v4", CommunityValue::ROUTE_FILTER_V4);
    map.insert(
        "route-filter-translated-v6",
        CommunityValue::ROUTE_FILTER_TRANSLATED_V6,
    );
    map.insert("route-filter-v6", CommunityValue::ROUTE_FILTER_V6);
    map.insert("llgr-stale", CommunityValue::LLGR_STALE);
    map.insert("no-llgr", CommunityValue::NO_LLGR);
    map.insert("accept-own-nexthop", CommunityValue::ACCEPT_OWN_NEXTHOP);
    map.insert("blackhole", CommunityValue::BLACKHOLE);
    map.insert("no-export", CommunityValue::NO_EXPORT);
    map.insert("no-advertise", CommunityValue::NO_ADVERTISE);
    map.insert("no-export-sub-confed", CommunityValue::NO_EXPORT_SUBCONFED);
    map.insert("local-AS", CommunityValue::LOCAL_AS);
    map.insert("no-peer", CommunityValue::NO_PEER);
    map
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push() {
        let mut com = Community::new();
        com.push(1u32);
        com.push(2u32);
        com.push(3u32);
        assert_eq!(format!("{}", com), "0:1 0:2 0:3");

        let mut com = Community::new();
        com.push(1u32);
        com.push(CommunityValue::BLACKHOLE.value());
        com.push(3u32);
        assert_eq!(format!("{}", com), "0:1 blackhole 0:3");
    }

    #[test]
    fn from_str() {
        let com = Community::from_str("no-export 100:10 100").unwrap();
        assert_eq!(format!("{}", com), "0:100 100:10 no-export");

        let com = Community::from_str("100:10 local-AS 100").unwrap();
        assert_eq!(format!("{}", com), "0:100 100:10 local-AS");

        let com = Community::from_str("100 llgr-stale 100:10").unwrap();
        assert_eq!(format!("{}", com), "0:100 100:10 llgr-stale");

        let com = Community::from_str("4294967295 graceful-shutdown 100:10").unwrap();
        assert_eq!(format!("{}", com), "100:10 graceful-shutdown 65535:65535");

        let com = Community::from_str("4294967296 no-export 100:10");
        assert!(com.is_err());

        let com = Community::from_str("not-well-defined 100:10");
        assert!(com.is_err());

        let com = Community::from_str("");
        assert!(com.is_err());

        let com = Community::from_str("-1");
        assert!(com.is_err());

        let com = Community::from_str("10+");
        assert!(com.is_err());

        let com = Community::from_str("100:test");
        assert!(com.is_err());

        let com = Community::from_str("65535:65535").unwrap();
        assert_eq!(format!("{}", com), "65535:65535");

        let com = Community::from_str("65535:65536");
        assert!(com.is_err());

        let com = Community::from_str("65536:65535");
        assert!(com.is_err());

        let com = Community::from_str("65536").unwrap();
        assert_eq!(format!("{}", com), "1:0");

        let com = Community::from_str("1").unwrap();
        assert_eq!(format!("{}", com), "0:1");
    }

    #[test]
    fn to_string() {
        let com = Community::from_str("no-export 100:10 100").unwrap();
        let string = com.to_string();
        assert_eq!(string, "0:100 100:10 no-export");
    }

    #[test]
    fn contains() {
        let com = Community::from_str("no-export 100:10 100").unwrap();
        assert!(com.contains(&100u32));

        let com = Community::from_str("no-export 100:10 100").unwrap();
        assert!(com.contains(&CommunityValue::NO_EXPORT.value()));

        assert!(!com.contains(&CommunityValue::NO_ADVERTISE.value()));

        let val = CommunityValue::from_digit_str("100:10").unwrap();
        assert!(com.contains(&val.0));
    }

    #[test]
    fn sort_uniq() {
        let mut com = Community::from_str("100:10 no-export 100:10 100").unwrap();
        com.sort_uniq();
        assert_eq!(format!("{}", com), "0:100 100:10 no-export");
    }

    #[test]
    fn sort_uniq_no_export() {
        let mut com = Community::from_str("no-export no-export no-export").unwrap();
        com.sort_uniq();
        assert_eq!(format!("{}", com), "no-export");
    }

    #[test]
    fn value_from_str() {
        let com = CommunityValue::from_readable_str("no-export").unwrap();
        assert_eq!(com.value(), CommunityValue::NO_EXPORT.value());

        let com = CommunityValue::from_readable_str("100:10").unwrap();
        assert_eq!(com.value(), (100 << 16) + 10);

        let com = CommunityValue::from_readable_str("6553620").unwrap();
        assert_eq!(com.value(), (100 << 16) + 20);
    }

    #[test]
    fn append() {
        let mut com = Community::from_str("100:10 100:20").unwrap();
        let mut other = Community::from_str("100:30 100:20").unwrap();

        com.append(&mut other);
        assert_eq!(format!("{}", com), "100:10 100:20 100:30");
    }
}
