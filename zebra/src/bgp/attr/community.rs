use bytes::{BufMut, BytesMut};
use nom_derive::NomBE;
use rusticata_macros::newtype_enum;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use super::{AttributeFlags, AttributeType};

#[derive(Clone, Debug, Default, NomBE)]
pub struct Community(pub Vec<u32>);

impl Community {
    pub fn new() -> Self {
        Community(Vec::<u32>::new())
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::OPTIONAL | AttributeFlags::TRANSITIVE
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
        self.contains(&CommunityValue::NoExport.value())
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut attr_buf = BytesMut::new();
        for com in self.0.iter() {
            attr_buf.put_u32(*com);
        }
        if attr_buf.len() > 255 {
            buf.put_u8(Self::flags().bits() | AttributeFlags::EXTENDED.bits());
            buf.put_u8(AttributeType::Community.0);
            buf.put_u16(attr_buf.len() as u16)
        } else {
            buf.put_u8(Self::flags().bits());
            buf.put_u8(AttributeType::Community.0);
            buf.put_u8(attr_buf.len() as u8);
        }
        buf.put(&attr_buf[..]);
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
        let com_strs: Vec<&str> = s.split(' ').collect();
        if com_strs.is_empty() {
            return Err(());
        }

        let mut coms = Community::new();

        for s in com_strs.iter() {
            match CommunityValue::from_str(s) {
                Some(c) => coms.push(c.value()),
                None => return Err(()),
            }
        }
        coms.sort_uniq();
        Ok(coms)
    }
}

/// BGP Community 32 bit value.
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct CommunityValue(pub u32);

newtype_enum! {
    impl display CommunityValue {
        GracefulShutdown = 0xFFFF0000u32,
        AcceptOwn = 0xFFFF0001u32,
        RouteFilterTranslatedV4 = 0xFFFF0002u32,
        RouteFilterV4 = 0xFFFF0003u32,
        RouteFilterTranslatedV6 = 0xFFFF0004u32,
        RouteFilterV6 = 0xFFFF0005,
        LlgrStale = 0xFFFF0006,
        NoLlgr = 0xFFFF0007,
        AcceptOwnNexthop = 0xFFFF0008,
        Blackhole = 0xFFFF029Au32,
        NoExport = 0xFFFFFF01,
        NoAdvertise = 0xFFFFFF02,
        NoExportSubconfed = 0xFFFFFF03,
        LocalAs = 0xFFFFFF03,
        NoPeer = 0xFFFFFF04,
    }
}

static WELLKNOWN_STR_MAP: LazyLock<HashMap<CommunityValue, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert(CommunityValue::GracefulShutdown, "graceful-shutdown");
    map.insert(CommunityValue::AcceptOwn, "accept-own");
    map.insert(
        CommunityValue::RouteFilterTranslatedV4,
        "route-filter-translated-v4",
    );
    map.insert(CommunityValue::RouteFilterV4, "route-filter-v4");
    map.insert(
        CommunityValue::RouteFilterTranslatedV6,
        "route-filter-translated-v6",
    );
    map.insert(CommunityValue::RouteFilterV6, "route-filter-v6");
    map.insert(CommunityValue::LlgrStale, "llgr-stale");
    map.insert(CommunityValue::NoLlgr, "no-llgr");
    map.insert(CommunityValue::AcceptOwnNexthop, "accept-own-nexthop");
    map.insert(CommunityValue::Blackhole, "blackhole");
    map.insert(CommunityValue::NoExport, "no-export");
    map.insert(CommunityValue::NoAdvertise, "no-advertise");
    map.insert(CommunityValue::NoExportSubconfed, "no-export-sub-confed");
    map.insert(CommunityValue::LocalAs, "local-AS");
    map.insert(CommunityValue::NoPeer, "no-peer");
    map
});

static STR_WELLKNOWN_MAP: LazyLock<HashMap<&'static str, CommunityValue>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert("graceful-shutdown", CommunityValue::GracefulShutdown);
    map.insert("accept-own", CommunityValue::AcceptOwn);
    map.insert(
        "route-filter-translated-v4",
        CommunityValue::RouteFilterTranslatedV4,
    );
    map.insert("route-filter-v4", CommunityValue::RouteFilterV4);
    map.insert(
        "route-filter-translated-v6",
        CommunityValue::RouteFilterTranslatedV6,
    );
    map.insert("route-filter-v6", CommunityValue::RouteFilterV6);
    map.insert("llgr-stale", CommunityValue::LlgrStale);
    map.insert("no-llgr", CommunityValue::NoLlgr);
    map.insert("accept-own-nexthop", CommunityValue::AcceptOwnNexthop);
    map.insert("blackhole", CommunityValue::Blackhole);
    map.insert("no-export", CommunityValue::NoExport);
    map.insert("no-advertise", CommunityValue::NoAdvertise);
    map.insert("no-export-sub-confed", CommunityValue::NoExportSubconfed);
    map.insert("local-AS", CommunityValue::LocalAs);
    map.insert("no-peer", CommunityValue::NoPeer);
    map
});

impl CommunityValue {
    pub fn from_wellknown_str(s: &str) -> Option<Self> {
        STR_WELLKNOWN_MAP.get(s).cloned()
    }

    fn from_digit_str(s: &str) -> Option<Self> {
        let com_strs: Vec<&str> = s.split(':').collect();
        match com_strs.len() {
            // ASN:NN format.
            2 => {
                if let Ok(hval) = com_strs[0].parse::<u16>() {
                    if let Ok(lval) = com_strs[1].parse::<u16>() {
                        return Some(Self(u32::from(hval) << 16 | u32::from(lval)));
                    }
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

    pub fn from_str(s: &str) -> Option<Self> {
        Self::from_wellknown_str(s).or(Self::from_digit_str(s))
    }

    pub fn to_wellknown_str(&self) -> Option<&'static str> {
        WELLKNOWN_STR_MAP.get(self).cloned()
    }

    pub fn to_digit_str(&self) -> String {
        let hval: u32 = (self.0 & 0xFFFF0000) >> 16;
        let lval: u32 = self.0 & 0x0000FFFF;
        hval.to_string() + ":" + &lval.to_string()
    }

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

#[cfg(test)]
mod test {
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
        com.push(CommunityValue::Blackhole.value());
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
        if com.is_ok() {
            panic!("com must be None");
        }

        let com = Community::from_str("not-well-defined 100:10");
        if com.is_ok() {
            panic!("com must be None");
        }

        let com = Community::from_str("");
        if com.is_ok() {
            panic!("com must be None");
        }

        let com = Community::from_str("-1");
        if com.is_ok() {
            panic!("com must be None");
        }

        let com = Community::from_str("10+");
        if com.is_ok() {
            panic!("com must be None");
        }

        let com = Community::from_str("100:test");
        if com.is_ok() {
            panic!("com must be None");
        }

        let com = Community::from_str("65535:65535").unwrap();
        assert_eq!(format!("{}", com), "65535:65535");

        let com = Community::from_str("65535:65536");
        if com.is_ok() {
            panic!("com must be None");
        }

        let com = Community::from_str("65536:65535");
        if com.is_ok() {
            panic!("com must be None");
        }

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
        if !com.contains(&100u32) {
            panic!("Community must contain no-export");
        }

        let com = Community::from_str("no-export 100:10 100").unwrap();
        if !com.contains(&CommunityValue::NoExport.value()) {
            panic!("Community must contain no-export");
        }

        if com.contains(&CommunityValue::NoAdvertise.value()) {
            panic!("Community must not contain no-advertise");
        }

        let val = CommunityValue::from_digit_str("100:10").unwrap();
        if !com.contains(&val.0) {
            panic!("Community must contain 100:10");
        }
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
        let com = CommunityValue::from_str("no-export").unwrap();
        assert_eq!(com.value(), CommunityValue::NoExport.value());

        let com = CommunityValue::from_str("100:10").unwrap();
        assert_eq!(com.value(), (100 << 16) + 10);

        let com = CommunityValue::from_str("6553620").unwrap();
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
