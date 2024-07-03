use nom_derive::NomBE;
use rusticata_macros::newtype_enum;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::str::FromStr;

/// BGP Community attribute.
#[derive(Clone, Debug, NomBE)]
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

    fn parse_community(s: &str) -> Option<u32> {
        let com_strs: Vec<&str> = s.split(':').collect();
        match com_strs.len() {
            // ASN:NN format.
            2 => {
                if let Ok(hval) = com_strs[0].parse::<u16>() {
                    if let Ok(lval) = com_strs[1].parse::<u16>() {
                        return Some(u32::from(hval) << 16 | u32::from(lval));
                    }
                }
                None
            }
            // NN format.
            1 => {
                if let Ok(val) = com_strs[0].parse::<u32>() {
                    return Some(val);
                }
                None
            }
            // Otherwise none.
            _ => None,
        }
    }
}

impl Default for Community {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let format = |v: &u32| {
            let hval: u32 = (v & 0xFFFF0000) >> 16;
            let lval: u32 = v & 0x0000FFFF;
            hval.to_string() + ":" + &lval.to_string()
        };
        let mut iter = self.0.iter();
        let val = match iter.next() {
            None => String::new(),
            Some(first_elem) => {
                let mut result = match CommunityValue::to_string(*first_elem) {
                    Some(s) => s,
                    None => format(first_elem),
                };
                for elem in iter {
                    result.push(' ');
                    let elem_str = match CommunityValue::to_string(*elem) {
                        Some(s) => s,
                        None => format(elem),
                    };
                    result = result + &elem_str;
                }
                result
            }
        };
        write!(f, "{}", val)
    }
}

impl FromStr for Community {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let com_strs: Vec<&str> = s.split(' ').collect();
        if com_strs.is_empty() {
            return Err(());
        }

        // At least one community string exists.
        let mut coms = Community::new();

        for s in com_strs.iter() {
            // Well known community value match.
            match CommunityValue::to_welknown(s) {
                Some(c) => coms.push(c.to_value()),
                None => {
                    // ASN:NN or NN format parse.
                    if let Some(c) = Community::parse_community(s) {
                        coms.push(c)
                    } else {
                        return Err(());
                    }
                }
            }
        }
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

impl CommunityValue {
    pub fn to_string(com: u32) -> Option<String> {
        let map: HashMap<CommunityValue, String> = HashMap::from([
            (
                CommunityValue::GracefulShutdown,
                String::from("graceful-shutdown"),
            ),
            (CommunityValue::AcceptOwn, String::from("accept-own")),
            (
                CommunityValue::RouteFilterTranslatedV4,
                String::from("route-filter-translated-v4"),
            ),
            (
                CommunityValue::RouteFilterV4,
                String::from("route-filter-v4"),
            ),
            (
                CommunityValue::RouteFilterTranslatedV6,
                String::from("route-filter-translated-v6"),
            ),
            (
                CommunityValue::RouteFilterV6,
                String::from("route-filter-v6"),
            ),
            (CommunityValue::LlgrStale, String::from("llgr-stale")),
            (CommunityValue::NoLlgr, String::from("no-llgr")),
            (
                CommunityValue::AcceptOwnNexthop,
                String::from("accept-own-nexthop"),
            ),
            (CommunityValue::Blackhole, String::from("blackhole")),
            (CommunityValue::NoExport, String::from("no-export")),
            (CommunityValue::NoAdvertise, String::from("no-advertise")),
            (CommunityValue::NoExportSubconfed, String::from("")),
            (CommunityValue::LocalAs, String::from("local-AS")),
            (CommunityValue::NoPeer, String::from("no-peer")),
        ]);
        map.get(&CommunityValue(com)).cloned()
    }

    pub fn to_welknown(str: &str) -> Option<CommunityValue> {
        let map: HashMap<&str, CommunityValue> = HashMap::from([
            ("graceful-shutdown", CommunityValue::GracefulShutdown),
            ("accept-own", CommunityValue::AcceptOwn),
            (
                "route-filter-translated-v4",
                CommunityValue::RouteFilterTranslatedV4,
            ),
            ("route-filter-v4", CommunityValue::RouteFilterV4),
            (
                "route-filter-translated-v6",
                CommunityValue::RouteFilterTranslatedV6,
            ),
            ("route-filter-v6", CommunityValue::RouteFilterV6),
            ("llgr-stale", CommunityValue::LlgrStale),
            ("no-llgr", CommunityValue::NoLlgr),
            ("accept-own-nexthop", CommunityValue::AcceptOwnNexthop),
            ("blackhole", CommunityValue::Blackhole),
            ("no-export", CommunityValue::NoExport),
            ("no-advertise", CommunityValue::NoAdvertise),
            ("no-export-sub-confed", CommunityValue::NoExportSubconfed),
            ("local-AS", CommunityValue::LocalAs),
            ("no-peer", CommunityValue::NoPeer),
        ]);
        map.get(str).cloned()
    }

    pub fn to_value(&self) -> u32 {
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
        com.push(CommunityValue::Blackhole.to_value());
        com.push(3u32);
        assert_eq!(format!("{}", com), "0:1 blackhole 0:3");
    }

    #[test]
    fn from_str() {
        let com = Community::from_str("no-export 100:10 100").unwrap();
        assert_eq!(format!("{}", com), "no-export 100:10 0:100");

        let com = Community::from_str("100:10 local-AS 100").unwrap();
        assert_eq!(format!("{}", com), "100:10 local-AS 0:100");

        let com = Community::from_str("100 llgr-stale 100:10").unwrap();
        assert_eq!(format!("{}", com), "0:100 llgr-stale 100:10");

        let com = Community::from_str("4294967295 graceful-shutdown 100:10").unwrap();
        assert_eq!(format!("{}", com), "65535:65535 graceful-shutdown 100:10");

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
    fn contains() {
        let com = Community::from_str("no-export 100:10 100").unwrap();
        if !com.contains(&100u32) {
            panic!("Community must contain no-export");
        }

        let com = Community::from_str("no-export 100:10 100").unwrap();
        if !com.contains(&CommunityValue::NoExport.to_value()) {
            panic!("Community must contain no-export");
        }

        if com.contains(&CommunityValue::NoAdvertise.to_value()) {
            panic!("Community must not contain no-advertise");
        }

        let val = Community::parse_community("100:10").unwrap();
        if !com.contains(&val) {
            panic!("Community must contain 100:10");
        }
    }

    #[test]
    fn sort_uniq() {
        let mut com = Community::from_str("100:10 no-export 100:10 100").unwrap();
        com.sort_uniq();
        assert_eq!(format!("{}", com), "0:100 100:10 no-export");
    }

    fn sort_uniq_no_export() {
        let mut com = Community::from_str("no-export no-export no-export").unwrap();
        com.sort_uniq();
        assert_eq!(format!("{}", com), "no-export");
    }
}
