use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

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

#[derive(Debug, NomBE)]
pub struct CommunityAttr(pub Vec<u32>);

impl CommunityAttr {
    pub fn new() -> Self {
        CommunityAttr(Vec::<u32>::new())
    }

    pub fn push(&mut self, value: u32) {
        self.0.push(value)
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

impl Default for CommunityAttr {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CommunityAttr {
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

impl FromStr for CommunityAttr {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let com_strs: Vec<&str> = s.split(' ').collect();
        if com_strs.is_empty() {
            return Err(());
        }

        // At least one community string exists.
        let mut coms = CommunityAttr::new();

        for s in com_strs.iter() {
            // Well known community value match.
            match CommunityValue::to_welknown(s) {
                Some(c) => coms.push(c.to_value()),
                None => {
                    // ASN:NN or NN format parse.
                    if let Some(c) = CommunityAttr::parse_community(s) {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn push() {
        let mut com = CommunityAttr::new();
        com.push(1u32);
        com.push(2u32);
        com.push(3u32);
        assert_eq!(format!("{}", com), "0:1 0:2 0:3");

        let mut com = CommunityAttr::new();
        com.push(1u32);
        com.push(CommunityValue::Blackhole.to_value());
        com.push(3u32);
        assert_eq!(format!("{}", com), "0:1 blackhole 0:3");
    }

    #[test]
    fn from_str() {
        let com = CommunityAttr::from_str("no-export 100:10 100").unwrap();
        assert_eq!(format!("{}", com), "no-export 100:10 0:100");

        let com = CommunityAttr::from_str("100:10 local-AS 100").unwrap();
        assert_eq!(format!("{}", com), "100:10 local-AS 0:100");

        let com = CommunityAttr::from_str("100 llgr-stale 100:10").unwrap();
        assert_eq!(format!("{}", com), "0:100 llgr-stale 100:10");

        let com = CommunityAttr::from_str("4294967295 graceful-shutdown 100:10").unwrap();
        assert_eq!(format!("{}", com), "65535:65535 graceful-shutdown 100:10");

        let com = CommunityAttr::from_str("4294967296 no-export 100:10");
        if let Ok(_) = com {
            panic!("com must be None");
        }

        let com = CommunityAttr::from_str("not-well-defined 100:10");
        if let Ok(_) = com {
            panic!("com must be None");
        }

        let com = CommunityAttr::from_str("");
        if let Ok(_) = com {
            panic!("com must be None");
        }

        let com = CommunityAttr::from_str("-1");
        if let Ok(_) = com {
            panic!("com must be None");
        }

        let com = CommunityAttr::from_str("100:test");
        if let Ok(_) = com {
            panic!("com must be None");
        }

        let com = CommunityAttr::from_str("65535:65535").unwrap();
        assert_eq!(format!("{}", com), "65535:65535");

        let com = CommunityAttr::from_str("65535:65536");
        if let Ok(_) = com {
            panic!("com must be None");
        }

        let com = CommunityAttr::from_str("65536:65535");
        if let Ok(_) = com {
            panic!("com must be None");
        }

        let com = CommunityAttr::from_str("65536").unwrap();
        assert_eq!(format!("{}", com), "1:0");

        let com = CommunityAttr::from_str("1").unwrap();
        assert_eq!(format!("{}", com), "0:1");
    }

    #[test]
    fn contains() {
        let com = CommunityAttr::from_str("no-export 100:10 100").unwrap();
        if !com.contains(&100u32) {
            panic!("Community must contain no-export");
        }

        let com = CommunityAttr::from_str("no-export 100:10 100").unwrap();
        if !com.contains(&CommunityValue::NoExport.to_value()) {
            panic!("Community must contain no-export");
        }

        if com.contains(&CommunityValue::NoAdvertise.to_value()) {
            panic!("Community must not contain no-advertise");
        }

        let val = CommunityAttr::parse_community("100:10").unwrap();
        if !com.contains(&val) {
            panic!("Community must contain 100:10");
        }
    }
}
