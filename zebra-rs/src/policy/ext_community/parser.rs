// Ext-community matcher.
//
// Mirrors `ExtendedMatcher` from the `community` module but is its
// own type so that `ext-community-set` only accepts ext-community
// syntax (`rt:`, `soo:`) — no standard-community values, no
// well-known names. Regex patterns are matched against the value
// portion (after the `rt:`/`soo:` prefix) to mirror the existing
// extended-community matching semantics.

use std::str::FromStr;

use bgp_packet::{BgpAttr, ExtCommunity, ExtCommunitySubType, ExtCommunityValue};

use crate::policy::community::CompiledRegex;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum ExtCommunityMatcher {
    Exact(ExtCommunityValue),
    Regex(ExtCommunitySubType, CompiledRegex),
}

impl FromStr for ExtCommunityMatcher {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Some(value_str) = input.strip_prefix("rt:") {
            if let Ok(ext_com) = ExtCommunity::from_str(input)
                && let Some(first) = ext_com.0.first()
            {
                return Ok(ExtCommunityMatcher::Exact(first.clone()));
            }
            let compiled = CompiledRegex::new(value_str).map_err(|_| ())?;
            return Ok(ExtCommunityMatcher::Regex(
                ExtCommunitySubType::RouteTarget,
                compiled,
            ));
        }
        if let Some(value_str) = input.strip_prefix("soo:") {
            if let Ok(ext_com) = ExtCommunity::from_str(input)
                && let Some(first) = ext_com.0.first()
            {
                return Ok(ExtCommunityMatcher::Exact(first.clone()));
            }
            let compiled = CompiledRegex::new(value_str).map_err(|_| ())?;
            return Ok(ExtCommunityMatcher::Regex(
                ExtCommunitySubType::RouteOrigin,
                compiled,
            ));
        }
        Err(())
    }
}

pub fn match_ext_community_set(matcher: &ExtCommunityMatcher, bgp_attr: &BgpAttr) -> bool {
    let Some(ref ecom) = bgp_attr.ecom else {
        return false;
    };
    match matcher {
        ExtCommunityMatcher::Exact(target) => ecom.0.iter().any(|v| {
            v.high_type == target.high_type && v.low_type == target.low_type && v.val == target.val
        }),
        ExtCommunityMatcher::Regex(sub_type, compiled) => {
            let target_low_type: u8 = (*sub_type).into();
            for v in &ecom.0 {
                if v.low_type == target_low_type {
                    let s = v.to_string();
                    if let Some((_, value_part)) = s.split_once(':')
                        && compiled.is_match(value_part)
                    {
                        return true;
                    }
                }
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rt_exact_asn() {
        let m = ExtCommunityMatcher::from_str("rt:100:200").unwrap();
        let ExtCommunityMatcher::Exact(v) = m else {
            panic!("expected exact");
        };
        assert_eq!(v.low_type, 0x02);
    }

    #[test]
    fn parse_rt_exact_ip() {
        let m = ExtCommunityMatcher::from_str("rt:1.2.3.4:100").unwrap();
        let ExtCommunityMatcher::Exact(v) = m else {
            panic!("expected exact");
        };
        assert_eq!(v.low_type, 0x02);
    }

    #[test]
    fn parse_rt_regex() {
        let m = ExtCommunityMatcher::from_str("rt:^65001:.*").unwrap();
        let ExtCommunityMatcher::Regex(st, c) = m else {
            panic!("expected regex");
        };
        assert_eq!(st, ExtCommunitySubType::RouteTarget);
        assert_eq!(c.pattern(), "^65001:.*");
    }

    #[test]
    fn parse_soo_exact() {
        let m = ExtCommunityMatcher::from_str("soo:100:200").unwrap();
        let ExtCommunityMatcher::Exact(v) = m else {
            panic!("expected exact");
        };
        assert_eq!(v.low_type, 0x03);
    }

    #[test]
    fn parse_rejects_standard_community() {
        // Bare standard community syntax is not valid in
        // ext-community-set. This is what differentiates it from
        // the legacy community-set.
        assert!(ExtCommunityMatcher::from_str("100:200").is_err());
        assert!(ExtCommunityMatcher::from_str("no-export").is_err());
    }

    #[test]
    fn match_exact_rt() {
        let mut attr = BgpAttr::new();
        attr.ecom = Some(ExtCommunity::from_str("rt:100:200").unwrap());

        let m = ExtCommunityMatcher::from_str("rt:100:200").unwrap();
        assert!(match_ext_community_set(&m, &attr));

        let m = ExtCommunityMatcher::from_str("rt:100:300").unwrap();
        assert!(!match_ext_community_set(&m, &attr));
    }

    #[test]
    fn regex_does_not_cross_subtype() {
        let mut attr = BgpAttr::new();
        attr.ecom = Some(ExtCommunity::from_str("rt:100:200").unwrap());

        // soo regex must not match rt-typed community.
        let m = ExtCommunityMatcher::from_str("soo:100:.*").unwrap();
        assert!(!match_ext_community_set(&m, &attr));
    }

    #[test]
    fn no_ecom_attr_never_matches() {
        let attr = BgpAttr::new();
        let m = ExtCommunityMatcher::from_str("rt:100:200").unwrap();
        assert!(!match_ext_community_set(&m, &attr));
    }
}
