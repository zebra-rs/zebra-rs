// Large-community matcher.
//
// A `large-community-set` member is one of:
//   - an exact value `A:B:C` (three colon-separated u32s, RFC 8092),
//   - a regex pattern matched against the textual `A:B:C` form of
//     each LARGE_COMMUNITIES element on the route.
//
// Parsing tries the exact form first; anything else compiles as
// regex. (Bare patterns without regex metacharacters still parse as
// regex if they aren't valid literal triples — that mirrors how the
// legacy community-set treats fallthrough.)

use std::str::FromStr;

use bgp_packet::{BgpAttr, LargeCommunityValue};

use crate::policy::community::CompiledRegex;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum LargeCommunityMatcher {
    Exact(LargeCommunityValue),
    Regex(CompiledRegex),
}

fn parse_literal(s: &str) -> Option<LargeCommunityValue> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let global = parts[0].parse::<u32>().ok()?;
    let local1 = parts[1].parse::<u32>().ok()?;
    let local2 = parts[2].parse::<u32>().ok()?;
    Some(LargeCommunityValue {
        global,
        local1,
        local2,
    })
}

impl FromStr for LargeCommunityMatcher {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Some(v) = parse_literal(input) {
            return Ok(LargeCommunityMatcher::Exact(v));
        }
        let compiled = CompiledRegex::new(input).map_err(|_| ())?;
        Ok(LargeCommunityMatcher::Regex(compiled))
    }
}

pub fn match_large_community_set(matcher: &LargeCommunityMatcher, bgp_attr: &BgpAttr) -> bool {
    let Some(ref lcom) = bgp_attr.lcom else {
        return false;
    };
    match matcher {
        LargeCommunityMatcher::Exact(target) => lcom.0.iter().any(|v| v == target),
        LargeCommunityMatcher::Regex(compiled) => {
            lcom.0.iter().any(|v| compiled.is_match(&v.to_str()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::LargeCommunity;

    #[test]
    fn parse_exact_triple() {
        let m = LargeCommunityMatcher::from_str("65001:100:200").unwrap();
        let LargeCommunityMatcher::Exact(v) = m else {
            panic!("expected exact");
        };
        assert_eq!(v.global, 65001);
        assert_eq!(v.local1, 100);
        assert_eq!(v.local2, 200);
    }

    #[test]
    fn parse_regex_when_not_a_triple() {
        let m = LargeCommunityMatcher::from_str("^65001:.*:.*$").unwrap();
        let LargeCommunityMatcher::Regex(c) = m else {
            panic!("expected regex");
        };
        assert_eq!(c.pattern(), "^65001:.*:.*$");
    }

    #[test]
    fn match_exact() {
        let mut attr = BgpAttr::new();
        attr.lcom = Some(LargeCommunity::from_str("65001:100:200 65002:300:400").unwrap());

        let m = LargeCommunityMatcher::from_str("65001:100:200").unwrap();
        assert!(match_large_community_set(&m, &attr));

        let m = LargeCommunityMatcher::from_str("65001:100:201").unwrap();
        assert!(!match_large_community_set(&m, &attr));
    }

    #[test]
    fn match_regex() {
        let mut attr = BgpAttr::new();
        attr.lcom = Some(LargeCommunity::from_str("65001:100:200 65002:300:400").unwrap());

        let m = LargeCommunityMatcher::from_str("^65001:.*:.*$").unwrap();
        assert!(match_large_community_set(&m, &attr));

        let m = LargeCommunityMatcher::from_str("^99999:.*").unwrap();
        assert!(!match_large_community_set(&m, &attr));
    }

    #[test]
    fn no_lcom_attr_never_matches() {
        let attr = BgpAttr::new();
        let m = LargeCommunityMatcher::from_str("65001:100:200").unwrap();
        assert!(!match_large_community_set(&m, &attr));
    }
}
