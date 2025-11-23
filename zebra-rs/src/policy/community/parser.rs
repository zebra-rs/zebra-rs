// We are going to implement policy configuration for "community-set".
// The community-set can be matched to either Community or ExtCommunity.
//
// Below is a matching for route-target of BGP extended community attribute.
//
// community-set TENANT-A-REGEX {
//   member {
//     rt:^62692:.*$;
//   };
// }
//
// community-set TENANT-A {
//   member {
//     soo:62692:100;
//   };
// }
//
// BGP Extended community attribute, The prefix could be "rt:" or "soo:" or "opaque:".
//
// Below is a example of Community match.
//
// community-set TENANT-A-COM {
//   member {
//     62692:100;
//   };
// }
//
// Community can have wellknown community value such as "no-export". We can have
// multiple of member value. In that case,
//
// community-set TENANT-A-COM {
//   member {
//     62692:100;
//     no-export;
//   };
// }

use std::str::FromStr;

use bgp_packet::*;

#[derive(Debug)]
pub enum StandardMatcher {
    Exact(CommunityValue),
    Regex(String),
}

#[derive(Debug)]
pub enum ExtendedMatcher {
    Exact(ExtCommunityValue),
    Regex(ExtCommunitySubType, String),
}

#[derive(Debug)]
pub enum CommunityMatcher {
    Standard(StandardMatcher),
    Extended(ExtendedMatcher),
}

pub fn parse_community_set(input: &str) -> Option<CommunityMatcher> {
    if input == "no-export" {
        return Some(CommunityMatcher::Standard(StandardMatcher::Exact(
            CommunityValue::NO_EXPORT,
        )));
    }
    if input.starts_with("rt:") {
        let value_str = &input[3..]; // Skip "rt:" prefix

        // Try to parse as exact route target (e.g., "rt:100:200" or "rt:1.2.3.4:100")
        if let Ok(ext_com) = ExtCommunity::from_str(&format!("rt {}", value_str)) {
            // Successfully parsed as exact extended community
            if let Some(first) = ext_com.0.first() {
                return Some(CommunityMatcher::Extended(ExtendedMatcher::Exact(
                    first.clone(),
                )));
            }
        }

        // If exact parse failed, treat as regex pattern (e.g., "rt:^62692:.*$")
        return Some(CommunityMatcher::Extended(ExtendedMatcher::Regex(
            ExtCommunitySubType::RouteTarget,
            value_str.to_string(),
        )));
    }

    if input.starts_with("soo:") {
        let value_str = &input[4..]; // Skip "soo:" prefix

        // Try to parse as exact site of origin
        if let Ok(ext_com) = ExtCommunity::from_str(&format!("soo {}", value_str)) {
            if let Some(first) = ext_com.0.first() {
                return Some(CommunityMatcher::Extended(ExtendedMatcher::Exact(
                    first.clone(),
                )));
            }
        }

        // If exact parse failed, treat as regex pattern
        return Some(CommunityMatcher::Extended(ExtendedMatcher::Regex(
            ExtCommunitySubType::RouteOrigin,
            value_str.to_string(),
        )));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_no_export() {
        let result = parse_community_set("no-export");
        assert!(result.is_some());
        if let Some(CommunityMatcher::Standard(StandardMatcher::Exact(val))) = result {
            assert_eq!(val, CommunityValue::NO_EXPORT);
        } else {
            panic!("Expected Standard exact match for no-export");
        }
    }

    #[test]
    fn test_parse_rt_exact_asn() {
        let result = parse_community_set("rt:100:200");
        assert!(result.is_some());
        if let Some(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x02); // Route Target
        } else {
            panic!("Expected Extended exact match for rt:100:200");
        }
    }

    #[test]
    fn test_parse_rt_exact_ip() {
        let result = parse_community_set("rt:1.2.3.4:100");
        assert!(result.is_some());
        if let Some(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x02); // Route Target
        } else {
            panic!("Expected Extended exact match for rt:1.2.3.4:100");
        }
    }

    #[test]
    fn test_parse_rt_regex() {
        let result = parse_community_set("rt:^62692:.*$");
        assert!(result.is_some());
        if let Some(CommunityMatcher::Extended(ExtendedMatcher::Regex(sub_type, pattern))) = result
        {
            assert_eq!(sub_type, ExtCommunitySubType::RouteTarget);
            assert_eq!(pattern, "^62692:.*$");
        } else {
            panic!("Expected Extended regex match for rt:^62692:.*$");
        }
    }

    #[test]
    fn test_parse_soo_exact() {
        let result = parse_community_set("soo:62692:100");
        assert!(result.is_some());
        if let Some(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x03); // Site of Origin
        } else {
            panic!("Expected Extended exact match for soo:62692:100");
        }
    }

    #[test]
    fn test_parse_soo_regex() {
        let result = parse_community_set("soo:^100:.*$");
        assert!(result.is_some());
        if let Some(CommunityMatcher::Extended(ExtendedMatcher::Regex(sub_type, pattern))) = result
        {
            assert_eq!(sub_type, ExtCommunitySubType::RouteOrigin);
            assert_eq!(pattern, "^100:.*$");
        } else {
            panic!("Expected Extended regex match for soo:^100:.*$");
        }
    }
}
