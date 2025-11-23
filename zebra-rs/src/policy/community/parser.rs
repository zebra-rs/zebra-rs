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
        // Try to parse as exact route target (e.g., "rt:100:200" or "rt:1.2.3.4:100")
        if let Ok(ext_com) = ExtCommunity::from_str(input) {
            // Successfully parsed as exact extended community
            if let Some(first) = ext_com.0.first() {
                return Some(CommunityMatcher::Extended(ExtendedMatcher::Exact(
                    first.clone(),
                )));
            }
        }

        // If exact parse failed, treat as regex pattern (e.g., "rt:^62692:.*$")
        let value_str = &input[3..]; // Skip "rt:" prefix for regex pattern
        return Some(CommunityMatcher::Extended(ExtendedMatcher::Regex(
            ExtCommunitySubType::RouteTarget,
            value_str.to_string(),
        )));
    }

    if input.starts_with("soo:") {
        // Try to parse as exact site of origin (e.g., "soo:100:200")
        if let Ok(ext_com) = ExtCommunity::from_str(input) {
            if let Some(first) = ext_com.0.first() {
                return Some(CommunityMatcher::Extended(ExtendedMatcher::Exact(
                    first.clone(),
                )));
            }
        }

        // If exact parse failed, treat as regex pattern
        let value_str = &input[4..]; // Skip "soo:" prefix for regex pattern
        return Some(CommunityMatcher::Extended(ExtendedMatcher::Regex(
            ExtCommunitySubType::RouteOrigin,
            value_str.to_string(),
        )));
    }

    None
}

pub fn match_community_set(matcher: &CommunityMatcher, bgp_attr: &BgpAttr) -> bool {
    match matcher {
        CommunityMatcher::Standard(standard_matcher) => {
            // Check standard community attribute
            let Some(ref community) = bgp_attr.com else {
                return false;
            };

            match standard_matcher {
                StandardMatcher::Exact(target_value) => {
                    // Check if the community list contains the exact value
                    community.contains(&target_value.0)
                }
                StandardMatcher::Regex(pattern) => {
                    // Convert all communities to strings and check against regex
                    use regex::Regex;
                    let Ok(re) = Regex::new(pattern) else {
                        return false;
                    };

                    for &com_val in &community.0 {
                        let com_str = CommunityValue(com_val).to_str();
                        if re.is_match(&com_str) {
                            return true;
                        }
                    }
                    false
                }
            }
        }
        CommunityMatcher::Extended(extended_matcher) => {
            // Check extended community attribute
            let Some(ref ecom) = bgp_attr.ecom else {
                return false;
            };

            match extended_matcher {
                ExtendedMatcher::Exact(target_value) => {
                    // Check if any extended community matches exactly
                    for ext_com_val in &ecom.0 {
                        if ext_com_val.high_type == target_value.high_type
                            && ext_com_val.low_type == target_value.low_type
                            && ext_com_val.val == target_value.val
                        {
                            return true;
                        }
                    }
                    false
                }
                ExtendedMatcher::Regex(sub_type, pattern) => {
                    // Filter by subtype and match against regex
                    use regex::Regex;
                    let Ok(re) = Regex::new(pattern) else {
                        return false;
                    };

                    let target_low_type: u8 = match sub_type {
                        ExtCommunitySubType::RouteTarget => 0x02,
                        ExtCommunitySubType::RouteOrigin => 0x03,
                        ExtCommunitySubType::Opaque => 0x0c,
                    };

                    for ext_com_val in &ecom.0 {
                        // Only match communities of the correct subtype
                        if ext_com_val.low_type == target_low_type {
                            let ext_com_str = ext_com_val.to_string();
                            if re.is_match(&ext_com_str) {
                                return true;
                            }
                        }
                    }
                    false
                }
            }
        }
    }
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
