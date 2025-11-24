// BGP Community Matcher Implementation
//
// This module provides parsing and matching functionality for BGP community-set
// policy configuration. Community-sets can match either standard BGP communities
// or extended communities (route-target, site-of-origin).
//
// # Supported Formats
//
// ## Extended Community Matching
//
// Route Target (exact match):
// ```
// community-set TENANT-A {
//   member {
//     rt:62692:100;        // ASN:value format
//     rt:1.2.3.4:100;      // IP:value format
//   };
// }
// ```
//
// Route Target (regex match):
// ```
// community-set TENANT-A-REGEX {
//   member {
//     rt:^62692:.*$;       // Match all communities from AS 62692
//     rt:62692:.*0$;       // Match communities ending with 0
//   };
// }
// ```
//
// Site of Origin:
// ```
// community-set TENANT-B {
//   member {
//     soo:62692:100;       // Exact match
//     soo:^100:.*$;        // Regex match
//   };
// }
// ```
//
// ## Standard Community Matching
//
// Well-known communities:
// ```
// community-set WELL-KNOWN {
//   member {
//     no-export;           // Well-known community value
//     no-advertise;        // Another well-known value
//   };
// }
// ```
//
// Standard community exact match:
// ```
// community-set TENANT-A-COM {
//   member {
//     100:200;             // Exact match for AS:value format
//     65000:100;           // Another exact match
//   };
// }
// ```
//
// Standard community regex match:
// ```
// community-set TENANT-A-REGEX {
//   member {
//     ^100:.*$;            // Match all communities from AS 100
//     .*:200$;             // Match all communities with value 200
//   };
// }
// ```
//
// # Implementation Details
//
// - Extended communities support both exact and regex pattern matching
// - Regex patterns are applied to the value portion after the prefix (rt:/soo:)
// - Subtype filtering ensures rt: patterns only match route-target communities
// - Invalid regex patterns return false without panicking

use std::str::FromStr;

use bgp_packet::*;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum StandardMatcher {
    Exact(CommunityValue),
    Regex(String),
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum ExtendedMatcher {
    Exact(ExtCommunityValue),
    Regex(ExtCommunitySubType, String),
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum CommunityMatcher {
    Standard(StandardMatcher),
    Extended(ExtendedMatcher),
}

impl FromStr for CommunityMatcher {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.starts_with("rt:") {
            // Try to parse as exact route target (e.g., "rt:100:200" or "rt:1.2.3.4:100")
            if let Ok(ext_com) = ExtCommunity::from_str(input) {
                // Successfully parsed as exact extended community
                if let Some(first) = ext_com.0.first() {
                    return Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(
                        first.clone(),
                    )));
                }
            }

            // If exact parse failed, treat as regex pattern (e.g., "rt:^62692:.*$")
            let value_str = &input[3..]; // Skip "rt:" prefix for regex pattern
            return Ok(CommunityMatcher::Extended(ExtendedMatcher::Regex(
                ExtCommunitySubType::RouteTarget,
                value_str.to_string(),
            )));
        }

        if input.starts_with("soo:") {
            // Try to parse as exact site of origin (e.g., "soo:100:200")
            if let Ok(ext_com) = ExtCommunity::from_str(input) {
                if let Some(first) = ext_com.0.first() {
                    return Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(
                        first.clone(),
                    )));
                }
            }

            // If exact parse failed, treat as regex pattern
            let value_str = &input[4..]; // Skip "soo:" prefix for regex pattern
            return Ok(CommunityMatcher::Extended(ExtendedMatcher::Regex(
                ExtCommunitySubType::RouteOrigin,
                value_str.to_string(),
            )));
        }

        // Check if input looks like a regex pattern (contains special regex chars)
        let has_regex_chars = input.contains('^')
            || input.contains('$')
            || input.contains('*')
            || input.contains('.')
            || input.contains('[')
            || input.contains(']')
            || input.contains('(')
            || input.contains(')')
            || input.contains('|')
            || input.contains('+')
            || input.contains('?');

        if has_regex_chars {
            // Definitely a regex pattern
            return Ok(CommunityMatcher::Standard(StandardMatcher::Regex(
                input.to_string(),
            )));
        }

        // Try to parse as standard community (e.g., "100:200")
        if let Some(com_val) = CommunityValue::from_readable_str(input) {
            return Ok(CommunityMatcher::Standard(StandardMatcher::Exact(com_val)));
        }

        // If it doesn't parse as exact value and no regex chars, treat as simple regex
        Ok(CommunityMatcher::Standard(StandardMatcher::Regex(
            input.to_string(),
        )))
    }
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

                    // Use IntoPrimitive derive to convert ExtCommunitySubType to u8
                    let target_low_type: u8 = (*sub_type).into();

                    for ext_com_val in &ecom.0 {
                        // Only match communities of the correct subtype
                        if ext_com_val.low_type == target_low_type {
                            let ext_com_str = ext_com_val.to_string();
                            // Remove the prefix (e.g., "rt:" or "soo:") before matching
                            // The to_string() produces "rt:100:200", but pattern is "^100:.*"
                            if let Some(value_part) = ext_com_str.split_once(':') {
                                if re.is_match(value_part.1) {
                                    return true;
                                }
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
        let result = CommunityMatcher::from_str("no-export");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Standard(StandardMatcher::Exact(val))) = result {
            assert_eq!(val, CommunityValue::NO_EXPORT);
        } else {
            panic!("Expected Standard exact match for no-export");
        }
    }

    #[test]
    fn test_parse_rt_exact_asn() {
        let result = CommunityMatcher::from_str("rt:100:200");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x02); // Route Target
        } else {
            panic!("Expected Extended exact match for rt:100:200");
        }
    }

    #[test]
    fn test_parse_rt_exact_ip() {
        let result = CommunityMatcher::from_str("rt:1.2.3.4:100");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x02); // Route Target
        } else {
            panic!("Expected Extended exact match for rt:1.2.3.4:100");
        }
    }

    #[test]
    fn test_parse_rt_regex() {
        let result = CommunityMatcher::from_str("rt:62692:.*");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Regex(sub_type, pattern))) = result {
            assert_eq!(sub_type, ExtCommunitySubType::RouteTarget);
            assert_eq!(pattern, "62692:.*");
        } else {
            panic!("Expected Extended regex match for rt:62692:.*");
        }
    }

    #[test]
    fn test_parse_soo_exact() {
        let result = CommunityMatcher::from_str("soo:62692:100");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x03); // Site of Origin
        } else {
            panic!("Expected Extended exact match for soo:62692:100");
        }
    }

    #[test]
    fn test_parse_soo_regex() {
        let result = CommunityMatcher::from_str("soo:100:.*");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Regex(sub_type, pattern))) = result {
            assert_eq!(sub_type, ExtCommunitySubType::RouteOrigin);
            assert_eq!(pattern, "100:.*");
        } else {
            panic!("Expected Extended regex match for soo:100:.*");
        }
    }

    #[test]
    fn test_match_standard_community_exact() {
        // Create a BGP attribute with standard community
        let mut bgp_attr = BgpAttr::new();
        bgp_attr.com = Some(Community(vec![
            CommunityValue::from_readable_str("100:200").unwrap().0,
            CommunityValue::from_readable_str("300:400").unwrap().0,
        ]));

        // Test exact match - should find 100:200
        let matcher = CommunityMatcher::from_str("100:200").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test exact match - should find 300:400
        let matcher = CommunityMatcher::from_str("300:400").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test no match - different value
        let matcher = CommunityMatcher::from_str("500:600").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test with no-export
        let matcher = CommunityMatcher::from_str("no-export").unwrap();
        let mut bgp_attr_export = BgpAttr::new();
        bgp_attr_export.com = Some(Community(vec![CommunityValue::NO_EXPORT.0]));
        assert!(match_community_set(&matcher, &bgp_attr_export));

        // Test no match
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_standard_community_regex() {
        // Create a BGP attribute with standard communities
        let mut bgp_attr = BgpAttr::new();
        bgp_attr.com = Some(Community(vec![
            CommunityValue::from_readable_str("100:200").unwrap().0,
            CommunityValue::from_readable_str("100:300").unwrap().0,
            CommunityValue::from_readable_str("200:400").unwrap().0,
        ]));

        // Test regex match - should match 100:*
        let matcher = CommunityMatcher::from_str("^100:.*").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test regex match with end anchor
        let matcher = CommunityMatcher::from_str("100:.*0$").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test regex no match
        let matcher = CommunityMatcher::from_str("^300:.*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test regex partial match (without anchors) - matches substring
        let matcher = CommunityMatcher::from_str(":200").unwrap();
        // This should match "100:200" because it contains ":200"
        assert!(match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_exact_rt() {
        // Create a BGP attribute with extended community (route target)
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:100:200").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test exact match - should find rt:100:200
        let matcher = CommunityMatcher::from_str("rt:100:200").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test no match - different value
        let matcher = CommunityMatcher::from_str("rt:100:300").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test no match - different type (soo instead of rt)
        let matcher = CommunityMatcher::from_str("soo:100:200").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_exact_ip() {
        // Create a BGP attribute with IP-based extended community
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:1.2.3.4:100").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test exact match
        let matcher = CommunityMatcher::from_str("rt:1.2.3.4:100").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test no match - different IP
        let matcher = CommunityMatcher::from_str("rt:1.2.3.5:100").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_regex_rt() {
        // Create a BGP attribute with multiple route targets (using actual values, not regex)
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:62692:100 rt:62692:200 soo:100:300").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test regex match - pattern should match rt:62692:*
        let matcher = CommunityMatcher::from_str("rt:^62692:.*").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test regex no match - different ASN pattern
        let matcher = CommunityMatcher::from_str("rt:99999:.*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test that soo regex doesn't match rt values
        let matcher = CommunityMatcher::from_str("soo:62692:.*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:62692:.*$").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:62692:.*0$").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:62692:.*1$").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:692:.*$").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:^692:.*$").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_regex_soo() {
        // Create a BGP attribute with site of origin (using actual values, not regex)
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("soo:100:200 soo:100:300").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test regex match - pattern should match soo:100:*
        let matcher = CommunityMatcher::from_str("soo:100:.*").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test regex no match
        let matcher = CommunityMatcher::from_str("soo:200:.*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_no_community_attribute() {
        // Create a BGP attribute without any communities
        let bgp_attr = BgpAttr::new();

        // Test standard community matcher - should return false
        let matcher = CommunityMatcher::from_str("no-export").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test extended community matcher - should return false
        let matcher = CommunityMatcher::from_str("rt:100:200").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_multiple_values() {
        // Create a BGP attribute with multiple different extended communities
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:100:200 rt:1.2.3.4:300 soo:400:500").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Should match first rt
        let matcher = CommunityMatcher::from_str("rt:100:200").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Should match second rt (IP-based)
        let matcher = CommunityMatcher::from_str("rt:1.2.3.4:300").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Should match soo
        let matcher = CommunityMatcher::from_str("soo:400:500").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Should not match non-existent value
        let matcher = CommunityMatcher::from_str("rt:999:999").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_invalid_regex() {
        // Create a BGP attribute with extended community
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:100:200").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test with invalid regex pattern - should return false without panicking
        let matcher = CommunityMatcher::Extended(ExtendedMatcher::Regex(
            ExtCommunitySubType::RouteTarget,
            "[invalid(regex".to_string(),
        ));
        assert!(!match_community_set(&matcher, &bgp_attr));
    }
}
