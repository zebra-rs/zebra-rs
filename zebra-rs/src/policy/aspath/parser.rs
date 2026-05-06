// BGP AS-Path Matcher Implementation
//
// Each member of an as-path-set is a regular expression matched against the
// route's AS_PATH attribute rendered as a space-separated string (e.g.
// "65001 65002 65003" or "65001 {65010 65011} 65003").
//
// Examples:
//   as-path-set CUSTOMER {
//     member ^65001 .*;        // path starts with 65001 (neighbor-is)
//     member 65535$;           // path ends with 65535 (originates-from)
//     member \\b65001\\b;      // 65001 anywhere in the path
//   }

use std::str::FromStr;

use bgp_packet::BgpAttr;
use regex::Regex;

#[derive(Clone)]
pub struct AsPathMatcher {
    pattern: String,
    regex: Regex,
}

impl AsPathMatcher {
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

impl FromStr for AsPathMatcher {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let regex = Regex::new(input).map_err(|_| ())?;
        Ok(Self {
            pattern: input.to_string(),
            regex,
        })
    }
}

impl std::fmt::Debug for AsPathMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsPathMatcher")
            .field("pattern", &self.pattern)
            .finish()
    }
}

impl PartialEq for AsPathMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for AsPathMatcher {}

impl PartialOrd for AsPathMatcher {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AsPathMatcher {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.pattern.cmp(&other.pattern)
    }
}

pub fn match_as_path_set(matcher: &AsPathMatcher, bgp_attr: &BgpAttr) -> bool {
    let Some(aspath) = &bgp_attr.aspath else {
        return false;
    };
    let rendered = aspath.as_path_display();
    matcher.regex.is_match(&rendered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::As4Path;

    fn attr_with_path(path: &str) -> BgpAttr {
        let mut attr = BgpAttr::new();
        attr.aspath = Some(As4Path::from_str(path).unwrap());
        attr
    }

    #[test]
    fn neighbor_is_anchored_start() {
        let m = AsPathMatcher::from_str("^65001\\b").unwrap();
        assert!(match_as_path_set(&m, &attr_with_path("65001 65002 65003")));
        assert!(!match_as_path_set(&m, &attr_with_path("65000 65001 65002")));
    }

    #[test]
    fn originates_from_anchored_end() {
        let m = AsPathMatcher::from_str("\\b65535$").unwrap();
        assert!(match_as_path_set(&m, &attr_with_path("65001 65002 65535")));
        assert!(!match_as_path_set(&m, &attr_with_path("65535 65001 65002")));
    }

    #[test]
    fn passes_through() {
        let m = AsPathMatcher::from_str("\\b777\\b").unwrap();
        assert!(match_as_path_set(&m, &attr_with_path("65001 777 65003")));
        assert!(match_as_path_set(&m, &attr_with_path("777 65001")));
        assert!(!match_as_path_set(&m, &attr_with_path("7777 65001")));
    }

    #[test]
    fn empty_path() {
        let m = AsPathMatcher::from_str("\\b65001\\b").unwrap();
        let mut attr = BgpAttr::new();
        attr.aspath = None;
        assert!(!match_as_path_set(&m, &attr));
    }

    #[test]
    fn invalid_regex_rejected() {
        assert!(AsPathMatcher::from_str("[invalid(").is_err());
    }
}
