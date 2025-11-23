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
        // TODO: Parse the input string with ExtCommunity. When it succeed, build
        // Extended(ExtendedMatcher::Exact) otherwise, Regex(ExtCommunitySubType::RouteTarget)
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_matches_community_rt() {
        //
    }
}
