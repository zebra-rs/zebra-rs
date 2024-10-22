use std::collections::BTreeMap;

use super::Action;

#[allow(dead_code)]
#[derive(Default)]
pub struct RouteMapTree {
    pub rmap: BTreeMap<String, RouteMap>,
}

#[allow(dead_code)]
#[derive(Default)]
pub struct RouteMap {
    pub seq: BTreeMap<u32, RouteMapEntry>,
    pub delete: bool,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RouteMapEntry {
    pub seq: i32,
    pub action: Action,
    pub matches: Vec<MatchEntry>,
    pub sets: Vec<SetEntry>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct MatchEntry {}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SetEntry {}

#[allow(dead_code)]
#[derive(Debug)]
enum MatchType {
    PrefixList,
    CommList,
    ExtCommList,
    LargeCommList,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum SetType {
    NextHop,
}

// route-map hoge {
//     seq 10 {
//         action permit;
//         match {
//             comm-list clist;
//         }
//         set {
//             as-path-prepend 100 101;
//         }
//     }
//     seq 20 {
//         action permit;
//         set {
//             metric 123;
//         }
//     }
// }

#[cfg(test)]
mod tests {
    #[test]
    fn test_rmap() {}
}
