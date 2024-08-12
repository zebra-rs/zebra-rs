use std::collections::BTreeMap;

#[derive(Debug)]
pub struct Policy {
    pub route_map: BTreeMap<String, RouteMap>,
}

impl Policy {
    pub fn new() -> Self {
        Self {
            route_map: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct RouteMap {
    pub name: String,
}

impl RouteMap {
    pub fn new() -> Self {
        Self {
            name: String::from(""),
        }
    }
}

#[derive(Debug)]
pub struct RouteMapEntry {
    pub seq: i32,
    pub action: EntryAction,
    pub matches: Vec<EntryMatch>,
}

impl RouteMapEntry {
    pub fn new(seq: i32) -> Self {
        Self {
            seq,
            action: EntryAction::None,
            matches: Vec::new(),
        }
    }

    pub fn action(&mut self, action: EntryAction) {
        self.action = action;
    }

    pub fn match_add(&mut self, _match_type: EntryMatch, _arg: &[&str]) {}

    pub fn set_add(&mut self, _set_type: EntrySet, _arg: &str) {}
}

#[derive(Debug)]
pub enum EntryAction {
    None,
    Permit,
    Deny,
}

#[derive(Debug)]
pub enum EntryMatch {
    PrefixList,
    CommList,
    ExtCommList,
    LargeCommList,
}

#[derive(Debug)]
pub enum EntrySet {
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

pub fn PolicyInit() {
    let pmap = Policy::new();
    println!("{:?}", pmap);

    let rmap = RouteMap::new();
    println!("{:?}", rmap);

    let mut rentry = RouteMapEntry::new(5);
    rentry.action(EntryAction::Permit);
    rentry.match_add(EntryMatch::CommList, &["clist"]);
    // rentry.match_del();
    // rentry.set_add();
    // rentry.set_del();
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rmap() {}
}
