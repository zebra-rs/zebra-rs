use std::collections::BTreeMap;

pub struct Policy {
    pub route_map: BTreeMap<String, RouteMap>,
}

pub struct RouteMap {
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rmap() {}
}
