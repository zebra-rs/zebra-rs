use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Default, Clone)]
pub struct StaticNexthop {
    pub distance: Option<u8>,
    pub metric: Option<u32>,
    pub weight: Option<u32>,
}

#[derive(Debug, Default, Clone)]
pub struct StaticRoute {
    pub distance: Option<u8>,
    pub metric: Option<u32>,
    pub nexthops: BTreeMap<Ipv4Addr, StaticNexthop>,
    pub delete: bool,
}

impl fmt::Display for StaticRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let distance = self.distance.unwrap_or(1);
        let metric = self.metric.unwrap_or(0);

        write!(f, "[{}/{}]", distance, metric).unwrap();
        for (p, n) in self.nexthops.iter() {
            let distance = n.distance.unwrap_or(distance);
            let metric = n.metric.unwrap_or(metric);
            writeln!(f, "  {} [{}/{}]", p, distance, metric).unwrap();
        }
        write!(f, "")
    }
}
