use crate::rib::Nexthop;

#[allow(dead_code)]
#[derive(Default)]
pub struct NexthopResilience {
    buckets: u16,
    idle_timer: u32,
    unbalanced_timer: u32,
    unbalanced_time: u64,
}

#[derive(Default)]
struct NexthopGroup {
    nexthops: Vec<Nexthop>,
    resilience: NexthopResilience,
}
