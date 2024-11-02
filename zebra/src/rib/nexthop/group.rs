use std::collections::BTreeSet;

use crate::rib::Nexthop;

#[allow(dead_code)]
#[derive(Default)]
pub struct NexthopResilience {
    buckets: u16,
    idle_timer: u32,
    unbalanced_timer: u32,
    unbalanced_time: u64,
}

pub enum NexthopGroup {
    Uni(NexthopUni),
    Multi(NexthopMulti),
    Protect(NexthopProtect),
}

pub struct NexthopUni {
    //
}

pub struct NexthopWeight {
    nhid: usize,
    weight: u8,
}

pub struct NexthopMulti {
    nhid: usize,
    nhops: BTreeSet<usize>,
}

pub struct NexthopProtect {
    //
}
