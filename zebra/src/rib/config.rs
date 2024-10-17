use super::{
    entry::{RibEntry, RibType},
    instance::{Rib, RibEntries},
};
use crate::{
    config::{Args, ConfigOp},
    rib::{nexthop::Nexthop, route::StaticRoute},
};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::{collections::BTreeMap, net::Ipv4Addr};

pub fn routing_static_route(rib: &mut Rib, mut args: Args, op: ConfigOp) {
    let prefix: Ipv4Net = args.v4net().unwrap();
    println!("route {}", prefix);

    if op == ConfigOp::Set {
        if rib.cache.get(&prefix).is_none() {
            rib.cache.insert(prefix, StaticRoute::default());
        }
        let s = rib.cache.get_mut(&prefix).unwrap();
        println!("s: {:?}", s);
    }
    if op == ConfigOp::Delete {
        //
    }
}

pub fn routing_static_commit(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    cache: &mut BTreeMap<Ipv4Net, StaticRoute>,
) {
    for (p, s) in cache.into_iter() {
        println!("p: {:?} s: {:?}", p, s);
        let e = rib.entry(*p).or_default();
        e.st = Some(s.clone());
        // rib.register_static(p, s);
    }
    cache.clear();
}

pub fn routing_static_route_metric(rib: &mut Rib, mut args: Args, op: ConfigOp) {
    let prefix: Ipv4Net = args.v4net().unwrap();
    println!("route metric {}", prefix);

    if op == ConfigOp::Set {
        if rib.cache.get(&prefix).is_none() {
            rib.cache.insert(prefix, StaticRoute::default());
        }
        let s = rib.cache.get_mut(&prefix).unwrap();

        let metric = args.u32().unwrap();
        s.metric = Some(metric);

        println!("s: {:?}", s);
    }
    if op == ConfigOp::Delete {
        //
    }
}

pub fn routing_static_route_distance(rib: &mut Rib, mut args: Args, op: ConfigOp) {
    let prefix: Ipv4Net = args.v4net().unwrap();
    println!("route distance {}", prefix);

    if op == ConfigOp::Set {
        if rib.cache.get(&prefix).is_none() {
            rib.cache.insert(prefix, StaticRoute::default());
        }
        let s = rib.cache.get_mut(&prefix).unwrap();

        let distance = args.u8().unwrap();
        s.distance = Some(distance);

        println!("s: {:?}", s);
    }
    if op == ConfigOp::Delete {
        //
    }
}

pub fn routing_static_route_nexthop(rib: &mut Rib, mut args: Args, op: ConfigOp) {
    let prefix: Ipv4Net = args.v4net().unwrap();
    println!("route nexthop {}", prefix);

    if op == ConfigOp::Set {
        if rib.cache.get(&prefix).is_none() {
            rib.cache.insert(prefix, StaticRoute::default());
        }
        let s = rib.cache.get_mut(&prefix).unwrap();

        //
        let nexthop = args.v4addr().unwrap();
        s.nexthops.entry(nexthop).or_default();

        println!("s: {:?}", s);
    }
    if op == ConfigOp::Delete {
        //
    }
}

pub fn routing_static_route_nexthop_distance(rib: &mut Rib, mut args: Args, op: ConfigOp) {
    let prefix: Ipv4Net = args.v4net().unwrap();
    println!("route nexthop {}", prefix);

    if op == ConfigOp::Set {
        if rib.cache.get(&prefix).is_none() {
            rib.cache.insert(prefix, StaticRoute::default());
        }
        let s = rib.cache.get_mut(&prefix).unwrap();

        //
        let nhop = args.v4addr().unwrap();
        let nhop = s.nexthops.get_mut(&nhop).unwrap();

        //
        let distance = args.u8().unwrap();
        nhop.distance = Some(distance);

        println!("s: {:?}", s);
    }
    if op == ConfigOp::Delete {
        //
    }
}

pub fn routing_static_route_nexthop_metric(rib: &mut Rib, mut args: Args, op: ConfigOp) {
    let prefix: Ipv4Net = args.v4net().unwrap();
    println!("route nexthop {}", prefix);

    if op == ConfigOp::Set {
        if rib.cache.get(&prefix).is_none() {
            rib.cache.insert(prefix, StaticRoute::default());
        }
        let s = rib.cache.get_mut(&prefix).unwrap();

        //
        let nhop = args.v4addr().unwrap();
        let nhop = s.nexthops.get_mut(&nhop).unwrap();

        //
        let metric = args.u32().unwrap();
        nhop.metric = Some(metric);

        println!("s: {:?}", s);
    }
    if op == ConfigOp::Delete {
        //
    }
}

pub fn routing_static_route_nexthop_weight(rib: &mut Rib, mut args: Args, op: ConfigOp) {
    let prefix: Ipv4Net = args.v4net().unwrap();
    println!("route nexthop {}", prefix);

    if op == ConfigOp::Set {
        if rib.cache.get(&prefix).is_none() {
            rib.cache.insert(prefix, StaticRoute::default());
        }
        let s = rib.cache.get_mut(&prefix).unwrap();

        //
        let nhop = args.v4addr().unwrap();
        let nhop = s.nexthops.get_mut(&nhop).unwrap();

        //
        let weight = args.u32().unwrap();
        nhop.weight = Some(weight);

        println!("s: {:?}", s);
    }
    if op == ConfigOp::Delete {
        //
    }
}

pub async fn config_dispatch(rib: &mut Rib, path: String, args: Args, op: ConfigOp) {
    //println!("Path: {}", path);

    match path.as_str() {
        "/routing/static/route" => {
            routing_static_route(rib, args, op);
        }
        "/routing/static/route/metric" => {
            routing_static_route_metric(rib, args, op);
        }
        "/routing/static/route/distance" => {
            routing_static_route_distance(rib, args, op);
        }
        "/routing/static/route/nexthop" => {
            routing_static_route_nexthop(rib, args, op);
        }
        "/routing/static/route/nexthop/metric" => {
            routing_static_route_nexthop_metric(rib, args, op);
        }
        "/routing/static/route/nexthop/distance" => {
            routing_static_route_nexthop_distance(rib, args, op);
        }
        "/routing/static/route/nexthop/weight" => {
            routing_static_route_nexthop_weight(rib, args, op);
        }
        _ => {
            println!("route");
        }
    }

    // if path == "/routing/static/route" {
    //     println!("static add");
    //     static_route(rib, args.clone(), op.clone()).await;
    // }
    // if path == "/routing/static/route/nexthop" {
    //     println!("static add nexthop");
    //     static_route_nexthop(rib, args.clone(), op.clone()).await;
    // }
    // if let Some(f) = rib.callbacks.get(&path) {
    //     f(self, args, msg.op);
    // }
}

async fn static_route(_rib: &mut Rib, args: Args, op: ConfigOp) {
    if op == ConfigOp::Set && !args.is_empty() {
        // let asn_str = &args[0];
        // bgp.asn = asn_str.parse().unwrap();
    }
}

async fn static_route_nexthop(rib: &mut Rib, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set && args.len() > 1 {
        let dest: Ipv4Net = args.v4net()?;
        let gateway: Ipv4Addr = args.v4addr()?;

        println!("addr {} nexthop {}", dest, gateway);

        let mut entry = RibEntry::new(RibType::Static);
        entry.distance = 1;
        let mut nexthop = Nexthop::builder().addr(gateway).build();
        let found = resolve(rib, &mut nexthop);
        if let Some(ifc) = found {
            println!("XX Found {}", ifc.link_index);
        } else {
            println!("XX Not Found");
        }
        entry.nexthops.push(nexthop);
        // entry.gateway = IpAddr::V4(gateway);
        // XXX rib.rib.insert(dest, entry);

        rib.ipv4_add(dest, entry.clone());
        rib.ipv4_add(dest, entry);

        rib.fib_handle.route_ipv4_add(dest, gateway).await;
        // if let Some(handle) = rib.handle.as_ref() {
        //     route_add(handle.clone(), dest, gateway).await;
        // }
    }
    Some(())
}

trait Ipv4AddrEx {
    fn to_prefix(&self) -> Ipv4Net;
}

impl Ipv4AddrEx for Ipv4Addr {
    fn to_prefix(&self) -> Ipv4Net {
        Ipv4Net::new(*self, Ipv4Addr::BITS as u8).unwrap()
    }
}

fn resolve<'a>(rib: &'a Rib, nexthop: &'a mut Nexthop) -> Option<&'a RibEntry> {
    let Some(addr) = nexthop.addr else {
        return None;
    };
    let addr = addr.to_prefix();
    let (_, entry) = rib.rib.get_lpm(&addr)?;
    for e in entry.ribs.iter() {
        if e.rtype == RibType::Connected {
            return Some(e);
        }
    }
    None
}
