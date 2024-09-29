use super::{
    entry::{RibEntry, RibType},
    instance::Rib,
};
use crate::{
    config::{Args, ConfigOp},
    rib::nexthop::Nexthop,
};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

pub async fn config_dispatch(rib: &mut Rib, path: String, args: Args, op: ConfigOp) {
    if path == "/routing/static/route" {
        println!("static add");
        static_route(rib, args.clone(), op.clone()).await;
    }
    if path == "/routing/static/route/nexthop" {
        println!("static add nexthop");
        static_route_nexthop(rib, args.clone(), op.clone()).await;
    }
    // if let Some(f) = self.callbacks.get(&path) {
    //     f(self, args, msg.op);
    // }
}

async fn static_route(_rib: &mut Rib, args: Args, op: ConfigOp) {
    if op == ConfigOp::Set && !args.is_empty() {
        // let asn_str = &args[0];
        // bgp.asn = asn_str.parse().unwrap();
    }
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
    for e in entry.iter() {
        if e.rtype == RibType::Connected {
            return Some(e);
        }
    }
    None
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
