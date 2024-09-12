use super::{
    entry::{RibEntry, RibType},
    instance::Rib,
};
use crate::config::{Args, ConfigOp};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};

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

async fn static_route_nexthop(rib: &mut Rib, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set && args.len() > 1 {
        let dest: Ipv4Net = args.v4net()?;
        let gateway: Ipv4Addr = args.v4addr()?;

        println!("addr {} nexthop {}", dest, gateway);

        let mut entry = RibEntry::new(RibType::Static);
        entry.gateway = IpAddr::V4(gateway);
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
