use handlebars::Handlebars;

use super::handler::{Bgp, ShowCallback};
use super::peer::Peer;
use crate::config::Args;
use std::collections::HashMap;
use std::fmt::Write;

fn show_peer_summary(buf: &mut String, peer: &Peer) {
    let tx: u64 = peer.counter.tx.iter().sum();
    let rx: u64 = peer.counter.rx.iter().sum();
    writeln!(
        buf,
        "{:16} {:11} {:8} {:8}",
        peer.address, peer.peer_as, rx, tx,
    )
    .unwrap();
}

fn show_bgp_instance(bgp: &Bgp) -> String {
    let mut buf = String::new();
    let asn = if bgp.asn == 0 {
        "Not Configured".to_string()
    } else {
        bgp.asn.to_string()
    };
    let identifier = if bgp.router_id.is_unspecified() {
        "Not Configured".to_string()
    } else {
        bgp.router_id.to_string()
    };
    writeln!(
        buf,
        "BGP router identifier {}, local AS number {}",
        identifier, asn
    )
    .unwrap();
    writeln!(buf).unwrap();

    if bgp.peers.is_empty() {
        writeln!(buf, "No neighbor has been configured").unwrap();
    } else {
        writeln!(
            buf,
            "Neighbor                  AS  MsgRcvd  MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd"
        )
        .unwrap();
        for (_, peer) in bgp.peers.iter() {
            show_peer_summary(&mut buf, peer);
        }
    }

    buf
}

static SHOW_BGP_HEADER: &str = r#"Status codes:  s suppressed, d damped, h history, u unsorted,
               * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete
RPKI validation codes: V valid, I invalid, N Not found

     Network          Next Hop            Metric LocPrf Weight Path
"#;

fn show_bgp_route(bgp: &Bgp) -> String {
    let mut buf = String::new();

    buf.push_str(SHOW_BGP_HEADER);

    for (key, _value) in bgp.ptree.iter() {
        writeln!(buf, "{}", key).unwrap();
    }
    buf
}

fn show_bgp(bgp: &Bgp, args: Args) -> String {
    if args.is_empty() {
        show_bgp_route(bgp)
    } else {
        show_bgp_instance(bgp)
    }
}

use serde::Serialize;

#[derive(Serialize, Debug)]
struct Neighbor {
    name: String,
}

fn show_bgp_neighbor(bgp: &Bgp, args: Args) -> String {
    let neighbor = Neighbor {
        name: "neighbor".to_string(),
    };
    let serialized: String = serde_json::to_string(&neighbor).unwrap();
    println!("S: {}", serialized);

    let var_name = Handlebars::new();
    let mut handlebars = var_name;
    let source = "Hello {{ name }}";
    handlebars
        .register_template_string("hello", source)
        .unwrap();

    let mut data = HashMap::new();
    data.insert("name", "Rust");

    handlebars.render("hello", &data).unwrap()
}

impl Bgp {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/bgp", show_bgp);
        self.show_add("/show/ip/bgp/summary", show_bgp);
        self.show_add("/show/ip/bgp/neighbor", show_bgp_neighbor);
    }
}
