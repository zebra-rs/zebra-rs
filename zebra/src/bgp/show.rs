use crate::config::Args;

use super::handler::{Bgp, ShowCallback};
use super::peer::Peer;
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
    writeln!(buf, "").unwrap();

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

fn show_bgp_route(_bgp: &Bgp) -> String {
    let mut buf = String::new();
    buf
}

fn show_bgp(bgp: &Bgp, args: Args) -> String {
    if args.is_empty() {
        show_bgp_route(bgp)
    } else {
        show_bgp_instance(bgp)
    }
}

impl Bgp {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/bgp", show_bgp);
    }
}
