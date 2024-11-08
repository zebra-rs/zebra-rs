use std::fmt::Write;

use crate::rib::nexthop::group::GroupTrait;
use crate::{config::Args, rib::Rib};

use super::GroupSet;

pub(crate) fn nexthop_show(rib: &Rib, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for grp in rib.nmap.groups.iter() {
        if let GroupSet::Uni(uni) = grp {
            writeln!(buf, "ID: {}", uni.gid()).unwrap();
            writeln!(buf, "  Nexthop: {}", uni.addr).unwrap();
        }
    }
    buf
}
