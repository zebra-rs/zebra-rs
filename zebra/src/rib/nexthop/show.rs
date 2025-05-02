use std::fmt::Write;

use crate::rib::nexthop::group::GroupTrait;
use crate::{config::Args, rib::Rib};

use super::Group;

fn write_group_detail(buf: &mut String, grp: &Group) {
    writeln!(
        buf,
        "ID: {} refcnt: {} valid: {} installed: {}",
        grp.gid(),
        grp.refcnt(),
        grp.is_valid(),
        grp.is_installed(),
    )
    .unwrap();
}

pub fn nexthop_show(rib: &Rib, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for grp in rib.nmap.groups.iter().flatten() {
        write_group_detail(&mut buf, grp);
        match grp {
            Group::Uni(uni) => {
                writeln!(buf, "  via {}, {}", uni.addr, rib.link_name(uni.ifindex)).unwrap();
            }
            Group::Multi(multi) => {
                for (gid, weight) in multi.set.iter() {
                    if let Some(Group::Uni(uni)) = rib.nmap.get(*gid) {
                        writeln!(
                            buf,
                            "  [{}] via {}, {}, weight: {}",
                            gid,
                            uni.addr,
                            rib.link_name(uni.ifindex),
                            weight
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
    buf
}
