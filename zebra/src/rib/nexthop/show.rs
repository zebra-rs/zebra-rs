use std::fmt::Write;

use crate::rib::nexthop::group::GroupTrait;
use crate::{config::Args, rib::Rib};

use super::Group;

pub fn nexthop_show(rib: &Rib, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for grp in rib.nmap.groups.iter() {
        if let Some(grp) = grp {
            match grp {
                Group::Uni(uni) => {
                    writeln!(buf, "ID: {} refcnt: {}", uni.gid(), uni.refcnt()).unwrap();
                    writeln!(
                        buf,
                        "  Nexthop: {} is_valid {} is_installed {}",
                        uni.addr,
                        uni.is_valid(),
                        uni.is_installed()
                    )
                    .unwrap();
                }
                Group::Multi(multi) => {
                    writeln!(
                        buf,
                        "ID: {} refcnt: {} is_valid {} is_installed {}",
                        multi.gid(),
                        multi.refcnt(),
                        multi.is_valid(),
                        multi.is_installed()
                    )
                    .unwrap();
                    for (gid, weight) in multi.set.iter() {
                        writeln!(buf, "  gid: {} weight: {}", gid, weight).unwrap();
                    }
                }
                _ => {}
            }
        }
    }
    buf
}
