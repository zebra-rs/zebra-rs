use super::message::{OsLink, OsMessage};
use crate::rib::link;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use std::collections::BTreeMap;
use tokio::sync::mpsc::UnboundedSender;

use nix::net::if_::InterfaceFlags;

fn os_link_flags(flags: InterfaceFlags) -> link::LinkFlags {
    let mut link_flags: u32 = 0u32;
    if (flags & InterfaceFlags::IFF_UP) == InterfaceFlags::IFF_UP {
        link_flags += link::IFF_UP;
    }
    if (flags & InterfaceFlags::IFF_BROADCAST) == InterfaceFlags::IFF_BROADCAST {
        link_flags += link::IFF_BROADCAST;
    }
    if (flags & InterfaceFlags::IFF_LOOPBACK) == InterfaceFlags::IFF_LOOPBACK {
        link_flags += link::IFF_LOOPBACK;
    }
    if (flags & InterfaceFlags::IFF_POINTOPOINT) == InterfaceFlags::IFF_POINTOPOINT {
        link_flags += link::IFF_POINTOPOINT;
    }
    if (flags & InterfaceFlags::IFF_RUNNING) == InterfaceFlags::IFF_RUNNING {
        link_flags += link::IFF_RUNNING;
    }
    if (flags & InterfaceFlags::IFF_PROMISC) == InterfaceFlags::IFF_PROMISC {
        link_flags += link::IFF_PROMISC;
    }
    if (flags & InterfaceFlags::IFF_MULTICAST) == InterfaceFlags::IFF_MULTICAST {
        link_flags += link::IFF_MULTICAST;
    }
    link::LinkFlags(link_flags)
}

fn os_dump(tx: UnboundedSender<OsMessage>) {
    let mut links: BTreeMap<u32, OsLink> = BTreeMap::new();

    let addrs = getifaddrs().unwrap();
    for ifa in addrs {
        let index = if_nametoindex(ifa.interface_name.as_str());
        if let Ok(index) = index {
            if links.get(&index).is_none() {
                let mut link = OsLink::new();
                link.name = ifa.interface_name.clone();
                link.index = index;
                link.flags = os_link_flags(ifa.flags);
                if (link.flags.0 & link::IFF_LOOPBACK) == link::IFF_LOOPBACK {
                    link.link_type = link::LinkType::Loopback;
                }

                let msg = OsMessage::NewLink(link.clone());
                tx.send(msg).unwrap();
                links.insert(index, link);
            }
            //
        }
        match ifa.address {
            Some(_address) => {
                //
            }
            None => {
                // Unknown address family.
            }
        }
    }
}

pub async fn os_dump_spawn(tx: UnboundedSender<OsMessage>) -> std::io::Result<()> {
    os_dump(tx);

    Ok(())
}

pub fn os_traffic_dump() -> impl Fn(&String, &mut String) {
    move |_link_name: &String, _buf: &mut String| {}
}
