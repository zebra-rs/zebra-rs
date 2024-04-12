use super::message::{OsLink, OsMessage};
use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use std::collections::BTreeMap;
use tokio::sync::mpsc::UnboundedSender;

fn os_dump(tx: UnboundedSender<OsMessage>) {
    let mut links: BTreeMap<u32, OsLink> = BTreeMap::new();

    let addrs = getifaddrs().unwrap();
    for ifaddr in addrs {
        let index = if_nametoindex(ifaddr.interface_name.as_str());
        if let Ok(index) = index {
            if links.get(&index).is_none() {
                let mut link = OsLink::new();
                link.name = ifaddr.interface_name.clone();
                link.index = index;
                let msg = OsMessage::NewLink(link.clone());
                tx.send(msg).unwrap();
                links.insert(index, link);
            }
            //
        }
        match ifaddr.address {
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
