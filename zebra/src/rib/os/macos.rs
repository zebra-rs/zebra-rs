use super::message::{OsAddress, OsLink, OsMessage, OsRoute};
use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use tokio::sync::mpsc::UnboundedSender;

fn os_dump(tx: UnboundedSender<OsMessage>) {
    let addrs = getifaddrs().unwrap();
    for ifaddr in addrs {
        match ifaddr.address {
            Some(address) => {
                println!("interface {} address {}", ifaddr.interface_name, address);
                let ifindex = if_nametoindex(ifaddr.interface_name.as_str());
                println!("ifindex {:?}", ifindex);
            }
            None => {
                println!(
                    "interface {} with unsupported address family",
                    ifaddr.interface_name
                );
            }
        }
    }
}

pub async fn spawn_os_dump(tx: UnboundedSender<OsMessage>) -> std::io::Result<()> {
    os_dump(tx);

    Ok(())
}
