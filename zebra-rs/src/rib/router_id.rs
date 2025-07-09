use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::Link;

fn router_id(links: &BTreeMap<u32, Link>) -> Option<Ipv4Addr> {
    // Helper function to find a router ID based on loopback status and if the link is up.
    fn find_router_id(links: &BTreeMap<u32, Link>, loopback: bool) -> Option<Ipv4Addr> {
        // links
        //     .values()
        //     .filter(|link| link.is_up() && link.is_loopback() == loopback) // Match loopback and check if up
        //     .flat_map(|link| &link.addrv4) // Flatten addrv4 field into an iterator
        //     .map(|laddr| laddr.ifaddr.addr()) // Extract Ipv4Addr
        //     .find(|&addr| addr != Ipv4Addr::LOCALHOST) // Find the first non-localhost address
        None
    }

    // Try to find a router ID from up loopback interfaces first, then fallback to up non-loopback interfaces.
    find_router_id(links, true).or_else(|| find_router_id(links, false))
}

fn router_id_update() {
    //
}
