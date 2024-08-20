use super::message::{FibAddr, FibLink, FibMessage, FibRoute};
use crate::rib::link;
use anyhow::Result;
use ioctl_rs::SIOCGIFMTU;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use net_route::Route;
use nix::ifaddrs::getifaddrs;
use nix::libc::{ioctl, socket, AF_INET, IFNAMSIZ, SOCK_DGRAM};
use nix::net::if_::if_nametoindex;
use nix::net::if_::InterfaceFlags;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::UnboundedSender;

pub struct FibHandle {
    h: net_route::Handle,
}

impl FibHandle {
    pub fn new(_rib_tx: UnboundedSender<FibMessage>) -> Result<Self> {
        let h = net_route::Handle::new()?;
        Ok(Self { h })
    }

    pub async fn route_ipv4_add(&self, dest: Ipv4Net, gateway: Ipv4Addr) {
        let route = Route::new(IpAddr::V4(dest.addr()), dest.prefix_len())
            .with_gateway(IpAddr::V4(gateway));
        self.h.add(&route).await.unwrap();
    }

    #[allow(dead_code)]
    pub async fn route_ipv4_del(&self, dest: Ipv4Net, gateway: Ipv4Addr) {
        let route = Route::new(IpAddr::V4(dest.addr()), dest.prefix_len())
            .with_gateway(IpAddr::V4(gateway));
        self.h.delete(&route).await.unwrap();
    }
}

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

fn os_mtu(link_name: &String) -> u32 {
    let mut mtu = 0u32;

    if link_name.len() >= IFNAMSIZ {
        return 0u32;
    }

    let mut ifreq: nix::libc::ifreq = unsafe { std::mem::zeroed() };

    let name_str = CString::new(link_name.as_bytes()).unwrap();
    let name_bytes = name_str.as_bytes();
    unsafe {
        ifreq.ifr_name[..name_bytes.len()]
            .copy_from_slice(std::mem::transmute::<&[u8], &[i8]>(name_bytes));
    }

    unsafe {
        let s = socket(AF_INET, SOCK_DGRAM, 0);
        let ret = ioctl(s, SIOCGIFMTU, &ifreq);
        if ret == 0 {
            mtu = ifreq.ifr_ifru.ifru_mtu as u32;
        }
    }
    mtu
}

fn os_dump(tx: UnboundedSender<FibMessage>) {
    // Local cache for FibLink.
    let mut links: BTreeMap<u32, FibLink> = BTreeMap::new();

    let addrs = getifaddrs().unwrap();
    for ifa in addrs {
        let index = if_nametoindex(ifa.interface_name.as_str());
        if let Ok(index) = index {
            if let std::collections::btree_map::Entry::Vacant(e) = links.entry(index) {
                let mut link = FibLink::new();
                link.name.clone_from(&ifa.interface_name);
                link.index = index;
                link.flags = os_link_flags(ifa.flags);
                if (link.flags.0 & link::IFF_LOOPBACK) == link::IFF_LOOPBACK {
                    link.link_type = link::LinkType::Loopback;
                }
                link.mtu = os_mtu(&link.name);

                let msg = FibMessage::NewLink(link.clone());
                tx.send(msg).unwrap();
                e.insert(link);
            }
            // if !links.contains_key(&index) {
            //     let mut link = FibLink::new();
            //     link.name.clone_from(&ifa.interface_name);
            //     link.index = index;
            //     link.flags = os_link_flags(ifa.flags);
            //     if (link.flags.0 & link::IFF_LOOPBACK) == link::IFF_LOOPBACK {
            //         link.link_type = link::LinkType::Loopback;
            //     }
            //     link.mtu = os_mtu(&link.name);

            //     let msg = FibMessage::NewLink(link.clone());
            //     tx.send(msg).unwrap();
            //     links.insert(index, link);
            // }
            if let Some(addr) = ifa.address {
                if let Some(addr) = addr.as_sockaddr_in() {
                    let addr = Ipv4Addr::from(addr.as_ref().sin_addr.s_addr.to_be());
                    if let Some(mask) = ifa.netmask {
                        if let Some(mask) = mask.as_sockaddr_in() {
                            let prefixlen = mask.as_ref().sin_addr.s_addr.count_ones();
                            let ipv4net = Ipv4Net::new(addr, prefixlen as u8).unwrap();
                            let osaddr = FibAddr {
                                addr: IpNet::V4(ipv4net),
                                link_index: index,
                                secondary: false,
                            };
                            let msg = FibMessage::NewAddr(osaddr);
                            tx.send(msg).unwrap();
                        }
                    }
                }
                if let Some(addr) = addr.as_sockaddr_in6() {
                    let addr = Ipv6Addr::from(addr.as_ref().sin6_addr.s6_addr);
                    if let Some(mask) = ifa.netmask {
                        if let Some(mask) = mask.as_sockaddr_in6() {
                            let mask = Ipv6Addr::from(mask.as_ref().sin6_addr.s6_addr);
                            let prefixlen: u32 =
                                mask.octets().iter().map(|byte| byte.count_ones()).sum();
                            let ipv6net = Ipv6Net::new(addr, prefixlen as u8).unwrap();
                            let osaddr = FibAddr {
                                addr: IpNet::V6(ipv6net),
                                link_index: index,
                                secondary: false,
                            };
                            let msg = FibMessage::NewAddr(osaddr);
                            tx.send(msg).unwrap();
                        }
                    }
                }
                if let Some(_addr) = addr.as_link_addr() {
                    // println!("LL:{:?}", addr);
                }
            }
        }
    }
}

async fn os_route_dump(tx: UnboundedSender<FibMessage>) {
    let handle = net_route::Handle::new();
    if let Ok(handle) = handle {
        let routes = handle.list().await;
        if let Ok(routes) = routes {
            for route in routes {
                if let IpAddr::V4(v4) = route.destination {
                    if let Some(gateway) = route.gateway {
                        let v4net = Ipv4Net::new(v4, route.prefix).unwrap();
                        let osroute = FibRoute {
                            route: IpNet::V4(v4net),
                            gateway,
                        };
                        let msg = FibMessage::NewRoute(osroute);
                        tx.send(msg).unwrap();
                    }
                }
            }
        }
    }
}

pub async fn fib_dump(_handle: &FibHandle, tx: UnboundedSender<FibMessage>) -> std::io::Result<()> {
    os_dump(tx.clone());
    os_route_dump(tx.clone()).await;

    Ok(())
}

pub fn os_traffic_dump() -> impl Fn(&String, &mut String) {
    move |_link_name: &String, _buf: &mut String| {}
}
