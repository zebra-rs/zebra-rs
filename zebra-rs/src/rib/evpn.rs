//! EVPN Type-2 ownership. MAC-only, IPv4 and IPv6 NLRIs have independent
//! lifetimes; removing one must not remove a MAC another still references.
use super::{MacAddr, Rib};
use std::net::{IpAddr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MacRouteKey {
    pub vni: u32,
    pub mac: MacAddr,
    pub rd: [u8; 8],
    pub ip: Option<IpAddr>,
}

impl MacRouteKey {
    pub fn new(
        rd: bgp_packet::RouteDistinguisher,
        vni: u32,
        mac: MacAddr,
        ip: Option<IpAddr>,
    ) -> Self {
        let mut bytes = [0; 8];
        bytes[..2].copy_from_slice(&(rd.typ as u16).to_be_bytes());
        bytes[2..].copy_from_slice(&rd.val);
        Self {
            rd: bytes,
            vni,
            mac,
            ip,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MacRoute {
    pub key: MacRouteKey,
    pub tunnel_endpoint: Option<IpAddr>,
    pub flags: u8,
    pub seq: u32,
    pub esi: Option<[u8; 10]>,
    pub srv6_sid: Option<Ipv6Addr>,
    pub mpls_label: Option<u32>,
    pub local_port: Option<String>,
}

impl Rib {
    pub(super) async fn reconcile_evpn_mac(&mut self, vni: u32, mac: MacAddr) {
        let lo = MacRouteKey {
            vni,
            mac,
            rd: [0; 8],
            ip: None,
        };
        let hi = MacRouteKey {
            vni,
            mac,
            rd: [255; 8],
            ip: Some(Ipv6Addr::from(u128::MAX).into()),
        };
        let mut routes: Vec<_> = self
            .evpn_mac_routes
            .range(lo..=hi)
            .map(|(_, route)| route.clone())
            .collect();
        routes.sort_by_key(|route| std::cmp::Reverse(route.seq));
        let Some(winner) = routes.first() else {
            self.mac_del(vni, mac).await;
            return;
        };
        if self.local_device_mac_bridge(vni, mac).is_some() {
            return;
        }
        let seq = winner.seq;
        let esi = winner.esi.filter(|esi| *esi != [0; 10]);
        self.mac_table.remove(&(vni, mac));
        for route in routes
            .iter()
            .filter(|route| route.seq == seq || (esi.is_some() && route.esi == esi))
        {
            self.mac_add(
                vni,
                mac,
                route.tunnel_endpoint,
                route.flags,
                route.seq,
                route.esi,
                route.srv6_sid,
                route.mpls_label,
                route.local_port.clone(),
            )
            .await;
            if let Some(ip) = route.key.ip
                && route.srv6_sid.is_none()
                && route.mpls_label.is_none()
                && !self.fib_handle.cradle_active()
            {
                self.fib_handle.evpn_neighbor(vni, ip, mac, true).await;
            }
        }
    }
}
