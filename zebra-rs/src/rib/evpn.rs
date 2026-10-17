//! EVPN Type-2 ownership. MAC-only, IPv4 and IPv6 NLRIs have independent
//! lifetimes; removing one must not remove a MAC another still references.
use super::{MacAddr, Rib};
use std::net::{IpAddr, Ipv6Addr};

/// `MacRoute::flags` / `MacEntry::flags` bit: a sticky (static) MAC, the
/// sticky flag of the RFC 7432 §7.7 MAC Mobility community. It must not
/// move: it wins over any sequence number (§15.2), and the kernel bridge
/// row is installed static and sticky.
pub const MAC_FLAG_STICKY: u8 = 0x01;

/// `MacRoute::flags` / `MacEntry::flags` bit: EVPN E-Tree (RFC 8317 §4.1),
/// the MAC is behind a leaf AC on its PE — its selected Type-2 carries the
/// E-Tree EC with the Leaf-Indication flag. The cradle tee hands it to the
/// datapath as `FdbRemote.etree_leaf`. Bits 0x02-0x08 are gateway, router
/// and (shown, never set) sync.
pub const MAC_FLAG_ETREE_LEAF: u8 = 0x10;

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

impl MacRoute {
    /// The PE that advertised the route. The RD alone does not tell PEs
    /// apart: an operator may configure the same RD on every PE.
    fn originator(&self) -> ([u8; 8], Option<IpAddr>) {
        (self.key.rd, self.tunnel_endpoint)
    }
}

impl Rib {
    /// Point the kernel neighbor for `(vni, ip)` at the winning remote
    /// binding (highest mobility sequence). Called after a binding for the
    /// IP is added or withdrawn, so an IP that moved between MACs follows
    /// the live route rather than the last one processed.
    pub(super) async fn reassert_evpn_ip(&mut self, vni: u32, ip: IpAddr) {
        let Some(keys) = self.evpn_ip_refs.get(&(vni, ip)) else {
            return;
        };
        let Some(winner) = keys
            .iter()
            .filter_map(|key| self.evpn_mac_routes.get(key))
            .max_by_key(|route| route.seq)
        else {
            return;
        };
        if winner.srv6_sid.is_some()
            || winner.mpls_label.is_some()
            || self.fib_handle.cradle_active()
            || self.local_device_mac_bridge(vni, winner.key.mac).is_some()
        {
            return;
        }
        let mac = winner.key.mac;
        self.fib_handle.evpn_neighbor(vni, ip, mac, true).await;
    }

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
        // FRR sets the sticky flag on the MAC-only route of a sticky MAC and
        // sends its MAC+IP routes without a MAC Mobility community. Carry
        // the flag to every route of the same PE, so that neither the order
        // the routes are applied in nor which of them carries the highest
        // sequence number decides whether the MAC is sticky.
        let sticky: Vec<_> = routes
            .iter()
            .filter(|route| route.flags & MAC_FLAG_STICKY != 0)
            .map(MacRoute::originator)
            .collect();
        for route in &mut routes {
            if sticky.contains(&route.originator()) {
                route.flags |= MAC_FLAG_STICKY;
            }
        }
        // RFC 7432 §15.2: a sticky MAC is advertised with sequence number
        // zero and must not move, so it wins over any sequence number from
        // another PE, as in FRR's best-path selection and in
        // `evpn_local_path_wins` against this node's own route.
        if !sticky.is_empty() {
            routes.retain(|route| route.flags & MAC_FLAG_STICKY != 0);
        }
        routes.sort_by_key(|route| std::cmp::Reverse(route.seq));
        let Some(winner) = routes.first() else {
            self.mac_del(vni, mac).await;
            return;
        };
        // Refused before `mac_record` (which refuses the same way), so say so
        // here: the log line is how an operator sees a peer advertising one
        // of this node's own addresses.
        if let Some(bridge) = self.local_device_mac_bridge(vni, mac) {
            tracing::warn!(
                "mac_add: VNI {vni} mac {mac} is a local address on bridge ifindex {bridge}; \
                 ignoring the remote EVPN route for it"
            );
            return;
        }
        let seq = winner.seq;
        let esi = winner.esi.filter(|esi| *esi != [0; 10]);
        let previous = self.mac_table.remove(&(vni, mac));
        let winners: Vec<&MacRoute> = routes
            .iter()
            .filter(|route| route.seq == seq || (esi.is_some() && route.esi == esi))
            .collect();
        for route in &winners {
            self.mac_record(
                vni,
                mac,
                route.tunnel_endpoint,
                route.flags,
                route.seq,
                route.esi,
                route.srv6_sid,
                route.mpls_label,
                route.local_port.clone(),
            );
        }
        self.mac_reprogram(vni, mac, previous).await;
        for route in winners {
            if let Some(ip) = route.key.ip
                && route.srv6_sid.is_none()
                && route.mpls_label.is_none()
                && !self.fib_handle.cradle_active()
            {
                // Reconciliation can touch IPs other than the incoming
                // NLRI's IP. Each one must follow its winning binding
                // across all MACs, rather than the MAC being reconciled.
                self.reassert_evpn_ip(vni, ip).await;
            }
        }
    }
}
