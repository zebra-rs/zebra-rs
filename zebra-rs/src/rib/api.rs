use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::{BulkPhase, Link, MacAddr, Rib, RibType, RouteBatch, link::LinkAddr};

/// One nexthop entry inside a `FlexAlgoRoute`. Flattens the IS-IS
/// internal `SpfNexthop` to the public-API minimum: the IPv4 next-hop
/// address, the egress ifindex, and the outer MPLS label to push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlexAlgoNexthop {
    pub addr: Ipv4Addr,
    pub ifindex: u32,
    /// Outer MPLS label = the route origin's SRGB.start + the algo-N
    /// Prefix-SID index. The receiver of this struct (Color-aware
    /// nexthop resolver) pushes this label as the outermost LSP
    /// segment when forwarding a service route into the Flex-Algo
    /// path.
    pub label: u32,
}

/// Per-algorithm IPv4 route snapshot published from IS-IS (RFC 9350)
/// to RIB. Carries only the fields downstream consumers need —
/// IS-IS internals (`dest_vertex`, TI-LFA backup, raw `SidLabelValue`)
/// stay in the IS-IS module.
///
/// `algo` is the IS-IS Flex-Algorithm id (128..=255). The same
/// `(algo, prefix)` pair may arrive multiple times across IS-IS SPF
/// cycles; each arrival replaces the previous snapshot for that key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlexAlgoRoute {
    pub algo: u8,
    pub prefix: Ipv4Net,
    pub metric: u32,
    pub nexthops: Vec<FlexAlgoNexthop>,
}

/// One bridge-FDB row, distilled from the larger `FibNeighbor` so
/// subscribers don't need to drag the full address-family / state
/// surface around. Sent on `Rib::neighbors` insert / remove for
/// AF_BRIDGE entries whose master maps to a known VNI.
///
/// `flags` carries the kernel's `NTF_*` bits — most importantly
/// `NTF_EXT_LEARNED` (bit 0x10), which an EVPN advertise consumer
/// must check to avoid re-advertising MACs that this same daemon
/// just installed from a remote peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdbEntry {
    pub vni: u32,
    pub mac: MacAddr,
    pub ifindex: u32,
    pub bridge_ifindex: u32,
    pub flags: u8,
    /// Local VTEP source IP — the `local` address configured on the
    /// VXLAN slave of `bridge_ifindex` (`IFLA_VXLAN_LOCAL` /
    /// `IFLA_VXLAN_LOCAL6`). The EVPN advertise path uses this as
    /// the BGP MP_REACH nexthop per RFC 8365 §5.1.3 — that's the IP
    /// remote peers will encapsulate VXLAN packets to. None when the
    /// VXLAN was created without an explicit `local` (kernel uses
    /// 0.0.0.0 / :: in that case); callers fall back to router-id.
    pub vxlan_local: Option<IpAddr>,
}

#[allow(dead_code)]
pub struct RibRxChannel {
    pub tx: UnboundedSender<RibRx>,
    pub rx: UnboundedReceiver<RibRx>,
}

impl RibRxChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

// Message from rib to protocol module.
#[derive(Debug, PartialEq)]
pub enum RibRx {
    LinkAdd(Link),
    LinkUp(u32),
    LinkDown(u32),
    AddrAdd(LinkAddr),
    AddrDel(LinkAddr),
    RouterIdUpdate(Ipv4Addr),
    /// Bridge FDB entry just learned (or installed) on this host —
    /// emitted by RIB when a `FibMessage::NewNeighbor` for an
    /// AF_BRIDGE entry resolves to a known VNI. The EVPN advertise
    /// path consumes this to originate Type-2 routes.
    FdbAdd(FdbEntry),
    /// Inverse of `FdbAdd` — emitted on `FibMessage::DelNeighbor`.
    FdbDel(FdbEntry),
    /// Local VXLAN device with `IFLA_VXLAN_LOCAL` set. Emitted by
    /// RIB when a VXLAN slave is registered (`register_vxlan_ifindex`
    /// path in `link_add`) and replayed at subscribe time. The EVPN
    /// advertise path uses it to originate one Type-3 (Inclusive
    /// Multicast) route per local VTEP×VNI pair.
    VxlanAdd {
        vni: u32,
        vtep_local: IpAddr,
    },
    /// Inverse of `VxlanAdd` — emitted when the VXLAN device is
    /// removed or its VNI changes.
    VxlanDel {
        vni: u32,
    },
    /// A Linux VRF master device the operator has committed. Emitted
    /// when [`crate::rib::inst::Message::VrfAdd`] has allocated a
    /// `table_id` and the netlink-side `ip link add` succeeded; also
    /// replayed at subscribe time so a late-subscribing protocol
    /// (e.g. BGP spawning after VRFs were configured at startup)
    /// catches the running set. Step 15 introduces this so the global
    /// BGP runtime can lift `BgpVrf` from the step-14 placeholder
    /// `ProtoContext::default_table_no_rib` to a real
    /// `ProtoContext::for_vrf(rib, table_id, name)` once the kernel
    /// has acknowledged the VRF master.
    VrfAdd {
        name: String,
        table_id: u32,
        ifindex: u32,
    },
    /// Inverse of [`Self::VrfAdd`] — the VRF master has been torn
    /// down.
    VrfDel {
        name: String,
    },
    EoR,

    // ---- redistribute route push ---------------------------------
    //
    // Per-filter-row delivery of routes matched by a subscriber's
    // `RedistAdd` / `RedistUpdate`. `rtype` is at the message level
    // (every entry in a batch shares it by construction); `subtype`
    // is per-entry inside `RouteEntryV4`/`V6` so a wildcard
    // subscription replays in a single pass with one final EoR
    // instead of N walks and N EoRs. Self-route filtering is
    // enforced by RIB before send — a subscriber whose proto maps
    // to `rtype` will never see a RouteAdd of that rtype.
    #[allow(dead_code)]
    RouteAdd {
        rtype: RibType,
        routes: RouteBatch,
        bulk: BulkPhase,
    },
    #[allow(dead_code)]
    RouteDel {
        rtype: RibType,
        routes: RouteBatch,
        bulk: BulkPhase,
    },

    // ---- IS-IS Flex-Algorithm route fan-out -----------------------
    //
    // Phase 3 of the BGP ↔ IS-IS Flex-Algorithm integration: IS-IS
    // publishes per-algo route snapshots to RIB via
    // `Message::FlexAlgoRouteAdd/Del`; RIB shadows them in
    // `flex_algo_routes` and re-broadcasts via the two RibRx variants
    // below. The colour-aware nexthop resolver (next PR) is the first
    // consumer; today the fan-out lands on every subscribed protocol
    // and they ignore it.
    #[allow(dead_code)]
    FlexAlgoRouteAdd {
        route: FlexAlgoRoute,
    },
    #[allow(dead_code)]
    FlexAlgoRouteDel {
        algo: u8,
        prefix: Ipv4Net,
    },
}

impl Rib {
    /// Resolve a link's VRF id (kernel `rtm_table` value) by
    /// matching its `master` field against the ifindex of each
    /// known VRF master. Returns `0` for top-level links and for
    /// slaves of non-VRF masters (e.g. bridges) — both equate to
    /// the default routing table.
    fn link_vrf_id(&self, link: &Link) -> u32 {
        let Some(master) = link.master else {
            return 0;
        };
        self.vrfs
            .values()
            .find(|v| v.ifindex == master)
            .map(|v| v.table_id)
            .unwrap_or(0)
    }

    /// Resolve the VRF id for a link looked up by ifindex. Returns
    /// `0` when the ifindex is unknown — fail-safe to default-VRF,
    /// matching the inbound dispatcher's behaviour for ghost
    /// `ProtoId`s.
    fn ifindex_vrf_id(&self, ifindex: u32) -> u32 {
        self.links
            .get(&ifindex)
            .map(|l| self.link_vrf_id(l))
            .unwrap_or(0)
    }

    /// Push `LinkAdd` only to subscribers bound to this link's VRF.
    pub fn api_link_add(&self, link: &Link) {
        let vrf_id = self.link_vrf_id(link);
        for (_, sub) in self.client_registry.iter_vrf(vrf_id) {
            let _ = sub.rib_rx_tx.send(RibRx::LinkAdd(link.clone()));
        }
    }

    pub fn api_link_up(&self, ifindex: u32) {
        let vrf_id = self.ifindex_vrf_id(ifindex);
        for (_, sub) in self.client_registry.iter_vrf(vrf_id) {
            let _ = sub.rib_rx_tx.send(RibRx::LinkUp(ifindex));
        }
    }

    pub fn api_link_down(&self, ifindex: u32) {
        let vrf_id = self.ifindex_vrf_id(ifindex);
        for (_, sub) in self.client_registry.iter_vrf(vrf_id) {
            let _ = sub.rib_rx_tx.send(RibRx::LinkDown(ifindex));
        }
    }

    pub fn api_addr_add(&self, addr: &LinkAddr) {
        let vrf_id = self.ifindex_vrf_id(addr.ifindex);
        for (_, sub) in self.client_registry.iter_vrf(vrf_id) {
            let _ = sub.rib_rx_tx.send(RibRx::AddrAdd(addr.clone()));
        }
    }

    pub fn api_addr_del(&self, addr: &LinkAddr) {
        let vrf_id = self.ifindex_vrf_id(addr.ifindex);
        for (_, sub) in self.client_registry.iter_vrf(vrf_id) {
            let _ = sub.rib_rx_tx.send(RibRx::AddrDel(addr.clone()));
        }
    }

    /// Router id is daemon-global today (one IPv4 address per
    /// instance), so this push always targets default-VRF
    /// subscribers. Per-VRF router-id arrives with the BGP-per-VRF
    /// config in step 12 and will gain its own emit path.
    pub fn api_router_id_update(&self, router_id: Ipv4Addr) {
        for (_, sub) in self.client_registry.iter_vrf(0) {
            let _ = sub.rib_rx_tx.send(RibRx::RouterIdUpdate(router_id));
        }
    }

    /// FDB / VXLAN events are EVPN-specific and today flow to every
    /// subscriber regardless of VRF — EVPN consumers (BGP) run as a
    /// single instance and need the full view. Per-VRF EVPN will
    /// pick up a filter here when step 13+ introduces multi-instance
    /// BGP.
    pub fn api_fdb_add(&self, entry: &FdbEntry) {
        for (_, sub) in self.client_registry.iter() {
            let _ = sub.rib_rx_tx.send(RibRx::FdbAdd(entry.clone()));
        }
    }

    pub fn api_fdb_del(&self, entry: &FdbEntry) {
        for (_, sub) in self.client_registry.iter() {
            let _ = sub.rib_rx_tx.send(RibRx::FdbDel(entry.clone()));
        }
    }

    pub fn api_vxlan_add(&self, vni: u32, vtep_local: IpAddr) {
        for (_, sub) in self.client_registry.iter() {
            let _ = sub.rib_rx_tx.send(RibRx::VxlanAdd { vni, vtep_local });
        }
    }

    /// Announce a Linux VRF master device. Only default-VRF
    /// subscribers see this — per-VRF subscribers, once they exist,
    /// don't need cross-VRF visibility (they only care about their
    /// own kernel context, which is implicit in the
    /// `ProtoContext::for_vrf` they were spawned with).
    pub fn api_vrf_add(&self, vrf: &crate::rib::vrf::Vrf) {
        for (_, sub) in self.client_registry.iter_vrf(0) {
            let _ = sub.rib_rx_tx.send(RibRx::VrfAdd {
                name: vrf.name.clone(),
                table_id: vrf.table_id,
                ifindex: vrf.ifindex,
            });
        }
    }

    pub fn api_vrf_del(&self, name: &str) {
        for (_, sub) in self.client_registry.iter_vrf(0) {
            let _ = sub.rib_rx_tx.send(RibRx::VrfDel {
                name: name.to_string(),
            });
        }
    }

    pub fn api_vxlan_del(&self, vni: u32) {
        for (_, sub) in self.client_registry.iter() {
            let _ = sub.rib_rx_tx.send(RibRx::VxlanDel { vni });
        }
    }

    /// Fan-out a Flex-Algorithm route add to every default-VRF
    /// subscriber. Per-algo routes are global today — IS-IS runs as a
    /// single instance and the colour-aware nexthop resolver (BGP)
    /// resolves against the default-VRF table. When per-VRF flex-algo
    /// arrives a vrf_id filter slots in here.
    pub fn api_flex_algo_route_add(&self, route: &FlexAlgoRoute) {
        for (_, sub) in self.client_registry.iter_vrf(0) {
            let _ = sub.rib_rx_tx.send(RibRx::FlexAlgoRouteAdd {
                route: route.clone(),
            });
        }
    }

    pub fn api_flex_algo_route_del(&self, algo: u8, prefix: Ipv4Net) {
        for (_, sub) in self.client_registry.iter_vrf(0) {
            let _ = sub.rib_rx_tx.send(RibRx::FlexAlgoRouteDel { algo, prefix });
        }
    }
}
