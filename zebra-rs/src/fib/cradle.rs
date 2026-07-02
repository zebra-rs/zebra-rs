//! Optional tee of FIB route installs into the **cradle** eBPF data plane.
//!
//! Enabled by the `system cradle-grpc <endpoint>` config leaf (or the
//! `CRADLE_GRPC` env var as a fallback). When set, the protocol routes the RIB
//! installs are also pushed to a running `cradle` via its gRPC control API, so
//! zebra-rs-computed routes (static, BGP, OSPF, IS-IS, …) program the eBPF FIB
//! in addition to the kernel. This is the zebra-rs side of the cradle-rs
//! integration.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use ipnet::{Ipv4Net, Ipv6Net};
use tokio::sync::Mutex;
use tonic::transport::Channel;

pub mod pb {
    tonic::include_proto!("cradle.v1");
}
use pb::cradle_client::CradleClient;

/// Mirrors `cradle_common::FIB_F_ECMP` (data-plane ABI; kept local so this file
/// has no dependency on the cradle crates).
const FIB_F_ECMP: u32 = 1 << 3;
/// Mirrors `cradle_common::MPLS_OP_*` — the ILM `action` values.
pub const MPLS_OP_SWAP: u32 = 0;
pub const MPLS_OP_POP_L3: u32 = 1;

/// Map a kernel routing-table id to cradle's VRF-table convention: 0 is
/// global, and so is RT_TABLE_MAIN (254) — connected routes arrive with it.
/// Any other value is the RIB-allocated VRF table id, which is byte-identical
/// to the `vrf_table_id` the DecapVrf ILM tee sends.
fn cradle_vrf(table_id: u32) -> u32 {
    match table_id {
        0 | 254 => 0,
        id => id,
    }
}

#[derive(Clone)]
pub struct CradleFib {
    endpoint: String,
    client: Arc<Mutex<Option<CradleClient<Channel>>>>,
    /// Dedup `(gateway, oif, out-label stack) -> nexthop id` so we
    /// `SetNexthop` once per distinct nexthop.
    nh_ids: Arc<Mutex<HashMap<(u32, u32, Vec<u32>), u32>>>,
    nh_ids6: Arc<Mutex<HashMap<([u8; 16], u32, Vec<u32>), u32>>>,
    next_id: Arc<AtomicU32>,
}

impl CradleFib {
    /// Build a tee to the cradle gRPC endpoint `ep`. `unix:/path` (UDS) and
    /// `http://...` pass through; a bare `host:port` is treated as TCP.
    pub fn new(ep: &str) -> Self {
        let endpoint = if ep.starts_with("unix:") || ep.starts_with("http") {
            ep.to_string()
        } else {
            format!("http://{ep}")
        };
        tracing::info!("fib: cradle eBPF tee enabled -> {endpoint}");
        Self {
            endpoint,
            client: Arc::new(Mutex::new(None)),
            nh_ids: Arc::new(Mutex::new(HashMap::new())),
            nh_ids6: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Construct from `CRADLE_GRPC` if set (env fallback; the primary control is
    /// the `system cradle-grpc` config leaf). Returns `None` when unset.
    pub fn from_env() -> Option<Self> {
        std::env::var("CRADLE_GRPC").ok().map(|ep| Self::new(&ep))
    }

    /// Lazily connect (and cache) the gRPC client.
    async fn client(&self) -> anyhow::Result<CradleClient<Channel>> {
        let mut guard = self.client.lock().await;
        if guard.is_none() {
            *guard = Some(CradleClient::connect(self.endpoint.clone()).await?);
        }
        Ok(guard.as_ref().unwrap().clone())
    }

    /// Resolve (creating if needed) the cradle nexthop id for
    /// `(gw, oif, out-label stack)`. A non-empty `labels` makes this an MPLS
    /// nexthop: the stack is the imposition (route) or swap (ILM) labels.
    async fn nexthop_id(
        &self,
        gw: Option<Ipv4Addr>,
        oif: u32,
        labels: &[u32],
    ) -> anyhow::Result<u32> {
        let key = (gw.map(u32::from).unwrap_or(0), oif, labels.to_vec());
        {
            let ids = self.nh_ids.lock().await;
            if let Some(id) = ids.get(&key) {
                return Ok(*id);
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut client = self.client().await?;
        client
            .set_nexthop(pb::Nexthop {
                id,
                gateway: gw.map(|a| a.to_string()).unwrap_or_default(),
                oif: String::new(),
                oif_index: oif,
                v6: false,
                labels: labels.to_vec(),
            })
            .await?;
        self.nh_ids.lock().await.insert(key, id);
        Ok(id)
    }

    /// Install an IPv4 route with one or more nexthops. A single member becomes
    /// a plain route; multiple members become an ECMP nexthop group. Each
    /// member is `(gateway, oif, out-label stack)` — a non-empty stack makes
    /// the leg an MPLS imposition (ingress LER). `table_id` is the kernel
    /// routing table the route belongs to; VRF tables map to cradle's
    /// per-VRF FIB.
    pub async fn route_install(
        &self,
        prefix: Ipv4Net,
        table_id: u32,
        members: Vec<(Option<Ipv4Addr>, u32, Vec<u32>)>,
    ) {
        if let Err(e) = self.try_route_install(prefix, table_id, members).await {
            tracing::warn!("fib: cradle route_install {prefix} failed: {e}");
        }
    }

    async fn try_route_install(
        &self,
        prefix: Ipv4Net,
        table_id: u32,
        members: Vec<(Option<Ipv4Addr>, u32, Vec<u32>)>,
    ) -> anyhow::Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        let vrf_table_id = cradle_vrf(table_id);
        if members.len() == 1 {
            let (gw, oif, labels) = &members[0];
            let id = self.nexthop_id(*gw, *oif, labels).await?;
            self.client()
                .await?
                .add_route4(pb::Route4 {
                    prefix: prefix.to_string(),
                    nexthop_id: id,
                    flags: 0,
                    vrf_table_id,
                })
                .await?;
            return Ok(());
        }
        // ECMP: one nexthop per member, then a group the route points at.
        let mut ids = Vec::with_capacity(members.len());
        for (gw, oif, labels) in &members {
            ids.push(self.nexthop_id(*gw, *oif, labels).await?);
        }
        let gid = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut client = self.client().await?;
        client
            .set_nexthop_group(pb::NexthopGroup {
                id: gid,
                members: ids,
            })
            .await?;
        client
            .add_route4(pb::Route4 {
                prefix: prefix.to_string(),
                nexthop_id: gid,
                flags: FIB_F_ECMP,
                vrf_table_id,
            })
            .await?;
        tracing::debug!(
            "fib: cradle route_install {prefix} ECMP group {gid} ({} members)",
            members.len()
        );
        Ok(())
    }

    pub async fn route_del(&self, prefix: Ipv4Net, table_id: u32) {
        let result = async {
            self.client()
                .await?
                .del_route4(pb::Route4Del {
                    prefix: prefix.to_string(),
                    vrf_table_id: cradle_vrf(table_id),
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle route_del {prefix} failed: {e}");
        }
    }

    async fn nexthop_id6(
        &self,
        gw: Option<Ipv6Addr>,
        oif: u32,
        labels: &[u32],
    ) -> anyhow::Result<u32> {
        let key = (
            gw.map(|a| a.octets()).unwrap_or([0; 16]),
            oif,
            labels.to_vec(),
        );
        {
            let ids = self.nh_ids6.lock().await;
            if let Some(id) = ids.get(&key) {
                return Ok(*id);
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut client = self.client().await?;
        client
            .set_nexthop(pb::Nexthop {
                id,
                gateway: gw.map(|a| a.to_string()).unwrap_or_default(),
                oif: String::new(),
                oif_index: oif,
                v6: true,
                labels: labels.to_vec(),
            })
            .await?;
        self.nh_ids6.lock().await.insert(key, id);
        Ok(id)
    }

    /// Install an IPv6 route with one or more nexthops (single = plain route,
    /// multiple = ECMP nexthop group).
    pub async fn route_install6(
        &self,
        prefix: Ipv6Net,
        table_id: u32,
        members: Vec<(Option<Ipv6Addr>, u32, Vec<u32>)>,
    ) {
        // cradle has no per-VRF v6 FIB yet: skip VRF-scoped v6 routes rather
        // than leak them into the global table.
        if cradle_vrf(table_id) != 0 {
            tracing::debug!(
                "fib: cradle route_install6 {prefix}: v6 VRF tee not supported, skipped"
            );
            return;
        }
        if let Err(e) = self.try_route_install6(prefix, members).await {
            tracing::warn!("fib: cradle route_install6 {prefix} failed: {e}");
        }
    }

    async fn try_route_install6(
        &self,
        prefix: Ipv6Net,
        members: Vec<(Option<Ipv6Addr>, u32, Vec<u32>)>,
    ) -> anyhow::Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        if members.len() == 1 {
            let (gw, oif, labels) = &members[0];
            let id = self.nexthop_id6(*gw, *oif, labels).await?;
            self.client()
                .await?
                .add_route6(pb::Route6 {
                    prefix: prefix.to_string(),
                    nexthop_id: id,
                    flags: 0,
                })
                .await?;
            return Ok(());
        }
        let mut ids = Vec::with_capacity(members.len());
        for (gw, oif, labels) in &members {
            ids.push(self.nexthop_id6(*gw, *oif, labels).await?);
        }
        let gid = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut client = self.client().await?;
        client
            .set_nexthop_group(pb::NexthopGroup {
                id: gid,
                members: ids,
            })
            .await?;
        client
            .add_route6(pb::Route6 {
                prefix: prefix.to_string(),
                nexthop_id: gid,
                flags: FIB_F_ECMP,
            })
            .await?;
        Ok(())
    }

    pub async fn route_del6(&self, prefix: Ipv6Net, table_id: u32) {
        if cradle_vrf(table_id) != 0 {
            return; // v6 VRF routes are never teed (see route_install6)
        }
        let result = async {
            self.client()
                .await?
                .del_route6(pb::Route6Del {
                    prefix: prefix.to_string(),
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle route_del6 {prefix} failed: {e}");
        }
    }

    /// Install an ILM (incoming-label map) entry: `in_label` gets `action`
    /// (`MPLS_OP_SWAP` with the nexthop's `out_labels` as the imposed stack —
    /// empty = PHP, popped by the data plane on the S bit — or
    /// `MPLS_OP_POP_L3` with `vrf_table_id` for VPN decap) via `(gw, oif)`.
    pub async fn ilm_install(
        &self,
        in_label: u32,
        action: u32,
        vrf_table_id: u32,
        gw: Option<IpAddr>,
        oif: u32,
        out_labels: &[u32],
    ) {
        let result = async {
            let nexthop_id = match gw {
                Some(IpAddr::V6(v6)) => self.nexthop_id6(Some(v6), oif, out_labels).await?,
                Some(IpAddr::V4(v4)) => self.nexthop_id(Some(v4), oif, out_labels).await?,
                None => self.nexthop_id(None, oif, out_labels).await?,
            };
            self.client()
                .await?
                .add_ilm(pb::Ilm {
                    in_label,
                    nexthop_id,
                    action,
                    vrf_table_id,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle ilm_install {in_label} failed: {e}");
        }
    }

    pub async fn ilm_uninstall(&self, in_label: u32) {
        let result = async {
            self.client()
                .await?
                .del_ilm(pb::IlmDel { in_label })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle ilm_uninstall {in_label} failed: {e}");
        }
    }

    /// Feed a resolved neighbor (ARP/ND) into the cradle data plane — the
    /// MPLS egress rewrite (`mpls_l2_xmit`) resolves destination MACs from
    /// this state rather than the kernel neighbor table.
    pub async fn neighbor_add(&self, ip: IpAddr, oif_index: u32, mac: [u8; 6]) {
        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        let result = async {
            let mut client = self.client().await?;
            match ip {
                IpAddr::V4(v4) => {
                    client
                        .set_neighbor4(pb::Neighbor4 {
                            oif: String::new(),
                            ip: v4.to_string(),
                            mac,
                            oif_index,
                        })
                        .await?;
                }
                IpAddr::V6(v6) => {
                    client
                        .set_neighbor6(pb::Neighbor6 {
                            oif: String::new(),
                            ip: v6.to_string(),
                            mac,
                            oif_index,
                        })
                        .await?;
                }
            }
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle neighbor_add {ip} failed: {e}");
        }
    }
}
