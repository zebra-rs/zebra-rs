//! Optional tee of FIB route installs into the **cradle** eBPF data plane.
//!
//! Enabled by setting `CRADLE_GRPC=<host:port>`. When set, the protocol routes
//! the RIB installs are also pushed to a running `cradle` via its gRPC control
//! API, so zebra-rs-computed routes (static, BGP, OSPF, IS-IS, …) program the
//! eBPF FIB in addition to the kernel. This is the zebra-rs side of the
//! cradle-rs integration.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
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

#[derive(Clone)]
pub struct CradleFib {
    endpoint: String,
    client: Arc<Mutex<Option<CradleClient<Channel>>>>,
    /// Dedup `(gateway, oif) -> nexthop id` so we `SetNexthop` once per nexthop.
    nh_ids: Arc<Mutex<HashMap<(u32, u32), u32>>>,
    nh_ids6: Arc<Mutex<HashMap<([u8; 16], u32), u32>>>,
    next_id: Arc<AtomicU32>,
}

impl CradleFib {
    /// Construct from `CRADLE_GRPC` (e.g. `127.0.0.1:50151`). Returns `None`
    /// when the variable is unset (tee disabled).
    pub fn from_env() -> Option<Self> {
        let ep = std::env::var("CRADLE_GRPC").ok()?;
        // `unix:/path` (UDS) and `http://...` pass through; a bare host:port is
        // treated as TCP.
        let endpoint = if ep.starts_with("unix:") || ep.starts_with("http") {
            ep
        } else {
            format!("http://{ep}")
        };
        tracing::info!("fib: cradle eBPF tee enabled -> {endpoint}");
        Some(Self {
            endpoint,
            client: Arc::new(Mutex::new(None)),
            nh_ids: Arc::new(Mutex::new(HashMap::new())),
            nh_ids6: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
        })
    }

    /// Lazily connect (and cache) the gRPC client.
    async fn client(&self) -> anyhow::Result<CradleClient<Channel>> {
        let mut guard = self.client.lock().await;
        if guard.is_none() {
            *guard = Some(CradleClient::connect(self.endpoint.clone()).await?);
        }
        Ok(guard.as_ref().unwrap().clone())
    }

    /// Resolve (creating if needed) the cradle nexthop id for `(gw, oif)`.
    async fn nexthop_id(&self, gw: Option<Ipv4Addr>, oif: u32) -> anyhow::Result<u32> {
        let key = (gw.map(u32::from).unwrap_or(0), oif);
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
            })
            .await?;
        self.nh_ids.lock().await.insert(key, id);
        Ok(id)
    }

    /// Install an IPv4 route with one or more nexthops. A single member becomes
    /// a plain route; multiple members become an ECMP nexthop group.
    pub async fn route_install(&self, prefix: Ipv4Net, members: Vec<(Option<Ipv4Addr>, u32)>) {
        if let Err(e) = self.try_route_install(prefix, members).await {
            tracing::warn!("fib: cradle route_install {prefix} failed: {e}");
        }
    }

    async fn try_route_install(
        &self,
        prefix: Ipv4Net,
        members: Vec<(Option<Ipv4Addr>, u32)>,
    ) -> anyhow::Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        if members.len() == 1 {
            let (gw, oif) = members[0];
            let id = self.nexthop_id(gw, oif).await?;
            self.client()
                .await?
                .add_route4(pb::Route4 {
                    prefix: prefix.to_string(),
                    nexthop_id: id,
                    flags: 0,
                })
                .await?;
            return Ok(());
        }
        // ECMP: one nexthop per member, then a group the route points at.
        let mut ids = Vec::with_capacity(members.len());
        for (gw, oif) in &members {
            ids.push(self.nexthop_id(*gw, *oif).await?);
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
            })
            .await?;
        tracing::debug!(
            "fib: cradle route_install {prefix} ECMP group {gid} ({} members)",
            members.len()
        );
        Ok(())
    }

    pub async fn route_del(&self, prefix: Ipv4Net) {
        let result = async {
            self.client()
                .await?
                .del_route4(pb::Route4Del {
                    prefix: prefix.to_string(),
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle route_del {prefix} failed: {e}");
        }
    }

    async fn nexthop_id6(&self, gw: Option<Ipv6Addr>, oif: u32) -> anyhow::Result<u32> {
        let key = (gw.map(|a| a.octets()).unwrap_or([0; 16]), oif);
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
            })
            .await?;
        self.nh_ids6.lock().await.insert(key, id);
        Ok(id)
    }

    /// Install an IPv6 route with one or more nexthops (single = plain route,
    /// multiple = ECMP nexthop group).
    pub async fn route_install6(&self, prefix: Ipv6Net, members: Vec<(Option<Ipv6Addr>, u32)>) {
        if let Err(e) = self.try_route_install6(prefix, members).await {
            tracing::warn!("fib: cradle route_install6 {prefix} failed: {e}");
        }
    }

    async fn try_route_install6(
        &self,
        prefix: Ipv6Net,
        members: Vec<(Option<Ipv6Addr>, u32)>,
    ) -> anyhow::Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        if members.len() == 1 {
            let (gw, oif) = members[0];
            let id = self.nexthop_id6(gw, oif).await?;
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
        for (gw, oif) in &members {
            ids.push(self.nexthop_id6(*gw, *oif).await?);
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

    pub async fn route_del6(&self, prefix: Ipv6Net) {
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
}
