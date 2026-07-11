//! Optional tee of FIB route installs into the **cradle** eBPF data plane.
//!
//! Enabled by `system cradle enabled true`; the endpoint is the
//! `system cradle grpc-endpoint` override or the default `unix:cradle/grpc`
//! (the `CRADLE_GRPC` env var is a startup fallback). When active, the RIB
//! installs are also pushed to a running `cradle` via its gRPC control API, so
//! zebra-rs-computed routes (static, BGP, OSPF, IS-IS, …) program the eBPF FIB
//! in addition to the kernel. This is the zebra-rs side of the cradle-rs
//! integration.

use std::collections::{HashMap, HashSet};
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

/// A teed nexthop leaf: `(link gateway, oif, MPLS out-labels, SRv6 segment
/// list, SRv6 encap mode)`. A non-empty `segs` makes it an SRv6 (v6-underlay)
/// nexthop regardless of the route's family; `labels` and `segs` are mutually
/// exclusive.
pub type Leaf = (Option<IpAddr>, u32, Vec<u32>, Vec<Ipv6Addr>, u32);

/// A teed route member: a leaf plus an optional fast-reroute backup leaf
/// (`Nexthop::Protect` — the backup carries the TI-LFA repair: packed uSID
/// carriers + H.Insert for SRv6, the repair label stack for SR-MPLS).
/// Backups never nest.
type Member = (
    Option<IpAddr>,
    u32,
    Vec<u32>,
    Vec<Ipv6Addr>,
    u32,
    Option<Leaf>,
);

/// Desired-state mirror of every teed object class, keyed exactly like the
/// corresponding `*_del` signature. Recorded as ops flow through the tee
/// and replayed wholesale into a fresh engine by [`CradleFib::replay`] — a
/// supervised respawn (or adopted takeover) starts with empty maps, and
/// without a replay the datapath would stay empty until natural route
/// churn. Ports are deliberately absent: the `system ebpf` supervisor task
/// owns port desired-state and re-applies it on the same engine-up edge.
#[derive(Default, Clone)]
struct CradleMirror {
    /// (prefix, kernel table) → route members.
    routes4: HashMap<(Ipv4Net, u32), Vec<Member>>,
    routes6: HashMap<(Ipv6Net, u32), Vec<Member>>,
    /// in-label → (action, vrf_table_id, gw, oif, out-labels).
    ilm: HashMap<u32, (u32, u32, Option<IpAddr>, u32, Vec<u32>)>,
    /// SID prefix → (behavior, DX adjacency, oif) — config-static seg6local.
    static_sids: HashMap<Ipv6Net, (crate::rib::SidBehavior, Option<IpAddr>, u32)>,
    /// (SID address, prefix len) → (registry Sid, ifindex).
    local_sids: HashMap<(Ipv6Addr, u8), (crate::rib::Sid, u32)>,
    /// (outer dst, teid) → decap table (original kernel table id).
    gtp_pdrs: HashMap<(Ipv4Addr, u32), u32>,
    /// (UE prefix, kernel table) → (gtp_src, gtp_dst, teid, underlay gw, oif).
    gtp_encaps: HashMap<(Ipv4Net, u32), (Ipv4Addr, Ipv4Addr, u32, Option<Ipv4Addr>, u32)>,
    /// (bridge domain, mac) → remote End.DT2U/DT2M service SID.
    fdb: HashMap<(u32, [u8; 6]), Ipv6Addr>,
    /// (bridge domain, remote End.DT2M SID) flood-set memberships.
    repl_slots: HashSet<(u32, Ipv6Addr)>,
    /// (AC port, vid, dx2v table) → (remote SID, local decap SID).
    xconnects: HashMap<(String, u16, u32), (Ipv6Addr, Option<Ipv6Addr>)>,
    /// (mirror context, protected prefix) → reproduction VRF table.
    mirror_routes: HashMap<(u32, Ipv6Net), u32>,
    /// (neighbor ip, oif) → mac. Grow-only, like the upstream tee (no
    /// neighbor delete exists).
    neighbors: HashMap<(IpAddr, u32), [u8; 6]>,
}

/// Map zebra's `SidBehavior` to cradle's `SRV6_BH_*` (data-plane ABI). The
/// cradle datapath executes every behavior below; End.B6.Encaps additionally
/// carries its bound policy as a synthesized SRv6 nexthop (see
/// `local_sid_install`).
fn srv6_behavior(b: crate::rib::SidBehavior) -> u32 {
    use crate::rib::SidBehavior::*;
    match b {
        End => 0,
        EndX => 1,
        EndDT4 => 2,
        EndDT6 => 3,
        EndDT46 => 4,
        EndB6Encap => 5,
        UN => 6,
        UA => 7,       // classic End.X at /128 (no shift)
        UALib => 8,    // compressed carrier: shift + adjacency
        EndDT2U => 9,  // EVPN L2 unicast decap+bridge
        EndDT2M => 10, // EVPN L2 BUM decap+flood
        EndM => 11,    // egress-protection mirror (decap + mirror-context lookup)
        EndRep => 12,  // RFC 9800 REPLACE-C-SID (C-SID rewrite from containers)
        EndXRep => 13, // REPLACE-C-SID + adjacency cross-connect
        EndT => 14,    // End walk + table-scoped egress lookup (vrf_table_id)
        EndDX4 => 15,  // decap + IPv4 cross-connect (per-CE VPN egress)
        EndDX6 => 16,  // decap + IPv6 cross-connect
        EndDX2 => 17,  // decap + raw L2 emit on the AC (EVPN VPWS egress)
        EndDX2V => 18, // decap + VLAN-table AC demux (VLAN-scoped VPWS egress)
        // uT = a uN whose end-of-carrier lookup is table-scoped: cradle
        // models it as UN with a non-zero vrf_id (vrf_table_id below).
        UT => 6,
    }
}

/// Map an `EncapType` to cradle's `encap_mode`: the H.Encaps forms are 0/1
/// (cradle emits the reduced single-SID form regardless, so 1 only
/// annotates); H.Insert — the TI-LFA repair imposition — is 2
/// (`SRV6_ENCAP_MODE_INSERT`: insert an SRH into the existing IPv6 packet,
/// original destination as the final segment).
pub fn srv6_encap_mode(t: Option<isis_packet::srv6::EncapType>) -> u32 {
    use isis_packet::srv6::EncapType;
    match t {
        Some(EncapType::HEncapRed | EncapType::HEncapL2Red) => 1,
        Some(EncapType::HInsert) => 2,
        _ => 0,
    }
}

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
    /// Dedup `(gateway, oif, out-label stack, backup id) -> nexthop id` so we
    /// `SetNexthop` once per distinct nexthop.
    nh_ids: Arc<Mutex<HashMap<(u32, u32, Vec<u32>, u32), u32>>>,
    nh_ids6: Arc<Mutex<HashMap<([u8; 16], u32, Vec<u32>, u32), u32>>>,
    /// SRv6 nexthop dedup: `(underlay gateway, oif, segment list) -> id`.
    nh_ids_srv6: Arc<Mutex<HashMap<([u8; 16], u32, Vec<[u8; 16]>), u32>>>,
    /// GTP-U encap nexthop dedup:
    /// `(gtp_src, gtp_dst, teid, underlay gateway, oif) -> id`.
    nh_ids_gtp: Arc<Mutex<HashMap<([u8; 4], [u8; 4], u32, u32, u32), u32>>>,
    next_id: Arc<AtomicU32>,
    /// The SRv6 H.Encaps source is pushed once (best-effort).
    encap_src_set: Arc<std::sync::atomic::AtomicBool>,
    /// Everything this tee has programmed, for [`Self::replay`].
    mirror: Arc<Mutex<CradleMirror>>,
}

/// Connect a cradle gRPC client. `unix:/path` (filesystem UDS) and
/// `http://…` dial through tonic's built-in support; `unix:NAME` (no leading
/// `/`) is a Linux abstract socket — the default `unix:cradle/grpc` — which
/// tonic can't dial natively, so it gets a custom connector.
async fn connect_cradle(endpoint: &str) -> anyhow::Result<CradleClient<Channel>> {
    if let Some(name) = endpoint
        .strip_prefix("unix:")
        .filter(|name| !name.starts_with('/'))
    {
        return connect_abstract_cradle(name.trim_start_matches('@')).await;
    }
    Ok(CradleClient::connect(endpoint.to_string()).await?)
}

/// Dial a cradle server on a Linux abstract Unix socket by name. tonic's UDS
/// connector calls `UnixStream::connect(path)` (filesystem only), so we hand
/// it a connector that dials the abstract address. Mirrors `vtyhelper`.
async fn connect_abstract_cradle(name: &str) -> anyhow::Result<CradleClient<Channel>> {
    use hyper_util::rt::TokioIo;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr as StdSockAddr, UnixStream as StdUnixStream};
    use tokio::net::UnixStream;
    use tonic::transport::Endpoint;
    use tower::service_fn;

    let name = name.to_string();
    // The URI is a placeholder; the connector ignores it and dials the
    // abstract Unix socket each time tonic calls it.
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let name = name.clone();
            async move {
                let addr = StdSockAddr::from_abstract_name(name.as_bytes())
                    .map_err(std::io::Error::other)?;
                let std = StdUnixStream::connect_addr(&addr)?;
                std.set_nonblocking(true)?;
                let stream = UnixStream::from_std(std)?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(CradleClient::new(channel))
}

/// Probe whether a cradle gRPC server answers at `endpoint` (fresh connect +
/// `GetStats`, 2 s budget). Used by the engine supervisor (`crate::cradle`)
/// for the adopt-if-running check and adopted-instance liveness.
pub(crate) async fn probe_endpoint(endpoint: &str) -> bool {
    let attempt = async {
        let mut client = connect_cradle(endpoint).await?;
        client.get_stats(pb::StatsRequest::default()).await?;
        anyhow::Ok(())
    };
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(2), attempt).await,
        Ok(Ok(()))
    )
}

impl CradleFib {
    /// Build a tee to the cradle gRPC endpoint `ep`. `unix:/path` (filesystem
    /// UDS), `unix:NAME` (Linux abstract socket, e.g. the default
    /// `unix:cradle/grpc`), and `http://...` pass through; a bare `host:port`
    /// is treated as TCP.
    pub fn new(ep: &str) -> Self {
        let endpoint = if ep.starts_with("unix:") || ep.starts_with("http") {
            ep.to_string()
        } else {
            format!("http://{ep}")
        };
        Self {
            endpoint,
            client: Arc::new(Mutex::new(None)),
            nh_ids: Arc::new(Mutex::new(HashMap::new())),
            nh_ids6: Arc::new(Mutex::new(HashMap::new())),
            nh_ids_srv6: Arc::new(Mutex::new(HashMap::new())),
            nh_ids_gtp: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
            encap_src_set: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            mirror: Arc::new(Mutex::new(CradleMirror::default())),
        }
    }

    /// The normalized gRPC endpoint this tee dials (as stored by `new`).
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Construct from `CRADLE_GRPC` if set (env fallback; the primary control is
    /// the `system cradle grpc-endpoint` config leaf). Returns `None` when unset.
    pub fn from_env() -> Option<Self> {
        std::env::var("CRADLE_GRPC").ok().map(|ep| {
            let fib = Self::new(&ep);
            tracing::info!("fib: cradle eBPF tee enabled -> {}", fib.endpoint());
            fib
        })
    }

    /// Attach `name` as a data-plane port (`SetPort`): cradle resolves the
    /// ifindex, attaches the TC/XDP programs, and derives the port's
    /// local + connected routes. Scope for now: a routed port in the
    /// global VRF (`l3`, vlan 0, vrf 0) — VRF/bridge binding follows with
    /// the dynamic L2/L3 assignment work. Idempotent on cradle's side.
    pub async fn set_port(&self, name: &str) -> anyhow::Result<()> {
        self.client()
            .await?
            .set_port(pb::Port {
                name: name.to_string(),
                mac: String::new(),
                l3: true,
                vlan: 0,
                vrf_id: 0,
            })
            .await?;
        Ok(())
    }

    /// Inverse of [`Self::set_port`]: detach the programs and drop the
    /// port's map entries, derived routes, and learned FDB entries.
    /// cradle resolves by current ifindex with a fallback to the
    /// attach-time name, so this also cleans up after the device itself
    /// is gone. Idempotent (an unknown port is a no-op).
    pub async fn del_port(&self, name: &str) -> anyhow::Result<()> {
        self.client()
            .await?
            .del_port(pb::PortDel {
                name: name.to_string(),
            })
            .await?;
        Ok(())
    }

    /// Replay the entire mirrored tee state into a fresh engine. Called
    /// (via `FibHandle::cradle_replay` ← `Message::CradleEngineUp`) when
    /// the `system ebpf` supervisor reports the engine ready after a
    /// respawn or adopted-instance takeover: the new instance's maps are
    /// empty, and — just as important — every cached nexthop id below
    /// refers to a `NEXTHOPS` entry only the dead instance knew, so the
    /// dedup caches must reset or even *new* routes would reference
    /// missing nexthops.
    pub async fn replay(&self) {
        self.nh_ids.lock().await.clear();
        self.nh_ids6.lock().await.clear();
        self.nh_ids_srv6.lock().await.clear();
        self.nh_ids_gtp.lock().await.clear();
        self.encap_src_set.store(false, Ordering::Relaxed);
        // Snapshot, then replay without holding the lock — the methods
        // below re-record into the mirror as they run (same values).
        let m = self.mirror.lock().await.clone();
        // Neighbors and local SIDs first (SIDs also re-push the H.Encaps
        // source), then the label/route classes (each re-creates its
        // nexthops on demand), then the overlays that resolve through them.
        for ((ip, oif), mac) in &m.neighbors {
            self.neighbor_add(*ip, *oif, *mac).await;
        }
        for ((_, plen), (sid, ifindex)) in &m.local_sids {
            self.local_sid_install(sid, *plen, *ifindex).await;
        }
        for (prefix, (behavior, adj, oif)) in &m.static_sids {
            self.static_sid_install(*prefix, *behavior, *adj, *oif)
                .await;
        }
        for (label, (action, vrf, gw, oif, labels)) in &m.ilm {
            self.ilm_install(*label, *action, *vrf, *gw, *oif, labels)
                .await;
        }
        for ((prefix, table), members) in &m.routes4 {
            self.route_install(*prefix, *table, members.clone()).await;
        }
        for ((prefix, table), members) in &m.routes6 {
            self.route_install6(*prefix, *table, members.clone()).await;
        }
        for ((vni, mac), sid) in &m.fdb {
            self.fdb_add(*vni, *mac, *sid).await;
        }
        for (vni, sid) in &m.repl_slots {
            self.repl_slot_add(*vni, *sid).await;
        }
        for ((port, vid, table), (remote, local)) in &m.xconnects {
            self.xconnect_add(port, *remote, *local, *vid, *table).await;
        }
        for ((dst, teid), table) in &m.gtp_pdrs {
            self.gtp_pdr_add(*dst, *teid, *table).await;
        }
        for ((prefix, table), (src, dst, teid, gw, oif)) in &m.gtp_encaps {
            self.gtp_encap_install(*prefix, *table, *src, *dst, *teid, *gw, *oif)
                .await;
        }
        for ((ctx, prefix), vrf) in &m.mirror_routes {
            self.mirror_route_add(*ctx, *prefix, *vrf).await;
        }
        tracing::info!(
            "fib: cradle replay: {} v4 + {} v6 routes, {} ILM, {} SIDs (+{} static), \
             {} FDB, {} repl slots, {} xconnects, {} GTP PDRs + {} encaps, \
             {} mirror routes, {} neighbors re-applied",
            m.routes4.len(),
            m.routes6.len(),
            m.ilm.len(),
            m.local_sids.len(),
            m.static_sids.len(),
            m.fdb.len(),
            m.repl_slots.len(),
            m.xconnects.len(),
            m.gtp_pdrs.len(),
            m.gtp_encaps.len(),
            m.mirror_routes.len(),
            m.neighbors.len(),
        );
    }

    /// Lazily connect (and cache) the gRPC client.
    async fn client(&self) -> anyhow::Result<CradleClient<Channel>> {
        let mut guard = self.client.lock().await;
        if guard.is_none() {
            *guard = Some(connect_cradle(&self.endpoint).await?);
        }
        Ok(guard.as_ref().unwrap().clone())
    }

    /// Resolve (creating if needed) the cradle nexthop id for
    /// `(gw, oif, out-label stack)`. A non-empty `labels` makes this an MPLS
    /// nexthop: the stack is the imposition (route) or swap (ILM) labels.
    /// A non-zero `backup_id` marks a protected primary — the data plane
    /// fails over to that nexthop on link-down (SR-MPLS TI-LFA).
    async fn nexthop_id(
        &self,
        gw: Option<Ipv4Addr>,
        oif: u32,
        labels: &[u32],
        backup_id: u32,
    ) -> anyhow::Result<u32> {
        let key = (
            gw.map(u32::from).unwrap_or(0),
            oif,
            labels.to_vec(),
            backup_id,
        );
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
                segs: Vec::new(),
                encap_mode: 0,
                backup_id,
                gtp_src: String::new(),
                gtp_dst: String::new(),
                gtp_teid: 0,
            })
            .await?;
        self.nh_ids.lock().await.insert(key, id);
        Ok(id)
    }

    /// Resolve (creating if needed) an SRv6-encap nexthop id: a v6 underlay
    /// nexthop (`gw6`/`oif`) that imposes the segment list `segs` (H.Encaps).
    async fn srv6_nexthop_id(
        &self,
        gw6: Option<Ipv6Addr>,
        oif: u32,
        segs: &[Ipv6Addr],
        encap_mode: u32,
    ) -> anyhow::Result<u32> {
        let key = (
            gw6.map(|a| a.octets()).unwrap_or([0; 16]),
            oif,
            segs.iter().map(|a| a.octets()).collect::<Vec<_>>(),
        );
        {
            let ids = self.nh_ids_srv6.lock().await;
            if let Some(id) = ids.get(&key) {
                return Ok(*id);
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.client()
            .await?
            .set_nexthop(pb::Nexthop {
                id,
                gateway: gw6.map(|a| a.to_string()).unwrap_or_default(),
                oif: String::new(),
                oif_index: oif,
                v6: true,
                labels: Vec::new(),
                segs: segs.iter().map(|a| a.to_string()).collect(),
                encap_mode,
                backup_id: 0,
                gtp_src: String::new(),
                gtp_dst: String::new(),
                gtp_teid: 0,
            })
            .await?;
        self.nh_ids_srv6.lock().await.insert(key, id);
        Ok(id)
    }

    /// Resolve a teed member to a cradle nexthop id. SRv6 members (non-empty
    /// `segs`) are always v6-underlay; otherwise the family follows the
    /// gateway, or `route_v6` for an on-link (gateway-less) member.
    async fn member_nexthop_id(&self, m: &Member, route_v6: bool) -> anyhow::Result<u32> {
        let (gw, oif, labels, segs, encap_mode, backup) = m;
        // Fast-reroute: resolve the backup leaf first (the TI-LFA repair —
        // packed carriers + H.Insert for SRv6, the repair label stack for
        // SR-MPLS), then hang its id off the primary so the datapath fails
        // over on link-down.
        let backup_id = match backup {
            Some((bgw, boif, blabels, bsegs, bmode)) => {
                self.leaf_nexthop_id(bgw, *boif, blabels, bsegs, *bmode, route_v6)
                    .await?
            }
            None => 0,
        };
        if !segs.is_empty() {
            let gw6 = match gw {
                Some(IpAddr::V6(a)) => Some(*a),
                _ => None,
            };
            return self.srv6_nexthop_id(gw6, *oif, segs, *encap_mode).await;
        }
        match gw {
            Some(IpAddr::V4(a)) => self.nexthop_id(Some(*a), *oif, labels, backup_id).await,
            Some(IpAddr::V6(a)) => self.nexthop_id6(Some(*a), *oif, labels, backup_id).await,
            None if route_v6 => self.nexthop_id6(None, *oif, labels, backup_id).await,
            None => self.nexthop_id(None, *oif, labels, backup_id).await,
        }
    }

    /// Resolve a bare leaf (no backup) — the backup half of a protected pair.
    async fn leaf_nexthop_id(
        &self,
        gw: &Option<IpAddr>,
        oif: u32,
        labels: &[u32],
        segs: &[Ipv6Addr],
        encap_mode: u32,
        route_v6: bool,
    ) -> anyhow::Result<u32> {
        if !segs.is_empty() {
            let gw6 = match gw {
                Some(IpAddr::V6(a)) => Some(*a),
                _ => None,
            };
            return self.srv6_nexthop_id(gw6, oif, segs, encap_mode).await;
        }
        match gw {
            Some(IpAddr::V4(a)) => self.nexthop_id(Some(*a), oif, labels, 0).await,
            Some(IpAddr::V6(a)) => self.nexthop_id6(Some(*a), oif, labels, 0).await,
            None if route_v6 => self.nexthop_id6(None, oif, labels, 0).await,
            None => self.nexthop_id(None, oif, labels, 0).await,
        }
    }

    /// Install an IPv4 route with one or more nexthops. A single member becomes
    /// a plain route; multiple members become an ECMP nexthop group. `table_id`
    /// is the kernel routing table; VRF tables map to cradle's per-VRF FIB.
    pub async fn route_install(&self, prefix: Ipv4Net, table_id: u32, members: Vec<Member>) {
        self.mirror
            .lock()
            .await
            .routes4
            .insert((prefix, table_id), members.clone());
        if let Err(e) = self.try_route_install(prefix, table_id, members).await {
            tracing::warn!("fib: cradle route_install {prefix} failed: {e}");
        }
    }

    async fn try_route_install(
        &self,
        prefix: Ipv4Net,
        table_id: u32,
        members: Vec<Member>,
    ) -> anyhow::Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        let vrf_table_id = cradle_vrf(table_id);
        if members.len() == 1 {
            let id = self.member_nexthop_id(&members[0], false).await?;
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
        for m in &members {
            ids.push(self.member_nexthop_id(m, false).await?);
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
        self.mirror.lock().await.routes4.remove(&(prefix, table_id));
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
        backup_id: u32,
    ) -> anyhow::Result<u32> {
        let key = (
            gw.map(|a| a.octets()).unwrap_or([0; 16]),
            oif,
            labels.to_vec(),
            backup_id,
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
                segs: Vec::new(),
                encap_mode: 0,
                backup_id,
                gtp_src: String::new(),
                gtp_dst: String::new(),
                gtp_teid: 0,
            })
            .await?;
        self.nh_ids6.lock().await.insert(key, id);
        Ok(id)
    }

    /// Install an IPv6 route with one or more nexthops (single = plain route,
    /// multiple = ECMP nexthop group). VRF tables map to cradle's per-VRF v6
    /// FIB (`FIB6_VRF`).
    pub async fn route_install6(&self, prefix: Ipv6Net, table_id: u32, members: Vec<Member>) {
        self.mirror
            .lock()
            .await
            .routes6
            .insert((prefix, table_id), members.clone());
        if let Err(e) = self.try_route_install6(prefix, table_id, members).await {
            tracing::warn!("fib: cradle route_install6 {prefix} failed: {e}");
        }
    }

    async fn try_route_install6(
        &self,
        prefix: Ipv6Net,
        table_id: u32,
        members: Vec<Member>,
    ) -> anyhow::Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        let vrf_table_id = cradle_vrf(table_id);
        if members.len() == 1 {
            let id = self.member_nexthop_id(&members[0], true).await?;
            self.client()
                .await?
                .add_route6(pb::Route6 {
                    prefix: prefix.to_string(),
                    nexthop_id: id,
                    flags: 0,
                    vrf_table_id,
                })
                .await?;
            return Ok(());
        }
        let mut ids = Vec::with_capacity(members.len());
        for m in &members {
            ids.push(self.member_nexthop_id(m, true).await?);
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
                vrf_table_id,
            })
            .await?;
        Ok(())
    }

    pub async fn route_del6(&self, prefix: Ipv6Net, table_id: u32) {
        self.mirror.lock().await.routes6.remove(&(prefix, table_id));
        let result = async {
            self.client()
                .await?
                .del_route6(pb::Route6Del {
                    prefix: prefix.to_string(),
                    vrf_table_id: cradle_vrf(table_id),
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
        self.mirror.lock().await.ilm.insert(
            in_label,
            (action, vrf_table_id, gw, oif, out_labels.to_vec()),
        );
        let result = async {
            let nexthop_id = match gw {
                Some(IpAddr::V6(v6)) => self.nexthop_id6(Some(v6), oif, out_labels, 0).await?,
                Some(IpAddr::V4(v4)) => self.nexthop_id(Some(v4), oif, out_labels, 0).await?,
                None => self.nexthop_id(None, oif, out_labels, 0).await?,
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
        self.mirror.lock().await.ilm.remove(&in_label);
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

    /// Install an SRv6 local SID (seg6local) into the cradle data plane —
    /// the SRv6 analogue of the ILM tee. Maps the behavior to `SRV6_BH_*`;
    /// `End.DT*` carry the VRF table id; `End.X`/`uA` resolve their
    /// cross-connect adjacency (`nh6`) to a cradle nexthop.
    /// Tee a STATIC seg6local action route (config-static `action` leaf)
    /// as a cradle local SID. These install as route-embedded encaps on
    /// the kernel side and never pass through the SID registry, so
    /// `local_sid_install` never sees them — without this tee a static
    /// End/uN/DT*/DX* SID exists in the kernel but not in eBPF. `adj` is
    /// the DX cross-connect adjacency (v6 or v4), unspecified/absent for
    /// the decap-only actions.
    pub async fn static_sid_install(
        &self,
        prefix: Ipv6Net,
        behavior: crate::rib::SidBehavior,
        adj: Option<IpAddr>,
        oif: u32,
    ) {
        self.mirror
            .lock()
            .await
            .static_sids
            .insert(prefix, (behavior, adj, oif));
        let result = async {
            let nexthop_id = match adj {
                Some(IpAddr::V6(a)) if !a.is_unspecified() => {
                    self.nexthop_id6(Some(a), oif, &[], 0).await?
                }
                Some(IpAddr::V4(a)) if !a.is_unspecified() => {
                    self.nexthop_id(Some(a), oif, &[], 0).await?
                }
                _ => 0,
            };
            self.client()
                .await?
                .add_local_sid(pb::LocalSid {
                    sid: prefix.addr().to_string(),
                    prefix_len: prefix.prefix_len() as u32,
                    behavior: srv6_behavior(behavior),
                    vrf_table_id: 0,
                    oif,
                    nh6: String::new(),
                    lb_bits: 0,
                    ln_bits: 0,
                    fun_bits: 0,
                    arg_bits: 0,
                    nexthop_id,
                    flavors: 0,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle static_sid_install {} failed: {e}", prefix);
        }
    }

    /// Withdraw a static seg6local action SID teed by `static_sid_install`.
    pub async fn static_sid_uninstall(&self, prefix: Ipv6Net) {
        self.mirror.lock().await.static_sids.remove(&prefix);
        let result = async {
            self.client()
                .await?
                .del_local_sid(pb::LocalSidDel {
                    sid: prefix.addr().to_string(),
                    prefix_len: prefix.prefix_len() as u32,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle static_sid_uninstall {} failed: {e}", prefix);
        }
    }

    pub async fn local_sid_install(&self, sid: &crate::rib::Sid, prefix_len: u8, ifindex: u32) {
        self.mirror
            .lock()
            .await
            .local_sids
            .insert((sid.addr, prefix_len), (sid.clone(), ifindex));
        let result = async {
            let nexthop_id =
                if sid.behavior == crate::rib::SidBehavior::EndB6Encap && !sid.segs.is_empty() {
                    // The Binding SID's bound policy rides as a cradle SRv6
                    // nexthop (its id keys the `SRV6_ENCAP` segment list, which
                    // the eBPF End.B6 handler reads through
                    // `LocalSid.nexthop_id`). The gw/oif of this nexthop are
                    // not used by the push — the packet re-enters the FIB by
                    // the new outer DA, per S19.
                    self.srv6_nexthop_id(None, ifindex, &sid.segs, 0).await?
                } else {
                    match sid.nh6 {
                        Some(nh6) => self.nexthop_id6(Some(nh6), ifindex, &[], 0).await?,
                        None => 0,
                    }
                };
            let (lb, ln, fun, arg) = sid
                .structure
                .map(|s| (s.lb_bits, s.ln_bits, s.fun_bits, s.arg_bits))
                .unwrap_or((0, 0, 0, 0));
            self.client()
                .await?
                .add_local_sid(pb::LocalSid {
                    sid: sid.addr.to_string(),
                    prefix_len: prefix_len as u32,
                    behavior: srv6_behavior(sid.behavior),
                    vrf_table_id: cradle_vrf(sid.table_id),
                    oif: ifindex,
                    nh6: sid.nh6.map(|a| a.to_string()).unwrap_or_default(),
                    lb_bits: lb as u32,
                    ln_bits: ln as u32,
                    fun_bits: fun as u32,
                    arg_bits: arg as u32,
                    nexthop_id,
                    flavors: sid.flavors as u32,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle local_sid_install {} failed: {e}", sid.addr);
        }
        // Best-effort: the SRv6 H.Encaps outer source (zebra has no explicit
        // config for it). A local SID is in the node's locator, so its
        // address is a routable node source; forwarding does not depend on it.
        // Set it once, from the first local SID installed.
        if self.encap_src_set.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Err(e) = async {
            self.client()
                .await?
                .set_srv6_encap_source(pb::Srv6EncapSource {
                    addr: sid.addr.to_string(),
                })
                .await?;
            anyhow::Ok(())
        }
        .await
        {
            tracing::debug!("fib: cradle set_srv6_encap_source failed: {e}");
        }
    }

    pub async fn local_sid_uninstall(&self, sid: &crate::rib::Sid, prefix_len: u8) {
        self.mirror
            .lock()
            .await
            .local_sids
            .remove(&(sid.addr, prefix_len));
        let result = async {
            self.client()
                .await?
                .del_local_sid(pb::LocalSidDel {
                    sid: sid.addr.to_string(),
                    prefix_len: prefix_len as u32,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle local_sid_uninstall {} failed: {e}", sid.addr);
        }
    }

    /// Install a GTP-U decap PDR (`H.M.GTP4.D`): a G-PDU arriving on
    /// (`dst`, `teid`) is stripped and its inner packet forwarded in the VRF
    /// table `table_id` (0 = global). Cradle-only — the mainline kernel has no
    /// GTP action, so this is never a kernel route.
    pub async fn gtp_pdr_add(&self, dst: Ipv4Addr, teid: u32, table_id: u32) {
        self.mirror
            .lock()
            .await
            .gtp_pdrs
            .insert((dst, teid), table_id);
        if let Err(e) = async {
            self.client()
                .await?
                .add_gtp_pdr(pb::GtpPdr {
                    dst: dst.to_string(),
                    teid,
                    vrf: cradle_vrf(table_id),
                })
                .await?;
            anyhow::Ok(())
        }
        .await
        {
            tracing::warn!("fib: cradle gtp_pdr_add {dst} teid {teid} failed: {e}");
        }
    }

    /// Remove a GTP-U decap PDR.
    pub async fn gtp_pdr_del(&self, dst: Ipv4Addr, teid: u32) {
        self.mirror.lock().await.gtp_pdrs.remove(&(dst, teid));
        if let Err(e) = async {
            self.client()
                .await?
                .del_gtp_pdr(pb::GtpPdrDel {
                    dst: dst.to_string(),
                    teid,
                })
                .await?;
            anyhow::Ok(())
        }
        .await
        {
            tracing::debug!("fib: cradle gtp_pdr_del {dst} teid {teid} failed: {e}");
        }
    }

    /// Resolve (creating if needed) a GTP-U encap nexthop id: a v4 underlay
    /// nexthop (`gw`/`oif`) that wraps the packet in outer IPv4 + UDP(2152) +
    /// GTP-U toward `gtp_dst` (sourced from `gtp_src`, TEID `teid`).
    async fn gtp_nexthop_id(
        &self,
        gtp_src: Ipv4Addr,
        gtp_dst: Ipv4Addr,
        teid: u32,
        gw: Option<Ipv4Addr>,
        oif: u32,
    ) -> anyhow::Result<u32> {
        let key = (
            gtp_src.octets(),
            gtp_dst.octets(),
            teid,
            gw.map(u32::from).unwrap_or(0),
            oif,
        );
        {
            let ids = self.nh_ids_gtp.lock().await;
            if let Some(id) = ids.get(&key) {
                return Ok(*id);
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.client()
            .await?
            .set_nexthop(pb::Nexthop {
                id,
                gateway: gw.map(|a| a.to_string()).unwrap_or_default(),
                oif: String::new(),
                oif_index: oif,
                v6: false,
                labels: Vec::new(),
                segs: Vec::new(),
                encap_mode: 0,
                backup_id: 0,
                gtp_src: gtp_src.to_string(),
                gtp_dst: gtp_dst.to_string(),
                gtp_teid: teid,
            })
            .await?;
        self.nh_ids_gtp.lock().await.insert(key, id);
        Ok(id)
    }

    /// Install a GTP-U encap route (`GTP4.E`): traffic to `prefix` in `table_id`
    /// is wrapped in outer IPv4 + UDP(2152) + GTP-U(`teid`) toward `gtp_dst`
    /// (sourced from `gtp_src`) over the resolved v4 underlay `gw`/`oif`.
    #[allow(clippy::too_many_arguments)]
    pub async fn gtp_encap_install(
        &self,
        prefix: Ipv4Net,
        table_id: u32,
        gtp_src: Ipv4Addr,
        gtp_dst: Ipv4Addr,
        teid: u32,
        gw: Option<Ipv4Addr>,
        oif: u32,
    ) {
        self.mirror
            .lock()
            .await
            .gtp_encaps
            .insert((prefix, table_id), (gtp_src, gtp_dst, teid, gw, oif));
        if let Err(e) = async {
            let id = self.gtp_nexthop_id(gtp_src, gtp_dst, teid, gw, oif).await?;
            self.client()
                .await?
                .add_route4(pb::Route4 {
                    prefix: prefix.to_string(),
                    nexthop_id: id,
                    flags: 0,
                    vrf_table_id: cradle_vrf(table_id),
                })
                .await?;
            anyhow::Ok(())
        }
        .await
        {
            tracing::warn!(
                "fib: cradle gtp_encap_install {prefix} -> {gtp_dst} teid {teid} failed: {e}"
            );
        }
    }

    /// Remove a GTP-U encap route (the nexthop is kept for dedup reuse).
    pub async fn gtp_encap_del(&self, prefix: Ipv4Net, table_id: u32) {
        self.mirror
            .lock()
            .await
            .gtp_encaps
            .remove(&(prefix, table_id));
        if let Err(e) = async {
            self.client()
                .await?
                .del_route4(pb::Route4Del {
                    prefix: prefix.to_string(),
                    vrf_table_id: cradle_vrf(table_id),
                })
                .await?;
            anyhow::Ok(())
        }
        .await
        {
            tracing::debug!("fib: cradle gtp_encap_del {prefix} failed: {e}");
        }
    }

    /// EVPN-over-SRv6 overlay FDB entry (RFC 9252): `mac` in bridge domain
    /// `vni` sits behind the remote PE's L2 service SID (End.DT2U for
    /// unicast; the all-ones BUM sentinel carries End.DT2M). `nexthop_id: 0`
    /// — cradle resolves the underlay adjacency with a FIB6 lookup on the
    /// SID (the IGP's locator route, already teed).
    pub async fn fdb_add(&self, vni: u32, mac: [u8; 6], sid: std::net::Ipv6Addr) {
        self.mirror.lock().await.fdb.insert((vni, mac), sid);
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        let result = async {
            self.client()
                .await?
                .add_fdb_remote(pb::FdbRemote {
                    mac: mac_str.clone(),
                    bd: vni,
                    remote_sid: sid.to_string(),
                    nexthop_id: 0,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle fdb_add {mac_str} vni {vni} failed: {e}");
        }
    }

    /// Remove an overlay FDB entry.
    pub async fn fdb_del(&self, vni: u32, mac: [u8; 6]) {
        self.mirror.lock().await.fdb.remove(&(vni, mac));
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        let result = async {
            self.client()
                .await?
                .del_fdb_remote(pb::FdbRemoteDel {
                    mac: mac_str.clone(),
                    bd: vni,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle fdb_del {mac_str} vni {vni} failed: {e}");
        }
    }

    /// Subscribe to cradle's datapath MAC learning (EVPN over SRv6): the
    /// stream yields every locally-learned `(mac, bridge domain)` so the
    /// caller can originate EVPN Type-2 routes. A fresh subscription
    /// replays the full current set first; learns only (no aging yet).
    pub async fn watch_fdb(&self) -> anyhow::Result<tonic::Streaming<pb::FdbEvent>> {
        let resp = self
            .client()
            .await?
            .watch_fdb(pb::WatchFdbRequest {})
            .await?;
        Ok(resp.into_inner())
    }

    /// Add a BUM replication slot (EVPN Type-3 tee): the remote PE behind
    /// `sid` (its `End.DT2M`) joins VNI `vni`'s flood set. cradle owns the
    /// slot plumbing (veth pair + flood membership + per-copy encap);
    /// idempotent per `(vni, sid)`.
    pub async fn repl_slot_add(&self, vni: u32, sid: std::net::Ipv6Addr) {
        self.mirror.lock().await.repl_slots.insert((vni, sid));
        let result = async {
            self.client()
                .await?
                .add_repl_slot(pb::ReplSlot {
                    bd: vni,
                    remote_sid: sid.to_string(),
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle repl_slot_add vni {vni} {sid} failed: {e}");
        }
    }

    /// EVPN VPWS cross-connect (RFC 8214 / RFC 9252 §6.3): bind AC `port`
    /// to the remote PE's End.DX2/DX2V service SID. `local_sid`, when
    /// present, rides in the same RPC so cradle also installs the local
    /// decap bound to the AC — one message programs the E-Line both ways.
    /// A non-zero `vid` makes the binding VLAN-scoped (End.DX2V over VLAN
    /// table `table`).
    pub async fn xconnect_add(
        &self,
        port: &str,
        remote_sid: std::net::Ipv6Addr,
        local_sid: Option<std::net::Ipv6Addr>,
        vid: u16,
        table: u32,
    ) {
        self.mirror
            .lock()
            .await
            .xconnects
            .insert((port.to_string(), vid, table), (remote_sid, local_sid));
        let result = async {
            self.client()
                .await?
                .add_xconnect(pb::Xconnect {
                    port: port.to_string(),
                    port_index: 0,
                    remote_sid: remote_sid.to_string(),
                    local_sid: local_sid.map(|s| s.to_string()).unwrap_or_default(),
                    vid: vid as u32,
                    dx2v_table: table,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle xconnect_add {port} -> {remote_sid} failed: {e}");
        }
    }

    /// Remove a VPWS cross-connect (and its local End.DX2/DX2V decap, when
    /// `local_sid` is present).
    pub async fn xconnect_del(
        &self,
        port: &str,
        local_sid: Option<std::net::Ipv6Addr>,
        vid: u16,
        table: u32,
    ) {
        self.mirror
            .lock()
            .await
            .xconnects
            .remove(&(port.to_string(), vid, table));
        let result = async {
            self.client()
                .await?
                .del_xconnect(pb::XconnectDel {
                    port: port.to_string(),
                    port_index: 0,
                    local_sid: local_sid.map(|s| s.to_string()).unwrap_or_default(),
                    vid: vid as u32,
                    dx2v_table: table,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle xconnect_del {port} failed: {e}");
        }
    }

    /// Remove a `(vni, sid)` replication slot.
    pub async fn repl_slot_del(&self, vni: u32, sid: std::net::Ipv6Addr) {
        self.mirror.lock().await.repl_slots.remove(&(vni, sid));
        let result = async {
            self.client()
                .await?
                .del_repl_slot(pb::ReplSlot {
                    bd: vni,
                    remote_sid: sid.to_string(),
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle repl_slot_del vni {vni} {sid} failed: {e}");
        }
    }

    /// Install an egress-protection mirror route (the End.M context): the
    /// protected egress PE's locator `prefix` reproduces locally as an
    /// `End.DT46` decap into `vrf_table` — the cradle twin of the kernel's
    /// mirror-context-table route.
    pub async fn mirror_route_add(&self, ctx: u32, prefix: ipnet::Ipv6Net, vrf_table: u32) {
        self.mirror
            .lock()
            .await
            .mirror_routes
            .insert((ctx, prefix), vrf_table);
        let result = async {
            self.client()
                .await?
                .add_mirror_route(pb::MirrorRoute {
                    ctx,
                    prefix: prefix.addr().to_string(),
                    prefix_len: prefix.prefix_len() as u32,
                    behavior: 4, // SRV6_BH_END_DT46
                    vrf_table_id: cradle_vrf(vrf_table),
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle mirror_route_add {prefix} failed: {e}");
        }
    }

    /// Remove a mirror route.
    pub async fn mirror_route_del(&self, ctx: u32, prefix: ipnet::Ipv6Net) {
        self.mirror
            .lock()
            .await
            .mirror_routes
            .remove(&(ctx, prefix));
        let result = async {
            self.client()
                .await?
                .del_mirror_route(pb::MirrorRouteDel {
                    ctx,
                    prefix: prefix.addr().to_string(),
                    prefix_len: prefix.prefix_len() as u32,
                })
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("fib: cradle mirror_route_del {prefix} failed: {e}");
        }
    }

    /// Feed a resolved neighbor (ARP/ND) into the cradle data plane — the
    /// MPLS egress rewrite (`mpls_l2_xmit`) resolves destination MACs from
    /// this state rather than the kernel neighbor table.
    pub async fn neighbor_add(&self, ip: IpAddr, oif_index: u32, mac: [u8; 6]) {
        self.mirror
            .lock()
            .await
            .neighbors
            .insert((ip, oif_index), mac);
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
