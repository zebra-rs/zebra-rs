//! PFCP/N4 socket and message handling for the MUP controller.
//!
//! The controller terminates PFCP as a UP-node (UPF role): it binds a UDP
//! socket (default `[::]:8805`), answers the node-management messages
//! (Heartbeat, Association Setup/Release) and the session messages
//! (Establishment / Modification / Deletion), and reports each
//! session/association change to the BGP task as a [`MupCEvent`]. Wire
//! encode/decode is the `rs-pfcp` codec; the socket is ours.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use socket2::Domain;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;

use rs_pfcp::ie::IeType;
use rs_pfcp::ie::apply_action::ApplyAction;
use rs_pfcp::ie::cause::CauseValue;
use rs_pfcp::ie::create_far::CreateFar;
use rs_pfcp::ie::create_pdr::CreatePdr;
use rs_pfcp::ie::created_pdr::CreatedPdr;
use rs_pfcp::ie::destination_interface::Interface as DestInterface;
use rs_pfcp::ie::f_teid::FteidBuilder;
use rs_pfcp::ie::fseid::Fseid;
use rs_pfcp::ie::node_id::NodeId;
use rs_pfcp::ie::outer_header_creation::OuterHeaderCreation;
use rs_pfcp::ie::pdr_id::PdrId;
use rs_pfcp::ie::source_interface::SourceInterfaceValue;
use rs_pfcp::ie::update_far::UpdateFar;
use rs_pfcp::message::association_release_response::AssociationReleaseResponseBuilder;
use rs_pfcp::message::association_setup_response::AssociationSetupResponseBuilder;
use rs_pfcp::message::heartbeat_response::HeartbeatResponseBuilder;
use rs_pfcp::message::session_deletion_response::SessionDeletionResponseBuilder;
use rs_pfcp::message::session_establishment_response::SessionEstablishmentResponseBuilder;
use rs_pfcp::message::session_modification_response::SessionModificationResponseBuilder;
use rs_pfcp::message::{self, Message as PfcpMessage, MsgType};
use rs_pfcp::types::SequenceNumber;

use crate::context::Task;

use super::assoc::MupAssocInfo;
use super::inst::{Message, MupC, MupCEvent};
use super::session::MupSession;

/// Outcome of handling one PFCP request: an optional reply to send back
/// to the peer, plus the events to report to BGP.
type Handled = (Option<Vec<u8>>, Vec<MupCEvent>);

/// Upper bound on concurrent PFCP associations. The controller faces an
/// external SMF/CP, so the association and session tables are bounded to
/// keep a misbehaving or hostile peer from exhausting memory. Idle/dead
/// association eviction (driven by Heartbeat liveness) is a follow-up.
const MAX_ASSOCS: usize = 256;
/// Upper bound on concurrently learned sessions across all peers.
const MAX_SESSIONS: usize = 1 << 20;

impl MupC {
    /// (Re)bind the PFCP listener to the configured address/port and
    /// (re)start the recv task. Idempotent — replacing `recv_task`
    /// aborts the previous one. Failures are non-fatal: the controller
    /// stays up and reports the listener as down.
    pub(super) async fn bind(&mut self) {
        let addr = self.config.listen_socket_addr();
        let domain = match addr.ip() {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };
        let sock = match self.ctx.udp_socket_unbound(domain) {
            Ok(sock) => sock,
            Err(e) => {
                tracing::warn!("mup-c: PFCP socket({addr}) failed: {e}");
                return self.set_listener(None).await;
            }
        };
        let _ = sock.set_reuse_address(true);
        if let Err(e) = sock.bind(&addr.into()) {
            tracing::warn!("mup-c: PFCP bind {addr} failed: {e}");
            return self.set_listener(None).await;
        }
        if let Err(e) = sock.set_nonblocking(true) {
            tracing::warn!("mup-c: PFCP set_nonblocking failed: {e}");
        }
        let std_sock: std::net::UdpSocket = sock.into();
        let tokio_sock = match UdpSocket::from_std(std_sock) {
            Ok(sock) => sock,
            Err(e) => {
                tracing::warn!("mup-c: PFCP from_std failed: {e}");
                return self.set_listener(None).await;
            }
        };
        let sock = Arc::new(tokio_sock);
        let local = sock.local_addr().ok();
        self.listen_addr = local;
        self.sock = Some(sock.clone());
        // Replace the recv task; dropping the old handle aborts it.
        let tx = self.main_tx.clone();
        self.recv_task = Some(Task::spawn(async move {
            recv_loop(sock, tx).await;
        }));
        // tracing::info!("mup-c: PFCP listening on {local:?}");
        self.set_listener(local).await;
    }

    async fn set_listener(&self, bound: Option<SocketAddr>) {
        self.report(MupCEvent::Listener { bound }).await;
    }

    /// Decode one datagram, dispatch by message type, send the reply, and
    /// report the resulting events to BGP.
    pub(super) async fn handle_pfcp(&mut self, data: &[u8], src: SocketAddr) {
        // Decode + dispatch in a block so the parsed `Box<dyn Message>`
        // (not `Send`) is dropped before the `.await`s below; otherwise
        // the controller future would not be `Send`-spawnable.
        let (reply, events) = {
            let msg = match message::parse(data) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::warn!("mup-c: PFCP parse error from {src}: {e}");
                    return;
                }
            };
            match msg.msg_type() {
                MsgType::HeartbeatRequest => self.handle_heartbeat(msg.as_ref()),
                MsgType::AssociationSetupRequest => {
                    self.handle_association_setup(msg.as_ref(), src)
                }
                MsgType::AssociationReleaseRequest => {
                    self.handle_association_release(msg.as_ref(), src)
                }
                MsgType::SessionEstablishmentRequest => {
                    self.handle_session_establishment(msg.as_ref(), src)
                }
                MsgType::SessionModificationRequest => {
                    self.handle_session_modification(msg.as_ref(), src)
                }
                MsgType::SessionDeletionRequest => self.handle_session_deletion(msg.as_ref(), src),
                other => {
                    tracing::debug!("mup-c: unhandled PFCP {other:?} from {src}");
                    (None, Vec::new())
                }
            }
        };
        if let (Some(bytes), Some(sock)) = (reply, self.sock.as_ref())
            && let Err(e) = sock.send_to(&bytes, src).await
        {
            tracing::warn!("mup-c: PFCP send to {src} failed: {e}");
        }
        for ev in events {
            self.report(ev).await;
        }
    }

    fn handle_heartbeat(&mut self, msg: &dyn PfcpMessage) -> Handled {
        // Echo our fixed start-time recovery stamp, never `now()`: a
        // changing value makes the CP (free5GC) treat us as restarted and
        // release every session (TS 29.244 §19.5).
        let resp = HeartbeatResponseBuilder::new(msg.sequence())
            .recovery_time_stamp(self.recovery_ts)
            .build();
        (Some(resp.marshal()), Vec::new())
    }

    fn handle_association_setup(&mut self, msg: &dyn PfcpMessage, src: SocketAddr) -> Handled {
        // Bound the association table against a flood of distinct peers.
        // A re-setup from an already-known peer is always allowed.
        let reassoc = self.assoc.contains(&src);
        if !reassoc && self.assoc.count() >= MAX_ASSOCS {
            tracing::warn!("mup-c: association table full ({MAX_ASSOCS}); rejecting {src}");
            let resp = AssociationSetupResponseBuilder::new(msg.sequence())
                .cause(CauseValue::NoResourcesAvailable)
                .node_id(self.local_ip())
                .recovery_time_stamp(self.recovery_ts)
                .build();
            return (Some(resp.marshal()), Vec::new());
        }
        let node_id = msg
            .ies(IeType::NodeId)
            .next()
            .and_then(|ie| NodeId::unmarshal(&ie.payload).ok())
            .map(|n| node_id_string(&n))
            .unwrap_or_else(|| src.ip().to_string());

        // A re-setup from a peer that already has an association replaces
        // it (TS 29.244 §6.2.6.2): drop its existing sessions so they
        // don't leak, and tell BGP to withdraw their routes via AssocDown
        // before the fresh AssocUp re-originates them.
        let mut events = Vec::new();
        if reassoc {
            let _ = self.sessions.remove_peer(src);
            events.push(MupCEvent::AssocDown { peer: src });
        }
        self.assoc.upsert(
            src,
            MupAssocInfo {
                node_id: node_id.clone(),
            },
        );
        let resp = AssociationSetupResponseBuilder::new(msg.sequence())
            .cause_accepted()
            .node_id(self.local_ip())
            .recovery_time_stamp(self.recovery_ts)
            .build();
        events.push(MupCEvent::AssocUp { peer: src, node_id });
        (Some(resp.marshal()), events)
    }

    fn handle_association_release(&mut self, msg: &dyn PfcpMessage, src: SocketAddr) -> Handled {
        self.assoc.remove(&src);
        // The view's `AssocDown` drops this peer's sessions, so one event
        // covers them; the controller drops them locally here.
        let _ = self.sessions.remove_peer(src);
        let node_ie = node_from_ip(self.local_ip()).to_ie();
        let resp = AssociationReleaseResponseBuilder::new(msg.sequence())
            .cause_accepted()
            .node_id(node_ie)
            .build();
        (
            Some(resp.marshal()),
            vec![MupCEvent::AssocDown { peer: src }],
        )
    }

    fn handle_session_establishment(&mut self, msg: &dyn PfcpMessage, src: SocketAddr) -> Handled {
        let seq = msg.sequence();

        // The CP's F-SEID, which the response header must echo (TS 29.244
        // §7.2.2.4.2: the message SEID is the *receiver's* F-SEID). Read
        // it up front so even a rejection can be correlated by the CP.
        let cp_seid = cp_fseid(msg);

        // A session is only valid inside an established association
        // (3GPP TS 29.244 §6.2.6.2).
        if !self.assoc.contains(&src) {
            return (
                self.reject_session_establishment(
                    cp_seid,
                    seq,
                    CauseValue::NoEstablishedPfcpAssociation,
                ),
                Vec::new(),
            );
        }
        // Bound the session table against a hostile / runaway peer.
        if self.sessions.count() >= MAX_SESSIONS {
            tracing::warn!("mup-c: session table full ({MAX_SESSIONS}); rejecting from {src}");
            return (
                self.reject_session_establishment(cp_seid, seq, CauseValue::NoResourcesAvailable),
                Vec::new(),
            );
        }

        // Extract the session fields: UE IP + Network Instance from the PDRs,
        // and the GTP-U tunnel endpoints from the FARs' Outer Header Creation
        // (the gNB tunnel for the Type-1 ST route, the core tunnel for the
        // Type-2 ST route). See [`extract_pfcp`] for why the endpoints come
        // from the FARs, not the PDI F-TEIDs.
        let ex = extract_pfcp(msg);
        let (teid, endpoint) = ex.gnb.map_or((0, None), |(t, e)| (t, Some(e)));
        let (core_teid, core_endpoint) = ex.core.map_or((0, None), |(t, e)| (t, Some(e)));

        let seid = self.sessions.alloc_seid();
        let mut session = MupSession {
            seid,
            cp_seid,
            peer: src,
            ue_ipv4: ex.ue_ipv4,
            ue_ipv6: ex.ue_ipv6,
            teid,
            endpoint,
            core_teid,
            core_endpoint,
            network_instance: ex.network_instance,
            qfi: None,
        };
        // Core tunnel for the ST2 (decapsulation / uplink) route: the GTP-U
        // tunnel the mobile system sends uplink into, i.e. the tunnel this
        // UPF terminates (the datapath keys the uplink decap PDR on it). The
        // access/gNB tunnel is never borrowed (wrong direction). Resolved in
        // four tiers, most-specific first:
        //   0. CP-allocated (TS 29.244 CH=0) — the Access PDR's PDI local
        //      F-TEID. The SMF hands this same TEID to the gNB as the uplink
        //      target (free5GC allocates every UPF N3 TEID this way and
        //      ignores the Created PDR), so when present nothing else may
        //      key the tunnel.
        //   1. learned over PFCP — a Dest = Core FAR Outer Header Creation, a
        //      real N9 tunnel to a downstream anchor. Already on the session.
        //   2. the statically configured anchor: `upf-address` + `upf-teid`.
        //   3. self-allocated — MUP-U *is* the anchor UPF, so it owns the core
        //      receive F-TEID: its own address (`local_ip`) plus a fresh
        //      TEID. A real UPF allocates the TEIDs of the tunnels it
        //      terminates.
        // teid 0 is the null TEID and never a valid tunnel, so a learned or
        // configured 0 self-allocates too — an ST2 always carries a non-zero
        // core TEID.
        let cp_allocated = ex.n3_local;
        // Non-zero only when learned over PFCP (a Dest = Core FAR OHC).
        let learned_core = session.core_teid != 0;
        if let Some((teid, addr)) = cp_allocated {
            session.core_teid = teid;
            session.core_endpoint = Some(addr);
        } else {
            session.core_endpoint = session
                .core_endpoint
                .or(self.config.upf_address)
                .or(Some(self.local_ip()));
            if !learned_core {
                session.core_teid = match self.config.upf_teid {
                    Some(teid) if teid != 0 => teid,
                    _ => self.sessions.alloc_teid(),
                };
            }
        }
        self.sessions.insert(session.clone());

        let local_ip = self.local_ip();
        // UPF role: return our N3 F-TEID in a Created PDR (PDR id 1). The SMF
        // reads the UP-side N3 F-TEID from the establishment response's
        // Created PDR (TS 29.244 §7.5.3) and hands it to the gNB as the
        // uplink tunnel target — without it the CP cannot complete the PDU
        // session. When the core F-TEID is ours (CP-allocated, configured
        // anchor, or self-anchored — the UPF itself terminates the uplink
        // tunnel), the N3 F-TEID must be the SAME tunnel the ST2 describes:
        // the datapath keys the uplink decap PDR (`H.M.GTP4.D`) on the ST2's
        // endpoint+TEID, so a gNB handed anything else sends uplink into a
        // tunnel no PDR matches. Only a core F-TEID learned over PFCP (a
        // downstream anchor's N9 tunnel, not a tunnel we terminate) keeps a
        // separate nominal N3 allocation.
        let (n3_ip, n3_teid) = if let Some((teid, addr)) = cp_allocated {
            (addr, teid)
        } else if learned_core {
            (local_ip, self.sessions.alloc_teid())
        } else {
            (session.core_endpoint.unwrap_or(local_ip), session.core_teid)
        };
        let reply = build_establishment_response(cp_seid, seq, seid, local_ip, n3_ip, n3_teid);
        (reply, vec![MupCEvent::SessionUp(session)])
    }

    /// Build a rejected Session Establishment Response carrying `cause`.
    /// The header SEID echoes the CP's F-SEID so the SMF can correlate the
    /// rejection (no session was created, so our own SEID is meaningless
    /// here). An F-SEID IE is set even on rejection because the codec
    /// requires it; its value is irrelevant when the cause is not
    /// "accepted".
    fn reject_session_establishment(
        &self,
        cp_seid: u64,
        seq: SequenceNumber,
        cause: CauseValue,
    ) -> Option<Vec<u8>> {
        let local_ip = self.local_ip();
        match SessionEstablishmentResponseBuilder::new(cp_seid, seq, cause)
            .node_id(local_ip)
            .fseid(0u64, local_ip)
            .build()
        {
            Ok(resp) => Some(resp.marshal()),
            Err(e) => {
                tracing::warn!("mup-c: build rejected SessionEstablishmentResponse failed: {e}");
                None
            }
        }
    }

    fn handle_session_modification(&mut self, msg: &dyn PfcpMessage, src: SocketAddr) -> Handled {
        let seq = msg.sequence();
        // The CP addresses Modification by our F-SEID (the message SEID),
        // so it keys the table directly.
        let seid = msg.seid().map(|s| s.value()).unwrap_or(0);
        // Only the peer that owns the session may modify it; a mismatch
        // (or unknown SEID) is rejected without touching state. We have no
        // session to echo a CP F-SEID from, so the error response carries
        // the request's SEID.
        let Some(mut session) = self.sessions.get(seid).filter(|s| s.peer == src).cloned() else {
            let resp = SessionModificationResponseBuilder::new(seid, seq)
                .cause(CauseValue::SessionContextNotFound)
                .build();
            return (Some(resp.marshal()), Vec::new());
        };
        // Merge in whatever this modification carries. In 5G the gNB GTP-U
        // tunnel is programmed *here* — in an Update FAR's Outer Header
        // Creation, after the N2 PDU-session setup completes — not in the
        // establishment, so the Type-1 ST endpoint/TEID typically first
        // becomes known at modification time. Only overwrite a field the
        // modification actually provides (a modification carries just the
        // changed IEs, so an absent field means "unchanged").
        let ex = extract_pfcp(msg);
        if let Some((t, e)) = ex.gnb {
            session.teid = t;
            session.endpoint = Some(e);
        } else if ex.downlink_deactivated {
            // AN release / UE idle: tear down the gNB tunnel so the Type-1 ST
            // route is withdrawn (re-emitting `SessionUp` with no endpoint
            // makes the per-VRF `MupOriginate` handler withdraw and not
            // re-originate). A later activation modification re-programs it.
            session.teid = 0;
            session.endpoint = None;
        }
        if let Some((t, e)) = ex.n3_local {
            // CP-(re)allocated uplink receive F-TEID — authoritative (see
            // the establishment tiers).
            session.core_teid = t;
            session.core_endpoint = Some(e);
        } else if let Some((t, e)) = ex.core {
            session.core_teid = t;
            session.core_endpoint = Some(e);
        }
        if ex.ue_ipv4.is_some() {
            session.ue_ipv4 = ex.ue_ipv4;
        }
        if ex.ue_ipv6.is_some() {
            session.ue_ipv6 = ex.ue_ipv6;
        }
        if ex.network_instance.is_some() {
            session.network_instance = ex.network_instance;
        }
        self.sessions.insert(session.clone());
        // The response header SEID echoes the CP's F-SEID, not our own.
        let resp = SessionModificationResponseBuilder::new(session.cp_seid, seq)
            .cause_accepted()
            .build();
        (Some(resp.marshal()), vec![MupCEvent::SessionUp(session)])
    }

    fn handle_session_deletion(&mut self, msg: &dyn PfcpMessage, src: SocketAddr) -> Handled {
        let seq = msg.sequence();
        let seid = msg.seid().map(|s| s.value()).unwrap_or(0);
        // Only the peer that owns the session may delete it.
        let Some(cp_seid) = self
            .sessions
            .get(seid)
            .filter(|s| s.peer == src)
            .map(|s| s.cp_seid)
        else {
            let resp = SessionDeletionResponseBuilder::new(seid, seq)
                .cause(CauseValue::SessionContextNotFound)
                .build();
            return (Some(resp.marshal()), Vec::new());
        };
        self.sessions.remove(seid);
        // Header SEID echoes the CP's F-SEID so the SMF correlates it.
        let resp = SessionDeletionResponseBuilder::new(cp_seid, seq)
            .cause_accepted()
            .build();
        (Some(resp.marshal()), vec![MupCEvent::SessionDown { seid }])
    }
}

/// Build an accepted Session Establishment Response carrying our N3 F-TEID
/// (`n3_ip` + `n3_teid` — the uplink tunnel we terminate) in a Created PDR
/// (PDR id 1). The SMF reads the UP-side N3 F-TEID from here to give the gNB
/// an uplink target. `node_ip` is the N4 identity (Node ID + F-SEID address)
/// and may differ from `n3_ip`. The response header SEID = the CP's F-SEID
/// (so the SMF correlates it); our own SEID rides only in the F-SEID IE.
/// Returns `None` if the codec fails to build the message.
fn build_establishment_response(
    cp_seid: u64,
    seq: SequenceNumber,
    up_seid: u64,
    node_ip: IpAddr,
    n3_ip: IpAddr,
    n3_teid: u32,
) -> Option<Vec<u8>> {
    let fteid = {
        let b = FteidBuilder::new().teid(n3_teid);
        let b = match n3_ip {
            IpAddr::V4(v4) => b.ipv4(v4),
            IpAddr::V6(v6) => b.ipv6(v6),
        };
        match b.build() {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("mup-c: build N3 F-TEID failed: {e}");
                return None;
            }
        }
    };
    let created = CreatedPdr::new(PdrId::new(1), fteid).to_ie();
    match SessionEstablishmentResponseBuilder::accepted(cp_seid, seq)
        .node_id(node_ip)
        .fseid(up_seid, node_ip)
        .created_pdr(created)
        .build()
    {
        Ok(resp) => Some(resp.marshal()),
        Err(e) => {
            tracing::warn!("mup-c: build SessionEstablishmentResponse failed: {e}");
            None
        }
    }
}

/// Extract the CP's F-SEID from a Session Establishment Request's F-SEID
/// IE (`0` if absent — a malformed request, but the codec still needs a
/// value for the response header).
fn cp_fseid(msg: &dyn PfcpMessage) -> u64 {
    msg.ies(IeType::Fseid)
        .next()
        .and_then(|ie| Fseid::unmarshal(&ie.payload).ok())
        .map(|f| f.seid.value())
        .unwrap_or(0)
}

/// Receive datagrams forever, forwarding each to the controller event
/// loop. Exits when the controller is gone (send fails).
async fn recv_loop(sock: Arc<UdpSocket>, tx: UnboundedSender<Message>) {
    let mut buf = vec![0u8; 65535];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, src)) => {
                if tx
                    .send(Message::PfcpRecv {
                        data: buf[..n].to_vec(),
                        src,
                    })
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                // Transient (e.g. an ICMP port-unreachable surfaced on a
                // prior send). Log and keep listening.
                tracing::warn!("mup-c: PFCP recv error: {e}");
            }
        }
    }
}

/// Build a PFCP `NodeId` from an IP address.
fn node_from_ip(ip: IpAddr) -> NodeId {
    match ip {
        IpAddr::V4(v4) => NodeId::new_ipv4(v4),
        IpAddr::V6(v6) => NodeId::new_ipv6(v6),
    }
}

/// Human-readable form of a PFCP `NodeId`.
fn node_id_string(node_id: &NodeId) -> String {
    match node_id {
        NodeId::IPv4(addr) => addr.to_string(),
        NodeId::IPv6(addr) => addr.to_string(),
        NodeId::FQDN(fqdn) => fqdn.clone(),
    }
}

/// The session fields extracted from one PFCP Session Establishment or
/// Modification message. Every field is optional so a modification (which
/// carries only the changed IEs) can be merged into an existing session.
#[derive(Default)]
struct PfcpExtract {
    ue_ipv4: Option<std::net::Ipv4Addr>,
    ue_ipv6: Option<std::net::Ipv6Addr>,
    network_instance: Option<String>,
    /// gNB (access-side) GTP-U F-TEID — the `(TEID, endpoint)` the UPF
    /// encapsulates *downlink* traffic toward. Drives the Type-1 ST route.
    gnb: Option<(u32, IpAddr)>,
    /// Core-side GTP-U F-TEID — the `(TEID, endpoint)` of a core-facing GTP
    /// tunnel (e.g. an N9 to an anchor UPF). Drives the Type-2 ST route.
    /// Absent for a plain N6 breakout, which has no core-side GTP tunnel.
    core: Option<(u32, IpAddr)>,
    /// The UPF's own uplink *receive* F-TEID when the CP allocated it
    /// (TS 29.244 CH=0): the Access-side PDR's PDI local F-TEID. The SMF
    /// hands this same TEID to the gNB as the uplink target (free5GC
    /// allocates all UPF N3 TEIDs this way and ignores the Created PDR), so
    /// when present it is authoritative for the Type-2 ST route / uplink
    /// decap PDR. Absent when the CP asks the UP to choose (CH=1) or sends
    /// no PDI F-TEID.
    n3_local: Option<(u32, IpAddr)>,
    /// The message deactivated the downlink: an Update FAR switched to
    /// BUFF/DROP with no new Outer Header Creation (the AN-release / UE-idle
    /// flow). The gNB tunnel is torn down, so the Type-1 ST route must be
    /// withdrawn until a later modification re-programs it.
    downlink_deactivated: bool,
}

/// `(TEID, endpoint)` of a GTP-U Outer Header Creation, or `None` when the
/// OHC is not a GTP-U tunnel (e.g. an N6 native-IP forward) or lacks a
/// TEID/address.
fn ohc_gtpu(ohc: &OuterHeaderCreation) -> Option<(u32, IpAddr)> {
    if !(ohc.description.gtpu_udp_ipv4 || ohc.description.gtpu_udp_ipv6) {
        return None;
    }
    let teid = ohc.teid.as_ref()?.value();
    let addr = ohc
        .ipv4_address
        .map(IpAddr::V4)
        .or(ohc.ipv6_address.map(IpAddr::V6))?;
    Some((teid, addr))
}

/// Fold one FAR's forwarding info into `ex`: a GTP-U Outer Header Creation
/// bound for the `Access` interface is the gNB (downlink) tunnel (Type-1 ST);
/// one bound for `Core` is the core-facing tunnel (Type-2 ST). A GTP-U OHC
/// with no destination interface — an Update FAR that carries only the
/// changed OHC — is the downlink/gNB tunnel in every standard 5G call flow,
/// so it defaults to `Access`. The first tunnel of each kind wins.
fn apply_far_ohc(
    ex: &mut PfcpExtract,
    dest: Option<DestInterface>,
    ohc: Option<&OuterHeaderCreation>,
) {
    let Some(tunnel) = ohc.and_then(ohc_gtpu) else {
        return;
    };
    match dest.unwrap_or(DestInterface::Access) {
        DestInterface::Core => {
            if ex.core.is_none() {
                ex.core = Some(tunnel);
            }
        }
        _ => {
            if ex.gnb.is_none() {
                ex.gnb = Some(tunnel);
            }
        }
    }
}

/// Extract the MUP-relevant session fields from a PFCP Establishment or
/// Modification message.
///
/// UE IP and Network Instance come from the Create PDRs (matched by UE
/// address / carried per-PDI). The *remote* GTP-U tunnel endpoints come from
/// the **FARs' Outer Header Creation** (draft-ietf-bess-mup-safi §3.2.1 /
/// TS 29.244):
///
///   * The Type-1 ST route's endpoint is the **gNB** (the access-side tunnel
///     the PE encapsulates downlink traffic toward). In PFCP that gNB F-TEID
///     lives in the **downlink FAR's Outer Header Creation** (Destination
///     Interface = Access), which the SMF programs from the N2 setup — often
///     only in a later Session Modification. It never comes from a PDI
///     F-TEID (that is the UPF's own side, not the gNB).
///   * The Type-2 ST route's endpoint is the tunnel this UPF *terminates*
///     for uplink. When the CP allocates the UPF's N3 F-TEID itself
///     (TS 29.244 CH=0 — free5GC always does), it arrives in the
///     **Access-side PDR's PDI local F-TEID** and is authoritative
///     (`n3_local`). A FAR bound for the Core interface instead carries a
///     core-facing tunnel (N9 / interworking) toward a downstream anchor.
fn extract_pfcp(msg: &dyn PfcpMessage) -> PfcpExtract {
    let mut ex = PfcpExtract::default();
    // UE IP + Network Instance from the PDRs (source-interface-agnostic).
    for ie in msg.ies(IeType::CreatePdr) {
        let Ok(pdr) = CreatePdr::unmarshal(&ie.payload) else {
            continue;
        };
        let pdi = &pdr.pdi;
        if let Some(ue) = &pdi.ue_ip_address {
            if ue.ipv4_address.is_some() {
                ex.ue_ipv4 = ue.ipv4_address;
            }
            if ue.ipv6_address.is_some() {
                ex.ue_ipv6 = ue.ipv6_address;
            }
        }
        if ex.network_instance.is_none()
            && let Some(ni) = &pdi.network_instance
        {
            ex.network_instance = Some(ni.instance.clone());
        }
        // The Access PDR's PDI local F-TEID: the CP-allocated (CH=0) uplink
        // receive tunnel. The remote tunnels stay FAR-OHC-only (below); this
        // one is *ours* and keys the uplink decap.
        if ex.n3_local.is_none()
            && pdi.source_interface.value == SourceInterfaceValue::Access
            && let Some(f) = &pdi.f_teid
            && !f.ch
            && f.teid.value() != 0
            && let Some(addr) = f
                .ipv4_address
                .map(IpAddr::V4)
                .or(f.ipv6_address.map(IpAddr::V6))
        {
            ex.n3_local = Some((f.teid.value(), addr));
        }
    }
    // GTP-U tunnel endpoints from the FARs' Outer Header Creation.
    for ie in msg.ies(IeType::CreateFar) {
        let Ok(far) = CreateFar::unmarshal(&ie.payload) else {
            continue;
        };
        if let Some(fp) = &far.forwarding_parameters {
            apply_far_ohc(
                &mut ex,
                Some(fp.destination_interface.interface),
                fp.outer_header_creation.as_ref(),
            );
            if ex.network_instance.is_none()
                && let Some(ni) = &fp.network_instance
            {
                ex.network_instance = Some(ni.instance.clone());
            }
        }
    }
    for ie in msg.ies(IeType::UpdateFar) {
        let Ok(far) = UpdateFar::unmarshal(&ie.payload) else {
            continue;
        };
        let ohc = far
            .update_forwarding_parameters
            .as_ref()
            .and_then(|fp| fp.outer_header_creation.as_ref());
        if let Some(fp) = &far.update_forwarding_parameters {
            apply_far_ohc(
                &mut ex,
                fp.destination_interface.as_ref().map(|d| d.interface),
                fp.outer_header_creation.as_ref(),
            );
        }
        // A FAR that switches to BUFF/DROP without programming a new GTP-U
        // tunnel is an AN-release / UE-idle deactivation — the downlink gNB
        // tunnel is gone.
        if ohc.is_none()
            && far
                .apply_action
                .is_some_and(|aa| aa.intersects(ApplyAction::BUFF | ApplyAction::DROP))
        {
            ex.downlink_deactivated = true;
        }
    }
    ex
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rs_pfcp::ie::IeType;
    use rs_pfcp::ie::apply_action::ApplyAction;
    use rs_pfcp::ie::create_far::CreateFar;
    use rs_pfcp::ie::create_pdr::CreatePdrBuilder;
    use rs_pfcp::ie::created_pdr::CreatedPdr;
    use rs_pfcp::ie::destination_interface::{DestinationInterface, Interface};
    use rs_pfcp::ie::f_teid::FteidBuilder;
    use rs_pfcp::ie::far_id::FarId;
    use rs_pfcp::ie::forwarding_parameters::ForwardingParameters;
    use rs_pfcp::ie::network_instance::NetworkInstance;
    use rs_pfcp::ie::outer_header_creation::OuterHeaderCreation;
    use rs_pfcp::ie::pdi::PdiBuilder;
    use rs_pfcp::ie::pdr_id::PdrId;
    use rs_pfcp::ie::precedence::Precedence;
    use rs_pfcp::ie::source_interface::{SourceInterface, SourceInterfaceValue};
    use rs_pfcp::ie::ue_ip_address::UeIpAddress;
    use rs_pfcp::ie::update_far::UpdateFar;
    use rs_pfcp::ie::update_forwarding_parameters::UpdateForwardingParameters;
    use rs_pfcp::message::association_setup_request::AssociationSetupRequestBuilder;
    use rs_pfcp::message::heartbeat_request::HeartbeatRequestBuilder;
    use rs_pfcp::message::session_deletion_request::SessionDeletionRequestBuilder;
    use rs_pfcp::message::session_establishment_request::SessionEstablishmentRequestBuilder;
    use rs_pfcp::message::session_modification_request::SessionModificationRequestBuilder;
    use rs_pfcp::message::{self, Message as PfcpMessage, MsgType};

    use super::super::inst::{MupC, MupCConfig, MupCEvent};
    use std::net::{IpAddr, SocketAddr};

    fn peer() -> SocketAddr {
        "10.0.0.2:8805".parse().unwrap()
    }

    /// Establish the association that `peer()` must hold before the
    /// controller will accept its session messages.
    fn associate(mupc: &mut MupC) {
        let asr = AssociationSetupRequestBuilder::new(1u32)
            .node_id(Ipv4Addr::new(10, 0, 0, 2))
            .recovery_time_stamp(std::time::SystemTime::now())
            .build()
            .marshal();
        let msg = message::parse(&asr).unwrap();
        let _ = mupc.handle_association_setup(msg.as_ref(), peer());
    }

    /// A Create FAR that forwards to `dest` and GTP-U-encapsulates toward
    /// `(teid, addr)` — the wire shape the SMF programs the gNB (Dest =
    /// Access) or a core (Dest = Core) tunnel with. This is where the ST
    /// endpoints come from, not the PDI F-TEIDs.
    fn gtpu_far(far_id: u32, dest: Interface, teid: u32, addr: Ipv4Addr) -> CreateFar {
        let fp = ForwardingParameters::new(DestinationInterface::new(dest))
            .with_outer_header_creation(OuterHeaderCreation::gtpu_ipv4(teid, addr));
        CreateFar::builder(FarId::new(far_id))
            .apply_action(ApplyAction::FORW)
            .forwarding_parameters(fp)
            .build()
            .unwrap()
    }

    /// A Session Establishment Request carrying UE IPv4 + Network Instance in
    /// a PDR, the UPF's *own* CP-allocated N3 receive F-TEID in that PDR's
    /// PDI (TS 29.244 CH=0 — authoritative for the uplink tunnel: free5GC
    /// hands this same TEID to the gNB), and the gNB tunnel in a downlink
    /// FAR's Outer Header Creation (Destination Interface = Access) — the
    /// endpoint the controller must pick for the Type-1 ST route.
    fn establishment_bytes() -> Vec<u8> {
        let upf_n3 = FteidBuilder::new()
            .teid(0xDEAD_BEEFu32)
            .ipv4(Ipv4Addr::new(127, 0, 0, 8))
            .build()
            .unwrap();
        let pdi = PdiBuilder::new(SourceInterface::new(SourceInterfaceValue::Access))
            .f_teid(upf_n3)
            .ue_ip_address(UeIpAddress::new(Some(Ipv4Addr::new(192, 0, 2, 5)), None))
            .network_instance(NetworkInstance::new("internet.apn"))
            .build()
            .unwrap();
        let pdr = CreatePdrBuilder::new(PdrId::new(1))
            .precedence(Precedence::new(100))
            .pdi(pdi)
            .far_id(FarId::new(1))
            .build()
            .unwrap();
        let far = gtpu_far(
            1,
            Interface::Access,
            0x1234_5678,
            Ipv4Addr::new(10, 0, 0, 1),
        );
        SessionEstablishmentRequestBuilder::new(0u64, 1u32)
            .node_id(Ipv4Addr::new(10, 0, 0, 2))
            .fseid(0x1111u64, Ipv4Addr::new(10, 0, 0, 2))
            .create_pdrs(vec![pdr.to_ie()])
            .create_fars(vec![far.to_ie()])
            .build()
            .unwrap()
            .marshal()
    }

    /// Like [`establishment_bytes`] but with no PDI F-TEID: the CP left the
    /// uplink F-TEID allocation to the UP (or omitted it), so the lower
    /// resolution tiers (configured anchor / self-allocation) apply.
    fn establishment_no_local_fteid_bytes() -> Vec<u8> {
        let pdi = PdiBuilder::new(SourceInterface::new(SourceInterfaceValue::Access))
            .ue_ip_address(UeIpAddress::new(Some(Ipv4Addr::new(192, 0, 2, 5)), None))
            .network_instance(NetworkInstance::new("internet.apn"))
            .build()
            .unwrap();
        let pdr = CreatePdrBuilder::new(PdrId::new(1))
            .precedence(Precedence::new(100))
            .pdi(pdi)
            .far_id(FarId::new(1))
            .build()
            .unwrap();
        let far = gtpu_far(
            1,
            Interface::Access,
            0x1234_5678,
            Ipv4Addr::new(10, 0, 0, 1),
        );
        SessionEstablishmentRequestBuilder::new(0u64, 1u32)
            .node_id(Ipv4Addr::new(10, 0, 0, 2))
            .fseid(0x1111u64, Ipv4Addr::new(10, 0, 0, 2))
            .create_pdrs(vec![pdr.to_ie()])
            .create_fars(vec![far.to_ie()])
            .build()
            .unwrap()
            .marshal()
    }

    /// A Session Establishment Request with both a gNB tunnel (downlink FAR,
    /// Dest = Access → Type-1 ST) and a core tunnel (FAR, Dest = Core →
    /// Type-2 ST), so the controller captures a distinct endpoint per side.
    fn establishment_two_endpoints_bytes() -> Vec<u8> {
        let pdi = PdiBuilder::new(SourceInterface::new(SourceInterfaceValue::Access))
            .ue_ip_address(UeIpAddress::new(Some(Ipv4Addr::new(192, 0, 2, 5)), None))
            .network_instance(NetworkInstance::new("internet.apn"))
            .build()
            .unwrap();
        let pdr = CreatePdrBuilder::new(PdrId::new(1))
            .precedence(Precedence::new(100))
            .pdi(pdi)
            .far_id(FarId::new(1))
            .build()
            .unwrap();
        let gnb = gtpu_far(
            1,
            Interface::Access,
            0x1234_5678,
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let core = gtpu_far(2, Interface::Core, 0x8765_4321, Ipv4Addr::new(10, 9, 0, 1));
        SessionEstablishmentRequestBuilder::new(0u64, 1u32)
            .node_id(Ipv4Addr::new(10, 0, 0, 2))
            .fseid(0x1111u64, Ipv4Addr::new(10, 0, 0, 2))
            .create_pdrs(vec![pdr.to_ie()])
            .create_fars(vec![gnb.to_ie(), core.to_ie()])
            .build()
            .unwrap()
            .marshal()
    }

    #[test]
    fn session_establishment_captures_access_and_core_endpoints() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        associate(&mut mupc);
        let bytes = establishment_two_endpoints_bytes();
        let msg = message::parse(&bytes).unwrap();
        let (reply, events) = mupc.handle_session_establishment(msg.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp, got {:?}", events[0]);
        };
        // gNB (Type-1 ST) endpoint from the downlink FAR (Dest = Access) OHC.
        assert_eq!(session.teid, 0x1234_5678);
        assert_eq!(
            session.endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        // Core (Type-2 ST) endpoint from the FAR (Dest = Core) OHC — distinct.
        assert_eq!(session.core_teid, 0x8765_4321);
        assert_eq!(
            session.core_endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)))
        );
        // A learned core F-TEID is a downstream anchor's N9 tunnel, not one
        // we terminate — the N3 F-TEID stays a separate own allocation.
        let resp = message::parse(&reply.expect("a response")).unwrap();
        let created = resp
            .ies(IeType::CreatedPdr)
            .next()
            .and_then(|ie| CreatedPdr::unmarshal(&ie.payload).ok())
            .expect("establishment response must carry a Created PDR");
        assert_ne!(created.f_teid.teid.value(), 0);
        assert_ne!(
            created.f_teid.teid.value(),
            0x8765_4321,
            "learned N9 core TEID must not be echoed as our N3 F-TEID"
        );
    }

    /// An establishment that carries the UE IP + NI but a downlink FAR with no
    /// Outer Header Creation yet — the state right after PDU-session setup,
    /// before the N2 tunnel is programmed. No gNB endpoint is known yet.
    fn establishment_no_gnb_bytes() -> Vec<u8> {
        let pdi = PdiBuilder::new(SourceInterface::new(SourceInterfaceValue::Access))
            .ue_ip_address(UeIpAddress::new(Some(Ipv4Addr::new(192, 0, 2, 5)), None))
            .network_instance(NetworkInstance::new("internet.apn"))
            .build()
            .unwrap();
        let pdr = CreatePdrBuilder::new(PdrId::new(1))
            .precedence(Precedence::new(100))
            .pdi(pdi)
            .far_id(FarId::new(1))
            .build()
            .unwrap();
        // Downlink FAR present but no GTP-U OHC yet (buffer/drop until N2).
        let far = CreateFar::builder(FarId::new(1))
            .forward_to(Interface::Access)
            .build()
            .unwrap();
        SessionEstablishmentRequestBuilder::new(0u64, 1u32)
            .node_id(Ipv4Addr::new(10, 0, 0, 2))
            .fseid(0x1111u64, Ipv4Addr::new(10, 0, 0, 2))
            .create_pdrs(vec![pdr.to_ie()])
            .create_fars(vec![far.to_ie()])
            .build()
            .unwrap()
            .marshal()
    }

    /// The MUP-C learns the gNB tunnel from a Session *Modification* (post-N2),
    /// not the establishment: an Update FAR whose Update Forwarding Parameters
    /// program the gNB GTP-U Outer Header Creation. Before it, the Type-1 ST
    /// endpoint is unknown; after it, it is populated.
    #[test]
    fn session_modification_learns_gnb_tunnel() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        associate(&mut mupc);

        // Establishment: UE IP + NI, but no gNB tunnel yet.
        let est = message::parse(&establishment_no_gnb_bytes()).unwrap();
        let (_reply, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        let seid = session.seid;
        assert_eq!(
            session.endpoint, None,
            "no gNB tunnel known at establishment"
        );
        assert_eq!(session.teid, 0);

        // Modification: program the gNB tunnel in an Update FAR's OHC.
        let ufp = UpdateForwardingParameters::new()
            .with_destination_interface(DestinationInterface::new(Interface::Access))
            .with_outer_header_creation(OuterHeaderCreation::gtpu_ipv4(
                0x1234_5678u32,
                Ipv4Addr::new(10, 0, 0, 1),
            ));
        let ufar = UpdateFar::builder(FarId::new(1))
            .update_forwarding_parameters(ufp)
            .build()
            .unwrap();
        let modify = SessionModificationRequestBuilder::new(seid, 3u32)
            .update_fars(vec![ufar.to_ie()])
            .build()
            .marshal();
        let msg = message::parse(&modify).unwrap();
        let (_reply, events) = mupc.handle_session_modification(msg.as_ref(), peer());

        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp after modification");
        };
        // The gNB (Type-1 ST) endpoint/TEID are now learned from the Update FAR.
        assert_eq!(
            session.endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(session.teid, 0x1234_5678);
        // Pre-existing fields survive the merge.
        assert_eq!(session.ue_ipv4, Some(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(session.network_instance.as_deref(), Some("internet.apn"));
        // And the stored session reflects the update.
        assert_eq!(
            mupc.sessions.get(seid).and_then(|s| s.endpoint),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    /// AN release / UE idle: a Session Modification whose Update FAR switches
    /// to BUFF with no Outer Header Creation tears down the gNB tunnel, so the
    /// controller clears the Type-1 ST endpoint (which makes the per-VRF
    /// origination withdraw the ST1). A later activation re-programs it.
    #[test]
    fn session_modification_deactivates_downlink() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        associate(&mut mupc);

        // Establish with a gNB tunnel already present.
        let est = message::parse(&establishment_bytes()).unwrap();
        let (_reply, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        let seid = session.seid;
        assert_eq!(
            session.endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "gNB tunnel present after establishment"
        );

        // Deactivate: Update FAR → BUFF, no OHC.
        let ufar = UpdateFar::builder(FarId::new(1))
            .apply_action(ApplyAction::BUFF)
            .build()
            .unwrap();
        let modify = SessionModificationRequestBuilder::new(seid, 4u32)
            .update_fars(vec![ufar.to_ie()])
            .build()
            .marshal();
        let msg = message::parse(&modify).unwrap();
        let (_reply, events) = mupc.handle_session_modification(msg.as_ref(), peer());

        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp after deactivation");
        };
        // The gNB tunnel is torn down → Type-1 ST endpoint cleared.
        assert_eq!(session.endpoint, None, "gNB tunnel cleared on deactivation");
        assert_eq!(session.teid, 0);
        // UE IP survives — the session still exists, just idle.
        assert_eq!(session.ue_ipv4, Some(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(mupc.sessions.get(seid).and_then(|s| s.endpoint), None);
    }

    #[test]
    fn session_establishment_extracts_and_acks() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        associate(&mut mupc);
        let bytes = establishment_bytes();
        let msg = message::parse(&bytes).unwrap();
        let (reply, events) = mupc.handle_session_establishment(msg.as_ref(), peer());

        assert_eq!(events.len(), 1);
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp, got {:?}", events[0]);
        };
        assert_eq!(session.ue_ipv4, Some(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(session.teid, 0x1234_5678);
        assert_eq!(
            session.endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(session.network_instance.as_deref(), Some("internet.apn"));
        assert_eq!(session.peer, peer());
        assert!(mupc.sessions.get(session.seid).is_some());

        // We learned the CP's F-SEID (0x1111, from the request's F-SEID
        // IE) so later Modification/Deletion responses can echo it.
        assert_eq!(session.cp_seid, 0x1111);

        let reply = reply.expect("a Session Establishment Response");
        let resp = message::parse(&reply).unwrap();
        assert_eq!(resp.msg_type(), MsgType::SessionEstablishmentResponse);
        // Regression (free5GC interop): the response header SEID must echo
        // the CP's F-SEID (0x1111), NOT our own allocated SEID. A strict
        // SMF rejects the establishment otherwise ("received unexpected
        // SEID response message").
        assert_eq!(
            resp.seid().map(|s| s.value()),
            Some(0x1111),
            "establishment response must echo the CP F-SEID in the header"
        );
        assert_ne!(
            resp.seid().map(|s| s.value()),
            Some(session.seid),
            "header SEID must not be our own allocated SEID"
        );

        // UPF role: the response must return our allocated N3 F-TEID in a
        // Created PDR (PDR id 1) — the SMF reads the UP N3 F-TEID from here to
        // give the gNB an uplink target. Without it a strict SMF (radian-rs)
        // cannot complete the PDU session.
        let created = resp
            .ies(IeType::CreatedPdr)
            .next()
            .and_then(|ie| CreatedPdr::unmarshal(&ie.payload).ok())
            .expect("establishment response must carry a Created PDR");
        assert_ne!(created.f_teid.teid.value(), 0, "N3 F-TEID must be non-zero");
        // The CP allocated the uplink F-TEID (PDI local F-TEID, CH=0): it is
        // authoritative — the SMF hands that same TEID to the gNB — so both
        // the ST2 core tunnel and the echoed Created PDR must carry it.
        assert_eq!(session.core_teid, 0xDEAD_BEEF);
        assert_eq!(
            session.core_endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)))
        );
        assert_eq!(created.f_teid.teid.value(), 0xDEAD_BEEF);
        assert_eq!(
            created.f_teid.ipv4_address,
            Some(Ipv4Addr::new(127, 0, 0, 8)),
            "Created PDR echoes the CP-allocated N3 F-TEID"
        );
        // The N3 F-TEID handed to the SMF IS the tunnel the ST2 describes —
        // the gNB sends uplink with this TEID, and the datapath keys the
        // decap PDR on the ST2's endpoint+TEID. Anything else sends every
        // uplink packet into an unmatched tunnel.
        assert_eq!(
            created.f_teid.teid.value(),
            session.core_teid,
            "Created PDR N3 TEID must equal the ST2 core TEID"
        );
    }

    /// The self-anchored tiers (Created-PDR allocation) apply only when the
    /// CP did not allocate the uplink F-TEID itself. When it did (PDI local
    /// F-TEID, CH=0), that tunnel wins over a configured `upf-address` /
    /// `upf-teid` too.
    #[test]
    fn cp_allocated_n3_fteid_beats_configured_anchor() {
        let cfg = MupCConfig {
            upf_address: Some(IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1))),
            upf_teid: Some(0x0102_0304),
            ..Default::default()
        };
        let (mut mupc, _bgp_rx) = MupC::new_for_test(cfg);
        associate(&mut mupc);
        let est = message::parse(&establishment_bytes()).unwrap();
        let (_reply, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        assert_eq!(session.core_teid, 0xDEAD_BEEF);
        assert_eq!(
            session.core_endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8))),
            "CP-allocated local F-TEID beats the configured anchor"
        );
    }

    /// N6 breakout: a session with only an access/gNB tunnel (no core-side
    /// F-TEID) gets its Type-2 ST endpoint AND TEID from the configured
    /// `upf-address` / `upf-teid` (both are needed for an ST2).
    #[test]
    fn upf_address_fills_core_endpoint_for_n6_breakout() {
        let cfg = MupCConfig {
            upf_address: Some(IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1))),
            upf_teid: Some(0x0102_0304),
            ..Default::default()
        };
        let (mut mupc, _bgp_rx) = MupC::new_for_test(cfg);
        associate(&mut mupc);
        // A gNB tunnel (Access FAR OHC) but no core-side tunnel and no
        // CP-allocated local F-TEID.
        let est = message::parse(&establishment_no_local_fteid_bytes()).unwrap();
        let (reply, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        assert_eq!(
            session.core_endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1))),
            "no core tunnel → ST2 endpoint from configured upf-address"
        );
        assert_eq!(
            session.core_teid, 0x0102_0304,
            "no core F-TEID → ST2 TEID from configured upf-teid"
        );
        // The gNB (access) side is unaffected (and is NOT copied to the core).
        assert_eq!(
            session.endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        // The configured anchor is a tunnel WE terminate, so the N3 F-TEID
        // handed to the SMF must be that same tunnel, not a fresh allocation
        // at the N4 address.
        let resp = message::parse(&reply.expect("a response")).unwrap();
        let created = resp
            .ies(IeType::CreatedPdr)
            .next()
            .and_then(|ie| CreatedPdr::unmarshal(&ie.payload).ok())
            .expect("establishment response must carry a Created PDR");
        assert_eq!(created.f_teid.teid.value(), 0x0102_0304);
        assert_eq!(
            created.f_teid.ipv4_address,
            Some(Ipv4Addr::new(10, 100, 0, 1)),
            "Created PDR F-TEID address = configured upf-address"
        );
    }

    /// A session that learns a core-side F-TEID over PFCP (e.g. an N9 tunnel)
    /// keeps that learned endpoint in preference to the configured one.
    #[test]
    fn learned_core_endpoint_beats_upf_address() {
        let cfg = MupCConfig {
            upf_address: Some(IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1))),
            ..Default::default()
        };
        let (mut mupc, _bgp_rx) = MupC::new_for_test(cfg);
        associate(&mut mupc);
        let est = message::parse(&establishment_two_endpoints_bytes()).unwrap();
        let (_reply, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        assert_eq!(
            session.core_endpoint,
            Some(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))),
            "learned core F-TEID wins over configured upf-address"
        );
    }

    /// MUP-U as the anchor UPF: a session with no learned core F-TEID and no
    /// configured `upf-address`/`upf-teid` still originates an ST2 — the UPF
    /// allocates its own core receive F-TEID (a non-zero TEID at its own
    /// `local_ip`), just as it allocates the N3 F-TEID. It is never borrowed
    /// from the access/gNB tunnel.
    #[test]
    fn anchor_upf_self_allocates_core_teid() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        associate(&mut mupc);
        // A gNB tunnel (access teid 0x1234_5678) but no core tunnel, no
        // CP-allocated local F-TEID, and no upf-address / upf-teid configured.
        let est = message::parse(&establishment_no_local_fteid_bytes()).unwrap();
        let (_reply, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        assert_ne!(
            session.core_teid, 0,
            "anchor UPF self-allocates a non-zero core F-TEID for the ST2"
        );
        assert_eq!(
            session.core_endpoint,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "self-allocated core tunnel terminates at the UPF's own address"
        );
        assert_ne!(
            session.core_teid, session.teid,
            "core F-TEID is self-allocated, not copied from the access tunnel"
        );
    }

    #[test]
    fn session_deletion_removes_session() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        associate(&mut mupc);
        let est = message::parse(&establishment_bytes()).unwrap();
        let (_, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        let seid = session.seid;

        let del = SessionDeletionRequestBuilder::new(seid, 2u32)
            .build()
            .marshal();
        let msg = message::parse(&del).unwrap();
        let (reply, events) = mupc.handle_session_deletion(msg.as_ref(), peer());

        assert!(mupc.sessions.get(seid).is_none());
        assert!(
            matches!(events.as_slice(), [MupCEvent::SessionDown { seid: s }] if *s == seid),
            "expected SessionDown {{ {seid} }}, got {events:?}"
        );
        let resp = message::parse(&reply.unwrap()).unwrap();
        assert_eq!(resp.msg_type(), MsgType::SessionDeletionResponse);
    }

    #[test]
    fn session_without_association_is_rejected() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        // No association established for peer().
        let msg = message::parse(&establishment_bytes()).unwrap();
        let (reply, events) = mupc.handle_session_establishment(msg.as_ref(), peer());

        assert!(
            events.is_empty(),
            "no session learned without an association"
        );
        assert!(mupc.sessions.get(1).is_none(), "no session inserted");
        let resp = message::parse(&reply.unwrap()).unwrap();
        assert_eq!(resp.msg_type(), MsgType::SessionEstablishmentResponse);
    }

    #[test]
    fn foreign_peer_cannot_delete_session() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        associate(&mut mupc);
        let est = message::parse(&establishment_bytes()).unwrap();
        let (_, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        let seid = session.seid;

        // A different peer tries to delete the session by SEID.
        let other: SocketAddr = "10.9.9.9:8805".parse().unwrap();
        let del = SessionDeletionRequestBuilder::new(seid, 9u32)
            .build()
            .marshal();
        let msg = message::parse(&del).unwrap();
        let (reply, events) = mupc.handle_session_deletion(msg.as_ref(), other);

        assert!(events.is_empty(), "foreign delete emits no event");
        assert!(
            mupc.sessions.get(seid).is_some(),
            "session survives a foreign delete"
        );
        let _ = reply.expect("a (rejected) response is still sent");
    }

    #[test]
    fn heartbeat_is_answered() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        let hb = HeartbeatRequestBuilder::new(7u32)
            .recovery_time_stamp(std::time::SystemTime::now())
            .build()
            .marshal();
        let msg = message::parse(&hb).unwrap();
        let (reply, events) = mupc.handle_heartbeat(msg.as_ref());

        assert!(events.is_empty());
        let resp = message::parse(&reply.unwrap()).unwrap();
        assert_eq!(resp.msg_type(), MsgType::HeartbeatResponse);
    }

    /// Pull the Recovery Time Stamp IE payload out of a marshalled
    /// response (the 4-byte NTP-era seconds the CP compares).
    fn recovery_ts_bytes(bytes: &[u8]) -> Vec<u8> {
        let msg = message::parse(bytes).unwrap();
        msg.ies(IeType::RecoveryTimeStamp)
            .next()
            .expect("a Recovery Time Stamp IE")
            .payload
            .clone()
    }

    #[test]
    fn node_id_is_listen_address_not_controller_address() {
        // Regression (free5GC interop): the PFCP Node ID must be our N4
        // listen address (what the CP dialed and keys its context by), not
        // the SRv6 `controller-address`. Conflating them makes free5GC
        // look up an unknown PFCPContext key and crash on a nil deref.
        let config = MupCConfig {
            controller_address: Some("fcbb:bbbb:2::1".parse().unwrap()),
            ..MupCConfig::default()
        };
        let (mut mupc, _bgp_rx) = MupC::new_for_test(config);
        mupc.listen_addr = Some("127.0.0.8:8805".parse().unwrap());

        assert_eq!(
            mupc.local_ip(),
            "127.0.0.8".parse::<IpAddr>().unwrap(),
            "Node ID must be the listen address, not the controller-address"
        );
    }

    #[test]
    fn recovery_timestamp_is_stable_across_responses() {
        // Regression (free5GC interop): the Recovery Time Stamp must not
        // change between responses, or the CP treats us as restarted and
        // releases every session ("RecoveryTimeStamp has been updated"),
        // re-establishing them forever.
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());

        let hb = HeartbeatRequestBuilder::new(1u32)
            .recovery_time_stamp(std::time::SystemTime::now())
            .build()
            .marshal();
        let msg = message::parse(&hb).unwrap();
        let (r1, _) = mupc.handle_heartbeat(msg.as_ref());
        let (r2, _) = mupc.handle_heartbeat(msg.as_ref());

        let asr = AssociationSetupRequestBuilder::new(2u32)
            .node_id(Ipv4Addr::new(10, 0, 0, 2))
            .recovery_time_stamp(std::time::SystemTime::now())
            .build()
            .marshal();
        let msg = message::parse(&asr).unwrap();
        let (r3, _) = mupc.handle_association_setup(msg.as_ref(), peer());

        let t1 = recovery_ts_bytes(&r1.unwrap());
        assert_eq!(
            t1,
            recovery_ts_bytes(&r2.unwrap()),
            "heartbeat stamp drifts"
        );
        assert_eq!(
            t1,
            recovery_ts_bytes(&r3.unwrap()),
            "association stamp differs from heartbeat stamp"
        );
    }

    #[test]
    fn reassociation_clears_prior_sessions() {
        // A second Association Setup from the same peer replaces the
        // association (TS 29.244 §6.2.6.2): its sessions must be dropped
        // (with an AssocDown so BGP withdraws their routes) so they don't
        // accumulate across CP-driven re-associations.
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        associate(&mut mupc);
        let est = message::parse(&establishment_bytes()).unwrap();
        let (_, events) = mupc.handle_session_establishment(est.as_ref(), peer());
        let MupCEvent::SessionUp(session) = &events[0] else {
            panic!("expected SessionUp");
        };
        let seid = session.seid;
        assert!(mupc.sessions.get(seid).is_some());

        // Re-setup from the same peer.
        let asr = AssociationSetupRequestBuilder::new(9u32)
            .node_id(Ipv4Addr::new(10, 0, 0, 2))
            .recovery_time_stamp(std::time::SystemTime::now())
            .build()
            .marshal();
        let msg = message::parse(&asr).unwrap();
        let (_, events) = mupc.handle_association_setup(msg.as_ref(), peer());

        assert!(
            mupc.sessions.get(seid).is_none(),
            "re-association must drop the peer's prior sessions"
        );
        assert!(
            matches!(
                events.as_slice(),
                [MupCEvent::AssocDown { peer: d }, MupCEvent::AssocUp { peer: u, .. }]
                    if *d == peer() && *u == peer()
            ),
            "re-association must emit AssocDown then AssocUp, got {events:?}"
        );
    }

    #[test]
    fn association_setup_records_peer_and_acks() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(MupCConfig::default());
        let asr = AssociationSetupRequestBuilder::new(3u32)
            .node_id(Ipv4Addr::new(10, 0, 0, 2))
            .recovery_time_stamp(std::time::SystemTime::now())
            .build()
            .marshal();
        let msg = message::parse(&asr).unwrap();
        let (reply, events) = mupc.handle_association_setup(msg.as_ref(), peer());

        assert!(
            matches!(events.as_slice(), [MupCEvent::AssocUp { peer: p, .. }] if *p == peer()),
            "expected AssocUp, got {events:?}"
        );
        let resp = message::parse(&reply.unwrap()).unwrap();
        assert_eq!(resp.msg_type(), MsgType::AssociationSetupResponse);
    }
}
