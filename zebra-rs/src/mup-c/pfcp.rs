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
use rs_pfcp::ie::cause::CauseValue;
use rs_pfcp::ie::create_pdr::CreatePdr;
use rs_pfcp::ie::fseid::Fseid;
use rs_pfcp::ie::node_id::NodeId;
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
        tracing::info!("mup-c: PFCP listening on {local:?}");
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

        // Walk the Create PDRs for the access-side F-TEID, UE IP and NI.
        let mut ue_ipv4 = None;
        let mut ue_ipv6 = None;
        let mut teid = 0u32;
        let mut endpoint = None;
        let mut network_instance = None;
        for ie in msg.ies(IeType::CreatePdr) {
            let Ok(pdr) = CreatePdr::unmarshal(&ie.payload) else {
                continue;
            };
            let pdi = &pdr.pdi;
            if let Some(f) = &pdi.f_teid {
                if teid == 0 {
                    teid = f.teid.value();
                }
                if endpoint.is_none() {
                    endpoint = f
                        .ipv4_address
                        .map(IpAddr::V4)
                        .or(f.ipv6_address.map(IpAddr::V6));
                }
            }
            if let Some(ue) = &pdi.ue_ip_address {
                if ue.ipv4_address.is_some() {
                    ue_ipv4 = ue.ipv4_address;
                }
                if ue.ipv6_address.is_some() {
                    ue_ipv6 = ue.ipv6_address;
                }
            }
            if network_instance.is_none()
                && let Some(ni) = &pdi.network_instance
            {
                network_instance = Some(ni.instance.clone());
            }
        }

        let seid = self.sessions.alloc_seid();
        let session = MupSession {
            seid,
            cp_seid,
            peer: src,
            ue_ipv4,
            ue_ipv6,
            teid,
            endpoint,
            network_instance,
            qfi: None,
        };
        self.sessions.insert(session.clone());

        let local_ip = self.local_ip();
        // Response header SEID = the CP's F-SEID (so the SMF correlates the
        // response); our own SEID goes only in the F-SEID IE.
        let reply = match SessionEstablishmentResponseBuilder::accepted(cp_seid, seq)
            .node_id(local_ip)
            .fseid(seid, local_ip)
            .build()
        {
            Ok(resp) => Some(resp.marshal()),
            Err(e) => {
                tracing::warn!("mup-c: build SessionEstablishmentResponse failed: {e}");
                None
            }
        };
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
        let Some(session) = self.sessions.get(seid).filter(|s| s.peer == src).cloned() else {
            let resp = SessionModificationResponseBuilder::new(seid, seq)
                .cause(CauseValue::SessionContextNotFound)
                .build();
            return (Some(resp.marshal()), Vec::new());
        };
        // PR-A re-reports the existing session unchanged (field-level
        // re-extraction from Update/Create PDRs is a follow-up). The
        // response header SEID echoes the CP's F-SEID, not our own.
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rs_pfcp::ie::IeType;
    use rs_pfcp::ie::create_far::CreateFar;
    use rs_pfcp::ie::create_pdr::CreatePdrBuilder;
    use rs_pfcp::ie::destination_interface::Interface;
    use rs_pfcp::ie::f_teid::FteidBuilder;
    use rs_pfcp::ie::far_id::FarId;
    use rs_pfcp::ie::network_instance::NetworkInstance;
    use rs_pfcp::ie::pdi::PdiBuilder;
    use rs_pfcp::ie::pdr_id::PdrId;
    use rs_pfcp::ie::precedence::Precedence;
    use rs_pfcp::ie::source_interface::{SourceInterface, SourceInterfaceValue};
    use rs_pfcp::ie::ue_ip_address::UeIpAddress;
    use rs_pfcp::message::association_setup_request::AssociationSetupRequestBuilder;
    use rs_pfcp::message::heartbeat_request::HeartbeatRequestBuilder;
    use rs_pfcp::message::session_deletion_request::SessionDeletionRequestBuilder;
    use rs_pfcp::message::session_establishment_request::SessionEstablishmentRequestBuilder;
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

    /// A Session Establishment Request whose uplink/access PDR carries an
    /// F-TEID (teid + GTP endpoint), a UE IPv4 address and a Network
    /// Instance — the three things the controller extracts.
    fn establishment_bytes() -> Vec<u8> {
        let fteid = FteidBuilder::new()
            .teid(0x1234_5678u32)
            .ipv4(Ipv4Addr::new(10, 0, 0, 1))
            .build()
            .unwrap();
        let pdi = PdiBuilder::new(SourceInterface::new(SourceInterfaceValue::Access))
            .f_teid(fteid)
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
        let far = CreateFar::builder(FarId::new(1))
            .forward_to(Interface::Core)
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
