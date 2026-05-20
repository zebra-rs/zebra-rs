//! Per-protocol-task runtime context.
//!
//! `ProtoContext` is the spawn-time bundle every protocol task
//! receives from `ConfigManager`. It owns the protocol's
//! [`RibClient`] handle and — for VRF-attached instances — the
//! VRF identifier plus the master device name. The socket factory
//! methods on the context (`tcp_socket_v4`, `tcp_socket_v6`,
//! `tcp_listen`, `udp_socket`, `raw_socket`) wrap the OS primitives
//! so VRF binding is applied automatically and uniformly: protocol
//! code calls `ctx.tcp_socket_v4()?` instead of `TcpSocket::new_v4()`
//! and the context decides whether to set `SO_BINDTODEVICE`.
//!
//! Step 4 lands the type and the factory API surface; the
//! `maybe_bind_device` body is a no-op until step 8 wires the
//! actual setsockopt call. The `for_vrf` constructor exists for
//! symmetry but has no production caller until step 13 (per-VRF
//! BGP tasks) reaches it — `default_table` is the only spawn-side
//! constructor in tree today, which is exactly the no-binding
//! behaviour the legacy `TcpSocket::new_*` callsites had.
//!
//! `Clone` is intentional: the per-task FSMs, listen accept loops,
//! and timer callbacks all take their own copies. The clone is
//! cheap (an `Arc` inside the `UnboundedSender` in `RibClient` plus
//! a `Copy` id plus `Arc<str>`-like field clones).

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};

use crate::rib::client::RibClient;

/// Spawn-time runtime context for a protocol instance.
#[derive(Debug, Clone)]
pub struct ProtoContext {
    /// 0 = default routing table (no `SO_BINDTODEVICE`).
    /// Non-zero = Linux VRF table id, the same `table_id` RIB hands
    /// out from `VrfIdAllocator` when the master device is created.
    vrf_id: u32,
    /// VRF master device name. `Some(name)` iff `vrf_id != 0` — the
    /// invariant the constructors enforce. The socket factories use
    /// this for `SO_BINDTODEVICE` once step 8 lights up the body of
    /// `maybe_bind_device`.
    vrf_ifname: Option<String>,
    /// Bound RIB client. Public so the FSM / listen accept loop / SR
    /// allocator / redistribute helpers can clone it without having
    /// to thread it through `ProtoContext` accessors. Cloning is
    /// cheap (`Arc` inside the inbound sender).
    pub rib: RibClient,
}

impl ProtoContext {
    /// Context for a protocol instance running in the default
    /// routing table — what every existing protocol task uses
    /// today. Socket factories produce sockets without
    /// `SO_BINDTODEVICE` set; behaviour matches the pre-`ProtoContext`
    /// `TcpSocket::new_*` callsites exactly.
    pub fn default_table(rib: RibClient) -> Self {
        Self {
            vrf_id: 0,
            vrf_ifname: None,
            rib,
        }
    }

    /// Same as [`Self::default_table`] but mints a parked
    /// `RibClient` internally — used by protocol instances that
    /// don't subscribe to RIB (today: BFD). The parked client
    /// owns an `UnboundedSender` whose receiver is leaked; calling
    /// `.send(...)` on it queues into a channel nobody reads. That
    /// matters in principle, but BFD has no code path that touches
    /// `ctx.rib` today — keeping the field present rather than
    /// `Option<RibClient>` keeps every other caller's
    /// `ctx.rib.send(...)` unconditional.
    pub fn default_table_no_rib() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        // The receiver half is intentionally leaked. A parked
        // ProtoContext lives for the duration of the protocol task,
        // which matches the daemon lifetime in practice; even if a
        // protocol respawns, the leaked rx becomes garbage that the
        // OS reclaims on exit.
        Box::leak(Box::new(rx));
        let rib = RibClient::new(tx, crate::rib::client::ProtoId::from_raw(u32::MAX));
        Self {
            vrf_id: 0,
            vrf_ifname: None,
            rib,
        }
    }

    /// Context for a protocol instance attached to a non-default
    /// VRF. The socket factories will `SO_BINDTODEVICE` to
    /// `vrf_ifname` so the resulting socket lands in the matching
    /// kernel routing table.
    ///
    /// Has no production caller in step 4; step 13 (per-VRF BGP
    /// task spawn) is the first.
    #[allow(dead_code)] // first caller lands in step 13.
    pub fn for_vrf(rib: RibClient, vrf_id: u32, vrf_ifname: String) -> Self {
        debug_assert!(
            vrf_id != 0,
            "ProtoContext::for_vrf requires a non-zero vrf_id; use default_table for vrf 0"
        );
        Self {
            vrf_id,
            vrf_ifname: Some(vrf_ifname),
            rib,
        }
    }

    #[allow(dead_code)] // first reader lands in step 8 (per-VRF table dispatch).
    pub fn vrf_id(&self) -> u32 {
        self.vrf_id
    }

    /// Build a TCP socket pre-bound to the context's VRF. The
    /// caller still chooses bind / connect / listen + any per-peer
    /// setsockopts (TCP-MD5 / TCP-AO / `SO_REUSEADDR`). Returned by
    /// value so BGP's `peer_connect` keeps owning the socket through
    /// its auth-key installation.
    pub fn tcp_socket_v4(&self) -> io::Result<TcpSocket> {
        let sock = TcpSocket::new_v4()?;
        self.maybe_bind_device(&sock)?;
        Ok(sock)
    }

    pub fn tcp_socket_v6(&self) -> io::Result<TcpSocket> {
        let sock = TcpSocket::new_v6()?;
        self.maybe_bind_device(&sock)?;
        Ok(sock)
    }

    /// One-shot listen helper: create a TCP socket for `addr`'s
    /// family, enable `SO_REUSEADDR`, bind, and start listening.
    /// Used by BGP's `:179` listener; the per-VRF variant in step 16
    /// will reuse the same call against a different ctx.
    pub async fn tcp_listen(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        let sock = match addr {
            SocketAddr::V4(_) => self.tcp_socket_v4()?,
            SocketAddr::V6(_) => self.tcp_socket_v6()?,
        };
        sock.set_reuseaddr(true)?;
        sock.bind(addr)?;
        sock.listen(128)
    }

    /// IPv6-only variant of [`Self::tcp_listen`]. Sets
    /// `IPV6_V6ONLY` before bind so the listener accepts only
    /// IPv6 connections, leaving a separate `0.0.0.0:port` listener
    /// free to bind the same port for IPv4.
    ///
    /// `tokio::TcpSocket` does not expose `set_only_v6`, so this
    /// path drops down to `socket2::Socket` and converts via
    /// `std::net::TcpListener::from_std`. The VRF binding still
    /// flows through `maybe_bind_device`.
    pub async fn tcp_listen_v6_only(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        if !addr.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp_listen_v6_only requires an IPv6 SocketAddr",
            ));
        }
        let sock = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        sock.set_only_v6(true)?;
        sock.set_reuse_address(true)?;
        self.maybe_bind_device(&sock)?;
        sock.bind(&addr.into())?;
        sock.listen(128)?;
        let std_listener: std::net::TcpListener = sock.into();
        std_listener.set_nonblocking(true)?;
        TcpListener::from_std(std_listener)
    }

    /// Bound UDP socket — convenience wrapper. Used by callers that
    /// only need a simple bound `tokio::net::UdpSocket` and no
    /// further per-socket setsockopt configuration. Internally
    /// builds an unbound socket via [`Self::udp_socket_unbound`],
    /// applies `SO_REUSEADDR`, binds, sets non-blocking, and
    /// converts to the tokio type.
    #[allow(dead_code)] // first caller lands when a VRF-aware UDP protocol arrives.
    pub async fn udp_socket(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let sock = self.udp_socket_unbound(domain)?;
        sock.set_reuse_address(true)?;
        sock.bind(&addr.into())?;
        let std_sock: std::net::UdpSocket = sock.into();
        std_sock.set_nonblocking(true)?;
        UdpSocket::from_std(std_sock)
    }

    /// Unbound DGRAM UDP socket pre-`SO_BINDTODEVICE`-applied.
    /// Returned as `socket2::Socket` so the caller can configure
    /// further setsockopts (`IP_TTL`, `IP_RECVTTL`, `IP_PKTINFO`,
    /// multicast joins) and bind on its own schedule. BFD's
    /// `bfd_socket_ipv4` is the canonical consumer; OSPF reaches
    /// for [`Self::raw_socket`] instead since it needs `Type::RAW`.
    pub fn udp_socket_unbound(&self, domain: Domain) -> io::Result<Socket> {
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        self.maybe_bind_device(&sock)?;
        Ok(sock)
    }

    /// Raw socket — for OSPF (IP protocol 89) and IS-IS-over-Ethernet.
    /// Caller still does any further `setsockopt` it needs (`IP_HDRINCL`,
    /// `IP_PKTINFO`, multicast joins). Returned as `socket2::Socket`
    /// so protocols can keep using `AsyncFd` to drive it.
    #[allow(dead_code)] // OSPF / IS-IS migration in step 6 is the first caller.
    pub fn raw_socket(&self, domain: Domain, protocol: Protocol) -> io::Result<Socket> {
        let sock = Socket::new(domain, Type::RAW, Some(protocol))?;
        self.maybe_bind_device(&sock)?;
        Ok(sock)
    }

    /// Hook point for `SO_BINDTODEVICE`. The implementation is
    /// deliberately empty in step 4 — every production caller uses
    /// `default_table`, where binding is a no-op — and lands in
    /// step 8 alongside per-VRF table support in RIB.
    ///
    /// Reading `vrf_ifname` here even though the body is a no-op
    /// keeps the field from being flagged unused, and gives step 8
    /// a single point to extend.
    fn maybe_bind_device<S: AsRawFd>(&self, _sock: &S) -> io::Result<()> {
        if let Some(ifname) = &self.vrf_ifname {
            // for_vrf has no production caller in step 4, so this
            // arm is reachable only from explicit unit tests. The
            // `trace!` lets those tests observe that the field
            // plumbing works without us actually issuing a
            // privileged setsockopt.
            tracing::trace!(
                vrf_id = self.vrf_id,
                ifname = %ifname,
                "ProtoContext: SO_BINDTODEVICE deferred to step 8"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::sync::mpsc::unbounded_channel;

    use crate::rib::client::{ProtoId, RibClient, RibInbound};

    /// Build a parked `RibClient` for ProtoContext tests. The
    /// inbound rx is leaked so a `client.send(...)` from any code
    /// under test doesn't trip a SendError on a dropped receiver.
    /// Tests don't assert anything about what the client sent —
    /// we're testing the socket factories, not the RIB channel.
    fn test_rib_client() -> RibClient {
        let (inbound_tx, inbound_rx) = unbounded_channel::<RibInbound>();
        Box::leak(Box::new(inbound_rx));
        RibClient::new(inbound_tx, ProtoId::from_raw(0))
    }

    #[test]
    fn default_table_is_vrf_zero_with_no_ifname() {
        let ctx = ProtoContext::default_table(test_rib_client());
        assert_eq!(ctx.vrf_id(), 0);
        assert!(ctx.vrf_ifname.is_none());
    }

    #[test]
    fn for_vrf_records_id_and_ifname() {
        let ctx = ProtoContext::for_vrf(test_rib_client(), 17, "vrf-CUST-A".to_string());
        assert_eq!(ctx.vrf_id(), 17);
        assert_eq!(ctx.vrf_ifname.as_deref(), Some("vrf-CUST-A"));
    }

    #[test]
    fn tcp_socket_v4_creates_a_socket() {
        let ctx = ProtoContext::default_table(test_rib_client());
        let sock = ctx.tcp_socket_v4().expect("v4 socket creation");
        // Touching the fd proves the socket is real.
        assert!(sock.as_raw_fd() >= 0);
    }

    #[test]
    fn tcp_socket_v6_creates_a_socket() {
        let ctx = ProtoContext::default_table(test_rib_client());
        let sock = ctx.tcp_socket_v6().expect("v6 socket creation");
        assert!(sock.as_raw_fd() >= 0);
    }

    #[tokio::test]
    async fn tcp_listen_on_ephemeral_port_succeeds() {
        let ctx = ProtoContext::default_table(test_rib_client());
        let listener = ctx
            .tcp_listen("127.0.0.1:0".parse().unwrap())
            .await
            .expect("listen on ephemeral port");
        let local = listener.local_addr().expect("local_addr");
        assert!(local.port() != 0, "OS allocated an ephemeral port");
        assert!(local.ip().is_loopback());
    }

    #[tokio::test]
    async fn udp_socket_on_ephemeral_port_succeeds() {
        let ctx = ProtoContext::default_table(test_rib_client());
        let sock = ctx
            .udp_socket("127.0.0.1:0".parse().unwrap())
            .await
            .expect("udp bind on ephemeral port");
        let local = sock.local_addr().expect("local_addr");
        assert!(local.port() != 0);
        assert!(local.ip().is_loopback());
    }

    #[tokio::test]
    async fn tcp_listen_v6_only_succeeds_on_localhost() {
        let ctx = ProtoContext::default_table(test_rib_client());
        let listener = ctx
            .tcp_listen_v6_only("[::1]:0".parse().unwrap())
            .await
            .expect("v6-only listen on ::1");
        let local = listener.local_addr().expect("local_addr");
        assert!(local.is_ipv6());
        assert!(local.port() != 0);
    }

    #[tokio::test]
    async fn tcp_listen_v6_only_rejects_ipv4_addr() {
        let ctx = ProtoContext::default_table(test_rib_client());
        let err = ctx
            .tcp_listen_v6_only("127.0.0.1:0".parse().unwrap())
            .await
            .expect_err("v4 addr must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn udp_socket_unbound_produces_a_dgram_socket() {
        let ctx = ProtoContext::default_table(test_rib_client());
        let sock = ctx
            .udp_socket_unbound(Domain::IPV4)
            .expect("udp_socket_unbound");
        // Caller is responsible for binding; the only invariant the
        // factory promises is a real, non-blocking-capable fd
        // (caller flips O_NONBLOCK after its own setsockopts).
        assert!(sock.as_raw_fd() >= 0);
    }

    #[test]
    fn default_table_no_rib_yields_usable_context() {
        let ctx = ProtoContext::default_table_no_rib();
        assert_eq!(ctx.vrf_id(), 0);
        // ctx.rib sends are no-ops in observable terms (the receiver
        // is leaked away). The test only asserts construction
        // succeeds and the rib field is present.
        let _ = ctx.rib.clone();
    }

    #[tokio::test]
    async fn for_vrf_socket_factory_still_succeeds_in_step_4() {
        // maybe_bind_device is a no-op until step 8; for_vrf
        // contexts must therefore produce sockets without error.
        let ctx = ProtoContext::for_vrf(test_rib_client(), 10, "vrf-test".to_string());
        let listener = ctx
            .tcp_listen("127.0.0.1:0".parse().unwrap())
            .await
            .expect("for_vrf tcp_listen no-op in step 4");
        assert!(listener.local_addr().is_ok());
    }
}
