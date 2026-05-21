//! v3 protocol instance: socket + I/O task wiring.
//!
//! This is the spine. It opens the raw IPv6 socket, spawns the
//! `read_packet_v6` and `write_packet_v6` tasks introduced by the
//! Phase 5 network PRs, and runs a minimal event loop that drains
//! incoming packets. The IFSM / NFSM / LSDB layers attach to this
//! struct in subsequent Phase 6 PRs.
//!
//! Distinct from `super::super::Ospf` (the v2 instance) per the
//! hybrid plan: the two instances run side-by-side, share the
//! `OspfVersion` trait + `ProtoContext` + SPF infrastructure, and
//! diverge on packet types, LSDB, and FSM state. A future
//! refactor may unify them via generics once v3 protocol logic
//! has matured enough to constrain the trait surface.

use std::sync::Arc;

use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::context::{ProtoContext, Task};

use super::super::network_v6::{Ospfv3Recv, Ospfv3Send, read_packet_v6, write_packet_v6};
use super::super::socket::ospf_socket_ipv6;

/// Standalone OSPFv3 protocol instance.
///
/// Holds the v6 raw socket plus the two halves of the I/O
/// channels: `rx_recv` drains parsed `Ospfv3Recv` items from the
/// rx loop, `tx_send` lets the protocol layer enqueue
/// `Ospfv3Send` items for the tx loop.
pub struct Ospfv3Instance {
    /// VRF / network namespace context. Held so subsequent PRs can
    /// reach netlink, RIB, etc. through the same handle the v2
    /// instance uses.
    pub ctx: ProtoContext,
    /// Raw IPv6 socket, shared with the spawned rx/tx tasks via
    /// `Arc<AsyncFd<…>>`.
    pub sock: Arc<AsyncFd<Socket>>,
    /// Receiver end of the rx-loop channel. The rx-loop owns the
    /// `tx_recv` half (consumed during construction); this end is
    /// drained by the instance's event loop.
    rx_recv: UnboundedReceiver<Ospfv3Recv>,
    /// Sender end of the tx-loop channel. Protocol code (Hello
    /// timer, DBD exchange, flood-out, etc.) pushes outgoing
    /// packets here; the spawned tx loop owns the `rx_send` half.
    pub tx_send: UnboundedSender<Ospfv3Send>,
}

impl Ospfv3Instance {
    /// Create a new v3 instance: opens the raw v6 socket through
    /// `ProtoContext` (so VRF binding inherits automatically) and
    /// spawns the two long-lived I/O tasks bound to it.
    ///
    /// Returns `Err` only when the kernel refuses to give us the
    /// raw socket (typically missing `CAP_NET_RAW`); on success
    /// the instance is fully wired but the event loop is not yet
    /// running — the caller drives that via [`serve`].
    pub fn new(ctx: ProtoContext) -> std::io::Result<Self> {
        let sock = Arc::new(AsyncFd::new(ospf_socket_ipv6(&ctx)?)?);

        let (tx_recv, rx_recv) = mpsc::unbounded_channel::<Ospfv3Recv>();
        let (tx_send, rx_send) = mpsc::unbounded_channel::<Ospfv3Send>();

        // Spawn the rx loop. It owns its sender half; the
        // instance keeps the receiver half on `rx_recv`.
        let rx_sock = sock.clone();
        tokio::spawn(async move {
            read_packet_v6(rx_sock, tx_recv).await;
        });

        // Spawn the tx loop. It owns its receiver half; the
        // instance keeps the sender half on `tx_send`.
        let tx_sock = sock.clone();
        tokio::spawn(async move {
            write_packet_v6(tx_sock, rx_send).await;
        });

        Ok(Self {
            ctx,
            sock,
            rx_recv,
            tx_send,
        })
    }

    /// Drain incoming v3 packets. For now just trace-logs them
    /// — IFSM dispatch and neighbor lookup land in the next
    /// Phase 6 PRs.
    pub async fn event_loop(&mut self) {
        while let Some(recv) = self.rx_recv.recv().await {
            tracing::info!(
                "ospfv3: rx type={:?} from {} dst={} ifindex={}",
                recv.packet.typ,
                recv.src,
                recv.dst,
                recv.ifindex,
            );
        }
    }
}

/// Spawn the v3 instance's event loop on the tokio runtime,
/// returning a handle that aborts the task on drop. Mirrors the
/// v2 `super::super::inst::serve` shape.
pub fn serve(mut inst: Ospfv3Instance) -> Task<()> {
    Task::spawn(async move {
        inst.event_loop().await;
    })
}
