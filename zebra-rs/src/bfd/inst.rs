use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver};

use crate::context::{Context, Task};

use super::network::read_packet;
use super::session::SessionTable;
use super::socket::{BFD_SINGLE_HOP_PORT, bfd_socket_ipv4};

/// Top-level BFD instance. Holds the IPv4 single-hop socket, the
/// session table, and the event channel; the read task feeds events
/// in and the event loop demuxes them to sessions.
///
/// PR 3a wires the session table into the event loop's demux path.
/// PR 3b adds the public `add_session` API, the TX scheduler, and the
/// detection timer.
pub struct Bfd {
    pub rx: UnboundedReceiver<Message>,
    pub sessions: SessionTable,
}

/// Event-loop messages. PR 3 adds Send / interface / config variants.
#[derive(Debug)]
pub enum Message {
    /// A parsed, GTSM-validated control packet arrived.
    Recv {
        packet: bfd_packet::ControlPacket,
        src: SocketAddrV4,
        dst: Option<IpAddr>,
        ifindex: u32,
    },
}

impl Bfd {
    /// Bind the IPv4 single-hop socket on `0.0.0.0:3784` and spawn the
    /// receive task.
    pub fn new(_ctx: Context) -> std::io::Result<Self> {
        let sock = bfd_socket_ipv4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            BFD_SINGLE_HOP_PORT,
        ))?;
        let sock = Arc::new(AsyncFd::new(sock)?);

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            read_packet(sock, tx).await;
        });

        Ok(Self {
            rx,
            sessions: SessionTable::new(),
        })
    }

    pub async fn event_loop(&mut self) {
        while let Some(msg) = self.rx.recv().await {
            match msg {
                Message::Recv {
                    packet,
                    src,
                    dst,
                    ifindex,
                } => self.on_recv(packet, src, dst, ifindex),
            }
        }
    }

    /// Demux an incoming control packet. RFC 5880 §6.8.6: when `Your
    /// Discriminator` is non-zero, look up the session by that value;
    /// otherwise the bootstrap (`(local, remote, ifindex)`) demux
    /// path applies — that fallback lands in PR 3b together with the
    /// outbound packet path that creates the first peer-side state.
    fn on_recv(
        &mut self,
        packet: bfd_packet::ControlPacket,
        src: SocketAddrV4,
        dst: Option<IpAddr>,
        ifindex: u32,
    ) {
        if packet.your_disc == 0 {
            tracing::debug!(
                ?src,
                ?dst,
                ifindex,
                "bfd: rx packet with Your Disc = 0; bootstrap demux not yet wired",
            );
            return;
        }
        let Some(session) = self.sessions.get_by_disc_mut(packet.your_disc) else {
            tracing::debug!(
                ?src,
                ifindex,
                your_disc = format_args!("{:#010x}", packet.your_disc),
                "bfd: no session for received discriminator",
            );
            return;
        };
        if let Some(change) = session.handle_packet(&packet) {
            tracing::info!(
                key = ?session.key,
                from = %change.from,
                to = %change.to,
                diag = %change.diag,
                "bfd: session state change",
            );
        }
    }
}

/// Spawn the event loop. Mirrors [`crate::ospf::serve`]. The returned
/// [`Task`] handle owns the spawned future; dropping it aborts the
/// loop (see [`crate::config::bfd::despawn_bfd`]).
pub fn serve(mut bfd: Bfd) -> Task<()> {
    Task::spawn(async move {
        bfd.event_loop().await;
    })
}
