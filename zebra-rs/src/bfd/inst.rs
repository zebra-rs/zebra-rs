use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver};

use crate::context::{Context, Task};

use super::network::read_packet;
use super::socket::{BFD_SINGLE_HOP_PORT, bfd_socket_ipv4};

/// Top-level BFD instance. PR 2 only stands up the IPv4 single-hop
/// receive path: open the UDP/3784 socket, spawn the read task, and
/// drain the resulting event stream with a debug log. The session
/// table, FSM, timers, and outbound packet path arrive in PR 3.
pub struct Bfd {
    pub rx: UnboundedReceiver<Message>,
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

        Ok(Self { rx })
    }

    pub async fn event_loop(&mut self) {
        while let Some(msg) = self.rx.recv().await {
            match msg {
                Message::Recv {
                    packet,
                    src,
                    dst,
                    ifindex,
                } => {
                    tracing::debug!(
                        ?src,
                        ?dst,
                        ifindex,
                        state = ?packet.state,
                        my_disc = format_args!("{:#010x}", packet.my_disc),
                        your_disc = format_args!("{:#010x}", packet.your_disc),
                        "bfd: rx control packet",
                    );
                }
            }
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
