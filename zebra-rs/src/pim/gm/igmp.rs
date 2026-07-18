//! The IGMP (IPv4) membership codec: the raw IGMP socket, the read /
//! write tasks, and the wire ↔ [`GmInput`] / query translation. This
//! is the `Ipv4` implementor of [`GmCodec`]; an MLD codec (Phase 4)
//! plugs an IPv6 wire form into the same engine.

use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn};
use pim_packet::{IgmpGroupMessage, IgmpPacket, IgmpV3Query, igmp_verify_checksum, value_to_code};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::context::Task;

use super::super::inst::Message;
use super::super::ipv4::Ipv4;
use super::super::socket::{igmp_join_if, igmp_leave_if};
use super::{GM_ROBUSTNESS, GmCodec, GmInput, GmRecord, IgmpConfig};

/// Outbound IGMP query for the write task.
struct IgmpSend {
    packet: IgmpPacket,
    ifindex: u32,
    dst: Ipv4Addr,
}

/// The IGMP transport: raw socket + read/write tasks. Dropping it drops
/// the tasks, which end when the channels close.
pub struct IgmpCodec {
    sock: Arc<AsyncFd<Socket>>,
    send_tx: UnboundedSender<IgmpSend>,
    _read_task: Task<()>,
    _write_task: Task<()>,
}

impl IgmpCodec {
    /// Take the (already-opened) IGMP socket and spawn the read / write
    /// tasks. The socket is opened by the caller before the RIB
    /// subscription so a failure can't leave a dead receiver queued.
    /// The read task feeds normalized membership into the instance's `tx`.
    pub fn new(sock: AsyncFd<Socket>, tx: UnboundedSender<Message<Ipv4>>) -> Self {
        let sock = Arc::new(sock);
        let (send_tx, send_rx) = mpsc::unbounded_channel();

        let read_sock = sock.clone();
        let read_task = Task::spawn(async move {
            igmp_read(read_sock, tx).await;
        });
        let write_sock = sock.clone();
        let write_task = Task::spawn(async move {
            igmp_write(write_sock, send_rx).await;
        });

        Self {
            sock,
            send_tx,
            _read_task: read_task,
            _write_task: write_task,
        }
    }
}

impl GmCodec<Ipv4> for IgmpCodec {
    /// Build and queue a general (group `None`) or group-specific query.
    fn send_query(&self, cfg: &IgmpConfig, ifindex: u32, group: Option<Ipv4Addr>) {
        // Max Resp is in units of 1/10 s; group-specific queries use the
        // Last Member Query Interval (1 s). The exponent-coded form
        // represents values past 8 bits instead of clamping.
        let max_resp = match group {
            None => value_to_code((cfg.query_max_resp() as u32 * 10).min(u16::MAX as u32) as u16),
            Some(_) => 10,
        };
        let dst = group.unwrap_or(<Ipv4 as super::super::af::PimAf>::GENERAL_QUERY_DST);
        // A general query carries 0.0.0.0 as the group.
        let wire_group = group.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let packet = if cfg.version() == 2 {
            IgmpPacket::QueryV2(IgmpGroupMessage {
                max_resp,
                group: wire_group,
            })
        } else {
            IgmpPacket::QueryV3(IgmpV3Query {
                max_resp_code: max_resp,
                group: wire_group,
                suppress: false,
                qrv: GM_ROBUSTNESS as u8,
                // QQIC in seconds, exponent-coded above 127.
                qqic: value_to_code(cfg.query_interval()),
                sources: vec![],
            })
        };
        let _ = self.send_tx.send(IgmpSend {
            packet,
            ifindex,
            dst,
        });
    }

    fn join_if(&self, ifindex: u32) {
        igmp_join_if(&self.sock, ifindex);
    }

    fn leave_if(&self, ifindex: u32) {
        igmp_leave_if(&self.sock, ifindex);
    }
}

/// Normalize a received IGMP packet into a [`GmInput`]. IGMP addresses
/// are already IPv4 (`= <Ipv4 as PimAf>::Addr`), so no family
/// conversion is needed here.
fn parse_igmp(packet: IgmpPacket) -> Option<GmInput<Ipv4>> {
    Some(match packet {
        IgmpPacket::QueryV2(_) | IgmpPacket::QueryV3(_) => GmInput::Query,
        IgmpPacket::ReportV1(msg) | IgmpPacket::ReportV2(msg) => GmInput::V2Report(msg.group),
        IgmpPacket::LeaveV2(msg) => GmInput::V2Leave(msg.group),
        IgmpPacket::ReportV3(report) => {
            let records = report
                .records
                .into_iter()
                .map(|r| GmRecord {
                    rec_type: r.rec_type,
                    group: r.group,
                    sources: r.sources,
                })
                .collect();
            GmInput::V3Report(records)
        }
        IgmpPacket::Unknown { typ, .. } => {
            tracing::debug!("igmp: unknown type {:#04x} ignored", typ);
            return None;
        }
    })
}

async fn igmp_read(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message<Ipv4>>) {
    let mut buf = [0u8; 1024 * 16];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrIn>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                )?;

                let mut cmsgs = msg.cmsgs()?;

                let Some(src) = msg.address else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };

                let Some(ControlMessageOwned::Ipv4PacketInfo(pktinfo)) = cmsgs.next() else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };

                let ifindex = pktinfo.ipi_ifindex as u32;

                let Some(input) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                // IGMP always carries the Router Alert IP option, so the
                // IHL is essential here.
                if input.is_empty() {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
                let ihl = ((input[0] & 0x0f) as usize) * 4;
                if ihl < 20 || input.len() <= ihl {
                    return Err(ErrorKind::InvalidData.into());
                }
                let igmp_input = &input[ihl..];

                if !igmp_verify_checksum(igmp_input) {
                    tracing::debug!("igmp: bad checksum from {} on ifindex {ifindex}", src.ip());
                    return Err(ErrorKind::InvalidData.into());
                }
                let Ok((_, packet)) = IgmpPacket::parse_be(igmp_input) else {
                    tracing::debug!(
                        "igmp: malformed packet from {} on ifindex {ifindex}",
                        src.ip()
                    );
                    return Err(ErrorKind::InvalidData.into());
                };

                if let Some(gm_input) = parse_igmp(packet) {
                    let _ = tx.send(Message::Membership {
                        ifindex,
                        src: src.ip(),
                        input: gm_input,
                    });
                }

                Ok(())
            })
            .await;
        if tx.is_closed() {
            return;
        }
    }
}

async fn igmp_write(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<IgmpSend>) {
    while let Some(send) = rx.recv().await {
        let mut buf = BytesMut::new();
        send.packet.emit(&mut buf);

        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn = SocketAddrV4::new(send.dst, 0).into();
        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: send.ifindex as i32,
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        let cmsg = [socket::ControlMessage::Ipv4PacketInfo(&pktinfo)];

        let _ = sock
            .async_io(Interest::WRITABLE, |sock| {
                socket::sendmsg(
                    sock.as_raw_fd(),
                    &iov,
                    &cmsg,
                    socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(std::io::Error::from)?;
                Ok(())
            })
            .await;
    }
}
