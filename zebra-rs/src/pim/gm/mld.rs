//! The MLD (IPv6) membership codec: the raw ICMPv6 socket, the read /
//! write tasks, and the wire ↔ [`GmInput`] / query translation. This
//! is the `Ipv6` implementor of [`GmCodec`] — MLDv1/v2 (RFC 2710 / RFC
//! 3810) plugs an IPv6 wire form into the same [`Gm`](super::Gm) engine
//! the IGMP codec drives.

use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn6};
use pim_packet::{MldGroupMessage, MldPacket, MldV2Query, mld_verify_checksum, value_to_code};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::context::Task;

use super::super::inst::Message;
use super::super::ipv6::Ipv6;
use super::super::socket::{mld_join_if, mld_leave_if};
use super::{GM_ROBUSTNESS, GmCodec, GmInput, GmRecord, IgmpConfig};

/// Outbound MLD query for the write task. `src` is the pinned
/// link-local source; the pseudo-header checksum folds it in.
struct MldSend {
    packet: MldPacket,
    ifindex: u32,
    dst: Ipv6Addr,
    src: Ipv6Addr,
}

/// The MLD transport: raw ICMPv6 socket + read/write tasks.
pub struct MldCodec {
    sock: Arc<AsyncFd<Socket>>,
    send_tx: UnboundedSender<MldSend>,
    _read_task: Task<()>,
    _write_task: Task<()>,
}

impl MldCodec {
    /// Take the (already-opened) MLD socket and spawn the read / write
    /// tasks. The read task feeds normalized membership into `tx`.
    pub fn new(sock: AsyncFd<Socket>, tx: UnboundedSender<Message<Ipv6>>) -> Self {
        let sock = Arc::new(sock);
        let (send_tx, send_rx) = mpsc::unbounded_channel();

        let read_sock = sock.clone();
        let read_task = Task::spawn(async move {
            mld_read(read_sock, tx).await;
        });
        let write_sock = sock.clone();
        let write_task = Task::spawn(async move {
            mld_write(write_sock, send_rx).await;
        });

        Self {
            sock,
            send_tx,
            _read_task: read_task,
            _write_task: write_task,
        }
    }
}

impl GmCodec<Ipv6> for MldCodec {
    fn send_query(
        &self,
        cfg: &IgmpConfig,
        ifindex: u32,
        group: Option<Ipv6Addr>,
        src: Option<Ipv6Addr>,
    ) {
        // MLD control is link-local sourced; without an interface
        // link-local we cannot form a valid query.
        let Some(src) = src else {
            return;
        };
        // Max Response Code is a 16-bit millisecond value (RFC 3810
        // §5.1.3); group-specific queries use the Last Member Query
        // Interval (1 s). Values under 32768 encode directly.
        let max_resp_code: u16 = match group {
            None => (cfg.query_max_resp() as u32 * 1000).min(u16::MAX as u32) as u16,
            Some(_) => 1000,
        };
        let dst = group.unwrap_or(<Ipv6 as super::super::af::PimAf>::GENERAL_QUERY_DST);
        // A general query carries the unspecified group.
        let wire_group = group.unwrap_or(Ipv6Addr::UNSPECIFIED);
        let packet = if cfg.version() == 1 {
            MldPacket::QueryV1(MldGroupMessage {
                max_resp_code,
                group: wire_group,
            })
        } else {
            MldPacket::QueryV2(MldV2Query {
                max_resp_code,
                group: wire_group,
                suppress: false,
                qrv: GM_ROBUSTNESS as u8,
                qqic: value_to_code(cfg.query_interval()) as u8,
                sources: vec![],
            })
        };
        let _ = self.send_tx.send(MldSend {
            packet,
            ifindex,
            dst,
            src,
        });
    }

    fn join_if(&self, ifindex: u32) {
        mld_join_if(&self.sock, ifindex);
    }

    fn leave_if(&self, ifindex: u32) {
        mld_leave_if(&self.sock, ifindex);
    }
}

/// Normalize a received MLD packet into a [`GmInput`]. MLD addresses
/// are already IPv6 (`= <Ipv6 as PimAf>::Addr`), so no family
/// conversion is needed.
fn parse_mld(packet: MldPacket) -> Option<GmInput<Ipv6>> {
    Some(match packet {
        MldPacket::QueryV1(_) | MldPacket::QueryV2(_) => GmInput::Query,
        MldPacket::ReportV1(msg) => GmInput::V2Report(msg.group),
        MldPacket::DoneV1(msg) => GmInput::V2Leave(msg.group),
        MldPacket::ReportV2(report) => {
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
        MldPacket::Unknown { typ, .. } => {
            tracing::debug!("mld: unknown type {typ} ignored");
            return None;
        }
    })
}

async fn mld_read(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message<Ipv6>>) {
    let mut buf = [0u8; 1024 * 16];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo, libc::c_int);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrIn6>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                )?;

                let Some(src_sa) = msg.address else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };
                let src: Ipv6Addr = src_sa.ip();

                let mut dst: Option<Ipv6Addr> = None;
                let mut hop_limit: Option<i32> = None;
                for cmsg in msg.cmsgs()? {
                    match cmsg {
                        ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                            dst = Some(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr));
                        }
                        ControlMessageOwned::Ipv6HopLimit(hl) => hop_limit = Some(hl),
                        _ => {}
                    }
                }
                let Some(dst) = dst else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };

                // RFC 3810 §6.2: MLD messages carry hop limit 1 and a
                // link-local source; drop anything else.
                if hop_limit != Some(1) || !is_link_local(&src) {
                    return Err(ErrorKind::InvalidData.into());
                }

                let Some(input) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                if !mld_verify_checksum(input, src, dst) {
                    tracing::debug!("mld: bad checksum from {src}");
                    return Err(ErrorKind::InvalidData.into());
                }
                let Ok((_, packet)) = MldPacket::parse_be(input) else {
                    tracing::debug!("mld: malformed packet from {src}");
                    return Err(ErrorKind::InvalidData.into());
                };

                let ifindex = pktinfo_ifindex(&msg)?;
                if let Some(gm_input) = parse_mld(packet) {
                    let _ = tx.send(Message::Membership {
                        ifindex,
                        src,
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

/// The ingress ifindex from the packet-info ancillary message.
fn pktinfo_ifindex(msg: &socket::RecvMsg<'_, '_, SockaddrIn6>) -> Result<u32, std::io::Error> {
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::Ipv6PacketInfo(pktinfo) = cmsg {
            return Ok(pktinfo.ipi6_ifindex);
        }
    }
    Err(ErrorKind::AddrNotAvailable.into())
}

fn is_link_local(a: &Ipv6Addr) -> bool {
    let o = a.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

async fn mld_write(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<MldSend>) {
    while let Some(send) = rx.recv().await {
        let mut buf = BytesMut::new();
        send.packet.emit(&mut buf, send.src, send.dst);

        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn6 = SocketAddrV6::new(send.dst, 0, 0, 0).into();
        let pktinfo = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: send.src.octets(),
            },
            ipi6_ifindex: send.ifindex,
        };
        let cmsg = [socket::ControlMessage::Ipv6PacketInfo(&pktinfo)];

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
