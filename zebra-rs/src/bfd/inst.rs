use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{ConfigChannel, ConfigRequest, path_from_command};
use crate::context::{Context, Task};

use super::config::{BfdConfig, Callback};
use super::fsm::Event;
use super::network::{WriteRequest, read_packet, write_packet};
use super::session::{Session, SessionKey, SessionParams, SessionTable, StateChange};
use super::socket::{BFD_SINGLE_HOP_PORT, bfd_socket_ipv4};
use super::timer::{InitialParams, TimerCmd, session_timer};

/// Top-level BFD instance. Owns the IPv4 single-hop UDP socket, the
/// session table, the committed YANG config mirror, and a
/// per-session timer handle map. Read and write tasks are
/// tokio-spawned at construction and feed the event loop via
/// `main_tx` / `write_tx`. The config-manager subscription drains
/// through `cm.rx`.
pub struct Bfd {
    pub rx: UnboundedReceiver<Message>,
    pub sessions: SessionTable,
    /// Local address the recv socket was bound to. Useful to tests
    /// that bind to ephemeral ports — `local_addr.port()` reveals the
    /// kernel-chosen value so the peer can be told where to send.
    pub local_addr: SocketAddrV4,
    /// In-memory mirror of `container bfd` from the committed config.
    /// Populated by per-leaf callbacks registered in
    /// [`Bfd::callback_build`].
    pub config: BfdConfig,
    /// Callback table — path → handler — used by [`Self::process_cm_msg`].
    pub callbacks: HashMap<String, Callback>,
    /// Config-manager subscription endpoints (the receive half drains
    /// in the event loop).
    pub cm: ConfigChannel,
    main_tx: UnboundedSender<Message>,
    write_tx: UnboundedSender<WriteRequest>,
    timer_handles: HashMap<SessionKey, TimerHandle>,
    notify_tx: Option<UnboundedSender<BfdEvent>>,
}

/// Holds the per-session timer task and its command channel. Dropping
/// the `Task` aborts the timer loop; the `cmd_tx` is used to update
/// intervals, reset the detection timer, and request graceful
/// shutdown.
struct TimerHandle {
    cmd_tx: UnboundedSender<TimerCmd>,
    _task: Task<()>,
}

#[derive(Debug)]
pub enum Message {
    /// A parsed, GTSM-validated control packet arrived.
    Recv {
        packet: bfd_packet::ControlPacket,
        src: SocketAddrV4,
        dst: Option<IpAddr>,
        ifindex: u32,
    },
    /// Periodic transmission timer fired for `key`.
    TxTick { key: SessionKey },
    /// Detection timer fired for `key`.
    DetectExpired { key: SessionKey },
}

/// Lifecycle events emitted by the instance for clients (tests today,
/// protocol modules like BGP / OSPF in later PRs) to observe.
#[derive(Debug, Clone, Copy)]
pub enum BfdEvent {
    StateChange {
        key: SessionKey,
        change: StateChange,
    },
}

impl Bfd {
    /// Production constructor — binds to `0.0.0.0:3784` and emits no
    /// `BfdEvent` notifications.
    pub fn new(ctx: Context) -> std::io::Result<Self> {
        Self::new_with(
            ctx,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, BFD_SINGLE_HOP_PORT),
            None,
        )
    }

    /// Explicit constructor that lets the caller pick the bind
    /// address (used by the integration test to run two instances on
    /// loopback ephemeral ports) and supply an optional [`BfdEvent`]
    /// notifier.
    pub fn new_with(
        _ctx: Context,
        bind: SocketAddrV4,
        notify_tx: Option<UnboundedSender<BfdEvent>>,
    ) -> std::io::Result<Self> {
        let sock = bfd_socket_ipv4(bind)?;
        let local_addr = sock
            .local_addr()?
            .as_socket_ipv4()
            .ok_or_else(|| std::io::Error::other("bound socket has no IPv4 local address"))?;
        let sock = Arc::new(AsyncFd::new(sock)?);

        let (main_tx, rx) = mpsc::unbounded_channel::<Message>();
        let (write_tx, write_rx) = mpsc::unbounded_channel::<WriteRequest>();

        let read_sock = sock.clone();
        let read_tx = main_tx.clone();
        tokio::spawn(async move {
            read_packet(read_sock, read_tx).await;
        });

        let write_sock = sock.clone();
        tokio::spawn(async move {
            write_packet(write_sock, write_rx).await;
        });

        let mut bfd = Self {
            rx,
            sessions: SessionTable::new(),
            local_addr,
            config: BfdConfig::default(),
            callbacks: HashMap::new(),
            cm: ConfigChannel::new(),
            main_tx,
            write_tx,
            timer_handles: HashMap::new(),
            notify_tx,
        };
        bfd.callback_build();
        Ok(bfd)
    }

    /// Dispatch a single committed config request through the
    /// per-leaf callback table.
    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path).copied() {
            f(self, args, msg.op);
        }
    }

    /// Insert a new session and spawn its timer task. Returns the
    /// locally-assigned, non-zero, collision-free discriminator.
    pub fn add_session(&mut self, key: SessionKey, params: SessionParams) -> u32 {
        let disc = self.sessions.insert(key, params);

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let initial = InitialParams {
            // No peer reply yet → start TX at our desired interval;
            // the negotiated value lands on the first Rx.
            tx_interval_us: params.desired_min_tx_us,
            // No peer reply yet → detection timer is not armed.
            detection_time_us: 0,
            detect_mult: params.detect_mult,
        };
        let main_tx = self.main_tx.clone();
        let task = Task::spawn(session_timer(key, initial, cmd_rx, main_tx));
        self.timer_handles.insert(
            key,
            TimerHandle {
                cmd_tx,
                _task: task,
            },
        );

        disc
    }

    /// Remove a session and shut down its timer task. Returns the
    /// removed session, if any.
    pub fn remove_session(&mut self, key: &SessionKey) -> Option<Session> {
        if let Some(h) = self.timer_handles.remove(key) {
            let _ = h.cmd_tx.send(TimerCmd::Shutdown);
        }
        self.sessions.remove(key)
    }

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => match msg {
                    Message::Recv { packet, src, dst, ifindex } =>
                        self.on_recv(packet, src, dst, ifindex),
                    Message::TxTick { key } => self.on_tx_tick(key),
                    Message::DetectExpired { key } => self.on_detect_expired(key),
                },
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
            }
        }
    }

    fn on_recv(
        &mut self,
        packet: bfd_packet::ControlPacket,
        src: SocketAddrV4,
        dst: Option<IpAddr>,
        ifindex: u32,
    ) {
        let lookup = if packet.your_disc != 0 {
            self.sessions.get_by_disc(packet.your_disc).map(|s| s.key)
        } else {
            self.bootstrap_lookup(src, ifindex)
        };
        let Some(key) = lookup else {
            tracing::debug!(
                ?src,
                ?dst,
                ifindex,
                your_disc = format_args!("{:#010x}", packet.your_disc),
                "bfd: no session matches received packet",
            );
            return;
        };

        let (change, new_tx_us, new_detect_us, new_detect_mult) = {
            let session = self
                .sessions
                .get_by_key_mut(&key)
                .expect("just looked up by key");
            let change = session.handle_packet(&packet);
            (
                change,
                session.tx_interval_us(),
                session.detection_time_us(),
                session.detect_mult,
            )
        };

        // Every valid Rx must reset the detection timer (RFC 5880
        // §6.8.4). When intervals are also negotiated freshly, the
        // Update command implicitly does the reset as part of arming.
        if let Some(h) = self.timer_handles.get(&key) {
            let _ = h.cmd_tx.send(TimerCmd::Update {
                tx_interval_us: new_tx_us,
                detection_time_us: new_detect_us,
                detect_mult: new_detect_mult,
            });
        }

        if let Some(change) = change {
            self.notify_state_change(key, change);
        }
    }

    /// Find an existing session that matches an incoming packet whose
    /// `Your Discriminator` is zero (RFC 5880 §6.8.6 bootstrap path).
    /// Linear scan — fine for the small session counts a single
    /// process maintains; an explicit (local, remote, ifindex) index
    /// can be added later if it shows up in profiles.
    fn bootstrap_lookup(&self, src: SocketAddrV4, ifindex: u32) -> Option<SessionKey> {
        let src_ip = IpAddr::V4(*src.ip());
        self.sessions.iter().find_map(|(_, s)| {
            let ifindex_match = s.key.ifindex == 0 || s.key.ifindex == ifindex;
            if s.key.remote == src_ip && ifindex_match {
                Some(s.key)
            } else {
                None
            }
        })
    }

    fn on_tx_tick(&self, key: SessionKey) {
        let Some(session) = self.sessions.get_by_key(&key) else {
            return;
        };
        let IpAddr::V4(remote) = session.key.remote else {
            // PR 7 adds IPv6.
            return;
        };
        let dst = SocketAddrV4::new(remote, session.dst_port);
        let ifindex = (session.key.ifindex != 0).then_some(session.key.ifindex);
        let _ = self.write_tx.send(WriteRequest {
            packet: session.build_packet(),
            dst,
            ifindex,
        });
    }

    fn on_detect_expired(&mut self, key: SessionKey) {
        let Some(session) = self.sessions.get_by_key_mut(&key) else {
            return;
        };
        let change = session.handle_event(Event::DetectExpired);
        if let Some(change) = change {
            self.notify_state_change(key, change);
        }
    }

    fn notify_state_change(&self, key: SessionKey, change: StateChange) {
        tracing::info!(
            ?key,
            from = %change.from,
            to = %change.to,
            diag = %change.diag,
            "bfd: session state change",
        );
        if let Some(tx) = &self.notify_tx {
            let _ = tx.send(BfdEvent::StateChange { key, change });
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
