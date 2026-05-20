//! Async wrapper around [`super::engine::NdEngine`]. Owns the raw
//! ICMPv6 socket, spawns the read / write tasks, and runs the
//! `tokio::select!` loop that drives the engine in real time.
//!
//! `Nd::new()` constructs the instance and immediately spawns the
//! read and write tasks. [`serve`] takes ownership and drives the
//! event loop on a third spawned task. The daemon's
//! [`crate::config::ConfigManager`] calls both at startup.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep_until;

use crate::config::{ConfigChannel, ConfigRequest, path_from_command};
use crate::context::Task;
use crate::rib::api::RibRx;

use super::config::Callback;
use super::engine::{NdEngine, NdEvent};
use super::network::{read_packet, write_packet};
use super::send::RaSendConfig;
use super::{NdRecv, NdSend};

/// Control requests from external clients (the YANG callback layer
/// in RA-5, BGP unnumbered for the `SetNotifier` variant, and tests).
#[derive(Debug)]
pub enum NdClientReq {
    EnableInterface {
        ifindex: u32,
        cfg: RaSendConfig,
    },
    DisableInterface {
        ifindex: u32,
    },
    /// Attach a downstream subscriber for [`NdEvent`]. Replaces any
    /// previously-attached notifier; consumers needing fan-out should
    /// layer a broadcast outside.
    SetNotifier {
        tx: UnboundedSender<NdEvent>,
    },
}

/// Top-level ND instance.
pub struct Nd {
    engine: NdEngine,
    recv_rx: UnboundedReceiver<NdRecv>,
    send_tx: UnboundedSender<NdSend>,
    client_rx: UnboundedReceiver<NdClientReq>,
    client_tx: UnboundedSender<NdClientReq>,
    rib_rx: UnboundedReceiver<RibRx>,
    /// Config-manager subscription endpoints. The receive half drains
    /// in the event loop and feeds [`Self::process_cm_msg`].
    pub cm: ConfigChannel,
    /// Callback table — path → handler — populated by
    /// [`Self::callback_build`] (in `super::config`) and consumed by
    /// [`Self::process_cm_msg`].
    pub callbacks: HashMap<String, Callback>,
    // Hold the spawned read / write tasks so dropping `Nd` aborts them.
    _read_task: Task<()>,
    _write_task: Task<()>,
}

impl Nd {
    /// Build a new instance from a pre-opened raw ICMPv6 socket.
    ///
    /// Spawns the read / write tasks and wires up the RIB
    /// subscription channel so the engine learns about links as the
    /// kernel exposes them. The event loop is *not* spawned here —
    /// call [`serve`] for that.
    ///
    /// The socket is opened by the caller (see `super::socket::nd_socket`)
    /// so that socket failures can be detected *before* registering a
    /// `RibRx` subscriber — otherwise the caller would have to drop
    /// `rib_rx` on the error path, leaving a dead receiver queued in
    /// RIB's inbox and causing a panic when RIB tries to dump links.
    pub fn new(socket: AsyncFd<Socket>, rib_rx: UnboundedReceiver<RibRx>) -> Self {
        let socket = Arc::new(socket);
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        let (client_tx, client_rx) = mpsc::unbounded_channel();

        let read_socket = socket.clone();
        let read_task = Task::spawn(async move {
            read_packet(read_socket, recv_tx).await;
        });
        let write_socket = socket;
        let write_task = Task::spawn(async move {
            write_packet(write_socket, send_rx).await;
        });

        let mut nd = Self {
            engine: NdEngine::new(),
            recv_rx,
            send_tx,
            client_rx,
            client_tx,
            rib_rx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            _read_task: read_task,
            _write_task: write_task,
        };
        nd.callback_build();
        nd
    }

    /// Internal accessor for callbacks living in [`super::config`].
    pub(super) fn engine(&self) -> &NdEngine {
        &self.engine
    }

    /// Internal accessor for callbacks living in [`super::config`].
    pub(super) fn engine_mut(&mut self) -> &mut NdEngine {
        &mut self.engine
    }

    /// Clone of the client-request sender. Distribute to YANG callback
    /// glue / tests so they can drive `EnableInterface` etc.
    pub fn client_tx(&self) -> UnboundedSender<NdClientReq> {
        self.client_tx.clone()
    }

    /// Attach the single downstream subscriber. The BGP unnumbered
    /// runtime calls this once at startup.
    pub fn set_notifier(&mut self, tx: UnboundedSender<NdEvent>) {
        self.engine.set_notifier(tx);
    }

    async fn event_loop(&mut self) {
        loop {
            let wakeup = self.engine.next_wakeup();
            tokio::select! {
                Some(msg) = self.recv_rx.recv() => {
                    self.engine.on_recv(msg, Instant::now());
                }
                Some(req) = self.client_rx.recv() => {
                    self.process_client_req(req);
                }
                Some(rmsg) = self.rib_rx.recv() => {
                    self.process_rib_msg(rmsg);
                }
                Some(cmsg) = self.cm.rx.recv() => {
                    self.process_cm_msg(cmsg);
                }
                _ = sleep_until_opt(wakeup) => {
                    let now = Instant::now();
                    for frame in self.engine.tick(now) {
                        // SendError is benign — the write task may be
                        // back-pressured for a moment; the next tick
                        // will retry.
                        let _ = self.send_tx.send(frame);
                    }
                }
            }
        }
    }

    fn process_rib_msg(&mut self, msg: RibRx) {
        // Only LinkAdd is interesting at this stage; the engine doesn't
        // need address or route notifications yet (those land when the
        // BGP unnumbered hand-off needs to derive the local source
        // link-local in a follow-up PR).
        if let RibRx::LinkAdd(link) = msg {
            self.engine.process_link_add(&link);
        }
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path).copied() {
            f(self, args, msg.op);
        }
    }

    fn process_client_req(&mut self, req: NdClientReq) {
        match req {
            NdClientReq::EnableInterface { ifindex, cfg } => {
                self.engine.enable_interface(ifindex, cfg, Instant::now());
            }
            NdClientReq::DisableInterface { ifindex } => {
                self.engine.disable_interface(ifindex);
            }
            NdClientReq::SetNotifier { tx } => {
                self.engine.set_notifier(tx);
            }
        }
    }
}

/// Spawn the event loop. Mirrors [`crate::bfd::serve`].
pub fn serve(mut nd: Nd) -> Task<()> {
    Task::spawn(async move {
        nd.event_loop().await;
    })
}

/// Park `tokio::time::sleep_until` on a far-future Instant when the
/// engine has nothing scheduled, so the `select!` arm never wakes
/// up spuriously. `sleep_until(None)` isn't a thing in tokio, so we
/// roll our own.
async fn sleep_until_opt(when: Option<Instant>) {
    match when {
        Some(t) => sleep_until(t.into()).await,
        None => std::future::pending::<()>().await,
    }
}
