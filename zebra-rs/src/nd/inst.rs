//! Async wrapper around [`super::engine::NdEngine`]. Owns the raw
//! ICMPv6 socket, spawns the read / write tasks, and runs the
//! `tokio::select!` loop that drives the engine in real time.
//!
//! `Nd::new()` constructs the instance and immediately spawns the
//! read and write tasks. [`serve`] takes ownership and drives the
//! event loop on a third spawned task. Nothing calls `serve` from
//! `main.rs` yet — the YANG-config PR (RA-5) wires it in.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep_until;

use crate::context::Task;

use super::engine::{NdEngine, NdEvent};
use super::network::{read_packet, write_packet};
use super::send::RaSendConfig;
use super::socket::{SocketError, nd_socket};
use super::{NdRecv, NdSend};

/// Control requests from external clients (the YANG callback layer
/// in RA-5, and tests).
#[derive(Debug)]
pub enum NdClientReq {
    EnableInterface { ifindex: u32, cfg: RaSendConfig },
    DisableInterface { ifindex: u32 },
}

/// Top-level ND instance.
pub struct Nd {
    engine: NdEngine,
    recv_rx: UnboundedReceiver<NdRecv>,
    send_tx: UnboundedSender<NdSend>,
    client_rx: UnboundedReceiver<NdClientReq>,
    client_tx: UnboundedSender<NdClientReq>,
    // Hold the spawned read / write tasks so dropping `Nd` aborts them.
    _read_task: Task<()>,
    _write_task: Task<()>,
}

impl Nd {
    /// Build a new instance. Opens the raw socket and spawns the
    /// read / write tasks immediately. The event loop is *not* spawned
    /// here — call [`serve`] for that.
    pub fn new() -> Result<Self, SocketError> {
        let socket = Arc::new(nd_socket()?);
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

        Ok(Self {
            engine: NdEngine::new(),
            recv_rx,
            send_tx,
            client_rx,
            client_tx,
            _read_task: read_task,
            _write_task: write_task,
        })
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

    fn process_client_req(&mut self, req: NdClientReq) {
        match req {
            NdClientReq::EnableInterface { ifindex, cfg } => {
                self.engine.enable_interface(ifindex, cfg, Instant::now());
            }
            NdClientReq::DisableInterface { ifindex } => {
                self.engine.disable_interface(ifindex);
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
