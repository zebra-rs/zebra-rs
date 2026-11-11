//! Async wrapper around [`super::engine::NdEngine`]. Owns the raw
//! ICMPv6 socket, spawns the read task, and runs the `tokio::select!`
//! loop that drives the engine in real time and writes its RAs.
//!
//! `Nd::new()` constructs the instance and immediately spawns the
//! read task. [`serve`] takes ownership and drives the event loop on
//! a second spawned task. The daemon's
//! [`crate::config::ConfigManager`] calls both at startup.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep_until;

use crate::config::{
    Args, ConfigChannel, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::Task;
use crate::resolver::{Report, ResolverTx, Source};
use crate::rib::api::RibRx;
use crate::rib::client::RibClient;

use super::NdRecv;
use super::config::Callback;
use super::engine::{NdEngine, NdEvent};
use super::host::HostAction;
use super::network::{read_packet, send_packet};
use super::send::RaSendConfig;

/// `show nd ...` dispatch handler. Mirrors [`crate::bfd::inst::ShowCallback`]:
/// given the Nd instance, parsed trailing [`Args`], and the JSON flag,
/// renders the response text.
pub type ShowCallback = fn(&Nd, Args, bool) -> Result<String, std::fmt::Error>;

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
    /// Shared with the read task. The event loop writes RAs on it
    /// directly, so the engine learns at once whether each went out.
    socket: Arc<AsyncFd<Socket>>,
    recv_rx: UnboundedReceiver<NdRecv>,
    client_rx: UnboundedReceiver<NdClientReq>,
    client_tx: UnboundedSender<NdClientReq>,
    /// The RA host's routes and SLAAC addresses go to the RIB here.
    rib: RibClient,
    rib_rx: UnboundedReceiver<RibRx>,
    /// What the RA host learns of name resolution (RDNSS, DNSSL) is
    /// reported here ([`crate::resolver`]).
    resolver: Option<ResolverTx>,
    /// Config-manager subscription endpoints. The receive half drains
    /// in the event loop and feeds [`Self::process_cm_msg`].
    pub cm: ConfigChannel,
    /// `show ipv6 nd ...` subscription endpoints. The receive half
    /// drains in the event loop and dispatches through
    /// [`Self::show_cb`].
    pub show: ShowChannel,
    /// Show callback table — path → handler — populated by
    /// [`Self::show_build`] (in `super::show`) and consulted by
    /// [`Self::process_show_msg`].
    pub show_cb: HashMap<String, ShowCallback>,
    /// Callback table — path → handler — from
    /// [`super::config::callbacks`], consumed by
    /// [`Self::process_cm_msg`].
    pub callbacks: HashMap<String, Callback>,
    // Hold the spawned read task so dropping `Nd` aborts it.
    _read_task: Task<()>,
}

impl Nd {
    /// Build a new instance from a pre-opened raw ICMPv6 socket.
    ///
    /// Spawns the read task and wires up the RIB
    /// subscription channel so the engine learns about links as the
    /// kernel exposes them. The event loop is *not* spawned here —
    /// call [`serve`] for that.
    ///
    /// The socket is opened by the caller (see `super::socket::nd_socket`)
    /// so that socket failures can be detected *before* registering a
    /// `RibRx` subscriber — otherwise the caller would have to drop
    /// `rib_rx` on the error path, leaving a dead receiver queued in
    /// RIB's inbox and causing a panic when RIB tries to dump links.
    pub fn new(socket: AsyncFd<Socket>, rib: RibClient, rib_rx: UnboundedReceiver<RibRx>) -> Self {
        let socket = Arc::new(socket);
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let (client_tx, client_rx) = mpsc::unbounded_channel();

        let read_socket = socket.clone();
        let read_task = Task::spawn(async move {
            read_packet(read_socket, recv_tx).await;
        });

        let mut nd = Self {
            engine: NdEngine::new(),
            socket,
            recv_rx,
            client_rx,
            client_tx,
            rib,
            rib_rx,
            resolver: None,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            callbacks: super::config::callbacks(),
            _read_task: read_task,
        };
        nd.show_build();
        nd
    }

    /// Internal accessor for the show callbacks in [`super::show`].
    pub(super) fn engine(&self) -> &NdEngine {
        &self.engine
    }

    /// Report the RA host's name servers and search domains to the
    /// resolver task, which gives the system resolver what it is told
    /// of.
    pub fn set_resolver(&mut self, resolver: ResolverTx) {
        self.resolver = Some(resolver);
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
        // Drain RIB's initial dump up to `EoR` before selecting on
        // the other channels. `commit_config` enqueues ConfigRequests
        // synchronously in the same call that spawned us, while the
        // link dump makes a round trip through the RIB task — so
        // without this barrier a `send-advertisements` callback can
        // run before the LinkAdds that feed name → ifindex
        // resolution. The engine's name-keyed pending config covers
        // links that appear later (and would absorb this race too);
        // the barrier makes the cold-start ordering deterministic so
        // config applies on the spot instead of waiting for a replay.
        while let Some(msg) = self.rib_rx.recv().await {
            if matches!(msg, RibRx::EoR) {
                break;
            }
            self.process_rib_msg(msg);
        }
        self.perform_host_actions();
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
                Some(smsg) = self.show.rx.recv() => {
                    self.process_show_msg(smsg).await;
                }
                _ = sleep_until_opt(wakeup) => {
                    let socket = self.socket.get_ref();
                    self.engine
                        .tick(Instant::now(), |frame| send_packet(socket, frame));
                }
            }
            self.perform_host_actions();
        }
    }

    /// Do what the RA host has asked for since the last event: hand its
    /// routes and addresses to the RIB, its name servers to the resolver
    /// task, and turn the kernel's own RA processing off where it runs.
    fn perform_host_actions(&mut self) {
        for action in self.engine.hosts_mut().take_actions() {
            match action {
                HostAction::DisableKernelRa { ifname } => disable_kernel_ra(&ifname),
                HostAction::Dns { ifname, dns } => {
                    if let Some(resolver) = &self.resolver {
                        let _ = resolver.send(Report {
                            ifname,
                            source: Source::Ra,
                            dns,
                        });
                    }
                }
                action => {
                    if let Some(msg) = action.into_message() {
                        let _ = self.rib.send(msg);
                    }
                }
            }
        }
    }

    /// Stamp the arrival time and hand the notification to the engine.
    /// The dispatch itself lives in [`NdEngine::process_rib_msg`] so it
    /// can be unit-tested — `Nd` owns a raw ICMPv6 socket and cannot be
    /// constructed without `CAP_NET_RAW`.
    fn process_rib_msg(&mut self, msg: RibRx) {
        self.engine.process_rib_msg(msg, Instant::now());
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        super::config::dispatch(&mut self.engine, &self.callbacks, msg, Instant::now());
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            let _ = msg.resp.send(output).await;
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

/// Turn the kernel's own Router Advertisement processing off on `ifname`
/// (docs/design/dhcp-client.md D4): the RA host handles RAs there, and a
/// kernel default route under `proto ra` would sit beside its route, at a
/// distance of 0 to the RIB. Forwarding already makes the kernel ignore
/// `accept_ra=1`, but not `accept_ra=2`, and not a later per-interface
/// forwarding change. Written through `/proc` rather than the dotted
/// sysctl name, which a VLAN interface's own dot (`eth0.100`) would split.
fn disable_kernel_ra(ifname: &str) {
    for knob in ["accept_ra", "autoconf"] {
        let path = format!("/proc/sys/net/ipv6/conf/{ifname}/{knob}");
        if let Err(e) = std::fs::write(&path, "0") {
            tracing::warn!("nd: {ifname}: could not turn the kernel's {knob} off ({path}): {e}");
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
