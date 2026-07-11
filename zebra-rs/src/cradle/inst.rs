//! The cradle supervisor task: consumes `/system/ebpf/*` (its own knob) and
//! `/system/cradle/grpc-endpoint` (shared with the tee) from the config
//! broadcast, and reconciles a running [`supervisor`] loop against the
//! committed state at each `CommitEnd`.

use tokio::sync::watch;
use tracing::info;

use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, path_from_command};
use crate::context::Task;

use super::supervisor;

/// The tee's default endpoint (`fib/cradle.rs` / `rib`), which is also
/// cradle's own `--grpc` default: a Linux abstract socket, per-netns.
const DEFAULT_ENDPOINT: &str = "unix:cradle/grpc";

/// A running supervisor loop for one desired endpoint.
struct Engine {
    endpoint: String,
    /// Flipping this to `true` asks the loop to stop: it SIGTERMs a child
    /// it spawned (never an adopted instance) and exits.
    shutdown: watch::Sender<bool>,
    task: Task<()>,
}

/// Top-level supervisor instance, registered like the other modules
/// (`spawn_cradle` in `config/cradle.rs`).
pub struct Cradle {
    /// Config-manager subscription endpoints; drained by [`Self::event_loop`].
    pub cm: ConfigChannel,
    /// Staged `system ebpf enabled` (applied at `CommitEnd`).
    ebpf_enabled: bool,
    /// Staged `system cradle grpc-endpoint` override.
    grpc_endpoint: Option<String>,
    engine: Option<Engine>,
}

impl Cradle {
    pub fn new() -> Self {
        Self {
            cm: ConfigChannel::new(),
            ebpf_enabled: false,
            grpc_endpoint: None,
            engine: None,
        }
    }

    pub async fn event_loop(&mut self) {
        while let Some(msg) = self.cm.rx.recv().await {
            self.process_cm_msg(msg);
        }
    }

    fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, mut args) = path_from_command(&msg.paths);
                match path.as_str() {
                    "/system/ebpf/enabled" => {
                        self.ebpf_enabled = msg.op.is_set() && args.boolean().unwrap_or(false);
                    }
                    "/system/cradle/grpc-endpoint" => {
                        self.grpc_endpoint = if msg.op.is_set() { args.string() } else { None };
                    }
                    _ => {}
                }
            }
            ConfigOp::CommitEnd => self.reconcile(),
            _ => {}
        }
    }

    /// Desired engine endpoint: `None` when `system ebpf` is off, else the
    /// `system cradle grpc-endpoint` override or the shared default.
    fn desired(&self) -> Option<String> {
        self.ebpf_enabled.then(|| {
            self.grpc_endpoint
                .clone()
                .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string())
        })
    }

    /// Converge the running supervisor loop on the committed state. An
    /// endpoint change restarts the loop (the engine must re-listen there);
    /// disabling stops it gracefully.
    fn reconcile(&mut self) {
        let desired = self.desired();
        if self.engine.as_ref().map(|e| e.endpoint.as_str()) == desired.as_deref() {
            return;
        }
        if let Some(engine) = self.engine.take() {
            info!("cradle: stopping engine supervisor for {}", engine.endpoint);
            let _ = engine.shutdown.send(true);
            // Let the loop run its graceful SIGTERM path instead of
            // aborting it (Task aborts on drop).
            engine.task.detach();
        }
        if let Some(endpoint) = desired {
            info!("cradle: starting engine supervisor for {endpoint}");
            let (shutdown, shutdown_rx) = watch::channel(false);
            let ep = endpoint.clone();
            let task = Task::spawn(async move {
                supervisor::run(ep, shutdown_rx).await;
            });
            self.engine = Some(Engine {
                endpoint,
                shutdown,
                task,
            });
        }
    }
}

pub fn serve(mut cradle: Cradle) -> Task<()> {
    Task::spawn(async move {
        cradle.event_loop().await;
    })
}
