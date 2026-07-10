use super::vty::CommandPath;
use super::{ApplyCode, Completion, ExecCode};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::Sender;

#[derive(Debug)]
pub struct ConfigChannel {
    pub tx: UnboundedSender<ConfigRequest>,
    pub rx: UnboundedReceiver<ConfigRequest>,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, PartialOrd, Ord)]
pub enum ConfigOp {
    CommitStart,
    CommitEnd,
    Set,
    Delete,
    Completion,
    Clear,
}

impl ConfigOp {
    pub fn is_set(&self) -> bool {
        *self == ConfigOp::Set
    }
}

#[derive(Debug)]
pub struct ConfigRequest {
    pub paths: Vec<CommandPath>,
    pub op: ConfigOp,
    pub resp: Option<Sender<Vec<String>>>,
}

impl ConfigRequest {
    pub fn new(paths: Vec<CommandPath>, op: ConfigOp) -> Self {
        Self {
            paths,
            op,
            resp: None,
        }
    }
}

impl ConfigChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

#[derive(Debug)]
pub struct ExecuteRequest {
    pub mode: String,
    pub input: String,
    pub resp: Sender<ExecuteResponse>,
}

#[derive(Debug, Default)]
pub struct ExecuteResponse {
    pub code: ExecCode,
    pub output: String,
    pub paths: Vec<CommandPath>,
    /// The running-config `system hostname` value, or `None` when
    /// unconfigured. Carried on every Execute reply; the vty shell
    /// queries it via `vtyhelper -H` (startup seed + the
    /// post-command `_cli_hostname_refresh`) to keep the prompt in
    /// sync. Read from the running store, so the reply to the very
    /// `commit` that changes the hostname already carries the new
    /// name.
    pub hostname: Option<String>,
}

#[derive(Debug)]
pub struct CompletionRequest {
    pub mode: String,
    pub input: String,
    pub interactive: bool,
    pub resp: Sender<CompletionResponse>,
}

#[derive(Debug, Default)]
pub struct CompletionResponse {
    pub code: ExecCode,
    pub comps: Vec<Completion>,
}

impl ExecuteRequest {
    pub fn new(mode: &str, input: &str, resp: Sender<ExecuteResponse>) -> Self {
        Self {
            mode: mode.to_string(),
            input: input.to_string(),
            resp,
        }
    }
}

impl ExecuteResponse {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

impl CompletionRequest {
    pub fn new(
        mode: &str,
        input: &str,
        interactive: bool,
        resp: Sender<CompletionResponse>,
    ) -> Self {
        Self {
            mode: mode.to_string(),
            input: input.to_string(),
            interactive,
            resp,
        }
    }
}

impl CompletionResponse {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct DeployRequest {
    pub config: String,
    pub resp: Sender<DeployResponse>,
}

#[derive(Debug, Default)]
pub struct DeployResponse {
    pub apply_code: ApplyCode,
    pub exec_code: ExecCode,
    pub cmd: String,
}

#[derive(Debug)]
pub struct DisplayTxRequest {
    pub paths: Vec<CommandPath>,
    pub resp: Sender<DisplayTxResponse>,
}

#[derive(Debug)]
pub struct DisplayTxResponse {
    pub tx: UnboundedSender<DisplayRequest>,
    /// When the manager rewrote the command (e.g. stripped a
    /// `vrf <name>` selector to redirect into an instance task), the
    /// caller must dispatch these paths instead of the original.
    pub paths: Option<Vec<CommandPath>>,
}

#[derive(Debug)]
pub enum Message {
    Execute(ExecuteRequest),
    Completion(CompletionRequest),
    Deploy(DeployRequest),
    DisplayTx(DisplayTxRequest),
    ClearTx(ClearTxRequest),
    /// Register a per-instance (e.g. per-VRF) show channel under a
    /// composite key like `"bgp:vrf:<name>"`, so the manager can
    /// redirect `show <proto> vrf <name> …` into that task.
    SubscribeShowVrf {
        key: String,
        tx: UnboundedSender<DisplayRequest>,
    },
    /// Remove a previously-registered per-instance show channel.
    UnsubscribeShowVrf {
        key: String,
    },
}

#[derive(Debug)]
pub struct ShowChannel {
    pub tx: UnboundedSender<DisplayRequest>,
    pub rx: UnboundedReceiver<DisplayRequest>,
}

impl ShowChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

#[derive(Debug)]
pub struct DisplayRequest {
    pub paths: Vec<CommandPath>,
    pub json: bool,
    pub resp: mpsc::Sender<String>,
}

#[derive(Debug)]
pub struct ClearTxRequest {
    pub paths: Vec<CommandPath>,
    pub resp: Sender<ClearTxResponse>,
}

#[derive(Debug)]
pub struct ClearTxResponse {
    pub result: i32,
    pub output: String,
}
