use super::vtysh::CommandPath;
use super::{Completion, ExecCode};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::Sender;

#[derive(Debug)]
pub struct ConfigChannel {
    pub tx: UnboundedSender<ConfigRequest>,
    pub rx: UnboundedReceiver<ConfigRequest>,
}

#[derive(Debug, PartialEq, Clone, Eq, PartialOrd, Ord)]
pub enum ConfigOp {
    CommitStart,
    CommitEnd,
    Set,
    Delete,
    Completion,
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
}

#[derive(Debug)]
pub struct CompletionRequest {
    pub mode: String,
    pub input: String,
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
    pub fn new(mode: &str, input: &str, resp: Sender<CompletionResponse>) -> Self {
        Self {
            mode: mode.to_string(),
            input: input.to_string(),
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
    // pub code: u32,
    // pub output: String,
}

#[derive(Debug)]
pub enum Message {
    Execute(ExecuteRequest),
    Completion(CompletionRequest),
    Deploy(DeployRequest),
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
