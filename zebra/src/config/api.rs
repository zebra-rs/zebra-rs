use super::{Completion, ExecCode};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::Sender;

#[derive(Debug)]
pub struct ConfigChannel {
    pub tx: UnboundedSender<String>,
    pub rx: UnboundedReceiver<String>,
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
pub enum Message {
    Execute(ExecuteRequest),
    Completion(CompletionRequest),
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
    pub resp: mpsc::Sender<String>,
}
