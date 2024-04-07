use super::{Completion, ExecCode};
use tokio::sync::mpsc;
use tokio::sync::oneshot::Sender;

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

// #[derive(Debug)]
// pub struct SubscribeRequest {
//     pub resp: Sender<String>,
// }

// #[derive(Debug, Default)]
// pub struct SubscribeResponse {
//     pub code: ExecCode,
//     pub comps: Vec<Completion>,
// }

#[derive(Debug)]
pub enum Message {
    Execute(ExecuteRequest),
    Completion(CompletionRequest),
    //Subscribe(),
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DisplayRequest {
    pub resp: mpsc::Sender<String>,
}
