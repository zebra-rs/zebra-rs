use std::collections::HashMap;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::Response;
use tonic::transport::Server;

use crate::config::api::DeployRequest;

use super::api::{
    CompletionRequest, CompletionResponse, DisplayRequest, DisplayTxRequest, ExecuteRequest,
    ExecuteResponse, Message,
};
use super::vtysh::apply_server::{Apply, ApplyServer};
use super::vtysh::exec_server::{Exec, ExecServer};
use super::vtysh::show_server::{Show, ShowServer};
use super::vtysh::{
    ApplyCode, ApplyReply, ApplyRequest, CommandPath, ExecCode, ExecReply, ExecRequest, ExecType,
    ShowReply, ShowRequest, YangMatch,
};
#[derive(Debug)]
struct ExecService {
    pub tx: mpsc::Sender<Message>,
}

impl ExecService {
    async fn execute_request(&self, mode: &str, input: &str) -> ExecuteResponse {
        let (tx, rx) = oneshot::channel();
        let req = ExecuteRequest::new(mode, input, tx);
        self.tx.send(Message::Execute(req)).await.unwrap();
        rx.await.unwrap()
    }

    async fn completion_request(&self, mode: &str, input: &str) -> CompletionResponse {
        let (tx, rx) = oneshot::channel();
        let req = CompletionRequest::new(mode, input, tx);
        self.tx.send(Message::Completion(req)).await.unwrap();
        rx.await.unwrap()
    }

    fn reply(&self, code: ExecCode, lines: String) -> Result<Response<ExecReply>, tonic::Status> {
        let reply = ExecReply {
            code: code as i32,
            candidates: Vec::new(),
            lines,
            port: 2666,
            paths: Vec::new(),
        };
        Ok(Response::new(reply))
    }

    fn reply_exec(
        &self,
        code: ExecCode,
        lines: String,
        paths: Vec<CommandPath>,
    ) -> Result<Response<ExecReply>, tonic::Status> {
        let reply = ExecReply {
            code: code as i32,
            candidates: Vec::new(),
            lines,
            port: 2666,
            paths,
        };
        Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl Exec for ExecService {
    async fn do_exec(
        &self,
        request: tonic::Request<ExecRequest>,
    ) -> Result<Response<ExecReply>, tonic::Status> {
        let request = request.get_ref();
        match request.r#type {
            x if x == ExecType::Exec as i32 => {
                let resp = self.execute_request(&request.mode, &request.line).await;
                let (code, output, paths) = exec_commands(&resp);
                self.reply_exec(code, output, paths)
            }
            x if x == ExecType::CompleteFirstCommands as i32 => {
                let resp = self.completion_request(&request.mode, &request.line).await;
                self.reply(ExecCode::Success, first_commands(&resp))
            }
            x if x == ExecType::Complete as i32 => {
                let resp = self.completion_request(&request.mode, &request.line).await;
                self.reply(ExecCode::Success, comp_commands(&resp))
            }
            x if x == ExecType::CompleteTrailingSpace as i32 => {
                let mut input = request.line.clone();
                input.push(' ');
                let resp = self.completion_request(&request.mode, &input).await;
                self.reply(ExecCode::Success, comp_commands(&resp))
            }
            _ => self.reply(ExecCode::Success, String::from("Success\n")),
        }
    }
}

fn first_commands(resp: &CompletionResponse) -> String {
    let estimated_capacity = resp.comps.len() * 20;
    let mut s = String::with_capacity(estimated_capacity);
    for comp in resp.comps.iter() {
        s.push_str(&comp.name);
        s.push('\n');
    }
    s
}

fn comp_commands(resp: &CompletionResponse) -> String {
    let base_size = match resp.code {
        ExecCode::Success => 8,
        ExecCode::Incomplete => 12,
        ExecCode::Nomatch => 9,
        ExecCode::Ambiguous => 11,
        _ => 9,
    };
    let estimated_capacity = base_size + (resp.comps.len() * 50);
    let mut line = String::with_capacity(estimated_capacity);

    line.push_str(match resp.code {
        ExecCode::Success => "Success\n",
        ExecCode::Incomplete => "Incomplete\n",
        ExecCode::Nomatch => "NoMatch\n",
        ExecCode::Ambiguous => "Ambiguous\n",
        _ => "NoMatch\n",
    });

    for comp in resp.comps.iter() {
        if comp.ymatch == YangMatch::Key {
            line.push_str(&comp.name);
            line.push_str("\t+>\t");
            line.push_str(&comp.help);
            line.push('\n');
        } else if comp.ymatch == YangMatch::Dir {
            line.push_str(&comp.name);
            line.push_str("\t->\t");
            line.push_str(&comp.help);
            line.push('\n');
        } else {
            line.push_str(&comp.name);
            line.push_str("\t  \t");
            line.push_str(&comp.help);
            line.push('\n');
        }
    }
    line
}

fn exec_commands(resp: &ExecuteResponse) -> (ExecCode, String, Vec<CommandPath>) {
    if resp.code == ExecCode::Nomatch {
        return (
            ExecCode::Nomatch,
            String::from("NoMatch\n"),
            resp.paths.clone(),
        );
    }
    if resp.code == ExecCode::Ambiguous {
        return (
            ExecCode::Ambiguous,
            String::from("Ambiguous\n"),
            resp.paths.clone(),
        );
    }
    if resp.code == ExecCode::Incomplete {
        return (
            ExecCode::Incomplete,
            String::from("Incomplete\n"),
            resp.paths.clone(),
        );
    }
    (resp.code, resp.output.to_owned(), resp.paths.clone())
}

#[derive(Debug)]
struct ShowService {
    pub tx: mpsc::Sender<Message>,
}

#[tonic::async_trait]
impl Show for ShowService {
    type ShowStream = ReceiverStream<Result<ShowReply, tonic::Status>>;

    async fn show(
        &self,
        request: tonic::Request<ShowRequest>,
    ) -> std::result::Result<Response<Self::ShowStream>, tonic::Status> {
        let request = request.get_ref();

        let (tx, rx) = oneshot::channel();
        let query = DisplayTxRequest {
            paths: request.paths.clone(),
            resp: tx,
        };
        self.tx.send(Message::DisplayTx(query)).await.unwrap();
        let serve = rx.await.unwrap();
        let (bus_tx, mut bus_rx) = mpsc::channel::<String>(4);
        let req = DisplayRequest {
            paths: request.paths.clone(),
            json: request.json,
            resp: bus_tx.clone(),
        };
        serve.tx.send(req).unwrap();

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(item) = bus_rx.recv().await {
                match tx.send(Ok(ShowReply { str: item })).await {
                    Ok(_) => {}
                    Err(_) => {
                        break;
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

pub struct Cli {
    pub tx: mpsc::Sender<Message>,
    pub show_clients: HashMap<String, UnboundedSender<DisplayRequest>>,
}

impl Cli {
    pub fn new(config_tx: Sender<Message>) -> Self {
        Self {
            tx: config_tx,
            show_clients: HashMap::new(),
        }
    }

    pub fn subscribe(&mut self, name: &str, tx: UnboundedSender<DisplayRequest>) {
        self.show_clients.insert(name.to_string(), tx);
    }
}

struct ApplyService {
    pub tx: mpsc::Sender<Message>,
}

#[tonic::async_trait]
impl Apply for ApplyService {
    async fn apply(
        &self,
        request: tonic::Request<tonic::Streaming<ApplyRequest>>,
    ) -> Result<tonic::Response<ApplyReply>, tonic::Status> {
        let mut stream = request.into_inner();

        // Process the stream of requests
        let mut config = String::new();
        while let Some(req) = stream.next().await {
            match req {
                Ok(ApplyRequest { line }) => {
                    config.push_str(&line);
                }
                Err(e) => {
                    eprintln!("Error receiving request: {}", e);
                    return Err(tonic::Status::internal("Failed to receive request."));
                }
            }
        }

        let (tx, rx) = oneshot::channel();
        let deploy = DeployRequest { config, resp: tx };
        self.tx.send(Message::Deploy(deploy)).await.unwrap();
        let _resp = rx.await.unwrap();

        let code = ApplyCode::Applied;
        let description = String::from("All lines processed successfully.");

        // Create the reply based on the processing outcome
        let reply = ApplyReply {
            code: code as i32,
            description,
        };

        // Return the response
        Ok(Response::new(reply))
    }
}

pub fn serve(cli: Cli) {
    let exec_service = ExecService { tx: cli.tx.clone() };
    let exec_server = ExecServer::new(exec_service);

    let show_service = ShowService { tx: cli.tx.clone() };
    let show_server = ShowServer::new(show_service);

    let apply_service = ApplyService { tx: cli.tx.clone() };
    let apply_server = ApplyServer::new(apply_service);

    let addr = "0.0.0.0:2666".parse().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(exec_server)
            .add_service(show_server)
            .add_service(apply_server)
            .serve(addr)
            .await
    });
}
