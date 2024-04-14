use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::Response;

use super::api::{
    CompletionRequest, CompletionResponse, DisplayRequest, ExecuteRequest, ExecuteResponse, Message,
};
use super::vtysh::exec_server::{Exec, ExecServer};
use super::vtysh::show_server::{Show, ShowServer};
use super::vtysh::{
    CommandPath, ExecCode, ExecReply, ExecRequest, ExecType, ShowReply, ShowRequest, YangMatch,
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
            port: 2650,
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
            port: 2650,
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
    ) -> std::result::Result<Response<ExecReply>, tonic::Status> {
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
    let mut s = String::from("");
    for comp in resp.comps.iter() {
        s.push_str(&comp.name);
        s.push('\n');
    }
    s
}

fn comp_commands(resp: &CompletionResponse) -> String {
    let mut line = match resp.code {
        ExecCode::Success | ExecCode::Incomplete => String::from("Success\n"),
        ExecCode::Nomatch => String::from("NoMatch\n"),
        ExecCode::Ambiguous => String::from("Ambiguous\n"),
        _ => String::from("NoMatch\n"),
    };
    for comp in resp.comps.iter() {
        if comp.ymatch == YangMatch::Key {
            line.push_str(&format!("{}\t+>\t{}\n", comp.name, comp.help));
        } else if comp.ymatch == YangMatch::Dir {
            line.push_str(&format!("{}\t->\t{}\n", comp.name, comp.help));
        } else {
            line.push_str(&format!("{}\t  \t{}\n", comp.name, comp.help));
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
    txes: Vec<UnboundedSender<DisplayRequest>>,
}

#[tonic::async_trait]
impl Show for ShowService {
    type ShowStream = ReceiverStream<Result<ShowReply, tonic::Status>>;

    async fn show(
        &self,
        request: tonic::Request<ShowRequest>,
    ) -> std::result::Result<Response<Self::ShowStream>, tonic::Status> {
        let request = request.get_ref();
        let (bus_tx, mut bus_rx) = mpsc::channel::<String>(4);
        let req = DisplayRequest {
            paths: request.paths.clone(),
            resp: bus_tx.clone(),
        };
        if self.txes.len() > 0 {
            let tx = self.txes[0].clone();
            tx.send(req).unwrap();
        }

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
    pub txes: Vec<UnboundedSender<DisplayRequest>>,
}

impl Cli {
    pub fn new(config_tx: Sender<Message>) -> Self {
        Self {
            tx: config_tx,
            txes: Vec::new(),
        }
    }

    pub fn subscribe(&mut self, disp_tx: UnboundedSender<DisplayRequest>) {
        self.txes.push(disp_tx);
    }
}

pub fn serve(cli: Cli) {
    let exec_service = ExecService { tx: cli.tx.clone() };
    let exec_server = ExecServer::new(exec_service);

    let mut show_service = ShowService { txes: Vec::new() };
    for tx in cli.txes.iter() {
        show_service.txes.push(tx.clone());
    }
    let show_server = ShowServer::new(show_service);

    let addr = "0.0.0.0:2650".parse().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(exec_server)
            .add_service(show_server)
            .serve(addr)
            .await
    });
}
