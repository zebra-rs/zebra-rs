use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::Response;

use super::vtysh::exec_server::{Exec, ExecServer};
use super::vtysh::show_server::{Show, ShowServer};
use super::vtysh::{ExecCode, ExecReply, ExecRequest, ExecType, ShowReply, ShowRequest};

use super::api::{CompletionRequest, CompletionResponse, ExecuteRequest, ExecuteResponse, Message};

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
            port: 0,
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
                let (code, output) = exec_commands(&resp);
                self.reply(code, output)
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
        line.push_str(&format!("{}\t  \t{}\n", comp.name, comp.help));
    }
    line
}

fn exec_commands(resp: &ExecuteResponse) -> (ExecCode, String) {
    if resp.code == ExecCode::Nomatch {
        return (ExecCode::Nomatch, String::from("NoMatch\n"));
    }
    if resp.code == ExecCode::Ambiguous {
        return (ExecCode::Ambiguous, String::from("Ambiguous\n"));
    }
    if resp.code == ExecCode::Incomplete {
        return (ExecCode::Incomplete, String::from("Incomplete\n"));
    }
    (resp.code, resp.output.to_owned())
}

#[derive(Debug)]
struct ShowService {}

#[tonic::async_trait]
impl Show for ShowService {
    type ShowStream = ReceiverStream<Result<ShowReply, tonic::Status>>;

    async fn show(
        &self,
        _request: tonic::Request<ShowRequest>,
    ) -> std::result::Result<Response<Self::ShowStream>, tonic::Status> {
        let (tx, rx) = mpsc::channel(4);

        tokio::spawn(async move {
            for _ in 0..4 {
                let _ = tx
                    .send(Ok(ShowReply {
                        str: String::from(""),
                    }))
                    .await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

pub async fn serve(config_tx: Sender<Message>) {
    let exec_service = ExecService { tx: config_tx };
    let exec_server = ExecServer::new(exec_service);

    let show_service = ShowService {};
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
