use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::Response;
use tonic::transport::Server;

use crate::config::api::DeployRequest;

use super::api::{
    ClearTxRequest, CompletionRequest, CompletionResponse, DisplayRequest, DisplayTxRequest,
    ExecuteRequest, ExecuteResponse, Message,
};
use super::vty::apply_server::{Apply, ApplyServer};
use super::vty::clear_server::{Clear, ClearServer};
use super::vty::exec_server::{Exec, ExecServer};
use super::vty::show_server::{Show, ShowServer};
use super::vty::{
    ApplyReply, ApplyRequest, ClearReply, ClearRequest, CommandPath, ExecCode, ExecReply,
    ExecRequest, ExecType, ShowReply, ShowRequest, YangMatch,
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

    async fn completion_request(
        &self,
        mode: &str,
        input: &str,
        interactive: bool,
    ) -> CompletionResponse {
        let (tx, rx) = oneshot::channel();
        let req = CompletionRequest::new(mode, input, interactive, tx);
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
                let resp = self
                    .completion_request(&request.mode, &request.line, request.interactive)
                    .await;
                self.reply(ExecCode::Success, first_commands(&resp))
            }
            x if x == ExecType::Complete as i32 => {
                let resp = self
                    .completion_request(&request.mode, &request.line, request.interactive)
                    .await;
                self.reply(ExecCode::Success, comp_commands(&resp))
            }
            x if x == ExecType::CompleteTrailingSpace as i32 => {
                let mut input = request.line.clone();
                input.push(' ');
                let resp = self
                    .completion_request(&request.mode, &input, request.interactive)
                    .await;
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

#[derive(Debug)]
struct ClearService {
    pub tx: mpsc::Sender<Message>,
}

#[tonic::async_trait]
impl Clear for ClearService {
    async fn clear(
        &self,
        request: tonic::Request<ClearRequest>,
    ) -> std::result::Result<Response<ClearReply>, tonic::Status> {
        let request = request.get_ref();

        let (tx, rx) = oneshot::channel();
        let query = ClearTxRequest {
            paths: request.paths.clone(),
            resp: tx,
        };
        self.tx.send(Message::ClearTx(query)).await.unwrap();
        let resp = rx.await.unwrap();

        let reply = ClearReply {
            result: resp.result,
            str: resp.output,
        };
        Ok(Response::new(reply))
    }
}

pub struct Cli {
    pub tx: mpsc::Sender<Message>,
    pub _show_clients: HashMap<String, UnboundedSender<DisplayRequest>>,
}

impl Cli {
    pub fn new(config_tx: Sender<Message>) -> Self {
        Self {
            tx: config_tx,
            _show_clients: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn subscribe(&mut self, name: &str, tx: UnboundedSender<DisplayRequest>) {
        self._show_clients.insert(name.to_string(), tx);
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
        let resp = rx.await.unwrap();

        // Create the reply based on the processing outcome
        let reply = ApplyReply {
            apply_code: resp.apply_code as i32,
            exec_code: resp.exec_code as i32,
            description: resp.cmd,
        };

        // Return the response
        Ok(Response::new(reply))
    }
}

/// VTY gRPC listen endpoint.
///
/// `AbstractUds` uses a Linux abstract Unix socket whose name is scoped by the
/// process network namespace, which is the isolation primitive we rely on for
/// per-netns zebra-rs deployments.
#[derive(Debug, Clone)]
pub enum VtyAddr {
    Tcp(SocketAddr),
    #[cfg(target_os = "linux")]
    AbstractUds(String),
}

impl VtyAddr {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some(rest) = s.strip_prefix("tcp:") {
            let addr: SocketAddr = rest
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid tcp address {rest:?}: {e}"))?;
            return Ok(Self::Tcp(addr));
        }
        if let Some(rest) = s.strip_prefix("unix:") {
            #[cfg(target_os = "linux")]
            {
                let name = rest.trim_start_matches('@').to_string();
                if name.is_empty() {
                    anyhow::bail!("unix name must be non-empty");
                }
                return Ok(Self::AbstractUds(name));
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = rest;
                anyhow::bail!("unix sockets are only supported on Linux");
            }
        }
        anyhow::bail!("--vty-socket must start with 'tcp:' or 'unix:'");
    }
}

/// Per-RPC interceptor that surfaces peer identity from SO_PEERCRED.
///
/// Behaviour for PR3 is **log-only**: every UDS request gets a tracing event
/// with uid/pid, and an optional `ZEBRA_VTY_ALLOW_UIDS` allow-list produces
/// warnings for non-matching peers but does not actually reject them. PR4
/// will turn the warning into a `Status::permission_denied`.
#[derive(Clone)]
struct VtyPeerInterceptor {
    allow_uids: Option<Arc<HashSet<u32>>>,
}

impl VtyPeerInterceptor {
    fn from_env() -> Self {
        let allow_uids = std::env::var("ZEBRA_VTY_ALLOW_UIDS").ok().and_then(|raw| {
            let set: HashSet<u32> = raw
                .split(',')
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .collect();
            if set.is_empty() {
                None
            } else {
                Some(Arc::new(set))
            }
        });
        Self { allow_uids }
    }
}

impl tonic::service::Interceptor for VtyPeerInterceptor {
    fn call(&mut self, req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        #[cfg(target_os = "linux")]
        if let Some(info) = req
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            && let Some(cred) = &info.peer_cred
        {
            let uid = cred.uid();
            let gid = cred.gid();
            let pid = cred.pid().unwrap_or(-1);
            match &self.allow_uids {
                Some(allowed) if !allowed.contains(&uid) => {
                    tracing::warn!(
                        uid,
                        gid,
                        pid,
                        "vty rpc from peer not in ZEBRA_VTY_ALLOW_UIDS (would deny)"
                    );
                }
                _ => tracing::info!(uid, gid, pid, "vty rpc"),
            }
        }
        Ok(req)
    }
}

pub fn serve(cli: Cli, addr: VtyAddr) -> anyhow::Result<()> {
    let exec_service = ExecService { tx: cli.tx.clone() };
    let show_service = ShowService { tx: cli.tx.clone() };
    let apply_service = ApplyService { tx: cli.tx.clone() };
    let clear_service = ClearService { tx: cli.tx.clone() };

    let interceptor = VtyPeerInterceptor::from_env();
    if let Some(set) = &interceptor.allow_uids {
        tracing::info!(uids = ?set, "VTY peer UID allow-list active (log-only)");
    }

    let builder = Server::builder()
        .add_service(ExecServer::with_interceptor(
            exec_service,
            interceptor.clone(),
        ))
        .add_service(ShowServer::with_interceptor(
            show_service,
            interceptor.clone(),
        ))
        .add_service(ApplyServer::with_interceptor(
            apply_service,
            interceptor.clone(),
        ))
        .add_service(ClearServer::with_interceptor(clear_service, interceptor));

    match addr {
        VtyAddr::Tcp(addr) => {
            tracing::info!("VTY gRPC listening on tcp://{addr}");
            tokio::spawn(async move { builder.serve(addr).await });
        }
        #[cfg(target_os = "linux")]
        VtyAddr::AbstractUds(name) => {
            let incoming = bind_abstract_uds(&name)?;
            tracing::info!("VTY gRPC listening on abstract UDS @{name}");
            tokio::spawn(async move { builder.serve_with_incoming(incoming).await });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_abstract_uds(name: &str) -> anyhow::Result<tokio_stream::wrappers::UnixListenerStream> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr as StdSockAddr;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    let addr = StdSockAddr::from_abstract_name(name.as_bytes())
        .map_err(|e| anyhow::anyhow!("from_abstract_name: {e}"))?;
    let std_listener =
        StdUnixListener::bind_addr(&addr).map_err(|e| anyhow::anyhow!("bind_addr: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("set_nonblocking: {e}"))?;
    let listener =
        UnixListener::from_std(std_listener).map_err(|e| anyhow::anyhow!("from_std: {e}"))?;
    Ok(UnixListenerStream::new(listener))
}
