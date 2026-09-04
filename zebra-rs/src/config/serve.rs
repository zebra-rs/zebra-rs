use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::Response;
use tonic::transport::Server;

use crate::config::api::DeployRequest;
use crate::config::enable_rate::EnableRateLimiter;
use crate::config::session::{
    AuthzError, DEFAULT_GC_INTERVAL, DEFAULT_IDLE_TTL, ENABLE_HARD_CAP, ENABLE_IDLE_TTL,
    ENABLE_PAM_USER, ProcfsReader, SessionContext, SessionError, SessionTable, run_gc,
    watch_bash_death,
};

use super::api::{
    ClearTxRequest, CompletionRequest, CompletionResponse, DisplayRequest, DisplayTxRequest,
    ExecuteRequest, ExecuteResponse, Message,
};
use super::show_provider::{ShowProviderBridge, ShowProviderServiceServer};
use super::subscribe::{ConfigServiceServer, ConfigSubscribeService};
use super::vty::apply_server::{Apply, ApplyServer};
use super::vty::clear_server::{Clear, ClearServer};
use super::vty::exec_server::{Exec, ExecServer};
use super::vty::show_server::{Show, ShowServer};
use super::vty::{
    ApplyReply, ApplyRequest, ClearReply, ClearRequest, CommandPath, DisableReply, DisableRequest,
    EnableReply, EnableRequest, ExecCode, ExecReply, ExecRequest, ExecType, LogoutReply,
    LogoutRequest, ShowReply, ShowRequest, YangMatch,
};

#[derive(Debug)]
struct ExecService {
    pub tx: mpsc::Sender<Message>,
    pub sessions: Arc<SessionTable>,
    pub enable_rate: Arc<EnableRateLimiter>,
}

/// Authorize an Admin-required RPC. Returns Ok on success, or an
/// already-formed `Status` describing why the caller is not allowed.
///
/// Wraps [`SessionTable::require_admin`] with the tonic-side mapping so
/// every gated handler does the same boilerplate.
fn enforce_admin<T>(
    sessions: &SessionTable,
    request: &tonic::Request<T>,
) -> Result<(), tonic::Status> {
    let key = request
        .extensions()
        .get::<SessionContext>()
        .map(|c| c.key)
        .ok_or_else(|| tonic::Status::unauthenticated("no session"))?;
    match sessions.require_admin(&key) {
        Ok(()) => Ok(()),
        Err(AuthzError::NoSession) => Err(tonic::Status::unauthenticated("no session")),
        Err(AuthzError::NotAdmin) => Err(tonic::Status::permission_denied(
            "admin role required; run 'enable' first",
        )),
        Err(AuthzError::EnableExpired) => Err(tonic::Status::permission_denied(
            "enable session expired; run 'enable' again",
        )),
    }
}

/// Resolve the path to the `vtypam` helper.
///
/// `ZEBRA_VTYPAM_BIN` env var wins for developer convenience; otherwise
/// falls back to the distribution install path `/usr/sbin/vtypam` (D6/D15).
fn vtypam_path() -> std::path::PathBuf {
    std::env::var_os("ZEBRA_VTYPAM_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/sbin/vtypam"))
}

/// Spawn vtypam, feed it the password on stdin, and return its exit code.
///
/// See `vtypam/src/main.rs` for the exit-code contract (0/1/2/3).
async fn spawn_vtypam(username: &str, password: &str) -> std::io::Result<i32> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    let mut child = Command::new(vtypam_path())
        .arg(username)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        // Closing stdin signals EOF so vtypam stops waiting for input.
        drop(stdin);
    }
    let status = child.wait().await?;
    Ok(status.code().unwrap_or(3))
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
            hostname: String::new(),
        };
        Ok(Response::new(reply))
    }

    fn reply_exec(
        &self,
        code: ExecCode,
        lines: String,
        paths: Vec<CommandPath>,
        hostname: String,
    ) -> Result<Response<ExecReply>, tonic::Status> {
        let reply = ExecReply {
            code: code as i32,
            candidates: Vec::new(),
            lines,
            port: 2666,
            paths,
            hostname,
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
        // Configure-mode gate (D23). Apply only to ExecType::Exec — tab
        // completion paths remain free so non-admin users can still see
        // what commands exist.
        //
        // Two conditions trigger the gate:
        //   (a) mode != "exec"
        //       Any request claiming to be in configure (or any other
        //       privileged) mode requires admin. This is the strict
        //       check that prevents a client from setting mode=configure
        //       directly to bypass the entry gate.
        //   (b) mode == "exec" && first_word == "configure"
        //       Block the mode-entry command itself so vty users get an
        //       immediate "admin required" instead of a successful mode
        //       flip followed by every command failing.
        //
        // The configure-mode lock is intentionally deferred (see D11);
        // multiple admins can still enter configure simultaneously.
        if request.get_ref().r#type == ExecType::Exec as i32 {
            let req = request.get_ref();
            let mode = req.mode.as_str();
            let first_word = req.line.split_whitespace().next().unwrap_or("");
            let needs_admin = mode != "exec" || first_word == "configure";
            if needs_admin {
                enforce_admin(&self.sessions, &request)?;
            }
        }

        let request = request.get_ref();
        match request.r#type {
            x if x == ExecType::Exec as i32 => {
                let resp = self.execute_request(&request.mode, &request.line).await;
                let hostname = resp.hostname.clone().unwrap_or_default();
                let (code, output, paths) = exec_commands(&resp);
                self.reply_exec(code, output, paths, hostname)
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

    async fn logout(
        &self,
        request: tonic::Request<LogoutRequest>,
    ) -> Result<Response<LogoutReply>, tonic::Status> {
        if let Some(ctx) = request.extensions().get::<SessionContext>() {
            let removed = self.sessions.remove(&ctx.key);
            if super::tracing::vty() {
                tracing::info!(uid = ctx.key.0, bash_pid = ctx.key.1, removed, "vty logout",);
            }
        }
        Ok(Response::new(LogoutReply { ok: true }))
    }

    async fn enable(
        &self,
        request: tonic::Request<EnableRequest>,
    ) -> Result<Response<EnableReply>, tonic::Status> {
        let key = request
            .extensions()
            .get::<SessionContext>()
            .map(|c| c.key)
            .ok_or_else(|| tonic::Status::unauthenticated("no session"))?;
        let uid = key.0;

        // Root (D20) is already Admin from session creation.
        if uid == 0 {
            if super::tracing::vty() {
                tracing::info!(uid, "enable noop (root permanent admin)");
            }
            return Ok(Response::new(EnableReply {
                ok: true,
                message: String::new(),
                ttl_secs: 0,
            }));
        }

        // Configure-authorization group: passwordless enable (D27).
        if self.sessions.is_config_group_member(&ProcfsReader, uid) {
            let promoted = self
                .sessions
                .promote_to_admin(&key, ENABLE_IDLE_TTL, ENABLE_HARD_CAP);
            if !promoted {
                return Err(tonic::Status::unauthenticated("session vanished"));
            }
            if super::tracing::vty() {
                tracing::info!(uid, "enable success (config group)");
            }
            return Ok(Response::new(EnableReply {
                ok: true,
                message: String::new(),
                ttl_secs: ENABLE_IDLE_TTL.as_secs() as u32,
            }));
        }

        if let Err(remaining) = self.enable_rate.check(uid) {
            tracing::warn!(
                uid,
                remaining_secs = remaining.as_secs(),
                "enable rate limited"
            );
            return Err(tonic::Status::resource_exhausted(format!(
                "rate limited; retry in {}s",
                remaining.as_secs().max(1)
            )));
        }

        let inner = request.into_inner();
        let password = inner.password;
        let _ = inner.auth_user;
        let target_user = ENABLE_PAM_USER;

        let exit = match spawn_vtypam(target_user, &password).await {
            Ok(code) => code,
            Err(e) => {
                tracing::error!(uid, error = %e, "vtypam spawn failed");
                return Err(tonic::Status::internal("authentication helper unavailable"));
            }
        };

        match exit {
            0 => {
                self.enable_rate.record_success(uid);
                let promoted =
                    self.sessions
                        .promote_to_admin(&key, ENABLE_IDLE_TTL, ENABLE_HARD_CAP);
                if !promoted {
                    return Err(tonic::Status::unauthenticated("session vanished"));
                }
                if super::tracing::vty() {
                    tracing::info!(uid, auth_user = %target_user, "enable success");
                }
                Ok(Response::new(EnableReply {
                    ok: true,
                    message: String::new(),
                    ttl_secs: ENABLE_IDLE_TTL.as_secs() as u32,
                }))
            }
            1 => {
                let locked = self.enable_rate.record_failure(uid);
                tracing::warn!(uid, auth_user = %target_user, locked, "enable auth failed");
                Err(tonic::Status::permission_denied("authentication failed"))
            }
            2 => {
                self.enable_rate.record_failure(uid);
                tracing::warn!(
                    uid,
                    auth_user = %target_user,
                    "enable refused: account not permitted"
                );
                Err(tonic::Status::permission_denied("account not permitted"))
            }
            _ => {
                tracing::error!(uid, auth_user = %target_user, exit, "vtypam system error");
                Err(tonic::Status::internal("authentication system error"))
            }
        }
    }

    async fn disable(
        &self,
        request: tonic::Request<DisableRequest>,
    ) -> Result<Response<DisableReply>, tonic::Status> {
        if let Some(ctx) = request.extensions().get::<SessionContext>() {
            let cleared = self.sessions.disable(&ctx.key);
            if super::tracing::vty() {
                tracing::info!(
                    uid = ctx.key.0,
                    bash_pid = ctx.key.1,
                    cleared,
                    "vty disable",
                );
            }
        }
        Ok(Response::new(DisableReply { ok: true }))
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
        let (bus_tx, bus_rx) = mpsc::channel::<String>(4);
        // The manager may rewrite the command (e.g. stripping a
        // `vrf <name>` selector to redirect into an instance task); use
        // its rewritten paths when present.
        let req = DisplayRequest {
            paths: serve.paths.unwrap_or_else(|| request.paths.clone()),
            json: request.json,
            resp: bus_tx.clone(),
        };
        serve.tx.send(req).unwrap();

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(forward_show_stream(bus_rx, tx, request.line.clone()));
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Forward protocol-task show output to the gRPC response stream.
///
/// Show handlers that answer always send at least one item (an empty
/// string for legitimately-empty output), so a bus that closes without
/// a single item means no handler picked the command up. Surface that
/// as a NotFound status instead of a clean empty stream, which clients
/// would otherwise render as empty-output-and-success.
async fn forward_show_stream(
    mut bus_rx: mpsc::Receiver<String>,
    tx: mpsc::Sender<Result<ShowReply, tonic::Status>>,
    line: String,
) {
    let mut sent_any = false;
    while let Some(item) = bus_rx.recv().await {
        sent_any = true;
        if tx.send(Ok(ShowReply { str: item })).await.is_err() {
            return;
        }
    }
    if !sent_any {
        let _ = tx
            .send(Err(tonic::Status::not_found(format!(
                "no show handler produced output for '{line}'"
            ))))
            .await;
    }
}

#[derive(Debug)]
struct ClearService {
    pub tx: mpsc::Sender<Message>,
    pub sessions: Arc<SessionTable>,
}

#[tonic::async_trait]
impl Clear for ClearService {
    async fn clear(
        &self,
        request: tonic::Request<ClearRequest>,
    ) -> std::result::Result<Response<ClearReply>, tonic::Status> {
        enforce_admin(&self.sessions, &request)?;

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
}

impl Cli {
    pub fn new(config_tx: Sender<Message>) -> Self {
        Self { tx: config_tx }
    }
}

struct ApplyService {
    pub tx: mpsc::Sender<Message>,
    pub sessions: Arc<SessionTable>,
}

#[tonic::async_trait]
impl Apply for ApplyService {
    async fn apply(
        &self,
        request: tonic::Request<tonic::Streaming<ApplyRequest>>,
    ) -> Result<tonic::Response<ApplyReply>, tonic::Status> {
        enforce_admin(&self.sessions, &request)?;

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
/// per-netns zebra-rs deployments. `Uds` binds a filesystem socket at the
/// given absolute path instead.
#[derive(Debug, Clone)]
pub enum VtyAddr {
    Tcp(SocketAddr),
    AbstractUds(String),
    Uds(PathBuf),
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
            // `unix:@NAME` is explicitly abstract, `unix:/PATH` binds a
            // filesystem socket, and bare `unix:NAME` stays an abstract
            // name (the historical default).
            if let Some(name) = rest.strip_prefix('@') {
                if name.is_empty() {
                    anyhow::bail!("unix name must be non-empty");
                }
                return Ok(Self::AbstractUds(name.to_string()));
            }
            if rest.starts_with('/') {
                return Ok(Self::Uds(PathBuf::from(rest)));
            }
            if rest.is_empty() {
                anyhow::bail!("unix name must be non-empty");
            }
            return Ok(Self::AbstractUds(rest.to_string()));
        }
        anyhow::bail!("--vty-socket must start with 'tcp:' or 'unix:'");
    }
}

/// Per-RPC interceptor that surfaces peer identity from SO_PEERCRED and
/// resolves the caller's VTY session.
///
/// For each UDS request the interceptor:
///   1. Pulls uid/pid from SO_PEERCRED.
///   2. Enforces the optional `ZEBRA_VTY_ALLOW_UIDS` env allow-list.
///   3. Resolves a `(uid, bash_pid)` session key via `/proc` and records or
///      refreshes the entry in [`SessionTable`].
///
/// The session table backs RBAC, enable, and streaming consumers via
/// [`SessionTable`].
#[derive(Clone)]
struct VtyPeerInterceptor {
    allow_uids: Option<Arc<HashSet<u32>>>,
    sessions: Arc<SessionTable>,
}

/// Parse the `ZEBRA_VTY_ALLOW_UIDS` env allow-list shared by both
/// interceptors. `None` when unset or empty (allow-list disabled).
fn allow_uids_from_env() -> Option<Arc<HashSet<u32>>> {
    std::env::var("ZEBRA_VTY_ALLOW_UIDS").ok().and_then(|raw| {
        let set: HashSet<u32> = raw
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .collect();
        if set.is_empty() {
            None
        } else {
            Some(Arc::new(set))
        }
    })
}

impl VtyPeerInterceptor {
    fn from_env(sessions: Arc<SessionTable>) -> Self {
        Self {
            allow_uids: allow_uids_from_env(),
            sessions,
        }
    }
}

/// Per-RPC interceptor for the machine-facing APIs (`zebra.config.v1`
/// subscription, `zebra.show.v1` show provider).
///
/// Enforces the same `ZEBRA_VTY_ALLOW_UIDS` allow-list from
/// SO_PEERCRED as [`VtyPeerInterceptor`], but does NOT resolve a vty
/// session: these RPCs carry no role-gated operations — they are
/// read/serve surfaces at the same trust level as the session-less
/// `Show` phase — so there is nothing a session would gate. TCP peers
/// pass through untouched, matching the vty interceptor's posture.
#[derive(Clone)]
struct MachinePeerInterceptor {
    allow_uids: Option<Arc<HashSet<u32>>>,
}

impl MachinePeerInterceptor {
    fn from_env() -> Self {
        Self {
            allow_uids: allow_uids_from_env(),
        }
    }
}

impl tonic::service::Interceptor for MachinePeerInterceptor {
    fn call(&mut self, req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(info) = req
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            && let Some(cred) = &info.peer_cred
        {
            let uid = cred.uid();
            if let Some(allowed) = &self.allow_uids
                && !allowed.contains(&uid)
            {
                tracing::warn!(uid, "machine rpc denied: uid not in allow-list");
                return Err(tonic::Status::permission_denied(format!(
                    "uid {uid} is not permitted to use this API"
                )));
            }
        }
        Ok(req)
    }
}

impl tonic::service::Interceptor for VtyPeerInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(info) = req
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            && let Some(cred) = &info.peer_cred
        {
            let uid = cred.uid();
            let gid = cred.gid();
            let pid = cred.pid().unwrap_or(-1);
            if let Some(allowed) = &self.allow_uids
                && !allowed.contains(&uid)
            {
                tracing::warn!(uid, gid, pid, "vty rpc denied: uid not in allow-list");
                return Err(tonic::Status::permission_denied(format!(
                    "uid {uid} is not permitted to use the VTY"
                )));
            }

            match self.sessions.resolve(&ProcfsReader, uid, pid) {
                Ok(((skey_uid, bash_pid), is_new)) => {
                    req.extensions_mut().insert(SessionContext {
                        key: (skey_uid, bash_pid),
                    });
                    if is_new {
                        if super::tracing::vty() {
                            tracing::info!(
                                uid = skey_uid,
                                gid,
                                pid,
                                bash_pid,
                                "vty rpc (new session)"
                            );
                        }
                        let table = self.sessions.clone();
                        tokio::spawn(async move {
                            watch_bash_death(table, (skey_uid, bash_pid), bash_pid).await;
                        });
                    } else if super::tracing::vty() {
                        tracing::info!(uid = skey_uid, gid, pid, bash_pid, "vty rpc");
                    }
                }
                Err(SessionError::CrossPidNamespace) => {
                    tracing::warn!(uid, gid, pid, "vty rpc denied: cross PID namespace");
                    return Err(tonic::Status::failed_precondition(
                        "client not visible in daemon's PID namespace",
                    ));
                }
                Err(SessionError::ParentVanished) => {
                    tracing::warn!(uid, gid, pid, "vty rpc denied: parent shell vanished");
                    return Err(tonic::Status::unauthenticated("parent shell vanished"));
                }
                Err(SessionError::ParentUidMismatch) => {
                    tracing::warn!(uid, gid, pid, "vty rpc denied: parent uid mismatch");
                    return Err(tonic::Status::unauthenticated("parent uid mismatch"));
                }
                Err(SessionError::ProcReadFailure) => {
                    tracing::warn!(uid, gid, pid, "vty rpc: /proc read failed");
                    return Err(tonic::Status::internal("cannot read /proc"));
                }
            }
        }
        Ok(req)
    }
}

pub fn serve(cli: Cli, addr: VtyAddr) -> anyhow::Result<()> {
    let config_group_gid = SessionTable::resolve_config_group_gid();
    // The one-shot setup notices in this function run before the startup
    // config is loaded (`serve()` precedes `event_loop`), so no runtime
    // toggle could be live yet — they log at debug level instead of
    // consulting `system tracing config vty` like the per-session sites.
    if let Some(gid) = config_group_gid {
        tracing::debug!(gid, "VTY configure-authorization group active");
    } else {
        tracing::debug!("VTY configure-authorization group not found; PAM-only fallback");
    }
    let sessions = SessionTable::with_config_group(config_group_gid);
    let enable_rate = EnableRateLimiter::new();

    let exec_service = ExecService {
        tx: cli.tx.clone(),
        sessions: sessions.clone(),
        enable_rate: enable_rate.clone(),
    };
    let show_service = ShowService { tx: cli.tx.clone() };
    let apply_service = ApplyService {
        tx: cli.tx.clone(),
        sessions: sessions.clone(),
    };
    let clear_service = ClearService {
        tx: cli.tx.clone(),
        sessions: sessions.clone(),
    };
    // Machine-facing APIs: running-config subscription
    // (zebra.config.v1) and the external show provider
    // (zebra.show.v1). Both use the session-less machine interceptor:
    // they carry no role-gated operations, so there is no session to
    // resolve.
    let config_service = ConfigSubscribeService { tx: cli.tx.clone() };
    let show_provider = ShowProviderBridge { tx: cli.tx.clone() };
    let machine_interceptor = MachinePeerInterceptor::from_env();

    let interceptor = VtyPeerInterceptor::from_env(sessions.clone());
    if let Some(set) = &interceptor.allow_uids {
        tracing::debug!(uids = ?set, "VTY peer UID allow-list active (log-only)");
    }

    {
        let gc_table = sessions.clone();
        tokio::spawn(async move {
            run_gc(
                gc_table,
                ProcfsReader,
                DEFAULT_GC_INTERVAL,
                DEFAULT_IDLE_TTL,
            )
            .await
        });
        tracing::debug!(
            interval_secs = DEFAULT_GC_INTERVAL.as_secs(),
            idle_ttl_secs = DEFAULT_IDLE_TTL.as_secs(),
            "VTY session GC sweep started",
        );
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
        .add_service(ConfigServiceServer::with_interceptor(
            config_service,
            machine_interceptor.clone(),
        ))
        .add_service(ShowProviderServiceServer::with_interceptor(
            show_provider,
            machine_interceptor,
        ))
        .add_service(ClearServer::with_interceptor(clear_service, interceptor));

    match addr {
        VtyAddr::Tcp(addr) => {
            tracing::debug!("VTY gRPC listening on tcp://{addr}");
            tokio::spawn(async move { builder.serve(addr).await });
        }
        VtyAddr::AbstractUds(name) => {
            let incoming = bind_abstract_uds(&name)?;
            tracing::debug!("VTY gRPC listening on abstract UDS @{name}");
            tokio::spawn(async move { builder.serve_with_incoming(incoming).await });
        }
        VtyAddr::Uds(path) => {
            let incoming = bind_path_uds(&path)?;
            tracing::debug!("VTY gRPC listening on UDS {}", path.display());
            tokio::spawn(async move { builder.serve_with_incoming(incoming).await });
        }
    }
    Ok(())
}

fn bind_abstract_uds(name: &str) -> anyhow::Result<tokio_stream::wrappers::UnixListenerStream> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr as StdSockAddr;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    let addr = StdSockAddr::from_abstract_name(name.as_bytes()).map_err(|e| {
        anyhow::anyhow!("invalid abstract socket name '@{name}' (contains NUL?): {e}")
    })?;

    let std_listener = StdUnixListener::bind_addr(&addr).map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrInUse => anyhow::anyhow!(
            "abstract VTY socket '@{name}' is already in use.\n\
             Another zebra-rs daemon is likely running in this network namespace.",
        ),
        std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
            "permission denied binding abstract VTY socket '@{name}'.\n\
             Abstract Unix sockets are scoped by the network namespace; check\n\
             that the daemon has access to it (CAP_NET_ADMIN in the current ns).",
        ),
        _ => anyhow::anyhow!("failed to bind abstract VTY socket '@{name}': {e}"),
    })?;

    std_listener
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("set_nonblocking on abstract VTY socket '@{name}': {e}"))?;
    let listener = UnixListener::from_std(std_listener)
        .map_err(|e| anyhow::anyhow!("register abstract VTY socket '@{name}' with tokio: {e}"))?;
    Ok(UnixListenerStream::new(listener))
}

fn bind_path_uds(
    path: &std::path::Path,
) -> anyhow::Result<tokio_stream::wrappers::UnixListenerStream> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    let disp = path.display();

    // A filesystem socket outlives its daemon, so distinguish a stale
    // leftover (unlink and rebind) from a live one — abstract sockets get
    // this for free as EADDRINUSE, and quietly stealing the path from a
    // running daemon must stay just as impossible here.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if StdUnixStream::connect(path).is_ok() {
                anyhow::bail!(
                    "VTY socket {disp} is already in use.\n\
                     Another zebra-rs daemon is likely listening on it.",
                );
            }
            std::fs::remove_file(path)
                .map_err(|e| anyhow::anyhow!("remove stale VTY socket {disp}: {e}"))?;
        }
        Ok(_) => anyhow::bail!("VTY socket path {disp} exists and is not a socket"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::anyhow!("stat VTY socket path {disp}: {e}")),
    }

    let std_listener = StdUnixListener::bind(path)
        .map_err(|e| anyhow::anyhow!("failed to bind VTY socket {disp}: {e}"))?;

    // Authorization is per-RPC via SO_PEERCRED roles, matching the abstract
    // socket, which has no filesystem permission check at all — so open the
    // socket file to all local users; restrict via the parent directory
    // where a tighter policy is wanted.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .map_err(|e| anyhow::anyhow!("set permissions on VTY socket {disp}: {e}"))?;

    std_listener
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("set_nonblocking on VTY socket {disp}: {e}"))?;
    let listener = UnixListener::from_std(std_listener)
        .map_err(|e| anyhow::anyhow!("register VTY socket {disp} with tokio: {e}"))?;
    Ok(UnixListenerStream::new(listener))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vty_addr_parse_recognizes_all_forms() {
        assert!(matches!(
            VtyAddr::parse("tcp:127.0.0.1:2666"),
            Ok(VtyAddr::Tcp(_))
        ));
        match VtyAddr::parse("unix:zebra-rs/vty").unwrap() {
            VtyAddr::AbstractUds(name) => assert_eq!(name, "zebra-rs/vty"),
            other => panic!("expected abstract, got {other:?}"),
        }
        match VtyAddr::parse("unix:@zebra-rs/vty").unwrap() {
            VtyAddr::AbstractUds(name) => assert_eq!(name, "zebra-rs/vty"),
            other => panic!("expected abstract, got {other:?}"),
        }
        match VtyAddr::parse("unix:/tmp/zebra-rs").unwrap() {
            VtyAddr::Uds(path) => assert_eq!(path, PathBuf::from("/tmp/zebra-rs")),
            other => panic!("expected filesystem UDS, got {other:?}"),
        }
        // An explicit `@` wins even when the name looks like a path.
        match VtyAddr::parse("unix:@/tmp/zebra-rs").unwrap() {
            VtyAddr::AbstractUds(name) => assert_eq!(name, "/tmp/zebra-rs"),
            other => panic!("expected abstract, got {other:?}"),
        }
        assert!(VtyAddr::parse("unix:").is_err());
        assert!(VtyAddr::parse("unix:@").is_err());
        assert!(VtyAddr::parse("bogus").is_err());
        assert!(VtyAddr::parse("tcp:nonsense").is_err());
    }

    #[tokio::test]
    async fn forward_show_stream_passes_items_through() {
        let (bus_tx, bus_rx) = mpsc::channel::<String>(4);
        let (tx, mut rx) = mpsc::channel(4);
        bus_tx.send("line one\n".to_string()).await.unwrap();
        bus_tx.send(String::new()).await.unwrap();
        drop(bus_tx);

        forward_show_stream(bus_rx, tx, "show version".to_string()).await;

        assert_eq!(rx.recv().await.unwrap().unwrap().str, "line one\n");
        assert_eq!(rx.recv().await.unwrap().unwrap().str, "");
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn forward_show_stream_reports_unanswered_command() {
        let (bus_tx, bus_rx) = mpsc::channel::<String>(4);
        let (tx, mut rx) = mpsc::channel(4);
        drop(bus_tx);

        forward_show_stream(bus_rx, tx, "show nosuch".to_string()).await;

        let status = rx.recv().await.unwrap().unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(status.message().contains("show nosuch"));
        assert!(rx.recv().await.is_none());
    }
}
