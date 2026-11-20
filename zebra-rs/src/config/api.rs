use super::history::Origin;
use super::session::SessionKey;
use super::subscribe::ConfigSubscribeRequest;
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

/// What a line is run for: whose line it is, and what a commit it makes
/// is recorded with.
///
/// It goes with the line, from the request that brought it to the
/// handler of the command it turns out to be. Nothing about the caller
/// is left in the config manager for the handler to find there: what a
/// handler is not handed, it cannot mistake for the caller's (a `commit`
/// line of an apply for an operator's), and what runs next cannot
/// inherit.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// The session whose line it is. The line runs on that session's
    /// candidate (`config::private`). `None` for a line that is no
    /// session's: the config file's at startup, an apply's, a test's.
    pub session: Option<SessionKey>,
    /// The login name of who runs it, recorded with a commit it makes.
    pub user: Option<String>,
    /// Whose line it is when it is not one an operator typed: a line of
    /// a `vtyctl apply` document ([`Origin::Apply`]) or of the config
    /// file ([`Origin::ConfigFile`]).
    pub writer: Option<Origin>,
    /// The text of `commit comment <text>`, for the commit the line
    /// makes.
    pub comment: Option<String>,
}

impl Context {
    /// A line of session `session`, typed by `user`.
    pub fn session(session: Option<SessionKey>, user: Option<String>) -> Self {
        Self {
            session,
            user,
            ..Default::default()
        }
    }

    /// The same caller, running a line of `writer`'s: a document it
    /// applies, the config file it loads.
    pub fn line_of(&self, writer: Origin) -> Self {
        Self {
            writer: Some(writer),
            comment: None,
            ..self.clone()
        }
    }

    /// The same line, with the comment taken off it.
    pub fn commented(&self, comment: String) -> Self {
        Self {
            comment: Some(comment),
            ..self.clone()
        }
    }

    /// What a commit made by the line is: an operator's `commit`,
    /// unless the line is another writer's.
    pub fn origin(&self) -> Origin {
        self.writer.unwrap_or(Origin::Commit)
    }

    /// Whether an operator typed the line: what a `commit` must be to
    /// confirm a `commit confirmed`.
    pub fn typed(&self) -> bool {
        self.writer.is_none()
    }
}

#[derive(Debug)]
pub struct ExecuteRequest {
    pub mode: String,
    pub input: String,
    /// Whose line it is: the session, whose candidate it runs on, and
    /// its login name.
    pub ctx: Context,
    pub resp: Sender<ExecuteResponse>,
}

#[derive(Debug, Default)]
pub struct ExecuteResponse {
    pub code: ExecCode,
    pub output: String,
    pub paths: Vec<CommandPath>,
    /// The running-config `system hostname` value, or `None` when
    /// unconfigured. Carried on every Execute reply; the vty shell
    /// queries it via `vtyhelper -H` (startup seed) and `vtyhelper -S`
    /// (the post-command `_cli_hostname_refresh`) to keep the prompt in
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
    /// The session, whose candidate says what is there to complete.
    pub session: Option<SessionKey>,
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
            ctx: Context::default(),
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
            session: None,
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
    /// The login name of the caller, for the commit history.
    pub user: Option<String>,
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
    /// The session that asks, for what is shown of its own: its
    /// candidate.
    pub session: Option<SessionKey>,
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
    /// The shell of a session is gone: its candidate goes with it
    /// (`config::private`).
    SessionEnd {
        key: SessionKey,
    },
    /// The timer of a `commit confirmed` ran out (`config::confirm`).
    ConfirmTimeout {
        generation: u64,
    },
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
    /// Register an external gRPC subscriber to running-config commits
    /// (`zebra.config.v1.ConfigService/Subscribe`). The manager sends
    /// the snapshot event and keeps the sender until the client goes
    /// away.
    ConfigSubscribe(ConfigSubscribeRequest),
    /// Register an external show provider (`zebra.show.v1`) under a
    /// top-level show routing key ("firewall", "ipsec", …), replacing
    /// any previous holder of that name.
    SubscribeShow {
        name: String,
        tx: UnboundedSender<DisplayRequest>,
    },
    /// Withdraw an external show provider's name — but only while the
    /// registry still points at that provider's channel
    /// (`same_channel`), so a replaced provider's exit cannot remove
    /// its successor.
    UnsubscribeShow {
        name: String,
        tx: UnboundedSender<DisplayRequest>,
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
