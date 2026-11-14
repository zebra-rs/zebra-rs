use anyhow::Result;
use clap::Parser;
use std::env;
use std::time::Duration;
use tokio::io::{self, AsyncWriteExt};
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use vty::exec_client::ExecClient;
use vty::show_client::ShowClient;
use vty::{
    CommandPath, DisableRequest, EnableRequest, ExecCode, ExecReply, ExecRequest, ExecType,
    LogoutRequest, ShowRequest,
};

mod endpoint;

pub mod vty {
    tonic::include_proto!("vty");
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, help = "Completion of the command")]
    completion: bool,

    #[arg(short, long, help = "First commands list")]
    first: bool,

    #[arg(short, long, help = "Command has trailing space")]
    trailing: bool,

    #[arg(short, long, help = "Current mode", default_value = "exec")]
    mode: String,

    #[arg(short, long, help = "Show command flag")]
    show: bool,

    #[arg(short, long, help = "Show command port", default_value = "2666")]
    port: u32,

    #[arg(short, long, help = "Show output in JSON format")]
    json: bool,

    #[arg(
        short,
        long,
        help = "Logout: tear down the server-side session (invoked from vty bash EXIT trap)"
    )]
    logout: bool,

    #[arg(
        short = 'e',
        long,
        help = "Enable: prompt-less PAM authentication; password is read from CLI_ENABLE_PASSWORD"
    )]
    enable: bool,

    #[arg(
        short = 'd',
        long,
        help = "Disable: drop the session back to View role"
    )]
    disable: bool,

    #[arg(
        short = 'u',
        long = "uncommitted",
        help = "Answer \"does the candidate config differ from running?\" through the exit code: 0 differs, 1 identical, 2 unknown. Prints nothing; used by the vty EXIT hook."
    )]
    uncommitted: bool,

    #[arg(
        short = 'H',
        long = "hostname",
        help = "Print the daemon's configured `system hostname` (empty when unset); \
                used once at vty startup to seed CLI_HOSTNAME for the prompt"
    )]
    hostname: bool,

    #[arg(
        short = 'a',
        long = "admin-left",
        help = "Print how many seconds the session's admin role has left: 0 when not admin, \
                -1 when it never lapses (root). Asking does not extend it."
    )]
    admin_left: bool,

    #[arg(
        short = 'S',
        long = "state",
        help = "Print the daemon's configured `system hostname` and, on a second line, \
                what -a prints (empty when the daemon cannot say); the vty shell's \
                after-command refresh"
    )]
    state: bool,

    #[arg(
        long,
        value_name = "SECS",
        help = "Sleep SECS seconds, then send SIGUSR1 to the parent (the vty shell, which \
                then asks whether its admin role lapsed). Dies with the parent."
    )]
    timer: Option<u64>,

    #[arg(
        long,
        value_name = "PID",
        requires = "timer",
        help = "With --timer: the vty shell's own pid. The timer signals only that process, \
                and only while it is still the timer's parent"
    )]
    parent: Option<i32>,

    #[arg(
        long,
        help = "Deprecated and ignored; the daemon always authenticates enable against root."
    )]
    auth_user: Option<String>,

    #[arg(
        short,
        long,
        help = "Server endpoint URI (unix:NAME, unix:/PATH, tcp://host:port, http://host:port). \
                Bare host like 'http://127.0.0.1' is combined with --port for backward compat.",
        default_value = "unix:zebra-rs/vty"
    )]
    base: String,

    commands: Vec<String>,
}

fn privilege_get() -> u32 {
    match env::var("CLI_PRIVILEGE") {
        Ok(val) => val.parse::<u32>().unwrap_or(1),
        Err(_) => 1,
    }
}

/// Exit statuses of the command paths, which the vty shell tells apart.
/// Enable, disable and `--uncommitted` keep their own documented codes,
/// except that enable and disable also exit `EXIT_UNREACHABLE` when the
/// daemon cannot be reached.
const EXIT_FAILURE: i32 = 1;
/// The daemon could not be reached; the warning went to stderr.
const EXIT_UNREACHABLE: i32 = 3;
/// The daemon refused the command: it needs the admin role, which the
/// session does not hold (never enabled, or lapsed). Nothing printed.
const EXIT_DENIED: i32 = 4;
/// `-a`: the daemon does not say how long the role has left (it
/// predates `ExecReply.admin`). Nothing printed.
const EXIT_UNKNOWN: i32 = 5;

/// Metadata key the daemon puts on a refusal that is not for want of the
/// admin role (the uid is not on its allow-list).
const DENIED_KEY: &str = "zebra-rs-denied";

/// A `show` stream ended in an error after part of the output: the
/// warning is already on stdout, after that output.
#[derive(Debug)]
struct CutShort {
    /// Lost the daemon, rather than an error of the daemon's or ours.
    lost: bool,
}

impl std::fmt::Display for CutShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "output cut short")
    }
}

impl std::error::Error for CutShort {}

/// The daemon answered `-a` without the admin role's time.
#[derive(Debug)]
struct NoLease;

impl std::fmt::Display for NoLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the daemon does not report the admin role")
    }
}

impl std::error::Error for NoLease {}

/// The daemon could not be reached. Its Display is the one-line warning
/// the vty shell shows in place of the command's output.
#[derive(Debug)]
struct Unreachable {
    uri: String,
    reason: String,
    /// Nothing is listening (refused, no such socket): most likely
    /// zebra-rs is not running, or runs in another network namespace.
    not_running: bool,
    /// Lost while `show` output was streaming: what was printed is cut
    /// short.
    midway: bool,
}

impl Unreachable {
    fn new(uri: &str, err: &anyhow::Error) -> Self {
        // tonic's own layers say only "transport error"; the io::Error at
        // the bottom of the chain says why.
        let io = err.chain().find_map(|e| e.downcast_ref::<std::io::Error>());
        let reason = match io {
            Some(io) => {
                let text = io.to_string();
                match text.find(" (os error ") {
                    Some(at) => text[..at].to_string(),
                    None => text,
                }
            }
            None => err.root_cause().to_string(),
        };
        let not_running = io.is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            )
        });
        Self {
            uri: uri.to_string(),
            reason,
            not_running,
            midway: false,
        }
    }

    /// Lost the daemon after connecting.
    fn lost(uri: &str, status: &tonic::Status, midway: bool) -> Self {
        Self {
            uri: uri.to_string(),
            reason: status.message().to_string(),
            not_running: false,
            midway,
        }
    }
}

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.midway {
            return write!(
                f,
                "% Output cut short: lost zebra-rs at {}: {}",
                self.uri, self.reason
            );
        }
        write!(
            f,
            "% Cannot connect to zebra-rs at {}: {}",
            self.uri, self.reason
        )?;
        if self.not_running {
            write!(f, "; is zebra-rs running?")?;
        }
        Ok(())
    }
}

impl std::error::Error for Unreachable {}

/// Connect to the daemon, turning a failure into [`Unreachable`].
async fn dial(uri: &str) -> Result<Channel> {
    endpoint::connect(uri)
        .await
        .map_err(|err| Unreachable::new(uri, &err).into())
}

/// Build the endpoint URI from the parsed CLI.
///
/// `--base` may already be a full URI (`unix:…`, `tcp:host:port`,
/// `tcp://host:port`, `http://host:port`) — in which case `--port` is
/// ignored. Otherwise the legacy `{base}:{port}` concatenation is used,
/// matching the historical `http://127.0.0.1` + `2666` defaults.
fn endpoint_uri(base: &str, port: u32) -> String {
    if base.starts_with("unix:")
        || base.starts_with("tcp:")
        || base.starts_with("http://") && base.matches(':').count() >= 2
        || base.starts_with("https://") && base.matches(':').count() >= 2
    {
        base.to_string()
    } else {
        format!("{base}:{port}")
    }
}

fn output(reply: ExecReply) {
    if reply.code == ExecCode::Show as i32 {
        println!("Show");
    }
    println!("{:}", reply.lines);
}

fn command_string(commands: &[String]) -> String {
    if !commands.is_empty() {
        commands.join(" ")
    } else {
        String::from("")
    }
}

fn commands_trim_run(commands: &[String]) -> Vec<String> {
    let mut commands = commands.to_owned();
    if !commands.is_empty() && commands[0] == "run" {
        commands.remove(0);
    }
    commands
}

fn exec_request(exec_type: i32, mode: &String, commands: &Vec<String>) -> ExecRequest {
    ExecRequest {
        r#type: exec_type,
        privilege: privilege_get(),
        mode: mode.to_owned(),
        line: command_string(commands),
        args: commands.to_owned(),
        interactive: true,
    }
}

async fn show(cli: Cli, port: Option<u32>, paths: Vec<CommandPath>) -> Result<()> {
    let port = port.unwrap_or(cli.port);
    let uri = endpoint_uri(&cli.base, port);
    let channel = dial(&uri).await?;
    let mut client = ShowClient::new(channel);

    let commands = commands_trim_run(&cli.commands);
    let request = tonic::Request::new(ShowRequest {
        json: cli.json,
        line: command_string(&commands),
        paths,
    });

    let mut stdout = io::stdout();
    let mut stream = client.show(request).await?.into_inner();
    println!("Show");
    let mut at_line_start = true;
    while let Some(reply) = stream.next().await {
        let reply = match reply {
            Ok(reply) => reply,
            // The daemon's own end: no show handler had output for the
            // line. Nothing is missing.
            Err(status) if status.code() == tonic::Code::NotFound => break,
            // Anything else leaves what was printed short of the answer
            // (the daemon lost, a chunk over the decode limit). Say so
            // after it, on stdout: the vty pages stdout only once we
            // exit, so a warning on stderr would come out above the
            // output and scroll away.
            Err(status) => {
                let lost = lost_connection(&status);
                let warning = if lost {
                    Unreachable::lost(&uri, &status, true).to_string()
                } else {
                    format!("% Output cut short: {}", status.message())
                };
                let lead = if at_line_start { "" } else { "\n" };
                stdout
                    .write_all(format!("{lead}{warning}\n").as_bytes())
                    .await?;
                stdout.flush().await?;
                return Err(CutShort { lost }.into());
            }
        };
        if let Some(last) = reply.str.as_bytes().last() {
            at_line_start = *last == b'\n';
        }
        stdout.write_all(reply.str.as_bytes()).await?;
    }
    stdout.flush().await?;

    Ok(())
}

/// Did this stream error come from losing the connection rather than
/// from the daemon? The daemon ends a show stream with NotFound when no
/// handler had output; a dropped connection surfaces as Unavailable,
/// Unknown (an h2 error) or Cancelled.
fn lost_connection(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable | tonic::Code::Unknown | tonic::Code::Cancelled
    )
}

async fn completion(cli: Cli) -> Result<()> {
    let channel = dial(&endpoint_uri(&cli.base, cli.port)).await?;
    let mut client = ExecClient::new(channel);

    let exec_type: i32 = if cli.completion {
        ExecType::Complete as i32
    } else if cli.trailing {
        ExecType::CompleteTrailingSpace as i32
    } else if cli.first {
        ExecType::CompleteFirstCommands as i32
    } else {
        ExecType::Exec as i32
    };

    let request = tonic::Request::new(exec_request(exec_type, &cli.mode, &cli.commands));
    let reply = client.do_exec(request).await?.into_inner();
    println!("{:}", reply.lines);

    Ok(())
}

async fn redirect(cli: Cli, port: u32) -> Result<()> {
    let channel = dial(&endpoint_uri(&cli.base, port)).await?;
    let mut client = ExecClient::new(channel);

    let commands = commands_trim_run(&cli.commands);
    let request = tonic::Request::new(exec_request(ExecType::Exec as i32, &cli.mode, &commands));
    let reply = client.do_exec(request).await?.into_inner();

    output(reply);

    Ok(())
}

/// Print the daemon's configured `system hostname` (empty when
/// unset). Invoked as `vtyhelper -H` by the vty shell once at startup
/// to seed `CLI_HOSTNAME`; after every executed command the shell asks
/// `-S` instead (`_cli_hostname_refresh`), so the prompt tracks `set
/// system hostname` / `delete system hostname` as soon as they commit.
async fn hostname_fetch(cli: Cli) -> Result<()> {
    let reply = probe(&cli).await?;
    println!("{}", reply.hostname);
    Ok(())
}

/// Print how many seconds the session's admin role has left (see
/// `ExecReply.admin`). Invoked as `vtyhelper -a` by the vty shell, which
/// leaves configure mode when the answer is 0. Asked with ADMIN_LEFT,
/// which the daemon answers from its session table alone.
async fn admin_left(cli: Cli) -> Result<()> {
    let channel = dial(&endpoint_uri(&cli.base, cli.port)).await?;
    let mut client = ExecClient::new(channel);
    let request = tonic::Request::new(exec_request(
        ExecType::AdminLeft as i32,
        &String::from("exec"),
        &Vec::new(),
    ));
    let reply = client.do_exec(request).await?.into_inner();
    let lease = reply.admin.ok_or(NoLease)?;
    println!("{}", lease.secs);
    Ok(())
}

/// `-S`: the host name and the admin role's time from one reply, for the
/// vty shell's refresh after every command.
async fn state(cli: Cli) -> Result<()> {
    let reply = probe(&cli).await?;
    println!("{}", reply.hostname);
    match reply.admin {
        Some(lease) => println!("{}", lease.secs),
        None => println!(),
    }
    Ok(())
}

/// An empty exec-mode line: runs nothing, passes no admin gate (so it
/// slides no deadline), and its reply carries the session-wide fields.
async fn probe(cli: &Cli) -> Result<ExecReply> {
    let channel = dial(&endpoint_uri(&cli.base, cli.port)).await?;
    let mut client = ExecClient::new(channel);
    let request = tonic::Request::new(exec_request(
        ExecType::Exec as i32,
        &String::from("exec"),
        &Vec::new(),
    ));
    Ok(client.do_exec(request).await?.into_inner())
}

/// `--timer SECS`: wake the vty shell when its admin role may have lapsed.
///
/// Sleeps, then sends SIGUSR1 to the parent, whose trap asks the daemon
/// (`-a`) and either re-arms for the time left or leaves configure mode.
/// The signal must reach the vty and nothing else: SIGUSR1 kills a
/// process that does not catch it. A shell that died leaves its pid free
/// for reuse, so the timer dies with it (PR_SET_PDEATHSIG) and checks the
/// parent is still the one it started with. A shell that ran `exec ssh
/// host` keeps its pid but is now another program, which the death
/// signal does not cover: the parent's executable must also be the one
/// it was.
fn timer(secs: u64, shell: Option<libc::pid_t>) -> i32 {
    // SAFETY: getppid, prctl and kill are plain syscalls on integers.
    let parent = unsafe { libc::getppid() };
    // The shell names itself (`--parent $$`): a vty may be PID 1 in its
    // container, which is also what an orphaned timer's parent reads as.
    // Without the name, a parent of 1 can only be an orphan's.
    match shell {
        Some(pid) if pid != parent => return 0,
        None if parent <= 1 => return 0,
        _ => {}
    }
    // prctl reads its second argument as an unsigned long. Without the
    // death signal the timer could outlive the shell: no timer then.
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) } != 0 {
        return 0;
    }
    // The parent may have died before prctl took effect.
    if unsafe { libc::getppid() } != parent {
        return 0;
    }
    // Unknown means it cannot be checked later: do not signal at all.
    // Read now, while the parent is still the shell that started us: the
    // vty starts a timer and goes back to its prompt, so an `exec` can
    // only come later.
    let Some(program) = executable(parent) else {
        return 0;
    };
    std::thread::sleep(Duration::from_secs(secs));
    // Same pid, same program, and it catches SIGUSR1: anything else (an
    // `exec vty -c ...` script, a vty still starting) would be killed by
    // it.
    if unsafe { libc::getppid() } == parent
        && executable(parent).as_deref() == Some(&program)
        && catches(parent, libc::SIGUSR1)
    {
        unsafe {
            libc::kill(parent, libc::SIGUSR1);
        }
    }
    0
}

/// Does `pid` catch signal `sig`? Read off the `SigCgt` mask in
/// /proc/PID/status; false when it cannot be read.
fn catches(pid: libc::pid_t, sig: libc::c_int) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .is_some_and(|status| sig_caught(&status, sig))
}

/// `sig`'s bit in the `SigCgt:` line of a /proc/PID/status text.
fn sig_caught(status: &str, sig: libc::c_int) -> bool {
    let Some(mask) = status
        .lines()
        .find_map(|line| line.strip_prefix("SigCgt:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
    else {
        return false;
    };
    (1..=64).contains(&sig) && mask & (1u64 << (sig - 1)) != 0
}

/// The program `pid` runs, as /proc names it. A binary replaced on disk
/// (a package upgrade) reads "PATH (deleted)"; that is still the same
/// program.
fn executable(pid: libc::pid_t) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let path = path.to_string_lossy();
    Some(path.strip_suffix(" (deleted)").unwrap_or(&path).to_string())
}

async fn exec(cli: Cli) -> Result<()> {
    let channel = dial(&endpoint_uri(&cli.base, cli.port)).await?;
    let mut client = ExecClient::new(channel);

    let request = tonic::Request::new(exec_request(
        ExecType::Exec as i32,
        &cli.mode,
        &cli.commands,
    ));

    let reply = client.do_exec(request).await?.into_inner();
    match reply.code {
        _ if reply.code == ExecCode::Redirect as i32 => {
            redirect(cli, reply.port).await?;
        }
        _ if reply.code == ExecCode::RedirectShow as i32 => {
            show(cli, Some(reply.port), reply.paths).await?;
        }
        _ => output(reply),
    }
    Ok(())
}

/// Tear down the server-side session. Invoked from the vty bash `EXIT`
/// trap, so this path is silent on success and on failure — the user's
/// shell is already exiting and any stdout would be jarring.
async fn logout(cli: Cli) -> Result<()> {
    let channel = dial(&endpoint_uri(&cli.base, cli.port)).await?;
    let mut client = ExecClient::new(channel);
    let _ = client.logout(tonic::Request::new(LogoutRequest {})).await?;
    Ok(())
}

/// Promote the session to Admin via the server's Enable RPC.
///
/// Reads the password from `CLI_ENABLE_PASSWORD` (set by the vty bash
/// `enable` function which uses `read -s` to capture it without echo).
/// Prints a one-line result and exits 0 on success, 1 on auth failure,
/// or non-zero on other errors (transport, rate-limit, etc.).
async fn enable(cli: Cli) -> i32 {
    let password = env::var("CLI_ENABLE_PASSWORD").unwrap_or_default();
    // Wipe the env var immediately so the password doesn't linger in our
    // own process environment beyond the RPC call.
    // SAFETY: single-threaded at this point; tokio runtime not yet handling
    // concurrent env access for vtyhelper.
    unsafe {
        env::remove_var("CLI_ENABLE_PASSWORD");
    }

    let uri = endpoint_uri(&cli.base, cli.port);
    let channel = match dial(&uri).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return EXIT_UNREACHABLE;
        }
    };
    let mut client = ExecClient::new(channel);
    let req = EnableRequest {
        password,
        auth_user: cli.auth_user.clone().unwrap_or_default(),
    };
    match client.enable(tonic::Request::new(req)).await {
        Ok(reply) => {
            let r = reply.into_inner();
            if r.ok {
                println!("% Enabled (admin role active for {} seconds)", r.ttl_secs);
                0
            } else {
                println!("% Enable failed: {}", r.message);
                1
            }
        }
        // Lost the daemon after connecting: the same news as not reaching
        // it, and the shell says nothing more for exit 3.
        Err(status) if lost_connection(&status) => {
            eprintln!("{}", Unreachable::lost(&uri, &status, false));
            EXIT_UNREACHABLE
        }
        Err(status) => {
            // permission_denied = wrong password; everything else is a
            // system/rate-limit problem worth distinguishing in scripts.
            let code = if status.code() == tonic::Code::PermissionDenied {
                1
            } else {
                2
            };
            println!("% Enable failed: {}", status.message());
            code
        }
    }
}

/// Exit codes for `--uncommitted`. The vty EXIT hook prompts on
/// `DIRTY` and on nothing else, so neither a clean config nor an
/// unreachable daemon can stand between the operator and their exit.
/// `UNKNOWN` stays distinct from `CLEAN` deliberately: folding an error
/// into "nothing to commit" would make a broken query indistinguishable
/// from a real answer.
const UNCOMMITTED_DIRTY: i32 = 0;
const UNCOMMITTED_CLEAN: i32 = 1;
const UNCOMMITTED_UNKNOWN: i32 = 2;

/// Does the candidate config differ from running?
///
/// The predicate is a string comparison of `show running-config formal`
/// against `show candidate-config formal`. Both render through
/// `Config::formal()` — a `set `-prefixed spelling of the `list()`
/// rendering `commit_config` diffs, with the prefix applied uniformly
/// to both sides — so this answers "would a commit do anything?" rather
/// than the weaker "do the two trees look different"; the
/// configure-mode `show` command compares the other (`format()`)
/// rendering and the two can disagree.
/// Both commands live in exec mode and are not admin-gated, so a View
/// session can ask.
///
/// Two round trips of the whole config, but only ever on the way out of
/// a shell, which is why this is a one-shot query and not a flag
/// stamped on every reply.
async fn uncommitted(cli: Cli) -> i32 {
    let channel = match dial(&endpoint_uri(&cli.base, cli.port)).await {
        Ok(c) => c,
        Err(_) => return UNCOMMITTED_UNKNOWN,
    };
    let mut client = ExecClient::new(channel);

    let mut formal = Vec::new();
    for target in ["running-config", "candidate-config"] {
        let commands = vec![
            String::from("show"),
            String::from(target),
            String::from("formal"),
        ];
        let request = tonic::Request::new(exec_request(
            ExecType::Exec as i32,
            &String::from("exec"),
            &commands,
        ));
        let Ok(reply) = client.do_exec(request).await else {
            return UNCOMMITTED_UNKNOWN;
        };
        let reply = reply.into_inner();
        // Anything but Show means the command didn't run (schema
        // changed under us, RBAC, a daemon mid-restart) — that is an
        // unknown answer, not an empty config.
        if reply.code != ExecCode::Show as i32 {
            return UNCOMMITTED_UNKNOWN;
        }
        formal.push(reply.lines);
    }

    if formal[0] == formal[1] {
        UNCOMMITTED_CLEAN
    } else {
        UNCOMMITTED_DIRTY
    }
}

/// Drop the session back to View. Idempotent; the daemon doesn't error.
async fn disable(cli: Cli) -> i32 {
    let uri = endpoint_uri(&cli.base, cli.port);
    let channel = match dial(&uri).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return EXIT_UNREACHABLE;
        }
    };
    let mut client = ExecClient::new(channel);
    match client.disable(tonic::Request::new(DisableRequest {})).await {
        Ok(_) => {
            println!("% Disabled");
            0
        }
        Err(status) if lost_connection(&status) => {
            eprintln!("{}", Unreachable::lost(&uri, &status, false));
            EXIT_UNREACHABLE
        }
        Err(status) => {
            println!("% Disable failed: {}", status.message());
            2
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    if cli.logout {
        logout(cli).await?;
    } else if cli.hostname {
        hostname_fetch(cli).await?;
    } else if cli.admin_left {
        admin_left(cli).await?;
    } else if cli.state {
        state(cli).await?;
    } else if cli.show {
        show(cli, None, Vec::new()).await?;
    } else if cli.completion || cli.trailing || cli.first {
        completion(cli).await?;
    } else {
        exec(cli).await?;
    }
    Ok(())
}

/// Exit status of a failed command path. Prints the unreachable warning
/// when that is why; a refusal and any other failure stay silent, so the
/// shell sees empty output and a non-zero status as before.
fn failure_code(uri: &str, err: &anyhow::Error) -> i32 {
    if let Some(unreachable) = err.downcast_ref::<Unreachable>() {
        eprintln!("{unreachable}");
        return EXIT_UNREACHABLE;
    }
    // Already said, after the output it cut short.
    if let Some(cut) = err.downcast_ref::<CutShort>() {
        return if cut.lost {
            EXIT_UNREACHABLE
        } else {
            EXIT_FAILURE
        };
    }
    if err.downcast_ref::<NoLease>().is_some() {
        return EXIT_UNKNOWN;
    }
    if let Some(status) = err.downcast_ref::<tonic::Status>() {
        match status.code() {
            // Not on the daemon's uid allow-list: every command is
            // refused, `show` too, and no role would cure that. Say so.
            tonic::Code::PermissionDenied if status.metadata().get(DENIED_KEY).is_some() => {
                eprintln!("% {}", status.message());
                return EXIT_FAILURE;
            }
            // Only a refusal for want of the role: the shell takes it as
            // the role having lapsed, or as `configure` needing it.
            tonic::Code::PermissionDenied => return EXIT_DENIED,
            // Connected, then lost the daemon (stopped mid-call).
            _ if lost_connection(status) => {
                eprintln!("{}", Unreachable::lost(uri, status, false));
                return EXIT_UNREACHABLE;
            }
            // Any other refusal is the daemon's to explain: no session
            // (a TCP endpoint has no peer credentials), a client outside
            // its PID namespace, /proc unreadable.
            _ => {
                eprintln!("% {}", status.message());
                return EXIT_FAILURE;
            }
        }
    }
    EXIT_FAILURE
}

async fn dispatch(cli: Cli) -> i32 {
    // Enable/Disable need to control their own exit codes for the shell
    // wrapper to react (e.g. flip CLI_PRIVILEGE on success).
    if cli.enable {
        return enable(cli).await;
    }
    if cli.disable {
        return disable(cli).await;
    }
    // Same reason as enable/disable: the exit code *is* the answer, so
    // it must not go through `run`'s failure mapping.
    if cli.uncommitted {
        return uncommitted(cli).await;
    }

    let uri = endpoint_uri(&cli.base, cli.port);
    let logout_mode = cli.logout;
    match run(cli).await {
        Ok(()) => 0,
        // Logout runs from the bash EXIT trap (`|| true`) of a shell that
        // is already leaving: no message, no status.
        Err(_) if logout_mode => 0,
        // Nothing on stdout, so the bash side can detect failure (empty
        // output / non-zero exit) and retry registration on the next
        // command or completion.
        Err(err) => failure_code(&uri, &err),
    }
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if let Ok(val) = env::var("CLI_SERVER_URL") {
        cli.base = val;
    }

    // The timer sleeps for up to the whole admin lease; it needs no
    // runtime and its threads.
    if let Some(secs) = cli.timer {
        std::process::exit(timer(secs, cli.parent));
    }

    // One request per run: a thread pool would only cost start-up time,
    // which the vty pays on every command.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let code = runtime.block_on(dispatch(cli));
    // Let the runtime finish any write to stdout before exiting.
    drop(runtime);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "unix:zebra-rs/vty";

    fn code_of(err: impl Into<anyhow::Error>) -> i32 {
        failure_code(URI, &err.into())
    }

    #[test]
    fn only_permission_denied_is_a_refusal() {
        assert_eq!(code_of(tonic::Status::permission_denied("x")), EXIT_DENIED);
        // No session (a TCP endpoint has no peer credentials): no role
        // would cure that, so the shell must not take it for a lapse.
        assert_eq!(code_of(tonic::Status::unauthenticated("x")), EXIT_FAILURE);
    }

    #[test]
    fn lost_daemon_is_unreachable() {
        assert_eq!(code_of(tonic::Status::unavailable("x")), EXIT_UNREACHABLE);
        // A dropped connection can surface as an h2 error or a cancel.
        assert_eq!(code_of(tonic::Status::unknown("h2")), EXIT_UNREACHABLE);
        assert_eq!(code_of(tonic::Status::cancelled("x")), EXIT_UNREACHABLE);
        let refused =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(code_of(Unreachable::new(URI, &refused)), EXIT_UNREACHABLE);
    }

    #[test]
    fn other_refusals_are_failures_not_lapses() {
        let pidns = tonic::Status::failed_precondition("client not visible");
        assert_eq!(code_of(pidns), EXIT_FAILURE);
        assert_eq!(
            code_of(tonic::Status::internal("cannot read /proc")),
            EXIT_FAILURE
        );
    }

    #[test]
    fn cut_short_keeps_its_cause() {
        assert_eq!(code_of(CutShort { lost: true }), EXIT_UNREACHABLE);
        assert_eq!(code_of(CutShort { lost: false }), EXIT_FAILURE);
    }

    #[test]
    fn missing_lease_is_unknown() {
        assert_eq!(code_of(NoLease), EXIT_UNKNOWN);
    }

    #[test]
    fn unreachable_says_why() {
        let refused = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ECONNREFUSED))
            .context("connect unix:zebra-rs/vty");
        assert_eq!(
            Unreachable::new(URI, &refused).to_string(),
            "% Cannot connect to zebra-rs at unix:zebra-rs/vty: Connection refused; \
             is zebra-rs running?"
        );
        let status = tonic::Status::unavailable("connection reset");
        assert_eq!(
            Unreachable::lost(URI, &status, true).to_string(),
            "% Output cut short: lost zebra-rs at unix:zebra-rs/vty: connection reset"
        );
    }

    #[test]
    fn allow_list_refusal_is_not_a_lapse() {
        let mut status = tonic::Status::permission_denied("uid 1000 is not permitted");
        status.metadata_mut().insert(
            DENIED_KEY,
            tonic::metadata::MetadataValue::from_static("peer"),
        );
        assert_eq!(code_of(status), EXIT_FAILURE);
    }

    #[test]
    fn only_a_lost_connection_cuts_show_short() {
        assert!(lost_connection(&tonic::Status::unavailable("x")));
        assert!(lost_connection(&tonic::Status::unknown(
            "h2 protocol error"
        )));
        // The daemon's own end of a show with no handler output.
        assert!(!lost_connection(&tonic::Status::not_found(
            "no show handler"
        )));
    }

    #[test]
    fn sigcgt_mask_read() {
        // SIGUSR1 is 10: bit 9 is 0x200.
        let with = "Name:\tvty\nSigBlk:\t0000000000000000\nSigCgt:\t000000004b817efb\n";
        let without = "Name:\tsleep\nSigCgt:\t0000000000000000\n";
        assert!(sig_caught(with, libc::SIGUSR1));
        assert!(!sig_caught(without, libc::SIGUSR1));
        assert!(!sig_caught("Name:\tx\n", libc::SIGUSR1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_names_the_running_program() {
        // SAFETY: getpid is a plain syscall.
        let me = unsafe { libc::getpid() };
        let exe = std::env::current_exe().unwrap();
        assert_eq!(executable(me).as_deref(), exe.to_str());
    }
}
