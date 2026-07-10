use anyhow::Result;
use clap::Parser;
use std::env;
use tokio::io::{self, AsyncWriteExt};
use tokio_stream::StreamExt;
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
        short = 'H',
        long = "hostname",
        help = "Print the daemon's configured `system hostname` (empty when unset); \
                used once at vty startup to seed CLI_HOSTNAME for the prompt"
    )]
    hostname: bool,

    #[arg(
        long,
        help = "Deprecated and ignored; the daemon always authenticates enable against root."
    )]
    auth_user: Option<String>,

    #[arg(
        short,
        long,
        help = "Server endpoint URI (unix:NAME, tcp://host:port, http://host:port). \
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

/// Build the endpoint URI from the parsed CLI.
///
/// `--base` may already be a full URI (`unix:…`, `tcp://host:port`,
/// `http://host:port`) — in which case `--port` is ignored. Otherwise the
/// legacy `{base}:{port}` concatenation is used, matching the historical
/// `http://127.0.0.1` + `2666` defaults.
fn endpoint_uri(base: &str, port: u32) -> String {
    if base.starts_with("unix:")
        || base.starts_with("tcp://")
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
    let channel = endpoint::connect(&endpoint_uri(&cli.base, port)).await?;
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
    while let Some(reply) = stream.next().await {
        let Ok(reply) = reply else {
            return Ok(());
        };
        stdout.write_all(reply.str.as_bytes()).await?;
    }

    Ok(())
}

async fn completion(cli: Cli) -> Result<()> {
    let channel = endpoint::connect(&endpoint_uri(&cli.base, cli.port)).await?;
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
    let channel = endpoint::connect(&endpoint_uri(&cli.base, port)).await?;
    let mut client = ExecClient::new(channel);

    let commands = commands_trim_run(&cli.commands);
    let request = tonic::Request::new(exec_request(ExecType::Exec as i32, &cli.mode, &commands));
    let reply = client.do_exec(request).await?.into_inner();

    output(reply);

    Ok(())
}

/// Print the daemon's configured `system hostname` (empty when
/// unset). Invoked as `vtyhelper -H` by the vty shell — once at
/// startup to seed `CLI_HOSTNAME`, and after every executed command
/// (`_cli_hostname_refresh`) so the prompt tracks `set system
/// hostname` / `delete system hostname` as soon as they commit.
async fn hostname_fetch(cli: Cli) -> Result<()> {
    let channel = endpoint::connect(&endpoint_uri(&cli.base, cli.port)).await?;
    let mut client = ExecClient::new(channel);
    let request = tonic::Request::new(exec_request(
        ExecType::Exec as i32,
        &String::from("exec"),
        &Vec::new(),
    ));
    let reply = client.do_exec(request).await?.into_inner();
    println!("{}", reply.hostname);
    Ok(())
}

async fn exec(cli: Cli) -> Result<()> {
    let channel = endpoint::connect(&endpoint_uri(&cli.base, cli.port)).await?;
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
    let channel = endpoint::connect(&endpoint_uri(&cli.base, cli.port)).await?;
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

    let channel = match endpoint::connect(&endpoint_uri(&cli.base, cli.port)).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("% enable: connect failed: {e}");
            return 2;
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

/// Drop the session back to View. Idempotent; the daemon doesn't error.
async fn disable(cli: Cli) -> i32 {
    let channel = match endpoint::connect(&endpoint_uri(&cli.base, cli.port)).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("% disable: connect failed: {e}");
            return 2;
        }
    };
    let mut client = ExecClient::new(channel);
    match client.disable(tonic::Request::new(DisableRequest {})).await {
        Ok(_) => {
            println!("% Disabled");
            0
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
    } else if cli.show {
        show(cli, None, Vec::new()).await?;
    } else if cli.completion || cli.trailing || cli.first {
        completion(cli).await?;
    } else {
        exec(cli).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if let Ok(val) = env::var("CLI_SERVER_URL") {
        cli.base = val;
    }

    // Enable/Disable need to control their own exit codes for the shell
    // wrapper to react (e.g. flip CLI_PRIVILEGE on success).
    if cli.enable {
        std::process::exit(enable(cli).await);
    }
    if cli.disable {
        std::process::exit(disable(cli).await);
    }

    let logout_mode = cli.logout;
    if let Err(_err) = run(cli).await {
        // Stay silent: no fallback output, so the bash side can detect
        // failure (empty stdout / non-zero exit) and retry registration
        // on the next command or completion. Logout runs from the bash
        // EXIT trap (`|| true`), so a non-zero exit is harmless there.
        if !logout_mode {
            std::process::exit(1);
        }
    }
    Ok(())
}
