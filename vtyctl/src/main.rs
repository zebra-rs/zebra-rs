use anyhow::Result;
use clap::{Parser, Subcommand};

pub mod vty {
    tonic::include_proto!("vty");
}
pub mod apply;
pub mod clear;
pub mod configdb;
pub mod endpoint;
pub mod frr;
pub mod mcp;
pub mod show;
pub mod watch;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Server endpoint URI (unix:NAME, unix:/PATH, tcp:HOST:PORT); \
                usable before or after the subcommand [default: unix:zebra-rs/vty]"
    )]
    vty_socket: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

const DEFAULT_ENDPOINT: &str = "unix:zebra-rs/vty";

/// Effective endpoint: the per-subcommand `--host` wins over the global
/// `--vty-socket`; both fall back to the default abstract socket.
fn endpoint<'a>(host: &'a Option<String>, vty_socket: &'a Option<String>) -> &'a str {
    host.as_deref()
        .or(vty_socket.as_deref())
        .unwrap_or(DEFAULT_ENDPOINT)
}

#[derive(Subcommand)]
enum ConfigDbAction {
    /// Print the next order as `{"id": N, "patch": [...]}`, or nothing
    /// when none comes in time.
    Wait {
        #[arg(long, default_value_t = 30, help = "Seconds to wait for an order")]
        timeout: u32,
    },
    /// Report on an order: written, or with --error not written and why.
    Done {
        #[arg(help = "The order's id")]
        id: u64,

        #[arg(long, help = "Why the change was not written")]
        error: Option<String>,
    },
}

#[derive(Subcommand)]
enum Commands {
    #[command(disable_help_flag = true)]
    Apply {
        #[arg(short, long, help = "Server endpoint URI (overrides --vty-socket)")]
        host: Option<String>,

        #[arg(short, long, help = "Config filename", default_value = "")]
        filename: String,

        #[arg(short, long, help = "Command line strings")]
        command: Option<String>,
    },
    #[command(disable_help_flag = true)]
    Clear {
        #[arg(short, long, help = "Server endpoint URI (overrides --vty-socket)")]
        host: Option<String>,

        #[arg(help = "Clear command to execute")]
        command: String,
    },
    #[command(disable_help_flag = true)]
    Show {
        #[arg(short, long, help = "Server endpoint URI (overrides --vty-socket)")]
        host: Option<String>,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,

        #[arg(help = "Show command to execute")]
        command: String,
    },
    /// The writer of CONFIG_DB on a SONiC device: take the next change a
    /// commit needs written, and say what became of it.
    #[command(name = "config-db")]
    ConfigDb {
        #[arg(
            short = 'H',
            long,
            help = "Server endpoint URI (overrides --vty-socket)"
        )]
        host: Option<String>,

        #[command(subcommand)]
        action: ConfigDbAction,
    },
    #[command(disable_help_flag = true)]
    Watch {
        #[arg(short, long, help = "Server endpoint URI (overrides --vty-socket)")]
        host: Option<String>,

        #[arg(
            short,
            long,
            help = "Whole-subtree JSON per commit instead of set/delete lines"
        )]
        json: bool,

        #[arg(help = "Config path to watch, e.g. 'router bgp' (omit for the whole config)")]
        path: Vec<String>,
    },
    /// FRR vtysh compatibility: `vtyctl vtysh -c 'show bgp summary json'`
    #[command(disable_help_flag = true)]
    Vtysh {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Start MCP (Model Context Protocol) server for AI assistant integration
    Mcp {
        #[arg(
            short = 'H',
            long,
            help = "Server endpoint URI (overrides --vty-socket)"
        )]
        host: Option<String>,

        #[arg(
            short,
            long,
            help = "gRPC server port (TCP only)",
            default_value = "2666"
        )]
        port: u32,

        #[arg(short, long, help = "Enable debug logging")]
        debug: bool,

        #[arg(
            short,
            long,
            help = "Ontology JSON file to serve via the get-ontology tool"
        )]
        ontology: Option<String>,

        #[arg(
            short,
            long,
            help = "Serve a whole fleet: ontology JSON file naming the routers \
                    (name = netns); adds a 'router' argument to every tool"
        )]
        fleet: Option<String>,
    },
}

fn print_help() {
    eprintln!("`vtyctl' controls zebra-rs configuration and show commands.");
    eprintln!();
    eprintln!("Basic Commands:");
    eprintln!("  apply       Apply configuration.");
    eprintln!("  clear       Clear commands.");
    eprintln!("  show        Show commands.");
    eprintln!("  watch       Watch running-config commits.");
    eprintln!("  config-db   Take and answer CONFIG_DB changes (SONiC).");
    eprintln!("  vtysh       Take an FRR vtysh command line (-c 'show ...').");
    eprintln!("  mcp         Start MCP server for AI assistant integration.");
}

#[tokio::main]
async fn main() -> Result<()> {
    // Installed under the name `vtysh` (SONiC's bgp container links it
    // there), the binary takes FRR's vtysh command line instead of its own.
    let mut argv = std::env::args();
    if frr::is_vtysh_name(&argv.next().unwrap_or_default()) {
        std::process::exit(frr::run(DEFAULT_ENDPOINT, argv.collect()).await);
    }

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Apply {
            host,
            filename,
            command,
        }) => {
            apply::apply(endpoint(host, &cli.vty_socket), filename, command.as_ref()).await?;
        }
        Some(Commands::Clear { host, command }) => {
            clear::clear(endpoint(host, &cli.vty_socket), command).await?;
        }
        Some(Commands::Show {
            host,
            json,
            command,
        }) => {
            show::show(endpoint(host, &cli.vty_socket), command, *json).await?;
        }
        Some(Commands::Vtysh { args }) => {
            let code = frr::run(endpoint(&None, &cli.vty_socket), args.clone()).await;
            std::process::exit(code);
        }
        Some(Commands::ConfigDb { host, action }) => {
            let host = endpoint(host, &cli.vty_socket);
            match action {
                ConfigDbAction::Wait { timeout } => configdb::wait(host, *timeout).await?,
                ConfigDbAction::Done { id, error } => {
                    configdb::done(host, *id, error.clone()).await?
                }
            }
        }
        Some(Commands::Watch { host, json, path }) => {
            watch::watch(endpoint(host, &cli.vty_socket), *json, path.clone()).await?;
        }
        Some(Commands::Mcp {
            host,
            port,
            debug,
            ontology,
            fleet,
        }) => {
            mcp::run(
                endpoint(host, &cli.vty_socket),
                *port,
                *debug,
                ontology.as_deref(),
                fleet.as_deref(),
            )
            .await?;
        }
        None => {
            print_help();
        }
    }

    Ok(())
}
