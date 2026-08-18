use anyhow::Result;
use clap::{Parser, Subcommand};

pub mod vty {
    tonic::include_proto!("vty");
}
pub mod apply;
pub mod clear;
pub mod endpoint;
pub mod mcp;
pub mod show;
pub mod watch;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(disable_help_flag = true)]
    Apply {
        #[arg(short, long, default_value = "unix:zebra-rs/vty")]
        host: String,

        #[arg(short, long, help = "Config filename", default_value = "")]
        filename: String,

        #[arg(short, long, help = "Command line strings")]
        command: Option<String>,
    },
    #[command(disable_help_flag = true)]
    Clear {
        #[arg(short, long, default_value = "unix:zebra-rs/vty")]
        host: String,

        #[arg(help = "Clear command to execute")]
        command: String,
    },
    #[command(disable_help_flag = true)]
    Show {
        #[arg(short, long, default_value = "unix:zebra-rs/vty")]
        host: String,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,

        #[arg(help = "Show command to execute")]
        command: String,
    },
    #[command(disable_help_flag = true)]
    Watch {
        #[arg(short, long, default_value = "unix:zebra-rs/vty")]
        host: String,

        #[arg(
            short,
            long,
            help = "Whole-subtree JSON per commit instead of set/delete lines"
        )]
        json: bool,

        #[arg(help = "Config path to watch, e.g. 'router bgp' (omit for the whole config)")]
        path: Vec<String>,
    },
    /// Start MCP (Model Context Protocol) server for AI assistant integration
    Mcp {
        #[arg(short = 'H', long, default_value = "unix:zebra-rs/vty")]
        host: String,

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
    eprintln!("  mcp         Start MCP server for AI assistant integration.");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Apply {
            host,
            filename,
            command,
        }) => {
            apply::apply(host, filename, command.as_ref()).await?;
        }
        Some(Commands::Clear { host, command }) => {
            clear::clear(host, command).await?;
        }
        Some(Commands::Show {
            host,
            json,
            command,
        }) => {
            show::show(host, command, *json).await?;
        }
        Some(Commands::Watch { host, json, path }) => {
            watch::watch(host, *json, path.clone()).await?;
        }
        Some(Commands::Mcp {
            host,
            port,
            debug,
            ontology,
        }) => {
            mcp::run(host, *port, *debug, ontology.as_deref()).await?;
        }
        None => {
            print_help();
        }
    }

    Ok(())
}
