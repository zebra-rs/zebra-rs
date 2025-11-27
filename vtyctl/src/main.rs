use anyhow::Result;
use clap::{Parser, Subcommand};

pub mod vtysh {
    tonic::include_proto!("vtysh");
}
pub mod apply;
pub mod mcp;
pub mod show;

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
        #[arg(short, long, default_value = "127.0.0.1")]
        host: String,

        #[arg(short, long, help = "Base URL of the server", default_value = "")]
        filename: String,
    },
    #[command(disable_help_flag = true)]
    Show {
        #[arg(short, long, default_value = "127.0.0.1")]
        host: String,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,

        #[arg(help = "Show command to execute")]
        command: String,
    },
    /// Start MCP (Model Context Protocol) server for AI assistant integration
    Mcp {
        #[arg(short = 'H', long, default_value = "127.0.0.1")]
        host: String,

        #[arg(short, long, help = "gRPC server port", default_value = "2666")]
        port: u32,

        #[arg(short, long, help = "Enable debug logging")]
        debug: bool,
    },
}

fn print_help() {
    eprintln!("`vtyctl' controls zebra-rs configuration and show commands.");
    eprintln!("");
    eprintln!("Basic Commands:");
    eprintln!("  apply       Apply configuration.");
    eprintln!("  show        Show commands.");
    eprintln!("  mcp         Start MCP server for AI assistant integration.");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Apply { host, filename }) => {
            apply::apply(host, filename).await?;
        }
        Some(Commands::Show {
            host,
            json,
            command,
        }) => {
            show::show(host, command, *json).await?;
        }
        Some(Commands::Mcp { host, port, debug }) => {
            mcp::run(host, *port, *debug).await?;
        }
        None => {
            print_help();
        }
    }

    Ok(())
}
