use anyhow::Result;
use clap::{Parser, Subcommand};

pub mod vtysh {
    tonic::include_proto!("vtysh");
}
pub mod apply;
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
}

fn print_help() {
    eprintln!("`zctl' controls zebra-rs configuration and show commands.");
    eprintln!("");
    eprintln!("Basic Commands:");
    eprintln!("  apply       Apply configuration.");
    eprintln!("  show        Show commands.");
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
        None => {
            print_help();
        }
    }

    Ok(())
}
