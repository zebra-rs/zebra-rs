use anyhow::Result;
use clap::{Parser, Subcommand};

pub mod vtysh {
    tonic::include_proto!("vtysh");
}
pub mod apply;

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
}

fn print_help() {
    eprintln!("`vtyctl' controls Zebra Routing Software configuration.");
    eprintln!("");
    eprintln!("Basic Commands:");
    eprintln!("  apply       Apply configuration.");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Apply { host, filename }) => {
            apply::apply(host, filename).await?;
        }
        None => {
            print_help();
        }
    }

    Ok(())
}
