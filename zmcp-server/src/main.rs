use anyhow::Result;
use clap::Parser;
use tracing::{debug, error};
use tracing_subscriber::{self, Registry};

use zmcp_server::ZmcpServer;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(
        short,
        long,
        help = "Base URL of zebra-rs server",
        default_value = "http://127.0.0.1"
    )]
    base: String,

    #[arg(short, long, help = "Show server port", default_value = "2666")]
    port: u32,

    #[arg(short, long, help = "Enable debug logging")]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing - disable all terminal output for MCP compatibility
    // Only enable logging if explicitly requested via RUST_LOG environment variable
    if std::env::var("RUST_LOG").is_ok() || cli.debug {
        let log_level = if cli.debug {
            "debug".to_string()
        } else {
            std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string())
        };
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
    } else {
        // Disable all logging output to keep stdin/stdout clean
        tracing::subscriber::set_global_default(Registry::default())?;
    }

    debug!("Starting zmcp-server v{}", env!("CARGO_PKG_VERSION"));
    debug!("Connecting to zebra-rs at {}:{}", cli.base, cli.port);

    let server = ZmcpServer::new(cli.base, cli.port);

    // Test connection to zebra-rs
    if let Err(e) = server.zebra_client().test_connection().await {
        error!("Failed to connect to zebra-rs: {}", e);
        error!("Make sure zebra-rs is running on the specified address");
        return Err(e);
    }

    debug!("Successfully connected to zebra-rs");

    server.run().await?;

    Ok(())
}
