pub mod client;
pub mod server;
pub mod tools;

use anyhow::Result;
use tracing::{debug, error};
use tracing_subscriber::{self, Registry};

use server::ZmcpServer;

/// Run the MCP server
pub async fn run(host: &str, port: u32, debug_mode: bool) -> Result<()> {
    // Initialize tracing - disable all terminal output for MCP compatibility
    // Only enable logging if explicitly requested via RUST_LOG environment variable
    if std::env::var("RUST_LOG").is_ok() || debug_mode {
        let log_level = if debug_mode {
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

    debug!("Starting vtyctl mcp server v{}", env!("CARGO_PKG_VERSION"));
    debug!("Connecting to zebra-rs at {}:{}", host, port);

    let base_url = if host.starts_with("http://") || host.starts_with("https://") {
        host.to_string()
    } else {
        format!("http://{}", host)
    };

    let server = ZmcpServer::new(base_url, port);

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
