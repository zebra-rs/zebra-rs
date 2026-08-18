pub mod client;
pub mod fleet;
pub mod server;
pub mod tools;

use anyhow::Result;
use std::path::Path;
use tracing::{debug, error};
use tracing_subscriber::{self, Registry};

use fleet::Fleet;
use server::ZmcpServer;
use tools::ontology::OntologyTool;

/// Run the MCP server
pub async fn run(
    host: &str,
    port: u32,
    debug_mode: bool,
    ontology: Option<&str>,
    fleet: Option<&str>,
) -> Result<()> {
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

    // Pass the host through unchanged; `ZebraClient::endpoint()` normalizes
    // it (bare host → `http://host:port`, while `unix:NAME` and full
    // `http(s)://` / `tcp://` URIs are used as-is). Pre-prepending `http://`
    // here would corrupt `unix:` sockets — including the default
    // `unix:zebra-rs/vty` — into the unparseable `http://unix:...`.
    // Fleet mode: the ontology file doubles as the router roster, so
    // `--fleet` alone also serves get-ontology (an explicit `--ontology`
    // still wins). Both fail fast on a bad file, before the client sees
    // a server that would break on its first call.
    let fleet_srv = fleet
        .map(|path| Fleet::new(Path::new(path), host))
        .transpose()?;
    let ontology_tool = ontology
        .or(fleet)
        .map(|path| OntologyTool::new(Path::new(path)))
        .transpose()?;

    let server = ZmcpServer::new(host.to_string(), port, ontology_tool, fleet_srv);

    // Test connection to zebra-rs. In fleet mode there is no local daemon
    // to dial — each call spawns a per-router child — so skip the probe.
    if server.fleet().is_none() {
        if let Err(e) = server.zebra_client().test_connection().await {
            error!("Failed to connect to zebra-rs: {}", e);
            error!("Make sure zebra-rs is running on the specified address");
            return Err(e);
        }
        debug!("Successfully connected to zebra-rs");
    }

    server.run().await?;

    Ok(())
}
