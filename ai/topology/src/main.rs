//! zebra-topology — 3D traffic path visualizer for the zebra-rs
//! `playset/isis-flexalgo` lab.
//!
//! Serves an embedded globe.gl frontend and three JSON APIs. All router
//! state is obtained through the MCP framework (`vtyctl mcp`, one
//! stateless session per call, per router namespace) — never by scraping
//! vty/vtyctl CLI output.
//!
//! The `snapshot` subcommand exports the same frontend plus every API
//! response as static files, for publishing on a static host.

mod api;
mod mcp;
mod ontology;
mod snapshot;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use api::App;
use mcp::McpLauncher;

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const STYLE_CSS: &str = include_str!("../static/style.css");

/// In live mode the manifest declares "no snapshot": the frontend probes
/// `window.ZEBRA_SNAPSHOT` to decide between the live API and the static
/// `data/` files a snapshot export writes in its place.
const LIVE_MANIFEST_JS: &str = "window.ZEBRA_SNAPSHOT = null;\n";

#[derive(Parser)]
#[command(
    name = "zebra-topology",
    about = "3D traffic path visualizer for the isis-flexalgo playset (MCP-backed)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// HTTP server port (serve mode).
    #[arg(long, global = true, default_value_t = 8080)]
    port: u16,

    /// Path to the playset ontology (router names, cities, regions).
    #[arg(
        long,
        global = true,
        default_value = "playset/isis-flexalgo/ontology.json"
    )]
    ontology: PathBuf,

    /// vtyctl binary providing `vtyctl mcp`. Defaults to $VTYCTL_BIN,
    /// then a vtyctl next to this executable, then target/debug/vtyctl,
    /// then plain `vtyctl` from PATH.
    #[arg(long, global = true)]
    vtyctl: Option<String>,

    /// VTY gRPC endpoint passed to `vtyctl mcp -H` (as seen from inside
    /// each router's namespace).
    #[arg(long, global = true, default_value = "unix:zebra-rs/vty")]
    mcp_host: String,

    /// Per-MCP-call timeout in seconds.
    #[arg(long, global = true, default_value_t = 15)]
    timeout: u64,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the viewer live against the running lab (the default).
    Serve,
    /// Export the viewer plus pre-fetched data for every source router ×
    /// algorithm as a static site (for GitHub Pages and the like).
    Snapshot {
        /// Output directory for the static site.
        #[arg(long, default_value = "dist/topology")]
        out: PathBuf,
        /// How long to wait (seconds) for the lab to converge before
        /// giving up rather than exporting a partial topology.
        #[arg(long, default_value_t = 120)]
        settle_timeout: u64,
    },
}

/// Resolve the vtyctl binary the same way the playset scripts do, plus an
/// executable-sibling fallback so `sudo ./target/debug/zebra-topology`
/// works from any directory.
fn resolve_vtyctl(explicit: Option<String>) -> String {
    if let Some(path) = explicit {
        return path;
    }
    if let Ok(path) = std::env::var("VTYCTL_BIN")
        && !path.is_empty()
    {
        return path;
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("vtyctl");
        if sibling.is_file() {
            return sibling.to_string_lossy().into_owned();
        }
    }
    let built = PathBuf::from("target/debug/vtyctl");
    if built.is_file() {
        return built.to_string_lossy().into_owned();
    }
    "vtyctl".to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let routers = ontology::load(&cli.ontology)?;
    let vtyctl = resolve_vtyctl(cli.vtyctl);
    let app = Arc::new(App {
        routers,
        launcher: McpLauncher {
            vtyctl: vtyctl.clone(),
            host: cli.mcp_host.clone(),
            timeout: Duration::from_secs(cli.timeout),
        },
    });

    println!(
        "  ontology : {} ({} routers)",
        cli.ontology.display(),
        app.routers.len()
    );
    println!("  vtyctl   : {vtyctl}");
    println!("  mcp host : {}", cli.mcp_host);

    match cli.command {
        Some(Command::Snapshot {
            out,
            settle_timeout,
        }) => snapshot::run(&app, &out, Duration::from_secs(settle_timeout)).await,
        None | Some(Command::Serve) => serve(app, cli.port).await,
    }
}

async fn serve(app: Arc<App>, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    println!("zebra-topology: http://localhost:{port}");

    loop {
        let (stream, _) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(req, app.clone()));
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("connection error: {e}");
            }
        });
    }
}

fn query_params(req: &Request<Incoming>) -> HashMap<String, String> {
    req.uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn respond(
    status: StatusCode,
    content_type: &str,
    body: impl Into<Bytes>,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(body.into()))
        .expect("static response parts are valid")
}

fn json_ok(value: serde_json::Value) -> Response<Full<Bytes>> {
    respond(StatusCode::OK, "application/json", value.to_string())
}

fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    respond(
        status,
        "application/json",
        serde_json::json!({ "error": message }).to_string(),
    )
}

async fn handle(
    req: Request<Incoming>,
    app: Arc<App>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() != Method::GET {
        return Ok(json_error(StatusCode::METHOD_NOT_ALLOWED, "GET only"));
    }

    let path = req.uri().path().to_string();
    let response = match path.as_str() {
        "/" => respond(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML),
        "/static/app.js" => respond(StatusCode::OK, "application/javascript", APP_JS),
        "/static/style.css" => respond(StatusCode::OK, "text/css", STYLE_CSS),
        "/data/manifest.js" => respond(StatusCode::OK, "application/javascript", LIVE_MANIFEST_JS),
        "/api/routers" => json_ok(app.api_routers()),
        "/api/algorithms" => api_algorithms(&req, &app).await,
        "/api/topology" => api_topology(&req, &app).await,
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    };
    Ok(response)
}

/// Validate a `source`/`destination` query value: it must be a router the
/// ontology knows. Since the router name doubles as the network namespace
/// in the spawned `ip netns exec` argv, unknown names are rejected rather
/// than passed through.
fn known_router<'a>(app: &App, params: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    params
        .get(key)
        .map(String::as_str)
        .filter(|name| app.router(name).is_some())
}

async fn api_algorithms(req: &Request<Incoming>, app: &App) -> Response<Full<Bytes>> {
    let params = query_params(req);
    let Some(source) = known_router(app, &params, "source") else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "unknown or missing 'source' router",
        );
    };
    match app.api_algorithms(source).await {
        Ok(v) => json_ok(v),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, &format!("{e:#}")),
    }
}

async fn api_topology(req: &Request<Incoming>, app: &App) -> Response<Full<Bytes>> {
    let params = query_params(req);
    let Some(source) = known_router(app, &params, "source") else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "unknown or missing 'source' router",
        );
    };

    let algorithm = match params.get("algorithm").map(String::as_str) {
        None | Some("") | Some("0") => 0u8,
        Some(text) => match text.parse::<u8>() {
            Ok(n) if (128..=255).contains(&n) => n,
            _ => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "'algorithm' must be 0 or a Flex-Algorithm number 128-255",
                );
            }
        },
    };

    let destination = match params.get("destination").map(String::as_str) {
        None | Some("") | Some("__all__") => None,
        Some(_) => match known_router(app, &params, "destination") {
            Some(name) => Some(name),
            None => {
                return json_error(StatusCode::BAD_REQUEST, "unknown 'destination' router");
            }
        },
    };

    match app.api_topology(source, algorithm, destination).await {
        Ok(v) => json_ok(v),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, &format!("{e:#}")),
    }
}
