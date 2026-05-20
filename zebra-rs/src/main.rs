use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use clap::Parser;
use daemonize::Daemonize;

mod bfd;
mod bgp;
mod config;
mod context;
use config::{Cli, ConfigManager};
mod fib;
mod fmt;
mod isis;
mod nd;
mod policy;
use policy::Policy;
mod rib;
use rib::{LogFormatType, LogOutputType, Rib, logging_config, tracing_set};
mod ospf;
mod spf;
mod srv6;
mod version;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Arg {
    #[arg(short, long, help = "YANG load path", default_value = "")]
    yang_path: String,

    #[arg(short, long, help = "Run as daemon in background")]
    daemon: bool,

    #[arg(
        long,
        value_enum,
        help = "Logging output destination",
        default_value = "stdout"
    )]
    log_output: LogOutputType,

    #[arg(
        long,
        help = "Log file path (optional, defaults to ./zebra-rs.log when --log-output=file)"
    )]
    log_file: Option<String>,

    #[arg(long, value_enum, help = "Logging format", default_value = "terminal")]
    log_format: LogFormatType,

    #[arg(
        long,
        help = "Disable nexthop ID and use embedded nexthop in routes (for kernels < 5.3)"
    )]
    no_nhid: bool,

    #[arg(
        long,
        help = "Re-install configured addresses removed by the kernel (cool-down on burst); off by default"
    )]
    enable_addr_recovery: bool,

    #[arg(
        long,
        help = "Write PID to this file on startup; in --daemon mode replaces /var/run/zebra-rs.pid"
    )]
    pid_file: Option<String>,

    #[arg(
        long,
        help = "VTY gRPC listen address. Forms: unix:NAME (Linux abstract socket) or tcp:HOST:PORT",
        default_value = "unix:zebra-rs/vty"
    )]
    vty_socket: String,
}

// 1. Option Yang path
// 2. HomeDir ~/.zebra/yang
// 3. System /etc/zebra-rs/yang

fn yang_path(arg: &Arg) -> Option<String> {
    if !arg.yang_path.is_empty() {
        let path = Path::new(&arg.yang_path);
        if path.exists() {
            return Some(path.to_string_lossy().to_string());
        }
    }
    if let Some(mut home_dir) = dirs::home_dir() {
        home_dir.push(".zebra-rs");
        home_dir.push("yang");
        if home_dir.exists() {
            return Some(home_dir.to_string_lossy().to_string());
        }
    }
    let path = Path::new("/etc/zebra-rs/yang");
    if path.exists() {
        Some(path.to_string_lossy().to_string())
    } else {
        None
    }
}

fn system_path(arg: &Arg) -> PathBuf {
    if !arg.yang_path.is_empty() {
        PathBuf::from(&arg.yang_path)
    } else {
        let mut home = dirs::home_dir().unwrap();
        home.push(".zebra-rs");
        home.push("yang");
        if home.is_dir() {
            home
        } else {
            let mut path = PathBuf::new();
            path.push("etc");
            path.push("zebra-rs");
            home.push("yang");
            if path.is_dir() {
                path
            } else {
                let mut cwd = std::env::current_dir().unwrap();
                cwd.push("yang");
                cwd
            }
        }
    }
}

fn daemonize() -> anyhow::Result<()> {
    // Preserve the original cwd in the daemonized child so relative
    // paths (e.g. `--yang-path ./yang`, relative `--pid-file`) still
    // resolve the same way they would in foreground mode.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    Daemonize::new()
        .working_directory(cwd)
        .start()
        .map_err(|e| anyhow::anyhow!("Failed to daemonize: {}", e))
}

fn write_pid_file(path: &str) -> anyhow::Result<()> {
    std::fs::write(path, format!("{}\n", std::process::id()))
        .map_err(|e| anyhow::anyhow!("Failed to write PID to {}: {}", path, e))
}

fn main() {
    let arg = Arg::parse();

    // Daemonize before building the tokio runtime.
    if arg.daemon {
        daemonize().unwrap_or_else(|e| {
            eprintln!("zebra-rs: {e:#}");
            std::process::exit(1);
        });
    }

    if let Some(ref path) = arg.pid_file {
        write_pid_file(path).unwrap_or_else(|e| {
            eprintln!("zebra-rs: {e:#}");
            std::process::exit(1);
        });
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("zebra-rs: {e:#}");
            std::process::exit(1);
        });

    rt.block_on(async {
        if let Err(e) = run(arg).await {
            eprintln!("zebra-rs: {e:#}");
            std::process::exit(1);
        }
    });
}

async fn run(arg: Arg) -> anyhow::Result<()> {
    let Some(yang_path) = yang_path(&arg) else {
        eprintln!("zebra-rs: Can't find YANG load path");
        std::process::exit(1);
    };

    // Setup tracing before any subsystem spin-up so warn/error events
    // emitted during construction (e.g. ND failing to open its raw
    // socket inside `ConfigManager::new`) are actually surfaced to the
    // operator instead of being swallowed by the default subscriber.
    let log_config = logging_config(&arg.log_output, &arg.log_file, &arg.log_format);
    tracing_set(arg.daemon, Some(log_config));

    let rib = Rib::new(arg.no_nhid, arg.enable_addr_recovery)?;

    let policy = Policy::new();

    // Runtime-mutable YANG-defined service-accounts. Shared between
    // ConfigManager (writes on commit) and SessionTable (reads at session
    // creation). Empty at startup; populated by the config file load that runs
    // inside ConfigManager.
    let service_accounts: Arc<RwLock<HashSet<u32>>> = Arc::new(RwLock::new(HashSet::new()));

    let config = ConfigManager::new(
        system_path(&arg),
        yang_path,
        rib.tx.clone(),
        rib.inbound_tx.clone(),
        policy.tx.clone(),
        service_accounts.clone(),
    )?;
    config.subscribe("rib", rib.cm.tx.clone());
    config.subscribe("policy", policy.cm.tx.clone());
    config.subscribe_show("rib", rib.show.tx.clone());
    config.subscribe_show("policy", policy.show.tx.clone());

    let cli = Cli::new(config.tx.clone(), service_accounts);

    let vty_addr = config::VtyAddr::parse(&arg.vty_socket)?;

    config::serve(cli, vty_addr)?;

    policy::serve(policy);

    rib::serve(rib);

    // rib::nanomsg::serve();

    tracing::info!("zebra-rs started");

    config::event_loop(config).await;

    Ok(())
}
