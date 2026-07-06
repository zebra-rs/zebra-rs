use std::path::Path;
use std::path::PathBuf;

use clap::Parser;
use daemonize::Daemonize;

// Per-thread-caching allocator. The N-shard worker pool (RIB sharding
// Phase C) has up to 64 threads allocating concurrently on the hot path
// (intern, BgpRib, attr clones); a profile of an N=12 convergence put
// ~12% of CPU in the global allocator's `osq_lock`. mimalloc's per-thread
// heaps remove that contention.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod bfd;
mod bgp;
mod config;
mod context;
use config::{Cli, ConfigManager};
mod fib;
mod flex_algo;
mod fmt;
mod isis;
// The MUP controller lives in `src/mup-c/` (hyphenated dir, per the
// feature's home); `#[path]` maps it to the `mup_c` module name.
#[path = "mup-c/mod.rs"]
mod mup_c;
mod nd;
mod policy;
use policy::Policy;
mod rib;
use rib::{LogFormatType, LogOutputType, Rib, logging_config, tracing_set};
mod ospf;
// Embedded Lua scripting engine, behind the `lua` feature. PR1 is the
// engine skeleton only; the route.rs Loc-RIB hooks that call it land in a
// later PR, so nothing references it yet — drop the allow once wired.
#[allow(dead_code)]
mod script;
mod spf;
mod srv6;
mod stamp;
/// IOS-XR-style exponential-backoff throttle, shared by the IS-IS and
/// OSPF SPF/LSA schedulers.
mod throttle;
mod version;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Arg {
    #[arg(short, long, help = "YANG load path", default_value = "")]
    yang_path: String,

    #[arg(
        short = 'c',
        long = "config-file",
        value_name = "FILENAME",
        help = "Configuration file to load at startup (CLI, JSON, YAML, or set/delete format); overrides the default zebra-rs.conf"
    )]
    config_file: Option<String>,

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

// YANG schema directory search order:
//   1. `--yang-path` argument, if the path exists
//   2. `~/.zebra-rs/yang`, if it exists
//   3. `/etc/zebra-rs/yang`, if it exists
// Returns `None` if none resolve, which causes startup to abort.
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

fn daemonize() -> anyhow::Result<()> {
    // Preserve the original cwd in the daemonized child so relative paths for
    // --yang-path or --pid-file still resolve the same way they would in
    // foreground mode.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    Daemonize::new()
        .working_directory(cwd)
        // The daemonize crate defaults to umask 0o027, which makes a
        // root daemon's pid file (and log files) mode 0640 — unreadable
        // by unprivileged tooling. The BDD harness reads the pid file as
        // the test user to stop the daemon at teardown, so 0o027 made
        // every teardown silently skip the kill and leak the daemon.
        // Use the conventional 0o022 to match foreground behavior.
        .umask(0o022)
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

    let log_config = logging_config(&arg.log_output, &arg.log_file, &arg.log_format);
    tracing_set(arg.daemon, Some(log_config));

    let rib = Rib::new(arg.no_nhid)?;

    let policy = Policy::new();

    let config = ConfigManager::new(
        yang_path,
        arg.config_file.clone(),
        rib.tx.clone(),
        rib.inbound_tx.clone(),
        policy.tx.clone(),
    )?;

    config.subscribe("rib", rib.cm.tx.clone());
    config.subscribe("policy", policy.cm.tx.clone());
    config.subscribe_show("rib", rib.show.tx.clone());
    config.subscribe_show("policy", policy.show.tx.clone());

    let cli = Cli::new(config.tx.clone());

    let vty_addr = config::VtyAddr::parse(&arg.vty_socket)?;

    config::serve(cli, vty_addr)?;

    policy::serve(policy);

    rib::serve(rib);

    // rib::nanomsg::serve();

    // Background drainer for Lua scripts' non-blocking side-effects
    // (sideeffect.nft → nftables). Must run inside the tokio runtime.
    #[cfg(feature = "lua")]
    script::sideeffect::spawn_drainer();

    tracing::info!("zebra-rs started");

    config::event_loop(config).await;

    Ok(())
}
