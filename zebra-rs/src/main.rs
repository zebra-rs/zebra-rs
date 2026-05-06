mod config;
mod fmt;
mod spf;
mod version;
use config::{Cli, ConfigManager};
use std::path::PathBuf;
mod bgp;
use bgp::Bgp;
mod rib;
use rib::{LogFormatType, LogOutputType, Rib, logging_config_from_args, tracing_set};
mod policy;
use policy::Policy;
mod context;
mod fib;
mod isis;
mod ospf;
mod srv6;

use clap::Parser;
use daemonize::Daemonize;

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
}

// 1. Option Yang path
// 2. HomeDir ~/.zebra/yang
// 3. System /etc/zebra-rs/yang

use std::path::Path;

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

fn daemonize(pid_file: Option<&str>) -> anyhow::Result<()> {
    let daemonize = Daemonize::new()
        .pid_file(pid_file.unwrap_or("/var/run/zebra-rs.pid"))
        .chown_pid_file(true) // is optional, see `Daemonize` documentation
        .working_directory("/") // for default behaviour.
        .umask(0o027) // Set umask, `0o027` by default.
        .privileged_action(|| "Executed before drop privileges");

    match daemonize.start() {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Failed to daemonize: {}", e)),
    }
}

fn write_pid_file(path: &str) -> anyhow::Result<()> {
    std::fs::write(path, format!("{}\n", std::process::id()))
        .map_err(|e| anyhow::anyhow!("Failed to write PID to {}: {}", path, e))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arg = Arg::parse();

    let yang_path = yang_path(&arg);
    if yang_path.is_none() {
        println!("Can't find YANG load path");
        std::process::exit(1);
    }
    let yang_path = yang_path.unwrap();

    let mut rib = Rib::new(arg.no_nhid, arg.enable_addr_recovery)?;

    let policy = Policy::new();

    let bgp = Bgp::new(rib.tx.clone(), policy.tx.clone());
    rib.subscribe(bgp.redist.tx.clone(), "bgp".to_string());

    let config = ConfigManager::new(system_path(&arg), yang_path, rib.tx.clone())?;
    config.subscribe("rib", rib.cm.tx.clone());
    config.subscribe("bgp", bgp.cm.tx.clone());
    config.subscribe("policy", policy.cm.tx.clone());
    config.subscribe_show("rib", rib.show.tx.clone());
    config.subscribe_show("bgp", bgp.show.tx.clone());
    config.subscribe_show("policy", policy.show.tx.clone());

    let cli = Cli::new(config.tx.clone());

    config::serve(cli);

    policy::serve(policy);

    bgp::serve(bgp);

    rib::serve(rib);
    // rib::nanomsg::serve();

    // Setup tracing based on CLI arguments
    let log_config = logging_config_from_args(&arg.log_output, &arg.log_file, &arg.log_format);
    tracing_set(arg.daemon, Some(log_config));

    // Daemonize if requested (after tracing setup)
    if arg.daemon {
        daemonize(arg.pid_file.as_deref())?;
    } else if let Some(ref path) = arg.pid_file {
        write_pid_file(path)?;
    }

    tracing::info!("zebra-rs started");

    config::event_loop(config).await;

    Ok(())
}
