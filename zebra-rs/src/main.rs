// SPDX-License-Identifier: GPL-3.0-or-later

mod config;
mod spf;
mod version;
use config::{Cli, ConfigManager};
use std::path::PathBuf;
mod bgp;
use bgp::Bgp;
mod rib;
use rib::Rib;
mod policy;
use policy::Policy;
mod context;
mod fib;
mod isis;
mod ospf;

use clap::Parser;
use tracing::Level;
use daemonize::Daemonize;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Arg {
    #[arg(short, long, help = "YANG load path", default_value = "")]
    yang_path: String,

    #[arg(short, long, help = "Run as daemon in background")]
    daemon: bool,
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
        return Some(path.to_string_lossy().to_string());
    } else {
        return None;
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

fn tracing_set(daemon_mode: bool) {
    // console_subscriber::init();
    if daemon_mode {
        // In daemon mode, log to syslog or disable console logging
        tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .with_writer(std::io::sink) // Discard output in daemon mode
            .init();
    } else {
        tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    }
}

fn daemonize() -> anyhow::Result<()> {
    let daemonize = Daemonize::new()
        .pid_file("/var/run/zebra-rs.pid") // Every method except `new` and `start`
        .chown_pid_file(true)              // is optional, see `Daemonize` documentation
        .working_directory("/")            // for default behaviour.
        .umask(0o027)                      // Set umask, `0o027` by default.
        .privileged_action(|| "Executed before drop privileges");

    match daemonize.start() {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Failed to daemonize: {}", e)),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arg = Arg::parse();

    // Daemonize if requested
    if arg.daemon {
        daemonize()?;
    }

    let yang_path = yang_path(&arg);
    if yang_path.is_none() {
        println!("Can't find YANG load path");
        std::process::exit(1);
    }
    let yang_path = yang_path.unwrap();

    let mut rib = Rib::new()?;

    let bgp = Bgp::new(rib.api.tx.clone());
    // rib.subscribe(bgp.redist.tx.clone(), "bgp".to_string());

    let policy = Policy::new();

    let config = ConfigManager::new(system_path(&arg), yang_path, rib.tx.clone())?;
    config.subscribe("rib", rib.cm.tx.clone());
    config.subscribe("bgp", bgp.cm.tx.clone());
    config.subscribe("policy", policy.cm.tx.clone());
    config.subscribe_show("rib", rib.show.tx.clone());
    config.subscribe_show("bgp", bgp.show.tx.clone());

    let cli = Cli::new(config.tx.clone());

    config::serve(cli);

    policy::serve(policy);

    bgp::serve(bgp);

    rib::serve(rib);

    // rib::nanomsg::serve();

    tracing_set(false);
    tracing::info!("zebra-rs started");

    config::event_loop(config).await;

    Ok(())
}
