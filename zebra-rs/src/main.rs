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
use daemonize::Daemonize;
use std::io;
use tracing::Level;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Clone)]
pub enum LoggingOutput {
    Stdout,
    Syslog,
    File(String),
}

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
        // In daemon mode, use syslog by default
        setup_tracing(LoggingOutput::Syslog).unwrap_or_else(|e| {
            eprintln!(
                "Failed to setup syslog logging: {}, falling back to file",
                e
            );
            setup_tracing(LoggingOutput::File("zebra-rs.log".to_string())).unwrap_or_else(|e| {
                eprintln!("Failed to setup file logging: {}, discarding logs", e);
                tracing_subscriber::fmt()
                    .with_max_level(Level::INFO)
                    .with_writer(std::io::sink)
                    .init();
            });
        });
    } else {
        setup_tracing(LoggingOutput::Stdout).unwrap_or_else(|e| {
            eprintln!("Failed to setup stdout logging: {}", e);
            tracing_subscriber::fmt().with_max_level(Level::INFO).init();
        });
    }
}

pub fn setup_tracing(output: LoggingOutput) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match output {
        LoggingOutput::Stdout => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .init();
        }
        LoggingOutput::Syslog => {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::sync::Mutex;
                use syslog::{Facility, Formatter3164};

                // Create a writer that wraps syslog
                struct SyslogWriter {
                    logger: Mutex<syslog::Logger<syslog::LoggerBackend, Formatter3164>>,
                }

                impl SyslogWriter {
                    fn new() -> anyhow::Result<Self> {
                        let formatter = Formatter3164 {
                            facility: Facility::LOG_DAEMON,
                            hostname: None,
                            process: "zebra-rs".to_string(),
                            pid: std::process::id(),
                        };
                        let logger = syslog::unix(formatter)
                            .map_err(|e| anyhow::anyhow!("Failed to connect to syslog: {}", e))?;
                        Ok(SyslogWriter {
                            logger: Mutex::new(logger),
                        })
                    }
                }

                impl Write for SyslogWriter {
                    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                        if let Ok(mut logger) = self.logger.lock() {
                            let msg_cow = String::from_utf8_lossy(buf);
                            let msg = msg_cow.trim();
                            let _ = logger.info(msg);
                        }
                        Ok(buf.len())
                    }

                    fn flush(&mut self) -> io::Result<()> {
                        Ok(())
                    }
                }

                let syslog_writer = SyslogWriter::new()?;
                let layer = tracing_subscriber::fmt::layer()
                    .with_writer(Mutex::new(syslog_writer))
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_file(false)
                    .with_line_number(false)
                    .with_ansi(false);

                tracing_subscriber::registry()
                    .with(filter)
                    .with(layer)
                    .init();
            }
            #[cfg(not(unix))]
            {
                return Err(anyhow::anyhow!("Syslog is only supported on Unix systems"));
            }
        }
        LoggingOutput::File(path) => {
            // Create a safe fallback path for log files
            let safe_log_path = if path.starts_with('/') {
                // Absolute path - validate and create directory if needed
                let path_obj = std::path::Path::new(&path);
                let parent = path_obj
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("Invalid log file path: {}", path))?;

                // Try to create the directory if it doesn't exist
                if !parent.exists() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to create log directory {}: {}",
                            parent.display(),
                            e
                        )
                    })?;
                }

                // Check if we can write to the directory
                if !parent.exists()
                    || std::fs::metadata(parent)
                        .map(|m| m.permissions().readonly())
                        .unwrap_or(true)
                {
                    return Err(anyhow::anyhow!(
                        "Cannot write to log directory: {}",
                        parent.display()
                    ));
                }

                path.clone()
            } else {
                // Relative path - try /var/log first, fallback to user home or current dir
                let fallback_paths = vec![
                    format!("/var/log/{}", path),
                    dirs::home_dir()
                        .map(|mut h| {
                            h.push(".zebra-rs");
                            h.push(&path);
                            h.to_string_lossy().to_string()
                        })
                        .unwrap_or_else(|| format!("./{}", path)),
                    format!("./{}", path),
                ];

                let mut chosen_path = None;
                for test_path in fallback_paths {
                    let path_obj = std::path::Path::new(&test_path);
                    let parent = path_obj
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."));

                    // Try to create directory and test write permission
                    if let Ok(_) = std::fs::create_dir_all(parent) {
                        // Test write permission by trying to create a temp file
                        let test_file = parent.join(".zebra_write_test");
                        if std::fs::write(&test_file, "test").is_ok() {
                            let _ = std::fs::remove_file(&test_file);
                            chosen_path = Some(test_path);
                            break;
                        }
                    }
                }

                chosen_path.ok_or_else(|| {
                    anyhow::anyhow!("Cannot find writable directory for log file: {}", path)
                })?
            };

            // Extract directory and filename from the safe path
            let log_path = std::path::Path::new(&safe_log_path);
            let log_dir = log_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let log_filename = log_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid log filename"))?;

            let writer = rolling::never(log_dir, log_filename);

            let layer = tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .with_ansi(false);

            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
        }
    }
    Ok(())
}

fn daemonize() -> anyhow::Result<()> {
    let daemonize = Daemonize::new()
        .pid_file("/var/run/zebra-rs.pid") // Every method except `new` and `start`
        .chown_pid_file(true) // is optional, see `Daemonize` documentation
        .working_directory("/") // for default behaviour.
        .umask(0o027) // Set umask, `0o027` by default.
        .privileged_action(|| "Executed before drop privileges");

    match daemonize.start() {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Failed to daemonize: {}", e)),
    }
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

    // Daemonize if requested
    if arg.daemon {
        daemonize()?;
    }

    // tracing_set(arg.daemon);
    // setup_tracing(LoggingOutput::File(
    //     "/home/kunihiro/zebra-rs.log".to_string(),
    // ))
    // .unwrap_or_else(|e| {
    //     eprintln!("Failed to setup file logging: {}, discarding logs", e);
    //     tracing_subscriber::fmt()
    //         .with_max_level(Level::INFO)
    //         .with_writer(std::io::sink)
    //         .init();
    // });

    tracing::info!("zebra-rs started");

    config::event_loop(config).await;

    Ok(())
}
