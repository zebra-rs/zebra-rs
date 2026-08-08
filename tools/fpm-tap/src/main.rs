//! `fpm-tap` — record, replay and decode the FPM wire protocol.
//!
//! Built for the SONiC port: before zebra-rs can emit FPM, we need to
//! know exactly what SONiC's FRR emits. SONiC does not run upstream
//! FRR's `dplane_fpm_nl` — it ships a fork, `dplane_fpm_sonic`, that
//! adds private netlink message types for SRv6 local SIDs, PIC contexts,
//! SRv6 VPN routes and EVPN multihoming. The only trustworthy
//! specification for that dialect is the bytes themselves.
//!
//! Typical use:
//!
//! ```text
//! # 1. Capture what stock SONiC FRR emits (fpmsyncd not running).
//! fpm-tap record --out golden/v4-ecmp.fpm
//!
//! # 2. Same, but keep the real system working and catch the
//! #    RTM_F_OFFLOAD replies too.
//! fpm-tap record --listen 0.0.0.0:2620 --forward 127.0.0.1:2621 \
//!                --out golden/offload.fpm
//!
//! # 3. Look at what was captured.
//! fpm-tap decode golden/v4-ecmp.fpm
//!
//! # 4. Push a trace into a live fpmsyncd and diff the resulting APPL_DB.
//! fpm-tap replay golden/v4-ecmp.fpm --target 127.0.0.1:2620
//! ```
//!
//! The capture format keeps every byte verbatim, so a trace recorded
//! today stays a valid oracle after a SONiC FRR bump — re-record and
//! diff to see precisely what the dialect change was.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

mod capture;
mod decode;
mod frame;
#[cfg(test)]
mod golden;
mod record;
mod replay;

use frame::FPM_DEFAULT_PORT;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Record, replay and decode the FPM wire protocol (SONiC fpmsyncd dialect)"
)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Listen on the FPM port in place of fpmsyncd and record what zebra sends.
    Record {
        /// Address to listen on. fpmsyncd is the server side of FPM, so
        /// this is where zebra connects.
        #[arg(long, default_value_t = default_listen())]
        listen: SocketAddr,

        /// Forward to a real fpmsyncd and record both directions.
        /// Without this the tap terminates the connection, so no
        /// offload replies will ever be seen.
        #[arg(long)]
        forward: Option<SocketAddr>,

        /// Capture file to write.
        #[arg(long, short)]
        out: PathBuf,

        /// Don't print a summary line per message.
        #[arg(long, short)]
        quiet: bool,

        /// Flush after every message, so a capture survives Ctrl-C.
        #[arg(long, default_value_t = true)]
        sync: bool,

        /// Exit after the first connection closes instead of waiting
        /// for zebra to reconnect.
        #[arg(long)]
        once: bool,
    },

    /// Replay a capture into a live fpmsyncd.
    Replay {
        /// Capture file to replay.
        input: PathBuf,

        /// The fpmsyncd to send to.
        #[arg(long, default_value_t = default_listen())]
        target: SocketAddr,

        /// Milliseconds to wait between messages.
        #[arg(long, default_value_t = 0)]
        pace_ms: u64,

        /// Reproduce the capture's original timing instead of --pace-ms.
        #[arg(long)]
        realtime: bool,

        /// Milliseconds to keep reading replies after the last message.
        #[arg(long, default_value_t = 500)]
        linger_ms: u64,

        #[arg(long, short)]
        quiet: bool,
    },

    /// Pretty-print a capture.
    Decode {
        /// Capture file to read.
        input: PathBuf,

        /// Print full attribute detail, not just the summary line.
        #[arg(long, short)]
        verbose: bool,

        /// Only show messages of this netlink type (name or number),
        /// e.g. `RTM_NEWROUTE` or `24`.
        #[arg(long)]
        r#type: Option<String>,

        /// Only show this direction: `to-fpm` or `to-zebra`.
        #[arg(long)]
        dir: Option<String>,
    },

    /// One-line inventory of a capture: message counts by type and direction.
    Stats {
        /// Capture file to read.
        input: PathBuf,
    },
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], FPM_DEFAULT_PORT))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Cmd::Record {
            listen,
            forward,
            out,
            quiet,
            sync,
            once,
        } => {
            let opts = record::Opts {
                listen,
                forward,
                out,
                quiet,
                sync,
                once,
            };
            // Ctrl-C is the normal way a capture session ends, and the
            // writer flushes per message when --sync is on, so simply
            // returning is enough to leave a complete file behind.
            tokio::select! {
                r = record::run(opts) => r,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\nfpm-tap: interrupted, capture flushed");
                    Ok(())
                }
            }
        }
        Cmd::Replay {
            input,
            target,
            pace_ms,
            realtime,
            linger_ms,
            quiet,
        } => {
            replay::run(replay::Opts {
                input,
                target,
                pace_ms,
                realtime,
                linger_ms,
                quiet,
            })
            .await
        }
        Cmd::Decode {
            input,
            verbose,
            r#type,
            dir,
        } => cmd_decode(&input, verbose, r#type.as_deref(), dir.as_deref()),
        Cmd::Stats { input } => cmd_stats(&input),
    }
}

fn cmd_decode(
    input: &Path,
    verbose: bool,
    type_filter: Option<&str>,
    dir_filter: Option<&str>,
) -> Result<()> {
    let records = capture::read(input)?;
    let want_dir = match dir_filter {
        None => None,
        Some("to-fpm") => Some(capture::Dir::ToFpm),
        Some("to-zebra") => Some(capture::Dir::ToZebra),
        Some(other) => anyhow::bail!("--dir must be `to-fpm` or `to-zebra`, got `{other}`"),
    };

    for (i, rec) in records.iter().enumerate() {
        if want_dir.is_some_and(|d| d != rec.dir) {
            continue;
        }
        let d = decode::decode(&rec.bytes);
        if let Some(want) = type_filter {
            let numeric = want.parse::<u16>().ok();
            let matches = match numeric {
                Some(n) => n == d.nl_type,
                None => d.summary.starts_with(want),
            };
            if !matches {
                continue;
            }
        }
        println!(
            "[{i:>5}] [{:>10.6}] {} {}",
            rec.usec as f64 / 1_000_000.0,
            rec.dir.arrow(),
            d.summary
        );
        if verbose {
            for line in d.detail.lines() {
                println!("        {line}");
            }
            println!();
        }
    }
    Ok(())
}

fn cmd_stats(input: &Path) -> Result<()> {
    let records = capture::read(input)?;
    // BTreeMap keeps the report deterministic, which matters when the
    // output is pasted into a bug report or diffed between two runs.
    let mut by_type: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    let mut bytes = 0usize;

    for rec in &records {
        bytes += rec.bytes.len();
        let d = decode::decode(&rec.bytes);
        // First token of the summary is the message-type name.
        let name = d
            .summary
            .split_whitespace()
            .next()
            .unwrap_or("?")
            .to_string();
        let e = by_type.entry(name).or_default();
        match rec.dir {
            capture::Dir::ToFpm => e.0 += 1,
            capture::Dir::ToZebra => e.1 += 1,
        }
    }

    let span = records.last().map(|r| r.usec).unwrap_or(0) as f64 / 1_000_000.0;
    println!("{} messages, {bytes} bytes, {span:.3}s span", records.len());
    println!("{:<34} {:>8} {:>8}", "type", "to-fpm", "to-zebra");
    for (name, (to_fpm, to_zebra)) in by_type {
        println!("{name:<34} {to_fpm:>8} {to_zebra:>8}");
    }
    Ok(())
}
