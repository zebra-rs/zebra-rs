//! Userspace loader + datapath for the per-interface BFD Echo helper.
//!
//! Loads the eBPF object (embedded at build time) and attaches the
//! `bfd_echo_reflect` XDP program — the **responder** (loops a peer's Echo).
//! Attachment tries native/driver mode first and falls back to generic SKB
//! mode, needed on virtual NICs that lack native XDP (e.g. the Parallels lab).
//!
//! It then runs the **originator** datapath ([`sender`]): driven by zebra-rs
//! over a stdin/stdout line protocol, it transmits Echo per session and reports
//! `echo-down` on detection timeout. With no controller (standalone) it simply
//! reflects. Runs until Ctrl-C / SIGTERM.

use std::time::Duration;

use anyhow::Context as _;
use aya::programs::{Xdp, XdpMode};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::io::AsyncBufReadExt as _;
use tokio::signal;

mod sender;

#[derive(Debug, Parser)]
#[command(about = "XDP BFD Echo (udp/3785) reflector")]
struct Opt {
    /// Interface to attach the reflector to.
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    /// XDP attach mode: `auto` (native, fall back to SKB), `native`, or `skb`.
    /// Use `skb` on veth / virtual NICs, where native XDP *attaches* but does
    /// not pass frames to the program.
    #[clap(short, long, default_value = "auto")]
    mode: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opt { iface, mode } = Opt::parse();
    env_logger::init();

    // Bump the memlock rlimit. Needed on older kernels that don't use the
    // memcg-based accounting; see https://lwn.net/Articles/837122/.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Embed the eBPF object built by build.rs and load it (the object's name is
    // the eBPF crate's `[[bin]]` name, `xdp-bfd-echo`). The datapath has no eBPF
    // logging, so there is no aya-log setup.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-bfd-echo"
    )))?;

    let program: &mut Xdp = ebpf
        .program_mut("bfd_echo_reflect")
        .context("XDP program 'bfd_echo_reflect' not found in object")?
        .try_into()?;
    program.load()?;

    match mode.as_str() {
        "skb" => {
            program
                .attach(&iface, XdpMode::Skb)
                .context("failed to attach XDP program in SKB mode")?;
            info!("attached BFD Echo reflector to {iface} (generic/SKB XDP)");
        }
        "native" => {
            program
                .attach(&iface, XdpMode::Driver)
                .context("failed to attach XDP program in native/driver mode")?;
            info!("attached BFD Echo reflector to {iface} (native/driver XDP)");
        }
        // auto: native first (mode 0 = let the kernel pick native; it does NOT
        // auto-fall back to generic), then retry explicitly in SKB mode.
        _ => match program.attach(&iface, XdpMode::default()) {
            Ok(_) => info!("attached BFD Echo reflector to {iface} (native/driver XDP)"),
            Err(e) => {
                warn!("native XDP attach on {iface} failed ({e}); retrying in SKB mode");
                program
                    .attach(&iface, XdpMode::Skb)
                    .context("failed to attach XDP program in SKB mode")?;
                info!("attached BFD Echo reflector to {iface} (generic/SKB XDP)");
            }
        },
    }

    // Take the XDP maps for userspace to drive (the loaded program keeps using
    // the same kernel maps); `ebpf` itself stays in scope so the XDP link
    // persists until exit. `OUR_LOCAL_IPS` teaches the program our source IPs;
    // `ECHO_TIMERS` (Echo returns) and `CONTROL_TIMERS` (control-packet
    // expiration watchdog) hold the per-session bpf_timer detection state we
    // seed and poll.
    let local_ips = aya::maps::HashMap::try_from(
        ebpf.take_map("OUR_LOCAL_IPS")
            .context("OUR_LOCAL_IPS map missing from object")?,
    )?;
    let local_ips_v6 = aya::maps::HashMap::try_from(
        ebpf.take_map("OUR_LOCAL_IPS_V6")
            .context("OUR_LOCAL_IPS_V6 map missing from object")?,
    )?;
    let timers = aya::maps::HashMap::try_from(
        ebpf.take_map("ECHO_TIMERS")
            .context("ECHO_TIMERS map missing from object")?,
    )?;
    let ctrl_timers = aya::maps::HashMap::try_from(
        ebpf.take_map("CONTROL_TIMERS")
            .context("CONTROL_TIMERS map missing from object")?,
    )?;
    let mut engine = sender::EchoEngine::new(&iface, local_ips, local_ips_v6, timers, ctrl_timers)?;

    info!("BFD Echo datapath up on {iface} (reflect + originate); Ctrl-C/SIGTERM to exit");

    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut ticker = tokio::time::interval(Duration::from_millis(10));
    // SIGTERM is how zebra-rs's supervisor stops us; handling it (and Ctrl-C)
    // lets the XDP link drop cleanly when `ebpf` does.
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    // Only consume stdin when it's a pipe/file (zebra-rs's control channel). On a
    // tty — a standalone, often backgrounded run — reading it would raise SIGTTIN
    // and stop us; there we just reflect and wait for a signal.
    let mut stdin_open = unsafe { libc::isatty(0) == 0 };
    let mut stdout = std::io::stdout();
    loop {
        tokio::select! {
            _ = ticker.tick() => engine.tick(&mut stdout),
            res = lines.next_line(), if stdin_open => match res {
                Ok(Some(line)) => engine.handle_command(&line),
                // stdin closed (controller gone) or errored: stop reading it but
                // keep reflecting/originating until SIGTERM. Standalone runs
                // (no controller) just never receive commands.
                Ok(None) | Err(_) => stdin_open = false,
            },
            _ = signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
        }
    }
    info!("exiting; detaching XDP program");
    Ok(())
}
