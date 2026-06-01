//! Userspace loader for the XDP BFD Echo reflector.
//!
//! Loads the eBPF object (embedded at build time), attaches the `bfd_echo_reflect`
//! XDP program to the requested interface, and runs until Ctrl-C. Attachment
//! tries native/driver mode first and falls back to generic SKB mode, which is
//! needed on virtual NICs that lack native XDP (e.g. the Parallels/Apple-Silicon
//! lab — see the offload notes §9).

use anyhow::Context as _;
use aya::programs::{Xdp, XdpMode};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::signal;

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

    // Embed the eBPF object built by build.rs and load it. The reflector is
    // a stateless datapath with no eBPF logging, so there is no aya-log setup.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bfd-echo-reflector"
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

    info!("reflecting BFD Echo (udp/3785) on {iface}; Ctrl-C or SIGTERM to exit");
    // Wait for SIGINT (Ctrl-C) or SIGTERM. zebra-rs's reflector supervisor
    // stops children with SIGTERM; handling it lets the XDP program detach
    // cleanly on the way out (the link drops when `ebpf` does) instead of
    // being left attached by an un-caught signal.
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
    info!("exiting; detaching XDP program");
    Ok(())
}
