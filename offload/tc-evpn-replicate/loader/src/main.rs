//! Userspace loader for the EVPN BUM replication TC/clsact dataplane
//! (RFC 9524 SR replication segment) — skeleton.
//!
//! Loads the eBPF object (embedded at build time) and attaches the
//! `tc_evpn_replicate` classifier to an interface's `clsact` qdisc. The
//! root/bud `End.Replicate` and leaf `End.DT2M` paths — and the replication
//! map the BGP control plane (`ReplSeg`) fills — land in follow-up slices.
//! Runs until Ctrl-C / SIGTERM.

use anyhow::Context as _;
use aya::programs::{SchedClassifier, TcAttachType, tc};
use clap::Parser;
use log::{debug, info};
use tokio::signal;

#[derive(Debug, Parser)]
#[command(about = "EVPN BUM replication (RFC 9524 SR P2MP) TC/clsact dataplane")]
struct Opt {
    /// Interface to attach the replicator to (the SR underlay-facing NIC).
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    /// clsact direction: `ingress` (bud/leaf decap) or `egress` (root encap).
    #[clap(short, long, default_value = "ingress")]
    direction: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opt { iface, direction } = Opt::parse();
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
    // the eBPF crate's `[[bin]]` name, `tc-evpn-replicate`).
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tc-evpn-replicate"
    )))?;

    // clsact hosts both the ingress and egress BPF classifiers. Adding it is
    // idempotent for our purposes: tolerate "already exists".
    if let Err(e) = tc::qdisc_add_clsact(&iface) {
        debug!("qdisc_add_clsact({iface}): {e} (already present?)");
    }

    let attach = match direction.as_str() {
        "egress" => TcAttachType::Egress,
        _ => TcAttachType::Ingress,
    };

    let program: &mut SchedClassifier = ebpf
        .program_mut("tc_evpn_replicate")
        .context("classifier 'tc_evpn_replicate' not found in object")?
        .try_into()?;
    program.load()?;
    program.attach(&iface, attach)?;

    info!("tc_evpn_replicate attached to {iface} ({direction}); waiting for Ctrl-C");
    signal::ctrl_c().await?;
    info!("Exiting");
    Ok(())
}
