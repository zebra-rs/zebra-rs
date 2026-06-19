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
use log::{debug, info, warn};
use tokio::io::AsyncBufReadExt as _;
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

    info!("tc_evpn_replicate attached to {iface} ({direction}); reading commands on stdin");

    // Replication segments are fed by the zebra-rs supervisor over a stdin
    // line protocol (one command per line):
    //   repl-add <vni> <tree-id> <srv6:0|1> <root-ip> <leaf-ip>...
    //   repl-del <vni>
    // Today each command is parsed and logged; populating the BPF replication
    // map and the End.Replicate / End.DT2M forwarding are follow-up slices.
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(l)) => handle_command(&l),
                // EOF (supervisor closed our stdin) or read error: exit so the
                // TC program detaches cleanly.
                _ => break,
            },
            _ = signal::ctrl_c() => break,
        }
    }
    info!("Exiting");
    Ok(())
}

/// Handle one control line from the supervisor. Unknown / malformed lines are
/// warned and ignored so a protocol mismatch never kills the dataplane.
fn handle_command(line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let mut it = line.split_whitespace();
    match it.next() {
        Some("repl-add") => {
            let vni = it.next();
            let tree_id = it.next();
            let srv6 = it.next();
            let root = it.next();
            let leaves: Vec<&str> = it.collect();
            match (vni, tree_id, srv6, root) {
                (Some(vni), Some(tree_id), Some(srv6), Some(root)) if !leaves.is_empty() => {
                    info!(
                        "repl-add vni={vni} tree={tree_id} srv6={srv6} root={root} \
                         leaves={leaves:?} (BPF map population pending)"
                    );
                }
                _ => warn!("malformed repl-add: {line:?}"),
            }
        }
        Some("repl-del") => match it.next() {
            Some(vni) => info!("repl-del vni={vni}"),
            None => warn!("malformed repl-del: {line:?}"),
        },
        Some(other) => warn!("unknown command: {other:?}"),
        None => {}
    }
}
