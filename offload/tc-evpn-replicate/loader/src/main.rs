//! Userspace loader for the EVPN BUM replication TC/clsact dataplane
//! (RFC 9524 SR replication segment).
//!
//! Loads the eBPF object (embedded at build time), attaches the
//! `tc_evpn_replicate` classifier to an interface's `clsact` qdisc, and
//! populates the `REPL_SEG` BPF map from a stdin line protocol fed by the
//! zebra-rs supervisor. The classifier reading that map to clone + rewrite
//! (`End.Replicate`) and decap (`End.DT2M`) is a follow-up slice.
//! Runs until Ctrl-C / SIGTERM.

use std::net::IpAddr;

use anyhow::Context as _;
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use clap::Parser;
use log::{debug, info, warn};
use tokio::io::AsyncBufReadExt as _;
use tokio::signal;

/// Must match `tc-evpn-replicate-ebpf`'s `MAX_LEAVES`.
const MAX_LEAVES: usize = 32;
const REPL_FLAG_SRV6: u32 = 1 << 0;
const REPL_FLAG_ROOT_V4: u32 = 1 << 1;

/// Userspace mirror of the eBPF `ReplSeg` map value — identical `#[repr(C)]`
/// layout (4-byte fields first, then the padding-free byte arrays) so it is a
/// valid `aya::Pod`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ReplSeg {
    tree_id: u32,
    n_leaves: u32,
    flags: u32,
    root: [u8; 16],
    leaves: [[u8; 16]; MAX_LEAVES],
    leaf_v4: [u8; MAX_LEAVES],
}

// SAFETY: `ReplSeg` is `#[repr(C)]`, contains only integer/byte-array fields
// (valid for any bit pattern) and has no padding (the three `u32`s lead, then
// 1-aligned arrays totalling a multiple of 4), so every byte is initialized.
unsafe impl aya::Pod for ReplSeg {}

type ReplMap = AyaHashMap<MapData, u32, ReplSeg>;

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

    // Userspace handle to the per-VNI replication map the classifier reads.
    let mut repl: ReplMap = AyaHashMap::try_from(
        ebpf.take_map("REPL_SEG")
            .context("map 'REPL_SEG' not found in object")?,
    )?;

    info!("tc_evpn_replicate attached to {iface} ({direction}); reading commands on stdin");

    // Replication segments are fed by the zebra-rs supervisor over a stdin
    // line protocol (one command per line):
    //   repl-add <vni> <tree-id> <srv6:0|1> <root-ip> <leaf-ip>...
    //   repl-del <vni>
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(l)) => handle_command(&l, &mut repl),
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

/// Encode an IP into the map's 16-byte slot: IPv6 verbatim, or IPv4 in the
/// first four bytes. Returns `(bytes, is_v4)`.
fn encode_addr(ip: IpAddr) -> ([u8; 16], bool) {
    match ip {
        IpAddr::V4(v4) => {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&v4.octets());
            (b, true)
        }
        IpAddr::V6(v6) => (v6.octets(), false),
    }
}

/// Handle one control line from the supervisor, programming the `REPL_SEG`
/// map. Unknown / malformed lines are warned and ignored so a protocol
/// mismatch never kills the dataplane.
fn handle_command(line: &str, repl: &mut ReplMap) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let mut it = line.split_whitespace();
    match it.next() {
        Some("repl-add") => match parse_add(&mut it) {
            Some((vni, seg)) => {
                if let Err(e) = repl.insert(vni, seg, 0) {
                    warn!("REPL_SEG insert vni={vni} failed: {e}");
                } else {
                    info!("repl-add vni={vni} ({} leaf PE(s))", seg.n_leaves);
                }
            }
            None => warn!("malformed repl-add: {line:?}"),
        },
        Some("repl-del") => match it.next().and_then(|v| v.parse::<u32>().ok()) {
            Some(vni) => {
                // `remove` errors if the key was never present — fine on a
                // duplicate/late withdraw, so only warn on other failures.
                if let Err(e) = repl.remove(&vni) {
                    debug!("REPL_SEG remove vni={vni}: {e}");
                }
                info!("repl-del vni={vni}");
            }
            None => warn!("malformed repl-del: {line:?}"),
        },
        Some(other) => warn!("unknown command: {other:?}"),
        None => {}
    }
}

/// Parse a `repl-add <vni> <tree-id> <srv6:0|1> <root-ip> <leaf-ip>...` body
/// (the verb already consumed) into the map key + value.
fn parse_add<'a>(it: &mut impl Iterator<Item = &'a str>) -> Option<(u32, ReplSeg)> {
    let vni: u32 = it.next()?.parse().ok()?;
    let tree_id: u32 = it.next()?.parse().ok()?;
    let srv6 = it.next()? == "1";
    let root: IpAddr = it.next()?.parse().ok()?;

    let mut seg = ReplSeg {
        tree_id,
        n_leaves: 0,
        flags: 0,
        root: [0; 16],
        leaves: [[0; 16]; MAX_LEAVES],
        leaf_v4: [0; MAX_LEAVES],
    };
    let (root_bytes, root_v4) = encode_addr(root);
    seg.root = root_bytes;
    if srv6 {
        seg.flags |= REPL_FLAG_SRV6;
    }
    if root_v4 {
        seg.flags |= REPL_FLAG_ROOT_V4;
    }

    let mut n = 0usize;
    let mut overflow = false;
    for tok in it {
        let Ok(leaf) = tok.parse::<IpAddr>() else {
            return None; // a malformed leaf invalidates the whole command
        };
        if n >= MAX_LEAVES {
            overflow = true;
            continue;
        }
        let (b, v4) = encode_addr(leaf);
        seg.leaves[n] = b;
        seg.leaf_v4[n] = u8::from(v4);
        n += 1;
    }
    if n == 0 {
        return None; // a replication segment with no leaves is meaningless
    }
    if overflow {
        warn!("repl-add vni={vni}: more than {MAX_LEAVES} leaves, truncated");
    }
    seg.n_leaves = n as u32;
    Some((vni, seg))
}
