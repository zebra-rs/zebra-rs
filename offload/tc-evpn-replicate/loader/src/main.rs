//! Userspace loader for the EVPN BUM replication TC/clsact dataplane
//! (RFC 9524 SR replication segment).
//!
//! Loads the eBPF object (embedded at build time), attaches the
//! `tc_evpn_replicate` classifier to an interface's `clsact` qdisc, and
//! populates the BPF maps from a stdin line protocol fed by the zebra-rs
//! supervisor. The classifier reads those maps to clone + rewrite each copy's
//! outer IPv6 Destination Address (`End.Replicate`) and to decap + bridge-flood
//! a leaf's `End.DT2M` SID. The maps:
//!   * `REPL_SEG`       — per-VNI replication segment (tree + leaf SIDs);
//!   * `REPL_LOCAL_SID` — local replication SID -> VNI, so the datapath can
//!     demux an inbound packet to its segment by outer DA (derived from each
//!     segment's root SID here);
//!   * `DT2M_SID`       — local `End.DT2M` SID -> VNI for the leaf role;
//!   * `CONFIG`         — index 0 = egress ifindex the replicated copies leave
//!     on (`--redirect-iface`); index 1 = bridge ifindex a leaf floods decapped
//!     frames into (`--bridge-iface`);
//!   * `ENCAP_CFG`      — root `H.Encaps` config (`--encap` mode): VNI, underlay
//!     ifindex, root SID, outer MAC header.
//! Runs until Ctrl-C / SIGTERM.

use std::collections::HashMap as StdHashMap;
use std::ffi::CString;
use std::net::IpAddr;

use anyhow::Context as _;
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use clap::Parser;
use log::{debug, info, warn};
use tokio::io::AsyncBufReadExt as _;
use tokio::signal;

/// Must match `tc-evpn-replicate-ebpf`'s `MAX_LEAVES`.
const MAX_LEAVES: usize = 32;
const ETH_HLEN: usize = 14;
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

/// Userspace mirror of the eBPF `EncapCfg` map value (root `H.Encaps` role).
/// Same padding-free `#[repr(C)]` layout (`u32`s first, then byte arrays).
#[repr(C)]
#[derive(Clone, Copy)]
struct EncapCfg {
    vni: u32,
    underlay_ifindex: u32,
    root_sid: [u8; 16],
    link_eth: [u8; ETH_HLEN],
    _pad: [u8; 2],
}

// SAFETY: `#[repr(C)]`, integer/byte-array fields only, no padding (two `u32`s
// then 1-aligned arrays totalling a multiple of 4) — every byte is initialized.
unsafe impl aya::Pod for EncapCfg {}

type ReplMap = AyaHashMap<MapData, u32, ReplSeg>;
type SidIndex = AyaHashMap<MapData, [u8; 16], u32>;
type EncapMap = AyaArray<MapData, EncapCfg>;

/// The maps the stdin line protocol programs, threaded together so a `repl-add`
/// keeps the per-VNI segment ([`ReplMap`]) and the SID demux index
/// ([`SidIndex`]) in lockstep, and `leaf-add`/`leaf-del` maintain the
/// `End.DT2M` SID index plus its reverse map (for eviction by VNI).
struct Maps {
    repl: ReplMap,
    sid_index: SidIndex,
    dt2m: SidIndex,
    /// VNI -> its `End.DT2M` SID, so `leaf-del <vni>` can evict the SID-keyed
    /// `dt2m` map (which has no VNI to look the key up by).
    leaf_sids: StdHashMap<u32, [u8; 16]>,
    /// Single-entry root `H.Encaps` config (`encap-cfg`).
    encap: EncapMap,
}

#[derive(Debug, Parser)]
#[command(about = "EVPN BUM replication (RFC 9524 SR P2MP) TC/clsact dataplane")]
struct Opt {
    /// Interface to attach the replicator to (the SR underlay-facing NIC).
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    /// clsact direction: `ingress` (bud/leaf decap) or `egress` (root encap).
    #[clap(short, long, default_value = "ingress")]
    direction: String,
    /// Interface the replicated copies are transmitted out of. Defaults to
    /// `--iface` (the all-on-one-underlay case, where copies leave the same NIC
    /// they arrived on, each toward a different leaf SID).
    #[clap(short, long)]
    redirect_iface: Option<String>,
    /// Bridge interface a leaf floods decapped `End.DT2M` frames into. Unset
    /// disables the leaf role (the datapath passes such frames to the stack).
    #[clap(short, long)]
    bridge_iface: Option<String>,
    /// Root `H.Encaps` mode: attach the `tc_evpn_encap` classifier at `--iface`
    /// *egress* (the overlay bridge port) instead of the ingress replicator, so
    /// every bare BUM frame is encapsulated + fanned out per `encap-cfg`.
    #[clap(short, long)]
    encap: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opt {
        iface,
        direction,
        redirect_iface,
        bridge_iface,
        encap,
    } = Opt::parse();
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

    // The device replicated copies are clone_redirect'd out of. Resolve to an
    // ifindex now (0 = lookup failure) so the datapath has it before any frame.
    let redirect = redirect_iface.unwrap_or_else(|| iface.clone());
    let redirect_ifindex = if_nametoindex(&redirect)
        .with_context(|| format!("redirect interface {redirect:?} not found"))?;

    // The bridge a leaf floods decapped End.DT2M frames into. Optional: 0
    // leaves the leaf role disabled (no bridge to flood into).
    let bridge_ifindex = match bridge_iface.as_deref() {
        Some(name) => {
            if_nametoindex(name).with_context(|| format!("bridge interface {name:?} not found"))?
        }
        None => 0,
    };

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

    // Encap mode attaches the root H.Encaps classifier at egress; otherwise the
    // ingress replicate/decap classifier at the requested direction.
    let (prog_name, attach) = if encap {
        ("tc_evpn_encap", TcAttachType::Egress)
    } else {
        let dir = match direction.as_str() {
            "egress" => TcAttachType::Egress,
            _ => TcAttachType::Ingress,
        };
        ("tc_evpn_replicate", dir)
    };

    let program: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("classifier {prog_name:?} not found in object"))?
        .try_into()?;
    program.load()?;
    program.attach(&iface, attach)?;

    // Egress devices: CONFIG[0] = replicate copies, CONFIG[1] = leaf bridge.
    let mut config: AyaArray<MapData, u32> = AyaArray::try_from(
        ebpf.take_map("CONFIG")
            .context("map 'CONFIG' not found in object")?,
    )?;
    config
        .set(0, redirect_ifindex, 0)
        .context("CONFIG[0] = redirect ifindex")?;
    config
        .set(1, bridge_ifindex, 0)
        .context("CONFIG[1] = bridge ifindex")?;

    // Userspace handles to the maps the classifier reads.
    let mut maps = Maps {
        repl: AyaHashMap::try_from(
            ebpf.take_map("REPL_SEG")
                .context("map 'REPL_SEG' not found in object")?,
        )?,
        sid_index: AyaHashMap::try_from(
            ebpf.take_map("REPL_LOCAL_SID")
                .context("map 'REPL_LOCAL_SID' not found in object")?,
        )?,
        dt2m: AyaHashMap::try_from(
            ebpf.take_map("DT2M_SID")
                .context("map 'DT2M_SID' not found in object")?,
        )?,
        leaf_sids: StdHashMap::new(),
        encap: AyaArray::try_from(
            ebpf.take_map("ENCAP_CFG")
                .context("map 'ENCAP_CFG' not found in object")?,
        )?,
    };

    if encap {
        info!("{prog_name} attached to {iface} (egress); awaiting encap-cfg + repl-add on stdin");
    } else {
        let bridge_desc = match bridge_iface.as_deref() {
            Some(name) => format!("{name} (ifindex {bridge_ifindex})"),
            None => "disabled".to_string(),
        };
        info!(
            "{prog_name} attached to {iface} ({direction}); copies -> {redirect} \
             (ifindex {redirect_ifindex}); leaf flood -> {bridge_desc}; reading commands on stdin"
        );
    }

    // The control plane feeds map updates over a stdin line protocol (one
    // command per line):
    //   repl-add <vni> <tree-id> <srv6:0|1> <root-ip> <leaf-ip>...
    //   repl-del <vni>
    //   leaf-add <vni> <dt2m-sid>        (this node's End.DT2M SID for the VNI)
    //   leaf-del <vni>
    //   encap-cfg <vni> <underlay-ifname> <root-sid> <eth-dst-mac> <eth-src-mac>
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(l)) => handle_command(&l, &mut maps),
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

/// Resolve an interface name to its ifindex via `if_nametoindex(3)`. Returns an
/// error (rather than 0) if the interface does not exist.
fn if_nametoindex(name: &str) -> anyhow::Result<u32> {
    let cname = CString::new(name).context("interface name has an interior NUL")?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("if_nametoindex({name:?}) failed");
    }
    Ok(idx)
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

/// Handle one control line from the supervisor, programming the maps. Unknown /
/// malformed lines are warned and ignored so a protocol mismatch never kills the
/// dataplane.
fn handle_command(line: &str, maps: &mut Maps) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let mut it = line.split_whitespace();
    match it.next() {
        Some("repl-add") => match parse_add(&mut it) {
            Some((vni, seg)) => {
                if let Err(e) = maps.repl.insert(vni, seg, 0) {
                    warn!("REPL_SEG insert vni={vni} failed: {e}");
                    return;
                }
                // Index the segment's root SID -> VNI so the datapath can match
                // an inbound packet's outer DA. The root is our local
                // replication SID for the tree at this node.
                if let Err(e) = maps.sid_index.insert(seg.root, vni, 0) {
                    warn!("REPL_LOCAL_SID insert vni={vni} failed: {e}");
                }
                info!("repl-add vni={vni} ({} leaf PE(s))", seg.n_leaves);
            }
            None => warn!("malformed repl-add: {line:?}"),
        },
        Some("repl-del") => match it.next().and_then(|v| v.parse::<u32>().ok()) {
            Some(vni) => {
                // Evict the SID index first, while we can still read the
                // segment's root SID (the index's key).
                if let Ok(seg) = maps.repl.get(&vni, 0) {
                    let _ = maps.sid_index.remove(&seg.root);
                }
                // `remove` errors if the key was never present — fine on a
                // duplicate/late withdraw, so only debug-log other failures.
                if let Err(e) = maps.repl.remove(&vni) {
                    debug!("REPL_SEG remove vni={vni}: {e}");
                }
                info!("repl-del vni={vni}");
            }
            None => warn!("malformed repl-del: {line:?}"),
        },
        Some("leaf-add") => match parse_leaf(&mut it) {
            Some((vni, sid)) => {
                if let Err(e) = maps.dt2m.insert(sid, vni, 0) {
                    warn!("DT2M_SID insert vni={vni} failed: {e}");
                    return;
                }
                maps.leaf_sids.insert(vni, sid);
                info!("leaf-add vni={vni}");
            }
            None => warn!("malformed leaf-add: {line:?}"),
        },
        Some("leaf-del") => match it.next().and_then(|v| v.parse::<u32>().ok()) {
            Some(vni) => {
                if let Some(sid) = maps.leaf_sids.remove(&vni) {
                    let _ = maps.dt2m.remove(&sid);
                }
                info!("leaf-del vni={vni}");
            }
            None => warn!("malformed leaf-del: {line:?}"),
        },
        Some("encap-cfg") => match parse_encap(&mut it) {
            Some(cfg) => {
                if let Err(e) = maps.encap.set(0, cfg, 0) {
                    warn!("ENCAP_CFG set failed: {e}");
                } else {
                    info!(
                        "encap-cfg vni={} underlay-ifindex={}",
                        cfg.vni, cfg.underlay_ifindex
                    );
                }
            }
            None => warn!("malformed encap-cfg: {line:?}"),
        },
        Some(other) => warn!("unknown command: {other:?}"),
        None => {}
    }
}

/// Parse a MAC address `aa:bb:cc:dd:ee:ff` into 6 bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0usize;
    for part in s.split(':') {
        if n >= 6 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

/// Parse an `encap-cfg <vni> <underlay-ifname> <root-sid> <eth-dst> <eth-src>`
/// body (the verb already consumed) into the root `H.Encaps` config: the root
/// SID must be IPv6; the underlay must resolve to an ifindex.
fn parse_encap<'a>(it: &mut impl Iterator<Item = &'a str>) -> Option<EncapCfg> {
    let vni: u32 = it.next()?.parse().ok()?;
    let underlay_ifindex = if_nametoindex(it.next()?).ok()?;
    let root_sid = match it.next()?.parse::<IpAddr>().ok()? {
        IpAddr::V6(a) => a.octets(),
        IpAddr::V4(_) => return None,
    };
    let dst = parse_mac(it.next()?)?;
    let src = parse_mac(it.next()?)?;
    let mut link_eth = [0u8; ETH_HLEN];
    link_eth[..6].copy_from_slice(&dst);
    link_eth[6..12].copy_from_slice(&src);
    link_eth[12] = 0x86; // EtherType IPv6 (0x86DD)
    link_eth[13] = 0xdd;
    Some(EncapCfg {
        vni,
        underlay_ifindex,
        root_sid,
        link_eth,
        _pad: [0; 2],
    })
}

/// Parse a `leaf-add <vni> <dt2m-sid>` body (the verb already consumed) into the
/// VNI + the 16-byte SID key. The SID must be an IPv6 address (an SRv6
/// `End.DT2M` SID); an IPv4 value is rejected.
fn parse_leaf<'a>(it: &mut impl Iterator<Item = &'a str>) -> Option<(u32, [u8; 16])> {
    let vni: u32 = it.next()?.parse().ok()?;
    match it.next()?.parse::<IpAddr>().ok()? {
        IpAddr::V6(sid) => Some((vni, sid.octets())),
        IpAddr::V4(_) => None,
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
