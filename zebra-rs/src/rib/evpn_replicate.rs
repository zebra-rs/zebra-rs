//! EVPN SR P2MP replication dataplane supervisor (RFC 9524).
//!
//! The BGP control plane computes a replication segment per VNI and sends
//! `rib::Message::ReplSegAdd` / `ReplSegDel`. The stock Linux kernel cannot
//! forward an SR replication tree (no `End.Replicate`, no MPLS P2MP, no
//! `End.DT2M`), so forwarding is offloaded to the `tc-evpn-replicate` eBPF
//! TC/clsact program (`offload/tc-evpn-replicate/`), run as a managed child
//! process — this module is its supervisor, mirroring the BFD echo reflector
//! (`bfd::reflector::EchoReflectors`).
//!
//! A single child carries every VNI's replication map; it is spawned on the
//! first replication segment and SIGTERM'd (clean TC detach) when the last is
//! withdrawn. Segments are pushed over a stdin line protocol:
//!
//! ```text
//!   repl-add <vni> <tree-id> <srv6:0|1> <root-ip> <leaf-ip>...
//!   repl-del <vni>
//! ```
//!
//! The underlay interface the replicator attaches to comes from
//! `$ZEBRA_TC_EVPN_REPLICATE_IFACE`; with it unset the dataplane is disabled
//! (the control plane still signals, nothing forwards) — honest on a host
//! without the offload installed.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::context::Task;

/// Env override for the replicator binary path (mirrors the BFD reflector's
/// `ZEBRA_XDP_BFD_ECHO_BIN`).
const BIN_ENV: &str = "ZEBRA_TC_EVPN_REPLICATE_BIN";
/// Underlay interface the TC replicator attaches to. Unset ⇒ dataplane off.
const IFACE_ENV: &str = "ZEBRA_TC_EVPN_REPLICATE_IFACE";

/// Interfaces + next hop the SR P2MP BUM-replication eBPF children attach to,
/// from BGP's `sr-p2mp-dataplane` config (`rib::Message::ReplDataplaneCfg`).
/// Consumed when the children are (re)spawned.
#[derive(Debug, Clone, Default)]
pub struct DataplaneTopology {
    /// Overlay bridge port the root `H.Encaps` classifier attaches to (egress).
    pub overlay: Option<String>,
    /// SR underlay NIC: replicated copies leave here; the leaf `End.DT2M`
    /// decap classifier attaches to its ingress.
    pub underlay: Option<String>,
    /// Bridge port a leaf floods decapped BUM frames into.
    pub bridge: Option<String>,
    /// Outer Ethernet next-hop MAC for the encapsulated copies.
    pub next_hop_mac: Option<String>,
}

impl DataplaneTopology {
    /// True when every interface + next hop the eBPF children need is set, so
    /// the supervisor can spawn the full send+receive dataplane.
    pub fn is_complete(&self) -> bool {
        self.overlay.is_some()
            && self.underlay.is_some()
            && self.bridge.is_some()
            && self.next_hop_mac.is_some()
    }
}

/// Supervises the single `tc-evpn-replicate` child that forwards EVPN BUM over
/// SR P2MP replication trees. Lifecycle is reference-counted by the set of
/// VNIs that currently have a replication segment.
pub struct ReplicationHelper {
    /// VNIs with an active replication segment — spawn on the first, stop on
    /// the last.
    vnis: BTreeSet<u32>,
    /// The child process, if it spawned. `None` when the dataplane is disabled
    /// (no interface) or the spawn failed.
    child: Option<Child>,
    /// Queue for stdin command lines to the child's IPC task.
    cmd_tx: Option<UnboundedSender<String>>,
    /// IPC task: writes commands to the child's stdin. Aborts when dropped.
    _io: Option<Task<()>>,
    bin: PathBuf,
    /// Underlay interface to attach to; `None` ($ZEBRA_..._IFACE unset)
    /// disables the dataplane.
    iface: Option<String>,
    /// Dataplane topology from BGP `sr-p2mp-dataplane` config. Consumed when
    /// the eBPF children are (re)spawned (a follow-up); stored here so the
    /// supervisor has it before the first replication segment arrives.
    topology: DataplaneTopology,
}

impl Default for ReplicationHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicationHelper {
    pub fn new() -> Self {
        Self {
            vnis: BTreeSet::new(),
            child: None,
            cmd_tx: None,
            _io: None,
            bin: resolve_bin(),
            iface: std::env::var(IFACE_ENV).ok().filter(|s| !s.is_empty()),
            topology: DataplaneTopology::default(),
        }
    }

    /// Update the SR P2MP dataplane topology from BGP `sr-p2mp-dataplane`
    /// config. Stored for use when the eBPF children are (re)spawned; logged so
    /// operators can see what the dataplane will attach to.
    pub fn set_topology(
        &mut self,
        overlay: Option<String>,
        underlay: Option<String>,
        bridge: Option<String>,
        next_hop_mac: Option<String>,
    ) {
        self.topology = DataplaneTopology {
            overlay,
            underlay,
            bridge,
            next_hop_mac,
        };
        tracing::info!(
            "evpn replication: dataplane topology updated: {:?} (complete={})",
            self.topology,
            self.topology.is_complete()
        );
    }

    /// Install or refresh the SR P2MP replication segment for `vni`, spawning
    /// the child on the first segment.
    pub fn add(&mut self, vni: u32, tree_id: u32, root: IpAddr, srv6: bool, leaves: &[IpAddr]) {
        self.ensure_child();
        self.vnis.insert(vni);
        let mut line = format!("repl-add {vni} {tree_id} {} {root}", u8::from(srv6));
        for leaf in leaves {
            line.push(' ');
            line.push_str(&leaf.to_string());
        }
        self.send(line);
    }

    /// Withdraw the replication segment for `vni`, stopping the child when the
    /// last segment is gone.
    pub fn del(&mut self, vni: u32) {
        if !self.vnis.remove(&vni) {
            return;
        }
        self.send(format!("repl-del {vni}"));
        if self.vnis.is_empty() {
            self.stop();
        }
    }

    fn send(&self, line: String) {
        if let Some(tx) = &self.cmd_tx {
            let _ = tx.send(line);
        }
    }

    fn ensure_child(&mut self) {
        if self.child.is_some() {
            return;
        }
        let Some(iface) = self.iface.clone() else {
            tracing::debug!("evpn replication: {IFACE_ENV} unset; SR P2MP dataplane disabled");
            return;
        };
        // The replicator encaps + clones at egress (the root); ingress
        // bud/leaf attach is a follow-up once those roles are wired.
        match Command::new(&self.bin)
            .arg("--iface")
            .arg(&iface)
            .arg("--direction")
            .arg("egress")
            .stdin(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(mut child) => {
                tracing::info!(
                    "evpn replication: spawned {} on {iface}",
                    self.bin.display()
                );
                if let Some(stdin) = child.stdin.take() {
                    let (tx, rx) = mpsc::unbounded_channel::<String>();
                    self._io = Some(Task::spawn(child_io(stdin, rx)));
                    self.cmd_tx = Some(tx);
                }
                self.child = Some(child);
            }
            Err(e) => {
                tracing::warn!(
                    "evpn replication: failed to spawn {} on {iface}: {e}",
                    self.bin.display()
                );
            }
        }
    }

    /// SIGTERM the child so the loader detaches its TC program cleanly.
    /// `kill_on_drop(true)` reaps it (SIGKILL) if it ignores us.
    fn stop(&mut self) {
        if let Some(pid) = self.child.as_ref().and_then(Child::id) {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            tracing::info!("evpn replication: stopping replicator (last segment withdrawn)");
        }
        self.child = None;
        self.cmd_tx = None;
        self._io = None;
    }
}

/// Per-child IPC task: drains queued command lines to the child's stdin. Ends
/// when the command sender is dropped (helper stopped) or a write fails (child
/// gone).
async fn child_io(mut stdin: ChildStdin, mut cmd_rx: UnboundedReceiver<String>) {
    while let Some(c) = cmd_rx.recv().await {
        if stdin.write_all(c.as_bytes()).await.is_err()
            || stdin.write_all(b"\n").await.is_err()
            || stdin.flush().await.is_err()
        {
            break;
        }
    }
}

/// Resolve the replicator binary: `$ZEBRA_TC_EVPN_REPLICATE_BIN`, else the dev
/// install (`~/.zebra/bin`), else the packaged location.
fn resolve_bin() -> PathBuf {
    if let Some(p) = std::env::var_os(BIN_ENV) {
        return PathBuf::from(p);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let dev = PathBuf::from(home).join(".zebra/bin/tc-evpn-replicate");
        if dev.exists() {
            return dev;
        }
    }
    PathBuf::from("/usr/sbin/tc-evpn-replicate")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn add_del_tracks_vnis() {
        let mut h = ReplicationHelper::new();
        // Force the dataplane off so the test never spawns a child regardless
        // of the environment — we exercise the segment bookkeeping only.
        h.iface = None;
        h.add(10, 10, ip("10.0.0.1"), false, &[ip("10.0.0.2")]);
        h.add(20, 20, ip("10.0.0.1"), true, &[ip("10.0.0.3")]);
        assert_eq!(h.vnis, BTreeSet::from([10, 20]));
        assert!(h.child.is_none(), "no iface → no child spawned");

        h.del(10);
        assert_eq!(h.vnis, BTreeSet::from([20]));
        h.del(99); // unknown VNI: no-op, no underflow
        assert_eq!(h.vnis, BTreeSet::from([20]));
        h.del(20);
        assert!(h.vnis.is_empty());
    }

    #[test]
    fn bin_env_override_is_honoured() {
        // SAFETY: single-threaded test; set then read immediately.
        unsafe { std::env::set_var(BIN_ENV, "/opt/custom/tc-evpn-replicate") };
        let h = ReplicationHelper::new();
        unsafe { std::env::remove_var(BIN_ENV) };
        assert_eq!(h.bin, PathBuf::from("/opt/custom/tc-evpn-replicate"));
    }
}
