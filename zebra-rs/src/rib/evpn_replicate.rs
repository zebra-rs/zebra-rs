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
//! Two children carry every VNI's state — an **ingress** child (clsact ingress
//! on the underlay: `End.Replicate` for a root/bud, `End.DT2M` decap for a leaf)
//! and an **encap** child (root `H.Encaps`, clsact egress on the overlay port).
//! Each is spawned lazily on the first segment/leaf SID and SIGTERM'd (clean TC
//! detach) when no role needs it. State is pushed over a stdin line protocol:
//!
//! ```text
//!   repl-add  <vni> <tree-id> <srv6:0|1> <root> <leaf-sid>...  # ingress + encap
//!   repl-del  <vni>
//!   leaf-add  <vni> <local-end-dt2m-sid>                       # ingress (decap)
//!   leaf-del  <vni>
//!   encap-cfg <vni> <underlay> <root> <eth-dst> <eth-src>      # encap (root)
//! ```
//!
//! The attach interfaces + next hop come from BGP's `sr-p2mp-dataplane` config
//! ([`ReplicationHelper::set_topology`]), with `$ZEBRA_TC_EVPN_REPLICATE_IFACE`
//! / `_BRIDGE` as fallbacks for the underlay / leaf-flood bridge. Until the
//! needed interfaces are configured the dataplane is disabled (the control
//! plane still signals, nothing forwards) — honest on a host without the
//! offload installed.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
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
/// Bridge port a leaf floods decapped `End.DT2M` frames into. Unset ⇒ the leaf
/// role programs its SID but the datapath passes such frames to the stack.
const BRIDGE_ENV: &str = "ZEBRA_TC_EVPN_REPLICATE_BRIDGE";

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

/// One managed `tc-evpn-replicate` child process + its stdin IPC task.
struct ReplChild {
    child: Child,
    cmd_tx: UnboundedSender<String>,
    _io: Task<()>,
}

impl ReplChild {
    /// Queue one command line to the child's stdin.
    fn send(&self, line: String) {
        let _ = self.cmd_tx.send(line);
    }

    /// SIGTERM the child so the loader detaches its TC program cleanly.
    /// `kill_on_drop(true)` reaps it (SIGKILL) if it ignores us.
    fn stop(&self) {
        if let Some(pid) = self.child.id() {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
    }
}

/// Supervises the `tc-evpn-replicate` eBPF children that forward EVPN BUM over
/// SR P2MP replication trees: an **ingress** child (clsact ingress on the
/// underlay — `End.Replicate` for a root/bud, `End.DT2M` decap for a leaf) and
/// an **encap** child (root `H.Encaps`, clsact egress on the overlay port).
/// Each is spawned lazily and SIGTERM'd when no role needs it; lifecycle is
/// reference-counted by the replication-segment + leaf-SID VNI sets.
pub struct ReplicationHelper {
    /// VNIs with an active replication segment (`repl-add`) — root/bud role.
    vnis: BTreeSet<u32>,
    /// VNIs with a local `End.DT2M` leaf SID (`leaf-add`) — leaf role. Tracked
    /// separately from `vnis` so the children live while EITHER role is active.
    leaf_vnis: BTreeSet<u32>,
    /// Ingress child: `End.Replicate` (root/bud) + `End.DT2M` (leaf), clsact
    /// ingress on the underlay.
    ingress: Option<ReplChild>,
    /// Encap child: root `H.Encaps`, clsact egress on the overlay port.
    encap: Option<ReplChild>,
    bin: PathBuf,
    /// Underlay interface env fallback ($ZEBRA_..._IFACE) when the YANG topology
    /// has no `underlay-interface`.
    iface: Option<String>,
    /// Leaf flood bridge-port env fallback ($ZEBRA_..._BRIDGE).
    bridge: Option<String>,
    /// Dataplane topology from BGP `sr-p2mp-dataplane` config — the primary
    /// source for the attach interfaces + next hop (the env vars are fallback).
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
            leaf_vnis: BTreeSet::new(),
            ingress: None,
            encap: None,
            bin: resolve_bin(),
            iface: std::env::var(IFACE_ENV).ok().filter(|s| !s.is_empty()),
            bridge: std::env::var(BRIDGE_ENV).ok().filter(|s| !s.is_empty()),
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

    /// Underlay interface: YANG `underlay-interface`, else the env fallback.
    fn underlay(&self) -> Option<String> {
        self.topology
            .underlay
            .clone()
            .or_else(|| self.iface.clone())
    }

    /// Leaf flood bridge port: YANG `bridge-interface`, else the env fallback.
    fn bridge_port(&self) -> Option<String> {
        self.topology.bridge.clone().or_else(|| self.bridge.clone())
    }

    /// Install or refresh the SR P2MP replication segment for `vni`: program the
    /// ingress child's `End.Replicate` fan-out and, when the SRv6 encap topology
    /// is configured, the egress encap child's root `H.Encaps` fan-out.
    pub fn add(&mut self, vni: u32, tree_id: u32, root: IpAddr, srv6: bool, leaves: &[IpAddr]) {
        self.vnis.insert(vni);
        let mut repl = format!("repl-add {vni} {tree_id} {} {root}", u8::from(srv6));
        for leaf in leaves {
            repl.push(' ');
            repl.push_str(&leaf.to_string());
        }
        // Ingress child: a bud replicates packets addressed to its local
        // replication SID (inert at a pure root/leaf, but harmless).
        self.ensure_ingress();
        if let Some(c) = &self.ingress {
            c.send(repl.clone());
        }
        // Encap child (root H.Encaps): wrap a bare BUM frame and fan it out, one
        // copy per leaf End.DT2M SID. SRv6-only, and needs the full encap
        // topology (overlay + underlay + next hop).
        if srv6 {
            self.ensure_encap();
            if let (Some(c), Some(underlay), Some(eth_dst)) = (
                self.encap.as_ref(),
                self.topology.underlay.as_ref(),
                self.topology.next_hop_mac.as_ref(),
            ) {
                // Outer Ethernet source = the underlay NIC's own MAC.
                let eth_src =
                    iface_mac(underlay).unwrap_or_else(|| "00:00:00:00:00:00".to_string());
                c.send(format!(
                    "encap-cfg {vni} {underlay} {root} {eth_dst} {eth_src}"
                ));
                c.send(repl);
            }
        }
    }

    /// Withdraw the replication segment for `vni`, stopping the children when no
    /// role (segment or leaf) needs them any more.
    pub fn del(&mut self, vni: u32) {
        if !self.vnis.remove(&vni) {
            return;
        }
        let line = format!("repl-del {vni}");
        if let Some(c) = &self.ingress {
            c.send(line.clone());
        }
        if let Some(c) = &self.encap {
            c.send(line);
        }
        self.stop_if_idle();
    }

    /// Program this node's local `End.DT2M` leaf SID for `vni`, so a replicated
    /// copy addressed to it is decapsulated and flooded into the bridge.
    pub fn leaf_add(&mut self, vni: u32, sid: Ipv6Addr) {
        self.ensure_ingress();
        self.leaf_vnis.insert(vni);
        if let Some(c) = &self.ingress {
            c.send(format!("leaf-add {vni} {sid}"));
        }
    }

    /// Withdraw this node's `End.DT2M` leaf SID for `vni`.
    pub fn leaf_del(&mut self, vni: u32) {
        if !self.leaf_vnis.remove(&vni) {
            return;
        }
        if let Some(c) = &self.ingress {
            c.send(format!("leaf-del {vni}"));
        }
        self.stop_if_idle();
    }

    /// Stop both children once neither role (replication segment nor leaf SID)
    /// is active, so the loaders detach their TC programs cleanly.
    fn stop_if_idle(&mut self) {
        if self.vnis.is_empty() && self.leaf_vnis.is_empty() {
            self.stop();
        }
    }

    /// Spawn the ingress child (`--direction ingress` on the underlay, with the
    /// leaf flood `--bridge-iface`) if not already running.
    fn ensure_ingress(&mut self) {
        if self.ingress.is_some() {
            return;
        }
        let Some(iface) = self.underlay() else {
            tracing::debug!("evpn replication: no underlay interface; SR P2MP dataplane disabled");
            return;
        };
        let mut args: Vec<String> = vec![
            "--iface".into(),
            iface,
            "--direction".into(),
            "ingress".into(),
        ];
        if let Some(bridge) = self.bridge_port() {
            args.push("--bridge-iface".into());
            args.push(bridge);
        }
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        self.ingress = self.spawn_child("ingress", &argv);
    }

    /// Spawn the encap child (`--encap` on the overlay port) if not already
    /// running. Needs the full encap topology — overlay + underlay + next hop
    /// (no env fallback for overlay / next-hop MAC).
    fn ensure_encap(&mut self) {
        if self.encap.is_some() {
            return;
        }
        // Needs the full encap topology; overlay + next-hop MAC have no env
        // fallback, so the encap child only runs once they are configured.
        let Some(overlay) = self.topology.overlay.as_deref() else {
            return;
        };
        if self.topology.underlay.is_none() || self.topology.next_hop_mac.is_none() {
            return;
        }
        self.encap = self.spawn_child("encap", &["--iface", overlay, "--encap"]);
    }

    /// Spawn one `tc-evpn-replicate` child with `args`, wiring its stdin IPC.
    fn spawn_child(&self, role: &str, args: &[&str]) -> Option<ReplChild> {
        match Command::new(&self.bin)
            .args(args)
            .stdin(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(mut child) => {
                tracing::info!(
                    "evpn replication: spawned {} {role} child ({})",
                    self.bin.display(),
                    args.join(" ")
                );
                let stdin = child.stdin.take()?;
                let (tx, rx) = mpsc::unbounded_channel::<String>();
                let io = Task::spawn(child_io(stdin, rx));
                Some(ReplChild {
                    child,
                    cmd_tx: tx,
                    _io: io,
                })
            }
            Err(e) => {
                tracing::warn!(
                    "evpn replication: failed to spawn {} {role} child: {e}",
                    self.bin.display()
                );
                None
            }
        }
    }

    /// SIGTERM both children (last role withdrawn) so the loaders detach cleanly.
    fn stop(&mut self) {
        if let Some(c) = self.ingress.take() {
            c.stop();
        }
        if let Some(c) = self.encap.take() {
            c.stop();
        }
        tracing::info!("evpn replication: stopped (no active role)");
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

/// Read an interface's MAC address from sysfs (`/sys/class/net/<name>/address`)
/// — the outer Ethernet source of the encapsulated copies.
fn iface_mac(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
        assert!(
            h.ingress.is_none() && h.encap.is_none(),
            "no interfaces → no children spawned"
        );

        h.del(10);
        assert_eq!(h.vnis, BTreeSet::from([20]));
        h.del(99); // unknown VNI: no-op, no underflow
        assert_eq!(h.vnis, BTreeSet::from([20]));
        h.del(20);
        assert!(h.vnis.is_empty());
    }

    #[test]
    fn leaf_add_del_tracks_independently_of_segments() {
        let mut h = ReplicationHelper::new();
        h.iface = None; // never spawn a child
        // A leaf SID and a replication segment for the same/another VNI are
        // tracked separately; the child lives while EITHER role is active.
        h.add(10, 10, ip("10.0.0.1"), true, &[ip("10.0.0.2")]);
        h.leaf_add(10, "2001:db8::1".parse().unwrap());
        h.leaf_add(20, "2001:db8::2".parse().unwrap());
        assert_eq!(h.vnis, BTreeSet::from([10]));
        assert_eq!(h.leaf_vnis, BTreeSet::from([10, 20]));

        // Dropping the segment leaves the leaf role; both must empty to idle.
        h.del(10);
        assert!(h.vnis.is_empty());
        assert_eq!(h.leaf_vnis, BTreeSet::from([10, 20]));
        h.leaf_del(10);
        h.leaf_del(99); // unknown: no-op
        assert_eq!(h.leaf_vnis, BTreeSet::from([20]));
        h.leaf_del(20);
        assert!(h.leaf_vnis.is_empty());
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
