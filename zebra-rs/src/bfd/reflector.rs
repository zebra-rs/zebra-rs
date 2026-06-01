//! Per-interface XDP BFD Echo reflector supervisor.
//!
//! BFD Echo (RFC 5880 §6.4 / RFC 5881 §4) is a single-hop, interface-scoped
//! data-plane hairpin: a peer sends Echo frames to UDP/3785 and our forwarding
//! plane loops them straight back. zebra-rs provides that loopback by running
//! the standalone `bfd-echo-reflector` XDP loader (see
//! `offload/bfd-echo-reflector/`) as a managed child process — one per
//! interface that has at least one single-hop session advertising Echo.
//!
//! Advertising a non-zero `Required Min Echo RX Interval` is a *promise to loop
//! Echo back* (RFC 5880 §6.8.1), so the advertise path must only do so once the
//! child for that interface is confirmed running ([`EchoReflectors::is_ready`]).
//!
//! Lifecycle is reference-counted by ifindex: [`EchoReflectors::acquire`] for
//! each echo session created on an interface, [`EchoReflectors::release`] when
//! one goes away. The child is spawned on the first reference and SIGTERM'd
//! (graceful XDP detach) on the last.

use std::collections::HashMap;
use std::path::PathBuf;

use tokio::process::{Child, Command};

/// Env override for the reflector binary path (mirrors vtypam's
/// `ZEBRA_VTYPAM_BIN`). Falls back to the install locations.
const BIN_ENV: &str = "ZEBRA_BFD_REFLECTOR_BIN";
/// Env override for the XDP attach mode (`auto` | `native` | `skb`). Default
/// `auto`; veth / virtual NICs need `skb` (native attaches but does not loop).
const MODE_ENV: &str = "ZEBRA_BFD_REFLECTOR_MODE";

/// One supervised reflector child, keyed by ifindex in [`EchoReflectors`].
struct Reflector {
    /// Number of single-hop echo sessions currently on this interface.
    refcount: u32,
    /// The child process, if it spawned. `None` when the spawn failed (e.g.
    /// the binary is missing or the ifindex has no name) — we then stay
    /// not-ready and keep advertising 0, which is honest.
    child: Option<Child>,
    ifname: String,
}

impl Reflector {
    /// SIGTERM the child so the loader detaches its XDP program cleanly. The
    /// `kill_on_drop(true)` set at spawn reaps it (SIGKILL) if it ignores us.
    fn stop(&mut self) {
        if let Some(pid) = self.child.as_ref().and_then(Child::id) {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            tracing::info!("bfd echo: stopping reflector on {}", self.ifname);
        }
    }

    /// True while the child is still running. A child that has exited (crash,
    /// killed externally) is not alive, so we must stop advertising Echo.
    fn is_alive(&mut self) -> bool {
        match &mut self.child {
            // `try_wait` is non-blocking: `Ok(None)` => still running.
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }
}

/// Supervises the set of `bfd-echo-reflector` child processes, one per
/// interface with active single-hop Echo sessions.
pub struct EchoReflectors {
    by_ifindex: HashMap<u32, Reflector>,
    bin: PathBuf,
    mode: String,
}

impl Default for EchoReflectors {
    fn default() -> Self {
        Self::new()
    }
}

impl EchoReflectors {
    pub fn new() -> Self {
        Self {
            by_ifindex: HashMap::new(),
            bin: resolve_bin(),
            mode: std::env::var(MODE_ENV).unwrap_or_else(|_| "auto".to_string()),
        }
    }

    /// Note one more single-hop echo session on `ifindex`; spawn the reflector
    /// child if this is the first.
    pub fn acquire(&mut self, ifindex: u32) {
        if let Some(r) = self.by_ifindex.get_mut(&ifindex) {
            r.refcount += 1;
            return;
        }
        let reflector = self.spawn(ifindex);
        self.by_ifindex.insert(ifindex, reflector);
    }

    /// Drop one reference; stop the child when the last echo session on
    /// `ifindex` goes away.
    pub fn release(&mut self, ifindex: u32) {
        let Some(r) = self.by_ifindex.get_mut(&ifindex) else {
            return;
        };
        r.refcount = r.refcount.saturating_sub(1);
        if r.refcount > 0 {
            return;
        }
        // The `get_mut` borrow ended at the comparison above (NLL), so the
        // last echo session is gone — remove the entry and stop the child.
        if let Some(mut r) = self.by_ifindex.remove(&ifindex) {
            r.stop();
        }
    }

    /// Whether the reflector for `ifindex` is confirmed running — the gate for
    /// honestly advertising a non-zero echo-rx on sessions over this interface.
    pub fn is_ready(&mut self, ifindex: u32) -> bool {
        self.by_ifindex
            .get_mut(&ifindex)
            .map(Reflector::is_alive)
            .unwrap_or(false)
    }

    /// Number of echo sessions currently referencing `ifindex` (0 if none).
    /// Test-only: lets the instance-level tests verify acquire/release wiring.
    #[cfg(test)]
    pub fn refcount(&self, ifindex: u32) -> u32 {
        self.by_ifindex.get(&ifindex).map_or(0, |r| r.refcount)
    }

    fn spawn(&self, ifindex: u32) -> Reflector {
        let Some(ifname) = if_indextoname(ifindex) else {
            tracing::warn!("bfd echo: no interface name for ifindex {ifindex}; reflector off");
            return Reflector {
                refcount: 1,
                child: None,
                ifname: String::new(),
            };
        };
        let child = match Command::new(&self.bin)
            .arg("-i")
            .arg(&ifname)
            .arg("-m")
            .arg(&self.mode)
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => {
                tracing::info!(
                    "bfd echo: spawned reflector on {ifname} (ifindex {ifindex}, mode {})",
                    self.mode
                );
                Some(child)
            }
            Err(e) => {
                tracing::warn!(
                    "bfd echo: failed to spawn {} on {ifname}: {e}",
                    self.bin.display()
                );
                None
            }
        };
        Reflector {
            refcount: 1,
            child,
            ifname,
        }
    }
}

/// Resolve the reflector binary path: `$ZEBRA_BFD_REFLECTOR_BIN`, else the dev
/// install (`make install` → `~/.zebra/bin`), else the packaged location.
fn resolve_bin() -> PathBuf {
    if let Some(p) = std::env::var_os(BIN_ENV) {
        return PathBuf::from(p);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let dev = PathBuf::from(home).join(".zebra/bin/bfd-echo-reflector");
        if dev.exists() {
            return dev;
        }
    }
    PathBuf::from("/usr/sbin/bfd-echo-reflector")
}

/// `if_indextoname(3)` — the reflector loader attaches by interface name.
fn if_indextoname(ifindex: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
    if p.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    cstr.to_str().ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    // An ifindex with no interface name: `spawn` resolves no name, so no child
    // process is launched, but the refcount bookkeeping still runs. Lets us
    // exercise acquire/release without depending on a real interface or binary.
    const NO_SUCH_IFINDEX: u32 = 0xFFFF_FFF0;

    #[test]
    fn acquire_release_refcounts_per_ifindex() {
        let mut r = EchoReflectors::new();
        assert!(!r.by_ifindex.contains_key(&NO_SUCH_IFINDEX));

        r.acquire(NO_SUCH_IFINDEX);
        r.acquire(NO_SUCH_IFINDEX);
        assert_eq!(r.by_ifindex.get(&NO_SUCH_IFINDEX).unwrap().refcount, 2);

        r.release(NO_SUCH_IFINDEX);
        assert_eq!(r.by_ifindex.get(&NO_SUCH_IFINDEX).unwrap().refcount, 1);

        r.release(NO_SUCH_IFINDEX);
        assert!(
            !r.by_ifindex.contains_key(&NO_SUCH_IFINDEX),
            "last release removes the entry"
        );
        // Failed-to-spawn (no ifname) reflector is never 'ready'.
        assert!(!r.is_ready(NO_SUCH_IFINDEX));
    }

    #[test]
    fn release_unknown_ifindex_is_noop() {
        let mut r = EchoReflectors::new();
        r.release(12345); // must not panic / underflow
        assert!(r.by_ifindex.is_empty());
    }

    #[test]
    fn bin_env_override_is_honoured() {
        // SAFETY: single-threaded test; set then read immediately.
        unsafe { std::env::set_var(BIN_ENV, "/opt/custom/bfd-echo-reflector") };
        let r = EchoReflectors::new();
        unsafe { std::env::remove_var(BIN_ENV) };
        assert_eq!(r.bin, PathBuf::from("/opt/custom/bfd-echo-reflector"));
    }
}
