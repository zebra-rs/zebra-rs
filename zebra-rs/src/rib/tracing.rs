//! Runtime RIB / FIB tracing configuration.
//!
//! Backs the `system tracing { rib {...} fib {...} }` config tree
//! defined in `zebra-rib-tracing.yang`. The per-protocol tracing blocks
//! (BGP / OSPF / IS-IS) keep their toggles on the protocol instance,
//! because every trace site has a `Peer` / instance handle. The RIB and
//! FIB trace sites do not: they are spread across `Rib` methods, free
//! functions in `rib::route` / `rib::nexthop`, and `FibHandle` methods,
//! none of which share a `self`. So the toggles live in one
//! process-global block of atomics — the runtime successor to the old
//! `const DEBUG_*: bool` flags that used to gate these same sites at
//! compile time.
//!
//! Reads are lock-free `Relaxed` loads (cheap enough for the route /
//! nexthop hot paths); writes happen only when `system tracing …` is
//! committed, dispatched from [`Rib::process_cm_msg`] via
//! [`config_dispatch`]. There is exactly one RIB per process, so a
//! global is the honest model here — the same way the `tracing` crate's
//! own subscriber is global.
//!
//! Only the categories that have a live trace site expose a reader
//! (`rib_route`, `fib_l2_fdb`, …); the remaining leaves are still parsed
//! and stored so the config round-trips and the `all` master switch
//! covers them once their sites are instrumented.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering::Relaxed};

use crate::config::{Args, ConfigOp};

/// Every `system tracing` leaf as an atomic toggle. `*_detail` mirror
/// the optional `detail` refinement; `fib_kernel_dir` holds the
/// `fib kernel direction` (0 = both, 1 = send, 2 = receive).
struct State {
    all: AtomicBool,

    /// Cross-cutting daemon task spawn / despawn lifecycle — not tied to
    /// a forwarding plane, so it sits beside `all` rather than under
    /// `rib` / `fib`.
    task: AtomicBool,

    rib_route: AtomicBool,
    rib_route_detail: AtomicBool,
    rib_nexthop: AtomicBool,
    rib_nexthop_detail: AtomicBool,
    rib_redistribute: AtomicBool,
    rib_label: AtomicBool,
    rib_static: AtomicBool,
    rib_interface: AtomicBool,
    rib_interface_detail: AtomicBool,
    rib_vrf: AtomicBool,
    rib_srv6: AtomicBool,
    rib_srv6_detail: AtomicBool,

    fib_route: AtomicBool,
    fib_route_detail: AtomicBool,
    fib_nexthop: AtomicBool,
    fib_nexthop_detail: AtomicBool,
    fib_kernel: AtomicBool,
    fib_kernel_detail: AtomicBool,
    fib_kernel_dir: AtomicU8,
    fib_label: AtomicBool,
    fib_neighbor: AtomicBool,
    fib_interface: AtomicBool,
    fib_interface_detail: AtomicBool,
    fib_link: AtomicBool,
    fib_vrf: AtomicBool,
    fib_srv6: AtomicBool,
    fib_srv6_detail: AtomicBool,
    fib_l2_bridge: AtomicBool,
    fib_l2_vxlan: AtomicBool,
    fib_l2_fdb: AtomicBool,
    fib_l2_mdb: AtomicBool,
}

impl State {
    const fn new() -> Self {
        State {
            all: AtomicBool::new(false),
            task: AtomicBool::new(false),
            rib_route: AtomicBool::new(false),
            rib_route_detail: AtomicBool::new(false),
            rib_nexthop: AtomicBool::new(false),
            rib_nexthop_detail: AtomicBool::new(false),
            rib_redistribute: AtomicBool::new(false),
            rib_label: AtomicBool::new(false),
            rib_static: AtomicBool::new(false),
            rib_interface: AtomicBool::new(false),
            rib_interface_detail: AtomicBool::new(false),
            rib_vrf: AtomicBool::new(false),
            rib_srv6: AtomicBool::new(false),
            rib_srv6_detail: AtomicBool::new(false),
            fib_route: AtomicBool::new(false),
            fib_route_detail: AtomicBool::new(false),
            fib_nexthop: AtomicBool::new(false),
            fib_nexthop_detail: AtomicBool::new(false),
            fib_kernel: AtomicBool::new(false),
            fib_kernel_detail: AtomicBool::new(false),
            fib_kernel_dir: AtomicU8::new(0),
            fib_label: AtomicBool::new(false),
            fib_neighbor: AtomicBool::new(false),
            fib_interface: AtomicBool::new(false),
            fib_interface_detail: AtomicBool::new(false),
            fib_link: AtomicBool::new(false),
            fib_vrf: AtomicBool::new(false),
            fib_srv6: AtomicBool::new(false),
            fib_srv6_detail: AtomicBool::new(false),
            fib_l2_bridge: AtomicBool::new(false),
            fib_l2_vxlan: AtomicBool::new(false),
            fib_l2_fdb: AtomicBool::new(false),
            fib_l2_mdb: AtomicBool::new(false),
        }
    }

    /// A category is on when its own toggle is set, or the `all` master
    /// switch is. `all` is summary-level only — it never implies detail.
    #[inline]
    fn on(&self, flag: &AtomicBool) -> bool {
        self.all.load(Relaxed) || flag.load(Relaxed)
    }

    /// Apply one committed `…/tracing/<rest>` Set/Delete line. `rest` is
    /// the path tail after the `tracing` node (e.g. `/rib/route`,
    /// `/fib/kernel/direction`); for the direction case `args` still
    /// holds the trailing send/receive token. Unknown tails are ignored
    /// — the YANG constrains the set, so a miss only means a leaf with no
    /// behavior yet.
    fn apply(&self, rest: &str, args: &mut Args, op: ConfigOp) {
        let set = op.is_set();
        match rest {
            "" | "/all" => self.all.store(set, Relaxed),
            "/task" => self.task.store(set, Relaxed),

            "/rib/route" => toggle(&self.rib_route, &self.rib_route_detail, op),
            "/rib/route/detail" => detail(&self.rib_route, &self.rib_route_detail, op),
            "/rib/nexthop" => toggle(&self.rib_nexthop, &self.rib_nexthop_detail, op),
            "/rib/nexthop/detail" => detail(&self.rib_nexthop, &self.rib_nexthop_detail, op),
            "/rib/redistribute" => self.rib_redistribute.store(set, Relaxed),
            "/rib/label" => self.rib_label.store(set, Relaxed),
            "/rib/static" => self.rib_static.store(set, Relaxed),
            "/rib/interface" => toggle(&self.rib_interface, &self.rib_interface_detail, op),
            "/rib/interface/detail" => detail(&self.rib_interface, &self.rib_interface_detail, op),
            "/rib/vrf" => self.rib_vrf.store(set, Relaxed),
            "/rib/srv6" => toggle(&self.rib_srv6, &self.rib_srv6_detail, op),
            "/rib/srv6/detail" => detail(&self.rib_srv6, &self.rib_srv6_detail, op),

            "/fib/route" => toggle(&self.fib_route, &self.fib_route_detail, op),
            "/fib/route/detail" => detail(&self.fib_route, &self.fib_route_detail, op),
            "/fib/nexthop" => toggle(&self.fib_nexthop, &self.fib_nexthop_detail, op),
            "/fib/nexthop/detail" => detail(&self.fib_nexthop, &self.fib_nexthop_detail, op),
            "/fib/kernel" => toggle(&self.fib_kernel, &self.fib_kernel_detail, op),
            "/fib/kernel/detail" => detail(&self.fib_kernel, &self.fib_kernel_detail, op),
            "/fib/kernel/direction" => direction(&self.fib_kernel, &self.fib_kernel_dir, args, op),
            "/fib/label" => self.fib_label.store(set, Relaxed),
            "/fib/neighbor" => self.fib_neighbor.store(set, Relaxed),
            "/fib/interface" => toggle(&self.fib_interface, &self.fib_interface_detail, op),
            "/fib/interface/detail" => detail(&self.fib_interface, &self.fib_interface_detail, op),
            "/fib/link" => self.fib_link.store(set, Relaxed),
            "/fib/vrf" => self.fib_vrf.store(set, Relaxed),
            "/fib/srv6" => toggle(&self.fib_srv6, &self.fib_srv6_detail, op),
            "/fib/srv6/detail" => detail(&self.fib_srv6, &self.fib_srv6_detail, op),
            "/fib/l2/bridge" => self.fib_l2_bridge.store(set, Relaxed),
            "/fib/l2/vxlan" => self.fib_l2_vxlan.store(set, Relaxed),
            "/fib/l2/fdb" => self.fib_l2_fdb.store(set, Relaxed),
            "/fib/l2/mdb" => self.fib_l2_mdb.store(set, Relaxed),
            _ => {}
        }
    }
}

static STATE: State = State::new();

/// `tracing <cat>` — bare presence enables the category; delete clears
/// it, including any `detail` underneath (matching the BGP block).
fn toggle(on: &AtomicBool, det: &AtomicBool, op: ConfigOp) {
    if op.is_set() {
        on.store(true, Relaxed);
    } else {
        on.store(false, Relaxed);
        det.store(false, Relaxed);
    }
}

/// `tracing <cat> detail` — enabling detail implies the category is
/// traced; delete leaves it enabled at summary level.
fn detail(on: &AtomicBool, det: &AtomicBool, op: ConfigOp) {
    if op.is_set() {
        on.store(true, Relaxed);
        det.store(true, Relaxed);
    } else {
        det.store(false, Relaxed);
    }
}

/// `tracing fib kernel direction {send|receive}` — restrict (and enable)
/// the netlink direction; delete reverts to both.
fn direction(on: &AtomicBool, dir: &AtomicU8, args: &mut Args, op: ConfigOp) {
    if op.is_set() {
        on.store(true, Relaxed);
        let d = match args.string().as_deref() {
            Some("send") => 1,
            Some("receive") | Some("recv") => 2,
            _ => 0,
        };
        dir.store(d, Relaxed);
    } else {
        dir.store(0, Relaxed);
    }
}

/// Dispatch a committed `/system/tracing/…` Set/Delete path. Called from
/// [`Rib::process_cm_msg`]; ignores anything outside the tracing subtree.
pub fn config_dispatch(path: &str, mut args: Args, op: ConfigOp) {
    if let Some(rest) = path.strip_prefix("/system/tracing") {
        STATE.apply(rest, &mut args, op);
    }
}

// ---- readers: one per category with a live trace site --------------

pub fn task() -> bool {
    STATE.on(&STATE.task)
}
pub fn rib_route() -> bool {
    STATE.on(&STATE.rib_route)
}
pub fn rib_nexthop() -> bool {
    STATE.on(&STATE.rib_nexthop)
}
pub fn rib_interface() -> bool {
    STATE.on(&STATE.rib_interface)
}
pub fn rib_srv6() -> bool {
    STATE.on(&STATE.rib_srv6)
}
pub fn fib_route() -> bool {
    STATE.on(&STATE.fib_route)
}
pub fn fib_nexthop() -> bool {
    STATE.on(&STATE.fib_nexthop)
}
pub fn fib_srv6() -> bool {
    STATE.on(&STATE.fib_srv6)
}
pub fn fib_link() -> bool {
    STATE.on(&STATE.fib_link)
}
pub fn fib_vrf() -> bool {
    STATE.on(&STATE.fib_vrf)
}
pub fn fib_l2_vxlan() -> bool {
    STATE.on(&STATE.fib_l2_vxlan)
}
pub fn fib_l2_fdb() -> bool {
    STATE.on(&STATE.fib_l2_fdb)
}
pub fn fib_l2_mdb() -> bool {
    STATE.on(&STATE.fib_l2_mdb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect::<VecDeque<_>>())
    }

    #[test]
    fn toggle_set_delete() {
        let s = State::new();
        s.apply("/rib/route", &mut args(&[]), ConfigOp::Set);
        assert!(s.on(&s.rib_route));
        s.apply("/rib/route", &mut args(&[]), ConfigOp::Delete);
        assert!(!s.on(&s.rib_route));
    }

    #[test]
    fn detail_implies_enabled_and_delete_keeps_enabled() {
        let s = State::new();
        s.apply("/fib/route/detail", &mut args(&[]), ConfigOp::Set);
        assert!(s.on(&s.fib_route));
        assert!(s.fib_route_detail.load(Relaxed));
        // Deleting detail leaves the category traced at summary level.
        s.apply("/fib/route/detail", &mut args(&[]), ConfigOp::Delete);
        assert!(s.on(&s.fib_route));
        assert!(!s.fib_route_detail.load(Relaxed));
        // Deleting the container clears the whole toggle.
        s.apply("/fib/route/detail", &mut args(&[]), ConfigOp::Set);
        s.apply("/fib/route", &mut args(&[]), ConfigOp::Delete);
        assert!(!s.on(&s.fib_route));
        assert!(!s.fib_route_detail.load(Relaxed));
    }

    #[test]
    fn fib_link_toggle_set_delete() {
        let s = State::new();
        s.apply("/fib/link", &mut args(&[]), ConfigOp::Set);
        assert!(s.on(&s.fib_link));
        s.apply("/fib/link", &mut args(&[]), ConfigOp::Delete);
        assert!(!s.on(&s.fib_link));
    }

    #[test]
    fn task_toggle_set_delete() {
        let s = State::new();
        s.apply("/task", &mut args(&[]), ConfigOp::Set);
        assert!(s.on(&s.task));
        s.apply("/task", &mut args(&[]), ConfigOp::Delete);
        assert!(!s.on(&s.task));
    }

    #[test]
    fn all_master_switch_lights_every_category() {
        let s = State::new();
        s.apply("/all", &mut args(&[]), ConfigOp::Set);
        assert!(s.on(&s.task));
        assert!(s.on(&s.rib_route));
        assert!(s.on(&s.fib_l2_fdb));
        assert!(s.on(&s.fib_srv6));
        assert!(s.on(&s.fib_link));
        // `all` is summary-level only — never implies detail.
        assert!(!s.fib_route_detail.load(Relaxed));
        s.apply("/all", &mut args(&[]), ConfigOp::Delete);
        assert!(!s.on(&s.rib_route));
    }

    #[test]
    fn kernel_direction_parses_and_enables() {
        let s = State::new();
        s.apply(
            "/fib/kernel/direction",
            &mut args(&["receive"]),
            ConfigOp::Set,
        );
        assert!(s.on(&s.fib_kernel));
        assert_eq!(s.fib_kernel_dir.load(Relaxed), 2);
        s.apply("/fib/kernel/direction", &mut args(&["send"]), ConfigOp::Set);
        assert_eq!(s.fib_kernel_dir.load(Relaxed), 1);
        s.apply("/fib/kernel/direction", &mut args(&[]), ConfigOp::Delete);
        assert_eq!(s.fib_kernel_dir.load(Relaxed), 0);
    }

    #[test]
    fn unknown_tail_ignored() {
        let s = State::new();
        s.apply("/bogus", &mut args(&[]), ConfigOp::Set);
        s.apply("/rib/bogus", &mut args(&[]), ConfigOp::Set);
        // No panic, nothing toggled.
        assert!(!s.on(&s.rib_route));
    }
}
