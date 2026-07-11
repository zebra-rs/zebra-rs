//! Supervisor for the **cradle** eBPF data-plane engine.
//!
//! `system ebpf enabled true` makes zebra-rs run the cradle daemon as a
//! managed child process: spawn it, restart it with backoff when it dies,
//! and stop it (SIGTERM, SIGKILL fallback) when the knob is deleted or the
//! daemon exits (`kill_on_drop` + `PR_SET_PDEATHSIG` cover crashes). An
//! instance already listening on the endpoint is **adopted** — monitored,
//! never killed — so externally-started engines keep working; if an adopted
//! engine dies, the supervisor spawns its own.
//!
//! This knob only manages the *process*. The FIB tee stays under
//! `system cradle enabled` (handled by the RIB task — see
//! `fib/cradle.rs`), and both sides share the `system cradle grpc-endpoint`
//! leaf: the child serves its gRPC API on the same endpoint the tee dials
//! (default `unix:cradle/grpc`, a per-netns Linux abstract socket). The
//! forward tee reconnects lazily and the `WatchFdb` subscriber retries with
//! backoff, so a supervised restart heals without extra wiring here.

pub mod inst;
pub mod supervisor;

pub use inst::{Cradle, serve};
