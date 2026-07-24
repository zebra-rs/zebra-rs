//! Conditional tracing for the BFD task.
//!
//! Every trace emitted under `src/bfd/` is gated behind a single runtime flag,
//! toggled with `set bfd tracing true`. The flag is a process-global atomic so
//! the gate works from every BFD context — the instance methods, the spawned
//! socket read/write tasks, and the cradle Echo/detect offload driver task —
//! without threading state through each call site.
//!
//! Use the level-preserving macros [`bfd_info!`], [`bfd_warn!`] and
//! [`bfd_debug!`] in place of `tracing::{info,warn,debug}!`; each expands to a
//! no-op unless the flag is set. So `set bfd tracing true` surfaces the info /
//! warn traces at the default log level; the debug traces additionally need
//! the log level raised (e.g. `RUST_LOG=debug`), matching their original
//! verbosity.

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether `set bfd tracing true` is in effect. Defaults off.
static BFD_TRACING: AtomicBool = AtomicBool::new(false);

/// Set from the `/bfd/tracing` config handler on commit.
pub(crate) fn set(enabled: bool) {
    BFD_TRACING.store(enabled, Ordering::Relaxed);
}

/// Read by the `bfd_*` tracing macros before emitting.
pub(crate) fn enabled() -> bool {
    BFD_TRACING.load(Ordering::Relaxed)
}

/// `tracing::info!`, gated on `set bfd tracing true`.
macro_rules! bfd_info {
    ($($arg:tt)*) => {
        if $crate::bfd::trace::enabled() {
            ::tracing::info!($($arg)*);
        }
    };
}

/// `tracing::warn!`, gated on `set bfd tracing true`.
macro_rules! bfd_warn {
    ($($arg:tt)*) => {
        if $crate::bfd::trace::enabled() {
            ::tracing::warn!($($arg)*);
        }
    };
}

/// `tracing::debug!`, gated on `set bfd tracing true`.
macro_rules! bfd_debug {
    ($($arg:tt)*) => {
        if $crate::bfd::trace::enabled() {
            ::tracing::debug!($($arg)*);
        }
    };
}

pub(crate) use {bfd_debug, bfd_info, bfd_warn};
