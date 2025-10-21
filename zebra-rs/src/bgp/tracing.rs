/// BGP-specific tracing macros that automatically include proto="bgp" field
///
/// This module provides convenience macros for BGP protocol logging that automatically
/// include the proto="bgp" field for better log categorization and filtering.

/// Log an info-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_info {
    ($($arg:tt)*) => {
        tracing::info!(proto = "bgp", $($arg)*)
    };
}

/// Log a warning-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_warn {
    ($($arg:tt)*) => {
        tracing::warn!(proto = "bgp", $($arg)*)
    };
}

/// Log an error-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_error {
    ($($arg:tt)*) => {
        tracing::error!(proto = "bgp", $($arg)*)
    };
}

/// Log a debug-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_debug {
    ($($arg:tt)*) => {
        tracing::debug!(proto = "bgp", $($arg)*)
    };
}

/// Log a debug-level message with category filtering
/// Usage: bgp_debug_cat!(bgp_instance, category = "update", "message", args...)
#[macro_export]
macro_rules! bgp_debug_cat {
    ($bgp:expr, category = $cat:expr, $($arg:tt)*) => {
        if $bgp.debug_flags.is_enabled($cat) {
            tracing::debug!(proto = "bgp", category = $cat, $($arg)*)
        }
    };
}

/// Log a trace-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_trace {
    ($($arg:tt)*) => {
        tracing::trace!(proto = "bgp", $($arg)*)
    };
}
