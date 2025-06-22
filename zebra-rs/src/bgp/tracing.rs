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

/// Log a trace-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_trace {
    ($($arg:tt)*) => {
        tracing::trace!(proto = "bgp", $($arg)*)
    };
}

// Re-export the macros for easier use within the bgp module
pub use {bgp_debug, bgp_error, bgp_info, bgp_trace, bgp_warn};
