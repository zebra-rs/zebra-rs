/// ISIS-specific tracing macros that automatically include proto="isis" field
///
/// This module provides convenience macros for ISIS protocol logging that automatically
/// include the proto="isis" field for better log categorization and filtering.

/// Log an info-level message with proto="isis" field
#[macro_export]
macro_rules! isis_info {
    ($($arg:tt)*) => {
        tracing::info!(proto = "isis", $($arg)*)
    };
}

/// Log a warning-level message with proto="isis" field
#[macro_export]
macro_rules! isis_warn {
    ($($arg:tt)*) => {
        tracing::warn!(proto = "isis", $($arg)*)
    };
}

/// Log an error-level message with proto="isis" field
#[macro_export]
macro_rules! isis_error {
    ($($arg:tt)*) => {
        tracing::error!(proto = "isis", $($arg)*)
    };
}

/// Log a debug-level message with proto="isis" field
#[macro_export]
macro_rules! isis_debug {
    ($($arg:tt)*) => {
        tracing::debug!(proto = "isis", $($arg)*)
    };
}

/// Log a trace-level message with proto="isis" field
#[macro_export]
macro_rules! isis_trace {
    ($($arg:tt)*) => {
        tracing::trace!(proto = "isis", $($arg)*)
    };
}

// Re-export the macros for easier use within the isis module
pub use {isis_debug, isis_error, isis_info, isis_trace, isis_warn};
