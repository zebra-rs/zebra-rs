// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

/// ISIS-specific conditional tracing system
///
/// This module provides a comprehensive conditional tracing system for ISIS protocol
/// that maps to YANG configuration options. It includes structures for fine-grained
/// control over packet, event, FSM, database, and segment routing tracing.
use super::level::Level;

/// Main ISIS tracing configuration structure
#[derive(Debug, Clone, Default)]
pub struct IsisTracing {
    /// Packet tracing configuration
    pub packet: PacketTracing,
    /// Event tracing configuration
    pub event: EventTracing,
    /// FSM tracing configuration
    pub fsm: FsmTracing,
    /// Database tracing configuration
    pub database: DatabaseTracing,
}

/// Packet tracing configuration
#[derive(Debug, Clone, Default)]
pub struct PacketTracing {
    pub hello: PacketConfig,
    pub lsp: PacketConfig,
    pub csnp: PacketConfig,
    pub psnp: PacketConfig,
    pub all: bool,
}

/// Individual packet type configuration
#[derive(Debug, Clone, Default)]
pub struct PacketConfig {
    pub enabled: bool,
    pub direction: PacketDirection,
    pub level: TracingLevel,
}

/// Packet direction filter
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum PacketDirection {
    Send,
    Recv,
    #[default]
    Both,
}

impl PacketDirection {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PacketDirection::Send => "Send",
            PacketDirection::Recv => "Receive",
            PacketDirection::Both => "Both",
        }
    }
}

/// Event tracing configuration
#[derive(Debug, Clone, Default)]
pub struct EventTracing {
    pub dis: EventConfig,
    pub lsp_originate: EventConfig,
    pub lsp_purge: EventConfig,
    pub all: bool,
}

/// Individual event type configuration
#[derive(Debug, Clone, Default)]
pub struct EventConfig {
    pub enabled: bool,
    pub level: TracingLevel,
}

/// FSM tracing configuration
#[derive(Debug, Clone, Default)]
pub struct FsmTracing {
    pub ifsm: FsmConfig,
    pub nfsm: FsmConfig,
}

/// Individual FSM type configuration
#[derive(Debug, Clone, Default)]
pub struct FsmConfig {
    pub enabled: bool,
}

/// Database tracing configuration
#[derive(Debug, Clone, Default)]
pub struct DatabaseTracing {
    pub lsdb: DatabaseConfig,
    pub all: bool,
}

/// Individual database type configuration
#[derive(Debug, Clone, Default)]
pub struct DatabaseConfig {
    pub enabled: bool,
    pub level: TracingLevel,
}

/// Tracing level filter
#[derive(Debug, Clone, Default, PartialEq)]
pub enum TracingLevel {
    #[default]
    Both,
}

/// Packet type enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Hello,
    Lsp,
    Csnp,
    Psnp,
}

impl PacketType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PacketType::Hello => "Hello",
            PacketType::Lsp => "Lsp",
            PacketType::Csnp => "Csnp",
            PacketType::Psnp => "Psnp",
        }
    }
}

/// Event type enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    LspOriginate,
    LspPurge,
}

/// Database type enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseType {
    Lsdb,
}

impl IsisTracing {
    /// Check if packet tracing should be enabled for given parameters
    pub fn should_trace_packet(
        &self,
        packet_type: PacketType,
        direction: PacketDirection,
        _level: &Level,
    ) -> bool {
        if !self.packet.all {
            let config = match packet_type {
                PacketType::Hello => &self.packet.hello,
                PacketType::Lsp => &self.packet.lsp,
                PacketType::Csnp => &self.packet.csnp,
                PacketType::Psnp => &self.packet.psnp,
            };

            if !config.enabled {
                return false;
            }

            // Check direction filter
            if config.direction != PacketDirection::Both && config.direction != direction {
                return false;
            }

            // Check level filter
            match config.level {
                TracingLevel::Both => true,
            }
        } else {
            true
        }
    }

    /// Check if event tracing should be enabled for given parameters
    pub fn should_trace_event(&self, event_type: EventType, _level: &Level) -> bool {
        if !self.event.all {
            let config = match event_type {
                EventType::LspOriginate => &self.event.lsp_originate,
                EventType::LspPurge => &self.event.lsp_purge,
            };

            if !config.enabled {
                return false;
            }

            // Check level filter
            match config.level {
                TracingLevel::Both => true,
            }
        } else {
            true
        }
    }

    /// Check if database tracing should be enabled for given parameters
    pub fn should_trace_database(&self, db_type: DatabaseType, _level: &Level) -> bool {
        if !self.database.all {
            let config = match db_type {
                DatabaseType::Lsdb => &self.database.lsdb,
            };

            if !config.enabled {
                return false;
            }

            // Check level filter
            match config.level {
                TracingLevel::Both => true,
            }
        } else {
            true
        }
    }
}

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

/// Conditional packet tracing macro
#[macro_export]
macro_rules! isis_packet_trace {
    ($tracing:expr, $packet_type:ident, $direction:ident, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_packet(
            $crate::isis::tracing::PacketType::$packet_type,
            $crate::isis::tracing::PacketDirection::$direction,
            $level
        ) {
            tracing::info!(
                proto = "isis",
                category = "packet",
                packet_type = stringify!($packet_type),
                direction = stringify!($direction),
                level = %$level,
                $($arg)*
            )
        }
    };
}

/// Conditional event tracing macro
#[macro_export]
macro_rules! isis_event_trace {
    ($tracing:expr, $event_type:ident, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_event(
            $crate::isis::tracing::EventType::$event_type,
            $level
        ) {
            tracing::info!(
                proto = "isis",
                category = "event",
                event_type = stringify!($event_type),
                level = %$level,
                $($arg)*
            )
        }
    };
}

/// Conditional database tracing macro
#[macro_export]
macro_rules! isis_database_trace {
    ($tracing:expr, $db_type:ident, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_database(
            $crate::isis::tracing::DatabaseType::$db_type,
            $level
        ) {
            tracing::info!(
                proto = "isis",
                category = "database",
                db_type = stringify!($db_type),
                level = %$level,
                $($arg)*
            )
        }
    };
}

/// Macro to define a packet receive handler with automatic tracing context.
/// This creates local constants for packet type and direction that can be used
/// with `isis_pkt_trace!` macro.
///
/// Usage:
/// ```ignore
/// isis_pdu_handler!(Hello, Recv);
/// // Now use isis_pkt_trace! instead of isis_packet_trace!
/// isis_pkt_trace!(top.tracing, &level, "[Hello] recv on {}", link.state.name);
/// ```
#[macro_export]
macro_rules! isis_pdu_handler {
    ($packet_type:ident, $direction:ident) => {
        const _ISIS_PKT_TYPE: $crate::isis::tracing::PacketType =
            $crate::isis::tracing::PacketType::$packet_type;
        const _ISIS_PKT_DIR: $crate::isis::tracing::PacketDirection =
            $crate::isis::tracing::PacketDirection::$direction;
    };
}

/// Simplified packet tracing macro that uses the context defined by `isis_pdu_handler!`.
/// Must be used after `isis_pdu_handler!` in the same scope.
#[macro_export]
macro_rules! isis_pkt_trace {
    ($tracing:expr, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_packet(_ISIS_PKT_TYPE, _ISIS_PKT_DIR, $level) {
            tracing::info!(
                proto = "isis",
                category = "packet",
                packet_type = _ISIS_PKT_TYPE.as_str(),
                direction = _ISIS_PKT_DIR.as_str(),
                level = %$level,
                $($arg)*
            )
        }
    };
}

/// Simplified packet tracing macro that uses the context defined by `isis_pdu_handler!`.
/// Must be used after `isis_pdu_handler!` in the same scope.
#[macro_export]
macro_rules! isis_pdu_trace {
    ($tracing:expr, $level:expr, $($arg:tt)*) => {
        if $tracing.tracing.should_trace_packet(_ISIS_PKT_TYPE, _ISIS_PKT_DIR, $level) {
            tracing::info!(
                proto = "isis",
                category = "packet",
                packet_type = _ISIS_PKT_TYPE.as_str(),
                direction = _ISIS_PKT_DIR.as_str(),
                level = %$level,
                $($arg)*
            )
        }
    };
}
