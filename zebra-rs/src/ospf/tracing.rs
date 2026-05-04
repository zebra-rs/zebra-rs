// OSPF-specific conditional tracing system
//
// This module provides a comprehensive conditional tracing system for OSPF protocol
// that maps to YANG configuration options. It includes structures for fine-grained
// control over packet, event, FSM, database, and segment routing tracing.

// Main OSPF tracing configuration structure
#[derive(Debug, Clone, Default)]
pub struct OspfTracing {
    // Enable all OSPF tracing
    pub all: bool,
    // Packet tracing configuration
    pub packet: PacketTracing,
    // FSM tracing configuration
    pub fsm: FsmTracing,
}

// Packet tracing configuration
#[derive(Debug, Clone, Default)]
pub struct PacketTracing {
    pub hello: PacketConfig,
    pub dd: PacketConfig,
    pub ls_req: PacketConfig,
    pub ls_update: PacketConfig,
    pub ls_ack: PacketConfig,
    pub all: bool,
}

// Individual packet type configuration
#[derive(Debug, Clone, Default)]
pub struct PacketConfig {
    pub enabled: bool,
    pub direction: PacketDirection,
}

// Packet direction filter
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

// FSM tracing configuration
#[derive(Debug, Clone, Default)]
pub struct FsmTracing {
    pub ifsm: FsmConfig,
    pub nfsm: FsmConfig,
    pub all: bool,
}

// Individual FSM type configuration
#[derive(Debug, Clone, Default)]
pub struct FsmConfig {
    pub enabled: bool,
    pub detail: bool,
}

use strum_macros::Display;

use crate::config::{Args, ConfigOp};

use super::Ospf;

// Packet type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Display)]
pub enum PacketType {
    #[strum(serialize = "hello")]
    Hello,
}

// FSM type enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum FsmType {
    Nfsm,
}

impl OspfTracing {
    // Check if packet tracing should be enabled for given parameters
    pub fn should_trace_packet(&self, packet_type: PacketType, direction: PacketDirection) -> bool {
        if !self.all && !self.packet.all {
            let config = match packet_type {
                PacketType::Hello => &self.packet.hello,
            };

            if !config.enabled {
                return false;
            }

            // Check direction filter
            if config.direction != PacketDirection::Both && config.direction != direction {
                return false;
            }

            true
        } else {
            true
        }
    }

    // Check if FSM tracing should be enabled for given parameters
    pub fn should_trace_fsm(&self, fsm_type: FsmType, detail: bool) -> bool {
        if !self.all && !self.fsm.all {
            let config = match fsm_type {
                FsmType::Nfsm => &self.fsm.nfsm,
            };

            config.enabled && (!detail || config.detail)
        } else {
            true
        }
    }
}

fn parse_direction(args: &mut Args) -> PacketDirection {
    match args.string().as_deref() {
        Some("send") => PacketDirection::Send,
        Some("recv") | Some("receive") => PacketDirection::Recv,
        Some("both") | None => PacketDirection::Both,
        Some(_) => PacketDirection::Both,
    }
}

fn set_packet_config(config: &mut PacketConfig, op: ConfigOp, direction: PacketDirection) {
    if op.is_set() {
        config.enabled = true;
        config.direction = direction;
    } else {
        config.enabled = false;
        config.direction = PacketDirection::Both;
    }
}

pub fn config_tracing_fsm(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let typ = args.string()?;

    match typ.as_str() {
        "nfsm" => {
            ospf.tracing.fsm.nfsm.enabled = op.is_set();
        }
        "ifsm" => {
            ospf.tracing.fsm.ifsm.enabled = op.is_set();
        }
        "all" => {
            ospf.tracing.fsm.nfsm.enabled = op.is_set();
            ospf.tracing.fsm.ifsm.enabled = op.is_set();
        }
        _ => {}
    }

    Some(())
}

pub fn config_tracing_packet(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let typ = args.string()?;
    let direction = parse_direction(&mut args);

    match typ.as_str() {
        "all" => {
            set_packet_config(&mut ospf.tracing.packet.hello, op, direction);
            set_packet_config(&mut ospf.tracing.packet.dd, op, direction);
            set_packet_config(&mut ospf.tracing.packet.ls_req, op, direction);
            set_packet_config(&mut ospf.tracing.packet.ls_update, op, direction);
            set_packet_config(&mut ospf.tracing.packet.ls_ack, op, direction);
        }
        "hello" => {
            set_packet_config(&mut ospf.tracing.packet.hello, op, direction);
        }
        "dd" => {
            set_packet_config(&mut ospf.tracing.packet.dd, op, direction);
        }
        "ls-req" => {
            set_packet_config(&mut ospf.tracing.packet.ls_req, op, direction);
        }
        "ls-update" => {
            set_packet_config(&mut ospf.tracing.packet.ls_update, op, direction);
        }
        "ls-ack" => {
            set_packet_config(&mut ospf.tracing.packet.ls_ack, op, direction);
        }
        _ => {
            println!("Unknown packet type: {}", typ);
        }
    }

    Some(())
}

// Log an info-level message with proto="ospf" field
#[macro_export]
macro_rules! ospf_info {
    ($($arg:tt)*) => {
        tracing::info!(proto = "ospf", $($arg)*)
    };
}

// Log a warning-level message with proto="ospf" field
#[macro_export]
macro_rules! ospf_warn {
    ($($arg:tt)*) => {
        tracing::warn!(proto = "ospf", $($arg)*)
    };
}

// Log an error-level message with proto="ospf" field
#[macro_export]
macro_rules! ospf_error {
    ($($arg:tt)*) => {
        tracing::error!(proto = "ospf", $($arg)*)
    };
}

// Log a debug-level message with proto="ospf" field
#[macro_export]
macro_rules! ospf_debug {
    ($($arg:tt)*) => {
        tracing::debug!(proto = "ospf", $($arg)*)
    };
}

// Log a trace-level message with proto="ospf" field
#[macro_export]
macro_rules! ospf_trace {
    ($($arg:tt)*) => {
        tracing::trace!(proto = "ospf", $($arg)*)
    };
}

// Conditional packet tracing macro
#[macro_export]
macro_rules! ospf_packet_trace {
    ($tracing:expr, $packet_type:ident, $direction:ident, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_packet(
            $crate::ospf::tracing::PacketType::$packet_type,
            $crate::ospf::tracing::PacketDirection::$direction,
            $level
        ) {
            tracing::info!(
                proto = "ospf",
                category = "packet",
                packet_type = stringify!($packet_type),
                direction = stringify!($direction),
                level = %$level,
                $($arg)*
            )
        }
    };
}

// Conditional FSM tracing macro
#[macro_export]
macro_rules! ospf_fsm_trace {
    ($tracing:expr, $fsm_type:ident, $detail:expr, $($arg:tt)*) => {
        if $tracing.should_trace_fsm(
            $crate::ospf::tracing::FsmType::$fsm_type,
            $detail
        ) {
            tracing::info!(
                proto = "ospf",
                category = "fsm",
                fsm_type = stringify!($fsm_type),
                detail = $detail,
                $($arg)*
            )
        }
    };
}

// Macro to define a packet receive handler with automatic tracing context.
// This creates local constants for packet type and direction that can be used
// with `ospf_pkt_trace!` macro.
//
// Usage:
// ```ignore
// ospf_pdu_handler!(Hello, Recv);
// // Now use ospf_pkt_trace! instead of ospf_packet_trace!
// ospf_pkt_trace!(top.tracing, &level, "[Hello] recv on {}", link.state.name);
// ```
#[macro_export]
macro_rules! ospf_pdu_handler {
    ($packet_type:ident, $direction:ident) => {
        const _OSPF_PKT_TYPE: $crate::ospf::tracing::PacketType =
            $crate::ospf::tracing::PacketType::$packet_type;
        const _OSPF_PKT_DIR: $crate::ospf::tracing::PacketDirection =
            $crate::ospf::tracing::PacketDirection::$direction;
    };
}

// Simplified packet tracing macro that uses the context defined by `ospf_pdu_handler!`.
// Must be used after `ospf_pdu_handler!` in the same scope.
#[macro_export]
macro_rules! ospf_pkt_trace {
    ($tracing:expr, $($arg:tt)*) => {
        if $tracing.should_trace_packet(_OSPF_PKT_TYPE, _OSPF_PKT_DIR) {
            tracing::info!(
                proto = "ospf",
                category = "packet",
                packet_type = _OSPF_PKT_TYPE.as_str(),
                direction = _OSPF_PKT_DIR.as_str(),
                $($arg)*
            )
        }
    };
}

// Simplified packet tracing macro that uses the context defined by `ospf_pdu_handler!`.
// Must be used after `ospf_pdu_handler!` in the same scope.
#[macro_export]
macro_rules! ospf_pdu_trace {
    ($tracing:expr, $($arg:tt)*) => {
        if $tracing.should_trace_packet(_OSPF_PKT_TYPE, _OSPF_PKT_DIR) {
            tracing::info!(
                proto = "ospf",
                category = "packet",
                packet_type = _OSPF_PKT_TYPE.to_string(),
                direction = _OSPF_PKT_DIR.as_str(),
                $($arg)*
            )
        }
    };
}
