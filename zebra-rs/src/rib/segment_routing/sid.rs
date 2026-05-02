// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

//! SRv6 SID allocation registry. Each entry is one SID address that some
//! protocol (IS-IS, OSPF, BGP) has carved out of a locator and is now
//! advertising as End / End.X / End.DT4 / etc. The RIB is the central
//! registry so `show segment-routing srv6 sid` has a single source of
//! truth across protocols.

use std::fmt;
use std::net::Ipv6Addr;

/// RFC 8986 endpoint behavior for an allocated SID. We only carry the
/// variants we know how to advertise today; future behaviors (uSID,
/// End.DT4, End.DT6, End.B6, ...) extend the enum.
///
/// `#[allow(dead_code)]` on the type until PR 2 starts populating the
/// registry; the show callback already discriminates on every variant
/// so no individual variant carries the attribute.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidBehavior {
    /// Plain End — RFC 8986 §4.1, "node SID". The SID identifies the
    /// owner node; no per-link context.
    End,
    /// End.X — RFC 8986 §4.2, "L3 cross-connect" / adjacency SID.
    /// Bound to a specific outgoing interface and neighbor.
    EndX,
}

impl fmt::Display for SidBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::End => write!(f, "End"),
            Self::EndX => write!(f, "End.X"),
        }
    }
}

/// Optional context that disambiguates per-link / per-VRF SIDs. End is
/// always `None`; End.X carries the outgoing interface name. Future
/// per-VRF behaviors (End.DT4, End.DT6) would add a `Vrf(String)`.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidContext {
    None,
    Interface(String),
}

impl fmt::Display for SidContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "-"),
            Self::Interface(name) => write!(f, "Interface '{}'", name),
        }
    }
}

/// How the SID's function bits were chosen. `Dynamic` is the common
/// case (allocator picks the next free function); `Explicit` covers an
/// operator-configured SID and is reserved for a future static-SID
/// feature.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidAllocationType {
    Dynamic,
    Explicit,
}

impl fmt::Display for SidAllocationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dynamic => write!(f, "dynamic"),
            Self::Explicit => write!(f, "explicit"),
        }
    }
}

/// Owner of a SID, rendered as "isis(0)" / "bgp(0)" in the show table.
/// The instance number gives operators a hook for future multi-instance
/// support (separate L1 / L2 IS-IS instances, multiple BGP VRFs, ...);
/// today every protocol passes 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidOwner {
    pub proto: String,
    pub instance: u32,
}

impl SidOwner {
    #[allow(dead_code)] // first user lands in PR 2 (IS-IS End SID allocator)
    pub fn new(proto: impl Into<String>, instance: u32) -> Self {
        Self {
            proto: proto.into(),
            instance,
        }
    }
}

impl fmt::Display for SidOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.proto, self.instance)
    }
}

/// A single allocated SID — one row in `show segment-routing srv6 sid`.
/// Identified uniquely by `addr`; the registry rejects duplicate adds
/// without going through a Del first.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    pub addr: Ipv6Addr,
    pub behavior: SidBehavior,
    pub context: SidContext,
    pub owner: SidOwner,
    pub locator: String,
    pub allocation_type: SidAllocationType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavior_render_matches_show_table() {
        assert_eq!(SidBehavior::End.to_string(), "End");
        assert_eq!(SidBehavior::EndX.to_string(), "End.X");
    }

    #[test]
    fn context_none_renders_as_dash() {
        // Operators expect a literal '-' for End SIDs (no interface
        // binding); empty string would look like a missing field.
        assert_eq!(SidContext::None.to_string(), "-");
    }

    #[test]
    fn context_interface_quotes_the_name() {
        assert_eq!(
            SidContext::Interface("enp0s7".into()).to_string(),
            "Interface 'enp0s7'"
        );
    }

    #[test]
    fn owner_renders_with_instance_in_parens() {
        assert_eq!(SidOwner::new("isis", 0).to_string(), "isis(0)");
        assert_eq!(SidOwner::new("bgp", 1).to_string(), "bgp(1)");
    }

    #[test]
    fn allocation_type_renders_lowercase() {
        // Lower-case matches the FRR-style table in the design doc and
        // keeps the column narrow.
        assert_eq!(SidAllocationType::Dynamic.to_string(), "dynamic");
        assert_eq!(SidAllocationType::Explicit.to_string(), "explicit");
    }
}
