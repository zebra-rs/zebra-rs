// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

//! SRv6 SID allocation registry. Each entry is one SID address that some
//! protocol (IS-IS, OSPF, BGP) has carved out of a locator and is now
//! advertising as End / End.X / End.DT4 / etc. The RIB is the central
//! registry so `show segment-routing srv6 sid` has a single source of
//! truth across protocols.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use ipnet::Ipv6Net;

/// SRv6 endpoint behavior for an allocated SID. RFC 8986 base set plus
/// the RFC 9800 NEXT-C-SID (uSID) variants we install today; other
/// behaviors (End.DT4, End.DT6, End.B6, ...) extend the enum.
///
/// `#[allow(dead_code)]` on the type until PR 2 starts populating the
/// registry; the show callback already discriminates on every variant
/// so no individual variant carries the attribute.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum SidBehavior {
    /// Plain End — RFC 8986 §4.1, "node SID". The SID identifies the
    /// owner node; no per-link context.
    End,
    /// End.X — RFC 8986 §4.2, "L3 cross-connect" / adjacency SID.
    /// Bound to a specific outgoing interface and neighbor.
    EndX,
    /// uN — RFC 9800 NEXT-C-SID flavor of End. Same host-local
    /// processing semantics; the kernel additionally shifts the
    /// destination address by `ln + fun` bits before passing the
    /// packet on. Carries a [`SidStructure`] so the FIB knows the
    /// shift width.
    UN,
    /// uA — RFC 9800 NEXT-C-SID flavor of End.X. Same per-adjacency
    /// forwarding as End.X with the additional uSID shift; carries a
    /// [`SidStructure`].
    UA,
    /// End.DT4 — RFC 8986 §4.6. Decapsulates and looks up the inner
    /// IPv4 packet in a configured table. Today only operator-
    /// configured static routes use it; the table-id arg isn't
    /// modeled yet (always uses the route's table at install time).
    EndDT4,
    /// End.DT6 — RFC 8986 §4.7. Decapsulates and looks up the inner
    /// IPv6 packet in a configured table. Same caveat as End.DT4.
    EndDT6,
}

impl fmt::Display for SidBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::End => write!(f, "End"),
            Self::EndX => write!(f, "End.X"),
            Self::UN => write!(f, "uN"),
            Self::UA => write!(f, "uA"),
            Self::EndDT4 => write!(f, "End.DT4"),
            Self::EndDT6 => write!(f, "End.DT6"),
        }
    }
}

impl FromStr for SidBehavior {
    type Err = SidBehaviorParseError;

    /// Accept the canonical `Display` strings used in the YANG enum.
    /// Case-sensitive — keep operator config matching the spec
    /// spelling rather than papering over typos.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "End" => Ok(Self::End),
            "End.X" => Ok(Self::EndX),
            "uN" => Ok(Self::UN),
            "uA" => Ok(Self::UA),
            "End.DT4" => Ok(Self::EndDT4),
            "End.DT6" => Ok(Self::EndDT6),
            other => Err(SidBehaviorParseError(other.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct SidBehaviorParseError(pub String);

impl fmt::Display for SidBehaviorParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown SRv6 endpoint behavior: {:?}", self.0)
    }
}

impl std::error::Error for SidBehaviorParseError {}

/// SRv6 SID Structure (RFC 9352 §9): how the 128-bit SID is partitioned
/// into Locator-Block / Locator-Node / Function / Argument bits.
/// Required to install a uSID SID into the kernel because the
/// `seg6local` NEXT-C-SID flavor needs Lblen / Nflen attributes to
/// know what to shift; classic End / End.X don't carry one.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidStructure {
    pub lb_bits: u8,
    pub ln_bits: u8,
    pub fun_bits: u8,
    pub arg_bits: u8,
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
///
/// `ifindex` and `nh6` carry the install hints the FIB needs:
///   - End: `ifindex` is the loopback (the action is purely local
///     processing, but the kernel rejects seg6local routes without an
///     output device); `nh6` is `None`.
///   - End.X: `ifindex` is the outgoing link, `nh6` is the IPv6 link-
///     local of the neighbor.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    pub addr: Ipv6Addr,
    pub behavior: SidBehavior,
    pub context: SidContext,
    pub owner: SidOwner,
    pub locator: String,
    pub allocation_type: SidAllocationType,
    pub ifindex: u32,
    pub nh6: Option<Ipv6Addr>,
    /// Partitioning of the SID's bits. Required for `UN`/`UA`; ignored
    /// for classic `End`/`EndX` (left `None`).
    pub structure: Option<SidStructure>,
}

impl Sid {
    /// IPv6 prefix the FIB / RIB indexes this SID under. End / End.X /
    /// uA install at /128; uN is a *prefix* install (the locator's
    /// LB+LN portion) so the NEXT-CSID flavor matches every function
    /// value beneath it. Returns `Ipv6Net::new(addr, 128)` as a
    /// degenerate-fallback for uN without a SidStructure — that
    /// shouldn't happen in practice, but a /128 keeps the FIB and RIB
    /// in lock-step instead of one tracking the locator and the
    /// other tracking the host address.
    pub fn prefix(&self) -> Ipv6Net {
        match self.behavior {
            SidBehavior::End
            | SidBehavior::EndX
            | SidBehavior::UA
            | SidBehavior::EndDT4
            | SidBehavior::EndDT6 => Ipv6Net::new(self.addr, 128).expect("/128 is always valid"),
            SidBehavior::UN => {
                let plen = self
                    .structure
                    .map(|s| s.lb_bits.saturating_add(s.ln_bits))
                    .unwrap_or(128);
                let masked = mask_v6(self.addr, plen);
                Ipv6Net::new(masked, plen)
                    .unwrap_or_else(|_| Ipv6Net::new(self.addr, 128).expect("/128 is always valid"))
            }
        }
    }
}

/// Zero the lower (128 - prefix_len) bits of `addr`.
fn mask_v6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if prefix_len >= 128 {
        return addr;
    }
    let bits = u128::from(addr);
    let shift = 128 - u32::from(prefix_len);
    let mask = !0u128 << shift;
    Ipv6Addr::from(bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavior_render_matches_show_table() {
        assert_eq!(SidBehavior::End.to_string(), "End");
        assert_eq!(SidBehavior::EndX.to_string(), "End.X");
        assert_eq!(SidBehavior::EndDT4.to_string(), "End.DT4");
        assert_eq!(SidBehavior::EndDT6.to_string(), "End.DT6");
    }

    #[test]
    fn behavior_round_trips_from_str() {
        // The static route YANG enum and the Display strings must stay
        // in sync — every value the YANG accepts must parse back.
        for variant in [
            SidBehavior::End,
            SidBehavior::EndX,
            SidBehavior::UN,
            SidBehavior::UA,
            SidBehavior::EndDT4,
            SidBehavior::EndDT6,
        ] {
            let s = variant.to_string();
            let parsed: SidBehavior = s.parse().expect("round-trip");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn behavior_unknown_string_is_error() {
        assert!("End.DT1".parse::<SidBehavior>().is_err());
        assert!("end".parse::<SidBehavior>().is_err()); // case-sensitive
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
