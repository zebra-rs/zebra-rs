//! PIM-SM (RFC 7761). Architecture:
//! docs/design/pim-sm-ssm-architecture.md and (IPv6 arc)
//! docs/design/pim-ipv6-architecture.md.
//!
//! The protocol data model is generic over the address family
//! ([`af::PimAf`]); the type parameter defaults to [`ipv4::Ipv4`] so
//! the concrete IPv4 engine reads unchanged while the IPv6 arc
//! monomorphizes a second instance.

pub mod af;
pub mod assert_fsm;
pub mod bsr;
pub mod config;
pub mod gm;
pub mod inst;
pub mod ipv4;
pub mod jp;
pub mod link;
pub mod macros;
pub mod mroute;
pub mod neighbor;
pub mod network;
pub mod register;
pub mod rp;
pub mod rpf;
pub mod show;
pub mod socket;
pub mod tib;
pub mod vrf;
