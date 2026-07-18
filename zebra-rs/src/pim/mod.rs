//! PIM-SM (RFC 7761). Phase 2: instance skeleton — Hello, neighbors,
//! DR election. Architecture: docs/design/pim-sm-ssm-architecture.md.

pub mod assert_fsm;
pub mod config;
pub mod igmp;
pub mod inst;
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
