// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

//! Segment Routing global configuration. Owns the SRGB/SRLB label blocks
//! (SR-MPLS) and SRv6 locators that the per-protocol modules (IS-IS, OSPF,
//! BGP-LU, ...) reference by name. The RIB is the natural owner because it
//! tracks the install state for both the SID/label space and the routes
//! that consume them.

pub mod block;
pub use block::{Block, BlockBuilder, BlockConfig};

pub mod locator;
pub use locator::{Locator, LocatorBuilder, LocatorConfig};
