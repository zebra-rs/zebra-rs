// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

//! Segment Routing global configuration. Owns the SRGB/SRLB label blocks
//! (SR-MPLS) and SRv6 locators that the per-protocol modules (IS-IS, OSPF,
//! BGP-LU, ...) reference by name. The RIB is the natural owner because it
//! tracks the install state for both the SID/label space and the routes
//! that consume them.

pub mod block;
pub use block::{Block, BlockBuilder, BlockConfig, DEFAULT_BLOCK_NAME};

pub mod locator;
pub use locator::{Locator, LocatorBehavior, LocatorBuilder, LocatorConfig};

pub mod sid;
// PR 2 wires up the IS-IS allocators that consume these types; until
// then only the show callback reaches into `Sid` and these helper
// types stay technically unused at the crate boundary.
#[allow(unused_imports)]
pub use sid::{Sid, SidAllocationType, SidBehavior, SidContext, SidOwner, SidStructure};

/// Subscription-channel return type from RIB to a protocol module.
/// `block: None` / `locator: None` signals deletion (or "doesn't exist
/// yet" if the protocol asked for a name that hasn't been configured).
///
/// The variants carry `#[allow(dead_code)]` until PR 2 of this branch
/// wires the IS-IS-side consumer that destructures them.
#[allow(dead_code)]
#[derive(Debug)]
pub enum RibSrRx {
    Block {
        name: String,
        block: Option<Block>,
    },
    Locator {
        name: String,
        locator: Option<Locator>,
    },
}
