//! The PIM address-family abstraction. The protocol data model is
//! generic over `A: PimAf`; one `Pim<A>` instance will be
//! monomorphized per `(VRF, AF)`.
//!
//! This first slice carries only the associated address / prefix
//! types — enough to parameterize every state type over the address
//! family. The behavioural methods (classification, prefix ops,
//! checksum context, transports, membership codec) arrive with the
//! `Pim<A>` monomorphization slice, alongside the generic logic that
//! calls them, so no trait method is ever dead.
//!
//! `ipnet` has no trait unifying `Ipv4Net`/`Ipv6Net`, which is why
//! prefix behaviour will live on this trait rather than on bounds of
//! the prefix type. `A` defaults to [`super::ipv4::Ipv4`] everywhere
//! so the concrete IPv4 engine reads unchanged.

use std::fmt::{Debug, Display};
use std::hash::Hash;

use serde::Serialize;

/// Marker + associated types for one PIM address family.
pub trait PimAf: Copy + Eq + Ord + Hash + Debug + Send + Sync + Sized + 'static {
    /// A router-wide protocol address (source, group, RP, neighbor).
    type Addr: Copy + Ord + Eq + Hash + Display + Debug + Send + Sync + Serialize + 'static;
    /// A multicast / RP group range.
    type Prefix: Copy + Eq + Ord + Display + Debug + Send + Sync + 'static;
}
