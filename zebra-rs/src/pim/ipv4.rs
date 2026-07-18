//! The IPv4 [`PimAf`] marker. This slice sets only the associated
//! address / prefix types; the behavioural methods land with the
//! `Pim<A>` monomorphization.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use super::af::PimAf;

/// IPv4 address-family marker. The ordering / hash / default derives
/// are what let `#[derive(Ord, Hash, Default)]` on the generic data
/// types (which add an `A: …` bound) resolve for `A = Ipv4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4;

impl PimAf for Ipv4 {
    type Addr = Ipv4Addr;
    type Prefix = Ipv4Net;
}
