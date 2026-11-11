//! The host's own resolver, as far as zebra-rs feeds it
//! (docs/design/dhcp-client.md §13).
//!
//! `system name-server dhcp <if>` names the interfaces whose learned name
//! servers the host itself is to use. Whoever learns name servers on an
//! interface (the DHCP client, the RA host) reports them here, whether
//! or not the interface is named. One task, [`inst::Resolver`], holds the
//! configuration and hands the named interfaces' servers and search
//! domains to systemd-resolved as that link's DNS configuration
//! ([`resolvectl`]), and takes them back when the source loses them or
//! the entry is deleted. zebra-rs never writes resolv.conf.

pub mod inst;
pub mod resolvectl;

use std::net::IpAddr;

use tokio::sync::mpsc::UnboundedSender;

/// The name servers and search domains of one interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkDns {
    pub servers: Vec<IpAddr>,
    pub domains: Vec<String>,
}

/// Who learned them. An interface can have several sources at once;
/// their servers are used in this order: what DHCP says goes ahead of
/// what Router Advertisements say (RFC 8106 §5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Dhcp4,
    /// RDNSS and DNSSL options (RFC 8106), from the RA host.
    Ra,
}

/// What `source` now knows of `ifname`: `None` when that is nothing (any
/// more).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub ifname: String,
    pub source: Source,
    pub dns: Option<LinkDns>,
}

/// Where the sources send their reports.
pub type ResolverTx = UnboundedSender<Report>;
