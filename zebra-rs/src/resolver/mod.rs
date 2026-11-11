//! The host's own resolver, as far as zebra-rs feeds it
//! (docs/design/dhcp-client.md §13).
//!
//! The name servers an interface learns are the host's to use, as its
//! leased address and its routes are. Whoever learns them (the DHCP
//! client, for DHCPv4 and for DHCPv6, and the RA host) reports them
//! here, unless its own configuration keeps them back (`interface <if>
//! ipv4 dhcp-options no-name-server`, `ipv6 dhcpv6-options
//! no-name-server`, `ipv6 ra-options no-name-server`). One task,
//! [`inst::Resolver`], hands each interface's servers and search domains
//! to systemd-resolved as that link's DNS configuration
//! ([`resolvectl`]), and takes them back when the sources lose them.
//! zebra-rs never writes resolv.conf.

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
/// what Router Advertisements say (RFC 8106 §5.3.1), and a DHCPv4 lease
/// ahead of a DHCPv6 one, as systemd-networkd has them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// A DHCPv4 lease (options 6, 15 and 119).
    Dhcp4,
    /// A DHCPv6 lease, or what `parameters-only` was given without one
    /// (options 23 and 24).
    Dhcp6,
    /// RDNSS and DNSSL options (RFC 8106), from the RA host.
    Ra,
}

/// What `source` now has on `ifname` for the host to use: `None` when
/// that is nothing (any more).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub ifname: String,
    pub source: Source,
    pub dns: Option<LinkDns>,
}

/// Where the sources send their reports.
pub type ResolverTx = UnboundedSender<Report>;
