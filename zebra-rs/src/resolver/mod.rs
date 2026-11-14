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
//! ([`resolvectl`]), and takes them back when the sources lose them,
//! also what a run before this one set ([`record`]).
//! zebra-rs never writes resolv.conf.

pub mod inst;
pub mod record;
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

/// What `source` now has for the host to use on the interface of that
/// index: `None` when that is nothing (any more).
///
/// A source says the interface it runs on, not what that is called. It
/// has the index from the RIB, with the link its sockets, its address
/// and its routes are on, and the system resolver keeps an interface's
/// settings by that index. So the name servers stay with the lease they
/// came with through a change of name, and no name is looked up between
/// here and the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub ifindex: u32,
    pub source: Source,
    pub dns: Option<LinkDns>,
}

/// Where the sources send their reports.
pub type ResolverTx = UnboundedSender<Report>;
