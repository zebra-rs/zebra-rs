//! The DHCP client (docs/design/dhcp-client.md).
//!
//! One task, [`inst::Dhcpc`], runs a client per interface configured with
//! `interface <if> ipv4 address dhcp`, and one per interface configured
//! with `interface <if> ipv6 address dhcpv6` or `… ipv6 dhcpv6-options
//! parameters-only`. Everything a lease produces goes through the RIB:
//! the address as a dynamic address (`Message::AddrDynAdd`), a DHCPv4
//! lease's routes as `RibType::DhcpClient` entries.
//!
//! - [`v4::client`]: the RFC 2131 state machine, without I/O.
//! - [`v4::socket`], [`v4::frame`]: the packet, ARP and UDP sockets.
//! - [`routes`]: lease routes gathered into RIB entries.
//! - [`lease`]: leases kept across a restart.
//! - [`config`], [`show`]: the configuration callbacks and
//!   `show dhcp client leases`, `renew|release dhcp interface <if>`.
//!
//! DHCPv6:
//!
//! - [`v6::client`]: the RFC 8415 state machine, without I/O.
//! - [`v6::socket`]: the UDP socket.
//! - [`v6::inst`]: the clients in the task, beside the DHCPv4 ones.
//! - [`v6::show`]: `show dhcpv6 client leases`.
//! - [`ident`]: the system DUID and the IAIDs.

pub mod config;
pub mod ident;
pub mod inst;
pub mod lease;
pub mod routes;
pub mod show;
pub mod v4;
pub mod v6;
