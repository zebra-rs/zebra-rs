//! The DHCP client (docs/design/dhcp-client.md).
//!
//! One task, [`inst::Dhcpc`], runs a client per interface configured with
//! `interface <if> ipv4 address dhcp`. Everything a lease produces goes
//! through the RIB: the address as a dynamic address
//! (`Message::AddrDynAdd`), its routes as `RibType::DhcpClient` entries.
//!
//! - [`v4::client`]: the RFC 2131 state machine, without I/O.
//! - [`v4::socket`], [`v4::frame`]: the packet, ARP and UDP sockets.
//! - [`routes`]: lease routes gathered into RIB entries.
//! - [`lease`]: leases kept across a restart.
//! - [`config`], [`show`]: the configuration callbacks and
//!   `show dhcp client leases`, `renew|release dhcp interface <if>`.

pub mod config;
pub mod inst;
pub mod lease;
pub mod routes;
pub mod show;
pub mod v4;
