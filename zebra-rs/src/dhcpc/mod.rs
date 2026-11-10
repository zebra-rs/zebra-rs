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
//!
//! DHCPv6 (P3 of the design) has its protocol half so far, which the task
//! does not run yet:
//!
//! - [`v6::client`]: the RFC 8415 state machine, without I/O.
//! - [`ident`]: the system DUID and the IAIDs.

pub mod config;
// Not called until the task runs the DHCPv6 client (the socket, the RIB
// and the configuration are the next step of P3).
#[allow(dead_code)]
pub mod ident;
pub mod inst;
pub mod lease;
pub mod routes;
pub mod show;
pub mod v4;
#[allow(dead_code)]
pub mod v6;
