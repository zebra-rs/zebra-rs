//! `show dhcpv6 client leases [interface <if>]`.
//!
//! (`renew|release dhcpv6 interface <if>` change state and are handled
//! in [`super::inst`]; they arrive on the same channel.)

use std::fmt::Write;
use std::time::Instant;

use serde::Serialize;

use crate::config::Args;
use crate::dhcpc::ident::format_duid;
use crate::dhcpc::inst::{Dhcpc, lifetime};

use super::client::Ntp;
use super::inst::Iface6;

/// One address of a lease.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AddressView {
    pub address: String,
    /// Seconds left; `u32::MAX` never ends.
    pub preferred_in: u32,
    pub valid_in: u32,
}

/// One interface's client, in the keys `show -j` keeps stable.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LeaseView6 {
    pub interface: String,
    pub vrf: String,
    pub state: String,
    /// Who the client is to a server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iaid: Option<u32>,
    /// Where the server's messages come from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_duid: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<AddressView>,
    /// Seconds; absent when the lease is never renewed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renew_in: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebind_in: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domain_search: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ntp_servers: Vec<String>,
    /// UNIX time a server last confirmed the lease.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obtained: Option<u64>,
}

fn view(dhcpc: &Dhcpc, name: &str, iface: &Iface6, now: Instant) -> LeaseView6 {
    let state = match &iface.session {
        Some(session) => session.client.state().to_string(),
        None if iface.ifindex.is_none() => "no link".to_string(),
        None => "stopped".to_string(),
    };
    let vrf = iface
        .ifindex
        .and_then(|ifindex| dhcpc.vrf_of(ifindex))
        .unwrap_or_else(|| "default".to_string());
    let mut view = LeaseView6 {
        interface: name.to_string(),
        vrf,
        state,
        duid: None,
        iaid: None,
        server: None,
        server_duid: None,
        addresses: vec![],
        renew_in: None,
        rebind_in: None,
        dns_servers: vec![],
        domain_search: vec![],
        ntp_servers: vec![],
        obtained: None,
    };
    let Some(session) = &iface.session else {
        return view;
    };
    let (duid, asks) = session.client.identity();
    view.duid = Some(format_duid(duid));
    // The IAID names the IA_NA: a client that asks for no address has
    // none.
    view.iaid = asks.ia_na;
    // What is in the RIB, with the time it has left now.
    let Some(lease) = session
        .bound
        .as_ref()
        .and_then(|_| session.client.lease(now))
    else {
        return view;
    };
    view.server = Some(lease.server_address.to_string());
    view.server_duid = Some(format_duid(&lease.server_id));
    if let Some(ia) = &lease.ia_na {
        view.addresses = ia
            .addresses
            .iter()
            .map(|a| AddressView {
                address: format!("{}/128", a.address),
                preferred_in: a.preferred,
                valid_in: a.valid,
            })
            .collect();
    }
    // One Renew, and one Rebind, is for everything leased: at the
    // earliest time any of it asks for.
    if lease.has_leases() {
        let (t1, t2) = lease.renewal();
        view.renew_in = (t1 != u32::MAX).then_some(t1);
        view.rebind_in = (t2 != u32::MAX).then_some(t2);
    }
    view.dns_servers = lease.dns_servers.iter().map(ToString::to_string).collect();
    view.domain_search = lease.domain_list.clone();
    view.ntp_servers = lease
        .ntp_servers
        .iter()
        .map(|server| match server {
            Ntp::Address(address) | Ntp::Multicast(address) => address.to_string(),
            Ntp::Fqdn(name) => name.clone(),
        })
        .collect();
    view.obtained = session.obtained;
    view
}

fn render(view: &LeaseView6, out: &mut String) -> std::fmt::Result {
    writeln!(out, "Interface: {}", view.interface)?;
    writeln!(out, "  VRF:          {}", view.vrf)?;
    writeln!(out, "  State:        {}", view.state)?;
    if let Some(duid) = &view.duid {
        writeln!(out, "  DUID:         {duid}")?;
    }
    if let Some(iaid) = view.iaid {
        writeln!(out, "  IAID:         {iaid}")?;
    }
    if let Some(server) = &view.server {
        writeln!(out, "  Server:       {server}")?;
    }
    if let Some(duid) = &view.server_duid {
        writeln!(out, "  Server DUID:  {duid}")?;
    }
    let mut label = "Address:";
    for address in &view.addresses {
        writeln!(
            out,
            "  {label:<13} {} preferred {} valid {}",
            address.address,
            lifetime(address.preferred_in),
            lifetime(address.valid_in),
        )?;
        label = "";
    }
    if !view.addresses.is_empty() {
        let or_never = |time: Option<u32>| time.map_or("never".to_string(), lifetime);
        writeln!(out, "  Renew in:     {}", or_never(view.renew_in))?;
        writeln!(out, "  Rebind in:    {}", or_never(view.rebind_in))?;
    }
    if !view.dns_servers.is_empty() {
        writeln!(out, "  DNS servers:  {}", view.dns_servers.join(", "))?;
    }
    if !view.domain_search.is_empty() {
        writeln!(out, "  Search:       {}", view.domain_search.join(", "))?;
    }
    if !view.ntp_servers.is_empty() {
        writeln!(out, "  NTP servers:  {}", view.ntp_servers.join(", "))?;
    }
    Ok(())
}

/// Every configured interface, or the one named.
pub fn show_leases6(dhcpc: &Dhcpc, mut args: Args, json: bool) -> Result<String, std::fmt::Error> {
    let only = args.string();
    let now = Instant::now();
    let views: Vec<LeaseView6> = dhcpc
        .v6
        .ifaces
        .iter()
        .filter(|(name, _)| only.as_ref().is_none_or(|only| only == *name))
        .map(|(name, iface)| view(dhcpc, name, iface, now))
        .collect();
    if json {
        return Ok(
            serde_json::to_string_pretty(&views).unwrap_or_else(|_| "[]".to_string()) + "\n",
        );
    }
    if let (Some(only), true) = (&only, views.is_empty()) {
        return Ok(format!("No DHCPv6 client on {only}\n"));
    }
    if views.is_empty() {
        return Ok("DHCPv6 client is not configured\n".to_string());
    }
    let mut out = String::new();
    for (i, view) in views.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        render(view, &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound() -> LeaseView6 {
        LeaseView6 {
            interface: "wan0".into(),
            vrf: "default".into(),
            state: "bound".into(),
            duid: Some("00:01:00:01:32:85:1b:00:52:54:00:12:34:56".into()),
            iaid: Some(1_194_042_915),
            server: Some("fe80::1".into()),
            server_duid: Some("00:03:00:01:02:00:00:00:00:fe".into()),
            addresses: vec![
                AddressView {
                    address: "2001:db8:1::100/128".into(),
                    preferred_in: 3000,
                    valid_in: 6600,
                },
                AddressView {
                    address: "2001:db8:1::200/128".into(),
                    preferred_in: u32::MAX,
                    valid_in: u32::MAX,
                },
            ],
            renew_in: Some(1200),
            rebind_in: None,
            dns_servers: vec!["2001:db8::53".into(), "2001:db8::35".into()],
            domain_search: vec!["example.com".into()],
            ntp_servers: vec!["ntp.example.com".into()],
            obtained: Some(1_794_268_800),
        }
    }

    #[test]
    fn a_bound_client_shows_its_lease() {
        let mut out = String::new();
        render(&bound(), &mut out).unwrap();
        assert_eq!(
            out,
            "Interface: wan0\n\
             \x20 VRF:          default\n\
             \x20 State:        bound\n\
             \x20 DUID:         00:01:00:01:32:85:1b:00:52:54:00:12:34:56\n\
             \x20 IAID:         1194042915\n\
             \x20 Server:       fe80::1\n\
             \x20 Server DUID:  00:03:00:01:02:00:00:00:00:fe\n\
             \x20 Address:      2001:db8:1::100/128 preferred 3000s valid 6600s\n\
             \x20               2001:db8:1::200/128 preferred forever valid forever\n\
             \x20 Renew in:     1200s\n\
             \x20 Rebind in:    never\n\
             \x20 DNS servers:  2001:db8::53, 2001:db8::35\n\
             \x20 Search:       example.com\n\
             \x20 NTP servers:  ntp.example.com\n"
        );
    }

    #[test]
    fn a_client_without_a_lease_shows_who_it_is() {
        let view = LeaseView6 {
            state: "soliciting".into(),
            server: None,
            server_duid: None,
            addresses: vec![],
            renew_in: None,
            dns_servers: vec![],
            domain_search: vec![],
            ntp_servers: vec![],
            obtained: None,
            ..bound()
        };
        let mut out = String::new();
        render(&view, &mut out).unwrap();
        assert_eq!(
            out,
            "Interface: wan0\n\
             \x20 VRF:          default\n\
             \x20 State:        soliciting\n\
             \x20 DUID:         00:01:00:01:32:85:1b:00:52:54:00:12:34:56\n\
             \x20 IAID:         1194042915\n"
        );
        // The stable keys, with what is not there left out.
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "interface": "wan0",
                "vrf": "default",
                "state": "soliciting",
                "duid": "00:01:00:01:32:85:1b:00:52:54:00:12:34:56",
                "iaid": 1_194_042_915u32,
            })
        );
    }

    #[test]
    fn parameters_show_without_an_address() {
        let view = LeaseView6 {
            state: "informed".into(),
            iaid: None,
            addresses: vec![],
            renew_in: None,
            ..bound()
        };
        let mut out = String::new();
        render(&view, &mut out).unwrap();
        assert_eq!(
            out,
            "Interface: wan0\n\
             \x20 VRF:          default\n\
             \x20 State:        informed\n\
             \x20 DUID:         00:01:00:01:32:85:1b:00:52:54:00:12:34:56\n\
             \x20 Server:       fe80::1\n\
             \x20 Server DUID:  00:03:00:01:02:00:00:00:00:fe\n\
             \x20 DNS servers:  2001:db8::53, 2001:db8::35\n\
             \x20 Search:       example.com\n\
             \x20 NTP servers:  ntp.example.com\n"
        );
    }
}
