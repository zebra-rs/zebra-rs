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

/// One interface numbered from a delegated prefix (`dhcpv6-options pd
/// <id> interface`).
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LanView {
    pub interface: String,
    /// Its address in its /64 of the prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Why it has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One delegated prefix.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct PrefixView {
    pub prefix: String,
    /// Seconds left; `u32::MAX` never ends.
    pub preferred_in: u32,
    pub valid_in: u32,
    /// The interfaces configured to be numbered from it, in the order
    /// of their names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<LanView>,
}

/// One delegation asked for (`dhcpv6-options pd <id>`), with what is
/// held of it.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DelegationView {
    /// The IAID of its IA_PD.
    pub id: u32,
    /// Empty while nothing is delegated.
    pub prefixes: Vec<PrefixView>,
    /// Who the prefixes are leased from: a delegation can be another
    /// server's than the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_duid: Option<String>,
    /// Seconds, for this delegation; absent when it is never renewed,
    /// or holds nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renew_in: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebind_in: Option<u32>,
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
    /// The delegations asked for, in the order of their ids.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pd: Vec<DelegationView>,
    /// Seconds, until the first of anything leased is renewed; absent
    /// when the lease is never renewed.
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
        pd: vec![],
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
    view.pd = asks.ia_pd.iter().map(|pd| delegation(pd.iaid)).collect();
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
    for ia in &lease.ia_pd {
        // Each is one the client asked for.
        let Some(pd) = view.pd.iter_mut().find(|pd| pd.id == ia.iaid) else {
            continue;
        };
        pd.prefixes = ia
            .prefixes
            .iter()
            .map(|p| PrefixView {
                prefix: p.prefix.to_string(),
                preferred_in: p.preferred,
                valid_in: p.valid,
                interfaces: vec![],
            })
            .collect();
        pd.server_duid = Some(format_duid(&ia.server_id));
        pd.renew_in = (ia.t1 != u32::MAX).then_some(ia.t1);
        pd.rebind_in = (ia.t2 != u32::MAX).then_some(ia.t2);
    }
    // What each prefix gives the interfaces configured under its
    // delegation.
    for assignment in dhcpc.assignments6(iface, now) {
        let prefix = assignment.prefix.to_string();
        let pd = view.pd.iter_mut().find(|pd| pd.id == assignment.id);
        let held = pd.and_then(|pd| pd.prefixes.iter_mut().find(|p| p.prefix == prefix));
        let Some(held) = held else {
            continue;
        };
        held.interfaces.push(LanView {
            interface: assignment.ifname,
            address: assignment
                .address
                .ok()
                .map(|(_, address)| address.to_string()),
            reason: assignment.address.err().map(|reason| reason.to_string()),
        });
    }
    // The next Renew, and the next Rebind, of anything leased: each
    // identity association has its own times.
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

/// A delegation that holds nothing.
fn delegation(id: u32) -> DelegationView {
    DelegationView {
        id,
        prefixes: vec![],
        server_duid: None,
        renew_in: None,
        rebind_in: None,
    }
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
    // Each delegation asked for, with what it holds.
    let mut label = "Prefix:";
    for pd in &view.pd {
        for prefix in &pd.prefixes {
            writeln!(
                out,
                "  {label:<13} {} preferred {} valid {} (pd {})",
                prefix.prefix,
                lifetime(prefix.preferred_in),
                lifetime(prefix.valid_in),
                pd.id,
            )?;
            label = "";
            for lan in &prefix.interfaces {
                let on = format!("on {}:", lan.interface);
                match (&lan.address, &lan.reason) {
                    (Some(address), _) => writeln!(out, "    {on:<11} {address}")?,
                    (None, Some(reason)) => writeln!(out, "    {on:<11} none ({reason})")?,
                    (None, None) => {}
                }
            }
        }
        if pd.prefixes.is_empty() {
            writeln!(out, "  {label:<13} none (pd {})", pd.id)?;
            label = "";
        }
    }
    let leased = !view.addresses.is_empty() || view.pd.iter().any(|pd| !pd.prefixes.is_empty());
    if leased {
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
            pd: vec![],
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
    fn delegations_show_what_they_hold() {
        let held = DelegationView {
            prefixes: vec![
                PrefixView {
                    prefix: "2001:db8:100::/56".into(),
                    preferred_in: 3000,
                    valid_in: 6600,
                    interfaces: vec![
                        LanView {
                            interface: "lan0".into(),
                            address: Some("2001:db8:100:1::1/64".into()),
                            reason: None,
                        },
                        LanView {
                            interface: "a-long-name-1".into(),
                            address: None,
                            reason: Some("in another VRF".into()),
                        },
                    ],
                },
                PrefixView {
                    prefix: "2001:db8:200::/56".into(),
                    preferred_in: u32::MAX,
                    valid_in: u32::MAX,
                    interfaces: vec![],
                },
            ],
            server_duid: Some("00:03:00:01:02:00:00:00:00:fd".into()),
            renew_in: Some(1500),
            rebind_in: None,
            ..delegation(1)
        };
        // Prefixes only: no IAID, which names the address's association.
        let view = LeaseView6 {
            iaid: None,
            addresses: vec![],
            pd: vec![held, delegation(7)],
            dns_servers: vec![],
            domain_search: vec![],
            ntp_servers: vec![],
            ..bound()
        };
        let mut out = String::new();
        render(&view, &mut out).unwrap();
        assert_eq!(
            out,
            "Interface: wan0\n\
             \x20 VRF:          default\n\
             \x20 State:        bound\n\
             \x20 DUID:         00:01:00:01:32:85:1b:00:52:54:00:12:34:56\n\
             \x20 Server:       fe80::1\n\
             \x20 Server DUID:  00:03:00:01:02:00:00:00:00:fe\n\
             \x20 Prefix:       2001:db8:100::/56 preferred 3000s valid 6600s (pd 1)\n\
             \x20   on lan0:    2001:db8:100:1::1/64\n\
             \x20   on a-long-name-1: none (in another VRF)\n\
             \x20               2001:db8:200::/56 preferred forever valid forever (pd 1)\n\
             \x20               none (pd 7)\n\
             \x20 Renew in:     1200s\n\
             \x20 Rebind in:    never\n"
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(
            json["pd"],
            serde_json::json!([
                {
                    "id": 1,
                    "prefixes": [
                        {
                            "prefix": "2001:db8:100::/56",
                            "preferred_in": 3000,
                            "valid_in": 6600,
                            "interfaces": [
                                {"interface": "lan0", "address": "2001:db8:100:1::1/64"},
                                {"interface": "a-long-name-1", "reason": "in another VRF"},
                            ],
                        },
                        {
                            "prefix": "2001:db8:200::/56",
                            "preferred_in": u32::MAX,
                            "valid_in": u32::MAX,
                        },
                    ],
                    "server_duid": "00:03:00:01:02:00:00:00:00:fd",
                    "renew_in": 1500,
                },
                {"id": 7, "prefixes": []},
            ])
        );

        // Asked for and not held yet: the delegation is named all the
        // same, and nothing is to be renewed.
        let view = LeaseView6 {
            state: "soliciting".into(),
            iaid: None,
            server: None,
            server_duid: None,
            addresses: vec![],
            pd: vec![delegation(1)],
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
             \x20 Prefix:       none (pd 1)\n"
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
