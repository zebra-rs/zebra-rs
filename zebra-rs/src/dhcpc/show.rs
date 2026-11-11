//! `show dhcp client leases [interface <if>]`.
//!
//! (`renew|release dhcp interface <if>` change state and are handled in
//! [`super::inst`]; they arrive on the same channel.)

use std::fmt::Write;
use std::time::Instant;

use serde::Serialize;

use crate::config::{Args, Builder};

use super::inst::{Dhcpc, Iface, ShowCallback, lifetime};
use super::routes::lease_routes;
use super::v6::show::show_leases6;

impl Dhcpc {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/dhcp/client/leases")
            .set(show_leases)
            .path("/show/dhcp/client/leases/interface")
            .set(show_leases)
            .path("/show/dhcpv6/client/leases")
            .set(show_leases6)
            .path("/show/dhcpv6/client/leases/interface")
            .set(show_leases6)
            .map();
    }
}

/// One interface's client, in the keys `show -j` keeps stable.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LeaseView {
    pub interface: String,
    pub vrf: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domain_search: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ntp_servers: Vec<String>,
    /// Seconds; absent for a lease that never expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renew_in: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebind_in: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u32>,
    /// UNIX time the lease began.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obtained: Option<u64>,
    /// Routes the lease installs, each `prefix via gateway`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_distance: Option<u8>,
}

fn strings<T: ToString>(items: &[T]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}

fn view(dhcpc: &Dhcpc, name: &str, iface: &Iface, now: Instant) -> LeaseView {
    let state = match &iface.client {
        // A saved lease on its way back to the server as the identity
        // that took it; the client for this interface starts after it.
        Some(_) if dhcpc.is_releasing(name) => "releasing".to_string(),
        Some(client) => client.state().to_string(),
        None if iface.ifindex.is_none() => "no link".to_string(),
        None => "stopped".to_string(),
    };
    let vrf = iface
        .ifindex
        .and_then(|ifindex| dhcpc.vrf_of(ifindex))
        .unwrap_or_else(|| "default".to_string());
    let mut view = LeaseView {
        interface: name.to_string(),
        vrf,
        state,
        address: None,
        server: None,
        gateway: None,
        dns_servers: vec![],
        domain_name: None,
        domain_search: vec![],
        ntp_servers: vec![],
        lease_time: None,
        renew_in: None,
        rebind_in: None,
        expires_in: None,
        obtained: None,
        routes: vec![],
        route_distance: None,
    };
    let Some(lease) = &iface.bound else {
        return view;
    };
    view.address = Some(lease.net().to_string());
    view.server = Some(lease.server_id.to_string());
    view.gateway = lease.routers.first().map(ToString::to_string);
    view.dns_servers = strings(&lease.dns_servers);
    view.domain_name = lease.domain_name.clone();
    view.domain_search = lease.domain_search.clone();
    view.ntp_servers = strings(&lease.ntp_servers);
    view.obtained = iface.obtained;
    if let Some((t1, t2, expiry)) = iface.client.as_ref().and_then(|c| c.remaining(now)) {
        view.lease_time = Some(lease.lease_time);
        view.renew_in = Some(t1);
        view.rebind_in = Some(t2);
        view.expires_in = Some(expiry);
    }
    let (routes, _) = lease_routes(lease, iface.cfg.no_default_route);
    view.routes = routes
        .iter()
        .map(|(prefix, gateway)| format!("{prefix} via {gateway}"))
        .collect();
    if !view.routes.is_empty() {
        view.route_distance = Some(iface.cfg.distance());
    }
    view
}

fn render(view: &LeaseView, out: &mut String) -> std::fmt::Result {
    writeln!(out, "Interface: {}", view.interface)?;
    writeln!(out, "  VRF:          {}", view.vrf)?;
    writeln!(out, "  State:        {}", view.state)?;
    let Some(address) = &view.address else {
        return Ok(());
    };
    writeln!(out, "  Address:      {address}")?;
    if let Some(server) = &view.server {
        writeln!(out, "  Server:       {server}")?;
    }
    if let Some(gateway) = &view.gateway {
        writeln!(out, "  Gateway:      {gateway}")?;
    }
    if !view.dns_servers.is_empty() {
        writeln!(out, "  DNS servers:  {}", view.dns_servers.join(", "))?;
    }
    if let Some(domain) = &view.domain_name {
        writeln!(out, "  Domain:       {domain}")?;
    }
    if !view.domain_search.is_empty() {
        writeln!(out, "  Search:       {}", view.domain_search.join(", "))?;
    }
    if !view.ntp_servers.is_empty() {
        writeln!(out, "  NTP servers:  {}", view.ntp_servers.join(", "))?;
    }
    match (
        view.lease_time,
        view.renew_in,
        view.rebind_in,
        view.expires_in,
    ) {
        (Some(lease), Some(t1), Some(t2), Some(expiry)) => {
            writeln!(out, "  Lease time:   {}", lifetime(lease))?;
            writeln!(out, "  Renew in:     {}", lifetime(t1))?;
            writeln!(out, "  Rebind in:    {}", lifetime(t2))?;
            writeln!(out, "  Expires in:   {}", lifetime(expiry))?;
        }
        _ => writeln!(out, "  Lease time:   forever")?,
    }
    if let Some(distance) = view.route_distance {
        let mut label = "Routes:";
        for route in &view.routes {
            writeln!(out, "  {label:<13} {route} [{distance}]")?;
            label = "";
        }
    }
    Ok(())
}

/// Every configured interface, or the one named.
fn show_leases(dhcpc: &Dhcpc, mut args: Args, json: bool) -> Result<String, std::fmt::Error> {
    let only = args.string();
    let now = Instant::now();
    let views: Vec<LeaseView> = dhcpc
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
        return Ok(format!("No DHCP client on {only}\n"));
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

    fn bound() -> LeaseView {
        LeaseView {
            interface: "wan0".into(),
            vrf: "default".into(),
            state: "bound".into(),
            address: Some("192.0.2.100/24".into()),
            server: Some("192.0.2.1".into()),
            gateway: Some("192.0.2.1".into()),
            dns_servers: vec!["198.51.100.53".into(), "198.51.100.54".into()],
            domain_name: Some("example.com".into()),
            domain_search: vec![],
            ntp_servers: vec![],
            lease_time: Some(3600),
            renew_in: Some(1790),
            rebind_in: Some(3140),
            expires_in: Some(3590),
            obtained: Some(1_800_000_000),
            routes: vec![
                "0.0.0.0/0 via 192.0.2.1".into(),
                "10.0.0.0/8 via 192.0.2.2".into(),
            ],
            route_distance: Some(210),
        }
    }

    #[test]
    fn text_view() {
        let mut out = String::new();
        render(&bound(), &mut out).unwrap();
        assert_eq!(
            out,
            "\
Interface: wan0
  VRF:          default
  State:        bound
  Address:      192.0.2.100/24
  Server:       192.0.2.1
  Gateway:      192.0.2.1
  DNS servers:  198.51.100.53, 198.51.100.54
  Domain:       example.com
  Lease time:   3600s
  Renew in:     1790s
  Rebind in:    3140s
  Expires in:   3590s
  Routes:       0.0.0.0/0 via 192.0.2.1 [210]
                10.0.0.0/8 via 192.0.2.2 [210]
"
        );

        // Without a lease only the state is known.
        let mut idle = bound();
        idle.state = "selecting".into();
        idle.address = None;
        let mut out = String::new();
        render(&idle, &mut out).unwrap();
        assert_eq!(
            out,
            "Interface: wan0\n  VRF:          default\n  State:        selecting\n"
        );
    }

    #[test]
    fn json_view_omits_what_is_unknown() {
        let mut view = bound();
        view.domain_name = None;
        view.lease_time = None;
        view.renew_in = None;
        view.rebind_in = None;
        view.expires_in = None;
        let json: serde_json::Value = serde_json::to_value(&view).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "interface",
                "vrf",
                "state",
                "address",
                "server",
                "gateway",
                "dns_servers",
                "obtained",
                "routes",
                "route_distance"
            ]
        );
    }
}
