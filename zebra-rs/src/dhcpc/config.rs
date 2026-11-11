//! Configuration callbacks: `interface <if> ipv4 address dhcp`,
//! `interface <if> ipv4 dhcp-options …` and `system hostname`; for
//! DHCPv6, `interface <if> ipv6 address dhcpv6` and
//! `interface <if> ipv6 dhcpv6-options …`.
//!
//! A callback only records the leaf and marks the interface as touched;
//! [`Dhcpc::process_cm_msg`] applies everything at the end of the commit,
//! so `address dhcp` and the options committed with it take effect
//! together.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::config::{Args, ConfigOp};

use super::ident::parse_duid;
use super::inst::{Dhcpc, IfConfig};
use super::v6::inst::IfConfig6;

pub type Callback = fn(&mut Dhcpc, Args, ConfigOp) -> Option<()>;

const OPTIONS: &str = "/interface/ipv4/dhcp-options";
const OPTIONS6: &str = "/interface/ipv6/dhcpv6-options";

impl Dhcpc {
    pub fn callback_build(&mut self) {
        self.callbacks
            .insert("/interface/ipv4/address".to_string(), config_address);
        self.callbacks
            .insert("/system/hostname".to_string(), config_hostname);
        let options: [(&str, Callback); 8] = [
            ("/client-id", config_client_id),
            ("/host-name", config_host_name),
            ("/vendor-class-id", config_vendor_class_id),
            ("/user-class", config_user_class),
            ("/default-route-distance", config_distance),
            ("/no-default-route", config_no_default_route),
            ("/no-name-server", config_no_name_server),
            ("/reject", config_reject),
        ];
        for (leaf, callback) in options {
            self.callbacks.insert(format!("{OPTIONS}{leaf}"), callback);
        }
        self.callbacks
            .insert("/interface/ipv6/address".to_string(), config_address6);
        let options6: [(&str, Callback); 4] = [
            ("/duid", config_duid),
            ("/parameters-only", config_parameters_only),
            ("/rapid-commit", config_rapid_commit),
            ("/no-release", config_no_release),
        ];
        for (leaf, callback) in options6 {
            self.callbacks.insert(format!("{OPTIONS6}{leaf}"), callback);
        }
    }

    /// As [`Dhcpc::touch`], for the DHCPv6 configuration.
    fn touch6(&mut self, args: &mut Args) -> Option<&mut IfConfig6> {
        let name = args.string()?;
        self.v6.touched.push(name.clone());
        Some(&mut self.v6.ifaces.entry(name).or_default().cfg)
    }

    /// The configuration of the interface the callback names, created on
    /// first mention, and marked for [`Dhcpc::reconcile`].
    fn touch(&mut self, args: &mut Args) -> Option<&mut IfConfig> {
        let name = args.string()?;
        self.touched.push(name.clone());
        Some(&mut self.ifaces.entry(name).or_default().cfg)
    }
}

/// `interface <if> ipv4 address …`: only the `dhcp` value is ours; the
/// RIB handles the prefixes. A delete with no value removes every
/// address, `dhcp` included.
fn config_address(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let mut values = Vec::new();
    while let Some(value) = args.string() {
        values.push(value);
    }
    let dhcp = values.iter().any(|v| v == "dhcp");
    let enabled = match op {
        ConfigOp::Set if dhcp => true,
        ConfigOp::Delete if dhcp || values.is_empty() => false,
        _ => return Some(()),
    };
    // A delete for an interface never configured for DHCP is not ours.
    if !enabled && !dhcpc.ifaces.contains_key(&name) {
        return Some(());
    }
    dhcpc.touched.push(name.clone());
    dhcpc.ifaces.entry(name).or_default().cfg.enabled = enabled;
    Some(())
}

/// `interface <if> ipv6 address …`: only the `dhcpv6` value is ours; the
/// RIB handles the prefixes and the RA host `autoconf`. A delete with no
/// value removes every address, `dhcpv6` included.
fn config_address6(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let mut values = Vec::new();
    while let Some(value) = args.string() {
        values.push(value);
    }
    let dhcpv6 = values.iter().any(|v| v == "dhcpv6");
    let enabled = match op {
        ConfigOp::Set if dhcpv6 => true,
        ConfigOp::Delete if dhcpv6 || values.is_empty() => false,
        _ => return Some(()),
    };
    // A delete for an interface never configured for DHCPv6 is not ours.
    if !enabled && !dhcpc.v6.ifaces.contains_key(&name) {
        return Some(());
    }
    dhcpc.v6.touched.push(name.clone());
    dhcpc.v6.ifaces.entry(name).or_default().cfg.address = enabled;
    Some(())
}

fn config_duid(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch6(&mut args)?;
    // The schema has checked its form; one that does not parse all the
    // same leaves the system's DUID in use.
    cfg.duid = if op.is_set() {
        parse_duid(&args.string()?)
    } else {
        None
    };
    Some(())
}

fn config_parameters_only(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch6(&mut args)?;
    cfg.parameters_only = op.is_set();
    Some(())
}

fn config_rapid_commit(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch6(&mut args)?;
    cfg.rapid_commit = op.is_set();
    Some(())
}

fn config_no_release(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch6(&mut args)?;
    cfg.no_release = op.is_set();
    Some(())
}

fn config_hostname(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    dhcpc.hostname = if op.is_set() { args.string() } else { None };
    dhcpc.touch_all();
    Some(())
}

/// Option 61 from the CLI: `xx:xx:…` is the identifier's bytes as they
/// are; anything else is text, sent with type 0 (RFC 2132 §9.14).
pub fn parse_client_id(value: &str) -> Vec<u8> {
    let hex: Option<Vec<u8>> = value
        .split(':')
        .map(|part| {
            (part.len() == 2)
                .then(|| u8::from_str_radix(part, 16).ok())
                .flatten()
        })
        .collect();
    match hex {
        Some(bytes) if bytes.len() >= 2 => bytes,
        _ => {
            let mut id = vec![0];
            id.extend_from_slice(value.as_bytes());
            id
        }
    }
}

fn config_client_id(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch(&mut args)?;
    cfg.client_id = if op.is_set() {
        Some(parse_client_id(&args.string()?))
    } else {
        None
    };
    Some(())
}

fn config_host_name(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch(&mut args)?;
    cfg.host_name = if op.is_set() { args.string() } else { None };
    Some(())
}

fn config_vendor_class_id(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch(&mut args)?;
    cfg.vendor_class_id = if op.is_set() { args.string() } else { None };
    Some(())
}

fn config_user_class(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch(&mut args)?;
    cfg.user_class = if op.is_set() { args.string() } else { None };
    Some(())
}

fn config_distance(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch(&mut args)?;
    cfg.distance = if op.is_set() { args.u8() } else { None };
    Some(())
}

fn config_no_default_route(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch(&mut args)?;
    cfg.no_default_route = op.is_set();
    Some(())
}

fn config_no_name_server(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch(&mut args)?;
    cfg.no_name_server = op.is_set();
    Some(())
}

/// A server address, or a prefix of them.
fn parse_reject(value: &str) -> Option<Ipv4Net> {
    value
        .parse::<Ipv4Net>()
        .ok()
        .or_else(|| value.parse::<Ipv4Addr>().ok().map(Ipv4Net::from))
}

/// A leaf-list: each line carries one or more values; a delete with no
/// value clears the list.
fn config_reject(dhcpc: &mut Dhcpc, mut args: Args, op: ConfigOp) -> Option<()> {
    let cfg = dhcpc.touch(&mut args)?;
    let mut values = Vec::new();
    while let Some(value) = args.string() {
        values.extend(parse_reject(&value));
    }
    if op.is_set() {
        for net in values {
            if !cfg.reject.contains(&net) {
                cfg.reject.push(net);
            }
        }
    } else if values.is_empty() {
        cfg.reject.clear();
    } else {
        cfg.reject.retain(|net| !values.contains(net));
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_forms() {
        assert_eq!(parse_client_id("01:02:00:ff"), [1, 2, 0, 0xff]);
        // Text, including text that only looks a little like hex.
        assert_eq!(parse_client_id("wan"), [0, b'w', b'a', b'n']);
        assert_eq!(parse_client_id("ab"), [0, b'a', b'b']);
        assert_eq!(parse_client_id("1:2:3"), [0, b'1', b':', b'2', b':', b'3']);
    }

    #[test]
    fn reject_forms() {
        assert_eq!(parse_reject("192.0.2.66"), "192.0.2.66/32".parse().ok());
        assert_eq!(parse_reject("192.0.2.0/24"), "192.0.2.0/24".parse().ok());
        assert_eq!(parse_reject("nonsense"), None);
    }
}
