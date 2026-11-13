//! Commit-time checks on leaf values the schema cannot constrain.
//!
//! A protocol's config callback cannot reject a value. By the time it
//! runs the commit has been dispatched, and its return is ignored. A
//! value the schema lets through therefore lands in the running config
//! while the protocol quietly keeps its previous setting. Any constraint
//! YANG cannot carry here is checked below, before anything is
//! dispatched: a step (YANG has none), or a decimal64 range or
//! `fraction-digits` (libyang extracts neither).

use crate::bgp::ethernet_segment::check_es_esi;
use crate::flex_algo::check_max_link_loss;
use crate::stamp::session::{check_loss_interval, check_loss_percent};

/// The E-Tree leaf-AC list (`router bgp afi-safi evpn etree
/// leaf-interface <name>`), as a callback path.
pub const ETREE_LEAF_PATH: &str = "/router/bgp/afi-safi/etree/leaf-interface";

/// The leaves that turn the cradle data plane on: the managed engine, or
/// the tee to an external one.
const CRADLE_ENABLED_PATHS: [&str; 2] = ["/system/ebpf/enabled", "/system/cradle/enabled"];

/// Whether a config line can carry a leaf [`etree_backend`] reads, so the
/// caller parses only those.
pub fn etree_backend_line(line: &str) -> bool {
    line.contains(" etree leaf-interface ")
        || line.starts_with("system ebpf enabled ")
        || line.starts_with("system cradle enabled ")
}

/// An E-Tree leaf AC needs the cradle data plane: only cradle keeps a leaf
/// from another leaf. The kernel bridge cannot drop by a remote MAC's
/// colour, and a leaf left unisolated is a leak of what E-Tree exists to
/// keep apart (RFC 8317 §7). `leaves` are a whole config's
/// [`etree_backend_line`]s as (callback path, arguments); the result is
/// one error per leaf AC when neither switch is on.
pub fn etree_backend(leaves: &[(String, Vec<String>)]) -> Vec<String> {
    let cradle = leaves.iter().any(|(path, args)| {
        CRADLE_ENABLED_PATHS.contains(&path.as_str())
            && args.last().map(String::as_str) == Some("true")
    });
    if cradle {
        return Vec::new();
    }
    leaves
        .iter()
        .filter(|(path, _)| path == ETREE_LEAF_PATH)
        .filter_map(|(_, args)| args.last())
        .map(|name| {
            format!(
                "etree leaf-interface {name}: E-Tree needs the cradle data plane \
                 (`system ebpf enabled` or `system cradle enabled`); the kernel \
                 bridge cannot keep leaves apart"
            )
        })
        .collect()
}

/// The IPv4 address list of an interface (`interface <name> ipv4
/// address <A.B.C.D/M>|dhcp`), as a callback path.
pub const IPV4_ADDRESS_PATH: &str = "/interface/ipv4/address";

/// Whether a config line can carry an entry [`address_dhcp_exclusive`]
/// reads, so the caller parses only those.
pub fn ipv4_address_line(line: &str) -> bool {
    line.starts_with("interface ") && line.contains(" ipv4 address ")
}

/// `interface <name> ipv4 address dhcp` leases the interface's address,
/// so it excludes a configured one on the same interface: an interface
/// is addressed by DHCP or statically, not both. This is the `must` on
/// the list in config.yang, which the schema library parses but does
/// not evaluate — a property of an interface's whole address list, not
/// of one line. `entries` are a whole config's [`ipv4_address_line`]s as
/// (callback path, arguments); the result is one error per interface
/// that has both, in the order the interfaces first appear.
pub fn address_dhcp_exclusive(entries: &[(String, Vec<String>)]) -> Vec<String> {
    // Interface name, whether it has `dhcp`, and its static addresses.
    let mut interfaces: Vec<(&str, bool, Vec<&str>)> = Vec::new();
    for (path, args) in entries {
        let [name, address] = args.as_slice() else {
            continue;
        };
        if path != IPV4_ADDRESS_PATH {
            continue;
        }
        let index = match interfaces.iter().position(|(n, ..)| n == name) {
            Some(index) => index,
            None => {
                interfaces.push((name, false, Vec::new()));
                interfaces.len() - 1
            }
        };
        let (_, dhcp, statics) = &mut interfaces[index];
        if address == "dhcp" {
            *dhcp = true;
        } else {
            statics.push(address);
        }
    }
    interfaces
        .into_iter()
        .filter(|(_, dhcp, statics)| *dhcp && !statics.is_empty())
        .map(|(name, _, statics)| {
            format!(
                "interface {name} ipv4 address: dhcp cannot be combined with a static \
                 address ({}); delete one or the other",
                statics.join(", ")
            )
        })
        .collect()
}

/// The callback paths [`dhcpv6_parameters_only_exclusive`] reads.
pub const IPV6_ADDRESS_PATH: &str = "/interface/ipv6/address";
pub const DHCPV6_PARAMETERS_ONLY_PATH: &str = "/interface/ipv6/dhcpv6-options/parameters-only";
pub const DHCPV6_PD_PATH: &str = "/interface/ipv6/dhcpv6-options/pd";

/// Whether a config line can carry an entry
/// [`dhcpv6_parameters_only_exclusive`] reads.
pub fn dhcpv6_mode_line(line: &str) -> bool {
    line.starts_with("interface ")
        && (line.contains(" ipv6 address dhcpv6")
            || line.contains(" ipv6 dhcpv6-options parameters-only")
            || line.contains(" ipv6 dhcpv6-options pd "))
}

/// `interface <name> ipv6 dhcpv6-options parameters-only` asks a DHCPv6
/// server for configuration and nothing to lease (an Information-request
/// carries no identity association), so it excludes `ipv6 address
/// dhcpv6` and `ipv6 dhcpv6-options pd` on the same interface: they are
/// different exchanges, and one client speaks one of them. `entries` are
/// a whole config's [`dhcpv6_mode_line`]s as (callback path, arguments);
/// the result is one error for each of the two an interface has beside
/// `parameters-only`, in the order the interfaces first appear.
pub fn dhcpv6_parameters_only_exclusive(entries: &[(String, Vec<String>)]) -> Vec<String> {
    #[derive(Default)]
    struct Modes {
        address: bool,
        pd: bool,
        parameters_only: bool,
    }
    let mut interfaces: Vec<(&str, Modes)> = Vec::new();
    for (path, args) in entries {
        let name = match (path.as_str(), args.as_slice()) {
            (IPV6_ADDRESS_PATH, [name, address]) if address == "dhcpv6" => name,
            (DHCPV6_PARAMETERS_ONLY_PATH, [name]) => name,
            // The list entry, or a leaf of it.
            (path, [name, ..]) if path.starts_with(DHCPV6_PD_PATH) => name,
            _ => continue,
        };
        let index = match interfaces.iter().position(|(n, _)| n == name) {
            Some(index) => index,
            None => {
                interfaces.push((name, Modes::default()));
                interfaces.len() - 1
            }
        };
        let modes = &mut interfaces[index].1;
        match path.as_str() {
            IPV6_ADDRESS_PATH => modes.address = true,
            DHCPV6_PARAMETERS_ONLY_PATH => modes.parameters_only = true,
            _ => modes.pd = true,
        }
    }
    let mut errors = Vec::new();
    for (name, modes) in interfaces {
        if !modes.parameters_only {
            continue;
        }
        if modes.address {
            errors.push(format!(
                "interface {name} ipv6: dhcpv6-options parameters-only asks for no address \
                 and cannot be combined with address dhcpv6; delete one or the other"
            ));
        }
        if modes.pd {
            errors.push(format!(
                "interface {name} ipv6: dhcpv6-options parameters-only asks for no prefix \
                 and cannot be combined with dhcpv6-options pd; delete one or the other"
            ));
        }
    }
    errors
}

/// The callback paths [`dhcpv6_pd_interfaces`] reads.
pub const DHCPV6_PD_LENGTH_PATH: &str = "/interface/ipv6/dhcpv6-options/pd/length";
pub const DHCPV6_PD_INTERFACE_PATH: &str = "/interface/ipv6/dhcpv6-options/pd/interface";
pub const DHCPV6_PD_SLA_ID_PATH: &str = "/interface/ipv6/dhcpv6-options/pd/interface/sla-id";

/// Whether a config line can carry an entry [`dhcpv6_pd_interfaces`]
/// reads.
pub fn dhcpv6_pd_line(line: &str) -> bool {
    line.starts_with("interface ") && line.contains(" ipv6 dhcpv6-options pd ")
}

/// What [`dhcpv6_pd_interfaces`] finds: what a commit is refused for,
/// and what it is only told.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PdFindings {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// `interface <name> ipv6 dhcpv6-options pd <id> interface <lan>` gives
/// `<lan>` one /64 of the prefix delegated to `<name>`: the one its
/// `sla-id` numbers, the first when it has none. `entries` are a whole
/// config's [`dhcpv6_pd_line`]s as (callback path, arguments). Refused,
/// in the order the delegations first appear:
///
/// - `<lan>` that is `<name>` itself: a delegated prefix must not number
///   the link it is delegated on (RFC 8415 §6.3);
/// - two interfaces of one delegation with the same `sla-id`: they would
///   share a /64, and each link needs its own.
///
/// And told, since only the server decides what it delegates: an
/// `sla-id` that a prefix of the `length` asked for has no room for. It
/// is looked at again against the prefix that is delegated (RFC 7084
/// WPD-3), and without a `length` there is nothing to compare it with.
pub fn dhcpv6_pd_interfaces(entries: &[(String, Vec<String>)]) -> PdFindings {
    #[derive(Default)]
    struct Delegation<'a> {
        length: Option<u8>,
        /// Each interface, and its `sla-id` when it has one.
        interfaces: Vec<(&'a str, Option<u32>)>,
    }
    let mut delegations: Vec<((&str, &str), Delegation)> = Vec::new();
    for (path, args) in entries {
        let [name, id, rest @ ..] = args.as_slice() else {
            continue;
        };
        if !path.starts_with(DHCPV6_PD_PATH) {
            continue;
        }
        let key = (name.as_str(), id.as_str());
        let index = match delegations.iter().position(|(k, _)| *k == key) {
            Some(index) => index,
            None => {
                delegations.push((key, Delegation::default()));
                delegations.len() - 1
            }
        };
        let delegation = &mut delegations[index].1;
        match (path.as_str(), rest) {
            (DHCPV6_PD_LENGTH_PATH, [length]) => delegation.length = length.parse().ok(),
            (DHCPV6_PD_INTERFACE_PATH, [lan]) => {
                if !delegation.interfaces.iter().any(|(n, _)| n == lan) {
                    delegation.interfaces.push((lan, None));
                }
            }
            (DHCPV6_PD_SLA_ID_PATH, [lan, sla_id]) => {
                let sla_id = sla_id.parse().ok();
                match delegation.interfaces.iter_mut().find(|(n, _)| n == lan) {
                    Some(interface) => interface.1 = sla_id,
                    None => delegation.interfaces.push((lan, sla_id)),
                }
            }
            _ => {}
        }
    }
    let mut findings = PdFindings::default();
    for ((name, id), delegation) in delegations {
        let at = format!("interface {name} ipv6 dhcpv6-options pd {id}");
        for (lan, _) in &delegation.interfaces {
            if *lan == name {
                findings.errors.push(format!(
                    "{at} interface {lan}: a delegated prefix cannot number the interface it \
                     is delegated on; name an interface behind this router"
                ));
            }
        }
        // Each sla-id once, with every interface that has it.
        let mut numbered: Vec<(u32, Vec<&str>)> = Vec::new();
        for (lan, sla_id) in &delegation.interfaces {
            let sla_id = sla_id.unwrap_or(0);
            match numbered.iter_mut().find(|(n, _)| *n == sla_id) {
                Some((_, interfaces)) => interfaces.push(lan),
                None => numbered.push((sla_id, vec![lan])),
            }
        }
        for (sla_id, interfaces) in numbered {
            if interfaces.len() > 1 {
                findings.errors.push(format!(
                    "{at}: interfaces {} have the same sla-id {sla_id}, which is one /64; \
                     give each its own",
                    interfaces.join(", ")
                ));
            }
        }
        let Some(length) = delegation.length else {
            continue;
        };
        let bits = 64u32.saturating_sub(length.into());
        for (lan, sla_id) in &delegation.interfaces {
            let sla_id = sla_id.unwrap_or(0);
            if u64::from(sla_id) >> bits != 0 {
                findings.warnings.push(format!(
                    "{at} interface {lan}: sla-id {sla_id} is beyond the {} /64s of a /{length}; \
                     the interface is numbered only if the server delegates a shorter prefix",
                    1u64 << bits
                ));
            }
        }
    }
    findings
}

/// A leaf value check: `Err` holds the reason, shown after the line.
pub type ValueCheck = fn(&str) -> Result<(), String>;

/// Whether a config line can carry an entry [`static_discard_exclusive`]
/// reads.
pub fn static_discard_line(line: &str) -> bool {
    line.starts_with("router static ")
        && (line.contains(" nexthop blackhole") || line.contains(" nexthop unreachable"))
}

/// `router static [vrf <name>] ipv4|ipv6 route <prefix> nexthop
/// blackhole` and `nexthop unreachable` each make the route a discard
/// route, of one kind: silent, or answered with an ICMP Destination
/// Unreachable. A route is one or the other, so the two on one route
/// are refused. They are two entries of one list, which the schema
/// cannot hold apart. `entries` are a whole config's
/// [`static_discard_line`]s as (callback path, arguments); the result is
/// one error per route that has both, in the order the routes first
/// appear.
pub fn static_discard_exclusive(entries: &[(String, Vec<String>)]) -> Vec<String> {
    // The route (callback path and its keys), and which keywords it has.
    let mut routes: Vec<((&str, &[String]), bool, bool)> = Vec::new();
    for (path, args) in entries {
        let Some(family) = path
            .strip_prefix("/router/static/")
            .and_then(|rest| rest.strip_suffix("/route/nexthop"))
        else {
            continue;
        };
        if !matches!(family, "ipv4" | "ipv6" | "vrf/ipv4" | "vrf/ipv6") {
            continue;
        }
        let Some((nexthop, keys)) = args.split_last() else {
            continue;
        };
        let (blackhole, unreachable) = match nexthop.as_str() {
            "blackhole" => (true, false),
            "unreachable" => (false, true),
            _ => continue,
        };
        let key = (family, keys);
        match routes.iter_mut().find(|(k, ..)| *k == key) {
            Some((_, b, u)) => {
                *b |= blackhole;
                *u |= unreachable;
            }
            None => routes.push((key, blackhole, unreachable)),
        }
    }
    routes
        .into_iter()
        .filter(|(_, blackhole, unreachable)| *blackhole && *unreachable)
        .map(|((family, keys), ..)| {
            // `vrf/ipv4` with keys [vrf, prefix]; `ipv4` with [prefix].
            let route = match (family.strip_prefix("vrf/"), keys) {
                (Some(family), [vrf, prefix]) => format!("vrf {vrf} {family} route {prefix}"),
                (_, keys) => format!("{family} route {}", keys.join(" ")),
            };
            format!(
                "router static {route}: nexthop blackhole cannot be combined with nexthop \
                 unreachable; delete one or the other"
            )
        })
        .collect()
}

/// `interface <name> ipv6 dhcpv6-options duid`: 3 to 130 octets (RFC 8415
/// §11.1). The schema's pattern says what an octet looks like and that
/// there are three; it cannot count to 130.
fn check_duid(value: &str) -> Result<(), String> {
    match crate::dhcpc::ident::parse_duid(value) {
        Some(_) => Ok(()),
        None => Err("a DUID is 3 to 130 colon-separated hex octets".to_string()),
    }
}

/// The check for the leaf at `path`, the callback path with keys
/// removed (`/router/isis/interface/te-metric/…`), if it has one.
pub fn value_check(path: &str) -> Option<ValueCheck> {
    if path == "/router/isis/flex-algo/exclude-max-link-loss" {
        return Some(|v| check_max_link_loss(v).map(drop));
    }
    if path == "/interface/ipv6/dhcpv6-options/duid" {
        return Some(check_duid);
    }
    // `te-metric measurement loss`, in IS-IS, OSPFv2 and OSPFv3 alike.
    let (_, leaf) = path
        .strip_prefix("/router/")?
        .split_once("/te-metric/measurement/loss/")?;
    match leaf {
        "interval" => Some(|v| check_loss_interval(v).map(drop)),
        "minimum-change" | "accelerated-threshold" | "anomaly-threshold" | "reuse-threshold" => {
            Some(|v| check_loss_percent(v).map(drop))
        }
        _ => None,
    }
}

/// The check for a leaf at `path`, as for [`value_check`], whose values
/// an earlier release took unchecked. A commit setting a bad one is
/// refused like any other, but the startup config is only warned about,
/// as for the MPLS label checks (`config::label_check`): a file an earlier
/// release loaded must not leave the router unconfigured. The protocol's
/// setter ignores the value instead.
pub fn startup_tolerant_check(path: &str) -> Option<ValueCheck> {
    match path {
        "/router/bgp/afi-safi/ethernet-segment/esi" => Some(|v| check_es_esi(v).map(drop)),
        // With `--feature insomnia` the name becomes the system's, and the
        // kernel takes 64 characters at most; the schema's pattern cannot
        // count, nor tell `r1..x` and `r1-` from a name. Without the feature
        // it is the same name, so the rule is the same. A startup name that
        // fails stays a label and is not applied (`rib::hostname`).
        "/system/hostname" => Some(crate::rib::hostname::valid),
        _ => None,
    }
}

/// The key of a `vrf` list, if `path` (a callback path, keys removed)
/// opens with one whose VRF names must not be `default`: the top-level
/// `vrf` list, and the per-VRF lists of the insomnia-enforced trees
/// (`service dhcp-server vrf <name>`, `vrrp vrf <name>`, …). Their first
/// key is that VRF's name.
fn names_a_vrf(path: &str) -> bool {
    path == "/vrf"
        || path.starts_with("/vrf/")
        || path
            .strip_prefix("/service/")
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(_, rest)| rest == "vrf" || rest.starts_with("vrf/"))
        || path == "/vrrp/vrf"
        || path.starts_with("/vrrp/vrf/")
}

/// `default` names the global routing table wherever a VRF is named:
/// the `<feature> vrf <name>` lists keep it for their top level, and
/// insomnia names its per-VRF daemon instances and their VRF bindings
/// after it (`kea-dhcp4@default`). A VRF called `default` would collide
/// with all of these, so the VRF lists refuse the name. Startup-tolerant
/// like [`startup_tolerant_check`]: an earlier release took the name.
pub fn reserved_vrf(path: &str, keys: &[&str]) -> Result<(), String> {
    match keys.first() {
        Some(&"default") if names_a_vrf(path) => {
            Err("VRF name \"default\" is reserved for the global routing table".to_string())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_not_a_vrf_name() {
        for (path, keys) in [
            ("/vrf", vec!["default"]),
            ("/vrf/table-id", vec!["default", "10"]),
            (
                "/service/dhcp-server/vrf/shared-network-name/subnet/subnet-id",
                vec!["default", "LAN", "10.1.0.0/24", "1"],
            ),
            (
                "/service/dhcpv6-relay/vrf/listen-interface",
                vec!["default", "eth1"],
            ),
            ("/vrrp/vrf/group/vrid", vec!["default", "WAN", "10"]),
        ] {
            assert!(reserved_vrf(path, &keys).is_err(), "{path} {keys:?}");
        }
        for (path, keys) in [
            ("/vrf", vec!["red"]),
            (
                "/service/dhcp-server/vrf/shared-network-name/subnet/subnet-id",
                vec!["red", "default", "10.1.0.0/24", "1"],
            ),
            // Not a VRF list: a shared network may be called anything.
            (
                "/service/dhcp-server/shared-network-name/subnet/subnet-id",
                vec!["default", "10.1.0.0/24", "1"],
            ),
            ("/interface/description", vec!["default", "x"]),
        ] {
            assert!(reserved_vrf(path, &keys).is_ok(), "{path} {keys:?}");
        }
    }

    #[test]
    fn loss_leaves_are_checked_in_every_igp() {
        for prefix in [
            "/router/isis/interface",
            "/router/ospf/area/interface",
            "/router/ospfv3/area/interface",
        ] {
            let path = format!("{prefix}/te-metric/measurement/loss/interval");
            let check = value_check(&path).expect(&path);
            assert!(check("60").is_ok());
            assert!(check("45").is_err(), "{path}");
            for leaf in [
                "minimum-change",
                "accelerated-threshold",
                "anomaly-threshold",
                "reuse-threshold",
            ] {
                let path = format!("{prefix}/te-metric/measurement/loss/{leaf}");
                let check = value_check(&path).expect(&path);
                assert!(check("0.5").is_ok());
                assert!(check("100.5").is_err(), "{path}");
            }
        }
        // Leaves YANG already bounds need nothing more.
        assert!(
            value_check("/router/isis/interface/te-metric/measurement/loss/threshold").is_none()
        );
        assert!(value_check("/router/isis/interface/te-metric/measurement/interval").is_none());
    }

    /// The link-loss constraint is bounded by what the wire can carry,
    /// 50.331642 %, not 100 %.
    #[test]
    fn flex_algo_max_link_loss_is_checked() {
        let check = value_check("/router/isis/flex-algo/exclude-max-link-loss").expect("checked");
        assert!(check("5").is_ok());
        assert!(check("50.331642").is_ok());
        assert!(check("50.331643").is_err());
        assert!(check("5.1234567").is_err());
    }

    fn leaf(path: &str, args: &[&str]) -> (String, Vec<String>) {
        (
            path.to_string(),
            args.iter().map(|a| a.to_string()).collect(),
        )
    }

    /// A leaf AC is refused unless the cradle data plane is on, through
    /// either switch, and set to true rather than merely present.
    #[test]
    fn etree_leaf_needs_cradle() {
        let leaf_ac = leaf(ETREE_LEAF_PATH, &["evpn", "ce1"]);
        let errors = etree_backend(std::slice::from_ref(&leaf_ac));
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].starts_with("etree leaf-interface ce1:"),
            "{errors:?}"
        );
        for path in CRADLE_ENABLED_PATHS {
            assert!(etree_backend(&[leaf_ac.clone(), leaf(path, &["true"])]).is_empty());
            assert_eq!(
                etree_backend(&[leaf_ac.clone(), leaf(path, &["false"])]).len(),
                1,
                "{path} false"
            );
        }
        // No leaf AC, nothing to refuse.
        assert!(etree_backend(&[leaf("/system/ebpf/enabled", &["false"])]).is_empty());
        assert!(etree_backend_line(
            "router bgp afi-safi evpn etree leaf-interface ce1"
        ));
        assert!(etree_backend_line("system ebpf enabled true"));
        assert!(etree_backend_line("system cradle enabled true"));
        assert!(!etree_backend_line("system cradle grpc-endpoint unix:x"));
    }

    /// A DUID is checked at commit for what the schema's pattern cannot
    /// say: how many octets it may have.
    #[test]
    fn a_duid_is_three_to_130_octets() {
        let check = value_check("/interface/ipv6/dhcpv6-options/duid").expect("a check");
        assert!(check("00:03:01").is_ok());
        assert!(check(&vec!["ab"; 130].join(":")).is_ok());
        for bad in ["00:03", &vec!["ab"; 131].join(":"), "00:03:0g", "000301"] {
            assert_eq!(
                check(bad),
                Err("a DUID is 3 to 130 colon-separated hex octets".to_string()),
                "{bad}"
            );
        }
        assert!(value_check("/interface/ipv6/dhcpv6-options/rapid-commit").is_none());
    }

    /// `parameters-only` and `address dhcpv6` exclude each other on one
    /// interface, and only there; other addresses and other options are
    /// not counted.
    #[test]
    fn dhcpv6_parameters_only_excludes_an_address() {
        let address = |name: &str, value: &str| leaf(IPV6_ADDRESS_PATH, &[name, value]);
        let only = |name: &str| leaf(DHCPV6_PARAMETERS_ONLY_PATH, &[name]);
        let check = dhcpv6_parameters_only_exclusive;

        // Either alone, and beside what is not the other.
        assert!(check(&[address("eth0", "dhcpv6")]).is_empty());
        assert!(check(&[only("eth0")]).is_empty());
        assert!(check(&[only("eth0"), address("eth0", "autoconf")]).is_empty());
        assert!(check(&[only("eth0"), address("eth0", "2001:db8::1/64")]).is_empty());
        assert!(check(&[only("eth0"), address("eth1", "dhcpv6")]).is_empty());
        assert!(
            check(&[
                address("eth0", "dhcpv6"),
                leaf("/interface/ipv6/dhcpv6-options/rapid-commit", &["eth0"]),
            ])
            .is_empty()
        );

        // Both on one interface, in either order; one error per
        // interface, the clean one left out.
        let refused = |name: &str| {
            format!(
                "interface {name} ipv6: dhcpv6-options parameters-only asks for no address \
                 and cannot be combined with address dhcpv6; delete one or the other"
            )
        };
        assert_eq!(
            check(&[address("eth0", "dhcpv6"), only("eth0")]),
            [refused("eth0")]
        );
        assert_eq!(
            check(&[
                only("eth2"),
                address("eth1", "dhcpv6"),
                only("eth0"),
                address("eth2", "dhcpv6"),
                address("eth0", "dhcpv6"),
            ]),
            [refused("eth2"), refused("eth0")]
        );
        // A delegation is something leased too: its list entry, or a
        // leaf of it, beside `parameters-only`.
        let pd = |name: &str| leaf(DHCPV6_PD_PATH, &[name, "0"]);
        let length = |name: &str| {
            leaf(
                "/interface/ipv6/dhcpv6-options/pd/length",
                &[name, "0", "56"],
            )
        };
        let no_prefix = |name: &str| {
            format!(
                "interface {name} ipv6: dhcpv6-options parameters-only asks for no prefix \
                 and cannot be combined with dhcpv6-options pd; delete one or the other"
            )
        };
        assert!(check(&[pd("eth0"), length("eth0")]).is_empty());
        assert!(check(&[pd("eth0"), address("eth0", "dhcpv6")]).is_empty());
        assert!(check(&[pd("eth0"), only("eth1")]).is_empty());
        assert_eq!(check(&[pd("eth0"), only("eth0")]), [no_prefix("eth0")]);
        assert_eq!(check(&[only("eth0"), length("eth0")]), [no_prefix("eth0")]);
        assert_eq!(
            check(&[pd("eth0"), only("eth0"), address("eth0", "dhcpv6")]),
            [refused("eth0"), no_prefix("eth0")]
        );
        // The lines it reads, and no others.
        assert!(dhcpv6_mode_line("interface eth0 ipv6 address dhcpv6"));
        assert!(dhcpv6_mode_line("interface eth0 ipv6 dhcpv6-options pd 0"));
        assert!(dhcpv6_mode_line(
            "interface eth0 ipv6 dhcpv6-options pd 0 length 56"
        ));
        assert!(dhcpv6_mode_line(
            "interface eth0 ipv6 dhcpv6-options parameters-only"
        ));
        assert!(!dhcpv6_mode_line("interface eth0 ipv6 address autoconf"));
        assert!(!dhcpv6_mode_line(
            "interface eth0 ipv6 dhcpv6-options rapid-commit"
        ));
        assert!(!dhcpv6_mode_line(
            "service dhcpv6-server interface eth0 ipv6 address dhcpv6"
        ));
    }

    /// The interfaces of a delegation: none is the one the prefix is
    /// delegated on, each has a /64 of its own, and an `sla-id` beyond
    /// the `length` asked for is only told.
    #[test]
    fn the_interfaces_of_a_delegation_are_checked() {
        const PD: &str = "/interface/ipv6/dhcpv6-options/pd";
        let pd = |name: &str, id: &str| leaf(PD, &[name, id]);
        let length = |name: &str, id: &str, n: &str| leaf(DHCPV6_PD_LENGTH_PATH, &[name, id, n]);
        let lan =
            |name: &str, id: &str, lan: &str| leaf(DHCPV6_PD_INTERFACE_PATH, &[name, id, lan]);
        let sla = |name: &str, id: &str, lan: &str, n: &str| {
            leaf(DHCPV6_PD_SLA_ID_PATH, &[name, id, lan, n])
        };
        let host = |name: &str, id: &str, lan: &str| {
            let path = "/interface/ipv6/dhcpv6-options/pd/interface/address";
            leaf(path, &[name, id, lan, "1"])
        };
        let check = dhcpv6_pd_interfaces;
        let clean = PdFindings::default();

        // A delegation alone, with one interface, and with several that
        // each have their own /64: the first for the one that names none.
        assert_eq!(check(&[pd("wan0", "1"), length("wan0", "1", "56")]), clean);
        assert_eq!(check(&[pd("wan0", "1"), lan("wan0", "1", "lan0")]), clean);
        assert_eq!(
            check(&[
                pd("wan0", "1"),
                lan("wan0", "1", "lan0"),
                host("wan0", "1", "lan0"),
                lan("wan0", "1", "lan1"),
                sla("wan0", "1", "lan1", "1"),
                sla("wan0", "1", "lan2", "2"),
            ]),
            clean
        );
        // The same sla-id under another delegation, or on another
        // upstream interface, is another prefix's /64; and one interface
        // may be numbered from two delegations.
        assert_eq!(
            check(&[
                lan("wan0", "1", "lan0"),
                lan("wan0", "2", "lan0"),
                lan("wan1", "1", "lan0"),
                lan("wan1", "1", "wan0"),
                sla("wan1", "1", "wan0", "1"),
            ]),
            clean
        );

        // The interface the prefix is delegated on.
        let found = check(&[lan("wan0", "1", "lan0"), sla("wan0", "1", "wan0", "1")]);
        assert_eq!(
            found.errors,
            [
                "interface wan0 ipv6 dhcpv6-options pd 1 interface wan0: a delegated prefix \
              cannot number the interface it is delegated on; name an interface behind this \
              router"
            ]
        );
        // One /64 for two interfaces: said or by default, in whichever
        // order the lines come, every interface named, once.
        let same = |id: &str, interfaces: &str, n: u32| {
            format!(
                "interface wan0 ipv6 dhcpv6-options pd {id}: interfaces {interfaces} have the \
                 same sla-id {n}, which is one /64; give each its own"
            )
        };
        let found = check(&[lan("wan0", "1", "lan0"), lan("wan0", "1", "lan1")]);
        assert_eq!(found.errors, [same("1", "lan0, lan1", 0)]);
        let found = check(&[
            sla("wan0", "1", "lan0", "5"),
            lan("wan0", "1", "lan1"),
            lan("wan0", "7", "lan3"),
            sla("wan0", "7", "lan4", "0"),
            lan("wan0", "1", "lan0"),
            sla("wan0", "1", "lan1", "5"),
            lan("wan0", "1", "lan2"),
            sla("wan0", "1", "lan2", "5"),
        ]);
        assert_eq!(
            found.errors,
            [same("1", "lan0, lan1, lan2", 5), same("7", "lan3, lan4", 0)]
        );
        assert!(found.warnings.is_empty());

        // Beyond the length asked for: told, not refused, and only when
        // a length is asked for.
        let beyond = |lan: &str, n: u32, count: u64, length: u8| {
            format!(
                "interface wan0 ipv6 dhcpv6-options pd 1 interface {lan}: sla-id {n} is beyond \
                 the {count} /64s of a /{length}; the interface is numbered only if the server \
                 delegates a shorter prefix"
            )
        };
        let interfaces = [
            lan("wan0", "1", "lan0"),
            sla("wan0", "1", "lan1", "255"),
            sla("wan0", "1", "lan2", "256"),
        ];
        assert_eq!(check(&interfaces), clean);
        let mut hinted = interfaces.to_vec();
        hinted.push(length("wan0", "1", "56"));
        let found = check(&hinted);
        assert!(found.errors.is_empty(), "{found:?}");
        assert_eq!(found.warnings, [beyond("lan2", 256, 256, 56)]);
        *hinted.last_mut().unwrap() = length("wan0", "1", "64");
        assert_eq!(
            check(&hinted).warnings,
            [beyond("lan1", 255, 1, 64), beyond("lan2", 256, 1, 64)]
        );
        *hinted.last_mut().unwrap() = length("wan0", "1", "32");
        assert_eq!(check(&hinted), clean);

        // The lines it reads, and no others.
        assert!(dhcpv6_pd_line("interface wan0 ipv6 dhcpv6-options pd 1"));
        assert!(dhcpv6_pd_line(
            "interface wan0 ipv6 dhcpv6-options pd 1 interface lan0 sla-id 1"
        ));
        assert!(!dhcpv6_pd_line("interface wan0 ipv6 address dhcpv6"));
        assert!(!dhcpv6_pd_line(
            "service dhcpv6-server interface wan0 ipv6 dhcpv6-options pd 1"
        ));
    }

    /// `address dhcp` and a static address exclude each other on one
    /// interface, and only there: other interfaces, and the IPv6 list,
    /// are not counted.
    #[test]
    fn address_dhcp_excludes_a_static_address() {
        let v4 = |name: &str, address: &str| leaf(IPV4_ADDRESS_PATH, &[name, address]);

        // Either alone, on any number of interfaces.
        assert!(address_dhcp_exclusive(&[v4("eth0", "dhcp")]).is_empty());
        assert!(
            address_dhcp_exclusive(&[v4("eth0", "10.0.0.1/24"), v4("eth0", "10.0.0.2/24")])
                .is_empty()
        );
        assert!(
            address_dhcp_exclusive(&[v4("eth0", "dhcp"), v4("eth1", "10.0.0.1/24")]).is_empty()
        );
        // An IPv6 address is no IPv4 static address.
        assert!(
            address_dhcp_exclusive(&[
                v4("eth0", "dhcp"),
                leaf("/interface/ipv6/address", &["eth0", "2001:db8::1/64"]),
            ])
            .is_empty()
        );

        // Both on one interface, in either order, every static named.
        for entries in [
            vec![
                v4("eth0", "10.0.0.1/24"),
                v4("eth0", "10.0.0.2/24"),
                v4("eth0", "dhcp"),
            ],
            vec![
                v4("eth0", "dhcp"),
                v4("eth0", "10.0.0.1/24"),
                v4("eth0", "10.0.0.2/24"),
            ],
        ] {
            assert_eq!(
                address_dhcp_exclusive(&entries),
                [
                    "interface eth0 ipv4 address: dhcp cannot be combined with a static \
                     address (10.0.0.1/24, 10.0.0.2/24); delete one or the other"
                ]
            );
        }

        // One error per interface, the clean one left out.
        let errors = address_dhcp_exclusive(&[
            v4("eth0", "dhcp"),
            v4("eth0", "10.0.0.1/24"),
            v4("eth1", "dhcp"),
            v4("eth2", "dhcp"),
            v4("eth2", "10.2.0.1/24"),
        ]);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors[0].starts_with("interface eth0 "), "{errors:?}");
        assert!(errors[1].starts_with("interface eth2 "), "{errors:?}");

        assert!(ipv4_address_line("interface eth0 ipv4 address dhcp"));
        assert!(ipv4_address_line("interface eth0 ipv4 address 10.0.0.1/24"));
        assert!(!ipv4_address_line(
            "interface eth0 ipv6 address 2001:db8::1/64"
        ));
        assert!(!ipv4_address_line(
            "interface eth0 ipv4 dhcp-options host-name edge1"
        ));
    }

    /// A static route is a blackhole or an unreachable route, not both:
    /// per route, per family and per VRF. A discard keyword beside an
    /// address is not this check's business.
    #[test]
    fn a_static_route_takes_one_discard_keyword() {
        let v4 = |prefix: &str, nexthop: &str| {
            leaf("/router/static/ipv4/route/nexthop", &[prefix, nexthop])
        };
        let v6 = |prefix: &str, nexthop: &str| {
            leaf("/router/static/ipv6/route/nexthop", &[prefix, nexthop])
        };
        let vrf = |name: &str, prefix: &str, nexthop: &str| {
            leaf(
                "/router/static/vrf/ipv4/route/nexthop",
                &[name, prefix, nexthop],
            )
        };

        // Either alone, each on its own route, and beside an address.
        assert!(static_discard_exclusive(&[v4("10.0.0.0/8", "blackhole")]).is_empty());
        assert!(static_discard_exclusive(&[v4("10.0.0.0/8", "unreachable")]).is_empty());
        assert!(
            static_discard_exclusive(&[
                v4("10.0.0.0/8", "blackhole"),
                v4("10.1.0.0/16", "unreachable"),
                v4("10.1.0.0/16", "192.0.2.1"),
            ])
            .is_empty()
        );
        // The same prefix in another family, another VRF or the default
        // one is another route. So is a label's nexthop.
        assert!(
            static_discard_exclusive(&[
                vrf("blue", "10.0.0.0/8", "blackhole"),
                vrf("red", "10.0.0.0/8", "unreachable"),
                v4("10.0.0.0/8", "unreachable"),
                leaf(
                    "/router/static/vrf/ipv6/route/nexthop",
                    &["blue", "10.0.0.0/8", "unreachable"]
                ),
                leaf("/router/static/mpls/label/nexthop", &["100", "blackhole"]),
                leaf("/router/static/mpls/label/nexthop", &["100", "unreachable"]),
            ])
            .is_empty()
        );
        // Nor a leaf below the entry.
        assert!(
            static_discard_exclusive(&[
                v4("10.0.0.0/8", "blackhole"),
                leaf(
                    "/router/static/ipv4/route/nexthop/metric",
                    &["10.0.0.0/8", "unreachable"]
                ),
            ])
            .is_empty()
        );

        // Both on one route, in either order.
        for entries in [
            vec![
                v4("10.0.0.0/8", "blackhole"),
                v4("10.0.0.0/8", "unreachable"),
            ],
            vec![
                v4("10.0.0.0/8", "unreachable"),
                v4("10.0.0.0/8", "blackhole"),
            ],
        ] {
            assert_eq!(
                static_discard_exclusive(&entries),
                [
                    "router static ipv4 route 10.0.0.0/8: nexthop blackhole cannot be \
                  combined with nexthop unreachable; delete one or the other"
                ]
            );
        }
        // One error per route, in order, the VRF named.
        assert_eq!(
            static_discard_exclusive(&[
                v6("2001:db8::/32", "unreachable"),
                vrf("blue", "10.0.0.0/8", "blackhole"),
                v4("10.9.0.0/16", "blackhole"),
                v6("2001:db8::/32", "blackhole"),
                vrf("blue", "10.0.0.0/8", "unreachable"),
            ]),
            [
                "router static ipv6 route 2001:db8::/32: nexthop blackhole cannot be \
                 combined with nexthop unreachable; delete one or the other",
                "router static vrf blue ipv4 route 10.0.0.0/8: nexthop blackhole cannot be \
                 combined with nexthop unreachable; delete one or the other",
            ]
        );

        assert!(static_discard_line(
            "router static ipv4 route 10.0.0.0/8 nexthop blackhole"
        ));
        assert!(static_discard_line(
            "router static vrf blue ipv6 route 2001:db8::/32 nexthop unreachable"
        ));
        assert!(!static_discard_line(
            "router static ipv4 route 10.0.0.0/8 nexthop 192.0.2.1"
        ));
        assert!(!static_discard_line("router bgp 65000 neighbor 192.0.2.1"));
    }

    /// `system hostname` is a name the kernel would take. Only the startup
    /// config tolerates another: an earlier release took any.
    #[test]
    fn system_hostname_is_checked() {
        let path = "/system/hostname";
        assert!(value_check(path).is_none());
        let check = startup_tolerant_check(path).expect("checked");
        for good in ["r1", "pe1-core", "r1.example.com", &"a".repeat(63)] {
            assert!(check(good).is_ok(), "{good}");
        }
        for bad in ["r1..x", "r1.", "r1-", &"a".repeat(64), &"a.".repeat(40)] {
            assert!(check(bad).is_err(), "{bad}");
        }
        // The other hostname leaves are not system names.
        assert!(startup_tolerant_check("/router/isis/hostname").is_none());
    }

    /// An Ethernet Segment's ESI: well-formed and not reserved (RFC 7432
    /// §5). Only the startup config tolerates a bad one.
    #[test]
    fn es_esi_is_checked() {
        let path = "/router/bgp/afi-safi/ethernet-segment/esi";
        assert!(value_check(path).is_none());
        let check = startup_tolerant_check(path).expect("checked");
        assert!(check("00:11:22:33:44:55:66:77:88:99").is_ok());
        assert!(check("00000000000000000001").is_ok());
        assert!(check("fe:ff:ff:ff:ff:ff:ff:ff:ff:ff").is_ok());
        for bad in [
            "00:00:00:00:00:00:00:00:00:00",
            "00000000000000000000",
            "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff",
            "FFFFFFFFFFFFFFFFFFFF",
            "00:11:22",
            "zz:11:22:33:44:55:66:77:88:99",
        ] {
            assert!(check(bad).is_err(), "{bad}");
        }
    }
}
