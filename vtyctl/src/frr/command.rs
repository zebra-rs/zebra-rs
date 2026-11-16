//! FRR command line → what to ask zebra-rs for.
//!
//! Pure: no I/O, so the whole mapping is unit-tested. The rule that
//! matters is at the bottom of [`translate`]: a `json` command this
//! module does not know is refused, never passed through. zebra-rs's own
//! JSON has a different schema, and a consumer written against FRR's
//! would read it as "no peers" or "no routes" without any error.

/// Address family a summary is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// FRR's key for the unicast family in `summary json`.
    pub fn frr_key(self) -> &'static str {
        match self {
            Family::V4 => "ipv4Unicast",
            Family::V6 => "ipv6Unicast",
        }
    }

    fn zebra(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `show … summary json`: zebra-rs's summary JSON, re-shaped. `family`
    /// keeps one family's section (`show ip bgp summary json`); `None` is
    /// every family (`show bgp summary json`). `per_vrf` wraps the result
    /// in FRR's `vrf all` envelope, `{"default": …}`.
    SummaryJson {
        family: Option<Family>,
        per_vrf: bool,
    },
    /// `show ip|ipv6 route [PROTOCOL | ADDRESS | PREFIX] json`, re-shaped.
    /// `protocol` keeps only that protocol's entries (`show ip route
    /// connected json`); `target` asks for the routes to one address or
    /// prefix (`show ip route 10.1.0.2 json`).
    RouteJson {
        family: Family,
        protocol: Option<String>,
        target: Option<String>,
    },
    /// `show ip bgp json`, of which only the header is answered: router
    /// id, local AS, VRF. sonic-utilities asks for it to print that
    /// header when a family has no neighbors.
    BgpHeaderJson,
    /// Text output of this zebra-rs show command, printed as it comes.
    Show(String),
    /// This zebra-rs clear command.
    Clear(String),
    /// Understood, and there is nothing to map it to. The string says why.
    Unsupported(String),
}

fn unsupported(why: &str) -> Action {
    Action::Unsupported(why.to_string())
}

/// Take `vrf NAME` out of the tokens. `Ok(true)` for `vrf all`, `Ok(false)`
/// for the default VRF (named or implied), `Err` for any other VRF.
fn take_vrf(tokens: &mut Vec<&str>) -> Result<bool, Action> {
    let Some(pos) = tokens.iter().position(|t| *t == "vrf") else {
        return Ok(false);
    };
    let Some(name) = tokens.get(pos + 1).copied() else {
        return Err(unsupported("`vrf` needs a name"));
    };
    tokens.drain(pos..=pos + 1);
    match name {
        "default" => Ok(false),
        "all" => Ok(true),
        other => Err(Action::Unsupported(format!(
            "VRF {other}: only the default VRF is mapped"
        ))),
    }
}

fn take(tokens: &mut Vec<&str>, word: &str) -> bool {
    match tokens.iter().position(|t| *t == word) {
        Some(pos) => {
            tokens.remove(pos);
            true
        }
        None => false,
    }
}

/// The family an FRR BGP command names: `ip bgp` and `bgp ipv4` are v4,
/// `ipv6 bgp` and `bgp ipv6` are v6, plain `bgp` names none.
fn take_bgp_family(lead_ip: Option<Family>, tokens: &mut Vec<&str>) -> Option<Family> {
    let mut family = lead_ip;
    if take(tokens, "ipv4") {
        family = Some(Family::V4);
    }
    if take(tokens, "ipv6") {
        family = Some(Family::V6);
    }
    take(tokens, "unicast");
    family
}

/// `show [ip] bgp …`, after `bgp`.
fn show_bgp(lead_ip: Option<Family>, mut tokens: Vec<&str>, json: bool) -> Action {
    let per_vrf = match take_vrf(&mut tokens) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let family = take_bgp_family(lead_ip, &mut tokens);
    // FRR takes `neighbor` as an abbreviation of `neighbors`, and that is
    // what sonic-utilities sends.
    if let Some(first) = tokens.first_mut()
        && *first == "neighbor"
    {
        *first = "neighbors";
    }

    match tokens.as_slice() {
        ["summary"] => {
            if json {
                Action::SummaryJson { family, per_vrf }
            } else if per_vrf {
                unsupported("`vrf all` is mapped for `summary json` only")
            } else {
                Action::Show(match family {
                    Some(f) => format!("show bgp {} summary", f.zebra()),
                    None => "show bgp summary".to_string(),
                })
            }
        }
        _ if per_vrf => unsupported("`vrf all` is mapped for `summary json` only"),
        [] if json => Action::BgpHeaderJson,
        _ if json => unsupported("no FRR-schema JSON for this command yet"),
        // FRR says `neighbors`, zebra-rs `neighbor`.
        ["neighbors"] => Action::Show("show bgp neighbor".to_string()),
        ["neighbors", addr] => Action::Show(format!("show bgp neighbor {addr}")),
        [
            "neighbors",
            addr,
            what @ ("advertised-routes" | "received-routes"),
        ] => {
            let tail = match family {
                Some(Family::V6) => " ipv6",
                _ => "",
            };
            Action::Show(format!("show bgp neighbor {addr} {what}{tail}"))
        }
        // FRR's `routes` is the accepted Adj-RIB-In; zebra-rs has no
        // separate view for it.
        ["neighbors", _, "routes"] => unsupported("`neighbors X routes` has no zebra-rs view"),
        rest => {
            let mut line = String::from("show bgp");
            if let Some(f) = family {
                line.push(' ');
                line.push_str(f.zebra());
            }
            for t in rest {
                line.push(' ');
                line.push_str(t);
            }
            Action::Show(line)
        }
    }
}

/// An address or a prefix: what `show ip route X` looks up.
fn is_route_target(token: &str) -> bool {
    let (addr, len) = match token.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (token, None),
    };
    addr.parse::<std::net::IpAddr>().is_ok() && len.is_none_or(|l| l.parse::<u8>().is_ok())
}

/// `show ip|ipv6 route …`, after `route`.
fn show_route(family: Family, mut tokens: Vec<&str>, json: bool) -> Action {
    match take_vrf(&mut tokens) {
        Ok(false) => {}
        Ok(true) => return unsupported("`route vrf all` is not mapped"),
        Err(e) => return e,
    }
    let ip = match family {
        Family::V4 => "ip",
        Family::V6 => "ipv6",
    };
    if json {
        return match tokens.as_slice() {
            [] => Action::RouteJson {
                family,
                protocol: None,
                target: None,
            },
            [proto @ ("connected" | "kernel" | "static" | "bgp" | "ospf" | "isis")] => {
                Action::RouteJson {
                    family,
                    protocol: Some((*proto).to_string()),
                    target: None,
                }
            }
            [target] if is_route_target(target) => Action::RouteJson {
                family,
                protocol: None,
                target: Some((*target).to_string()),
            },
            _ => unsupported("no FRR-schema JSON for this route command yet"),
        };
    }
    let mut line = format!("show {ip} route");
    for t in &tokens {
        line.push(' ');
        line.push_str(t);
    }
    Action::Show(line)
}

/// `clear [ip|ipv6] bgp [ipv4|ipv6] <*|ADDR> [soft] [in|out]`.
fn clear(tokens: Vec<&str>) -> Action {
    let mut tokens = tokens;
    let lead = match tokens.first().copied() {
        Some("ip") => {
            tokens.remove(0);
            Some(Family::V4)
        }
        Some("ipv6") => {
            tokens.remove(0);
            Some(Family::V6)
        }
        _ => None,
    };
    if tokens.first().copied() != Some("bgp") {
        return unsupported("only `clear … bgp …` is mapped");
    }
    tokens.remove(0);
    match take_vrf(&mut tokens) {
        Ok(false) => {}
        Ok(true) => return unsupported("`clear bgp vrf all` is not mapped"),
        Err(e) => return e,
    }
    if tokens.first().copied() == Some("peer-group") {
        return unsupported("zebra-rs has no `clear bgp neighbor-group`");
    }
    let named = take_bgp_family(lead, &mut tokens);
    // FRR's bare `in`/`out` are soft refreshes too.
    let soft = take(&mut tokens, "soft");
    let dir_in = take(&mut tokens, "in");
    let dir_out = take(&mut tokens, "out");
    let [target] = tokens.as_slice() else {
        return unsupported("expected `clear bgp <*|ADDRESS> [soft] [in|out]`");
    };
    let addr_family = match target.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => Some(Family::V4),
        Ok(std::net::IpAddr::V6(_)) => Some(Family::V6),
        Err(_) => None,
    };
    if *target != "*" && addr_family.is_none() {
        return unsupported("the neighbor must be `*` or an address");
    }
    // An address says its own family; `*` clears the family the command
    // named, and FRR's `clear bgp *` with none means IPv4 unicast peers.
    let family = addr_family.or(named).unwrap_or(Family::V4).zebra();
    let target = if *target == "*" { "all" } else { target };

    let mut line = format!("clear bgp {family} {target}");
    if soft || dir_in || dir_out {
        line.push_str(" soft");
        if dir_in && !dir_out {
            line.push_str(" in");
        } else if dir_out && !dir_in {
            line.push_str(" out");
        }
    }
    Action::Clear(line)
}

/// Map one FRR command line.
pub fn translate(line: &str) -> Action {
    let mut tokens: Vec<&str> = line.split_whitespace().collect();
    // `do show …` is how a show is spelled from FRR's configure mode.
    if tokens.first().copied() == Some("do") {
        tokens.remove(0);
    }
    let Some(verb) = tokens.first().copied() else {
        return unsupported("empty command");
    };
    tokens.remove(0);

    match verb {
        "clear" => clear(tokens),
        "show" => {
            let json = tokens.last().copied() == Some("json");
            if json {
                tokens.pop();
            }
            match tokens.as_slice() {
                ["ip", "bgp", rest @ ..] => show_bgp(Some(Family::V4), rest.to_vec(), json),
                ["ipv6", "bgp", rest @ ..] => show_bgp(Some(Family::V6), rest.to_vec(), json),
                ["bgp", rest @ ..] => show_bgp(None, rest.to_vec(), json),
                ["ip", "route", rest @ ..] => show_route(Family::V4, rest.to_vec(), json),
                ["ipv6", "route", rest @ ..] => show_route(Family::V6, rest.to_vec(), json),
                // See the module comment: never zebra-rs JSON in FRR's place.
                _ if json => unsupported("no FRR-schema JSON for this command yet"),
                ["run" | "running-config", ..] => Action::Show("show running-config".to_string()),
                rest => {
                    let mut line = String::from("show");
                    for t in rest {
                        line.push(' ');
                        line.push_str(t);
                    }
                    Action::Show(line)
                }
            }
        }
        "configure" | "conf" | "write" | "copy" | "end" | "exit" => {
            unsupported("configuration goes through `vtyctl apply`, not vtysh")
        }
        _ => unsupported("only `show` and `clear` commands are mapped"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn show(s: &str) -> Action {
        Action::Show(s.to_string())
    }

    /// The summary commands SONiC issues: bgpmon, `show ip bgp summary`,
    /// `show ipv6 bgp summary` (utilities_common/bgp_util.py) and
    /// generate_dump.
    #[test]
    fn summary_json_commands() {
        assert_eq!(
            translate("show bgp summary json"),
            Action::SummaryJson {
                family: None,
                per_vrf: false
            }
        );
        assert_eq!(
            translate("show ip bgp vrf default summary json"),
            Action::SummaryJson {
                family: Some(Family::V4),
                per_vrf: false
            }
        );
        assert_eq!(
            translate("show bgp vrf default ipv6 summary json"),
            Action::SummaryJson {
                family: Some(Family::V6),
                per_vrf: false
            }
        );
        assert_eq!(
            translate("show bgp vrf all ipv4 unicast summary json"),
            Action::SummaryJson {
                family: Some(Family::V4),
                per_vrf: true
            }
        );
        assert_eq!(
            translate("show ip bgp vrf all summary json"),
            Action::SummaryJson {
                family: Some(Family::V4),
                per_vrf: true
            }
        );
    }

    #[test]
    fn summary_text_commands() {
        assert_eq!(
            translate("show ip bgp summary"),
            show("show bgp ipv4 summary")
        );
        assert_eq!(
            translate("show bgp ipv6 summary"),
            show("show bgp ipv6 summary")
        );
        assert_eq!(translate("show bgp summary"), show("show bgp summary"));
    }

    /// route_check.py and fast-reboot-filter-routes.py.
    #[test]
    fn route_json_commands() {
        assert_eq!(
            translate("show ip route json"),
            Action::RouteJson {
                family: Family::V4,
                protocol: None,
                target: None,
            }
        );
        assert_eq!(
            translate("show ipv6 route json"),
            Action::RouteJson {
                family: Family::V6,
                protocol: None,
                target: None,
            }
        );
        assert_eq!(
            translate("show ip route connected json"),
            Action::RouteJson {
                family: Family::V4,
                protocol: Some("connected".to_string()),
                target: None,
            }
        );
    }

    /// `show ip route 10.1.0.2`: sonic-utilities adds `json` itself and
    /// prints the entries.
    #[test]
    fn route_json_for_one_address_or_prefix() {
        for target in ["10.1.0.2", "10.1.0.2/32"] {
            assert_eq!(
                translate(&format!("show ip route {target} json")),
                Action::RouteJson {
                    family: Family::V4,
                    protocol: None,
                    target: Some(target.to_string())
                }
            );
        }
        assert_eq!(
            translate("show ipv6 route vrf default fc00::/126 json"),
            Action::RouteJson {
                family: Family::V6,
                protocol: None,
                target: Some("fc00::/126".to_string())
            }
        );
        assert!(matches!(
            translate("show ip route summary json"),
            Action::Unsupported(_)
        ));
        assert!(matches!(
            translate("show ip route 10.1.0.2/x json"),
            Action::Unsupported(_)
        ));
    }

    /// What `show ipv6 bgp summary` falls back to on a box with no IPv6
    /// neighbors (bgp_util.process_bgp_vrf_summary).
    #[test]
    fn bgp_table_json_is_the_header() {
        assert_eq!(
            translate("show ip bgp vrf default json"),
            Action::BgpHeaderJson
        );
        assert_eq!(translate("show bgp json"), Action::BgpHeaderJson);
    }

    /// sonic-utilities' `show ip bgp neighbors` sends the abbreviation.
    #[test]
    fn neighbor_abbreviation_from_sonic_utilities() {
        assert_eq!(
            translate("show ip bgp vrf default neighbor 10.0.0.1"),
            show("show bgp neighbor 10.0.0.1")
        );
        assert_eq!(
            translate("show bgp vrf default ipv6 neighbor fc00::1 advertised-routes"),
            show("show bgp neighbor fc00::1 advertised-routes ipv6")
        );
        assert_eq!(
            translate("show ip bgp vrf default neighbor"),
            show("show bgp neighbor")
        );
    }

    #[test]
    fn route_text_passes_its_arguments() {
        assert_eq!(translate("show ip route"), show("show ip route"));
        assert_eq!(
            translate("show ip route vrf default 10.1.0.2/32"),
            show("show ip route 10.1.0.2/32")
        );
        assert_eq!(translate("show ipv6 route"), show("show ipv6 route"));
    }

    #[test]
    fn neighbors_is_respelled() {
        assert_eq!(
            translate("show ip bgp neighbors"),
            show("show bgp neighbor")
        );
        assert_eq!(
            translate("show bgp ipv6 neighbors fc00::1"),
            show("show bgp neighbor fc00::1")
        );
        assert_eq!(
            translate("show bgp ipv4 neighbors 10.0.0.1 advertised-routes"),
            show("show bgp neighbor 10.0.0.1 advertised-routes")
        );
        assert_eq!(
            translate("show bgp ipv6 neighbors fc00::1 advertised-routes"),
            show("show bgp neighbor fc00::1 advertised-routes ipv6")
        );
    }

    #[test]
    fn other_show_text_goes_through_as_it_is() {
        assert_eq!(translate("show version"), show("show version"));
        assert_eq!(translate("show run"), show("show running-config"));
        assert_eq!(
            translate("show running-config bgp"),
            show("show running-config")
        );
        assert_eq!(translate("do show ip route"), show("show ip route"));
        assert_eq!(translate("show ip bgp"), show("show bgp ipv4"));
        assert_eq!(translate("show bgp ipv6"), show("show bgp ipv6"));
    }

    /// The point of the module: an unmapped `json` command is refused.
    #[test]
    fn unknown_json_is_refused_not_passed_through() {
        for cmd in [
            "show bfd peers json",
            "show bgp neighbors 10.0.0.1 json",
            "show bgp peer-group PEER_V4 json",
            "show ip route summary json",
            "show evpn vni detail json",
        ] {
            assert!(
                matches!(translate(cmd), Action::Unsupported(_)),
                "{cmd} must be refused"
            );
        }
    }

    #[test]
    fn other_vrfs_are_refused() {
        assert!(matches!(
            translate("show ip bgp vrf Vrf1 summary json"),
            Action::Unsupported(_)
        ));
        assert!(matches!(
            translate("show ip route vrf Vrf1 json"),
            Action::Unsupported(_)
        ));
    }

    /// sonic-utilities' clear/bgp_quagga_v4.py, bgp_quagga_v6.py and
    /// bgp_frr_v6.py.
    #[test]
    fn clear_commands() {
        let clear = |s: &str| Action::Clear(s.to_string());
        assert_eq!(translate("clear ip bgp *"), clear("clear bgp ipv4 all"));
        assert_eq!(
            translate("clear ip bgp * soft in"),
            clear("clear bgp ipv4 all soft in")
        );
        assert_eq!(
            translate("clear ip bgp * in"),
            clear("clear bgp ipv4 all soft in")
        );
        assert_eq!(
            translate("clear ip bgp 10.0.0.1 soft out"),
            clear("clear bgp ipv4 10.0.0.1 soft out")
        );
        assert_eq!(
            translate("clear ip bgp 10.0.0.1 soft"),
            clear("clear bgp ipv4 10.0.0.1 soft")
        );
        assert_eq!(translate("clear bgp ipv6 *"), clear("clear bgp ipv6 all"));
        assert_eq!(translate("clear ipv6 bgp *"), clear("clear bgp ipv6 all"));
        assert_eq!(
            translate("clear bgp ipv6 fc00::1 soft in"),
            clear("clear bgp ipv6 fc00::1 soft in")
        );
        // The address decides, whatever the command's family word says.
        assert_eq!(
            translate("clear ip bgp fc00::1"),
            clear("clear bgp ipv6 fc00::1")
        );
    }

    #[test]
    fn clear_peer_group_and_configuration_are_refused() {
        assert!(matches!(
            translate("clear bgp peer-group PEER_V4 soft in"),
            Action::Unsupported(_)
        ));
        assert!(matches!(
            translate("configure terminal"),
            Action::Unsupported(_)
        ));
        assert!(matches!(
            translate("clear ip route"),
            Action::Unsupported(_)
        ));
    }
}
