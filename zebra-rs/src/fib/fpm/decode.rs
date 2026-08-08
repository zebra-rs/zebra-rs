//! Parsing the inbound half of FPM: offload acknowledgements.
//!
//! `fpmsyncd` sends an `RTM_NEWROUTE` back up the same connection with
//! `RTM_F_OFFLOAD` set once a route is considered programmed. This is
//! what `bgp suppress-fib-pending` waits on before advertising a prefix.
//!
//! There are **two** acknowledgement shapes, selected by CONFIG_DB's
//! `suppress-fib-pending`, and a parser has to accept both:
//!
//! * **disabled** (the default) — `fpmsyncd` replies the instant it
//!   parses the route, before APPL_DB is even written, by rebuilding the
//!   parsed route in full. The reply carries `RTA_GATEWAY` / `RTA_OIF` /
//!   `RTA_MULTIPATH`. The check reads `if (!isSuppressionEnabled())`
//!   (`routesync.cpp:2631`) — inverted from the intuitive reading.
//! * **enabled** — that immediate reply is skipped and the
//!   acknowledgement instead comes from orchagent's APPL_STATE_DB
//!   response, synthesized from scratch with **no nexthop at all**
//!   (`routesync.cpp:3700-3730`).
//!
//! So the only fields present in both are the family, the prefix, the
//! table and the protocol. Anything keying off nexthops works in one
//! mode and silently fails in the other. `nlmsg_seq` and `nlmsg_pid` are
//! zero in both — there is no correlation id, and matching is by prefix.
//!
//! Deletes are never acknowledged in either mode.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::frame::FPM_MSG_HDR_LEN;
use crate::fib::message::RouteOffload;

const NLMSG_HDRLEN: usize = 16;
const RTMSG_LEN: usize = 12;
const RTM_NEWROUTE: u16 = 24;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RTA_DST: u16 = 1;
const RTA_TABLE: u16 = 15;
const NLA_F_NESTED: u16 = 0x8000;

/// `RTM_F_OFFLOAD` — the bit that makes this an acknowledgement rather
/// than an ordinary route message.
const RTM_F_OFFLOAD: u32 = 0x4000;
/// `RTM_F_OFFLOAD_FAILED`. Not observed from `fpmsyncd` yet, but the
/// kernel defines it and reporting a failure as a success would leave a
/// prefix advertised that was never programmed — so it is recognized and
/// kept distinct.
const RTM_F_OFFLOAD_FAILED: u32 = 0x2000_0000;

/// Parse a complete FPM message as an offload acknowledgement.
///
/// Returns `None` for anything that is not an `RTM_NEWROUTE` carrying an
/// offload flag — including ordinary echoes and message types this
/// module does not handle. Malformed input yields `None` rather than an
/// error: a peer that sends nonsense should not take the tee down.
pub fn parse_ack(msg: &[u8]) -> Option<RouteOffload> {
    let payload = msg.get(FPM_MSG_HDR_LEN..)?;
    if payload.len() < NLMSG_HDRLEN + RTMSG_LEN {
        return None;
    }

    let nl_len = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
    let nl_type = u16::from_le_bytes(payload[4..6].try_into().ok()?);
    if nl_type != RTM_NEWROUTE {
        return None;
    }

    // Trust the netlink length, but never read past the buffer: the FPM
    // frame is padded, so payload is often a few bytes longer.
    let end = nl_len.min(payload.len());
    let body = payload.get(NLMSG_HDRLEN..end)?;
    if body.len() < RTMSG_LEN {
        return None;
    }

    let family = body[0];
    let dst_len = body[1];
    let table = body[4] as u32;
    let protocol = body[5];
    let flags = u32::from_le_bytes(body[8..12].try_into().ok()?);

    if flags & (RTM_F_OFFLOAD | RTM_F_OFFLOAD_FAILED) == 0 {
        return None;
    }

    let mut dst: Option<&[u8]> = None;
    let mut table_attr: Option<u32> = None;
    let mut rest = &body[RTMSG_LEN..];
    while rest.len() >= 4 {
        let len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
        let atype = u16::from_le_bytes([rest[2], rest[3]]) & !NLA_F_NESTED;
        if len < 4 || len > rest.len() {
            break;
        }
        match atype {
            RTA_DST => dst = Some(&rest[4..len]),
            RTA_TABLE if len >= 8 => {
                table_attr = Some(u32::from_le_bytes(rest[4..8].try_into().ok()?));
            }
            _ => {}
        }
        let advance = (len + 3) & !3;
        if advance >= rest.len() {
            break;
        }
        rest = &rest[advance..];
    }

    let dst = dst?;
    let prefix = match family {
        AF_INET if dst.len() >= 4 => {
            let o: [u8; 4] = dst[..4].try_into().ok()?;
            IpNet::V4(Ipv4Net::new(Ipv4Addr::from(o), dst_len).ok()?)
        }
        AF_INET6 if dst.len() >= 16 => {
            let o: [u8; 16] = dst[..16].try_into().ok()?;
            IpNet::V6(Ipv6Net::new(Ipv6Addr::from(o), dst_len).ok()?)
        }
        _ => return None,
    };

    Some(RouteOffload {
        prefix,
        vrf_ifindex: table_attr.unwrap_or(table),
        protocol,
        success: flags & RTM_F_OFFLOAD_FAILED == 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fib::fpm::testdata::read_capture;

    /// Every reverse-direction message in the suppression-**enabled**
    /// trace must parse. These are the synthesized minimal acks.
    #[test]
    fn parses_orchagent_driven_acks() {
        let acks: Vec<RouteOffload> = read_capture("offload.fpm")
            .into_iter()
            .filter(|(dir, _)| *dir == 1)
            .filter_map(|(_, bytes)| parse_ack(&bytes))
            .collect();

        assert!(!acks.is_empty(), "no acks parsed from offload.fpm");
        assert!(acks.iter().all(|a| a.success));
        // Default VRF throughout the scenario.
        assert!(acks.iter().all(|a| a.vrf_ifindex == 0));
        // Static routes come back with FRR's 196, not 4.
        assert!(
            acks.iter().any(|a| a.protocol == 196),
            "expected RTPROT_ZSTATIC in {acks:?}"
        );
        assert!(
            acks.iter().any(|a| a.prefix.to_string() == "10.100.2.0/24"),
            "expected the ECMP prefix in {acks:?}"
        );
    }

    /// The suppression-**disabled** trace: full-route echoes. Same
    /// parser, same fields, despite carrying nexthop attributes the
    /// other shape lacks — which is exactly the property that matters.
    #[test]
    fn parses_optimistic_acks() {
        let acks: Vec<RouteOffload> = read_capture("offload-optimistic.fpm")
            .into_iter()
            .filter(|(dir, _)| *dir == 1)
            .filter_map(|(_, bytes)| parse_ack(&bytes))
            .collect();

        assert!(
            !acks.is_empty(),
            "no acks parsed from offload-optimistic.fpm"
        );
        assert!(acks.iter().all(|a| a.success));
        assert!(
            acks.iter().any(|a| a.prefix.to_string() == "10.100.2.0/24"),
            "expected the ECMP prefix in {acks:?}"
        );
        // v6 acks parse too — the family byte drives the prefix width.
        assert!(
            acks.iter()
                .any(|a| a.prefix.to_string().contains("2001:db8:101::")),
            "expected a v6 ack in {acks:?}"
        );
    }

    /// Outbound route messages carry no offload flag and must not be
    /// mistaken for acknowledgements — the tee reads and writes the same
    /// socket, and a self-confusing parser would ack every route it sent.
    #[test]
    fn outbound_routes_are_not_acks() {
        let parsed = read_capture("basic.fpm")
            .into_iter()
            .filter(|(dir, _)| *dir == 0)
            .filter_map(|(_, bytes)| parse_ack(&bytes))
            .count();
        assert_eq!(parsed, 0, "outbound routes parsed as acknowledgements");
    }

    #[test]
    fn malformed_input_is_none_not_panic() {
        assert!(parse_ack(&[]).is_none());
        assert!(parse_ack(&[1, 1, 0, 4]).is_none());
        assert!(parse_ack(&[1, 1, 0, 8, 0xff, 0xff, 0xff, 0xff]).is_none());
        // Truncated netlink body.
        let mut m = vec![1u8, 1, 0, 24];
        m.extend_from_slice(&[0u8; 20]);
        assert!(parse_ack(&m).is_none());
    }
}
