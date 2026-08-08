//! A deliberately hand-rolled netlink decoder for FPM payloads.
//!
//! Why not a netlink crate: SONiC's FPM is *not* stock rtnetlink. The
//! `dplane_fpm_sonic` plugin sends private message types — `1000/1001`
//! (SRv6 local SID), `2000/2001` (PIC context), `3000/3001` (SRv6 VPN
//! route) — plus the `RTM_FPM_*` block at 140-148 for EVPN multihoming,
//! and it sets `NLA_F_NESTED` on attributes upstream never nests. A
//! strict parser rejects exactly the messages we most need to see. This
//! decoder is permissive by design: it names what it recognizes, prints
//! the rest as hex, and never refuses a message.
//!
//! This is a *diagnostic* view, not a specification. The capture file
//! holds the authoritative bytes; everything here is a lens onto them.

use std::fmt::Write as _;

use crate::frame::{FPM_MSG_HDR_LEN, Header};

/// Netlink message header length (`NLMSG_HDRLEN`).
const NLMSG_HDRLEN: usize = 16;
/// `struct rtmsg`.
const RTMSG_LEN: usize = 12;
/// `struct nhmsg`.
const NHMSG_LEN: usize = 8;
/// `NLA_F_NESTED` — FRR 7.5+ sets this on `RTA_ENCAP`, and `fpmsyncd`
/// masks it off before dispatching (`fpmlink.cpp:24-31`).
const NLA_F_NESTED: u16 = 0x8000;

/// `RTM_F_OFFLOAD` — the bit `fpmsyncd` sets on the reply it sends back
/// to zebra once a route lands in APPL_STATE_DB. Highlighted in output
/// because this bit is the entire Phase-2 feedback loop.
const RTM_F_OFFLOAD: u32 = 0x4000;
const RTM_F_TRAP: u32 = 0x8000;
const RTM_F_OFFLOAD_FAILED: u32 = 0x2000_0000;

fn nlmsg_type_name(t: u16) -> String {
    let name = match t {
        16 => "RTM_NEWLINK",
        17 => "RTM_DELLINK",
        20 => "RTM_NEWADDR",
        21 => "RTM_DELADDR",
        24 => "RTM_NEWROUTE",
        25 => "RTM_DELROUTE",
        26 => "RTM_GETROUTE",
        28 => "RTM_NEWNEIGH",
        29 => "RTM_DELNEIGH",
        44 => "RTM_NEWTFILTER",
        45 => "RTM_DELTFILTER",
        104 => "RTM_NEWNEXTHOP",
        105 => "RTM_DELNEXTHOP",
        106 => "RTM_GETNEXTHOP",
        // SONiC EVPN multihoming block (fpm.h rtm_fpm_msg_types_et).
        140 => "RTM_FPM_GETENCAPS",
        141 => "RTM_FPM_ADDENCAP",
        142 => "RTM_FPM_DELENCAP",
        143 => "RTM_FPM_ADD_EVPN_SHL",
        144 => "RTM_FPM_DEL_EVPN_SHL",
        145 => "RTM_FPM_ADD_EVPN_DF",
        146 => "RTM_FPM_DEL_EVPN_DF",
        147 => "RTM_FPM_ADD_EVPN_ES_BACKUP_NHG",
        148 => "RTM_FPM_DEL_EVPN_ES_BACKUP_NHG",
        // SONiC private types (fpmsyncd/fpmlink.h:19-24).
        1000 => "RTM_NEWSRV6LOCALSID",
        1001 => "RTM_DELSRV6LOCALSID",
        2000 => "RTM_NEWPICCONTEXT",
        2001 => "RTM_DELPICCONTEXT",
        3000 => "RTM_NEWSRV6VPNROUTE",
        3001 => "RTM_DELSRV6VPNROUTE",
        _ => return format!("TYPE_{t}"),
    };
    name.to_string()
}

fn nl_flags(f: u16) -> String {
    let mut v = Vec::new();
    for (bit, name) in [
        (0x0001, "REQUEST"),
        (0x0002, "MULTI"),
        (0x0004, "ACK"),
        (0x0008, "ECHO"),
        (0x0100, "REPLACE"),
        (0x0200, "EXCL"),
        (0x0400, "CREATE"),
        (0x0800, "APPEND"),
    ] {
        if f & bit != 0 {
            v.push(name);
        }
    }
    if v.is_empty() {
        "0".to_string()
    } else {
        v.join("|")
    }
}

fn rt_proto(p: u8) -> String {
    // fpmsyncd turns this byte into APPL_DB's `protocol` field via
    // rtnl_route_proto2str (routesync.cpp:960), so it is load-bearing,
    // not cosmetic.
    //
    // The 186-198 block is **FRR's private numbering**, declared in
    // zebra/rt_netlink.h — not standard rtnetlink. The trap: FRR maps
    // ZEBRA_ROUTE_STATIC to RTPROT_ZSTATIC (196), *not* RTPROT_STATIC
    // (4), and maps connected/local/kernel all to RTPROT_KERNEL (2)
    // (zebra2proto(), rt_netlink.c:246). An encoder that reaches for the
    // obvious standard constants produces a different APPL_DB
    // `protocol` value than FRR did, for every static and connected
    // route.
    let name = match p {
        0 => "unspec",
        1 => "redirect",
        2 => "kernel",
        3 => "boot",
        4 => "static",
        11 => "zebra",
        42 => "babel",
        186 => "bgp",
        187 => "isis",
        188 => "ospf",
        189 => "rip",
        190 => "ripng",
        191 => "nhrp",
        192 => "eigrp",
        193 => "ldp",
        194 => "sharp",
        195 => "pbr",
        196 => "zstatic",
        197 => "openfabric",
        198 => "srte",
        _ => return format!("{p}"),
    };
    name.to_string()
}

fn rt_scope(s: u8) -> String {
    let name = match s {
        0 => "universe",
        200 => "site",
        253 => "link",
        254 => "host",
        255 => "nowhere",
        _ => return format!("{s}"),
    };
    name.to_string()
}

fn rt_type(t: u8) -> String {
    let name = match t {
        0 => "unspec",
        1 => "unicast",
        2 => "local",
        3 => "broadcast",
        4 => "anycast",
        5 => "multicast",
        6 => "blackhole",
        7 => "unreachable",
        8 => "prohibit",
        9 => "throw",
        10 => "nat",
        _ => return format!("{t}"),
    };
    name.to_string()
}

fn rtm_flags(f: u32) -> String {
    let mut v = Vec::new();
    for (bit, name) in [
        (0x0100u32, "CLONED"),
        (0x0200, "EQUALIZE"),
        (0x0400, "PREFIX"),
        (RTM_F_OFFLOAD, "OFFLOAD"),
        (RTM_F_TRAP, "TRAP"),
        (RTM_F_OFFLOAD_FAILED, "OFFLOAD_FAILED"),
    ] {
        if f & bit != 0 {
            v.push(name);
        }
    }
    if v.is_empty() {
        "0".to_string()
    } else {
        v.join("|")
    }
}

fn af_name(f: u8) -> &'static str {
    match f {
        2 => "inet",
        7 => "bridge",
        10 => "inet6",
        24 => "mpls",
        _ => "af?",
    }
}

fn rta_name(t: u16) -> String {
    let name = match t & !NLA_F_NESTED {
        0 => "RTA_UNSPEC",
        1 => "RTA_DST",
        2 => "RTA_SRC",
        3 => "RTA_IIF",
        4 => "RTA_OIF",
        5 => "RTA_GATEWAY",
        6 => "RTA_PRIORITY",
        7 => "RTA_PREFSRC",
        8 => "RTA_METRICS",
        9 => "RTA_MULTIPATH",
        12 => "RTA_CACHEINFO",
        15 => "RTA_TABLE",
        16 => "RTA_MARK",
        18 => "RTA_VIA",
        19 => "RTA_NEWDST",
        20 => "RTA_PREF",
        21 => "RTA_ENCAP_TYPE",
        22 => "RTA_ENCAP",
        23 => "RTA_EXPIRES",
        30 => "RTA_NH_ID",
        other => return format!("RTA_{other}"),
    };
    if t & NLA_F_NESTED != 0 {
        format!("{name}|NESTED")
    } else {
        name.to_string()
    }
}

fn nha_name(t: u16) -> String {
    let name = match t & !NLA_F_NESTED {
        1 => "NHA_ID",
        2 => "NHA_GROUP",
        3 => "NHA_GROUP_TYPE",
        4 => "NHA_BLACKHOLE",
        5 => "NHA_OIF",
        6 => "NHA_GATEWAY",
        7 => "NHA_ENCAP_TYPE",
        8 => "NHA_ENCAP",
        9 => "NHA_GROUPS",
        10 => "NHA_MASTER",
        other => return format!("NHA_{other}"),
    };
    name.to_string()
}

fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Render an address payload. Length decides the family, not the
/// caller's claim — an `RTA_GATEWAY` on an IPv6 route may still be a
/// v4-mapped hop in some encodings, and guessing from `rtm_family`
/// would misprint it.
fn addr(data: &[u8]) -> String {
    match data.len() {
        4 => format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]),
        16 => {
            let groups: Vec<String> = data
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            // Not RFC 5952 canonical (no :: compression) — deliberately
            // literal, so two captures diff cleanly.
            groups.join(":")
        }
        _ => hex(data),
    }
}

fn u32_le(data: &[u8]) -> Option<u32> {
    (data.len() >= 4).then(|| u32::from_le_bytes(data[..4].try_into().unwrap()))
}

/// One parsed attribute: type, payload.
struct Attr<'a> {
    atype: u16,
    data: &'a [u8],
}

/// Walk a netlink TLV block. Malformed trailing bytes stop the walk
/// rather than erroring — see the module note on permissiveness.
fn attrs(mut buf: &[u8]) -> Vec<Attr<'_>> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let atype = u16::from_le_bytes([buf[2], buf[3]]);
        if len < 4 || len > buf.len() {
            break;
        }
        out.push(Attr {
            atype,
            data: &buf[4..len],
        });
        let advance = (len + 3) & !3;
        if advance >= buf.len() {
            break;
        }
        buf = &buf[advance..];
    }
    out
}

/// A decoded message: a one-line `summary` for streaming output and a
/// multi-line `detail` for `decode`.
pub struct Decoded {
    pub nl_type: u16,
    pub summary: String,
    pub detail: String,
}

/// Decode one complete FPM message (header included).
pub fn decode(msg: &[u8]) -> Decoded {
    let Some(hdr) = Header::parse(msg) else {
        return Decoded {
            nl_type: 0,
            summary: format!("<runt {} byte message>", msg.len()),
            detail: hex(msg),
        };
    };
    let payload = &msg[FPM_MSG_HDR_LEN.min(msg.len())..];

    let mut detail = String::new();
    let _ = writeln!(
        detail,
        "fpm: version={} type={} msg_len={} (payload {})",
        hdr.version,
        hdr.msg_type,
        hdr.msg_len,
        payload.len()
    );

    if payload.len() < NLMSG_HDRLEN {
        return Decoded {
            nl_type: 0,
            summary: format!("<truncated netlink, {} bytes>", payload.len()),
            detail: detail + &hex(payload),
        };
    }

    let nl_len = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let nl_type = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    let nl_flags_raw = u16::from_le_bytes(payload[6..8].try_into().unwrap());
    let nl_seq = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let nl_pid = u32::from_le_bytes(payload[12..16].try_into().unwrap());

    let _ = writeln!(
        detail,
        "nl:  len={} type={} ({}) flags={} seq={} pid={}",
        nl_len,
        nl_type,
        nlmsg_type_name(nl_type),
        nl_flags(nl_flags_raw),
        nl_seq,
        nl_pid
    );

    // The FPM frame pads to 4 bytes, so a payload up to 3 bytes longer
    // than the netlink message is normal. Anything else means the two
    // length fields genuinely disagree — worth surfacing, since an
    // encoder that gets this wrong produces messages fpmsyncd will
    // silently mis-slice rather than reject.
    let pad = hdr.data_len().saturating_sub(nl_len);
    if nl_len > hdr.data_len() || pad > 3 {
        let _ = writeln!(
            detail,
            "     !! length mismatch: netlink says {} but FPM payload is {}",
            nl_len,
            hdr.data_len()
        );
    }

    // Trust the netlink header's own length over the FPM frame's, but
    // never read past the buffer — a mismatch is itself worth seeing.
    let body_end = nl_len.min(payload.len());
    let body = &payload[NLMSG_HDRLEN..body_end.max(NLMSG_HDRLEN)];

    let summary = match nl_type {
        24 | 25 | 3000 | 3001 | 1000 | 1001 => {
            decode_route(nl_type, nl_flags_raw, body, &mut detail)
        }
        104 | 105 => decode_nexthop(nl_type, body, &mut detail),
        _ => {
            let _ = writeln!(detail, "body: {}", hex(body));
            format!("{} ({} body bytes)", nlmsg_type_name(nl_type), body.len())
        }
    };

    Decoded {
        nl_type,
        summary,
        detail,
    }
}

/// `RTM_NEWROUTE`/`RTM_DELROUTE` and the SONiC route-shaped private
/// types, all of which lead with a `struct rtmsg`.
fn decode_route(nl_type: u16, nl_flags_raw: u16, body: &[u8], detail: &mut String) -> String {
    if body.len() < RTMSG_LEN {
        let _ = writeln!(detail, "rtm: <truncated: {} bytes>", body.len());
        return format!("{} <truncated>", nlmsg_type_name(nl_type));
    }
    let family = body[0];
    let dst_len = body[1];
    let src_len = body[2];
    let tos = body[3];
    let table = body[4];
    let protocol = body[5];
    let scope = body[6];
    let rtype = body[7];
    let flags = u32::from_le_bytes(body[8..12].try_into().unwrap());

    let _ = writeln!(
        detail,
        "rtm: family={} dst_len={} src_len={} tos={} table={} protocol={} scope={} type={} flags={}",
        af_name(family),
        dst_len,
        src_len,
        tos,
        table,
        rt_proto(protocol),
        rt_scope(scope),
        rt_type(rtype),
        rtm_flags(flags)
    );

    let mut dst = None;
    let mut table_attr = None;
    let mut nexthops: Vec<String> = Vec::new();
    let mut nh_id = None;

    for a in attrs(&body[RTMSG_LEN..]) {
        let name = rta_name(a.atype);
        match a.atype & !NLA_F_NESTED {
            1 => {
                dst = Some(addr(a.data));
                let _ = writeln!(detail, "  {name}: {}", addr(a.data));
            }
            4 => {
                let oif = u32_le(a.data).unwrap_or(0);
                nexthops.push(format!("dev {oif}"));
                let _ = writeln!(detail, "  {name}: {oif}");
            }
            5 => {
                nexthops.push(format!("via {}", addr(a.data)));
                let _ = writeln!(detail, "  {name}: {}", addr(a.data));
            }
            6 | 15 | 16 | 20 | 30 => {
                let v = u32_le(a.data).unwrap_or(0);
                if a.atype & !NLA_F_NESTED == 15 {
                    table_attr = Some(v);
                }
                if a.atype & !NLA_F_NESTED == 30 {
                    nh_id = Some(v);
                }
                let _ = writeln!(detail, "  {name}: {v}");
            }
            7 => {
                let _ = writeln!(detail, "  {name}: {}", addr(a.data));
            }
            9 => {
                let _ = writeln!(detail, "  {name}:");
                nexthops.extend(decode_multipath(a.data, detail));
            }
            _ => {
                let _ = writeln!(detail, "  {name}: {} ({} bytes)", hex(a.data), a.data.len());
            }
        }
    }

    let prefix = match dst {
        Some(d) => format!("{d}/{dst_len}"),
        // No RTA_DST with dst_len 0 is the default route.
        None if dst_len == 0 => "default".to_string(),
        None => format!("<no-dst>/{dst_len}"),
    };
    let tbl = table_attr.unwrap_or(table as u32);
    let mut s = format!(
        "{} {} table={} proto={} type={}",
        nlmsg_type_name(nl_type),
        prefix,
        tbl,
        rt_proto(protocol),
        rt_type(rtype)
    );
    if let Some(id) = nh_id {
        let _ = write!(s, " nhid={id}");
    }
    if !nexthops.is_empty() {
        let _ = write!(s, " [{}]", nexthops.join(", "));
    }
    if flags & (RTM_F_OFFLOAD | RTM_F_TRAP | RTM_F_OFFLOAD_FAILED) != 0 {
        let _ = write!(s, " {}", rtm_flags(flags));
    }
    let nlf = nl_flags(nl_flags_raw);
    if nlf != "0" {
        let _ = write!(s, " ({nlf})");
    }
    s
}

/// `RTA_MULTIPATH` — a packed array of `struct rtnexthop`, each with its
/// own nested TLV block. This is the encoding SONiC uses by default,
/// because `docker_init.sh` writes `no fpm use-next-hop-groups` into
/// zebra.conf.
fn decode_multipath(mut buf: &[u8], detail: &mut String) -> Vec<String> {
    let mut out = Vec::new();
    while buf.len() >= 8 {
        let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let flags = buf[2];
        let hops = buf[3];
        let ifindex = i32::from_le_bytes(buf[4..8].try_into().unwrap());
        if len < 8 || len > buf.len() {
            break;
        }
        let mut leg = format!("dev {ifindex} weight {}", hops as u16 + 1);
        let _ = writeln!(
            detail,
            "    nexthop: len={len} flags={flags:#x} hops={hops} ifindex={ifindex}"
        );
        for a in attrs(&buf[8..len]) {
            let name = rta_name(a.atype);
            match a.atype & !NLA_F_NESTED {
                5 => {
                    leg = format!("via {} {leg}", addr(a.data));
                    let _ = writeln!(detail, "      {name}: {}", addr(a.data));
                }
                30 => {
                    let _ = writeln!(detail, "      {name}: {}", u32_le(a.data).unwrap_or(0));
                }
                _ => {
                    let _ = writeln!(detail, "      {name}: {}", hex(a.data));
                }
            }
        }
        out.push(leg);
        let advance = (len + 3) & !3;
        if advance >= buf.len() {
            break;
        }
        buf = &buf[advance..];
    }
    out
}

/// `RTM_NEWNEXTHOP`/`RTM_DELNEXTHOP` — kernel nexthop objects, sent only
/// when `fpm use-next-hop-groups` is enabled. `fpmsyncd` turns these
/// into `APP_NEXTHOP_GROUP_TABLE` rows.
fn decode_nexthop(nl_type: u16, body: &[u8], detail: &mut String) -> String {
    if body.len() < NHMSG_LEN {
        let _ = writeln!(detail, "nhm: <truncated: {} bytes>", body.len());
        return format!("{} <truncated>", nlmsg_type_name(nl_type));
    }
    let family = body[0];
    let scope = body[1];
    let protocol = body[2];
    let flags = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let _ = writeln!(
        detail,
        "nhm: family={} scope={} protocol={} flags={flags:#x}",
        af_name(family),
        rt_scope(scope),
        rt_proto(protocol)
    );

    let mut id = None;
    let mut members = Vec::new();
    let mut leg = Vec::new();
    for a in attrs(&body[NHMSG_LEN..]) {
        let name = nha_name(a.atype);
        match a.atype & !NLA_F_NESTED {
            1 => {
                id = u32_le(a.data);
                let _ = writeln!(detail, "  {name}: {}", id.unwrap_or(0));
            }
            2 => {
                // NHA_GROUP is an array of struct nexthop_grp
                // { u32 id; u8 weight; u8 resvd1; u16 resvd2; }.
                for chunk in a.data.chunks(8) {
                    if chunk.len() == 8 {
                        let gid = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
                        members.push(format!("{}w{}", gid, chunk[4] as u16 + 1));
                    }
                }
                let _ = writeln!(detail, "  {name}: [{}]", members.join(", "));
            }
            5 => {
                let oif = u32_le(a.data).unwrap_or(0);
                leg.push(format!("dev {oif}"));
                let _ = writeln!(detail, "  {name}: {oif}");
            }
            6 => {
                leg.push(format!("via {}", addr(a.data)));
                let _ = writeln!(detail, "  {name}: {}", addr(a.data));
            }
            4 => {
                leg.push("blackhole".to_string());
                let _ = writeln!(detail, "  {name}");
            }
            _ => {
                let _ = writeln!(detail, "  {name}: {}", hex(a.data));
            }
        }
    }

    let mut s = format!("{} id={}", nlmsg_type_name(nl_type), id.unwrap_or(0));
    if !members.is_empty() {
        let _ = write!(s, " group=[{}]", members.join(", "));
    }
    if !leg.is_empty() {
        let _ = write!(s, " [{}]", leg.join(" "));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::frame;

    /// Build an `RTM_NEWROUTE` for 10.1.1.0/24 via 10.0.0.1 dev 3,
    /// proto bgp, table 254 — the shape of the simplest golden trace.
    fn sample_route() -> Vec<u8> {
        let mut nl = Vec::new();
        let mut body = Vec::new();
        // struct rtmsg
        body.extend_from_slice(&[
            2,   // family AF_INET
            24,  // dst_len
            0,   // src_len
            0,   // tos
            254, // table RT_TABLE_MAIN
            186, // protocol RTPROT_BGP
            0,   // scope universe
            1,   // type RTN_UNICAST
        ]);
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        // RTA_DST
        body.extend_from_slice(&8u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[10, 1, 1, 0]);
        // RTA_GATEWAY
        body.extend_from_slice(&8u16.to_le_bytes());
        body.extend_from_slice(&5u16.to_le_bytes());
        body.extend_from_slice(&[10, 0, 0, 1]);
        // RTA_OIF
        body.extend_from_slice(&8u16.to_le_bytes());
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());

        let total = NLMSG_HDRLEN + body.len();
        nl.extend_from_slice(&(total as u32).to_le_bytes());
        nl.extend_from_slice(&24u16.to_le_bytes()); // RTM_NEWROUTE
        nl.extend_from_slice(&(0x0001u16 | 0x0400 | 0x0100).to_le_bytes()); // REQUEST|CREATE|REPLACE
        nl.extend_from_slice(&1u32.to_le_bytes()); // seq
        nl.extend_from_slice(&0u32.to_le_bytes()); // pid
        nl.extend_from_slice(&body);
        frame(&nl).unwrap()
    }

    #[test]
    fn decodes_a_route() {
        let d = decode(&sample_route());
        assert_eq!(d.nl_type, 24);
        assert!(d.summary.contains("RTM_NEWROUTE"), "{}", d.summary);
        assert!(d.summary.contains("10.1.1.0/24"), "{}", d.summary);
        assert!(d.summary.contains("proto=bgp"), "{}", d.summary);
        assert!(d.summary.contains("table=254"), "{}", d.summary);
        assert!(d.summary.contains("via 10.0.0.1"), "{}", d.summary);
        assert!(d.summary.contains("dev 3"), "{}", d.summary);
        assert!(d.detail.contains("RTA_DST"), "{}", d.detail);
    }

    #[test]
    fn names_sonic_private_types() {
        assert_eq!(nlmsg_type_name(1000), "RTM_NEWSRV6LOCALSID");
        assert_eq!(nlmsg_type_name(2001), "RTM_DELPICCONTEXT");
        assert_eq!(nlmsg_type_name(3000), "RTM_NEWSRV6VPNROUTE");
        assert_eq!(nlmsg_type_name(143), "RTM_FPM_ADD_EVPN_SHL");
    }

    /// Guards the two protocol values most likely to be encoded wrong,
    /// both observed in the `golden/basic.fpm` capture from real SONiC
    /// FRR: static routes arrive as 196 (RTPROT_ZSTATIC), and connected
    /// routes as 2 (RTPROT_KERNEL) — not 4 and not 11.
    #[test]
    fn uses_frrs_private_protocol_numbering() {
        assert_eq!(rt_proto(196), "zstatic");
        assert_eq!(rt_proto(2), "kernel");
        assert_eq!(rt_proto(186), "bgp");
        assert_eq!(rt_proto(4), "static");
    }

    #[test]
    fn surfaces_the_offload_bit() {
        assert!(rtm_flags(RTM_F_OFFLOAD).contains("OFFLOAD"));
        assert_eq!(rtm_flags(0), "0");
    }

    #[test]
    fn survives_a_truncated_message() {
        // Must not panic — captures from a killed rig end like this.
        let d = decode(&[1, 1, 0, 8, 0xff, 0xff]);
        assert!(!d.summary.is_empty());
    }

    #[test]
    fn formats_addresses_by_length() {
        assert_eq!(addr(&[192, 0, 2, 1]), "192.0.2.1");
        assert_eq!(
            addr(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001:db8:0:0:0:0:0:1"
        );
        assert_eq!(addr(&[1, 2, 3]), "010203");
    }
}
