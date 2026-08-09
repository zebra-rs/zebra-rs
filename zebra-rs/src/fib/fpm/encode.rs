//! Netlink encoders for the FPM southbound.
//!
//! These produce the exact bytes SONiC's FRR puts on the wire. That is a
//! stronger requirement than "a valid rtnetlink message": `fpmsyncd`
//! copies several fields straight into APPL_DB, so a semantically
//! equivalent encoding still shows up as a behavioural diff against the
//! FRR the port is replacing. Every rule below was read off a capture
//! from real SONiC FRR 10.5.4 (`tools/fpm-tap/golden/`), and the tests at
//! the bottom assert byte-equality against those recordings.
//!
//! Three rules are worth stating up front, because the obvious choice is
//! wrong in each case:
//!
//! * **Table is a VRF ifindex, not a routing-table id.** The SONiC dplane
//!   plugin explicitly substitutes one for the other
//!   (`dplane_fpm_sonic.c:1232-1242`: "Put vrf if_index instead of table
//!   id"), and `fpmsyncd` calls `getIfName()` on the value it reads
//!   (`routesync.cpp:920-942`). The default VRF is 0 — sending
//!   `RT_TABLE_MAIN` (254) would send fpmsyncd looking for an interface
//!   with ifindex 254.
//! * **Protocol uses FRR's private numbering** from `zebra/rt_netlink.h`,
//!   not the standard rtnetlink constants: static is 196
//!   (`RTPROT_ZSTATIC`) rather than 4, and connected collapses into 2
//!   (`RTPROT_KERNEL`) rather than 11.
//! * **The nexthop encoding switches on count.** Exactly one leg is flat
//!   `RTA_GATEWAY` + `RTA_OIF`; two or more become `RTA_MULTIPATH`.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::rib::entry::RibEntry;
use crate::rib::{Nexthop, NexthopMember, NexthopUni, RibType};

use super::frame;

// ── netlink message header ──────────────────────────────────────────
const NLMSG_HDRLEN: usize = 16;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;

// ── struct rtmsg ────────────────────────────────────────────────────
const RTMSG_LEN: usize = 12;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RT_SCOPE_UNIVERSE: u8 = 0;

const RTN_UNSPEC: u8 = 0;
const RTN_UNICAST: u8 = 1;
const RTN_BLACKHOLE: u8 = 6;

// ── route attributes ────────────────────────────────────────────────
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_MULTIPATH: u16 = 9;
/// `RTA_VIA` — a gateway in a different address family than the route
/// (RFC 5549: a v4 prefix reached over a v6 next-hop). `RTA_GATEWAY`'s
/// payload is sized by the ROUTE family, so putting 16 bytes of v6
/// address there makes the reader take the first 4 as an IPv4 gateway;
/// `RTA_VIA` carries its own 2-byte family header instead, which is
/// what FRR emits for the unnumbered case.
const RTA_VIA: u16 = 18;
/// FRR sets this on `RTA_MULTIPATH` (and `RTA_ENCAP`); `fpmsyncd` masks
/// it back off in `netlink_parse_rtattr` (`fpmlink.cpp:24-31`). Emitting
/// the bare attribute type would parse fine but not match the wire.
const NLA_F_NESTED: u16 = 0x8000;

// ── FRR's private protocol numbering (zebra/rt_netlink.h) ───────────
const RTPROT_KERNEL: u8 = 2;
const RTPROT_BGP: u8 = 186;
const RTPROT_ISIS: u8 = 187;
const RTPROT_OSPF: u8 = 188;
const RTPROT_ZSTATIC: u8 = 196;

/// Which netlink message to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOp {
    Add,
    Del,
}

impl RouteOp {
    fn nlmsg_type(self) -> u16 {
        match self {
            RouteOp::Add => RTM_NEWROUTE,
            RouteOp::Del => RTM_DELROUTE,
        }
    }

    /// Adds are `REQUEST|REPLACE|CREATE` — FPM has replace semantics, so
    /// a second add for a prefix supersedes the first outright. Deletes
    /// drop `REPLACE` but, oddly, keep `CREATE`; that is what FRR sends,
    /// and `fpmsyncd` keys only on the message type.
    fn nlmsg_flags(self) -> u16 {
        match self {
            RouteOp::Add => NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE,
            RouteOp::Del => NLM_F_REQUEST | NLM_F_CREATE,
        }
    }
}

/// Map a RIB route source to the protocol byte FRR would have sent.
///
/// This value reaches APPL_DB's `protocol` field verbatim (via
/// `rtnl_route_proto2str`, `routesync.cpp:960`), so it is part of the
/// observable contract rather than an internal detail.
fn protocol(rtype: RibType) -> u8 {
    match rtype {
        RibType::Static => RTPROT_ZSTATIC,
        RibType::Bgp => RTPROT_BGP,
        RibType::Ospf => RTPROT_OSPF,
        RibType::Isis => RTPROT_ISIS,
        // zebra2proto() folds CONNECT, LOCAL and KERNEL together
        // (rt_netlink.c:295-299).
        RibType::Connected | RibType::Kernel => RTPROT_KERNEL,
        _ => RTPROT_ZSTATIC,
    }
}

/// One flattened forwarding leg, in the only terms FPM can express.
///
/// Everything richer that a `NexthopUni` carries — MPLS label stacks,
/// SRv6 segment lists, fast-reroute backups — has no place in this
/// encoding and is dropped here deliberately. SONiC carries those over
/// the private message types (`RTM_NEWSRV6VPNROUTE` and friends), which
/// are a separate encoder.
struct Leg {
    gateway: Option<IpAddr>,
    ifindex: u32,
    weight: u8,
}

fn leg_of(uni: &NexthopUni) -> Leg {
    Leg {
        // An unspecified address means "no gateway" — an interface
        // (on-link) nexthop, which FRR encodes as RTA_OIF with no
        // RTA_GATEWAY at all.
        gateway: (!uni.addr.is_unspecified()).then_some(uni.addr),
        ifindex: uni.ifindex().unwrap_or(0),
        weight: uni.weight,
    }
}

/// Flatten a RIB nexthop into the legs FPM can carry.
///
/// `Protect` contributes only its primary: the backup exists to be
/// pre-installed in the kernel at a worse metric, and FPM has no way to
/// say "standby". Sending it would look like a second ECMP leg and
/// blackhole traffic across it.
fn legs(nexthop: &Nexthop) -> Vec<Leg> {
    match nexthop {
        Nexthop::Uni(uni) => vec![leg_of(uni)],
        Nexthop::Multi(multi) => multi.nexthops.iter().map(leg_of).collect(),
        Nexthop::List(list) => list.nexthops.iter().flat_map(member_legs).collect(),
        Nexthop::Protect(pro) => match &pro.primary {
            NexthopMember::Uni(uni) => vec![leg_of(uni)],
            NexthopMember::Multi(multi) => multi.nexthops.iter().map(leg_of).collect(),
        },
        // Blackhole carries no leg by construction; Link is the
        // placeholder default and has nothing to forward to.
        Nexthop::Blackhole(_) | Nexthop::Link(_) => vec![],
    }
}

fn member_legs(member: &NexthopMember) -> Vec<Leg> {
    match member {
        NexthopMember::Uni(uni) => vec![leg_of(uni)],
        NexthopMember::Multi(multi) => multi.nexthops.iter().map(leg_of).collect(),
    }
}

/// Incremental netlink writer. Netlink is host-endian and every SONiC
/// target is little-endian, which is also what the captures show, so the
/// little-endian encoding is written explicitly rather than relying on
/// `to_ne_bytes`.
#[derive(Default)]
struct NlWriter {
    buf: Vec<u8>,
}

impl NlWriter {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Pad to the 4-byte boundary netlink attributes are aligned on.
    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// One `struct rtattr`: length (header included), type, payload, pad.
    fn attr(&mut self, atype: u16, payload: &[u8]) {
        self.u16((4 + payload.len()) as u16);
        self.u16(atype);
        self.bytes(payload);
        self.pad();
    }

    fn attr_u32(&mut self, atype: u16, v: u32) {
        self.attr(atype, &v.to_le_bytes());
    }

    fn attr_addr(&mut self, atype: u16, addr: IpAddr) {
        match addr {
            IpAddr::V4(a) => self.attr(atype, &a.octets()),
            IpAddr::V6(a) => self.attr(atype, &a.octets()),
        }
    }

    /// A gateway attribute, family-aware: `RTA_GATEWAY` when the
    /// gateway matches the route's family, `RTA_VIA` (`struct rtvia`:
    /// 2-byte family + address bytes) when it does not — see the
    /// `RTA_VIA` constant for why the mismatch cannot ride
    /// `RTA_GATEWAY`.
    fn attr_gateway(&mut self, route_family: u8, gw: IpAddr) {
        let gw_family = if gw.is_ipv6() { AF_INET6 } else { AF_INET };
        if gw_family == route_family {
            self.attr_addr(RTA_GATEWAY, gw);
            return;
        }
        let mut payload = Vec::with_capacity(18);
        payload.extend_from_slice(&(gw_family as u16).to_le_bytes());
        match gw {
            IpAddr::V4(a) => payload.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => payload.extend_from_slice(&a.octets()),
        }
        self.attr(RTA_VIA, &payload);
    }

    /// Open a nested attribute, returning the offset to back-patch.
    fn nest_start(&mut self, atype: u16) -> usize {
        let off = self.buf.len();
        self.u16(0); // length, patched by nest_end
        self.u16(atype);
        off
    }

    fn nest_end(&mut self, off: usize) {
        let len = (self.buf.len() - off) as u16;
        self.buf[off..off + 2].copy_from_slice(&len.to_le_bytes());
    }
}

/// Encode one route as a complete, framed FPM message.
///
/// `vrf_ifindex` is the **ifindex of the VRF device**, 0 for the default
/// VRF — not a kernel routing-table id. See the module note.
///
/// Returns `None` when there is nothing to send: a nexthop shape with no
/// forwarding legs on an add would produce a route `fpmsyncd` cannot use.
pub fn encode_route(
    op: RouteOp,
    prefix: &IpNet,
    entry: &RibEntry,
    vrf_ifindex: u32,
) -> Option<Vec<u8>> {
    let legs = legs(&entry.nexthop);
    let blackhole = matches!(entry.nexthop, Nexthop::Blackhole(_));

    // A delete carries no nexthops at all, so it is fine without legs.
    // An add without them is not: it would install an unusable route.
    if op == RouteOp::Add && legs.is_empty() && !blackhole {
        return None;
    }

    let mut w = NlWriter::default();

    // Netlink header — length is back-patched once the body is known.
    // `seq` and `pid` are both 0: FRR sends a random per-session nonce as
    // pid, but nothing reads either field (there is no request/response
    // correlation in FPM), and zeroes keep the output deterministic.
    w.u32(0);
    w.u16(op.nlmsg_type());
    w.u16(op.nlmsg_flags());
    w.u32(0); // seq
    w.u32(0); // pid

    // struct rtmsg.
    let (family, dst_bytes) = match prefix {
        IpNet::V4(p) => (AF_INET, p.addr().octets().to_vec()),
        IpNet::V6(p) => (AF_INET6, p.addr().octets().to_vec()),
    };
    w.u8(family);
    w.u8(prefix.prefix_len());
    w.u8(0); // src_len
    w.u8(0); // tos
    // Table: see the module note — this is a VRF ifindex. Values of 256
    // and above move to RTA_TABLE, mirroring dplane_fpm_sonic.c:1499-1505.
    w.u8(if vrf_ifindex < 256 {
        vrf_ifindex as u8
    } else {
        0
    });
    w.u8(protocol(entry.rtype));
    // fpmsyncd never reads rtm_scope; FRR sends universe here.
    w.u8(RT_SCOPE_UNIVERSE);
    w.u8(match op {
        // A delete identifies the route by prefix alone, and FRR leaves
        // the type unset rather than repeating it.
        RouteOp::Del => RTN_UNSPEC,
        RouteOp::Add if blackhole => RTN_BLACKHOLE,
        RouteOp::Add => RTN_UNICAST,
    });
    w.u32(0); // flags

    // Attribute order matches FRR's exactly: destination, metric, then
    // nexthop information. fpmsyncd does not care about order, but a
    // golden-trace diff does, and that diff is the regression test.
    w.attr(RTA_DST, &dst_bytes);
    w.attr_u32(RTA_PRIORITY, entry.metric);

    if vrf_ifindex >= 256 {
        w.attr_u32(super::encode::RTA_TABLE, vrf_ifindex);
    }

    if !blackhole && op == RouteOp::Add {
        if legs.len() == 1 {
            // Single leg: flat attributes, no multipath wrapper.
            let leg = &legs[0];
            if let Some(gw) = leg.gateway {
                w.attr_gateway(family, gw);
            }
            w.attr_u32(RTA_OIF, leg.ifindex);
        } else {
            let nest = w.nest_start(RTA_MULTIPATH | NLA_F_NESTED);
            for leg in &legs {
                // struct rtnexthop: len, flags, hops, ifindex. `hops` is
                // weight-1, and the ifindex lives here rather than in a
                // nested RTA_OIF.
                let rtnh_off = w.buf.len();
                w.u16(0); // rtnh_len, patched below
                w.u8(0); // rtnh_flags
                w.u8(leg.weight.saturating_sub(1));
                w.u32(leg.ifindex);
                if let Some(gw) = leg.gateway {
                    w.attr_gateway(family, gw);
                }
                let rtnh_len = (w.buf.len() - rtnh_off) as u16;
                w.buf[rtnh_off..rtnh_off + 2].copy_from_slice(&rtnh_len.to_le_bytes());
            }
            w.nest_end(nest);
        }
    }

    // Back-patch nlmsg_len.
    let total = w.buf.len() as u32;
    w.buf[0..4].copy_from_slice(&total.to_le_bytes());
    debug_assert!(w.buf.len() >= NLMSG_HDRLEN + RTMSG_LEN);

    frame::frame(&w.buf)
}

/// Turn a framed SET (`RTM_NEWROUTE`) into the DELROUTE for the same
/// route, in place. Used by the VRF-delete flush, which holds only the
/// mirrored SET bytes: a full-bodied DELROUTE is legal, and reusing the
/// exact bytes guarantees the delete carries the same key
/// (prefix/table) the SET established.
pub fn set_msg_to_del(msg: &mut [u8]) {
    // FPM frame header (4 bytes) + nlmsg_len (4) puts nlmsg_type at 8.
    let off = frame::FPM_MSG_HDR_LEN + 4;
    if msg.len() >= off + 2 && u16::from_le_bytes([msg[off], msg[off + 1]]) == RTM_NEWROUTE {
        msg[off..off + 2].copy_from_slice(&RTM_DELROUTE.to_le_bytes());
    }
}

const RTA_TABLE: u16 = 15;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::Path;

    use super::*;
    use crate::rib::NexthopMulti;

    /// Minimal reader for the `fpm-tap` capture container
    /// (`tools/fpm-tap/src/capture.rs`): 8-byte magic, then records of
    /// `dir(u8) pad(3) usec(u64 LE) len(u32 LE) bytes(len)`.
    ///
    /// Duplicated here rather than shared, deliberately: pulling in a
    /// crate so a test can read a fixture would couple the daemon's
    /// build to a diagnostic tool. It is twenty lines and the format is
    /// frozen by the files already recorded.
    fn read_capture(name: &str) -> Vec<Vec<u8>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tools/fpm-tap/golden")
            .join(name);
        let data = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read golden trace {}: {e}", path.display()));
        assert_eq!(&data[..8], b"FPMTAP\x01\x00", "not an fpm-tap capture");

        let mut out = Vec::new();
        let mut pos = 8;
        while pos + 16 <= data.len() {
            let len = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap()) as usize;
            pos += 16;
            if pos + len > data.len() {
                break;
            }
            out.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        out
    }

    /// FRR stamps a random per-session nonce into `nlmsg_pid`; the
    /// encoder emits 0. Neither side reads it, so zero it on both before
    /// comparing.
    fn normalize(msg: &[u8]) -> Vec<u8> {
        let mut m = msg.to_vec();
        // 4 bytes FPM header + 12 into the netlink header.
        if m.len() >= 20 {
            m[16..20].fill(0);
        }
        m
    }

    /// Assert the encoder's output appears verbatim in a trace recorded
    /// from real SONiC FRR.
    fn assert_matches_frr(encoded: &[u8], trace: &str) {
        let want = normalize(encoded);
        let records: Vec<Vec<u8>> = read_capture(trace).iter().map(|r| normalize(r)).collect();
        if records.contains(&want) {
            return;
        }
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        // Same-length records are the plausible near-misses; showing
        // them makes a one-attribute diff obvious.
        let near: Vec<String> = records
            .iter()
            .filter(|r| r.len() == want.len())
            .map(|r| hex(r))
            .collect();
        panic!(
            "encoded message not found in {trace}\n  encoded: {}\n  same-length records:\n    {}",
            hex(&want),
            near.join("\n    ")
        );
    }

    fn uni(addr: &str, ifindex: u32) -> NexthopUni {
        let mut u = NexthopUni::new(addr.parse().unwrap(), 0, vec![]);
        u.ifindex_origin = Some(ifindex);
        u
    }

    fn entry(rtype: RibType, nexthop: Nexthop) -> RibEntry {
        let mut e = RibEntry::new(rtype);
        e.nexthop = nexthop;
        e
    }

    /// RFC 5549: a v4 prefix reached over a v6 next-hop (BGP
    /// unnumbered) must ride RTA_VIA, not RTA_GATEWAY — fpmsyncd sizes
    /// RTA_GATEWAY by the ROUTE family and would read the first four
    /// bytes of the v6 address as an IPv4 gateway.
    #[test]
    fn v4_over_v6_nexthop_uses_rta_via() {
        let e = entry(RibType::Bgp, Nexthop::Uni(uni("fe80::1", 3)));
        let msg = encode_route(RouteOp::Add, &"10.99.0.0/24".parse().unwrap(), &e, 0).unwrap();
        // struct rtvia: u16 family + 16 address bytes = 18 payload, 22
        // with the attribute header; family AF_INET6.
        let via_hdr = [22u8, 0, 18, 0, 10, 0];
        assert!(
            msg.windows(via_hdr.len()).any(|w| w == via_hdr),
            "no RTA_VIA attribute in the encoded message"
        );
        for gw_hdr in [[8u8, 0, 5, 0], [20u8, 0, 5, 0]] {
            assert!(
                !msg.windows(gw_hdr.len()).any(|w| w == gw_hdr),
                "a cross-family gateway must not ride RTA_GATEWAY"
            );
        }
        // Same-family single leg is untouched — the golden traces pin
        // that shape byte-for-byte in the tests below.
    }

    /// The VRF flush turns mirrored SETs into DELs by flipping the
    /// message type in place; everything else — the key fpmsyncd
    /// matches on — must survive byte-identical, and the result must
    /// still parse for the tombstone path.
    #[test]
    fn set_msg_to_del_flips_only_the_type() {
        let e = entry(RibType::Bgp, Nexthop::Uni(uni("192.0.2.1", 3)));
        let set = encode_route(RouteOp::Add, &"10.99.0.0/24".parse().unwrap(), &e, 7).unwrap();
        let mut del = set.clone();
        set_msg_to_del(&mut del);
        assert_eq!(
            u16::from_le_bytes([del[8], del[9]]),
            RTM_DELROUTE,
            "type must flip to RTM_DELROUTE"
        );
        assert_eq!(&del[..8], &set[..8], "frame + nlmsg_len untouched");
        assert_eq!(&del[10..], &set[10..], "body untouched");
        let (key, _) = super::super::decode::parse_route_key(&del)
            .expect("a flipped DEL must still parse for the tombstone path");
        assert_eq!(key.prefix, "10.99.0.0/24".parse::<IpNet>().unwrap());
        assert_eq!(key.vrf_ifindex, 7);
    }

    /// `ip route 10.100.0.0/24 10.0.0.2` — the simplest shape there is.
    #[test]
    fn single_nexthop_v4_matches_frr() {
        let e = entry(RibType::Static, Nexthop::Uni(uni("10.0.0.2", 3)));
        let msg = encode_route(RouteOp::Add, &"10.100.0.0/24".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "basic.fpm");
    }

    /// An interface nexthop: `ip route 10.100.1.0/24 dum1`. No gateway
    /// attribute at all, just RTA_OIF.
    #[test]
    fn interface_nexthop_v4_matches_frr() {
        let mut u = NexthopUni::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, vec![]);
        u.ifindex_origin = Some(4);
        let e = entry(RibType::Static, Nexthop::Uni(u));
        let msg = encode_route(RouteOp::Add, &"10.100.1.0/24".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "basic.fpm");
    }

    /// Two legs, so RTA_MULTIPATH rather than flat attributes.
    #[test]
    fn ecmp_v4_matches_frr() {
        let multi = NexthopMulti {
            metric: 0,
            nexthops: vec![uni("10.0.0.2", 3), uni("10.0.1.2", 4)],
            gid: 0,
        };
        let e = entry(RibType::Static, Nexthop::Multi(multi));
        let msg = encode_route(RouteOp::Add, &"10.100.2.0/24".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "basic.fpm");
    }

    #[test]
    fn blackhole_v4_matches_frr() {
        let e = entry(RibType::Static, Nexthop::Blackhole(0));
        let msg = encode_route(RouteOp::Add, &"10.100.4.0/24".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "basic.fpm");
    }

    #[test]
    fn delete_v4_matches_frr() {
        let e = entry(RibType::Static, Nexthop::Uni(uni("10.0.0.2", 3)));
        let msg = encode_route(RouteOp::Del, &"10.100.0.0/24".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "basic.fpm");
    }

    #[test]
    fn single_nexthop_v6_matches_frr() {
        let e = entry(RibType::Static, Nexthop::Uni(uni("2001:db8::2", 3)));
        let msg = encode_route(RouteOp::Add, &"2001:db8:100::/64".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "basic.fpm");
    }

    #[test]
    fn ecmp_v6_matches_frr() {
        let multi = NexthopMulti {
            metric: 0,
            nexthops: vec![uni("2001:db8::2", 3), uni("2001:db8:1::2", 4)],
            gid: 0,
        };
        let e = entry(RibType::Static, Nexthop::Multi(multi));
        let msg = encode_route(RouteOp::Add, &"2001:db8:101::/64".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "basic.fpm");
    }

    /// A connected route: protocol must collapse to RTPROT_KERNEL (2).
    /// `10.0.0.0/24` on dum0 is in the trace as part of interface setup.
    #[test]
    fn connected_route_uses_kernel_protocol() {
        let mut u = NexthopUni::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, vec![]);
        u.ifindex_origin = Some(3);
        let e = entry(RibType::Connected, Nexthop::Uni(u));
        let msg = encode_route(RouteOp::Add, &"10.0.0.0/24".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "basic.fpm");
    }

    /// A VRF route. The scenario behind `vrf.fpm` puts Vrf1 on kernel
    /// table 100 while its device lands on ifindex 6, so a capture that
    /// matches proves the encoder sends the *ifindex* — the two numbers
    /// cannot be confused for one another here.
    #[test]
    fn vrf_route_carries_the_device_ifindex() {
        let e = entry(RibType::Static, Nexthop::Uni(uni("10.0.1.2", 4)));
        let msg = encode_route(RouteOp::Add, &"10.200.0.0/24".parse().unwrap(), &e, 6).unwrap();
        assert_matches_frr(&msg, "vrf.fpm");
    }

    #[test]
    fn vrf_route_v6_carries_the_device_ifindex() {
        let e = entry(RibType::Static, Nexthop::Uni(uni("2001:db8:1::2", 4)));
        let msg = encode_route(RouteOp::Add, &"2001:db8:200::/64".parse().unwrap(), &e, 6).unwrap();
        assert_matches_frr(&msg, "vrf.fpm");
    }

    /// Deleting a VRF route keeps the same table encoding.
    #[test]
    fn vrf_delete_matches_frr() {
        let e = entry(RibType::Static, Nexthop::Uni(uni("10.0.1.2", 4)));
        let msg = encode_route(RouteOp::Del, &"10.200.1.0/24".parse().unwrap(), &e, 6).unwrap();
        assert_matches_frr(&msg, "vrf.fpm");
    }

    /// A default-VRF route recorded in the same trace still uses table 0,
    /// so the VRF encoding did not leak into the global one.
    #[test]
    fn default_vrf_route_in_the_vrf_trace_uses_table_zero() {
        let e = entry(RibType::Static, Nexthop::Uni(uni("10.0.0.2", 3)));
        let msg = encode_route(RouteOp::Add, &"10.100.0.0/24".parse().unwrap(), &e, 0).unwrap();
        assert_matches_frr(&msg, "vrf.fpm");
    }

    /// An ifindex of 256 or more does not fit the one-byte `rtm_table`,
    /// so it moves to RTA_TABLE — mirroring dplane_fpm_sonic.c:1499-1505.
    /// No capture exercises this (a test container will not reach ifindex
    /// 256), so it is asserted structurally instead.
    #[test]
    fn large_vrf_ifindex_moves_to_rta_table() {
        let e = entry(RibType::Static, Nexthop::Uni(uni("10.0.1.2", 4)));
        let msg = encode_route(RouteOp::Add, &"10.200.0.0/24".parse().unwrap(), &e, 300).unwrap();
        // rtm_table is the 5th byte of the rtmsg, which starts after the
        // 4-byte FPM header and the 16-byte netlink header.
        let rtm_table = msg[4 + 16 + 4];
        assert_eq!(
            rtm_table, 0,
            "rtm_table must be RT_TABLE_UNSPEC when the ifindex overflows it"
        );
        // RTA_TABLE (15) carrying 300 must be present.
        let needle = [8u8, 0, 15, 0, 44, 1, 0, 0];
        assert!(
            msg.windows(needle.len()).any(|w| w == needle),
            "expected an RTA_TABLE attribute holding 300"
        );
    }

    /// Guards the mapping itself, independent of any capture.
    #[test]
    fn protocol_uses_frr_numbering() {
        assert_eq!(
            protocol(RibType::Static),
            196,
            "static must be RTPROT_ZSTATIC"
        );
        assert_eq!(
            protocol(RibType::Connected),
            2,
            "connected must be RTPROT_KERNEL"
        );
        assert_eq!(protocol(RibType::Bgp), 186);
        assert_eq!(protocol(RibType::Ospf), 188);
        assert_eq!(protocol(RibType::Isis), 187);
    }

    /// An add with no forwarding leg would install an unusable route.
    #[test]
    fn add_without_legs_is_refused() {
        let e = entry(RibType::Static, Nexthop::Link(0));
        assert!(encode_route(RouteOp::Add, &"10.1.1.0/24".parse().unwrap(), &e, 0).is_none());
    }

    /// A protected route contributes only its primary — a standby leg
    /// sent as a second ECMP path would blackhole traffic across it.
    #[test]
    fn protect_contributes_only_the_primary() {
        use crate::rib::nexthop::NexthopProtect;
        let pro = NexthopProtect {
            primary: NexthopMember::Uni(uni("10.0.0.2", 3)),
            backup: NexthopMember::Uni(uni("10.0.1.2", 4)),
            gid: 0,
        };
        let e = entry(RibType::Static, Nexthop::Protect(pro));
        let msg = encode_route(RouteOp::Add, &"10.100.0.0/24".parse().unwrap(), &e, 0).unwrap();
        // Identical to the plain single-nexthop route through the same leg.
        assert_matches_frr(&msg, "basic.fpm");
    }
}
