use std::fmt;
use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};
use fixedbuf::FixedBuf;
use nom::number::complete::be_u16;
use nom_derive::*;

use crate::{
    Afi, AttrFlags, AttrType, BGP_HEADER_LEN, BGP_PACKET_LEN, BgpAttr, BgpHeader, BgpParseError,
    BgpType, Ipv4Nlri, MpReachAttr, MpUnreachAttr, ParseOption, Safi, nlri_psize,
    parse_bgp_nlri_ipv4, parse_bgp_update_attribute,
};

/// IPv6 next-hop that an RFC 8950 IPv4-over-IPv6 advertisement carries
/// in `MP_REACH_NLRI`. Pure-unnumbered links have no global half and
/// emit the 16-octet `LinkLocal` form; speakers with both a global
/// v6 and a link-local on the egress interface emit the 32-octet
/// `Dual` form, which receivers prefer for next-hop resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4MpReachNextHop {
    /// 16-octet form — link-local only.
    LinkLocal(Ipv6Addr),
    /// 32-octet form — global address followed by link-local, per
    /// RFC 8950 §3.
    Dual {
        global: Ipv6Addr,
        link_local: Ipv6Addr,
    },
}

#[derive(NomBE)]
pub struct UpdatePacket {
    pub header: BgpHeader,
    #[nom(Ignore)]
    pub bgp_attr: Option<BgpAttr>,
    #[nom(Ignore)]
    pub ipv4_update: Vec<Ipv4Nlri>,
    #[nom(Ignore)]
    pub ipv4_withdraw: Vec<Ipv4Nlri>,
    #[nom(Ignore)]
    pub mp_update: Option<MpReachAttr>,
    #[nom(Ignore)]
    pub mp_withdraw: Option<MpUnreachAttr>,
    #[nom(Ignore)]
    max_packet_size: usize,
}

impl UpdatePacket {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_packet_size(max_packet_size: usize) -> Self {
        Self {
            max_packet_size,
            ..Self::default()
        }
    }
}

impl Default for UpdatePacket {
    fn default() -> Self {
        Self {
            header: BgpHeader::new(BgpType::Update, BGP_HEADER_LEN),
            bgp_attr: None,
            ipv4_update: Vec::new(),
            ipv4_withdraw: Vec::new(),
            mp_update: None,
            mp_withdraw: None,
            max_packet_size: BGP_PACKET_LEN,
        }
    }
}

impl UpdatePacket {
    pub fn pop_ipv4(&mut self) -> Option<BytesMut> {
        if self.ipv4_update.is_empty() {
            return None;
        }
        let mut buf = BytesMut::with_capacity(self.max_packet_size);
        let header: BytesMut = self.header.clone().into();
        buf.put(&header[..]);

        // IPv4 unicast withdraw right now we only support IPv4 updates only.
        buf.put_u16(0u16); // Empty IPv4 withdraw.

        // Attributes length.
        let attr_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder
        let attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        // Attributes emit.
        if let Some(bgp_attr) = &self.bgp_attr {
            bgp_attr.attr_emit(&mut buf);
        }

        // No MP reach/unreach emit at this moment.

        // Fill in attr length.
        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        buf[attr_pos].copy_from_slice(&attr_len.to_be_bytes());

        // Consume self.ipv4_update with checking buffer size.
        while let Some(ip) = self.ipv4_update.pop() {
            // Calculate NLRI len. When it exceed remaing size, push back the ip
            // then return current buf.
            let mut nlri_len: usize = 0;
            if ip.id != 0 {
                nlri_len = 4;
            }
            nlri_len += 1;
            nlri_len += nlri_psize(ip.prefix.prefix_len());

            if buf.len() + nlri_len > self.max_packet_size {
                self.ipv4_update.push(ip);

                const LENGTH_POS: std::ops::Range<usize> = 16..18;
                let length: u16 = buf.len() as u16;
                buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

                return Some(buf);
            }

            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        Some(buf)
    }

    /// Emit a BGP UPDATE carrying `MP_REACH_NLRI` for AFI=1 / SAFI=1
    /// (IPv4 unicast) with an IPv6 next-hop, per RFC 8950. Mirrors the
    /// pagination shape of [`Self::pop_ipv4`]: pop NLRIs into a single
    /// packet until adding another would exceed `max_packet_size`,
    /// push the spilled NLRI back, return the encoded packet.
    ///
    /// `next_hop` controls whether the 16-octet (`LinkLocal`-only) or
    /// 32-octet (global || link-local) form is emitted; both are
    /// RFC 8950 §3 compliant and the receiver accepts either.
    ///
    /// The MP_REACH attribute is emitted with the extended-length
    /// (2-octet length) form unconditionally — once a single /24 is
    /// added alongside the 21-octet (or 37-octet for dual) MP_REACH
    /// preamble the value already crowds the 255-byte budget;
    /// pagination almost always produces values that need 2-octet
    /// lengths.
    ///
    /// `bgp_attr`, if set, is emitted verbatim (including any v4
    /// NEXT_HOP attribute). RFC 8950 §4 says the receiver MUST ignore
    /// NEXT_HOP when MP_REACH carries an IPv6 next-hop, so passing
    /// the attribute through is harmless and matches what FRR /
    /// IOS-XR emit.
    pub fn pop_ipv4_mp_reach(&mut self, next_hop: Ipv4MpReachNextHop) -> Option<BytesMut> {
        if self.ipv4_update.is_empty() {
            return None;
        }
        let mut buf = BytesMut::with_capacity(self.max_packet_size);
        let header: BytesMut = self.header.clone().into();
        buf.put(&header[..]);

        // Empty legacy IPv4 withdraw field — required by RFC 4271 §4.3
        // even though every reachable NLRI lives inside MP_REACH here.
        buf.put_u16(0u16);

        // Total Path Attributes Length placeholder.
        let attr_len_pos = buf.len();
        buf.put_u16(0u16);
        let attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        if let Some(bgp_attr) = &self.bgp_attr {
            bgp_attr.attr_emit(&mut buf);
        }

        // MP_REACH attribute header — Optional + Extended Length.
        let flags = AttrFlags::new().with_optional(true).with_extended(true);
        buf.put_u8(flags.into());
        buf.put_u8(AttrType::MpReachNlri.into());
        let mp_len_pos = buf.len();
        buf.put_u16(0u16);

        // MP_REACH value preamble: AFI + SAFI + nhop_len + nhop + SNPA.
        let mp_value_start = buf.len();
        buf.put_u16(u16::from(Afi::Ip));
        buf.put_u8(u8::from(Safi::Unicast));
        match next_hop {
            Ipv4MpReachNextHop::LinkLocal(ll) => {
                buf.put_u8(16);
                buf.put(&ll.octets()[..]);
            }
            Ipv4MpReachNextHop::Dual { global, link_local } => {
                // RFC 8950 §3: 32-octet form carries global || LL in
                // that order. Receivers prefer the global for next-hop
                // resolution and use the LL when both peers agree the
                // route is on-link.
                buf.put_u8(32);
                buf.put(&global.octets()[..]);
                buf.put(&link_local.octets()[..]);
            }
        }
        buf.put_u8(0);

        // Per-NLRI emit, breaking out when the next prefix wouldn't
        // fit. Symmetric with `pop_ipv4` — caller paginates by
        // looping until `None`.
        let mut emitted_any = false;
        while let Some(ip) = self.ipv4_update.pop() {
            let mut nlri_len: usize = if ip.id != 0 { 4 } else { 0 };
            nlri_len += 1 + nlri_psize(ip.prefix.prefix_len());

            if buf.len() + nlri_len > self.max_packet_size {
                self.ipv4_update.push(ip);
                break;
            }

            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
            emitted_any = true;
        }

        if !emitted_any {
            // First NLRI didn't fit — caller has a pathologically
            // small `max_packet_size` (smaller than a single NLRI plus
            // the MP_REACH preamble). Drop the packet rather than
            // emit an empty MP_REACH.
            return None;
        }

        // Patch MP_REACH attribute length.
        let mp_value_len = (buf.len() - mp_value_start) as u16;
        buf[mp_len_pos..mp_len_pos + 2].copy_from_slice(&mp_value_len.to_be_bytes());

        // Patch Path Attributes total length.
        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        buf[attr_pos].copy_from_slice(&attr_len.to_be_bytes());

        // Patch BGP header length.
        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        Some(buf)
    }

    /// Emit the BGP UPDATE that carries an `MP_REACH_NLRI` for EVPN
    /// (AFI=25 / SAFI=70). Mirrors `pop_vpnv4`'s framing — empty IPv4
    /// withdraw, attributes, MP_REACH — but uses the un-paginated
    /// `evpn_attr_emit` helper from `mp_reach`. All NLRIs in the
    /// `MpReachAttr::Evpn::updates` vector are emitted in a single
    /// packet; pagination across multiple UPDATEs (e.g. when a
    /// large RD's MAC table doesn't fit) is a follow-up.
    ///
    /// Returns `None` when the packet has no EVPN payload to emit
    /// (caller can stop iterating). Distinct from `pop_vpnv4` in
    /// that it's idempotently single-shot — callers that want to
    /// emit multiple UPDATEs should batch into separate
    /// `UpdatePacket` instances.
    pub fn pop_evpn(&mut self) -> Option<BytesMut> {
        let (snpa, nhop, updates) = match &self.mp_update {
            Some(MpReachAttr::Evpn {
                snpa,
                nhop,
                updates,
            }) if !updates.is_empty() => (*snpa, *nhop, updates.clone()),
            _ => return None,
        };

        let mut buf = FixedBuf::new(self.max_packet_size);
        let header: BytesMut = self.header.clone().into();
        let _ = buf.put(&header[..]);

        // No IPv4 withdraw on EVPN UPDATEs — same as the VPNv4 path.
        let _ = buf.put_u16(0u16);

        let attr_len_pos = buf.len();
        let _ = buf.put_u16(0u16); // placeholder

        if let Some(bgp_attr) = &self.bgp_attr {
            bgp_attr.attr_emit(buf.get_mut());
        }

        super::attrs::mp_reach::evpn_attr_emit(snpa, &nhop, &updates, buf.get_mut());

        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        let _ = buf.put_u16_at(attr_len_pos, attr_len);

        let length: u16 = buf.len() as u16;
        let _ = buf.put_u16_at(16, length);

        // Drain so a second call returns None — matches VPNv4's
        // "consume once" semantics from the flush_vpnv4 callers.
        if let Some(MpReachAttr::Evpn { updates, .. }) = self.mp_update.as_mut() {
            updates.clear();
        }

        Some(buf.get())
    }

    pub fn pop_vpnv6(&mut self) -> Option<BytesMut> {
        match &self.mp_update {
            Some(MpReachAttr::Vpnv6(vpnv6)) if !vpnv6.updates.is_empty() => {}
            _ => return None,
        }
        let mp_update = self.mp_update.as_mut().unwrap();

        let mut buf = FixedBuf::new(self.max_packet_size);
        let header: BytesMut = self.header.clone().into();
        let _ = buf.put(&header[..]);

        // No legacy IPv4 withdraw on a VPNv6 UPDATE.
        let _ = buf.put_u16(0u16);

        // Attributes length placeholder.
        let attr_len_pos = buf.len();
        let _ = buf.put_u16(0u16);

        if let Some(bgp_attr) = &self.bgp_attr {
            bgp_attr.attr_emit(buf.get_mut());
        }

        // MP reach (dispatches to Vpnv6Reach::attr_emit_mut, which
        // paginates the NLRI list across calls).
        mp_update.attr_emit_mut(buf.get_mut(), self.max_packet_size);

        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        let _ = buf.put_u16_at(attr_len_pos, attr_len);

        let length: u16 = buf.len() as u16;
        let _ = buf.put_u16_at(16, length);

        Some(buf.get())
    }

    pub fn pop_vpnv4(&mut self) -> Option<BytesMut> {
        match &self.mp_update {
            Some(MpReachAttr::Vpnv4(vpnv4)) if !vpnv4.updates.is_empty() => {}
            _ => return None,
        }
        let mp_update = self.mp_update.as_mut().unwrap();

        let mut buf = FixedBuf::new(self.max_packet_size);
        let header: BytesMut = self.header.clone().into();
        let _ = buf.put(&header[..]);

        // IPv4 unicast withdraw right now we only support VPNv4 updates only.
        let _ = buf.put_u16(0u16); // Empty IPv4 withdraw.

        // Attributes length.
        let attr_len_pos = buf.len();
        let _ = buf.put_u16(0u16); // Placeholder

        // Attributes emit.
        if let Some(bgp_attr) = &self.bgp_attr {
            bgp_attr.attr_emit(buf.get_mut());
        }

        // MP reach.
        mp_update.attr_emit_mut(buf.get_mut(), self.max_packet_size);

        // Fill in attr length.
        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        let _ = buf.put_u16_at(attr_len_pos, attr_len);

        // Fill in total length.
        let length: u16 = buf.len() as u16;
        let _ = buf.put_u16_at(16, length);

        Some(buf.get())
    }
}

impl From<UpdatePacket> for BytesMut {
    fn from(update: UpdatePacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = update.header.into();
        buf.put(&header[..]);

        // IPv4 unicast withdraw.
        let withdraw_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder.
        let withdraw_pos: std::ops::Range<usize> = withdraw_len_pos..withdraw_len_pos + 2;
        for ip in update.ipv4_withdraw.iter() {
            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }
        let withdraw_len: u16 = (buf.len() - withdraw_len_pos - 2) as u16;
        buf[withdraw_pos].copy_from_slice(&withdraw_len.to_be_bytes());

        // Attributes length.
        let attr_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder
        let attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        // Attributes emit.
        if let Some(bgp_attr) = update.bgp_attr {
            bgp_attr.attr_emit(&mut buf);
        }

        // MP reach.
        if let Some(mp_update) = update.mp_update {
            mp_update.attr_emit(&mut buf);
        }

        // MP unreach.
        if let Some(mp_withdraw) = update.mp_withdraw {
            mp_withdraw.attr_emit(&mut buf);
        }

        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        buf[attr_pos].copy_from_slice(&attr_len.to_be_bytes());

        // IPv4 unicast update.
        for ip in update.ipv4_update.iter() {
            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}

impl fmt::Debug for UpdatePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self)
    }
}

impl fmt::Display for UpdatePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Update Message:")?;
        if let Some(bgp_attr) = &self.bgp_attr {
            write!(f, "{}", bgp_attr)?;
        }
        if !self.ipv4_update.is_empty() {
            writeln!(f, " IPv4 Updates:")?;
            for update in self.ipv4_update.iter() {
                writeln!(f, "  {}", update.prefix)?;
            }
        }
        if !self.ipv4_withdraw.is_empty() {
            writeln!(f, " IPv4 Withdraw:")?;
            for withdraw in self.ipv4_withdraw.iter() {
                writeln!(f, "  {}", withdraw.prefix)?;
            }
        }
        if let Some(mp_update) = &self.mp_update {
            write!(f, "{}", mp_update)?;
        }
        if let Some(mp_withdraw) = &self.mp_withdraw {
            write!(f, "{}", mp_withdraw)?;
        }
        if self.bgp_attr.is_none()
            && self.mp_update.is_none()
            && self.mp_withdraw.is_none()
            && self.ipv4_update.is_empty()
            && self.ipv4_withdraw.is_empty()
        {
            writeln!(f, " EoR: IPv4/Unicast")?;
        }
        Ok(())
    }
}

impl UpdatePacket {
    pub fn parse_packet(
        input: &[u8],
        as4: bool,
        opt: Option<ParseOption>,
    ) -> Result<(&[u8], UpdatePacket), BgpParseError> {
        let add_path = if let Some(opt) = opt.as_ref() {
            opt.is_add_path_recv(Afi::Ip, Safi::Unicast)
        } else {
            false
        };
        let (input, mut packet) = UpdatePacket::parse_be(input)?;
        let (input, withdraw_len) = be_u16(input)?;
        let (input, mut withdrawal) = parse_bgp_nlri_ipv4(input, withdraw_len, add_path)?;
        packet.ipv4_withdraw.append(&mut withdrawal);
        let (input, attr_len) = be_u16(input)?;
        let (input, bgp_attr, mp_update, mp_withdraw) = if attr_len > 0 {
            parse_bgp_update_attribute(input, attr_len, as4, opt)?
        } else {
            (input, None, None, None)
        };
        packet.bgp_attr = bgp_attr;
        packet.mp_update = mp_update;
        packet.mp_withdraw = mp_withdraw;
        let nlri_len = packet
            .header
            .length
            .saturating_sub(BGP_HEADER_LEN)
            .saturating_sub(2)
            .saturating_sub(withdraw_len)
            .saturating_sub(2)
            .saturating_sub(attr_len);
        let (input, mut updates) = parse_bgp_nlri_ipv4(input, nlri_len, add_path)?;
        packet.ipv4_update.append(&mut updates);
        Ok((input, packet))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ipnet::Ipv4Net;

    use super::*;

    fn nlri(prefix: &str) -> Ipv4Nlri {
        Ipv4Nlri {
            id: 0,
            prefix: prefix.parse::<Ipv4Net>().unwrap(),
        }
    }

    /// Encode via `pop_ipv4_mp_reach` and parse the bytes back through
    /// `UpdatePacket::parse_packet`, then assert the recovered
    /// MP_REACH carries the next-hop and prefixes we put in.
    fn encode_and_parse(
        next_hop: Ipv4MpReachNextHop,
        nlris: &[Ipv4Nlri],
        max: usize,
    ) -> (UpdatePacket, Vec<BytesMut>) {
        let mut update = UpdatePacket::with_max_packet_size(max);
        update.bgp_attr = Some(BgpAttr::new());
        update.ipv4_update = nlris.to_vec();

        let mut packets = Vec::new();
        while let Some(bytes) = update.pop_ipv4_mp_reach(next_hop) {
            packets.push(bytes);
        }
        assert!(!packets.is_empty(), "expected at least one packet");

        let (_, parsed) =
            UpdatePacket::parse_packet(&packets[0], true, None).expect("must round-trip");
        (parsed, packets)
    }

    #[test]
    fn returns_none_with_no_nlris() {
        let mut update = UpdatePacket::new();
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(
            update
                .pop_ipv4_mp_reach(Ipv4MpReachNextHop::LinkLocal(ll))
                .is_none()
        );
    }

    #[test]
    fn single_prefix_round_trips_through_decoder() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let (parsed, _) = encode_and_parse(
            Ipv4MpReachNextHop::LinkLocal(ll),
            &[nlri("10.0.0.0/24")],
            BGP_PACKET_LEN,
        );
        match parsed.mp_update {
            Some(MpReachAttr::Ipv4 { nhop, updates, .. }) => {
                assert_eq!(nhop, IpAddr::V6(ll));
                assert_eq!(updates.len(), 1);
                assert_eq!(updates[0].prefix.to_string(), "10.0.0.0/24");
            }
            other => panic!("expected MpReachAttr::Ipv4, got {other:?}"),
        }
    }

    /// 32-octet form carries `global || link-local`. The decoder
    /// surfaces the global half, matching the RFC 8950 §3 receiver
    /// recommendation and the convention FRR / IOS-XR follow.
    #[test]
    fn dual_nexthop_round_trips_global_half_to_decoder() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ll: Ipv6Addr = "fe80::abcd".parse().unwrap();
        let (parsed, _) = encode_and_parse(
            Ipv4MpReachNextHop::Dual {
                global,
                link_local: ll,
            },
            &[nlri("10.0.0.0/24")],
            BGP_PACKET_LEN,
        );
        match parsed.mp_update {
            Some(MpReachAttr::Ipv4 { nhop, updates, .. }) => {
                assert_eq!(nhop, IpAddr::V6(global));
                assert_eq!(updates.len(), 1);
            }
            other => panic!("expected MpReachAttr::Ipv4, got {other:?}"),
        }
    }

    #[test]
    fn many_prefixes_round_trip_into_one_packet() {
        let ll: Ipv6Addr = "fe80::abcd".parse().unwrap();
        let prefixes: Vec<Ipv4Nlri> = (0..50).map(|i| nlri(&format!("10.{i}.0.0/24"))).collect();
        let (parsed, packets) =
            encode_and_parse(Ipv4MpReachNextHop::LinkLocal(ll), &prefixes, BGP_PACKET_LEN);
        assert_eq!(packets.len(), 1, "50 /24 should comfortably fit one MTU");
        match parsed.mp_update {
            Some(MpReachAttr::Ipv4 { nhop, updates, .. }) => {
                assert_eq!(nhop, IpAddr::V6(ll));
                assert_eq!(updates.len(), 50);
            }
            other => panic!("expected MpReachAttr::Ipv4, got {other:?}"),
        }
    }

    /// Pagination is forced by squeezing `max_packet_size` so far down
    /// that only one or two NLRIs fit per UPDATE. `parse_packet` on
    /// each emitted buffer must independently recover a valid
    /// MP_REACH; the union of decoded NLRIs must equal what we
    /// pushed in.
    #[test]
    fn pagination_splits_across_packets() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        // Build 20 distinct /24s; cap at 80 bytes so only one or two
        // NLRIs (~4 bytes each) fit alongside ~50 bytes of header +
        // attrs + MP_REACH preamble.
        let prefixes: Vec<Ipv4Nlri> = (0..20).map(|i| nlri(&format!("10.{i}.0.0/24"))).collect();
        let mut update = UpdatePacket::with_max_packet_size(80);
        update.bgp_attr = Some(BgpAttr::new());
        update.ipv4_update = prefixes.clone();

        let mut packets = Vec::new();
        while let Some(bytes) = update.pop_ipv4_mp_reach(Ipv4MpReachNextHop::LinkLocal(ll)) {
            packets.push(bytes);
        }
        assert!(
            packets.len() > 1,
            "expected pagination, got {} packet(s)",
            packets.len()
        );

        let mut recovered: Vec<String> = Vec::new();
        for buf in &packets {
            let (_, parsed) = UpdatePacket::parse_packet(buf, true, None).expect("decode");
            match parsed.mp_update {
                Some(MpReachAttr::Ipv4 { updates, .. }) => {
                    for u in updates {
                        recovered.push(u.prefix.to_string());
                    }
                }
                other => panic!("unexpected mp_update: {other:?}"),
            }
        }
        recovered.sort();
        let mut expected: Vec<String> = prefixes.iter().map(|n| n.prefix.to_string()).collect();
        expected.sort();
        assert_eq!(recovered, expected);
    }

    /// A `max_packet_size` smaller than the fixed packet preamble (so
    /// the first NLRI can never fit) returns `None` rather than an
    /// empty MP_REACH packet.
    #[test]
    fn returns_none_when_first_nlri_does_not_fit() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut update = UpdatePacket::with_max_packet_size(40);
        update.bgp_attr = Some(BgpAttr::new());
        update.ipv4_update = vec![nlri("10.0.0.0/24")];
        assert!(
            update
                .pop_ipv4_mp_reach(Ipv4MpReachNextHop::LinkLocal(ll))
                .is_none()
        );
    }
}
