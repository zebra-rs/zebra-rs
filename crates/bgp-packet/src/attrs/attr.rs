use std::fmt;

use bytes::BytesMut;
use nom::bytes::complete::take;
use nom::number::complete::be_u8;
use nom_derive::*;

use crate::{BgpAttr, BgpNexthop, BgpParseError, ParseBe, ParseOption};

use super::*;

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum AttrType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    Med = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Community = 8,
    OriginatorId = 9,
    ClusterList = 10,
    MpReachNlri = 14,
    MpUnreachNlri = 15,
    ExtendedCom = 16,
    PmsiTunnel = 22,
    // 25 — RFC 5701 IPv6 Address Specific Extended Community — is deliberately
    // absent, and must only be re-added together with an
    // `Attr::ExtendedIpv6Com` variant.
    //
    // Every code named here must have a matching `Attr` variant. Naming one
    // without it is strictly worse than not recognising the code at all: the
    // type stops matching `AttrType::Unknown`, so it skips the RFC 4271 §9
    // handling below, reaches `parse_attr_value`, fails the derived Switch with
    // no arm to select, and — not being a treat-as-withdraw attribute — resets
    // the session. Left unnamed it decodes as `Unknown(25)` and takes the §9
    // optional-transitive path: retained with the Partial bit and propagated.
    Aigp = 26,
    LargeCom = 32,
    PrefixSid = 40,
    TunnelEncap = 23,
    BgpLsAttr = 29,
    Unknown(u8),
}

impl From<u8> for AttrType {
    fn from(attr_type: u8) -> Self {
        use AttrType::*;
        match attr_type {
            1 => Origin,
            2 => AsPath,
            3 => NextHop,
            4 => Med,
            5 => LocalPref,
            6 => AtomicAggregate,
            7 => Aggregator,
            8 => Community,
            9 => OriginatorId,
            10 => ClusterList,
            14 => MpReachNlri,
            15 => MpUnreachNlri,
            16 => ExtendedCom,
            22 => PmsiTunnel,
            26 => Aigp,
            32 => LargeCom,
            40 => PrefixSid,
            23 => TunnelEncap,
            29 => BgpLsAttr,
            v => Unknown(v),
        }
    }
}

impl From<AttrType> for u8 {
    fn from(attr_type: AttrType) -> Self {
        use AttrType::*;
        match attr_type {
            Origin => 1,
            AsPath => 2,
            NextHop => 3,
            Med => 4,
            LocalPref => 5,
            AtomicAggregate => 6,
            Aggregator => 7,
            Community => 8,
            OriginatorId => 9,
            ClusterList => 10,
            MpReachNlri => 14,
            MpUnreachNlri => 15,
            ExtendedCom => 16,
            PmsiTunnel => 22,
            Aigp => 26,
            LargeCom => 32,
            PrefixSid => 40,
            TunnelEncap => 23,
            BgpLsAttr => 29,
            Unknown(v) => v,
        }
    }
}

struct AttrSelector(AttrType, Option<bool>);

#[derive(NomBE, Clone)]
#[nom(Selector = "AttrSelector")]
pub enum Attr {
    #[nom(Selector = "AttrSelector(AttrType::Origin, None)")]
    Origin(Origin),
    #[nom(Selector = "AttrSelector(AttrType::AsPath, Some(false))")]
    As2Path(As2Path),
    #[nom(Selector = "AttrSelector(AttrType::AsPath, Some(true))")]
    As4Path(As4Path),
    #[nom(Selector = "AttrSelector(AttrType::NextHop, None)")]
    NextHop(NexthopAttr),
    #[nom(Selector = "AttrSelector(AttrType::Med, None)")]
    Med(Med),
    #[nom(Selector = "AttrSelector(AttrType::LocalPref, None)")]
    LocalPref(LocalPref),
    #[nom(Selector = "AttrSelector(AttrType::AtomicAggregate, None)")]
    AtomicAggregate(AtomicAggregate),
    #[nom(Selector = "AttrSelector(AttrType::Aggregator, Some(false))")]
    Aggregator2(Aggregator2),
    #[nom(Selector = "AttrSelector(AttrType::Aggregator, Some(true))")]
    Aggregator(Aggregator),
    #[nom(Selector = "AttrSelector(AttrType::Community, None)")]
    Community(Community),
    #[nom(Selector = "AttrSelector(AttrType::OriginatorId, None)")]
    OriginatorId(OriginatorId),
    #[nom(Selector = "AttrSelector(AttrType::ClusterList, None)")]
    ClusterList(ClusterList),
    #[nom(Selector = "AttrSelector(AttrType::MpReachNlri, None)")]
    MpReachNlri(MpReachAttr),
    #[nom(Selector = "AttrSelector(AttrType::MpUnreachNlri, None)")]
    MpUnreachNlri(MpUnreachAttr),
    #[nom(Selector = "AttrSelector(AttrType::ExtendedCom, None)")]
    ExtendedCom(ExtCommunity),
    #[nom(Selector = "AttrSelector(AttrType::PmsiTunnel, None)")]
    PmsiTunnel(PmsiTunnel),
    #[nom(Selector = "AttrSelector(AttrType::Aigp, None)")]
    Aigp(Aigp),
    #[nom(Selector = "AttrSelector(AttrType::LargeCom, None)")]
    LargeCom(LargeCommunity),
    #[nom(Selector = "AttrSelector(AttrType::PrefixSid, None)")]
    PrefixSid(PrefixSid),
    #[nom(Selector = "AttrSelector(AttrType::TunnelEncap, None)")]
    TunnelEncap(TunnelEncap),
    #[nom(Selector = "AttrSelector(AttrType::BgpLsAttr, None)")]
    BgpLs(BgpLsAttr),
}

impl Attr {
    pub fn emit(&self, buf: &mut BytesMut) {
        match self {
            Attr::Origin(v) => v.attr_emit(buf),
            Attr::As4Path(v) => v.attr_emit(buf),
            Attr::NextHop(v) => v.attr_emit(buf),
            Attr::Med(v) => v.attr_emit(buf),
            Attr::LocalPref(v) => v.attr_emit(buf),
            Attr::AtomicAggregate(v) => v.attr_emit(buf),
            Attr::Aggregator(v) => v.attr_emit(buf),
            Attr::Aggregator2(v) => v.attr_emit(buf),
            Attr::OriginatorId(v) => v.attr_emit(buf),
            Attr::ClusterList(v) => v.attr_emit(buf),
            // Attr::MpReachNlri(v) => v.attr_emit(buf),
            Attr::Community(v) => v.attr_emit(buf),
            Attr::ExtendedCom(v) => v.attr_emit(buf),
            Attr::PmsiTunnel(v) => v.attr_emit(buf),
            Attr::LargeCom(v) => v.attr_emit(buf),
            Attr::Aigp(v) => v.attr_emit(buf),
            Attr::PrefixSid(v) => v.attr_emit(buf),
            Attr::TunnelEncap(v) => v.attr_emit(buf),
            Attr::BgpLs(v) => v.attr_emit(buf),
            _ => {
                //
            }
        }
    }
}

impl fmt::Display for Attr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attr::Origin(v) => write!(f, "{}", v),
            Attr::As4Path(v) => write!(f, "{}", v),
            Attr::NextHop(v) => write!(f, "{}", v),
            Attr::Med(v) => write!(f, "{}", v),
            Attr::LocalPref(v) => write!(f, "{}", v),
            Attr::AtomicAggregate(v) => write!(f, "{}", v),
            Attr::Aggregator(v) => write!(f, "{}", v),
            Attr::Aggregator2(v) => write!(f, "{}", v),
            Attr::OriginatorId(v) => write!(f, "{}", v),
            Attr::ClusterList(v) => write!(f, "{}", v),
            Attr::MpReachNlri(v) => write!(f, "{}", v),
            Attr::MpUnreachNlri(v) => write!(f, "{}", v),
            Attr::Community(v) => write!(f, "{}", v),
            Attr::ExtendedCom(v) => write!(f, "{}", v),
            Attr::PmsiTunnel(v) => write!(f, "{}", v),
            Attr::LargeCom(v) => write!(f, "{}", v),
            Attr::Aigp(v) => write!(f, "{}", v),
            Attr::PrefixSid(v) => write!(f, "{}", v),
            Attr::TunnelEncap(v) => write!(f, "{}", v),
            Attr::BgpLs(v) => write!(f, "{}", v),
            _ => write!(f, "Unknown"),
        }
    }
}

impl fmt::Debug for Attr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attr::Origin(v) => write!(f, "{:?}", v),
            Attr::As4Path(v) => write!(f, "{:?}", v),
            Attr::NextHop(v) => write!(f, "{:?}", v),
            Attr::Med(v) => write!(f, "{:?}", v),
            Attr::LocalPref(v) => write!(f, "{:?}", v),
            Attr::AtomicAggregate(v) => write!(f, "{:?}", v),
            Attr::Aggregator(v) => write!(f, "{:?}", v),
            Attr::Aggregator2(v) => write!(f, "{:?}", v),
            Attr::OriginatorId(v) => write!(f, "{:?}", v),
            Attr::ClusterList(v) => write!(f, "{:?}", v),
            Attr::MpReachNlri(v) => write!(f, "{:?}", v),
            Attr::MpUnreachNlri(v) => write!(f, "{:?}", v),
            Attr::Community(v) => write!(f, "{:?}", v),
            Attr::ExtendedCom(v) => write!(f, "{:?}", v),
            Attr::PmsiTunnel(v) => write!(f, "{:?}", v),
            Attr::LargeCom(v) => write!(f, "{:?}", v),
            Attr::Aigp(v) => write!(f, "{:?}", v),
            Attr::PrefixSid(v) => write!(f, "{:?}", v),
            Attr::TunnelEncap(v) => write!(f, "{:?}", v),
            Attr::BgpLs(v) => write!(f, "{:?}", v),
            _ => write!(f, "Unknown"),
        }
    }
}

impl Attr {
    /// Parse one attribute's framing — flags, type code, and length — and
    /// split its Value off the front of `input`, returning the Value
    /// slice plus the remaining input positioned at the next attribute.
    ///
    /// A framing error (truncated header, or a length that overruns the
    /// attribute block) is unrecoverable and propagates: per RFC 7606 §4
    /// an attribute-length error prevents parsing the rest of the
    /// attributes and forces a session reset. Errors parsing the Value
    /// itself are handled separately by `parse_attr_value`, which lets
    /// the caller recover (treat-as-withdraw) where the RFC allows it.
    fn parse_attr_header(
        input: &[u8],
    ) -> Result<(&[u8], AttrType, AttributeFlags, &[u8]), BgpParseError> {
        let (input, flags_byte) = be_u8(input)?;
        let flags = AttributeFlags::from_bits_truncate(flags_byte);
        let (input, attr_type_byte) = be_u8(input)?;
        let attr_type: AttrType = attr_type_byte.into();

        // Decide extended length presence and parse length
        let (input, length_bytes) = if flags.is_extended() {
            take(2usize).parse(input)?
        } else {
            take(1usize).parse(input)?
        };
        let attr_len = u16::from_be_bytes(if length_bytes.len() == 2 {
            [length_bytes[0], length_bytes[1]]
        } else {
            [0, length_bytes[0]]
        });

        // Split out the payload for this attribute
        let (input, attr_payload) =
            packet_utils::safe_split_at(input, attr_len as usize).map_err(BgpParseError::from)?;
        Ok((input, attr_type, flags, attr_payload))
    }

    /// Parse the Value of one attribute given its already-decoded framing.
    /// A failure here is recoverable by the caller for attributes whose
    /// RFC 7606 error action is treat-as-withdraw (see
    /// [`attr_malformation_is_withdraw`]).
    fn parse_attr_value(
        attr_type: AttrType,
        attr_payload: &[u8],
        as4: bool,
        opt: &Option<ParseOption>,
    ) -> Result<Attr, BgpParseError> {
        // Only AS_PATH or AGGREGATOR care about as4 extension
        let as4_opt = matches!(attr_type, AttrType::AsPath | AttrType::Aggregator).then_some(as4);

        // Parse the attribute using the appropriate selector with error context
        let attr = match attr_type {
            AttrType::MpReachNlri => {
                let (_, mp_reach) = MpReachAttr::parse_nlri_opt(attr_payload, opt.clone())
                    .map_err(|e| BgpParseError::AttributeParseError {
                        attr_type,
                        source: Box::new(BgpParseError::from(e)),
                    })?;
                Attr::MpReachNlri(mp_reach)
            }
            AttrType::MpUnreachNlri => {
                let (_, mp_unreach) = MpUnreachAttr::parse_nlri_opt(attr_payload, opt.clone())
                    .map_err(|e| BgpParseError::AttributeParseError {
                        attr_type,
                        source: Box::new(BgpParseError::from(e)),
                    })?;
                Attr::MpUnreachNlri(mp_unreach)
            }
            _ => {
                Attr::parse_be(attr_payload, AttrSelector(attr_type, as4_opt))
                    .map_err(|e| BgpParseError::AttributeParseError {
                        attr_type,
                        source: Box::new(BgpParseError::from(e)),
                    })?
                    .1
            }
        };
        Ok(attr)
    }

    pub fn parse_attr<'a>(
        input: &'a [u8],
        as4: bool,
        opt: &'a Option<ParseOption>,
    ) -> Result<(&'a [u8], Attr), BgpParseError> {
        let (input, attr_type, _flags, attr_payload) = Attr::parse_attr_header(input)?;
        let attr = Attr::parse_attr_value(attr_type, attr_payload, as4, opt)?;
        Ok((input, attr))
    }
}

/// Whether a malformed instance of `attr_type` should be handled by the
/// RFC 7606 "treat-as-withdraw" action rather than by resetting the BGP
/// session. The BGP Prefix-SID attribute uses treat-as-withdraw per
/// RFC 8669 §5 and RFC 9252 §7 (a malformed SRv6 Service TLV must not
/// tear the session down). Other attributes keep their existing
/// (session-reset) handling.
fn attr_malformation_is_withdraw(attr_type: AttrType) -> bool {
    matches!(
        attr_type,
        // RFC 7606 §7.8: a Community attribute whose length is not a non-zero
        // multiple of 4 is malformed and "SHALL be handled using the approach of
        // 'treat-as-withdraw'".
        AttrType::Community
            // RFC 8092 §3 says the same of a Large Communities attribute whose
            // length is not a non-zero multiple of 12.
            | AttrType::LargeCom
            | AttrType::PrefixSid
    )
}

type ParsedAttributes<'a> = Result<
    (
        &'a [u8],
        Option<BgpAttr>,
        Option<MpReachAttr>,
        Option<MpUnreachAttr>,
        // RFC 7606 treat-as-withdraw: set when a recoverable attribute
        // (e.g. a malformed BGP Prefix-SID) was discarded, so the caller
        // withdraws the UPDATE's reachable NLRI instead of installing.
        bool,
    ),
    BgpParseError,
>;

pub fn parse_bgp_update_attribute(
    input: &[u8],
    length: u16,
    as4: bool,
    opt: Option<ParseOption>,
) -> ParsedAttributes<'_> {
    let length = length as usize;
    let (input, attr) = packet_utils::safe_split_at(input, length).map_err(BgpParseError::from)?;
    let mut remaining = attr;
    let mut bgp_attr = BgpAttr::default();
    let mut mp_update: Option<MpReachAttr> = None;
    let mut mp_withdraw: Option<MpUnreachAttr> = None;
    let mut treat_as_withdraw = false;

    while !remaining.is_empty() {
        // Parse the framing first so a Value-parse error stays recoverable:
        // `new_remaining` already points at the next attribute.
        let (new_remaining, attr_type, flags, attr_payload) = Attr::parse_attr_header(remaining)?;

        // Unrecognized attribute Type Code — classify by the Attribute
        // Flags octet per RFC 4271 §6.3 / §9 (and RFC 7606):
        //   * Optional bit clear  → unrecognized WELL-KNOWN attribute:
        //     reset the session with a NOTIFICATION (subcode 2).
        //   * Optional + Transitive → retain, set the Partial bit, and
        //     re-advertise to other peers.
        //   * Optional, non-Transitive → quietly ignore (not propagated).
        if let AttrType::Unknown(type_code) = attr_type {
            if !flags.contains(AttributeFlags::OPTIONAL) {
                // Capture the full attribute TLV (flags..value) for the
                // NOTIFICATION Data field; `new_remaining` is positioned
                // just past this attribute.
                let consumed = remaining.len() - new_remaining.len();
                return Err(BgpParseError::UnrecognizedWellknownAttribute {
                    type_code,
                    attr: remaining[..consumed].to_vec(),
                });
            }
            if flags.contains(AttributeFlags::TRANSITIVE) {
                let mut unknown = UnknownAttr::new(flags.bits(), type_code, attr_payload.to_vec());
                unknown.set_partial();
                bgp_attr.unknown.push(unknown);
            }
            // Optional non-transitive: drop silently.
            remaining = new_remaining;
            continue;
        }

        let attr = match Attr::parse_attr_value(attr_type, attr_payload, as4, &opt) {
            Ok(attr) => attr,
            Err(e) => {
                if attr_malformation_is_withdraw(attr_type) {
                    // RFC 7606 / RFC 9252 §7: discard the malformed
                    // attribute and treat the UPDATE's reachable NLRI as
                    // withdrawn, keeping the session up.
                    treat_as_withdraw = true;
                    remaining = new_remaining;
                    continue;
                }
                return Err(e);
            }
        };
        match attr {
            Attr::Origin(v) => {
                bgp_attr.origin = Some(v);
            }
            Attr::As2Path(v) => {
                // Widen the 2-octet AS_PATH into the 4-octet form the rest of
                // the crate uses (RFC 6793 §4.2.2). Discarding it left
                // `bgp_attr.aspath` at None, so the route would be accepted with
                // no AS_PATH at all — no loop detection, no path-length
                // comparison — and re-advertised without a well-known mandatory
                // attribute.
                //
                // Not reachable today: `peer_packet_parse` passes a hardcoded
                // `as4 = true`, so AS_PATH always parses as `As4Path` and this
                // arm runs only from tests. It is wired up so that sourcing
                // `as4` from the negotiated capability cannot silently lose
                // AS_PATHs. Doing that properly also needs AS4_PATH (type 17)
                // to recover the 4-octet ASNs an OLD peer hides behind
                // AS_TRANS; neither attribute is implemented here.
                bgp_attr.aspath = Some(v.into());
            }
            Attr::As4Path(v) => {
                bgp_attr.aspath = Some(v);
            }
            Attr::NextHop(v) => {
                bgp_attr.nexthop = Some(BgpNexthop::Ipv4(v.nexthop));
            }
            Attr::Med(v) => {
                bgp_attr.med = Some(v);
            }
            Attr::LocalPref(v) => {
                bgp_attr.local_pref = Some(v);
            }
            Attr::AtomicAggregate(v) => {
                bgp_attr.atomic_aggregate = Some(v);
            }
            Attr::Aggregator(v) => {
                bgp_attr.aggregator = Some(v);
            }
            Attr::Aggregator2(_v) => {
                // TODO
            }
            Attr::Community(v) => {
                bgp_attr.com = Some(v);
            }
            Attr::OriginatorId(v) => {
                bgp_attr.originator_id = Some(v);
            }
            Attr::ClusterList(v) => {
                bgp_attr.cluster_list = Some(v);
            }
            Attr::MpReachNlri(v) => {
                match v {
                    MpReachAttr::Vpnv4(nlri) => {
                        bgp_attr.nexthop = Some(BgpNexthop::Vpnv4(nlri.nhop.clone()));
                        mp_update = Some(MpReachAttr::Vpnv4(nlri));
                    }
                    MpReachAttr::Evpn {
                        snpa,
                        nhop,
                        updates,
                    } => {
                        bgp_attr.nexthop = Some(BgpNexthop::Evpn(nhop));
                        mp_update = Some(MpReachAttr::Evpn {
                            snpa,
                            nhop,
                            updates,
                        })
                    }
                    MpReachAttr::Ipv4 {
                        snpa,
                        nhop,
                        updates,
                    } => {
                        // RFC 8950 IPv4-over-IPv6: the next-hop is an
                        // IPv6 address that `BgpNexthop` has no variant
                        // for, so leave `bgp_attr.nexthop` unset — the
                        // consumer in `bgp/route.rs` reads `nhop` off
                        // the mp_update variant directly.
                        mp_update = Some(MpReachAttr::Ipv4 {
                            snpa,
                            nhop,
                            updates,
                        });
                    }
                    MpReachAttr::Ipv6 {
                        snpa,
                        nhop,
                        updates,
                    } => {
                        // Native IPv6 unicast. The v6 next-hop rides on the
                        // MP_REACH and is stamped into the attr by the
                        // consumer in `bgp/route.rs`; just surface the NLRI.
                        mp_update = Some(MpReachAttr::Ipv6 {
                            snpa,
                            nhop,
                            updates,
                        });
                    }
                    // Every remaining MP family — VPNv6, IPv4/IPv6
                    // Labeled-Unicast, Flowspec, SR-Policy, Route-Target
                    // Constraint, BGP-LS, MUP — is dispatched by
                    // `route_from_peer`. Surface it so the UPDATE reaches the
                    // RIB instead of being silently dropped here; the
                    // per-family next-hop travels on the variant and is read
                    // by the consumer (these do not stamp `bgp_attr.nexthop`).
                    other => {
                        mp_update = Some(other);
                    }
                }
            }
            Attr::MpUnreachNlri(v) => {
                mp_withdraw = Some(v);
            }
            Attr::ExtendedCom(v) => {
                bgp_attr.ecom = Some(v);
            }
            Attr::PmsiTunnel(v) => {
                bgp_attr.pmsi_tunnel = Some(v);
            }
            Attr::Aigp(v) => {
                bgp_attr.aigp = Some(v);
            }
            Attr::LargeCom(v) => {
                bgp_attr.lcom = Some(v);
            }
            Attr::PrefixSid(v) => {
                bgp_attr.prefix_sid = Some(v);
            }
            Attr::TunnelEncap(v) => {
                bgp_attr.tunnel_encap = Some(v);
            }
            Attr::BgpLs(v) => {
                bgp_attr.bgp_ls = Some(v);
            }
        }
        remaining = new_remaining;
    }

    Ok((
        input,
        Some(bgp_attr),
        mp_update,
        mp_withdraw,
        treat_as_withdraw,
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_bgp_update_attribute;
    use crate::BgpParseError;

    #[test]
    fn parse_bgp_update_attribute_rejects_oversized_length() {
        let err = parse_bgp_update_attribute(&[0xff, 0xee, 0xdd], 4, false, None)
            .expect_err("oversized attribute block length must fail");
        match err {
            BgpParseError::IncompleteData { needed } => assert_eq!(needed, 4),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn malformed_prefix_sid_triggers_treat_as_withdraw_not_session_reset() {
        // A valid ORIGIN attribute followed by a BGP Prefix-SID (type 40)
        // whose SRv6 L3 Service TLV carries an under-length (5 < 21) SID
        // Information sub-TLV. Per RFC 9252 §7 / RFC 8669 §5 the malformed
        // Prefix-SID must be discarded and the UPDATE treated-as-withdraw
        // — NOT reset the session. So the parse succeeds, ORIGIN survives,
        // the Prefix-SID is gone, and the withdraw flag is set.
        let mut block = vec![0x40, 0x01, 0x01, 0x00]; // ORIGIN = IGP
        let service_value = [0x00, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut psid_value = vec![5u8, 0x00, service_value.len() as u8]; // SRv6 L3 Service TLV
        psid_value.extend_from_slice(&service_value);
        block.push(0xC0); // optional + transitive
        block.push(40); // type = PrefixSid
        block.push(psid_value.len() as u8);
        block.extend_from_slice(&psid_value);

        let len = block.len() as u16;
        let (_, bgp_attr, mp_update, mp_withdraw, treat_as_withdraw) =
            parse_bgp_update_attribute(&block, len, false, None).expect("must not reset session");
        assert!(
            treat_as_withdraw,
            "malformed Prefix-SID must treat-as-withdraw"
        );
        let bgp_attr = bgp_attr.expect("attrs parsed");
        assert!(
            bgp_attr.origin.is_some(),
            "ORIGIN must survive the recovery"
        );
        assert!(
            bgp_attr.prefix_sid.is_none(),
            "malformed Prefix-SID must be discarded"
        );
        assert!(mp_update.is_none() && mp_withdraw.is_none());
    }

    /// Regression: every MP family beyond Vpnv4/Evpn/Ipv4/Ipv6 (here a
    /// Flowspec MP_REACH) used to fall into the `MpReachNlri` `_ => {}`
    /// arm and never set `mp_update`, so the UPDATE was silently dropped
    /// before reaching the RIB. They must now surface for dispatch.
    #[test]
    fn mp_reach_other_family_surfaces_as_mp_update() {
        use crate::attrs::mp_reach::flowspec_attr_emit;
        use crate::{Afi, FlowspecComponent, FlowspecNlri, FlowspecPrefix, MpReachAttr};
        use bytes::BytesMut;

        let updates = vec![FlowspecNlri::new(
            Afi::Ip6,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V6 {
                length: 64,
                offset: 0,
                pattern: "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().octets()[..8].to_vec(),
            })],
        )];

        let mut block = vec![0x40, 0x01, 0x01, 0x00]; // ORIGIN = IGP
        let mut attr = BytesMut::new();
        flowspec_attr_emit(Afi::Ip6, &updates, &mut attr);
        block.extend_from_slice(&attr);

        let len = block.len() as u16;
        let (_, bgp_attr, mp_update, _mp_withdraw, treat_as_withdraw) =
            parse_bgp_update_attribute(&block, len, false, None).expect("attrs must parse");
        assert!(!treat_as_withdraw);
        assert!(bgp_attr.is_some());
        match mp_update {
            Some(MpReachAttr::Flowspec {
                afi,
                updates: parsed,
            }) => {
                assert_eq!(afi, Afi::Ip6);
                assert_eq!(parsed, updates);
            }
            other => panic!("Flowspec MP_REACH must surface as mp_update, got {other:?}"),
        }
    }

    /// A Community attribute whose length is not a non-zero multiple of 4 is
    /// malformed, and RFC 7606 §7.8 requires treat-as-withdraw rather than a
    /// session reset.
    #[test]
    fn community_width_violations_are_treat_as_withdraw() {
        // RFC 7606 §7.8: a Community attribute is malformed unless its length is
        // a non-zero multiple of 4, and a malformed one "SHALL be handled using
        // the approach of 'treat-as-withdraw'".
        //
        // Regression: the `Vec<u32>` decode stopped at the last whole value and
        // the leftover was discarded, so a 6-octet payload parsed as one
        // community, the two stray octets vanished, and the route installed.
        for value in [
            vec![0x00u8, 0x01, 0x00, 0x02, 0xAA, 0xBB], // 6: one value + 2 stray
            vec![],                                     // 0: must be non-zero
            vec![0x00, 0x01, 0x00],                     // 3: short of one value
        ] {
            let mut block = ORIGIN_IGP.to_vec();
            block.extend_from_slice(&[0xC0, 8, value.len() as u8]);
            block.extend_from_slice(&value);
            let len = block.len() as u16;

            let (_, bgp_attr, _, _, treat_as_withdraw) =
                parse_bgp_update_attribute(&block, len, true, None)
                    .expect("must not reset the session");
            assert!(
                treat_as_withdraw,
                "COMMUNITIES length {} must be treat-as-withdraw",
                value.len()
            );
            let bgp_attr = bgp_attr.expect("bgp_attr present");
            assert!(
                bgp_attr.com.is_none(),
                "the malformed attribute is discarded"
            );
            assert!(bgp_attr.origin.is_some(), "other attributes still parse");
        }
    }

    /// RFC 8092 §3: the same, for a Large Communities attribute whose length is
    /// not a non-zero multiple of 12.
    #[test]
    fn large_community_width_violations_are_treat_as_withdraw() {
        for n in [14usize, 0, 11] {
            let mut block = ORIGIN_IGP.to_vec();
            block.extend_from_slice(&[0xC0, 32, n as u8]);
            block.extend(std::iter::repeat_n(0u8, n));
            let len = block.len() as u16;

            let (_, bgp_attr, _, _, treat_as_withdraw) =
                parse_bgp_update_attribute(&block, len, true, None)
                    .expect("must not reset the session");
            assert!(
                treat_as_withdraw,
                "LARGE_COMMUNITY length {n} must be treat-as-withdraw"
            );
            assert!(bgp_attr.expect("bgp_attr").lcom.is_none());
        }
    }

    /// Well-formed widths still parse, so the check rejects only real
    /// violations.
    #[test]
    fn well_formed_community_widths_still_parse() {
        let mut block = ORIGIN_IGP.to_vec();
        block.extend_from_slice(&[0xC0, 8, 8, 0x00, 0x01, 0x00, 0x02, 0xFF, 0xFF, 0xFF, 0x01]);
        let len = block.len() as u16;
        let (_, bgp_attr, _, _, treat_as_withdraw) =
            parse_bgp_update_attribute(&block, len, true, None).expect("must parse");
        assert!(!treat_as_withdraw);
        let com = bgp_attr
            .expect("bgp_attr")
            .com
            .expect("communities present");
        assert_eq!(com.0.len(), 2);
        assert!(com.is_no_export());
    }

    /// An RFC 5701 IPv6 Address Specific Extended Community (type 25) must not
    /// tear the session down. Regression: `AttrType` named the code without an
    /// `Attr` variant to select, so it skipped the RFC 4271 §9 handling, failed
    /// the derived Switch in `parse_attr_value`, and — not being a
    /// treat-as-withdraw attribute — propagated the error out as a session
    /// reset. Unnamed, it is `Unknown(25)`: optional+transitive, so retained
    /// with the Partial bit and propagated.
    #[test]
    fn ipv6_ext_community_is_passed_through_not_session_reset() {
        let mut block = ORIGIN_IGP.to_vec();
        // flags 0xC0 (optional+transitive), type 25, length 20:
        // type/sub-type 0x00/0x02 (RT), 2001:db8::1, local admin 100.
        let mut v = vec![0xC0u8, 25, 20, 0x00, 0x02];
        v.extend_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        v.extend_from_slice(&100u16.to_be_bytes());
        block.extend_from_slice(&v);

        let len = block.len() as u16;
        let (_, bgp_attr, _, _, treat_as_withdraw) =
            parse_bgp_update_attribute(&block, len, true, None)
                .expect("an IPv6 ext-community must not reset the session");
        assert!(!treat_as_withdraw);

        let bgp_attr = bgp_attr.expect("bgp_attr present");
        assert!(bgp_attr.origin.is_some(), "well-known attributes survive");
        assert_eq!(bgp_attr.unknown.len(), 1, "retained for propagation");
        let u = &bgp_attr.unknown[0];
        assert_eq!(u.type_code, 25);
        assert!(
            AttributeFlags::from_bits_truncate(u.flags).contains(AttributeFlags::PARTIAL),
            "RFC 4271 §9: Partial set on an unrecognized optional-transitive attribute"
        );
    }

    // ---- 2-octet AS_PATH (RFC 6793 OLD-speaker encoding) --------------

    /// A 2-octet AS_PATH must reach `bgp_attr.aspath`, widened to the 4-octet
    /// form. Regression: the `Attr::As2Path` arm was an empty `// TODO`, so the
    /// well-known mandatory AS_PATH was parsed and then silently dropped,
    /// leaving `aspath` at None.
    ///
    /// Only reachable with `as4 = false`; `peer_packet_parse` hardcodes `true`
    /// today, so this guards the wiring rather than live behaviour.
    #[test]
    fn as2_path_reaches_bgp_attr_widened() {
        // ORIGIN = IGP, then AS_PATH (type 2, len 6): AS_SEQ of 65000 65001.
        let mut block = vec![0x40, 0x01, 0x01, 0x00];
        block.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x02, 0xfd, 0xe8, 0xfd, 0xe9]);

        let len = block.len() as u16;
        let (_, bgp_attr, _, _, treat_as_withdraw) =
            parse_bgp_update_attribute(&block, len, false, None).expect("attrs must parse");
        assert!(!treat_as_withdraw);

        let aspath = bgp_attr
            .expect("bgp_attr present")
            .aspath
            .expect("2-octet AS_PATH must not be dropped");
        let flat: Vec<u32> = aspath
            .segs
            .iter()
            .flat_map(|s| s.asn.iter().copied())
            .collect();
        assert_eq!(flat, vec![65000u32, 65001], "ASNs widened to 4 octets");
        assert_eq!(aspath.length, 2, "hop count preserved");
    }

    // ---- RFC 4271 §9 unrecognized attribute handling -----------------

    use crate::{AttributeFlags, UnknownAttr};
    use bytes::BytesMut;

    /// ORIGIN = IGP, used as a sentinel so we can prove the well-known
    /// attributes survive whatever the unknown attribute does.
    const ORIGIN_IGP: [u8; 4] = [0x40, 0x01, 0x01, 0x00];

    /// Unrecognized OPTIONAL TRANSITIVE attribute → accepted, the Partial
    /// bit is set, and it is retained for propagation (RFC 4271 §9). A
    /// re-emit reproduces the attribute with Partial set.
    #[test]
    fn unknown_optional_transitive_is_retained_with_partial() {
        let mut block = ORIGIN_IGP.to_vec();
        // flags 0xC0 = OPTIONAL|TRANSITIVE, type 250, len 2, value DE AD
        block.extend_from_slice(&[0xC0, 0xFA, 0x02, 0xDE, 0xAD]);
        let len = block.len() as u16;

        let (_, bgp_attr, _mp_u, _mp_w, taw) =
            parse_bgp_update_attribute(&block, len, false, None).expect("must parse");
        assert!(!taw, "unknown transitive must not treat-as-withdraw");
        let bgp_attr = bgp_attr.expect("attrs parsed");
        assert!(bgp_attr.origin.is_some(), "ORIGIN must survive");
        assert_eq!(bgp_attr.unknown.len(), 1, "transitive unknown retained");

        let u = &bgp_attr.unknown[0];
        assert_eq!(u.type_code, 250);
        assert_eq!(u.value, vec![0xDE, 0xAD]);
        assert!(u.is_optional() && u.is_transitive());
        assert!(u.is_partial(), "Partial bit must be set on receive (§9)");

        // Re-emit just the unknown attribute and confirm the Partial bit
        // is on the wire (0xE0 = OPTIONAL|TRANSITIVE|PARTIAL).
        let mut buf = BytesMut::new();
        u.attr_emit(&mut buf);
        assert_eq!(&buf[..], &[0xE0, 0xFA, 0x02, 0xDE, 0xAD]);
    }

    /// Unrecognized OPTIONAL NON-TRANSITIVE attribute → quietly ignored,
    /// never stored, never propagated (RFC 4271 §9).
    #[test]
    fn unknown_optional_nontransitive_is_dropped() {
        let mut block = ORIGIN_IGP.to_vec();
        // flags 0x80 = OPTIONAL only, type 251, len 1, value 07
        block.extend_from_slice(&[0x80, 0xFB, 0x01, 0x07]);
        let len = block.len() as u16;

        let (_, bgp_attr, _mp_u, _mp_w, taw) =
            parse_bgp_update_attribute(&block, len, false, None).expect("must parse");
        assert!(!taw);
        let bgp_attr = bgp_attr.expect("attrs parsed");
        assert!(bgp_attr.origin.is_some(), "ORIGIN must survive");
        assert!(
            bgp_attr.unknown.is_empty(),
            "non-transitive unknown must be dropped"
        );
    }

    /// Unrecognized WELL-KNOWN attribute (Optional bit clear) → session
    /// reset error carrying the offending attribute (RFC 4271 §6.3).
    #[test]
    fn unrecognized_wellknown_attribute_is_an_error() {
        let mut block = ORIGIN_IGP.to_vec();
        // flags 0x40 = TRANSITIVE, Optional CLEAR → well-known. type 252.
        block.extend_from_slice(&[0x40, 0xFC, 0x01, 0x09]);
        let len = block.len() as u16;

        let err = parse_bgp_update_attribute(&block, len, false, None)
            .expect_err("unrecognized well-known attribute must error");
        match err {
            BgpParseError::UnrecognizedWellknownAttribute { type_code, attr } => {
                assert_eq!(type_code, 252);
                // Full TLV: flags, type, length, value.
                assert_eq!(attr, vec![0x40, 0xFC, 0x01, 0x09]);
            }
            other => panic!("expected UnrecognizedWellknownAttribute, got {other:?}"),
        }
    }

    /// A whole-`BgpAttr` round-trip: an unknown transitive attribute set
    /// on `BgpAttr` is emitted by `attr_emit` and parses back identically
    /// (Partial already set), proving propagation is bit-faithful.
    #[test]
    fn bgp_attr_roundtrips_unknown_transitive() {
        let mut attr = crate::BgpAttr::new();
        let mut u = UnknownAttr::new(
            (AttributeFlags::OPTIONAL | AttributeFlags::TRANSITIVE).bits(),
            240,
            vec![1, 2, 3, 4],
        );
        u.set_partial();
        attr.unknown.push(u);

        let mut buf = BytesMut::new();
        attr.attr_emit(&mut buf);
        let len = buf.len() as u16;
        let (_, parsed, _, _, _) =
            parse_bgp_update_attribute(&buf, len, true, None).expect("re-parse");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.unknown.len(), 1);
        assert_eq!(parsed.unknown[0].type_code, 240);
        assert_eq!(parsed.unknown[0].value, vec![1, 2, 3, 4]);
        assert!(parsed.unknown[0].is_partial());
    }
}
