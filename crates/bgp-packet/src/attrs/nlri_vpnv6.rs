use std::fmt;
use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};
use ipnet::Ipv6Net;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{Afi, AttrType, Label, ParseNlri, RouteDistinguisher, Safi, nlri_psize};

use super::mp_reach::{MP_REACH_HEADER_LEN, put_mp_reach_attr};
use super::{AttrEmitter, AttrFlags, Ipv6Nlri};

#[derive(Debug, Clone)]
pub struct Vpnv6Nlri {
    pub label: Label,
    pub rd: RouteDistinguisher,
    pub nlri: Ipv6Nlri,
}

impl Vpnv6Nlri {
    /// Encode this NLRI as it appears in an MP_REACH / MP_UNREACH NLRI
    /// list — the v6 twin of [`super::nlri_vpnv4::Vpnv4Nlri::nlri_emit`].
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        if self.nlri.id != 0 {
            buf.put_u32(self.nlri.id);
        }
        buf.put_u8(self.nlri.prefix.prefix_len() + 88);
        buf.put(&self.label.to_bytes()[..]);
        buf.put_u16(self.rd.typ as u16);
        buf.put(&self.rd.val[..]);
        let plen = nlri_psize(self.nlri.prefix.prefix_len());
        buf.put(&self.nlri.prefix.addr().octets()[0..plen]);
    }
}

// Identity excludes the MPLS `label` — see [`super::nlri_vpnv4::Vpnv4Nlri`].
// A VPNv6 route is identified by (RD, prefix, path-id); the label is a
// forwarding property, and the advertise-cache removal path
// (`cache_remove_vpnv6`) doesn't carry it.
impl PartialEq for Vpnv6Nlri {
    fn eq(&self, other: &Self) -> bool {
        self.rd == other.rd && self.nlri == other.nlri
    }
}

impl Eq for Vpnv6Nlri {}

impl std::hash::Hash for Vpnv6Nlri {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.rd.hash(state);
        self.nlri.hash(state);
    }
}

impl ParseNlri<Vpnv6Nlri> for Vpnv6Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Vpnv6Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };

        // MPLS Label (3 octets) + RD (8 octets) + IPv6 Prefix (0-16 octets).
        let (input, mut plen) = be_u8(input)?;

        // Validate plen >= 88 (label 24 + RD 64) before parsing label and RD.
        if plen < 88 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }

        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        // MPLS Label.
        let (input, label) = take(3usize).parse(input)?;
        let label = Label::from(label);

        // RD.
        let (input, rd) = RouteDistinguisher::parse_be(input)?;

        // Adjust plen to MPLS Label and Route Distinguisher.
        plen -= 88;
        let psize = nlri_psize(plen);

        if psize > 16 {
            // Prefix size must be 0..=16 (the `> 16` bound also rejects
            // any `plen > 128`, keeping `Ipv6Net::new` below infallible).
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        if psize > input.len() {
            // Prefix size must be same or smaller than remaining input buffer.
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }

        // IPv6 prefix.
        let mut paddr = [0u8; 16];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");

        let nlri = Ipv6Nlri { id, prefix };

        let vpnv6 = Vpnv6Nlri { label, rd, nlri };

        Ok((input, vpnv6))
    }
}

impl fmt::Display for Vpnv6Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bos = if self.label.bos { "(BoS)" } else { "" };
        write!(
            f,
            "VPNv6 [{}]:[{}]{} label: {} {}",
            self.rd, self.nlri.id, self.nlri.prefix, self.label.label, bos,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vpnv6Nexthop {
    pub rd: RouteDistinguisher,
    pub nhop: Ipv6Addr,
}

impl fmt::Display for Vpnv6Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]:{}", self.rd, self.nhop)
    }
}

#[derive(Debug, Clone)]
pub struct Vpnv6Reach {
    pub snpa: u8,
    pub nhop: Vpnv6Nexthop,
    pub updates: Vec<Vpnv6Nlri>,
}

impl AttrEmitter for Vpnv6Reach {
    fn attr_type(&self) -> AttrType {
        AttrType::MpReachNlri
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        // AFI/SAFI.
        buf.put_u16(u16::from(Afi::Ip6));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Nexthop
        buf.put_u8(24); // Nexthop length.  RD(8)+IPv6 Nexthop(16);
        // Nexthop RD.
        let rd = [0u8; 8];
        buf.put(&rd[..]);
        // Nexthop.
        buf.put(&self.nhop.nhop.octets()[..]);
        // SNPA
        buf.put_u8(0);
        // Prefix.
        for update in self.updates.iter() {
            // AddPath
            if update.nlri.id != 0 {
                buf.put_u32(update.nlri.id);
            }
            // Plen
            let plen = update.nlri.prefix.prefix_len() + 88;
            buf.put_u8(plen);
            // Label
            buf.put(&update.label.to_bytes()[..]);
            // RD
            buf.put_u16(update.rd.typ as u16);
            buf.put(&update.rd.val[..]);
            // Prefix
            let plen = nlri_psize(update.nlri.prefix.prefix_len());
            buf.put(&update.nlri.prefix.addr().octets()[0..plen]);
        }
    }
}

impl Vpnv6Reach {
    /// Emit the MP_REACH_NLRI attribute into `buf` with as many NLRIs from
    /// `updates` as fit in a packet of `max_packet_size` octets, and return
    /// how many were emitted. See [`Vpnv4Reach::attr_emit_mut`] for the
    /// budget rule; this is its VPNv6 twin.
    pub fn attr_emit_mut(&mut self, buf: &mut BytesMut, max_packet_size: usize) -> usize {
        let budget = max_packet_size.saturating_sub(buf.len() + MP_REACH_HEADER_LEN);
        let mut value = BytesMut::new();
        let emitted = self.emit_value(&mut value, budget);
        if emitted == 0 {
            return 0;
        }
        put_mp_reach_attr(buf, &value);
        emitted
    }

    /// Write the attribute value (AFI/SAFI, next-hop, SNPA, NLRIs) into
    /// `value`, stopping before the NLRI that would push it past `budget`
    /// octets. Returns the number of NLRIs written.
    fn emit_value(&mut self, value: &mut BytesMut, budget: usize) -> usize {
        // AFI/SAFI.
        value.put_u16(u16::from(Afi::Ip6));
        value.put_u8(u8::from(Safi::MplsVpn));
        // Nexthop
        value.put_u8(24); // Nexthop length.  RD(8)+IPv6 Nexthop(16);
        // Nexthop RD.
        let rd = [0u8; 8];
        value.put(&rd[..]);
        // Nexthop.
        value.put(&self.nhop.nhop.octets()[..]);
        // SNPA
        value.put_u8(0);

        let mut emitted = 0;
        while let Some(update) = self.updates.pop() {
            // Exact wire size of this NLRI: optional 4-octet path-id,
            // 1-octet length, 3-octet label, 8-octet RD, prefix octets.
            let path_id_len = if update.nlri.id != 0 { 4 } else { 0 };
            let nlri_len = path_id_len + 1 + 3 + 8 + nlri_psize(update.nlri.prefix.prefix_len());
            if value.len() + nlri_len > budget {
                self.updates.push(update);
                break;
            }

            // AddPath
            if update.nlri.id != 0 {
                value.put_u32(update.nlri.id);
            }
            // Plen
            let plen = update.nlri.prefix.prefix_len() + 88;
            value.put_u8(plen);
            // Label
            value.put(&update.label.to_bytes()[..]);
            // RD
            value.put_u16(update.rd.typ as u16);
            value.put(&update.rd.val[..]);
            // Prefix
            let plen = nlri_psize(update.nlri.prefix.prefix_len());
            value.put(&update.nlri.prefix.addr().octets()[0..plen]);
            emitted += 1;
        }
        emitted
    }
}

pub struct Vpnv6Unreach {
    pub withdraw: Vec<Vpnv6Nlri>,
}

impl AttrEmitter for Vpnv6Unreach {
    fn attr_type(&self) -> AttrType {
        AttrType::MpUnreachNlri
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        // AFI/SAFI.
        buf.put_u16(u16::from(Afi::Ip6));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Prefix.
        for withdraw in self.withdraw.iter() {
            withdraw.nlri_emit(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::Ipv6Nlri;

    fn nlri(rd: &str, prefix: &str, label: u32) -> Vpnv6Nlri {
        Vpnv6Nlri {
            label: Label {
                label,
                exp: 0,
                bos: true,
            },
            rd: RouteDistinguisher::from_str(rd).unwrap(),
            nlri: Ipv6Nlri {
                id: 0,
                prefix: prefix.parse().unwrap(),
            },
        }
    }

    #[test]
    fn reach_round_trips_through_parser() {
        // Emit a Vpnv6Reach, strip the attribute header, and parse the
        // value back through the MP_REACH VPNv6 path.
        let reach = Vpnv6Reach {
            snpa: 0,
            nhop: Vpnv6Nexthop {
                rd: RouteDistinguisher::from_str("65000:1").unwrap(),
                nhop: "2001:db8::1".parse().unwrap(),
            },
            updates: vec![
                nlri("65000:1", "2001:db8:1::/64", 100),
                nlri("65000:1", "2001:db8:2::/48", 200),
            ],
        };

        let mut buf = BytesMut::new();
        reach.emit(&mut buf);

        // emit() writes the MP_REACH value (AFI/SAFI/nexthop/SNPA/NLRI)
        // without the path-attribute header, which is exactly what
        // `parse_nlri_opt` expects after MpReachHeader. Note the
        // MP_REACH parser returns the input positioned at the start of
        // the NLRI section (the post-`many0` remainder is discarded, as
        // on the Vpnv4 path), so the returned pointer is intentionally
        // non-empty — the parsed `updates` are the contract here.
        let (_rest, parsed) =
            crate::MpReachAttr::parse_nlri_opt(&buf, None).expect("VPNv6 MP_REACH must parse");

        match parsed {
            crate::MpReachAttr::Vpnv6(r) => {
                assert_eq!(r.nhop.nhop, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(r.updates.len(), 2);
                // Order is preserved by the iterator-based emit().
                assert_eq!(
                    r.updates[0].nlri.prefix,
                    "2001:db8:1::/64".parse::<Ipv6Net>().unwrap()
                );
                assert_eq!(r.updates[0].label.label, 100);
                assert_eq!(
                    r.updates[0].rd,
                    RouteDistinguisher::from_str("65000:1").unwrap()
                );
                assert_eq!(
                    r.updates[1].nlri.prefix,
                    "2001:db8:2::/48".parse::<Ipv6Net>().unwrap()
                );
                assert_eq!(r.updates[1].label.label, 200);
            }
            other => panic!("expected Vpnv6, got {other:?}"),
        }
    }

    #[test]
    fn unreach_round_trips_through_parser() {
        let unreach = Vpnv6Unreach {
            withdraw: vec![nlri("65001:7", "2001:db8:3::/56", 0)],
        };
        let mut buf = BytesMut::new();
        unreach.emit(&mut buf);

        let (rest, parsed) =
            crate::MpUnreachAttr::parse_nlri_opt(&buf, None).expect("VPNv6 MP_UNREACH must parse");
        assert!(rest.is_empty());
        match parsed {
            crate::MpUnreachAttr::Vpnv6(w) => {
                assert_eq!(w.len(), 1);
                assert_eq!(
                    w[0].nlri.prefix,
                    "2001:db8:3::/56".parse::<Ipv6Net>().unwrap()
                );
                assert_eq!(w[0].rd, RouteDistinguisher::from_str("65001:7").unwrap());
            }
            other => panic!("expected Vpnv6, got {other:?}"),
        }
    }

    #[test]
    fn unreach_empty_is_eor() {
        // AFI(Ip6) + SAFI(MplsVpn) with no NLRI bytes is an EoR marker.
        let mut buf = BytesMut::new();
        buf.put_u16(u16::from(Afi::Ip6));
        buf.put_u8(u8::from(Safi::MplsVpn));
        let (_rest, parsed) =
            crate::MpUnreachAttr::parse_nlri_opt(&buf, None).expect("EoR must parse");
        assert!(matches!(parsed, crate::MpUnreachAttr::Vpnv6Eor));
    }

    #[test]
    fn parse_rejects_plen_below_label_rd_floor() {
        // plen < 88 (less than label+RD) must be rejected before the
        // label/RD reads.
        let input = [0x00u8, 0x00, 0x00, 0x00];
        assert!(Vpnv6Nlri::parse_nlri(&input, false).is_err());
    }

    #[test]
    fn identity_ignores_label() {
        use std::collections::HashSet;
        // Same (RD, prefix), different label → equal, so a route cached
        // under its real label is removed by the default-label key.
        let advertised = nlri("65000:1", "2001:db8::/64", 80);
        let remove_key = nlri("65000:1", "2001:db8::/64", 0);
        assert_eq!(advertised, remove_key);
        let mut set = HashSet::new();
        set.insert(advertised);
        assert!(set.remove(&remove_key));
    }
}
