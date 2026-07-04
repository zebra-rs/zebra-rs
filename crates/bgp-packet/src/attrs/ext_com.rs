use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom_derive::{NomBE, Parse};

use crate::{
    AttrEmitter, AttrFlags, AttrType, ExtCommunitySubType, ExtCommunityType, MupExtComSubType,
    RouteDistinguisher, RouteDistinguisherType, TunnelType,
};

use super::ext_com_token::{Token, tokenizer};

// Extended Communities are an unordered set on the wire (RFC 4360);
// BTreeSet keeps the values deduplicated and canonically sorted (the
// derived ExtCommunityValue Ord is wire-byte order: type bytes first,
// then value) so equal sets compare/hash equal regardless of received
// order.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct ExtCommunity(pub BTreeSet<ExtCommunityValue>);

impl FromIterator<ExtCommunityValue> for ExtCommunity {
    fn from_iter<I: IntoIterator<Item = ExtCommunityValue>>(iter: I) -> Self {
        ExtCommunity(iter.into_iter().collect())
    }
}

impl<const N: usize> From<[ExtCommunityValue; N]> for ExtCommunity {
    fn from(values: [ExtCommunityValue; N]) -> Self {
        ExtCommunity(BTreeSet::from(values))
    }
}

// nom_derive has no Parse impl for BTreeSet, so the wire decode is
// hand-written: parse the attribute payload as consecutive 8-octet
// values (`Vec`'s blanket impl) and collect into the set.
impl<'a> Parse<&'a [u8]> for ExtCommunity {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        Self::parse_be(input)
    }
    fn parse_be(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (input, values) = <Vec<ExtCommunityValue>>::parse_be(input)?;
        Ok((input, values.into_iter().collect()))
    }
}

#[derive(Clone, Debug, Default, NomBE, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtCommunityValue {
    pub high_type: u8,
    pub low_type: u8,
    pub val: [u8; 6],
}

impl ExtCommunityValue {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.high_type);
        buf.put_u8(self.low_type);
        buf.put(&self.val[..]);
    }

    /// True iff this entry encodes a Color extended community
    /// (RFC 9012 §4.3): Transitive Opaque (0x03) + Color sub-type
    /// (0x0b).
    pub fn is_color(&self) -> bool {
        self.high_type == ExtCommunityType::TransOpaque as u8
            && self.low_type == ExtCommunitySubType::Color as u8
    }

    /// Decode the Color value if this entry is a Color extcomm.
    /// Returns the 2-octet Flags field (CO bits live in the top two
    /// bits, see draft-ietf-idr-bgp-ct §3.2.1) and the 4-octet color
    /// identifier. Returns None for any other extcomm type.
    pub fn as_color(&self) -> Option<Color> {
        if !self.is_color() {
            return None;
        }
        let flags = u16::from_be_bytes([self.val[0], self.val[1]]);
        let color = u32::from_be_bytes([self.val[2], self.val[3], self.val[4], self.val[5]]);
        Some(Color { flags, color })
    }

    /// Build a Color extended community. `co_bits` is the 2-bit
    /// CO-bits field that occupies the top of the 16-bit Flags word;
    /// any value > 3 is masked to the low two bits.
    pub fn from_color(co_bits: u8, color: u32) -> Self {
        let flags: u16 = ((co_bits as u16) & 0b11) << 14;
        Color { flags, color }.into()
    }

    /// True iff this entry is a MUP Extended Community (draft-ietf-bess-mup-safi §5):
    /// high-type byte 0x0c.
    pub fn is_mup(&self) -> bool {
        self.high_type == ExtCommunityType::Mup as u8
    }

    /// Decode the MUP Extended Community sub-type and surface the
    /// 6-octet payload as opaque bytes. Typed payload decoding per
    /// draft-ietf-bess-mup-safi §5 is deferred to a follow-up.
    pub fn as_mup(&self) -> Option<MupExtCom> {
        if !self.is_mup() {
            return None;
        }
        Some(MupExtCom {
            sub_type: MupExtComSubType::from(self.low_type),
            value: self.val,
        })
    }

    /// True iff this entry is the EVPN Multicast Flags Extended
    /// Community (RFC 9251 §6): EVPN high-type (0x06) + Multicast
    /// Flags sub-type (0x09).
    pub fn is_evpn_mcast_flags(&self) -> bool {
        self.high_type == ExtCommunityType::Evpn as u8 && self.low_type == EVPN_MCAST_FLAGS_SUB_TYPE
    }

    /// Decode the EVPN Multicast Flags EC (RFC 9251 §6). Returns the
    /// IGMP / MLD proxy-support bits. Per §6 an EC with **both** bits
    /// clear is malformed and MUST be ignored by the receiver, so this
    /// returns `None` in that case (and for any non-matching EC).
    pub fn as_evpn_mcast_flags(&self) -> Option<EvpnMcastFlags> {
        if !self.is_evpn_mcast_flags() {
            return None;
        }
        let flags = u16::from_be_bytes([self.val[0], self.val[1]]);
        let mcast = EvpnMcastFlags {
            igmp_proxy: flags & EvpnMcastFlags::IGMP_PROXY != 0,
            mld_proxy: flags & EvpnMcastFlags::MLD_PROXY != 0,
            segmentation_support: flags & EvpnMcastFlags::SEGMENTATION_SUPPORT != 0,
        };
        // RFC 9251 §6: an EC with no capability bits set is malformed and
        // MUST be ignored. With the RFC 9572 §8 segmentation bit added, that
        // means all three known bits clear.
        if !mcast.igmp_proxy && !mcast.mld_proxy && !mcast.segmentation_support {
            return None;
        }
        Some(mcast)
    }

    /// True iff this entry is the DF Election Extended Community
    /// (RFC 8584 §2.2): EVPN high-type (0x06) + DF Election sub-type (0x06).
    pub fn is_evpn_df_election(&self) -> bool {
        self.high_type == ExtCommunityType::Evpn as u8 && self.low_type == EVPN_DF_ELECTION_SUB_TYPE
    }

    /// Decode the DF Election Extended Community (RFC 8584 §2.2). Returns the
    /// DF election algorithm and the capability bitmap (carrying the AC-DF
    /// bit, used by RFC 9572 §5.3.1 inter-AS segmentation). `None` for any
    /// non-matching EC.
    pub fn as_df_election(&self) -> Option<DfElectionEc> {
        if !self.is_evpn_df_election() {
            return None;
        }
        Some(DfElectionEc {
            df_alg: self.val[0] & DfElectionEc::DF_ALG_MASK,
            bitmap: u16::from_be_bytes([self.val[1], self.val[2]]),
        })
    }

    /// Build an ES-Import Route Target (RFC 7432 §7.6): EVPN high-type
    /// (0x06) + Route Target sub-type (0x02), value auto-derived from the
    /// **high-order 6 octets of the ESI value** (ESI octets 1..7 — the
    /// 1-octet ESI Type is skipped). Carried on EVPN Ethernet Segment
    /// (Type-4) and IGMP/MLD Synch (Type-7/8, RFC 9251) routes to scope
    /// their distribution to the PEs attached to that Ethernet Segment.
    pub fn es_import_rt(esi: &[u8; 10]) -> Self {
        let mut es_import = [0u8; 6];
        es_import.copy_from_slice(&esi[1..7]);
        Self::es_import_rt_raw(es_import)
    }

    /// Build an ES-Import Route Target from an already-derived 6-octet
    /// ES-Import value.
    pub fn es_import_rt_raw(es_import: [u8; 6]) -> Self {
        ExtCommunityValue {
            high_type: ExtCommunityType::Evpn as u8,
            low_type: EVPN_ES_IMPORT_RT_SUB_TYPE,
            val: es_import,
        }
    }

    /// True iff this entry is an EVPN ES-Import Route Target (RFC 7432
    /// §7.6): EVPN high-type (0x06) + Route Target sub-type (0x02).
    pub fn is_es_import_rt(&self) -> bool {
        self.high_type == ExtCommunityType::Evpn as u8
            && self.low_type == EVPN_ES_IMPORT_RT_SUB_TYPE
    }

    /// Decode the 6-octet ES-Import value if this entry is an ES-Import RT.
    pub fn as_es_import_rt(&self) -> Option<[u8; 6]> {
        if self.is_es_import_rt() {
            Some(self.val)
        } else {
            None
        }
    }

    /// Build an ESI Label Extended Community (RFC 7432 §7.5): EVPN high-type
    /// (0x06) + ESI Label sub-type (0x01). Carried on the **per-ES** Ethernet
    /// A-D (Type-1) route. The Flags octet's low bit is the redundancy mode
    /// (`single_active`); the 3-octet `label` (low 20 bits) is the MPLS ESI
    /// label for split-horizon (unused/0 for VXLAN, where local-bias does the
    /// filtering — RFC 8365 §8.3.1 — but the mode flag still matters).
    pub fn esi_label(single_active: bool, label: u32) -> Self {
        let mut val = [0u8; 6];
        if single_active {
            val[0] = EsiLabelEc::SINGLE_ACTIVE;
        }
        // val[1..3] reserved (zero). Label in the low 20 bits of val[3..6].
        let lbl = label.to_be_bytes();
        val[3..6].copy_from_slice(&lbl[1..4]);
        ExtCommunityValue {
            high_type: ExtCommunityType::Evpn as u8,
            low_type: EVPN_ESI_LABEL_SUB_TYPE,
            val,
        }
    }

    /// True iff this entry is an EVPN ESI Label EC (RFC 7432 §7.5):
    /// EVPN high-type (0x06) + ESI Label sub-type (0x01).
    pub fn is_esi_label(&self) -> bool {
        self.high_type == ExtCommunityType::Evpn as u8 && self.low_type == EVPN_ESI_LABEL_SUB_TYPE
    }

    /// Decode the ESI Label EC (RFC 7432 §7.5): the redundancy-mode flag and
    /// the 3-octet ESI label. `None` for any non-matching EC.
    pub fn as_esi_label(&self) -> Option<EsiLabelEc> {
        if !self.is_esi_label() {
            return None;
        }
        Some(EsiLabelEc {
            single_active: self.val[0] & EsiLabelEc::SINGLE_ACTIVE != 0,
            label: u32::from_be_bytes([0, self.val[3], self.val[4], self.val[5]]),
        })
    }

    /// Build an EVPN Layer-2 Attributes Extended Community (RFC 8214 §3.1):
    /// EVPN high-type (0x06) + Layer-2 Attributes sub-type (0x04). Carried on
    /// the **per-EVI** Ethernet A-D (Type-1) route of a VPWS service. The
    /// 2-octet Control Flags carry P (primary), B (backup) and C
    /// (control word); the 2-octet L2 MTU is 0 when no MTU check is wanted.
    pub fn l2_attr(primary: bool, backup: bool, control_word: bool, mtu: u16) -> Self {
        let mut flags: u16 = 0;
        if primary {
            flags |= L2AttrEc::PRIMARY;
        }
        if backup {
            flags |= L2AttrEc::BACKUP;
        }
        if control_word {
            flags |= L2AttrEc::CONTROL_WORD;
        }
        let mut val = [0u8; 6];
        val[0..2].copy_from_slice(&flags.to_be_bytes());
        val[2..4].copy_from_slice(&mtu.to_be_bytes());
        ExtCommunityValue {
            high_type: ExtCommunityType::Evpn as u8,
            low_type: EVPN_L2_ATTR_SUB_TYPE,
            val,
        }
    }

    /// True iff this entry is an EVPN Layer-2 Attributes EC (RFC 8214 §3.1):
    /// EVPN high-type (0x06) + Layer-2 Attributes sub-type (0x04).
    pub fn is_l2_attr(&self) -> bool {
        self.high_type == ExtCommunityType::Evpn as u8 && self.low_type == EVPN_L2_ATTR_SUB_TYPE
    }

    /// Decode the Layer-2 Attributes EC (RFC 8214 §3.1): the P/B/C control
    /// flags and the L2 MTU (0 = no MTU check). `None` for any non-matching
    /// EC.
    pub fn as_l2_attr(&self) -> Option<L2AttrEc> {
        if !self.is_l2_attr() {
            return None;
        }
        let flags = u16::from_be_bytes([self.val[0], self.val[1]]);
        Some(L2AttrEc {
            primary: flags & L2AttrEc::PRIMARY != 0,
            backup: flags & L2AttrEc::BACKUP != 0,
            control_word: flags & L2AttrEc::CONTROL_WORD != 0,
            mtu: u16::from_be_bytes([self.val[2], self.val[3]]),
        })
    }

    /// Build an EVI-RT Extended Community (RFC 9251 §9.5) from the EVI's
    /// (BD's) Route Target. The EVI-RT carries the same 6-octet RT value
    /// under the EVPN high-type (0x06), with the sub-type selecting the RT
    /// format: 2-octet-AS RT (`0x00/0x02`) → Type 0 (`0x0A`), IPv4-address
    /// RT (`0x01/0x02`) → Type 1 (`0x0B`), 4-octet-AS RT (`0x02/0x02`) →
    /// Type 2 (`0x0C`). Returns `None` for a non-RT EC or an
    /// IPv6-address-specific RT (EVI-RT Type 3 / `0x0D` needs a 20-octet
    /// IPv6 EC that `ExtCommunityValue` cannot hold). Each Type-7/8 route
    /// carries exactly one EVI-RT EC matching its BD's RT.
    pub fn evi_rt_from_rt(rt: &ExtCommunityValue) -> Option<Self> {
        if rt.low_type != ExtCommunitySubType::RouteTarget as u8 {
            return None;
        }
        let sub_type = match rt.high_type {
            0x00 => EVI_RT_TYPE0_SUB_TYPE,
            0x01 => EVI_RT_TYPE1_SUB_TYPE,
            0x02 => EVI_RT_TYPE2_SUB_TYPE,
            _ => return None,
        };
        Some(ExtCommunityValue {
            high_type: ExtCommunityType::Evpn as u8,
            low_type: sub_type,
            val: rt.val,
        })
    }

    /// True iff this entry is an EVI-RT Extended Community (RFC 9251 §9.5):
    /// EVPN high-type (0x06) + a Type-0..3 EVI-RT sub-type (0x0A–0x0D).
    pub fn is_evi_rt(&self) -> bool {
        self.high_type == ExtCommunityType::Evpn as u8
            && matches!(
                self.low_type,
                EVI_RT_TYPE0_SUB_TYPE
                    | EVI_RT_TYPE1_SUB_TYPE
                    | EVI_RT_TYPE2_SUB_TYPE
                    | EVI_RT_TYPE3_SUB_TYPE
            )
    }

    /// Reconstruct the underlying Route Target EC carried by an EVI-RT EC
    /// (RFC 9251 §9.5), the inverse of [`evi_rt_from_rt`](Self::evi_rt_from_rt).
    /// Returns `None` for a non-EVI-RT EC or the IPv6 form (`0x0D`), which
    /// has no 8-octet RT representation.
    pub fn as_evi_rt(&self) -> Option<ExtCommunityValue> {
        if self.high_type != ExtCommunityType::Evpn as u8 {
            return None;
        }
        let high_type = match self.low_type {
            EVI_RT_TYPE0_SUB_TYPE => 0x00,
            EVI_RT_TYPE1_SUB_TYPE => 0x01,
            EVI_RT_TYPE2_SUB_TYPE => 0x02,
            _ => return None,
        };
        Some(ExtCommunityValue {
            high_type,
            low_type: ExtCommunitySubType::RouteTarget as u8,
            val: self.val,
        })
    }
}

/// EVPN Multicast Flags Extended Community sub-type (RFC 9251 §6),
/// carried under the EVPN high-type (0x06).
const EVPN_MCAST_FLAGS_SUB_TYPE: u8 = 0x09;

/// DF Election Extended Community sub-type (RFC 8584 §2.2), carried under
/// the EVPN high-type (0x06).
const EVPN_DF_ELECTION_SUB_TYPE: u8 = 0x06;

/// ES-Import Route Target sub-type (RFC 7432 §7.6), carried under the EVPN
/// high-type (0x06). Shares the Route Target sub-type value (0x02) but is
/// disambiguated by the EVPN high-type.
const EVPN_ES_IMPORT_RT_SUB_TYPE: u8 = 0x02;

/// ESI Label Extended Community sub-type (RFC 7432 §7.5), carried under the
/// EVPN high-type (0x06).
const EVPN_ESI_LABEL_SUB_TYPE: u8 = 0x01;

/// Layer-2 Attributes Extended Community sub-type (RFC 8214 §3.1), carried
/// under the EVPN high-type (0x06).
const EVPN_L2_ATTR_SUB_TYPE: u8 = 0x04;

/// Decoded EVPN Layer-2 Attributes Extended Community (RFC 8214 §3.1).
/// Carried on the per-EVI Ethernet A-D (Type-1) route of a VPWS service to
/// signal the endpoint role and the attachment circuit's L2 MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct L2AttrEc {
    /// P bit: this PE is the primary endpoint for the service.
    pub primary: bool,
    /// B bit: this PE is the backup endpoint (multihomed single-active).
    pub backup: bool,
    /// C bit: a control word is inserted between the label stack and the
    /// L2 frame (MPLS pseudowire framing; unused over SRv6).
    pub control_word: bool,
    /// L2 MTU of the attachment circuit; 0 = no MTU check (RFC 8214 §3.1:
    /// mismatched non-zero MTUs mean the remote MUST NOT be used).
    pub mtu: u16,
}

impl L2AttrEc {
    /// Control Flags bit 15 (LSB of the 16-bit field, MSB-0 numbering):
    /// B — backup endpoint.
    const BACKUP: u16 = 0x0001;
    /// Control Flags bit 14: P — primary endpoint.
    const PRIMARY: u16 = 0x0002;
    /// Control Flags bit 13: C — control word present.
    const CONTROL_WORD: u16 = 0x0004;
}

impl From<L2AttrEc> for ExtCommunityValue {
    fn from(a: L2AttrEc) -> Self {
        ExtCommunityValue::l2_attr(a.primary, a.backup, a.control_word, a.mtu)
    }
}

/// Decoded EVPN ESI Label Extended Community (RFC 7432 §7.5). Carried on the
/// per-ES Ethernet A-D (Type-1) route to signal the redundancy mode and the
/// split-horizon ESI label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EsiLabelEc {
    /// Redundancy mode: `true` = Single-Active, `false` = All-Active
    /// (Flags octet low bit).
    pub single_active: bool,
    /// 3-octet ESI label (low 20 bits). 0 / unused for VXLAN (local-bias).
    pub label: u32,
}

impl EsiLabelEc {
    /// Flags octet bit 0 (LSB): set = Single-Active redundancy mode.
    const SINGLE_ACTIVE: u8 = 0x01;
}

impl From<EsiLabelEc> for ExtCommunityValue {
    fn from(e: EsiLabelEc) -> Self {
        ExtCommunityValue::esi_label(e.single_active, e.label)
    }
}

/// EVI-RT Extended Community sub-types (RFC 9251 §9.5), carried under the
/// EVPN high-type (0x06). The sub-type selects which Route Target format the
/// 6-octet value encodes.
const EVI_RT_TYPE0_SUB_TYPE: u8 = 0x0A; // 2-octet-AS RT
const EVI_RT_TYPE1_SUB_TYPE: u8 = 0x0B; // IPv4-address RT
const EVI_RT_TYPE2_SUB_TYPE: u8 = 0x0C; // 4-octet-AS RT
const EVI_RT_TYPE3_SUB_TYPE: u8 = 0x0D; // IPv6-address RT (decode-only marker)

/// Decoded EVPN Multicast Flags Extended Community (RFC 9251 §6, extended
/// by RFC 9572 §8). A PE attaches this to its Inclusive Multicast (Type-3)
/// route to advertise IGMP / MLD proxy capability and/or BUM tunnel
/// **segmentation** support. The 2-octet Flags field carries the capability
/// bits; the remaining 4 octets are reserved (zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvpnMcastFlags {
    pub igmp_proxy: bool,
    pub mld_proxy: bool,
    /// Bit 8 (RFC 9572 §8): the PE supports BUM tunnel segmentation.
    pub segmentation_support: bool,
}

impl EvpnMcastFlags {
    /// Bit 15 of the Flags field (RFC 9251 §6): IGMP Proxy Support.
    const IGMP_PROXY: u16 = 0x0001;
    /// Bit 14 of the Flags field: MLD Proxy Support.
    const MLD_PROXY: u16 = 0x0002;
    /// Bit 8 of the Flags field (RFC 9572 §8): Segmentation Support. RFC
    /// bit numbering is MSB-0 across the 16-bit field, so bit 8 = `1 << 7`.
    const SEGMENTATION_SUPPORT: u16 = 0x0080;
}

impl From<EvpnMcastFlags> for ExtCommunityValue {
    fn from(m: EvpnMcastFlags) -> Self {
        let mut flags: u16 = 0;
        if m.igmp_proxy {
            flags |= EvpnMcastFlags::IGMP_PROXY;
        }
        if m.mld_proxy {
            flags |= EvpnMcastFlags::MLD_PROXY;
        }
        if m.segmentation_support {
            flags |= EvpnMcastFlags::SEGMENTATION_SUPPORT;
        }
        let mut val = [0u8; 6];
        val[0..2].copy_from_slice(&flags.to_be_bytes());
        ExtCommunityValue {
            high_type: ExtCommunityType::Evpn as u8,
            low_type: EVPN_MCAST_FLAGS_SUB_TYPE,
            val,
        }
    }
}

/// Decoded DF Election Extended Community (RFC 8584 §2.2). Carried on EVPN
/// Ethernet Segment (Type-4) routes to negotiate the Designated Forwarder
/// election algorithm and capabilities; RFC 9572 §5.3.1 reuses it on a
/// re-advertised Per-Region I-PMSI (Type-9), with AC-DF cleared, to pick a
/// single forwarding ASBR into a downstream AS that contains legacy PEs.
///
/// Wire layout of the 6-octet value (after the 0x06/0x06 type bytes):
/// `val[0]` = RSV (high 3 bits) + DF Alg (low 5 bits); `val[1..3]` = the
/// 16-bit capability Bitmap; `val[3..6]` = reserved (zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DfElectionEc {
    /// DF election algorithm (5-bit field, values 0–31).
    pub df_alg: u8,
    /// Capability Bitmap (16 bits, RFC MSB-0 numbering: Bit 0 = `0x8000`).
    pub bitmap: u16,
}

impl DfElectionEc {
    /// Mask of the 5-bit DF Alg field within `val[0]`.
    pub const DF_ALG_MASK: u8 = 0x1F;

    /// DF Alg 0 — Default DF Election (service-carving / modulus, RFC 7432).
    pub const ALG_DEFAULT: u8 = 0;
    /// DF Alg 1 — Highest Random Weight (HRW, RFC 8584 §3).
    pub const ALG_HRW: u8 = 1;

    /// Bitmap Bit 1 (RFC 8584 §2.2): AC-DF Capability (AC-Influenced DF
    /// election). MSB-0 within the 16-bit Bitmap → `0x4000`.
    pub const CAP_AC_DF: u16 = 0x4000;

    /// True when the AC-DF (AC-Influenced DF election) capability bit is set.
    pub fn ac_df(&self) -> bool {
        self.bitmap & Self::CAP_AC_DF != 0
    }

    /// Set or clear the AC-DF capability bit. RFC 9572 §5.3.1 clears it on the
    /// re-advertised Per-Region I-PMSI so exactly one ASBR forwards downstream.
    pub fn set_ac_df(&mut self, on: bool) {
        if on {
            self.bitmap |= Self::CAP_AC_DF;
        } else {
            self.bitmap &= !Self::CAP_AC_DF;
        }
    }

    /// Builder form of [`set_ac_df`](Self::set_ac_df).
    pub fn with_ac_df(mut self, on: bool) -> Self {
        self.set_ac_df(on);
        self
    }
}

impl From<DfElectionEc> for ExtCommunityValue {
    fn from(df: DfElectionEc) -> Self {
        let mut val = [0u8; 6];
        // RSV (high 3 bits of val[0]) stays 0; only the low 5 bits carry DF Alg.
        val[0] = df.df_alg & DfElectionEc::DF_ALG_MASK;
        val[1..3].copy_from_slice(&df.bitmap.to_be_bytes());
        ExtCommunityValue {
            high_type: ExtCommunityType::Evpn as u8,
            low_type: EVPN_DF_ELECTION_SUB_TYPE,
            val,
        }
    }
}

/// Decoded MUP Extended Community (draft-ietf-bess-mup-safi §5). The `value` field
/// is the raw 6-octet payload; typed accessors per sub-type will
/// follow once the spec layout is in-tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MupExtCom {
    pub sub_type: MupExtComSubType,
    pub value: [u8; 6],
}

impl MupExtCom {
    pub fn new(sub_type: MupExtComSubType, value: [u8; 6]) -> Self {
        Self { sub_type, value }
    }
}

impl From<MupExtCom> for ExtCommunityValue {
    fn from(m: MupExtCom) -> Self {
        ExtCommunityValue {
            high_type: ExtCommunityType::Mup as u8,
            low_type: m.sub_type.into(),
            val: m.value,
        }
    }
}

/// Decoded Color extended community (RFC 9012 §4.3). `flags` is the
/// raw 16-bit field; `co_bits` is the top two bits per
/// draft-ietf-idr-bgp-ct §3.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    pub flags: u16,
    pub color: u32,
}

impl Color {
    /// CO bits per draft-ietf-idr-bgp-ct §3.2.1: 00 default, 01 any
    /// transport supporting color, 10 SR-aware transport, 11 reserved.
    pub fn co_bits(self) -> u8 {
        ((self.flags >> 14) & 0b11) as u8
    }
}

impl From<Color> for ExtCommunityValue {
    fn from(c: Color) -> Self {
        let mut val = [0u8; 6];
        val[0..2].copy_from_slice(&c.flags.to_be_bytes());
        val[2..6].copy_from_slice(&c.color.to_be_bytes());
        ExtCommunityValue {
            high_type: ExtCommunityType::TransOpaque as u8,
            low_type: ExtCommunitySubType::Color as u8,
            val,
        }
    }
}

impl fmt::Display for ExtCommunityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtCommunityType::*;
        if self.high_type == TransTwoOctetAS as u8 {
            let asn = u16::from_be_bytes([self.val[0], self.val[1]]);
            let val = u32::from_be_bytes([self.val[2], self.val[3], self.val[4], self.val[5]]);
            write!(
                f,
                "{}:{asn}:{val}",
                ExtCommunitySubType::display(self.low_type)
            )
        } else if let Some(m) = self.as_mup() {
            // MUP Extended Community (draft-ietf-bess-mup-safi §5). Until typed
            // payloads land, render the sub-type identifier plus the
            // raw 6-byte value as a colon-joined hex string.
            write!(
                f,
                "{}:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                m.sub_type, m.value[0], m.value[1], m.value[2], m.value[3], m.value[4], m.value[5]
            )
        } else if self.high_type == TransOpaque as u8 {
            // Color extcomm (RFC 9012 §4.3) has its own 2-octet flags
            // + 4-octet color layout; surface that when it's set,
            // otherwise fall back to the generic tunnel-type / opaque
            // rendering.
            if let Some(c) = self.as_color() {
                return write!(f, "color:{}:{}", c.co_bits(), c.color);
            }
            let ip = Ipv4Addr::new(self.val[0], self.val[1], self.val[2], self.val[3]);
            let val = u16::from_be_bytes([self.val[4], self.val[5]]);
            if let Ok(tunnel_type) = TunnelType::try_from(val) {
                write!(
                    f,
                    "{}:{}",
                    ExtCommunitySubType::display(self.low_type),
                    tunnel_type
                )
            } else {
                write!(
                    f,
                    "{}:{ip}:{val}",
                    ExtCommunitySubType::display(self.low_type)
                )
            }
        } else if self.is_evpn_mcast_flags() {
            // EVPN Multicast Flags EC (RFC 9251 §6 / RFC 9572 §8). Render the
            // raw capability bits as `mcast-flags:` plus `I` (IGMP) / `M`
            // (MLD) / `S` (segmentation support); an all-clear value renders
            // as a bare `mcast-flags:`.
            let flags = u16::from_be_bytes([self.val[0], self.val[1]]);
            let mut s = String::new();
            if flags & EvpnMcastFlags::IGMP_PROXY != 0 {
                s.push('I');
            }
            if flags & EvpnMcastFlags::MLD_PROXY != 0 {
                s.push('M');
            }
            if flags & EvpnMcastFlags::SEGMENTATION_SUPPORT != 0 {
                s.push('S');
            }
            write!(f, "mcast-flags:{s}")
        } else if let Some(df) = self.as_df_election() {
            // DF Election EC (RFC 8584 §2.2): render the algorithm and append
            // `+ac-df` when the AC-Influenced DF election bit is set.
            write!(f, "df-election:alg{}", df.df_alg)?;
            if df.ac_df() {
                write!(f, "+ac-df")?;
            }
            Ok(())
        } else if let Some(es) = self.as_es_import_rt() {
            // ES-Import RT (RFC 7432 §7.6): render the 6-octet ES-Import as
            // a colon-joined hex string, MAC-like.
            write!(
                f,
                "es-import:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                es[0], es[1], es[2], es[3], es[4], es[5]
            )
        } else if let Some(es) = self.as_esi_label() {
            // ESI Label EC (RFC 7432 §7.5): redundancy mode + ESI label.
            let mode = if es.single_active {
                "single-active"
            } else {
                "all-active"
            };
            write!(f, "esi-label:{mode}:{}", es.label)
        } else if let Some(a) = self.as_l2_attr() {
            // Layer-2 Attributes EC (RFC 8214 §3.1): the P/B/C control
            // flags then the L2 MTU, e.g. `l2-attr:P:mtu1500`.
            let mut s = String::new();
            if a.primary {
                s.push('P');
            }
            if a.backup {
                s.push('B');
            }
            if a.control_word {
                s.push('C');
            }
            write!(f, "l2-attr:{s}:mtu{}", a.mtu)
        } else if self.is_evi_rt() {
            // EVI-RT EC (RFC 9251 §9.5): render `evi-rt:` then the underlying
            // Route Target. The IPv6 form (0x0D) has no 8-octet RT, so fall
            // back to a hex dump of the value.
            match self.as_evi_rt() {
                Some(rt) => write!(f, "evi-rt:{rt}"),
                None => write!(
                    f,
                    "evi-rt:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    self.val[0], self.val[1], self.val[2], self.val[3], self.val[4], self.val[5]
                ),
            }
        } else {
            let ip = Ipv4Addr::new(self.val[0], self.val[1], self.val[2], self.val[3]);
            let val = u16::from_be_bytes([self.val[4], self.val[5]]);
            write!(
                f,
                "{}:{ip}:{val}",
                ExtCommunitySubType::display(self.low_type)
            )
        }
    }
}

impl AttrEmitter for ExtCommunity {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true).with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::ExtendedCom
    }

    fn len(&self) -> Option<usize> {
        None // Length is variable, let attr_emit buffer and calculate
    }

    fn emit(&self, buf: &mut BytesMut) {
        for ext_community in &self.0 {
            buf.put_u8(ext_community.high_type);
            buf.put_u8(ext_community.low_type);
            buf.put(&ext_community.val[..]);
        }
    }
}

impl fmt::Display for ExtCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .0
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{v}")
    }
}

impl fmt::Debug for ExtCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtCommunity: {}", self)
    }
}

#[derive(PartialEq)]
enum State {
    Unspec,
    Rt,
    Soo,
}

impl FromStr for ExtCommunity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ecom = ExtCommunity::default();
        let tokens = tokenizer(String::from(s)).map_err(|_| ())?;
        let mut state = State::Unspec;

        for token in tokens.into_iter() {
            match token {
                Token::Rd(rd) => {
                    let mut val: ExtCommunityValue = rd.into();
                    match state {
                        State::Unspec => {
                            return Err(());
                        }
                        State::Rt => {
                            val.low_type = 0x02;
                        }
                        State::Soo => {
                            val.low_type = 0x03;
                        }
                    }
                    ecom.0.insert(val);
                }
                Token::Rt => {
                    state = State::Rt;
                }
                Token::Soo => {
                    state = State::Soo;
                }
            }
        }
        Ok(ecom)
    }
}

impl From<RouteDistinguisher> for ExtCommunityValue {
    fn from(from: RouteDistinguisher) -> Self {
        let mut to = ExtCommunityValue {
            val: from.val,
            ..Default::default()
        };
        match from.typ {
            RouteDistinguisherType::ASN => {
                to.high_type = 0x00;
            }
            RouteDistinguisherType::IP => {
                to.high_type = 0x01;
            }
        }
        to
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        // Test new colon-prefixed format
        let ecom: ExtCommunity = ExtCommunity::from_str("rt:100:200").unwrap();
        assert_eq!(ecom.to_string(), "rt:100:200");

        let ecom: ExtCommunity = ExtCommunity::from_str("soo:1.2.3.4:200").unwrap();
        assert_eq!(ecom.to_string(), "soo:1.2.3.4:200");

        // Values render in canonical sorted order (type bytes first):
        // the ASN-form soo (high_type 0x00) sorts before the IPv4-form
        // rt (high_type 0x01), regardless of input order.
        let ecom: ExtCommunity = ExtCommunity::from_str("rt:1.2.3.4:100 soo:10:100").unwrap();
        assert_eq!(ecom.to_string(), "soo:10:100 rt:1.2.3.4:100");

        // Test backward compatibility with old space-separated format
        let ecom: ExtCommunity = ExtCommunity::from_str("rt 100:200").unwrap();
        assert_eq!(ecom.to_string(), "rt:100:200");

        let ecom: ExtCommunity = ExtCommunity::from_str("soo 1.2.3.4:200").unwrap();
        assert_eq!(ecom.to_string(), "soo:1.2.3.4:200");
    }

    #[test]
    fn color_from_constructor_round_trips_decode() {
        let c = ExtCommunityValue::from_color(0b10, 100);
        assert!(c.is_color());
        let decoded = c.as_color().expect("color decode");
        assert_eq!(decoded.color, 100);
        assert_eq!(decoded.co_bits(), 0b10);
        // Top two bits of Flags carry the CO-bits.
        assert_eq!(decoded.flags & 0xc000, 0b10 << 14);
    }

    #[test]
    fn color_wire_layout_is_type_subtype_flags_color() {
        let c = ExtCommunityValue::from_color(0, 0x0000_002a);
        // [0x03, 0x0b, flags_hi=0, flags_lo=0, color bytes...]
        assert_eq!(c.high_type, 0x03);
        assert_eq!(c.low_type, 0x0b);
        assert_eq!(c.val, [0, 0, 0, 0, 0, 0x2a]);
    }

    #[test]
    fn color_co_bits_mask_to_two_bits() {
        // CO=0b11 — explicit max value.
        let c = ExtCommunityValue::from_color(0b11, 7);
        assert_eq!(c.as_color().unwrap().co_bits(), 0b11);
        // Values above 3 mask down — guards constructor callers that
        // forget the field is only 2 bits wide.
        let c = ExtCommunityValue::from_color(0b1111_0010, 7);
        assert_eq!(c.as_color().unwrap().co_bits(), 0b10);
    }

    #[test]
    fn is_color_false_for_rt_and_soo() {
        let rt: ExtCommunity = ExtCommunity::from_str("rt:100:200").unwrap();
        let soo: ExtCommunity = ExtCommunity::from_str("soo:1.2.3.4:200").unwrap();
        let rt = rt.0.first().unwrap();
        let soo = soo.0.first().unwrap();
        assert!(!rt.is_color());
        assert!(!soo.is_color());
        assert!(rt.as_color().is_none());
        assert!(soo.as_color().is_none());
    }

    #[test]
    fn color_renders_in_display() {
        let c = ExtCommunityValue::from_color(0b01, 4242);
        assert_eq!(c.to_string(), "color:1:4242");
    }

    #[test]
    fn evpn_mcast_flags_wire_layout() {
        // Both IGMP + MLD proxy: high 0x06, sub 0x09, Flags=0x0003,
        // reserved 4 octets zero.
        let ec: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: true,
            segmentation_support: false,
        }
        .into();
        assert_eq!(ec.high_type, 0x06);
        assert_eq!(ec.low_type, 0x09);
        assert_eq!(ec.val, [0x00, 0x03, 0, 0, 0, 0]);
        let mut buf = BytesMut::new();
        ec.encode(&mut buf);
        assert_eq!(&buf[..], &[0x06, 0x09, 0x00, 0x03, 0, 0, 0, 0]);
    }

    #[test]
    fn evpn_mcast_flags_igmp_only_round_trips() {
        let ec: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: false,
            segmentation_support: false,
        }
        .into();
        assert_eq!(ec.val[0..2], [0x00, 0x01], "Flags bit 15 (IGMP) set only");
        assert!(ec.is_evpn_mcast_flags());
        let decoded = ec.as_evpn_mcast_flags().expect("decode");
        assert!(decoded.igmp_proxy);
        assert!(!decoded.mld_proxy);
    }

    #[test]
    fn evpn_mcast_flags_both_zero_is_ignored() {
        // RFC 9251 §6: an EVPN Multicast Flags EC with both bits clear
        // is malformed; `as_evpn_mcast_flags` returns None so callers
        // ignore it (but `is_` still recognises the type for Display).
        let ec = ExtCommunityValue {
            high_type: 0x06,
            low_type: 0x09,
            val: [0; 6],
        };
        assert!(ec.is_evpn_mcast_flags());
        assert!(ec.as_evpn_mcast_flags().is_none());
        assert_eq!(ec.to_string(), "mcast-flags:");
    }

    #[test]
    fn evpn_mcast_flags_renders_in_display() {
        let both: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: true,
            segmentation_support: false,
        }
        .into();
        assert_eq!(both.to_string(), "mcast-flags:IM");
        let mld: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: false,
            mld_proxy: true,
            segmentation_support: false,
        }
        .into();
        assert_eq!(mld.to_string(), "mcast-flags:M");
    }

    #[test]
    fn evpn_l2_attr_roundtrip() {
        // RFC 8214 §3.1: single-homed primary, MTU 1500. Wire layout: flags
        // in val[0..2] (B=0x0001, P=0x0002, C=0x0004), MTU in val[2..4].
        let ec = ExtCommunityValue::l2_attr(true, false, false, 1500);
        assert_eq!(ec.high_type, 0x06);
        assert_eq!(ec.low_type, 0x04);
        assert_eq!(ec.val, [0x00, 0x02, 0x05, 0xdc, 0x00, 0x00]);
        let a = ec.as_l2_attr().expect("decodes");
        assert!(a.primary && !a.backup && !a.control_word);
        assert_eq!(a.mtu, 1500);
        assert_eq!(ec.to_string(), "l2-attr:P:mtu1500");

        let all: ExtCommunityValue = L2AttrEc {
            primary: true,
            backup: true,
            control_word: true,
            mtu: 0,
        }
        .into();
        assert_eq!(all.val[0..2], [0x00, 0x07]);
        assert_eq!(all.to_string(), "l2-attr:PBC:mtu0");
    }

    #[test]
    fn evpn_l2_attr_false_for_esi_label() {
        // Same EVPN high-type, different sub-type — must not cross-decode.
        let esi = ExtCommunityValue::esi_label(false, 0);
        assert!(esi.as_l2_attr().is_none());
        let l2 = ExtCommunityValue::l2_attr(true, false, false, 0);
        assert!(l2.as_esi_label().is_none());
    }

    #[test]
    fn evpn_mcast_flags_false_for_rt() {
        let rt: ExtCommunity = ExtCommunity::from_str("rt:100:200").unwrap();
        let rt = rt.0.first().unwrap();
        assert!(!rt.is_evpn_mcast_flags());
        assert!(rt.as_evpn_mcast_flags().is_none());
    }

    #[test]
    fn evpn_mcast_flags_round_trips_through_parse() {
        let original: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: true,
            segmentation_support: false,
        }
        .into();
        let mut buf = BytesMut::new();
        original.encode(&mut buf);
        let (_, parsed) = ExtCommunityValue::parse_be(&buf).expect("parse 8-octet EC");
        assert_eq!(parsed, original);
        assert_eq!(parsed.as_evpn_mcast_flags(), original.as_evpn_mcast_flags());
    }

    #[test]
    fn evpn_mcast_flags_segmentation_support() {
        // RFC 9572 §8: segmentation support is bit 8 of the Flags field
        // (0x0080). A segmentation-only EC must survive decode (it is not
        // "all bits clear") and renders with `S`.
        let ec: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: false,
            mld_proxy: false,
            segmentation_support: true,
        }
        .into();
        assert_eq!(ec.val[0..2], [0x00, 0x80], "Flags bit 8 (segmentation)");
        assert_eq!(ec.to_string(), "mcast-flags:S");
        let decoded = ec
            .as_evpn_mcast_flags()
            .expect("segmentation-only EC is valid");
        assert!(decoded.segmentation_support);
        assert!(!decoded.igmp_proxy && !decoded.mld_proxy);

        // Combined with IGMP: bit 15 (0x0001) + bit 8 (0x0080) = 0x0081.
        let combo: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: false,
            segmentation_support: true,
        }
        .into();
        assert_eq!(combo.val[0..2], [0x00, 0x81]);
        assert_eq!(combo.to_string(), "mcast-flags:IS");
        let mut buf = BytesMut::new();
        combo.encode(&mut buf);
        let (_, parsed) = ExtCommunityValue::parse_be(&buf).expect("parse 8-octet EC");
        assert_eq!(parsed.as_evpn_mcast_flags(), combo.as_evpn_mcast_flags());
    }

    #[test]
    fn df_election_wire_layout() {
        // RFC 8584 §2.2: high 0x06, sub 0x06; val[0] low-5-bits = DF Alg
        // (HRW = 1); Bitmap (val[1..3]) with AC-DF = Bit 1 = 0x4000; the
        // RSV bits and trailing 3 reserved octets are zero.
        let ec: ExtCommunityValue = DfElectionEc {
            df_alg: DfElectionEc::ALG_HRW,
            bitmap: DfElectionEc::CAP_AC_DF,
        }
        .into();
        assert_eq!(ec.high_type, 0x06);
        assert_eq!(ec.low_type, 0x06);
        assert_eq!(ec.val, [0x01, 0x40, 0x00, 0, 0, 0]);
        let mut buf = BytesMut::new();
        ec.encode(&mut buf);
        assert_eq!(&buf[..], &[0x06, 0x06, 0x01, 0x40, 0x00, 0, 0, 0]);
    }

    #[test]
    fn df_election_df_alg_is_low_five_bits() {
        // Only the low 5 bits of val[0] carry DF Alg; the high 3 (RSV) stay 0.
        // A 5-bit value of 31 (max) must round-trip without bleeding into RSV.
        let ec: ExtCommunityValue = DfElectionEc {
            df_alg: 31,
            bitmap: 0,
        }
        .into();
        assert_eq!(ec.val[0], 0x1F, "DF Alg in low 5 bits, RSV clear");
        let decoded = ec.as_df_election().expect("decode");
        assert_eq!(decoded.df_alg, 31);
        assert!(!decoded.ac_df());

        // A caller passing a too-wide value is masked to 5 bits on emit.
        let wide: ExtCommunityValue = DfElectionEc {
            df_alg: 0xFF,
            bitmap: 0,
        }
        .into();
        assert_eq!(wide.val[0], 0x1F);
    }

    #[test]
    fn df_election_ac_df_bit_toggles() {
        let mut df = DfElectionEc {
            df_alg: DfElectionEc::ALG_DEFAULT,
            bitmap: 0,
        };
        assert!(!df.ac_df());
        df.set_ac_df(true);
        assert_eq!(df.bitmap, 0x4000, "AC-DF is Bitmap Bit 1 (MSB-0)");
        assert!(df.ac_df());
        // RFC 9572 §5.3.1: clearing AC-DF leaves other capability bits intact.
        df.bitmap |= 0x8000; // Bit 0 (unassigned) — stand-in for "other bits".
        df.set_ac_df(false);
        assert!(!df.ac_df());
        assert_eq!(df.bitmap, 0x8000, "only AC-DF cleared");
    }

    #[test]
    fn df_election_round_trips_through_parse() {
        let original: ExtCommunityValue = DfElectionEc {
            df_alg: DfElectionEc::ALG_HRW,
            bitmap: DfElectionEc::CAP_AC_DF,
        }
        .into();
        let mut buf = BytesMut::new();
        original.encode(&mut buf);
        let (_, parsed) = ExtCommunityValue::parse_be(&buf).expect("parse 8-octet EC");
        assert_eq!(parsed, original);
        assert_eq!(parsed.as_df_election(), original.as_df_election());
        let decoded = parsed.as_df_election().expect("decode");
        assert_eq!(decoded.df_alg, DfElectionEc::ALG_HRW);
        assert!(decoded.ac_df());
    }

    #[test]
    fn df_election_renders_in_display() {
        let hrw_ac: ExtCommunityValue = DfElectionEc {
            df_alg: DfElectionEc::ALG_HRW,
            bitmap: DfElectionEc::CAP_AC_DF,
        }
        .into();
        assert_eq!(hrw_ac.to_string(), "df-election:alg1+ac-df");
        let default_only: ExtCommunityValue = DfElectionEc {
            df_alg: DfElectionEc::ALG_DEFAULT,
            bitmap: 0,
        }
        .into();
        assert_eq!(default_only.to_string(), "df-election:alg0");
    }

    #[test]
    fn df_election_false_for_rt_and_mcast_flags() {
        let rt: ExtCommunity = ExtCommunity::from_str("rt:100:200").unwrap();
        assert!(!rt.0.first().unwrap().is_evpn_df_election());
        assert!(rt.0.first().unwrap().as_df_election().is_none());
        // Same EVPN high-type but the Multicast Flags sub-type (0x09) must
        // not be mistaken for DF Election (0x06).
        let mcast: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: false,
            segmentation_support: false,
        }
        .into();
        assert!(!mcast.is_evpn_df_election());
        assert!(mcast.as_df_election().is_none());
    }

    #[test]
    fn color_round_trips_through_attribute_emit_parse() {
        // Build an ExtCommunity attribute with one Color value,
        // round-trip the wire bytes through emit, parse the raw 8
        // octets back, and assert decode matches.
        let original = ExtCommunityValue::from_color(0b10, 128);
        let ecom = ExtCommunity::from([original.clone()]);
        let mut buf = BytesMut::new();
        ecom.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        assert_eq!(bytes.len(), 8);
        // Re-build the ExtCommunityValue from raw bytes to confirm
        // wire layout matches our constructor.
        let mut val = [0u8; 6];
        val.copy_from_slice(&bytes[2..8]);
        let parsed = ExtCommunityValue {
            high_type: bytes[0],
            low_type: bytes[1],
            val,
        };
        assert_eq!(parsed, original);
        let c = parsed.as_color().unwrap();
        assert_eq!(c.color, 128);
        assert_eq!(c.co_bits(), 0b10);
    }

    #[test]
    fn mup_subtype_round_trip_known_and_unknown() {
        for raw in [0u8, 1, 2, 3, 4, 99, 255] {
            let st = MupExtComSubType::from(raw);
            assert_eq!(u8::from(st), raw);
        }
        assert_eq!(MupExtComSubType::from(0), MupExtComSubType::Sub00);
        assert_eq!(MupExtComSubType::from(3), MupExtComSubType::Sub03);
    }

    #[test]
    fn mup_extcom_recognized_via_high_type_0x0c() {
        let ev = ExtCommunityValue {
            high_type: 0x0c,
            low_type: 0x02,
            val: [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02],
        };
        assert!(ev.is_mup());
        let m = ev.as_mup().expect("must decode");
        assert_eq!(m.sub_type, MupExtComSubType::Sub02);
        assert_eq!(m.value, [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);
    }

    #[test]
    fn non_mup_extcom_returns_none_from_as_mup() {
        let color = ExtCommunityValue::from_color(0, 5);
        assert!(!color.is_mup());
        assert!(color.as_mup().is_none());
    }

    #[test]
    fn mup_extcom_round_trip_via_from() {
        let original = MupExtCom::new(MupExtComSubType::Sub01, [1, 2, 3, 4, 5, 6]);
        let ev: ExtCommunityValue = original.into();
        assert_eq!(ev.high_type, 0x0c);
        assert_eq!(ev.low_type, 0x01);
        let decoded = ev.as_mup().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn mup_extcom_unknown_subtype_preserved() {
        let original = MupExtCom::new(MupExtComSubType::Unknown(0x7F), [0; 6]);
        let ev: ExtCommunityValue = original.into();
        assert_eq!(ev.low_type, 0x7F);
        assert_eq!(
            ev.as_mup().unwrap().sub_type,
            MupExtComSubType::Unknown(0x7F)
        );
    }

    #[test]
    fn mup_extcom_display_renders_subtype_and_hex_value() {
        let ev: ExtCommunityValue = MupExtCom::new(
            MupExtComSubType::Sub00,
            [0xab, 0xcd, 0x00, 0x11, 0x22, 0x33],
        )
        .into();
        assert_eq!(format!("{ev}"), "mup-sub-0x00:abcd00112233");
    }

    #[test]
    fn mup_extcom_wire_round_trip_through_attribute_emit() {
        // Build an ExtCommunity attribute with one MUP value, round-
        // trip the wire bytes through emit, then reconstruct the value.
        let original = ExtCommunityValue {
            high_type: 0x0c,
            low_type: 0x03,
            val: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
        };
        let ecom = ExtCommunity::from([original.clone()]);
        let mut buf = BytesMut::new();
        ecom.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        assert_eq!(bytes.len(), 8);
        let mut val = [0u8; 6];
        val.copy_from_slice(&bytes[2..8]);
        let parsed = ExtCommunityValue {
            high_type: bytes[0],
            low_type: bytes[1],
            val,
        };
        assert_eq!(parsed, original);
        let m = parsed.as_mup().unwrap();
        assert_eq!(m.sub_type, MupExtComSubType::Sub03);
    }

    #[test]
    fn es_import_rt_derives_from_esi() {
        // ESI: Type byte (0x00) then the 9-octet value; the ES-Import RT is
        // the high-order 6 octets of that value (ESI octets 1..7).
        let esi = [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03];
        let ec = ExtCommunityValue::es_import_rt(&esi);
        assert_eq!(ec.high_type, ExtCommunityType::Evpn as u8);
        assert_eq!(ec.low_type, 0x02);
        assert_eq!(ec.val, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert!(ec.is_es_import_rt());
        assert_eq!(
            ec.as_es_import_rt(),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(ec.to_string(), "es-import:aa:bb:cc:dd:ee:ff");
        // A standard 2-octet-AS RT is not an ES-Import RT despite sharing
        // the 0x02 sub-type — the high-type differs.
        let rt = ExtCommunityValue {
            high_type: 0x00,
            low_type: 0x02,
            val: [0xfd, 0xe9, 0, 0, 0, 100],
        };
        assert!(!rt.is_es_import_rt());
    }

    #[test]
    fn evi_rt_round_trips_two_octet_as_rt() {
        // EVI RT value for AS 65001, VNI 100 (Local Admin) — the same 6-octet
        // value evpn_route_target builds.
        let rt = ExtCommunityValue {
            high_type: 0x00, // Two-Octet AS-specific
            low_type: 0x02,  // Route Target
            val: [0xfd, 0xe9, 0, 0, 0, 100],
        };
        let evi = ExtCommunityValue::evi_rt_from_rt(&rt).expect("2-octet-AS RT → EVI-RT Type 0");
        assert_eq!(evi.high_type, ExtCommunityType::Evpn as u8);
        assert_eq!(evi.low_type, 0x0A);
        assert_eq!(evi.val, rt.val);
        assert!(evi.is_evi_rt());
        // Reconstructing the RT yields the original.
        assert_eq!(evi.as_evi_rt(), Some(rt));
        assert_eq!(evi.to_string(), "evi-rt:rt:65001:100");
    }

    #[test]
    fn evi_rt_sub_type_per_rt_format() {
        // IPv4-address RT → Type 1 (0x0B); 4-octet-AS RT → Type 2 (0x0C).
        let v4 = ExtCommunityValue {
            high_type: 0x01,
            low_type: 0x02,
            val: [192, 0, 2, 1, 0, 7],
        };
        assert_eq!(
            ExtCommunityValue::evi_rt_from_rt(&v4).unwrap().low_type,
            0x0B
        );
        let as4 = ExtCommunityValue {
            high_type: 0x02,
            low_type: 0x02,
            val: [0, 1, 0, 0, 0, 9],
        };
        assert_eq!(
            ExtCommunityValue::evi_rt_from_rt(&as4).unwrap().low_type,
            0x0C
        );
        // A non-RT EC (Route Origin sub-type 0x03) yields no EVI-RT.
        let soo = ExtCommunityValue {
            high_type: 0x00,
            low_type: 0x03,
            val: [0; 6],
        };
        assert!(ExtCommunityValue::evi_rt_from_rt(&soo).is_none());
    }

    #[test]
    fn esi_label_ec_round_trips() {
        // All-active, label 100.
        let ec = ExtCommunityValue::esi_label(false, 100);
        assert_eq!(ec.high_type, ExtCommunityType::Evpn as u8);
        assert_eq!(ec.low_type, 0x01);
        assert_eq!(ec.val, [0x00, 0, 0, 0, 0, 100], "flags 0, label in low 24");
        assert!(ec.is_esi_label());
        let dec = ec.as_esi_label().expect("decode");
        assert!(!dec.single_active);
        assert_eq!(dec.label, 100);
        assert_eq!(ec.to_string(), "esi-label:all-active:100");
        // Single-active, label 0x12345 (20 bits).
        let sa = ExtCommunityValue::esi_label(true, 0x12345);
        assert_eq!(sa.val, [0x01, 0, 0, 0x01, 0x23, 0x45]);
        let dec = sa.as_esi_label().expect("decode");
        assert!(dec.single_active);
        assert_eq!(dec.label, 0x12345);
        assert_eq!(sa.to_string(), "esi-label:single-active:74565");
        // From-impl mirrors the constructor.
        let from: ExtCommunityValue = EsiLabelEc {
            single_active: true,
            label: 7,
        }
        .into();
        assert_eq!(from, ExtCommunityValue::esi_label(true, 7));
        // A standard RT is not an ESI Label EC.
        let rt = ExtCommunityValue {
            high_type: 0x00,
            low_type: 0x02,
            val: [0; 6],
        };
        assert!(!rt.is_esi_label());
    }
}
