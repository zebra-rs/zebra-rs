use std::fmt::{Display, Formatter, Result};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// SRv6 Endpoint Behaviors — IANA "SRv6 Endpoint Behaviors" registry.
//   - RFC 8986 base set + USD flavor variants
//   - RFC 9800 NEXT-C-SID (micro-SID / uSID) variants
#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum Behavior {
    End,
    EndPSP,
    EndUSP,
    EndPSPUSP,
    EndX,
    EndXPSP,
    EndXUSP,
    EndXPSPUSP,
    EndT,
    EndTPSP,
    EndTUSP,
    EndTPSPUSP,
    EndB6Encaps,
    EndBM,
    EndDX6,
    EndDX4,
    EndDT6,
    EndDT4,
    EndDT46,
    EndDX2,
    EndDX2V,
    EndDT2U,
    EndDT2M,
    EndB6EncapsRed,
    EndUSD,
    EndPSPUSD,
    EndUSPUSD,
    EndPSPUSPUSD,
    EndXUSD,
    EndXPSPUSD,
    EndXUSPUSD,
    EndXPSPUSPUSD,
    EndTUSD,
    EndTPSPUSD,
    EndTUSPUSD,
    EndTPSPUSPUSD,
    // RFC 9800 — NEXT-C-SID (micro-SID) variants.
    EndCSID,
    EndCSIDPSP,
    EndCSIDUSP,
    EndCSIDPSPUSP,
    EndCSIDUSD,
    EndCSIDPSPUSD,
    EndCSIDUSPUSD,
    EndCSIDPSPUSPUSD,
    EndXCSID,
    EndXCSIDPSP,
    EndXCSIDUSP,
    EndXCSIDPSPUSP,
    EndXCSIDUSD,
    EndXCSIDPSPUSD,
    EndXCSIDUSPUSD,
    EndXCSIDPSPUSPUSD,
    EndTCSID,
    EndTCSIDPSP,
    EndTCSIDUSP,
    EndTCSIDPSPUSP,
    EndTCSIDUSD,
    EndTCSIDPSPUSD,
    EndTCSIDUSPUSD,
    EndTCSIDPSPUSPUSD,
    EndB6EncapsCSID,
    EndB6EncapsRedCSID,
    EndBMCSID,
    EndLBSCSID,
    EndXLBSCSID,
    // draft-ietf-rtgwg-srv6-egress-protection — End.M (Mirroring
    // Context segment). Egress-protection variant of End.DT6: the
    // protector decapsulates and submits the inner packet to the
    // mirror-context FIB table of the protected egress.
    EndM,
    Resv(u16),
}

impl Behavior {
    /// RFC 9800 NEXT-C-SID flavor of End (uN), any PSP/USP/USD
    /// combination. A SID advertised with one of these consumes a
    /// locator-node-sized identifier from a uSID carrier.
    pub fn is_end_next_csid(&self) -> bool {
        use Behavior::*;
        matches!(
            self,
            EndCSID
                | EndCSIDPSP
                | EndCSIDUSP
                | EndCSIDPSPUSP
                | EndCSIDUSD
                | EndCSIDPSPUSD
                | EndCSIDUSPUSD
                | EndCSIDPSPUSPUSD
        )
    }

    /// RFC 9800 NEXT-C-SID flavor of End.X (uA), any PSP/USP/USD
    /// combination. A SID advertised with one of these consumes a
    /// function-sized identifier from a uSID carrier.
    pub fn is_endx_next_csid(&self) -> bool {
        use Behavior::*;
        matches!(
            self,
            EndXCSID
                | EndXCSIDPSP
                | EndXCSIDUSP
                | EndXCSIDPSPUSP
                | EndXCSIDUSD
                | EndXCSIDPSPUSD
                | EndXCSIDUSPUSD
                | EndXCSIDPSPUSPUSD
        )
    }

    /// Fold RFC 8986 §4.16 flavors into a base endpoint behavior,
    /// returning the flavored IANA codepoint. Supported bases: `End`,
    /// `EndX`, `EndCSID` (uN) and `EndXCSID` (uA); any other base — and
    /// an empty flavor set — returns `self` unchanged.
    pub fn with_flavors(self, psp: bool, usp: bool, usd: bool) -> Behavior {
        use Behavior::*;
        match (self, psp, usp, usd) {
            (_, false, false, false) => self,
            (End, true, false, false) => EndPSP,
            (End, false, true, false) => EndUSP,
            (End, true, true, false) => EndPSPUSP,
            (End, false, false, true) => EndUSD,
            (End, true, false, true) => EndPSPUSD,
            (End, false, true, true) => EndUSPUSD,
            (End, true, true, true) => EndPSPUSPUSD,
            (EndX, true, false, false) => EndXPSP,
            (EndX, false, true, false) => EndXUSP,
            (EndX, true, true, false) => EndXPSPUSP,
            (EndX, false, false, true) => EndXUSD,
            (EndX, true, false, true) => EndXPSPUSD,
            (EndX, false, true, true) => EndXUSPUSD,
            (EndX, true, true, true) => EndXPSPUSPUSD,
            (EndCSID, true, false, false) => EndCSIDPSP,
            (EndCSID, false, true, false) => EndCSIDUSP,
            (EndCSID, true, true, false) => EndCSIDPSPUSP,
            (EndCSID, false, false, true) => EndCSIDUSD,
            (EndCSID, true, false, true) => EndCSIDPSPUSD,
            (EndCSID, false, true, true) => EndCSIDUSPUSD,
            (EndCSID, true, true, true) => EndCSIDPSPUSPUSD,
            (EndXCSID, true, false, false) => EndXCSIDPSP,
            (EndXCSID, false, true, false) => EndXCSIDUSP,
            (EndXCSID, true, true, false) => EndXCSIDPSPUSP,
            (EndXCSID, false, false, true) => EndXCSIDUSD,
            (EndXCSID, true, false, true) => EndXCSIDPSPUSD,
            (EndXCSID, false, true, true) => EndXCSIDUSPUSD,
            (EndXCSID, true, true, true) => EndXCSIDPSPUSPUSD,
            _ => self,
        }
    }
}

impl From<Behavior> for u16 {
    fn from(typ: Behavior) -> Self {
        use Behavior::*;
        match typ {
            End => 1,
            EndPSP => 2,
            EndUSP => 3,
            EndPSPUSP => 4,
            EndX => 5,
            EndXPSP => 6,
            EndXUSP => 7,
            EndXPSPUSP => 8,
            EndT => 9,
            EndTPSP => 10,
            EndTUSP => 11,
            EndTPSPUSP => 12,
            EndB6Encaps => 14,
            EndBM => 15,
            EndDX6 => 16,
            EndDX4 => 17,
            EndDT6 => 18,
            EndDT4 => 19,
            EndDT46 => 20,
            EndDX2 => 21,
            EndDX2V => 22,
            EndDT2U => 23,
            EndDT2M => 24,
            EndB6EncapsRed => 27,
            EndUSD => 28,
            EndPSPUSD => 29,
            EndUSPUSD => 30,
            EndPSPUSPUSD => 31,
            EndXUSD => 32,
            EndXPSPUSD => 33,
            EndXUSPUSD => 34,
            EndXPSPUSPUSD => 35,
            EndTUSD => 36,
            EndTPSPUSD => 37,
            EndTUSPUSD => 38,
            EndTPSPUSPUSD => 39,
            EndCSID => 43,
            EndCSIDPSP => 44,
            EndCSIDUSP => 45,
            EndCSIDPSPUSP => 46,
            EndCSIDUSD => 47,
            EndCSIDPSPUSD => 48,
            EndCSIDUSPUSD => 49,
            EndCSIDPSPUSPUSD => 50,
            EndXCSID => 52,
            EndXCSIDPSP => 53,
            EndXCSIDUSP => 54,
            EndXCSIDPSPUSP => 55,
            EndXCSIDUSD => 56,
            EndXCSIDPSPUSD => 57,
            EndXCSIDUSPUSD => 58,
            EndXCSIDPSPUSPUSD => 59,
            EndTCSID => 85,
            EndTCSIDPSP => 86,
            EndTCSIDUSP => 87,
            EndTCSIDPSPUSP => 88,
            EndTCSIDUSD => 89,
            EndTCSIDPSPUSD => 90,
            EndTCSIDUSPUSD => 91,
            EndTCSIDPSPUSPUSD => 92,
            EndB6EncapsCSID => 93,
            EndB6EncapsRedCSID => 94,
            EndBMCSID => 95,
            EndLBSCSID => 96,
            EndXLBSCSID => 97,
            EndM => 74,
            Resv(v) => v,
        }
    }
}

impl From<u16> for Behavior {
    fn from(typ: u16) -> Self {
        use Behavior::*;
        match typ {
            1 => End,
            2 => EndPSP,
            3 => EndUSP,
            4 => EndPSPUSP,
            5 => EndX,
            6 => EndXPSP,
            7 => EndXUSP,
            8 => EndXPSPUSP,
            9 => EndT,
            10 => EndTPSP,
            11 => EndTUSP,
            12 => EndTPSPUSP,
            14 => EndB6Encaps,
            15 => EndBM,
            16 => EndDX6,
            17 => EndDX4,
            18 => EndDT6,
            19 => EndDT4,
            20 => EndDT46,
            21 => EndDX2,
            22 => EndDX2V,
            23 => EndDT2U,
            24 => EndDT2M,
            27 => EndB6EncapsRed,
            28 => EndUSD,
            29 => EndPSPUSD,
            30 => EndUSPUSD,
            31 => EndPSPUSPUSD,
            32 => EndXUSD,
            33 => EndXPSPUSD,
            34 => EndXUSPUSD,
            35 => EndXPSPUSPUSD,
            36 => EndTUSD,
            37 => EndTPSPUSD,
            38 => EndTUSPUSD,
            39 => EndTPSPUSPUSD,
            43 => EndCSID,
            44 => EndCSIDPSP,
            45 => EndCSIDUSP,
            46 => EndCSIDPSPUSP,
            47 => EndCSIDUSD,
            48 => EndCSIDPSPUSD,
            49 => EndCSIDUSPUSD,
            50 => EndCSIDPSPUSPUSD,
            52 => EndXCSID,
            53 => EndXCSIDPSP,
            54 => EndXCSIDUSP,
            55 => EndXCSIDPSPUSP,
            56 => EndXCSIDUSD,
            57 => EndXCSIDPSPUSD,
            58 => EndXCSIDUSPUSD,
            59 => EndXCSIDPSPUSPUSD,
            74 => EndM,
            85 => EndTCSID,
            86 => EndTCSIDPSP,
            87 => EndTCSIDUSP,
            88 => EndTCSIDPSPUSP,
            89 => EndTCSIDUSD,
            90 => EndTCSIDPSPUSD,
            91 => EndTCSIDUSPUSD,
            92 => EndTCSIDPSPUSPUSD,
            93 => EndB6EncapsCSID,
            94 => EndB6EncapsRedCSID,
            95 => EndBMCSID,
            96 => EndLBSCSID,
            97 => EndXLBSCSID,
            v => Resv(v),
        }
    }
}

impl Display for Behavior {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use Behavior::*;
        match self {
            End => write!(f, "End"),
            EndPSP => write!(f, "End (PSP)"),
            EndUSP => write!(f, "End (USP)"),
            EndPSPUSP => write!(f, "End (PSP, USP)"),
            EndX => write!(f, "End.X"),
            EndXPSP => write!(f, "End.X (PSP)"),
            EndXUSP => write!(f, "End.X (USP)"),
            EndXPSPUSP => write!(f, "End.X (PSP, USP)"),
            EndT => write!(f, "End.T"),
            EndTPSP => write!(f, "End.T (PSP)"),
            EndTUSP => write!(f, "End.T (USP)"),
            EndTPSPUSP => write!(f, "End.T (PSP, USP)"),
            EndB6Encaps => write!(f, "End.B6.Encaps"),
            EndBM => write!(f, "End.BM"),
            EndDX6 => write!(f, "End.DX6"),
            EndDX4 => write!(f, "End.DX4"),
            EndDT6 => write!(f, "End.DT6"),
            EndDT4 => write!(f, "End.DT4"),
            EndDT46 => write!(f, "End.DT46"),
            EndDX2 => write!(f, "End.DX2"),
            EndDX2V => write!(f, "End.DX2V"),
            EndDT2U => write!(f, "End.DT2U"),
            EndDT2M => write!(f, "End.DT2M"),
            EndB6EncapsRed => write!(f, "End.B6.Encaps.Red"),
            EndUSD => write!(f, "End (USD)"),
            EndPSPUSD => write!(f, "End (PSP, USD)"),
            EndUSPUSD => write!(f, "End (USP, USD)"),
            EndPSPUSPUSD => write!(f, "End (PSP, USP, USD)"),
            EndXUSD => write!(f, "End.X (USD)"),
            EndXPSPUSD => write!(f, "End.X (PSP, USD)"),
            EndXUSPUSD => write!(f, "End.X (USP, USD)"),
            EndXPSPUSPUSD => write!(f, "End.X (PSP, USP, USD)"),
            EndTUSD => write!(f, "End.T (USD)"),
            EndTPSPUSD => write!(f, "End.T (PSP, USD)"),
            EndTUSPUSD => write!(f, "End.T (USP, USD)"),
            EndTPSPUSPUSD => write!(f, "End.T (PSP, USP, USD)"),
            EndCSID => write!(f, "uN"),
            EndCSIDPSP => write!(f, "uN (PSP)"),
            EndCSIDUSP => write!(f, "uN (USP)"),
            EndCSIDPSPUSP => write!(f, "uN (PSP, USP)"),
            EndCSIDUSD => write!(f, "uN (USD)"),
            EndCSIDPSPUSD => write!(f, "uN (PSP, USD)"),
            EndCSIDUSPUSD => write!(f, "uN (USP, USD)"),
            EndCSIDPSPUSPUSD => write!(f, "uN (PSP, USP, USD)"),
            EndXCSID => write!(f, "uA"),
            EndXCSIDPSP => write!(f, "uA (PSP)"),
            EndXCSIDUSP => write!(f, "uA (USP)"),
            EndXCSIDPSPUSP => write!(f, "uA (PSP, USP)"),
            EndXCSIDUSD => write!(f, "uA (USD)"),
            EndXCSIDPSPUSD => write!(f, "uA (PSP, USD)"),
            EndXCSIDUSPUSD => write!(f, "uA (USP, USD)"),
            EndXCSIDPSPUSPUSD => write!(f, "uA (PSP, USP, USD)"),
            EndTCSID => write!(f, "uT"),
            EndTCSIDPSP => write!(f, "uT (PSP)"),
            EndTCSIDUSP => write!(f, "uT (USP)"),
            EndTCSIDPSPUSP => write!(f, "uT (PSP, USP)"),
            EndTCSIDUSD => write!(f, "uT (USD)"),
            EndTCSIDPSPUSD => write!(f, "uT (PSP, USD)"),
            EndTCSIDUSPUSD => write!(f, "uT (USP, USD)"),
            EndTCSIDPSPUSPUSD => write!(f, "uT (PSP, USP, USD)"),
            EndB6EncapsCSID => write!(f, "uB6.Encaps"),
            EndB6EncapsRedCSID => write!(f, "uB6.Encaps.Red"),
            EndBMCSID => write!(f, "uBM"),
            EndLBSCSID => write!(f, "uLBS"),
            EndXLBSCSID => write!(f, "uXLBS"),
            EndM => write!(f, "End.M"),
            Resv(v) => write!(f, "Resv({})", v),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum EncapType {
    HEncap,
    HEncapRed,
    HEncapL2,
    HEncapL2Red,
    /// SRH insertion (H.Insert, kernel `seg6 mode inline`): the segment
    /// list is inserted into the existing IPv6 packet with the original
    /// destination appended as the final segment, instead of pushing an
    /// outer IPv6 header. Unlike H.Encap*, the segment list needs no
    /// decapsulating terminator — after the last listed segment the
    /// packet continues to its original destination by plain IPv6
    /// forwarding. TI-LFA repair paths use this: their segments are
    /// transit End / End.X SIDs, which on Linux drop encapsulated
    /// traffic at SL=0 (no USD flavor support).
    HInsert,
}

impl EncapType {
    fn as_str(&self) -> &'static str {
        match self {
            EncapType::HEncap => "H.Encap",
            EncapType::HEncapRed => "H.Encap.Red",
            EncapType::HEncapL2 => "H.Encap.L2",
            EncapType::HEncapL2Red => "H.Encap.L2.Red",
            EncapType::HInsert => "H.Insert",
        }
    }
}

impl Display for EncapType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid SRv6 encap type: {0:?}")]
pub struct ParseEncapTypeError(pub String);

impl FromStr for EncapType {
    type Err = ParseEncapTypeError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "H.Encap" => Ok(EncapType::HEncap),
            "H.Encap.Red" => Ok(EncapType::HEncapRed),
            "H.Encap.L2" => Ok(EncapType::HEncapL2),
            "H.Encap.L2.Red" => Ok(EncapType::HEncapL2Red),
            "H.Insert" => Ok(EncapType::HInsert),
            other => Err(ParseEncapTypeError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the flavored endpoint-behavior codepoints to the IANA "SRv6
    /// Endpoint Behaviors" registry (RFC 8986 §10.2 + RFC 9800). The
    /// classic USD block was once off by one (shifted onto
    /// End.B6.Encaps.Red), which a conformant receiver would misread —
    /// this test keeps the registry values load-bearing.
    #[test]
    fn behavior_codepoints_match_iana() {
        use Behavior::*;
        let table: [(Behavior, u16); 24] = [
            (End, 1),
            (EndPSP, 2),
            (EndUSP, 3),
            (EndPSPUSP, 4),
            (EndX, 5),
            (EndXPSP, 6),
            (EndB6EncapsRed, 27),
            (EndUSD, 28),
            (EndPSPUSD, 29),
            (EndUSPUSD, 30),
            (EndPSPUSPUSD, 31),
            (EndXUSD, 32),
            (EndXPSPUSPUSD, 35),
            (EndTUSD, 36),
            (EndTPSPUSPUSD, 39),
            (EndCSID, 43),
            (EndCSIDPSP, 44),
            (EndCSIDUSP, 45),
            (EndCSIDUSD, 47),
            (EndCSIDPSPUSPUSD, 50),
            (EndXCSID, 52),
            (EndXCSIDPSP, 53),
            (EndXCSIDPSPUSPUSD, 59),
            (EndM, 74),
        ];
        for (behavior, code) in table {
            assert_eq!(u16::from(behavior), code, "{behavior:?} -> {code}");
            assert_eq!(Behavior::from(code), behavior, "{code} -> {behavior:?}");
        }
    }

    /// Every (base × flavor-set) fold, including that flavored results
    /// keep their NEXT-C-SID classification and non-foldable bases pass
    /// through unchanged.
    #[test]
    fn with_flavors_folds_every_combination() {
        use Behavior::*;
        for base in [End, EndX, EndCSID, EndXCSID] {
            let mut seen = std::collections::BTreeSet::new();
            for bits in 0u8..8 {
                let (psp, usp, usd) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
                let folded = base.with_flavors(psp, usp, usd);
                assert!(seen.insert(u16::from(folded)), "collision at {bits:03b}");
                if bits == 0 {
                    assert_eq!(folded, base);
                }
                assert_eq!(folded.is_end_next_csid(), base.is_end_next_csid());
                assert_eq!(folded.is_endx_next_csid(), base.is_endx_next_csid());
            }
        }
        assert_eq!(EndDT46.with_flavors(true, true, true), EndDT46);
        assert_eq!(EndCSID.with_flavors(true, false, false), EndCSIDPSP);
        assert_eq!(End.with_flavors(true, false, true), EndPSPUSD);
    }

    const ALL: [EncapType; 4] = [
        EncapType::HEncap,
        EncapType::HEncapRed,
        EncapType::HEncapL2,
        EncapType::HEncapL2Red,
    ];

    #[test]
    fn parses_canonical_strings() {
        assert_eq!("H.Encap".parse::<EncapType>().unwrap(), EncapType::HEncap);
        assert_eq!(
            "H.Encap.Red".parse::<EncapType>().unwrap(),
            EncapType::HEncapRed
        );
        assert_eq!(
            "H.Encap.L2".parse::<EncapType>().unwrap(),
            EncapType::HEncapL2
        );
        assert_eq!(
            "H.Encap.L2.Red".parse::<EncapType>().unwrap(),
            EncapType::HEncapL2Red
        );
    }

    #[test]
    fn rejects_unknown() {
        let err = "h.encap".parse::<EncapType>().unwrap_err();
        assert_eq!(err, ParseEncapTypeError("h.encap".to_string()));

        let err = "".parse::<EncapType>().unwrap_err();
        assert_eq!(err, ParseEncapTypeError(String::new()));
    }

    #[test]
    fn display_round_trips() {
        for variant in ALL {
            let parsed: EncapType = variant.to_string().parse().unwrap();
            assert_eq!(parsed, variant);
        }
    }
}
