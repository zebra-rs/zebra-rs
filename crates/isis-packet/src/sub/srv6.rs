// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

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
    Resv(u16),
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
            EndB6EncapsRed => 26,
            EndUSD => 27,
            EndPSPUSD => 28,
            EndUSPUSD => 29,
            EndPSPUSPUSD => 30,
            EndXUSD => 31,
            EndXPSPUSD => 32,
            EndXUSPUSD => 33,
            EndXPSPUSPUSD => 34,
            EndTUSD => 35,
            EndTPSPUSD => 36,
            EndTUSPUSD => 37,
            EndTPSPUSPUSD => 38,
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
            26 => EndB6EncapsRed,
            27 => EndUSD,
            28 => EndPSPUSD,
            29 => EndUSPUSD,
            30 => EndPSPUSPUSD,
            31 => EndXUSD,
            32 => EndXPSPUSD,
            33 => EndXUSPUSD,
            34 => EndXPSPUSPUSD,
            35 => EndTUSD,
            36 => EndTPSPUSD,
            37 => EndTUSPUSD,
            38 => EndTPSPUSPUSD,
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
            Resv(v) => write!(f, "Resv({})", v),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum EncapType {
    HEncap,
    HEncapRed,
    HEncapL2,
    HEncapL2Red,
}

impl EncapType {
    fn as_str(&self) -> &'static str {
        match self {
            EncapType::HEncap => "H.Encap",
            EncapType::HEncapRed => "H.Encap.Red",
            EncapType::HEncapL2 => "H.Encap.L2",
            EncapType::HEncapL2Red => "H.Encap.L2.Red",
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
            other => Err(ParseEncapTypeError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
