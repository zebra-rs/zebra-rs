// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::fmt::{Display, Formatter, Result};

use serde::{Deserialize, Serialize};

// SRv6 Endpoint Behaviors — IANA "SRv6 Endpoint Behaviors" registry
// (RFC 8986 base set + USD flavor variants).
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
            v => Resv(v),
        }
    }
}

impl Display for Behavior {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use Behavior::*;
        match self {
            End => write!(f, "End"),
            EndPSP => write!(f, "End with PSP"),
            EndUSP => write!(f, "End with USP"),
            EndPSPUSP => write!(f, "End with PSP, USP"),
            EndX => write!(f, "End.X"),
            EndXPSP => write!(f, "End.X with PSP"),
            EndXUSP => write!(f, "End.X with USP"),
            EndXPSPUSP => write!(f, "End.X with PSP, USP"),
            EndT => write!(f, "End.T"),
            EndTPSP => write!(f, "End.T with PSP"),
            EndTUSP => write!(f, "End.T with USP"),
            EndTPSPUSP => write!(f, "End.T with PSP, USP"),
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
            EndUSD => write!(f, "End with USD"),
            EndPSPUSD => write!(f, "End with PSP, USD"),
            EndUSPUSD => write!(f, "End with USP, USD"),
            EndPSPUSPUSD => write!(f, "End with PSP, USP, USD"),
            EndXUSD => write!(f, "End.X with USD"),
            EndXPSPUSD => write!(f, "End.X with PSP, USD"),
            EndXUSPUSD => write!(f, "End.X with USP, USD"),
            EndXPSPUSPUSD => write!(f, "End.X with PSP, USP, USD"),
            EndTUSD => write!(f, "End.T with USD"),
            EndTPSPUSD => write!(f, "End.T with PSP, USD"),
            EndTUSPUSD => write!(f, "End.T with USP, USD"),
            EndTPSPUSPUSD => write!(f, "End.T with PSP, USP, USD"),
            Resv(v) => write!(f, "Resv({})", v),
        }
    }
}
