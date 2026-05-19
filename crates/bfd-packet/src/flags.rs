use bitfield_struct::bitfield;

/// Byte 0 of the BFD control packet: Version (3 bits) | Diagnostic (5 bits).
///
/// `bitfield_struct` lays out fields LSB-first, so `diag` occupies bits 0–4
/// and `version` occupies bits 5–7, matching the on-wire encoding from
/// RFC 5880 §4.1.
#[bitfield(u8, debug = true)]
#[derive(PartialEq, Eq)]
pub struct VersDiag {
    #[bits(5)]
    pub diag: u8,
    #[bits(3)]
    pub version: u8,
}

/// Byte 1 of the BFD control packet: State (2 bits) | P | F | C | A | D | M.
///
/// LSB-first layout: M (bit 0), D (bit 1), A (bit 2), C (bit 3),
/// F (bit 4), P (bit 5), State (bits 6–7).
#[bitfield(u8, debug = true)]
#[derive(PartialEq, Eq)]
pub struct StateFlags {
    pub multipoint: bool,
    pub demand: bool,
    pub authentication: bool,
    pub cpi: bool,
    pub final_bit: bool,
    pub poll: bool,
    #[bits(2)]
    pub state: u8,
}
