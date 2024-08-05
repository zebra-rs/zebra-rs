#![allow(dead_code)]
use nom_derive::*;

pub const AS_SET: u8 = 1;
pub const AS_SEQUENCE: u8 = 2;
pub const AS_CONFED_SEQUENCE: u8 = 3;
pub const AS_CONFED_SET: u8 = 4;

#[derive(Debug, NomBE)]
pub struct AsSegmentHeader {
    pub typ: u8,
    pub length: u8,
}

#[derive(Clone, Debug)]
pub struct As2Segment {
    pub typ: u8,
    pub asn: Vec<u16>,
}

#[derive(Clone, Debug)]
pub struct As2PathAttr {
    pub segments: Vec<As2Segment>,
}

#[derive(Clone, Debug)]
pub struct As4Segment {
    pub typ: u8,
    pub asn: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct As4PathAttr {
    pub segments: Vec<As4Segment>,
}

// let output: Vec<u8> = input.iter().flat_map(|val| val.to_be_bytes()).collect();
