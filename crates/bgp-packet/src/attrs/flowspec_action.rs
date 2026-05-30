//! Flow Specification Traffic Filtering Action extended communities
//! (RFC 8955 §7, with the IPv6 redirect noted in RFC 8956).
//!
//! Actions ride alongside a Flow Specification NLRI as transitive
//! extended communities. Each is an 8-octet [`ExtCommunityValue`] whose
//! high/low type bytes identify the action and whose 6-octet value
//! carries the parameters. This module decodes the 8-octet forms into a
//! typed [`FlowspecAction`] and re-encodes them.
//!
//! The 20-octet IPv6-address-specific `redirect-ipv6` community
//! (RFC 8956 §4, sub-type 0x0d) uses a different on-wire container and
//! is handled separately when the IPv6 redirect dataplane lands.

use std::net::Ipv4Addr;

use crate::ExtCommunityValue;

// High-type bytes. 0x80 is the transitive flow-spec action range; the
// RT-redirect form additionally uses 0x81 (IPv4) and 0x82 (4-octet AS)
// to mirror the Route-Target community formats (RFC 8955 §7.4).
const FS_HIGH: u8 = 0x80;
const FS_HIGH_REDIRECT_IPV4: u8 = 0x81;
const FS_HIGH_REDIRECT_AS4: u8 = 0x82;

// Sub-type (low) bytes (RFC 8955 §7, IANA "Traffic Filtering Actions").
const SUB_TRAFFIC_RATE_BYTES: u8 = 0x06;
const SUB_TRAFFIC_ACTION: u8 = 0x07;
const SUB_REDIRECT: u8 = 0x08;
const SUB_TRAFFIC_MARKING: u8 = 0x09;
const SUB_TRAFFIC_RATE_PACKETS: u8 = 0x0c;

// Traffic-action value bits, in the least-significant octet (bit 47 is
// the rightmost bit of the 6-octet value).
const TA_TERMINAL: u8 = 0x01; // bit 47 'T'
const TA_SAMPLE: u8 = 0x02; // bit 46 'S'

/// A decoded Flow Specification traffic-filtering action.
///
/// `f32` rates are not `Eq`/`Ord`, so this type is interpretation-only
/// (`PartialEq`) and is never used as a map key — flow specs are keyed
/// by their NLRI, with the action set hanging off the path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowspecAction {
    /// `traffic-rate-bytes` (0x8006): police to `rate` bytes/second.
    /// A rate of `0.0` means discard all matching traffic.
    TrafficRateBytes { asn: u16, rate: f32 },
    /// `traffic-rate-packets` (0x800c): police to `rate` packets/second.
    TrafficRatePackets { asn: u16, rate: f32 },
    /// `traffic-action` (0x8007): terminal-action and sample flags.
    TrafficAction { terminal: bool, sample: bool },
    /// `rt-redirect` 2-octet AS form (0x8008): redirect to the VRF(s)
    /// importing this Route-Target.
    RedirectAs2 { asn: u16, value: u32 },
    /// `rt-redirect` IPv4 form (0x8108).
    RedirectIpv4 { addr: Ipv4Addr, value: u16 },
    /// `rt-redirect` 4-octet AS form (0x8208).
    RedirectAs4 { asn: u32, value: u16 },
    /// `traffic-marking` (0x8009): rewrite the DSCP field (6 bits).
    TrafficMarking { dscp: u8 },
}

impl ExtCommunityValue {
    /// Decode this extended community as a Flow Specification action,
    /// or `None` if it is not one of the 8-octet traffic-filtering
    /// action forms.
    pub fn as_flowspec_action(&self) -> Option<FlowspecAction> {
        let v = &self.val;
        match (self.high_type, self.low_type) {
            (FS_HIGH, SUB_TRAFFIC_RATE_BYTES) => Some(FlowspecAction::TrafficRateBytes {
                asn: u16::from_be_bytes([v[0], v[1]]),
                rate: f32::from_be_bytes([v[2], v[3], v[4], v[5]]),
            }),
            (FS_HIGH, SUB_TRAFFIC_RATE_PACKETS) => Some(FlowspecAction::TrafficRatePackets {
                asn: u16::from_be_bytes([v[0], v[1]]),
                rate: f32::from_be_bytes([v[2], v[3], v[4], v[5]]),
            }),
            (FS_HIGH, SUB_TRAFFIC_ACTION) => Some(FlowspecAction::TrafficAction {
                terminal: v[5] & TA_TERMINAL != 0,
                sample: v[5] & TA_SAMPLE != 0,
            }),
            (FS_HIGH, SUB_REDIRECT) => Some(FlowspecAction::RedirectAs2 {
                asn: u16::from_be_bytes([v[0], v[1]]),
                value: u32::from_be_bytes([v[2], v[3], v[4], v[5]]),
            }),
            (FS_HIGH_REDIRECT_IPV4, SUB_REDIRECT) => Some(FlowspecAction::RedirectIpv4 {
                addr: Ipv4Addr::new(v[0], v[1], v[2], v[3]),
                value: u16::from_be_bytes([v[4], v[5]]),
            }),
            (FS_HIGH_REDIRECT_AS4, SUB_REDIRECT) => Some(FlowspecAction::RedirectAs4 {
                asn: u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
                value: u16::from_be_bytes([v[4], v[5]]),
            }),
            (FS_HIGH, SUB_TRAFFIC_MARKING) => {
                Some(FlowspecAction::TrafficMarking { dscp: v[5] & 0x3f })
            }
            _ => None,
        }
    }

    /// True iff this extended community encodes a Flow Specification
    /// traffic-filtering action.
    pub fn is_flowspec_action(&self) -> bool {
        self.as_flowspec_action().is_some()
    }
}

impl From<FlowspecAction> for ExtCommunityValue {
    fn from(action: FlowspecAction) -> Self {
        let mut val = [0u8; 6];
        let (high_type, low_type) = match action {
            FlowspecAction::TrafficRateBytes { asn, rate } => {
                val[0..2].copy_from_slice(&asn.to_be_bytes());
                val[2..6].copy_from_slice(&rate.to_be_bytes());
                (FS_HIGH, SUB_TRAFFIC_RATE_BYTES)
            }
            FlowspecAction::TrafficRatePackets { asn, rate } => {
                val[0..2].copy_from_slice(&asn.to_be_bytes());
                val[2..6].copy_from_slice(&rate.to_be_bytes());
                (FS_HIGH, SUB_TRAFFIC_RATE_PACKETS)
            }
            FlowspecAction::TrafficAction { terminal, sample } => {
                if terminal {
                    val[5] |= TA_TERMINAL;
                }
                if sample {
                    val[5] |= TA_SAMPLE;
                }
                (FS_HIGH, SUB_TRAFFIC_ACTION)
            }
            FlowspecAction::RedirectAs2 { asn, value } => {
                val[0..2].copy_from_slice(&asn.to_be_bytes());
                val[2..6].copy_from_slice(&value.to_be_bytes());
                (FS_HIGH, SUB_REDIRECT)
            }
            FlowspecAction::RedirectIpv4 { addr, value } => {
                val[0..4].copy_from_slice(&addr.octets());
                val[4..6].copy_from_slice(&value.to_be_bytes());
                (FS_HIGH_REDIRECT_IPV4, SUB_REDIRECT)
            }
            FlowspecAction::RedirectAs4 { asn, value } => {
                val[0..4].copy_from_slice(&asn.to_be_bytes());
                val[4..6].copy_from_slice(&value.to_be_bytes());
                (FS_HIGH_REDIRECT_AS4, SUB_REDIRECT)
            }
            FlowspecAction::TrafficMarking { dscp } => {
                val[5] = dscp & 0x3f;
                (FS_HIGH, SUB_TRAFFIC_MARKING)
            }
        };
        ExtCommunityValue {
            high_type,
            low_type,
            val,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(action: FlowspecAction) {
        let ev: ExtCommunityValue = action.into();
        assert!(ev.is_flowspec_action());
        assert_eq!(ev.as_flowspec_action(), Some(action));
    }

    #[test]
    fn traffic_rate_bytes_round_trip() {
        round_trip(FlowspecAction::TrafficRateBytes {
            asn: 65000,
            rate: 1_000_000.0,
        });
    }

    #[test]
    fn discard_is_zero_rate() {
        let ev: ExtCommunityValue = FlowspecAction::TrafficRateBytes { asn: 0, rate: 0.0 }.into();
        // [0x80, 0x06, asn(2)=0, rate(4)=0.0].
        assert_eq!(ev.high_type, 0x80);
        assert_eq!(ev.low_type, 0x06);
        assert_eq!(ev.val, [0u8; 6]);
        match ev.as_flowspec_action() {
            Some(FlowspecAction::TrafficRateBytes { rate, .. }) => assert_eq!(rate, 0.0),
            other => panic!("expected traffic-rate, got {other:?}"),
        }
    }

    #[test]
    fn traffic_rate_packets_round_trip() {
        round_trip(FlowspecAction::TrafficRatePackets {
            asn: 100,
            rate: 500.0,
        });
    }

    #[test]
    fn traffic_action_flags_round_trip() {
        for terminal in [false, true] {
            for sample in [false, true] {
                round_trip(FlowspecAction::TrafficAction { terminal, sample });
            }
        }
    }

    #[test]
    fn traffic_action_bit_layout() {
        let ev: ExtCommunityValue = FlowspecAction::TrafficAction {
            terminal: true,
            sample: true,
        }
        .into();
        // Both bits live in the least-significant value octet.
        assert_eq!(ev.val, [0, 0, 0, 0, 0, 0x03]);
    }

    #[test]
    fn redirect_forms_round_trip() {
        round_trip(FlowspecAction::RedirectAs2 {
            asn: 65000,
            value: 42,
        });
        round_trip(FlowspecAction::RedirectIpv4 {
            addr: Ipv4Addr::new(192, 0, 2, 1),
            value: 7,
        });
        round_trip(FlowspecAction::RedirectAs4 {
            asn: 4_200_000_000,
            value: 9,
        });
    }

    #[test]
    fn redirect_high_type_bytes() {
        let as2: ExtCommunityValue = FlowspecAction::RedirectAs2 { asn: 1, value: 1 }.into();
        let v4: ExtCommunityValue = FlowspecAction::RedirectIpv4 {
            addr: Ipv4Addr::UNSPECIFIED,
            value: 1,
        }
        .into();
        let as4: ExtCommunityValue = FlowspecAction::RedirectAs4 { asn: 1, value: 1 }.into();
        assert_eq!((as2.high_type, as2.low_type), (0x80, 0x08));
        assert_eq!((v4.high_type, v4.low_type), (0x81, 0x08));
        assert_eq!((as4.high_type, as4.low_type), (0x82, 0x08));
    }

    #[test]
    fn traffic_marking_round_trip() {
        round_trip(FlowspecAction::TrafficMarking { dscp: 46 });
    }

    #[test]
    fn traffic_marking_masks_to_six_bits() {
        let ev: ExtCommunityValue = FlowspecAction::TrafficMarking { dscp: 0xff }.into();
        assert_eq!(ev.val[5], 0x3f);
    }

    #[test]
    fn non_action_communities_return_none() {
        // Route-Target (0x00/0x02) is not a flow-spec action.
        let rt = ExtCommunityValue {
            high_type: 0x00,
            low_type: 0x02,
            val: [0, 100, 0, 0, 0, 200],
        };
        assert!(!rt.is_flowspec_action());
        assert_eq!(rt.as_flowspec_action(), None);
    }
}
