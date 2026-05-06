use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom_derive::*;

use super::{BGP_HEADER_LEN, BgpHeader, BgpType};

// RFC 2918 §3 fixes the Route Refresh payload at 4 bytes after the
// 19-byte BGP header: AFI (2) | reserved (1) | SAFI (1).
const ROUTE_REFRESH_PAYLOAD_LEN: u16 = 4;
const ROUTE_REFRESH_TOTAL_LEN: u16 = BGP_HEADER_LEN + ROUTE_REFRESH_PAYLOAD_LEN;

// BGP Route Refresh message (type 5, RFC 2918). The single-byte
// reserved field is co-opted by RFC 7313 Enhanced Route Refresh as a
// subtype (0 = normal refresh, 1 = BoRR, 2 = EoRR); plain RFC 2918
// senders set it to 0 and receivers ignore it. AFI/SAFI are kept as
// raw integers so unknown values round-trip without lossy casts.
#[derive(Debug, Clone, NomBE)]
pub struct RouteRefreshPacket {
    pub header: BgpHeader,
    pub afi: u16,
    pub subtype: u8,
    pub safi: u8,
}

impl RouteRefreshPacket {
    pub fn new(afi: u16, safi: u8) -> Self {
        Self {
            header: BgpHeader::new(BgpType::RouteRefresh, ROUTE_REFRESH_TOTAL_LEN),
            afi,
            subtype: 0,
            safi,
        }
    }

    pub fn parse_packet(input: &[u8]) -> IResult<&[u8], RouteRefreshPacket> {
        Self::parse_be(input)
    }
}

impl From<RouteRefreshPacket> for BytesMut {
    fn from(p: RouteRefreshPacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = p.header.into();
        buf.put(&header[..]);
        buf.put_u16(p.afi);
        buf.put_u8(p.subtype);
        buf.put_u8(p.safi);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_refresh_roundtrip_ipv4_unicast() {
        let original = RouteRefreshPacket::new(1, 1);
        let bytes: BytesMut = original.into();
        assert_eq!(bytes.len(), ROUTE_REFRESH_TOTAL_LEN as usize);

        let (rest, parsed) = RouteRefreshPacket::parse_packet(&bytes).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(parsed.afi, 1);
        assert_eq!(parsed.safi, 1);
        assert_eq!(parsed.subtype, 0);
        assert_eq!(parsed.header.length, ROUTE_REFRESH_TOTAL_LEN);
    }

    #[test]
    fn route_refresh_preserves_unknown_afi_safi() {
        // Unknown AFI/SAFI must round-trip — receivers should not
        // reject Route Refresh just because they don't recognise the
        // address family (RFC 2918 leaves handling AFI/SAFI mismatch
        // to the receiver, but the wire form must still parse).
        let original = RouteRefreshPacket::new(9999, 200);
        let bytes: BytesMut = original.into();
        let (_, parsed) = RouteRefreshPacket::parse_packet(&bytes).expect("parse");
        assert_eq!(parsed.afi, 9999);
        assert_eq!(parsed.safi, 200);
    }
}
