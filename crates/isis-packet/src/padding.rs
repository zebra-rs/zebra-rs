use bytes::BytesMut;

use crate::{
    IsisHello, IsisP2pHello, IsisPacket, IsisPdu, IsisTlv, IsisTlvPadding, IsisType, parse,
};

impl IsisHello {
    pub fn padding(&mut self, mtu: usize) {
        let mut buf = BytesMut::new();

        // Try to emit Hello packet.
        let packet = IsisPacket::from(IsisType::L1Hello, IsisPdu::L1Hello(self.clone()));
        packet.emit(&mut buf);

        if parse(&buf).is_err() {
            return;
        }

        // Make sure we don't underflow
        let packet_len = buf.len();
        let base_len = 3;
        if packet_len + base_len > mtu {
            // Not enough space for any padding
            return;
        }

        let available_len = mtu - base_len - packet_len;
        if available_len < 2 {
            // Not enough space for even minimum padding TLV
            return;
        }

        // 257 = 2 byte header + 255 byte padding
        const TLV_MAX: usize = 255;
        const TLV_OVERHEAD: usize = 2;
        const TLV_SIZE: usize = TLV_OVERHEAD + TLV_MAX;

        let full_padding_count = available_len / TLV_SIZE;
        let remaining = available_len % TLV_SIZE;

        // Helper to generate Padding TLV
        fn padding_tlv(len: usize) -> IsisTlv {
            IsisTlv::Padding(IsisTlvPadding {
                padding: vec![0u8; len],
            })
        }

        // Add full (255-byte) padding TLVs
        for _ in 0..full_padding_count {
            self.tlvs.push(padding_tlv(TLV_MAX));
        }

        // Add the remainder as one smaller padding TLV (if enough room for TLV header)
        if remaining > TLV_OVERHEAD {
            let pad_len = remaining - TLV_OVERHEAD;
            if pad_len > 0 {
                self.tlvs.push(padding_tlv(pad_len));
            }
        }
    }
}

impl IsisP2pHello {
    pub fn padding(&mut self, mtu: usize) {
        let mut buf = BytesMut::new();

        // Try to emit Hello packet.
        let packet = IsisPacket::from(IsisType::P2pHello, IsisPdu::P2pHello(self.clone()));
        packet.emit(&mut buf);

        if parse(&buf).is_err() {
            return;
        }

        // Make sure we don't underflow
        let packet_len = buf.len();
        let base_len = 3;
        if packet_len + base_len > mtu {
            // Not enough space for any padding
            return;
        }

        let available_len = mtu - base_len - packet_len;
        if available_len < 2 {
            // Not enough space for even minimum padding TLV
            return;
        }

        // 257 = 2 byte header + 255 byte padding
        const TLV_MAX: usize = 255;
        const TLV_OVERHEAD: usize = 2;
        const TLV_SIZE: usize = TLV_OVERHEAD + TLV_MAX;

        let full_padding_count = available_len / TLV_SIZE;
        let remaining = available_len % TLV_SIZE;

        // Helper to generate Padding TLV
        fn padding_tlv(len: usize) -> IsisTlv {
            IsisTlv::Padding(IsisTlvPadding {
                padding: vec![0u8; len],
            })
        }

        // Add full (255-byte) padding TLVs
        for _ in 0..full_padding_count {
            self.tlvs.push(padding_tlv(TLV_MAX));
        }

        // Add the remainder as one smaller padding TLV (if enough room for TLV header)
        if remaining > TLV_OVERHEAD {
            let pad_len = remaining - TLV_OVERHEAD;
            if pad_len > 0 {
                self.tlvs.push(padding_tlv(pad_len));
            }
        }
    }
}
