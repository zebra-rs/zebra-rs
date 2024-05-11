use super::{BgpHeader, NotificationPacket, OpenPacket};
use bytes::{BufMut, BytesMut};

impl From<BgpHeader> for BytesMut {
    fn from(header: BgpHeader) -> Self {
        let mut buf = BytesMut::new();
        buf.put(&header.marker[..]);
        buf.put_u16(header.length);
        let typ: u8 = header.typ as u8;
        buf.put_u8(typ);
        buf
    }
}

impl From<OpenPacket> for BytesMut {
    fn from(open: OpenPacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = open.header.into();
        buf.put(&header[..]);
        buf.put_u8(open.version);
        buf.put_u16(open.asn);
        buf.put_u16(open.hold_time);
        buf.put(&open.bgp_id[..]);

        let op_param_pos = buf.len();
        buf.put_u8(open.opt_param_len);
        for cap in open.caps.iter() {
            cap.encode(&mut buf);
        }
        buf[op_param_pos] = (buf.len() - op_param_pos - 1) as u8;

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}

impl From<NotificationPacket> for BytesMut {
    fn from(notification: NotificationPacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = notification.header.into();
        buf.put(&header[..]);
        buf.put_u8(notification.code.0);
        buf.put_u8(notification.sub_code);
        buf.put(&notification.data[..]);

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}
