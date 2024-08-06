use super::{Attribute, BgpHeader, NotificationPacket, OpenPacket, UpdatePacket};
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

        // Opt param buffer.
        let mut opt_buf = BytesMut::new();
        for cap in open.caps.iter() {
            cap.encode(&mut opt_buf);
        }

        // Extended opt param length as defined in RFC9072.
        let opt_param_len = opt_buf.len();
        if opt_param_len < 255 {
            buf.put_u8(opt_param_len as u8);
        } else {
            buf.put_u8(255u8);
            buf.put_u8(255u8);
            buf.put_u16(opt_param_len as u16);
        }
        buf.put(&opt_buf[..]);

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}

impl From<UpdatePacket> for BytesMut {
    fn from(update: UpdatePacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = update.header.into();
        buf.put(&header[..]);

        // Withdraw.
        if !update.ipv4_withdraw.is_empty() {
            return buf;
        } else {
            buf.put_u16(0u16);
        }

        // Attributes.
        let attr_len_pos = buf.len();
        println!("attr_len_pos {}", attr_len_pos);
        buf.put_u16(0u16);
        let _attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        for attr in update.attrs.iter() {
            match attr {
                Attribute::Origin(attr) => {
                    attr.encode(&mut buf);
                }
                Attribute::NextHop(attr) => {
                    attr.encode(&mut buf);
                }
                // Attribute::As4Path(attr) => {
                //     attr.encode(&mut buf);
                // }
                _ => {}
            }
            println!("{:?}", attr)
        }

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
