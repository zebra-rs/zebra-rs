use std::fmt;

use bytes::{BufMut, BytesMut};
use fixedbuf::FixedBuf;
use nom::number::complete::be_u16;
use nom_derive::*;

use crate::{
    Afi, BGP_HEADER_LEN, BgpAttr, BgpHeader, BgpParseError, BgpType, Ipv4Nlri, MpReachAttr,
    MpUnreachAttr, ParseOption, Safi, nlri_psize, parse_bgp_nlri_ipv4, parse_bgp_update_attribute,
};

#[derive(NomBE)]
pub struct UpdatePacket {
    pub header: BgpHeader,
    #[nom(Ignore)]
    pub bgp_attr: Option<BgpAttr>,
    #[nom(Ignore)]
    pub ipv4_update: Vec<Ipv4Nlri>,
    #[nom(Ignore)]
    pub ipv4_withdraw: Vec<Ipv4Nlri>,
    #[nom(Ignore)]
    pub mp_update: Option<MpReachAttr>,
    #[nom(Ignore)]
    pub mp_withdraw: Option<MpUnreachAttr>,
    #[nom(Ignore)]
    max_packet_size: usize,
}

impl UpdatePacket {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for UpdatePacket {
    fn default() -> Self {
        Self {
            header: BgpHeader::new(BgpType::Update, BGP_HEADER_LEN),
            bgp_attr: None,
            ipv4_update: Vec::new(),
            ipv4_withdraw: Vec::new(),
            mp_update: None,
            mp_withdraw: None,
            max_packet_size: 4096,
        }
    }
}

impl UpdatePacket {
    pub fn pop_ipv4(&mut self) -> Option<BytesMut> {
        if self.ipv4_update.is_empty() {
            return None;
        }
        let mut buf = BytesMut::with_capacity(self.max_packet_size);
        let header: BytesMut = self.header.clone().into();
        buf.put(&header[..]);

        // IPv4 unicast withdraw right now we only support IPv4 updates only.
        buf.put_u16(0u16); // Empty IPv4 withdraw.

        // Attributes length.
        let attr_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder
        let attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        // Attributes emit.
        if let Some(bgp_attr) = &self.bgp_attr {
            bgp_attr.attr_emit(&mut buf);
        }

        // No MP reach/unreach emit at this moment.

        // Fill in attr length.
        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        buf[attr_pos].copy_from_slice(&attr_len.to_be_bytes());

        // Consume self.ipv4_update with checking buffer size.
        while let Some(ip) = self.ipv4_update.pop() {
            // Calculate NLRI len. When it exceed remaing size, push back the ip
            // then return current buf.
            let mut nlri_len: usize = 0;
            if ip.id != 0 {
                nlri_len = 4;
            }
            nlri_len += 1;
            nlri_len += nlri_psize(ip.prefix.prefix_len());

            if buf.len() + nlri_len > self.max_packet_size {
                self.ipv4_update.push(ip);

                const LENGTH_POS: std::ops::Range<usize> = 16..18;
                let length: u16 = buf.len() as u16;
                buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

                return Some(buf);
            }

            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        Some(buf)
    }

    pub fn pop_vpnv4(&mut self) -> Option<BytesMut> {
        match &self.mp_update {
            Some(MpReachAttr::Vpnv4(vpnv4)) if !vpnv4.updates.is_empty() => {}
            _ => return None,
        }
        let mp_update = self.mp_update.as_mut().unwrap();

        let mut buf = FixedBuf::new(self.max_packet_size);
        let header: BytesMut = self.header.clone().into();
        let _ = buf.put(&header[..]);

        // IPv4 unicast withdraw right now we only support VPNv4 updates only.
        let _ = buf.put_u16(0u16); // Empty IPv4 withdraw.

        // Attributes length.
        let attr_len_pos = buf.len();
        let _ = buf.put_u16(0u16); // Placeholder

        // Attributes emit.
        if let Some(bgp_attr) = &self.bgp_attr {
            bgp_attr.attr_emit(&mut buf.get_mut());
        }

        // MP reach.
        mp_update.attr_emit_mut(&mut buf.get_mut());

        // Fill in attr length.
        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        let _ = buf.put_u16_at(attr_len_pos, attr_len);

        // Fill in total length.
        let length: u16 = buf.len() as u16;
        let _ = buf.put_u16_at(16, length);

        Some(buf.get())
    }
}

impl From<UpdatePacket> for BytesMut {
    fn from(update: UpdatePacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = update.header.into();
        buf.put(&header[..]);

        // IPv4 unicast withdraw.
        let withdraw_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder.
        let withdraw_pos: std::ops::Range<usize> = withdraw_len_pos..withdraw_len_pos + 2;
        for ip in update.ipv4_withdraw.iter() {
            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }
        let withdraw_len: u16 = (buf.len() - withdraw_len_pos - 2) as u16;
        buf[withdraw_pos].copy_from_slice(&withdraw_len.to_be_bytes());

        // Attributes length.
        let attr_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder
        let attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        // Attributes emit.
        if let Some(bgp_attr) = update.bgp_attr {
            bgp_attr.attr_emit(&mut buf);
        }

        // MP reach.
        if let Some(mp_update) = update.mp_update {
            mp_update.attr_emit(&mut buf);
        }

        // MP unreach.
        if let Some(mp_withdraw) = update.mp_withdraw {
            mp_withdraw.attr_emit(&mut buf);
        }

        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        buf[attr_pos].copy_from_slice(&attr_len.to_be_bytes());

        // IPv4 unicast update.
        for ip in update.ipv4_update.iter() {
            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}

impl fmt::Debug for UpdatePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self)
    }
}

impl fmt::Display for UpdatePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Update Message:")?;
        if let Some(bgp_attr) = &self.bgp_attr {
            write!(f, "{}", bgp_attr)?;
        }
        if !self.ipv4_update.is_empty() {
            writeln!(f, " IPv4 Updates:")?;
            for update in self.ipv4_update.iter() {
                writeln!(f, "  {}", update.prefix)?;
            }
        }
        if !self.ipv4_withdraw.is_empty() {
            writeln!(f, " IPv4 Withdraw:")?;
            for withdraw in self.ipv4_withdraw.iter() {
                writeln!(f, "  {}", withdraw.prefix)?;
            }
        }
        if let Some(mp_update) = &self.mp_update {
            write!(f, "{}", mp_update)?;
        }
        if let Some(mp_withdraw) = &self.mp_withdraw {
            write!(f, "{}", mp_withdraw)?;
        }
        if self.bgp_attr.is_none()
            && self.mp_update.is_none()
            && self.mp_withdraw.is_none()
            && self.ipv4_update.is_empty()
            && self.ipv4_withdraw.is_empty()
        {
            writeln!(f, " EoR: IPv4/Unicast")?;
        }
        Ok(())
    }
}

impl UpdatePacket {
    pub fn parse_packet(
        input: &[u8],
        as4: bool,
        opt: Option<ParseOption>,
    ) -> Result<(&[u8], UpdatePacket), BgpParseError> {
        let add_path = if let Some(opt) = opt.as_ref() {
            opt.is_add_path_recv(Afi::Ip, Safi::Unicast)
        } else {
            false
        };
        let (input, mut packet) = UpdatePacket::parse_be(input)?;
        let (input, withdraw_len) = be_u16(input)?;
        let (input, mut withdrawal) = parse_bgp_nlri_ipv4(input, withdraw_len, add_path)?;
        packet.ipv4_withdraw.append(&mut withdrawal);
        let (input, attr_len) = be_u16(input)?;
        let (input, bgp_attr, mp_update, mp_withdraw) = if attr_len > 0 {
            parse_bgp_update_attribute(input, attr_len, as4, opt)?
        } else {
            (input, None, None, None)
        };
        packet.bgp_attr = bgp_attr;
        packet.mp_update = mp_update;
        packet.mp_withdraw = mp_withdraw;
        let nlri_len = packet.header.length - BGP_HEADER_LEN - 2 - withdraw_len - 2 - attr_len;
        let (input, mut updates) = parse_bgp_nlri_ipv4(input, nlri_len, add_path)?;
        packet.ipv4_update.append(&mut updates);
        Ok((input, packet))
    }
}
