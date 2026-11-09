//! DHCPv4 and BOOTP messages (RFC 2131, RFC 951, RFC 1542) and the
//! Relay Agent Information option (RFC 3046).
//!
//! The vendor area is decoded only when it starts with the magic
//! cookie; a plain BOOTP message keeps its vendor area as raw bytes,
//! because a relay forwards those untouched. `sname` and `file` stay
//! raw too, even under option overload (52), so they round-trip exactly;
//! a client reads the options they carry through
//! [`Packet::merged_options`]. [`params`] decodes the option values.

use std::net::Ipv4Addr;

use crate::Error;

pub mod params;

/// UDP port of servers and relay agents.
pub const SERVER_PORT: u16 = 67;
/// UDP port of clients.
pub const CLIENT_PORT: u16 = 68;

/// `op` of a client-to-server message.
pub const BOOTREQUEST: u8 = 1;
/// `op` of a server-to-client message.
pub const BOOTREPLY: u8 = 2;

/// `htype` of Ethernet.
pub const HTYPE_ETHERNET: u8 = 1;

/// The `flags` bit a client sets when it cannot receive unicast before
/// it has an address (RFC 2131 §4.1).
pub const FLAG_BROADCAST: u16 = 0x8000;

/// Marks the vendor area as DHCP options (RFC 2131 §3).
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// The fixed BOOTP header, up to the vendor area.
pub const HEADER_LEN: usize = 236;

/// The smallest BOOTP message (RFC 1542 §2.1); shorter output is padded.
pub const MIN_LEN: usize = 300;

/// Message types: the value of option 53 (RFC 2132 §9.6).
pub mod msg {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const DECLINE: u8 = 4;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
    pub const RELEASE: u8 = 7;
    pub const INFORM: u8 = 8;
}

/// Option codes (RFC 2132 unless noted).
pub mod opt {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS_SERVER: u8 = 6;
    pub const HOST_NAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const INTERFACE_MTU: u8 = 26;
    pub const BROADCAST_ADDRESS: u8 = 28;
    pub const NTP_SERVER: u8 = 42;
    pub const REQUESTED_ADDRESS: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const OVERLOAD: u8 = 52;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    pub const MESSAGE: u8 = 56;
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const VENDOR_CLASS_ID: u8 = 60;
    pub const CLIENT_ID: u8 = 61;
    /// RFC 3004.
    pub const USER_CLASS: u8 = 77;
    /// RFC 3046.
    pub const RELAY_AGENT_INFORMATION: u8 = 82;
    /// RFC 3397.
    pub const DOMAIN_SEARCH: u8 = 119;
    /// RFC 3442.
    pub const CLASSLESS_STATIC_ROUTE: u8 = 121;
    pub const END: u8 = 255;
}

/// Sub-option codes of the Relay Agent Information option.
pub mod agent {
    pub const CIRCUIT_ID: u8 = 1;
    pub const REMOTE_ID: u8 = 2;
}

/// One option as carried on the wire. Codes 0 (pad) and 255 (end) are
/// framing: `parse` never produces them and `emit` skips them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpOption {
    pub code: u8,
    pub data: Vec<u8>,
}

/// What follows the fixed header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// The magic cookie, then options in wire order. Each instance of a
    /// split option (RFC 3396) stays a separate entry.
    Options(Vec<DhcpOption>),
    /// No magic cookie: a BOOTP vendor area, kept as received.
    Bootp(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub body: Body,
}

impl Packet {
    pub fn parse(buf: &[u8]) -> Result<Packet, Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Short);
        }
        let u16_at = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
        let addr_at = |i: usize| Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
        let mut chaddr = [0; 16];
        chaddr.copy_from_slice(&buf[28..44]);
        let mut sname = [0; 64];
        sname.copy_from_slice(&buf[44..108]);
        let mut file = [0; 128];
        file.copy_from_slice(&buf[108..HEADER_LEN]);
        let vend = &buf[HEADER_LEN..];
        let body = match vend.strip_prefix(&MAGIC_COOKIE[..]) {
            Some(options) => Body::Options(parse_options(options)?),
            None => Body::Bootp(vend.to_vec()),
        };
        Ok(Packet {
            op: buf[0],
            htype: buf[1],
            hlen: buf[2],
            hops: buf[3],
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            secs: u16_at(8),
            flags: u16_at(10),
            ciaddr: addr_at(12),
            yiaddr: addr_at(16),
            siaddr: addr_at(20),
            giaddr: addr_at(24),
            chaddr,
            sname,
            file,
            body,
        })
    }

    /// The wire form: options, then the end option, then zero padding up
    /// to [`MIN_LEN`].
    pub fn emit(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.unpadded_len().max(MIN_LEN));
        out.extend_from_slice(&[self.op, self.htype, self.hlen, self.hops]);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        for addr in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            out.extend_from_slice(&addr.octets());
        }
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&self.sname);
        out.extend_from_slice(&self.file);
        match &self.body {
            Body::Options(options) => {
                out.extend_from_slice(&MAGIC_COOKIE);
                for option in options {
                    emit_option(&mut out, option);
                }
                out.push(opt::END);
            }
            Body::Bootp(vend) => out.extend_from_slice(vend),
        }
        if out.len() < MIN_LEN {
            out.resize(MIN_LEN, 0);
        }
        out
    }

    /// The length of [`Packet::emit`]'s output before the padding: what
    /// a relay's maximum-packet-size check measures.
    pub fn unpadded_len(&self) -> usize {
        HEADER_LEN
            + match &self.body {
                Body::Options(options) => {
                    MAGIC_COOKIE.len() + options.iter().map(option_len).sum::<usize>() + 1
                }
                Body::Bootp(vend) => vend.len(),
            }
    }

    /// The options in wire order; empty for BOOTP.
    pub fn options(&self) -> &[DhcpOption] {
        match &self.body {
            Body::Options(options) => options,
            Body::Bootp(_) => &[],
        }
    }

    /// The first instance of `code`.
    pub fn option(&self, code: u8) -> Option<&DhcpOption> {
        self.options().iter().find(|o| o.code == code)
    }

    /// Option 53. `None` means BOOTP, or a malformed DHCP message.
    pub fn message_type(&self) -> Option<u8> {
        self.option(opt::MESSAGE_TYPE)
            .and_then(|o| o.data.first().copied())
    }

    pub fn broadcast(&self) -> bool {
        self.flags & FLAG_BROADCAST != 0
    }

    /// `chaddr` as a MAC address, when the hardware type is Ethernet.
    pub fn ethernet_address(&self) -> Option<[u8; 6]> {
        if self.htype != HTYPE_ETHERNET || self.hlen != 6 {
            return None;
        }
        let mut mac = [0; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        Some(mac)
    }

    /// Removes every instance of `code` and returns how many there were.
    pub fn remove_options(&mut self, code: u8) -> usize {
        match &mut self.body {
            Body::Options(options) => {
                let before = options.len();
                options.retain(|o| o.code != code);
                before - options.len()
            }
            Body::Bootp(_) => 0,
        }
    }

    /// Appends `option` after the existing ones. A BOOTP message has no
    /// options, so it is left alone and `false` returned.
    pub fn push_option(&mut self, option: DhcpOption) -> bool {
        match &mut self.body {
            Body::Options(options) => {
                options.push(option);
                true
            }
            Body::Bootp(_) => false,
        }
    }

    /// The options as a receiver must read them: every instance of a code
    /// concatenated into one value (RFC 3396), taken from the options
    /// field, then `file`, then `sname`, the last two only when option 52
    /// hands them over to options (RFC 2131 §4.1). Codes keep the order of
    /// their first instance, and option 52 itself is left out. Empty for
    /// BOOTP. Fails when an overloaded field does not parse.
    pub fn merged_options(&self) -> Result<Vec<DhcpOption>, Error> {
        let mut merged = Merged::default();
        merged.extend(self.options());
        let overload = merged
            .options
            .iter()
            .find(|o| o.code == opt::OVERLOAD)
            .and_then(|o| o.data.first().copied())
            .unwrap_or(0);
        if overload & 1 != 0 {
            merged.extend(&parse_options(&self.file)?);
        }
        if overload & 2 != 0 {
            merged.extend(&parse_options(&self.sname)?);
        }
        let mut options = merged.options;
        options.retain(|o| o.code != opt::OVERLOAD);
        Ok(options)
    }
}

/// Options merged by code, RFC 3396 style, in one pass.
#[derive(Default)]
pub(crate) struct Merged {
    pub(crate) options: Vec<DhcpOption>,
    /// Where each code sits in `options`, so merging stays linear.
    index: Vec<Option<usize>>,
}

impl Merged {
    pub(crate) fn extend<'a>(&mut self, options: impl IntoIterator<Item = &'a DhcpOption>) {
        if self.index.is_empty() {
            self.index = vec![None; 256];
        }
        for option in options {
            match self.index[usize::from(option.code)] {
                Some(i) => self.options[i].data.extend_from_slice(&option.data),
                None => {
                    self.index[usize::from(option.code)] = Some(self.options.len());
                    self.options.push(option.clone());
                }
            }
        }
    }
}

fn parse_options(mut rest: &[u8]) -> Result<Vec<DhcpOption>, Error> {
    let mut options = Vec::new();
    while let Some((&code, tail)) = rest.split_first() {
        match code {
            opt::PAD => rest = tail,
            // Whatever follows the end option is padding.
            opt::END => break,
            _ => {
                let (&len, tail) = tail.split_first().ok_or(Error::Truncated)?;
                let len = usize::from(len);
                if tail.len() < len {
                    return Err(Error::Truncated);
                }
                let (data, tail) = tail.split_at(len);
                options.push(DhcpOption {
                    code,
                    data: data.to_vec(),
                });
                rest = tail;
            }
        }
    }
    Ok(options)
}

fn emit_option(out: &mut Vec<u8>, option: &DhcpOption) {
    if matches!(option.code, opt::PAD | opt::END) {
        return;
    }
    if option.data.is_empty() {
        out.extend_from_slice(&[option.code, 0]);
        return;
    }
    // RFC 3396: a value longer than 255 bytes goes out as consecutive
    // instances of the same code.
    for chunk in option.data.chunks(255) {
        out.extend_from_slice(&[option.code, chunk.len() as u8]);
        out.extend_from_slice(chunk);
    }
}

fn option_len(option: &DhcpOption) -> usize {
    match option.code {
        opt::PAD | opt::END => 0,
        _ if option.data.is_empty() => 2,
        _ => option.data.len() + 2 * option.data.len().div_ceil(255),
    }
}

/// One sub-option of the Relay Agent Information option.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubOption {
    pub code: u8,
    pub data: Vec<u8>,
}

/// The value of option 82: a sequence of sub-options (RFC 3046 §2.0).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayAgentInfo {
    pub sub_options: Vec<SubOption>,
}

impl RelayAgentInfo {
    /// A relay's own option: just the circuit ID.
    pub fn with_circuit_id(circuit_id: &[u8]) -> RelayAgentInfo {
        RelayAgentInfo {
            sub_options: vec![SubOption {
                code: agent::CIRCUIT_ID,
                data: circuit_id.to_vec(),
            }],
        }
    }

    /// Decodes the option's value. Sub-options have no pad or end codes,
    /// so every byte belongs to a code/length/value triple.
    pub fn parse(mut rest: &[u8]) -> Result<RelayAgentInfo, Error> {
        let mut sub_options = Vec::new();
        while let Some((&code, tail)) = rest.split_first() {
            let (&len, tail) = tail.split_first().ok_or(Error::Truncated)?;
            let len = usize::from(len);
            if tail.len() < len {
                return Err(Error::Truncated);
            }
            let (data, tail) = tail.split_at(len);
            sub_options.push(SubOption {
                code,
                data: data.to_vec(),
            });
            rest = tail;
        }
        Ok(RelayAgentInfo { sub_options })
    }

    /// The option's value. Fails when a sub-option or the whole value
    /// exceeds the 255 bytes a length octet can describe.
    pub fn emit(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for sub in &self.sub_options {
            let len = u8::try_from(sub.data.len()).map_err(|_| Error::TooLong)?;
            out.extend_from_slice(&[sub.code, len]);
            out.extend_from_slice(&sub.data);
        }
        if out.len() > 255 {
            return Err(Error::TooLong);
        }
        Ok(out)
    }

    pub fn sub_option(&self, code: u8) -> Option<&[u8]> {
        self.sub_options
            .iter()
            .find(|s| s.code == code)
            .map(|s| s.data.as_slice())
    }

    pub fn circuit_id(&self) -> Option<&[u8]> {
        self.sub_option(agent::CIRCUIT_ID)
    }

    pub fn remote_id(&self) -> Option<&[u8]> {
        self.sub_option(agent::REMOTE_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    /// A DHCPDISCOVER laid out by hand, not by `emit`: 53=1, 61 client
    /// id, 55 parameter list, a pad, the end option and trailing zeros.
    fn discover_bytes() -> Vec<u8> {
        let mut b = vec![BOOTREQUEST, 1, 6, 0];
        b.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        b.extend_from_slice(&[0, 3, 0x80, 0]);
        b.extend_from_slice(&[0; 16]);
        b.extend_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        b.extend_from_slice(&[0; 10]);
        b.extend_from_slice(&[0; 64 + 128]);
        b.extend_from_slice(&MAGIC_COOKIE);
        b.extend_from_slice(&[53, 1, 1]);
        b.extend_from_slice(&[61, 7, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        b.extend_from_slice(&[0]);
        b.extend_from_slice(&[55, 3, 1, 3, 6]);
        b.push(255);
        b.resize(MIN_LEN, 0);
        b
    }

    #[test]
    fn parse_discover() {
        let p = Packet::parse(&discover_bytes()).unwrap();
        assert_eq!(p.op, BOOTREQUEST);
        assert_eq!(p.xid, 0x1234_5678);
        assert_eq!(p.secs, 3);
        assert!(p.broadcast());
        assert_eq!(p.giaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            p.ethernet_address(),
            Some([0x52, 0x54, 0, 0x12, 0x34, 0x56])
        );
        assert_eq!(p.message_type(), Some(1));
        let codes: Vec<u8> = p.options().iter().map(|o| o.code).collect();
        assert_eq!(codes, [53, 61, 55]);
        // Canonical output equals the input here: the only pad sat
        // between options and the tail was zeros.
        let mut expected = discover_bytes();
        expected.remove(240 + 3 + 9);
        expected.push(0);
        assert_eq!(p.emit(), expected);
    }

    #[test]
    fn bootp_without_cookie() {
        let mut b = discover_bytes();
        b[HEADER_LEN] = 0;
        let p = Packet::parse(&b).unwrap();
        assert!(matches!(&p.body, Body::Bootp(v) if v.len() == MIN_LEN - HEADER_LEN));
        assert_eq!(p.message_type(), None);
        assert_eq!(p.emit(), b);
        // Exactly the fixed header: an empty vendor area, padded on output.
        let p = Packet::parse(&b[..HEADER_LEN]).unwrap();
        assert_eq!(p.body, Body::Bootp(Vec::new()));
        assert_eq!(p.emit().len(), MIN_LEN);
    }

    #[test]
    fn malformed() {
        let b = discover_bytes();
        assert_eq!(Packet::parse(&b[..HEADER_LEN - 1]), Err(Error::Short));
        // Option 61 claims 7 bytes; cut inside its value.
        assert_eq!(Packet::parse(&b[..240 + 3 + 5]), Err(Error::Truncated));
        // A code with no length octet.
        assert_eq!(Packet::parse(&b[..240 + 4]), Err(Error::Truncated));
        // No end option at all is accepted.
        let p = Packet::parse(&b[..240 + 3]).unwrap();
        assert_eq!(p.message_type(), Some(1));
    }

    #[test]
    fn long_option_is_split() {
        let mut p = Packet::parse(&discover_bytes()).unwrap();
        p.push_option(DhcpOption {
            code: 77,
            data: vec![7; 300],
        });
        let wire = p.emit();
        assert_eq!(wire.len(), p.unpadded_len());
        let back = Packet::parse(&wire).unwrap();
        let parts: Vec<usize> = back
            .options()
            .iter()
            .filter(|o| o.code == 77)
            .map(|o| o.data.len())
            .collect();
        assert_eq!(parts, [255, 45]);
    }

    #[test]
    fn unpadded_len_counts_end() {
        let mut p = Packet::parse(&discover_bytes()).unwrap();
        p.body = Body::Options(vec![DhcpOption {
            code: 53,
            data: vec![1],
        }]);
        assert_eq!(p.unpadded_len(), HEADER_LEN + 4 + 3 + 1);
        assert_eq!(p.emit().len(), MIN_LEN);
    }

    #[test]
    fn edit_options() {
        let mut p = Packet::parse(&discover_bytes()).unwrap();
        assert!(p.push_option(DhcpOption {
            code: opt::RELAY_AGENT_INFORMATION,
            data: vec![1, 1, b'x'],
        }));
        assert!(p.push_option(DhcpOption {
            code: opt::RELAY_AGENT_INFORMATION,
            data: vec![],
        }));
        assert_eq!(p.remove_options(opt::RELAY_AGENT_INFORMATION), 2);
        assert_eq!(p.remove_options(opt::RELAY_AGENT_INFORMATION), 0);
        p.body = Body::Bootp(vec![]);
        assert!(!p.push_option(DhcpOption {
            code: 1,
            data: vec![]
        }));
    }

    #[test]
    fn relay_agent_info() {
        let rai = RelayAgentInfo::parse(&[1, 4, b'e', b't', b'h', b'1', 2, 2, 0xab, 0xcd]).unwrap();
        assert_eq!(rai.circuit_id(), Some(&b"eth1"[..]));
        assert_eq!(rai.remote_id(), Some(&[0xab, 0xcd][..]));
        assert_eq!(rai.sub_option(9), None);
        assert_eq!(
            rai.emit().unwrap(),
            [1, 4, b'e', b't', b'h', b'1', 2, 2, 0xab, 0xcd]
        );
        assert_eq!(
            RelayAgentInfo::with_circuit_id(b"eth1").emit().unwrap(),
            [1, 4, b'e', b't', b'h', b'1']
        );
        assert_eq!(RelayAgentInfo::parse(&[1]), Err(Error::Truncated));
        assert_eq!(RelayAgentInfo::parse(&[1, 3, 0]), Err(Error::Truncated));
        assert_eq!(RelayAgentInfo::parse(&[]), Ok(RelayAgentInfo::default()));
        let big = RelayAgentInfo::with_circuit_id(&[0; 256]);
        assert_eq!(big.emit(), Err(Error::TooLong));
        let wide = RelayAgentInfo {
            sub_options: vec![
                SubOption {
                    code: 1,
                    data: vec![0; 200],
                },
                SubOption {
                    code: 2,
                    data: vec![0; 60],
                },
            ],
        };
        assert_eq!(wide.emit(), Err(Error::TooLong));
    }

    fn random_packet(rng: &mut Rng) -> Packet {
        let mut chaddr = [0; 16];
        chaddr.copy_from_slice(&rng.bytes(16));
        let mut sname = [0; 64];
        sname.copy_from_slice(&rng.bytes(64));
        let mut file = [0; 128];
        file.copy_from_slice(&rng.bytes(128));
        let body = if rng.chance(5) {
            // A BOOTP vendor area that round-trips: at least the 64 bytes
            // padding would add, and not starting with the cookie.
            let len = 64 + rng.below(64);
            let mut vend = rng.bytes(len);
            vend[0] = 0;
            Body::Bootp(vend)
        } else {
            let options = (0..rng.below(12))
                .map(|_| DhcpOption {
                    code: 1 + rng.below(254) as u8,
                    data: {
                        let len = rng.below(256);
                        rng.bytes(len)
                    },
                })
                .collect();
            Body::Options(options)
        };
        Packet {
            op: rng.byte(),
            htype: rng.byte(),
            hlen: rng.byte(),
            hops: rng.byte(),
            xid: rng.next_u64() as u32,
            secs: rng.next_u64() as u16,
            flags: rng.next_u64() as u16,
            ciaddr: Ipv4Addr::from(rng.next_u64() as u32),
            yiaddr: Ipv4Addr::from(rng.next_u64() as u32),
            siaddr: Ipv4Addr::from(rng.next_u64() as u32),
            giaddr: Ipv4Addr::from(rng.next_u64() as u32),
            chaddr,
            sname,
            file,
            body,
        }
    }

    #[test]
    fn round_trip() {
        let mut rng = Rng::new(0x4434);
        for _ in 0..2000 {
            let p = random_packet(&mut rng);
            let wire = p.emit();
            assert_eq!(wire.len(), p.unpadded_len().max(MIN_LEN));
            assert_eq!(Packet::parse(&wire).as_ref(), Ok(&p));
        }
    }

    #[test]
    fn rai_round_trip() {
        let mut rng = Rng::new(82);
        for _ in 0..2000 {
            let mut budget = 255;
            let mut rai = RelayAgentInfo::default();
            while budget > 2 && !rng.chance(4) {
                let len = rng.below(budget - 1);
                rai.sub_options.push(SubOption {
                    code: rng.byte(),
                    data: rng.bytes(len),
                });
                budget -= len + 2;
            }
            let wire = rai.emit().unwrap();
            assert_eq!(RelayAgentInfo::parse(&wire), Ok(rai));
        }
    }

    #[test]
    fn parse_is_total() {
        let mut rng = Rng::new(0xdead);
        let seed = discover_bytes();
        for _ in 0..20000 {
            let input = if rng.chance(2) {
                rng.mutate(&seed)
            } else {
                let len = rng.below(600);
                rng.bytes(len)
            };
            if let Ok(p) = Packet::parse(&input) {
                let back = Packet::parse(&p.emit()).unwrap();
                // DHCP messages come back identical. A short BOOTP vendor
                // area comes back longer, by the padding.
                if matches!(p.body, Body::Options(_)) {
                    assert_eq!(back, p);
                }
                for o in p.options() {
                    let _ = RelayAgentInfo::parse(&o.data);
                }
                let _ = p.merged_options();
                let _ = params::Params::from_packet(&p);
            }
        }
    }
}
