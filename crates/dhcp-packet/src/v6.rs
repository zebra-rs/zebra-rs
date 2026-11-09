//! DHCPv6 messages (RFC 8415 §8, §9): client/server messages and the
//! Relay-forw / Relay-repl envelopes.
//!
//! Options are kept opaque, in wire order. A relay needs exactly two of
//! them, Relay-Message (9) and Interface-ID (18), and both are plain
//! byte strings; the Relay-Message payload is itself a message, which
//! the caller parses with another [`Message::parse`] call when it needs
//! to look inside. [`params`] decodes the options a client uses.

use std::net::Ipv6Addr;

use crate::Error;

pub mod params;

/// UDP port of clients.
pub const CLIENT_PORT: u16 = 546;
/// UDP port of servers and relay agents.
pub const SERVER_PORT: u16 = 547;

/// All_DHCP_Relay_Agents_and_Servers: where clients and relays send.
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
/// All_DHCP_Servers: site scope, used by relays only.
pub const ALL_DHCP_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);

/// Message types (RFC 8415 §7.3, RFC 5007, RFC 7341).
pub mod msg {
    pub const SOLICIT: u8 = 1;
    pub const ADVERTISE: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const CONFIRM: u8 = 4;
    pub const RENEW: u8 = 5;
    pub const REBIND: u8 = 6;
    pub const REPLY: u8 = 7;
    pub const RELEASE: u8 = 8;
    pub const DECLINE: u8 = 9;
    pub const RECONFIGURE: u8 = 10;
    pub const INFORMATION_REQUEST: u8 = 11;
    pub const RELAY_FORW: u8 = 12;
    pub const RELAY_REPL: u8 = 13;
    pub const LEASEQUERY: u8 = 14;
    pub const LEASEQUERY_REPLY: u8 = 15;
    pub const LEASEQUERY_DONE: u8 = 16;
    pub const LEASEQUERY_DATA: u8 = 17;
    pub const DHCPV4_QUERY: u8 = 20;
    pub const DHCPV4_RESPONSE: u8 = 21;
}

/// Option codes (RFC 8415 §21 unless noted).
pub mod opt {
    pub const CLIENT_ID: u16 = 1;
    pub const SERVER_ID: u16 = 2;
    pub const IA_NA: u16 = 3;
    pub const IA_TA: u16 = 4;
    pub const IA_ADDR: u16 = 5;
    pub const ORO: u16 = 6;
    pub const PREFERENCE: u16 = 7;
    pub const ELAPSED_TIME: u16 = 8;
    pub const RELAY_MSG: u16 = 9;
    pub const AUTH: u16 = 11;
    pub const UNICAST: u16 = 12;
    pub const STATUS_CODE: u16 = 13;
    pub const RAPID_COMMIT: u16 = 14;
    pub const USER_CLASS: u16 = 15;
    pub const VENDOR_CLASS: u16 = 16;
    pub const VENDOR_OPTS: u16 = 17;
    pub const INTERFACE_ID: u16 = 18;
    pub const RECONF_MSG: u16 = 19;
    pub const RECONF_ACCEPT: u16 = 20;
    /// RFC 3646.
    pub const DNS_SERVERS: u16 = 23;
    /// RFC 3646.
    pub const DOMAIN_LIST: u16 = 24;
    pub const IA_PD: u16 = 25;
    pub const IA_PREFIX: u16 = 26;
    pub const INFORMATION_REFRESH_TIME: u16 = 32;
    /// RFC 5908.
    pub const NTP_SERVER: u16 = 56;
    pub const SOL_MAX_RT: u16 = 82;
    pub const INF_MAX_RT: u16 = 83;
}

/// Status codes (RFC 8415 §21.13).
pub mod status {
    pub const SUCCESS: u16 = 0;
    pub const UNSPEC_FAIL: u16 = 1;
    pub const NO_ADDRS_AVAIL: u16 = 2;
    pub const NO_BINDING: u16 = 3;
    pub const NOT_ON_LINK: u16 = 4;
    pub const USE_MULTICAST: u16 = 5;
    pub const NO_PREFIX_AVAIL: u16 = 6;
}

/// msg-type, transaction-id.
pub const CLIENT_HEADER_LEN: usize = 4;
/// msg-type, hop-count, link-address, peer-address.
pub const RELAY_HEADER_LEN: usize = 34;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dhcp6Option {
    pub code: u16,
    pub data: Vec<u8>,
}

/// Every type except Relay-forw and Relay-repl.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientMessage {
    pub msg_type: u8,
    /// 24 bits on the wire; `emit` drops the top byte.
    pub transaction_id: u32,
    pub options: Vec<Dhcp6Option>,
}

/// Relay-forw or Relay-repl.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayMessage {
    pub msg_type: u8,
    pub hop_count: u8,
    pub link_address: Ipv6Addr,
    pub peer_address: Ipv6Addr,
    pub options: Vec<Dhcp6Option>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Client(ClientMessage),
    Relay(RelayMessage),
}

/// Relay-forw and Relay-repl use the relay header; every other type,
/// including ones this codec does not know, uses the client header.
pub fn is_relay_type(msg_type: u8) -> bool {
    matches!(msg_type, msg::RELAY_FORW | msg::RELAY_REPL)
}

impl Message {
    pub fn parse(buf: &[u8]) -> Result<Message, Error> {
        let (&msg_type, _) = buf.split_first().ok_or(Error::Short)?;
        if is_relay_type(msg_type) {
            if buf.len() < RELAY_HEADER_LEN {
                return Err(Error::Short);
            }
            let addr_at = |i: usize| {
                let mut octets = [0; 16];
                octets.copy_from_slice(&buf[i..i + 16]);
                Ipv6Addr::from(octets)
            };
            Ok(Message::Relay(RelayMessage {
                msg_type,
                hop_count: buf[1],
                link_address: addr_at(2),
                peer_address: addr_at(18),
                options: parse_options(&buf[RELAY_HEADER_LEN..])?,
            }))
        } else {
            if buf.len() < CLIENT_HEADER_LEN {
                return Err(Error::Short);
            }
            Ok(Message::Client(ClientMessage {
                msg_type,
                transaction_id: u32::from_be_bytes([0, buf[1], buf[2], buf[3]]),
                options: parse_options(&buf[CLIENT_HEADER_LEN..])?,
            }))
        }
    }

    /// Fails only when an option is longer than its 16-bit length field
    /// can describe.
    pub fn emit(&self) -> Result<Vec<u8>, Error> {
        match self {
            Message::Client(m) => m.emit(),
            Message::Relay(m) => m.emit(),
        }
    }

    pub fn msg_type(&self) -> u8 {
        match self {
            Message::Client(m) => m.msg_type,
            Message::Relay(m) => m.msg_type,
        }
    }

    pub fn options(&self) -> &[Dhcp6Option] {
        match self {
            Message::Client(m) => &m.options,
            Message::Relay(m) => &m.options,
        }
    }
}

impl ClientMessage {
    /// A message with no options yet.
    pub fn new(msg_type: u8, transaction_id: u32) -> ClientMessage {
        ClientMessage {
            msg_type,
            transaction_id,
            options: Vec::new(),
        }
    }

    /// The first instance of `code`.
    pub fn option(&self, code: u16) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|o| o.code == code)
            .map(|o| o.data.as_slice())
    }

    /// See [`Message::emit`].
    pub fn emit(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![self.msg_type];
        out.extend_from_slice(&self.transaction_id.to_be_bytes()[1..]);
        emit_options(&mut out, &self.options)?;
        Ok(out)
    }
}

impl RelayMessage {
    /// See [`Message::emit`].
    pub fn emit(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![self.msg_type, self.hop_count];
        out.extend_from_slice(&self.link_address.octets());
        out.extend_from_slice(&self.peer_address.octets());
        emit_options(&mut out, &self.options)?;
        Ok(out)
    }

    /// The first instance of `code`.
    pub fn option(&self, code: u16) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|o| o.code == code)
            .map(|o| o.data.as_slice())
    }

    /// The encapsulated message, still encoded.
    pub fn relay_message(&self) -> Option<&[u8]> {
        self.option(opt::RELAY_MSG)
    }

    pub fn interface_id(&self) -> Option<&[u8]> {
        self.option(opt::INTERFACE_ID)
    }
}

/// Options filling `rest` exactly: a message's, or those nested in an
/// option's value (IA_NA, IA_ADDR, …).
pub(crate) fn parse_options(mut rest: &[u8]) -> Result<Vec<Dhcp6Option>, Error> {
    let mut options = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(Error::Truncated);
        }
        let code = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let tail = &rest[4..];
        if tail.len() < len {
            return Err(Error::Truncated);
        }
        let (data, tail) = tail.split_at(len);
        options.push(Dhcp6Option {
            code,
            data: data.to_vec(),
        });
        rest = tail;
    }
    Ok(options)
}

/// Appends `options` in wire form. Fails when a value is longer than the
/// 16-bit length field can describe.
pub(crate) fn emit_options(out: &mut Vec<u8>, options: &[Dhcp6Option]) -> Result<(), Error> {
    for option in options {
        let len = u16::try_from(option.data.len()).map_err(|_| Error::TooLong)?;
        out.extend_from_slice(&option.code.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&option.data);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    /// A Solicit laid out by hand: transaction 0xabcdef, Client ID
    /// (1, a DUID-LL) and Elapsed Time (8).
    fn solicit_bytes() -> Vec<u8> {
        let mut b = vec![msg::SOLICIT, 0xab, 0xcd, 0xef];
        b.extend_from_slice(&[0, 1, 0, 10, 0, 3, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        b.extend_from_slice(&[0, 8, 0, 2, 0, 0]);
        b
    }

    fn relay_forw_bytes() -> Vec<u8> {
        let inner = solicit_bytes();
        let mut b = vec![msg::RELAY_FORW, 0];
        b.extend_from_slice(&"2001:db8:1::1".parse::<Ipv6Addr>().unwrap().octets());
        b.extend_from_slice(
            &"fe80::5054:ff:fe12:3456"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        b.extend_from_slice(&[0, 18, 0, 4]);
        b.extend_from_slice(b"eth1");
        b.extend_from_slice(&[0, 9]);
        b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        b.extend_from_slice(&inner);
        b
    }

    #[test]
    fn parse_solicit() {
        let b = solicit_bytes();
        let m = Message::parse(&b).unwrap();
        let Message::Client(c) = &m else {
            panic!("not a client message")
        };
        assert_eq!(c.msg_type, msg::SOLICIT);
        assert_eq!(c.transaction_id, 0xab_cdef);
        let codes: Vec<u16> = c.options.iter().map(|o| o.code).collect();
        assert_eq!(codes, [1, 8]);
        assert_eq!(m.emit().unwrap(), b);
    }

    #[test]
    fn parse_relay_forw() {
        let b = relay_forw_bytes();
        let m = Message::parse(&b).unwrap();
        let Message::Relay(r) = &m else {
            panic!("not a relay message")
        };
        assert_eq!(r.msg_type, msg::RELAY_FORW);
        assert_eq!(r.hop_count, 0);
        assert_eq!(r.link_address, "2001:db8:1::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(r.interface_id(), Some(&b"eth1"[..]));
        assert_eq!(r.relay_message(), Some(&solicit_bytes()[..]));
        assert_eq!(m.emit().unwrap(), b);
        let inner = Message::parse(r.relay_message().unwrap()).unwrap();
        assert_eq!(inner.msg_type(), msg::SOLICIT);
    }

    #[test]
    fn malformed() {
        assert_eq!(Message::parse(&[]), Err(Error::Short));
        assert_eq!(Message::parse(&[msg::SOLICIT, 0, 0]), Err(Error::Short));
        assert_eq!(Message::parse(&[msg::RELAY_REPL; 33]), Err(Error::Short));
        let b = solicit_bytes();
        // Cut inside the Client ID value, then inside an option header.
        assert_eq!(Message::parse(&b[..10]), Err(Error::Truncated));
        assert_eq!(Message::parse(&b[..6]), Err(Error::Truncated));
        // A header with no options is fine.
        assert!(Message::parse(&b[..4]).is_ok());
        assert!(Message::parse(&relay_forw_bytes()[..RELAY_HEADER_LEN]).is_ok());
    }

    #[test]
    fn too_long() {
        let m = Message::Client(ClientMessage {
            msg_type: msg::SOLICIT,
            transaction_id: 1,
            options: vec![Dhcp6Option {
                code: 1,
                data: vec![0; 65536],
            }],
        });
        assert_eq!(m.emit(), Err(Error::TooLong));
    }

    fn random_options(rng: &mut Rng) -> Vec<Dhcp6Option> {
        (0..rng.below(8))
            .map(|_| Dhcp6Option {
                code: rng.next_u64() as u16,
                data: {
                    let len = rng.below(300);
                    rng.bytes(len)
                },
            })
            .collect()
    }

    #[test]
    fn round_trip() {
        let mut rng = Rng::new(0x0647);
        for _ in 0..2000 {
            let m = if rng.chance(2) {
                Message::Relay(RelayMessage {
                    msg_type: if rng.chance(2) {
                        msg::RELAY_FORW
                    } else {
                        msg::RELAY_REPL
                    },
                    hop_count: rng.byte(),
                    link_address: Ipv6Addr::from(u128::from(rng.next_u64()) << 64),
                    peer_address: Ipv6Addr::from(u128::from(rng.next_u64())),
                    options: random_options(&mut rng),
                })
            } else {
                let mut msg_type = rng.byte();
                if is_relay_type(msg_type) {
                    msg_type = msg::SOLICIT;
                }
                Message::Client(ClientMessage {
                    msg_type,
                    transaction_id: rng.next_u64() as u32 & 0xff_ffff,
                    options: random_options(&mut rng),
                })
            };
            let wire = m.emit().unwrap();
            assert_eq!(Message::parse(&wire).as_ref(), Ok(&m));
        }
    }

    #[test]
    fn parse_is_total() {
        let mut rng = Rng::new(0xbeef);
        let seeds = [solicit_bytes(), relay_forw_bytes()];
        for i in 0..20000 {
            let input = if rng.chance(2) {
                rng.mutate(&seeds[i % 2])
            } else {
                let len = rng.below(200);
                rng.bytes(len)
            };
            if let Ok(m) = Message::parse(&input) {
                assert_eq!(m.emit().unwrap(), input);
                if let Message::Relay(r) = &m
                    && let Some(inner) = r.relay_message()
                {
                    let _ = Message::parse(inner);
                }
                let _ = params::Params::from_options(m.options());
            }
        }
    }
}
