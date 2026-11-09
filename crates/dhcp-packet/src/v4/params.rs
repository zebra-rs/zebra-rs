//! DHCPv4 option values: what a client reads from an OFFER, ACK or NAK
//! ([`Params`]), and the options and requests it sends
//! ([`DhcpOption`] constructors, [`Packet::request`]).

use std::net::Ipv4Addr;

use super::{BOOTREQUEST, Body, DhcpOption, HTYPE_ETHERNET, Merged, Packet, opt};
use crate::{Error, name};

/// The lease time that never runs out (RFC 2132 §9.2).
pub const INFINITE: u32 = u32::MAX;

/// One RFC 3442 classless static route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClasslessRoute {
    /// The destination, with the bits past `prefix_len` cleared.
    pub destination: Ipv4Addr,
    pub prefix_len: u8,
    /// `0.0.0.0` is the usual way of saying the destination is on the
    /// link (dhcpcd and systemd-networkd read it so).
    pub router: Ipv4Addr,
}

/// A server's message, decoded: the options a client acts on or shows.
/// Options it does not use are left out. An option that does not decode
/// is left out too and listed in `malformed`, so one bad option does not
/// cost the whole lease; the client decides what it can do without it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Params {
    /// Option 53, see [`super::msg`].
    pub message_type: Option<u8>,
    /// Option 54.
    pub server_id: Option<Ipv4Addr>,
    /// Option 1, as a prefix length; a non-contiguous mask is malformed.
    pub prefix_len: Option<u8>,
    /// Option 3, in the server's order of preference.
    pub routers: Vec<Ipv4Addr>,
    /// Option 6.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Option 15.
    pub domain_name: Option<String>,
    /// Option 119.
    pub domain_search: Vec<String>,
    /// Option 42.
    pub ntp_servers: Vec<Ipv4Addr>,
    /// Option 26; values below the RFC 2132 minimum of 68 are malformed.
    pub interface_mtu: Option<u16>,
    /// Option 28.
    pub broadcast_address: Option<Ipv4Addr>,
    /// Option 51, in seconds; [`INFINITE`] never expires.
    pub lease_time: Option<u32>,
    /// Option 58 (T1), in seconds.
    pub renewal_time: Option<u32>,
    /// Option 59 (T2), in seconds.
    pub rebinding_time: Option<u32>,
    /// Option 121. When present, RFC 3442 has the client ignore `routers`.
    pub classless_routes: Vec<ClasslessRoute>,
    /// Option 56, usually a NAK's reason. Control characters are replaced
    /// and invalid UTF-8 is replaced, so it is safe to log.
    pub message: Option<String>,
    /// Option 61, which RFC 6842 servers echo back.
    pub client_id: Option<Vec<u8>>,
    /// Options present but not decodable, with the reason. Option 52
    /// stands for an overloaded `file` or `sname` that does not parse;
    /// the options field is decoded without it.
    pub malformed: Vec<(u8, Error)>,
}

impl Params {
    /// Decodes `packet`'s options, merged as [`Packet::merged_options`]
    /// describes. Never fails; see `malformed`.
    pub fn from_packet(packet: &Packet) -> Params {
        let mut params = Params::default();
        let options = packet.merged_options().unwrap_or_else(|error| {
            params.malformed.push((opt::OVERLOAD, error));
            let mut merged = Merged::default();
            merged.extend(packet.options());
            merged.options.retain(|o| o.code != opt::OVERLOAD);
            merged.options
        });
        for option in &options {
            if let Err(error) = params.apply(option.code, &option.data) {
                params.malformed.push((option.code, error));
            }
        }
        params
    }

    fn apply(&mut self, code: u8, data: &[u8]) -> Result<(), Error> {
        match code {
            opt::MESSAGE_TYPE => self.message_type = Some(decode_u8(data)?),
            opt::SERVER_ID => self.server_id = Some(decode_address(data)?),
            opt::SUBNET_MASK => self.prefix_len = Some(decode_prefix_len(data)?),
            opt::ROUTER => self.routers = decode_addresses(data)?,
            opt::DNS_SERVER => self.dns_servers = decode_addresses(data)?,
            opt::DOMAIN_NAME => self.domain_name = Some(decode_text(data)?),
            opt::DOMAIN_SEARCH => self.domain_search = name::decode_list(data, true)?,
            opt::NTP_SERVER => self.ntp_servers = decode_addresses(data)?,
            opt::INTERFACE_MTU => {
                let mtu = decode_u16(data)?;
                if mtu < 68 {
                    return Err(Error::Invalid);
                }
                self.interface_mtu = Some(mtu);
            }
            opt::BROADCAST_ADDRESS => self.broadcast_address = Some(decode_address(data)?),
            opt::LEASE_TIME => self.lease_time = Some(decode_u32(data)?),
            opt::RENEWAL_TIME => self.renewal_time = Some(decode_u32(data)?),
            opt::REBINDING_TIME => self.rebinding_time = Some(decode_u32(data)?),
            opt::CLASSLESS_STATIC_ROUTE => {
                self.classless_routes = decode_classless_routes(data)?;
            }
            opt::MESSAGE => self.message = Some(decode_message(data)),
            opt::CLIENT_ID => {
                // A type octet and at least one octet of identifier.
                if data.len() < 2 {
                    return Err(Error::Length);
                }
                self.client_id = Some(data.to_vec());
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn decode_u8(data: &[u8]) -> Result<u8, Error> {
    match data {
        [b] => Ok(*b),
        _ => Err(Error::Length),
    }
}

pub fn decode_u16(data: &[u8]) -> Result<u16, Error> {
    let bytes: [u8; 2] = data.try_into().map_err(|_| Error::Length)?;
    Ok(u16::from_be_bytes(bytes))
}

pub fn decode_u32(data: &[u8]) -> Result<u32, Error> {
    let bytes: [u8; 4] = data.try_into().map_err(|_| Error::Length)?;
    Ok(u32::from_be_bytes(bytes))
}

pub fn decode_address(data: &[u8]) -> Result<Ipv4Addr, Error> {
    let bytes: [u8; 4] = data.try_into().map_err(|_| Error::Length)?;
    Ok(Ipv4Addr::from(bytes))
}

/// One or more addresses (RFC 2132's lists all have a minimum length of 4).
pub fn decode_addresses(data: &[u8]) -> Result<Vec<Ipv4Addr>, Error> {
    let (addresses, rest) = data.as_chunks::<4>();
    if addresses.is_empty() || !rest.is_empty() {
        return Err(Error::Length);
    }
    Ok(addresses.iter().map(|&a| Ipv4Addr::from(a)).collect())
}

/// A subnet mask as a prefix length.
pub fn decode_prefix_len(data: &[u8]) -> Result<u8, Error> {
    let mask = u32::from(decode_address(data)?);
    if mask.leading_ones() != mask.count_ones() {
        return Err(Error::Invalid);
    }
    Ok(mask.leading_ones() as u8)
}

/// A host or domain name (options 12 and 15). RFC 2132 says no NUL
/// terminator, but servers send one often enough that trailing NULs are
/// dropped. What is left must be printable ASCII without spaces.
pub fn decode_text(data: &[u8]) -> Result<String, Error> {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let text = &data[..end];
    if text.is_empty() || !text.iter().all(u8::is_ascii_graphic) {
        return Err(Error::Invalid);
    }
    Ok(text.iter().map(|&b| char::from(b)).collect())
}

/// Free text for a log line: invalid UTF-8 and control characters are
/// replaced rather than refused.
fn decode_message(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// Option 121's value: one or more descriptors, each a width, the
/// significant octets of the destination, and the router (RFC 3442 §3).
pub fn decode_classless_routes(mut data: &[u8]) -> Result<Vec<ClasslessRoute>, Error> {
    if data.is_empty() {
        return Err(Error::Length);
    }
    let mut routes = Vec::new();
    while let Some((&width, rest)) = data.split_first() {
        if width > 32 {
            return Err(Error::Invalid);
        }
        let significant = usize::from(width).div_ceil(8);
        if rest.len() < significant + 4 {
            return Err(Error::Truncated);
        }
        let mut destination = [0; 4];
        destination[..significant].copy_from_slice(&rest[..significant]);
        let mask = u32::MAX.checked_shl(32 - u32::from(width)).unwrap_or(0);
        routes.push(ClasslessRoute {
            destination: Ipv4Addr::from(u32::from_be_bytes(destination) & mask),
            prefix_len: width,
            router: decode_address(&rest[significant..significant + 4])?,
        });
        data = &rest[significant + 4..];
    }
    Ok(routes)
}

/// Option 121's value for `routes`; widths over 32 are clamped to 32.
pub fn encode_classless_routes(routes: &[ClasslessRoute]) -> Vec<u8> {
    let mut out = Vec::new();
    for route in routes {
        let width = route.prefix_len.min(32);
        let significant = usize::from(width).div_ceil(8);
        out.push(width);
        out.extend_from_slice(&route.destination.octets()[..significant]);
        out.extend_from_slice(&route.router.octets());
    }
    out
}

impl DhcpOption {
    pub fn new(code: u8, data: impl Into<Vec<u8>>) -> DhcpOption {
        DhcpOption {
            code,
            data: data.into(),
        }
    }

    /// Option 53.
    pub fn message_type(msg_type: u8) -> DhcpOption {
        DhcpOption::new(opt::MESSAGE_TYPE, [msg_type])
    }

    /// An option holding one address: 50 (requested address), 54
    /// (server identifier), 1, 28, …
    pub fn address(code: u8, address: Ipv4Addr) -> DhcpOption {
        DhcpOption::new(code, address.octets())
    }

    /// Option 55.
    pub fn parameter_request_list(codes: &[u8]) -> DhcpOption {
        DhcpOption::new(opt::PARAMETER_REQUEST_LIST, codes)
    }

    /// Option 57; RFC 2132 §9.10 sets the floor at 576.
    pub fn max_message_size(size: u16) -> DhcpOption {
        DhcpOption::new(opt::MAX_MESSAGE_SIZE, size.max(576).to_be_bytes())
    }

    /// Option 77 in RFC 3004's form: each class as a length octet and its
    /// bytes. Fails on an empty class or one longer than 255 bytes.
    pub fn user_class(classes: &[&[u8]]) -> Result<DhcpOption, Error> {
        let mut data = Vec::new();
        for class in classes {
            let len = u8::try_from(class.len()).map_err(|_| Error::TooLong)?;
            if len == 0 {
                return Err(Error::Invalid);
            }
            data.push(len);
            data.extend_from_slice(class);
        }
        Ok(DhcpOption::new(opt::USER_CLASS, data))
    }
}

impl Packet {
    /// A client's BOOTREQUEST from an Ethernet interface: `chaddr` set to
    /// `mac`, every address zero, no flags, and option 53 as the only
    /// option. The caller sets `flags`, `ciaddr` and `secs`, and pushes
    /// the rest of the options.
    pub fn request(msg_type: u8, xid: u32, mac: [u8; 6]) -> Packet {
        let mut chaddr = [0; 16];
        chaddr[..6].copy_from_slice(&mac);
        Packet {
            op: BOOTREQUEST,
            htype: HTYPE_ETHERNET,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: [0; 64],
            file: [0; 128],
            body: Body::Options(vec![DhcpOption::message_type(msg_type)]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BOOTREPLY, msg};
    use super::*;
    use crate::testutil::Rng;

    fn addr(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn reply(options: Vec<DhcpOption>) -> Packet {
        let mut p = Packet::request(msg::ACK, 7, [2, 0, 0, 0, 0, 1]);
        p.op = BOOTREPLY;
        p.body = Body::Options(options);
        p
    }

    /// RFC 3442 §2's examples of descriptor encodings, with a router each.
    #[test]
    fn rfc3442_descriptors() {
        let r = [192, 0, 2, 1];
        let mut b = Vec::new();
        for descriptor in [
            &[0][..],
            &[8, 10],
            &[16, 10, 17],
            &[24, 10, 27, 129],
            &[25, 10, 229, 0, 128],
            &[32, 10, 198, 122, 47],
        ] {
            b.extend_from_slice(descriptor);
            b.extend_from_slice(&r);
        }
        let routes = decode_classless_routes(&b).unwrap();
        let got: Vec<(Ipv4Addr, u8)> = routes
            .iter()
            .map(|r| (r.destination, r.prefix_len))
            .collect();
        assert_eq!(
            got,
            [
                (addr("0.0.0.0"), 0),
                (addr("10.0.0.0"), 8),
                (addr("10.17.0.0"), 16),
                (addr("10.27.129.0"), 24),
                (addr("10.229.0.128"), 25),
                (addr("10.198.122.47"), 32),
            ]
        );
        assert!(routes.iter().all(|r| r.router == addr("192.0.2.1")));
        assert_eq!(encode_classless_routes(&routes), b);
    }

    #[test]
    fn classless_route_bits_past_the_width_are_cleared() {
        let routes = decode_classless_routes(&[9, 10, 255, 0, 0, 0, 0]).unwrap();
        assert_eq!(routes[0].destination, addr("10.128.0.0"));
        assert_eq!(decode_classless_routes(&[]), Err(Error::Length));
        assert_eq!(
            decode_classless_routes(&[33, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::Invalid)
        );
        assert_eq!(
            decode_classless_routes(&[24, 10, 0, 0, 1, 2, 3]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn ack() {
        let mut search = name::encode("example.com").unwrap();
        search.extend_from_slice(&[3, b'l', b'a', b'b', 0xc0, 0]);
        let p = reply(vec![
            DhcpOption::message_type(msg::ACK),
            DhcpOption::address(opt::SERVER_ID, addr("192.0.2.254")),
            DhcpOption::new(opt::LEASE_TIME, 3600u32.to_be_bytes()),
            DhcpOption::new(opt::RENEWAL_TIME, 1800u32.to_be_bytes()),
            DhcpOption::new(opt::REBINDING_TIME, 3150u32.to_be_bytes()),
            DhcpOption::address(opt::SUBNET_MASK, addr("255.255.255.0")),
            DhcpOption::new(opt::ROUTER, [192, 0, 2, 1, 192, 0, 2, 2]),
            DhcpOption::new(opt::DNS_SERVER, [198, 51, 100, 53]),
            DhcpOption::new(opt::DOMAIN_NAME, *b"example.com\0"),
            DhcpOption::new(opt::DOMAIN_SEARCH, search),
            DhcpOption::new(opt::NTP_SERVER, [198, 51, 100, 123]),
            DhcpOption::new(opt::INTERFACE_MTU, 1492u16.to_be_bytes()),
            DhcpOption::address(opt::BROADCAST_ADDRESS, addr("192.0.2.255")),
            DhcpOption::new(opt::CLASSLESS_STATIC_ROUTE, [0, 192, 0, 2, 1]),
            DhcpOption::new(opt::CLIENT_ID, [1, 2, 0, 0, 0, 0, 1]),
            DhcpOption::new(250, [1, 2, 3]),
        ]);
        let params = Params::from_packet(&Packet::parse(&p.emit()).unwrap());
        assert_eq!(
            params,
            Params {
                message_type: Some(msg::ACK),
                server_id: Some(addr("192.0.2.254")),
                prefix_len: Some(24),
                routers: vec![addr("192.0.2.1"), addr("192.0.2.2")],
                dns_servers: vec![addr("198.51.100.53")],
                domain_name: Some("example.com".into()),
                domain_search: vec!["example.com".into(), "lab.example.com".into()],
                ntp_servers: vec![addr("198.51.100.123")],
                interface_mtu: Some(1492),
                broadcast_address: Some(addr("192.0.2.255")),
                lease_time: Some(3600),
                renewal_time: Some(1800),
                rebinding_time: Some(3150),
                classless_routes: vec![ClasslessRoute {
                    destination: addr("0.0.0.0"),
                    prefix_len: 0,
                    router: addr("192.0.2.1"),
                }],
                message: None,
                client_id: Some(vec![1, 2, 0, 0, 0, 0, 1]),
                malformed: vec![],
            }
        );
    }

    #[test]
    fn nak_message_is_sanitized() {
        let p = reply(vec![
            DhcpOption::message_type(msg::NAK),
            DhcpOption::new(opt::MESSAGE, *b"wrong\nnet\xff"),
        ]);
        let params = Params::from_packet(&p);
        assert_eq!(params.message_type, Some(msg::NAK));
        assert_eq!(params.message.as_deref(), Some("wrong\u{fffd}net\u{fffd}"));
    }

    #[test]
    fn one_bad_option_costs_only_itself() {
        let p = reply(vec![
            DhcpOption::message_type(msg::OFFER),
            DhcpOption::new(opt::ROUTER, [192, 0, 2, 1, 9]),
            DhcpOption::address(opt::SUBNET_MASK, addr("255.0.255.0")),
            DhcpOption::new(opt::INTERFACE_MTU, 67u16.to_be_bytes()),
            DhcpOption::new(opt::DOMAIN_NAME, *b"has space"),
            DhcpOption::new(opt::DOMAIN_SEARCH, [0xc0, 0]),
            DhcpOption::new(opt::CLIENT_ID, [1]),
            DhcpOption::new(opt::MESSAGE_TYPE, [1, 2]),
            DhcpOption::new(opt::LEASE_TIME, 60u32.to_be_bytes()),
        ]);
        let params = Params::from_packet(&p);
        assert_eq!(params.lease_time, Some(60));
        assert!(params.routers.is_empty());
        assert_eq!(params.prefix_len, None);
        // Option 53 appears twice and is merged into [2, 1, 2] (RFC 3396),
        // which is malformed as a message type.
        assert_eq!(params.message_type, None);
        assert_eq!(
            params.malformed,
            [
                (opt::MESSAGE_TYPE, Error::Length),
                (opt::ROUTER, Error::Length),
                (opt::SUBNET_MASK, Error::Invalid),
                (opt::INTERFACE_MTU, Error::Invalid),
                (opt::DOMAIN_NAME, Error::Invalid),
                (opt::DOMAIN_SEARCH, Error::Invalid),
                (opt::CLIENT_ID, Error::Length),
            ]
        );
    }

    #[test]
    fn split_and_overloaded_options() {
        // Option 121 split in two (RFC 3396), option 6 in `file` and
        // option 15 in `sname` under overload 3.
        let mut p = reply(vec![
            DhcpOption::message_type(msg::ACK),
            DhcpOption::new(opt::CLASSLESS_STATIC_ROUTE, [24, 10, 0]),
            DhcpOption::new(opt::OVERLOAD, [3]),
            DhcpOption::new(opt::CLASSLESS_STATIC_ROUTE, [0, 192, 0, 2, 1]),
        ]);
        p.file[..7].copy_from_slice(&[opt::DNS_SERVER, 4, 198, 51, 100, 53, opt::END]);
        p.sname[..6].copy_from_slice(&[opt::DOMAIN_NAME, 3, b'l', b'a', b'b', opt::END]);
        let codes: Vec<u8> = p.merged_options().unwrap().iter().map(|o| o.code).collect();
        assert_eq!(
            codes,
            [
                opt::MESSAGE_TYPE,
                opt::CLASSLESS_STATIC_ROUTE,
                opt::DNS_SERVER,
                opt::DOMAIN_NAME
            ]
        );
        let params = Params::from_packet(&p);
        assert_eq!(params.classless_routes.len(), 1);
        assert_eq!(params.classless_routes[0].destination, addr("10.0.0.0"));
        assert_eq!(params.dns_servers, [addr("198.51.100.53")]);
        assert_eq!(params.domain_name.as_deref(), Some("lab"));
        assert_eq!(params.malformed, []);

        // Without option 52 the same fields are ignored.
        p.remove_options(opt::OVERLOAD);
        assert!(Params::from_packet(&p).dns_servers.is_empty());

        // An overloaded field that does not parse is reported, and the
        // options field is still decoded.
        p.push_option(DhcpOption::new(opt::OVERLOAD, [1]));
        p.file[..3].copy_from_slice(&[opt::DNS_SERVER, 200, 1]);
        assert_eq!(p.merged_options(), Err(Error::Truncated));
        let params = Params::from_packet(&p);
        assert_eq!(params.malformed, [(opt::OVERLOAD, Error::Truncated)]);
        assert_eq!(params.classless_routes.len(), 1);
    }

    #[test]
    fn request() {
        let mut p = Packet::request(msg::DISCOVER, 0xfeed, [2, 0, 0, 0, 0, 1]);
        p.push_option(DhcpOption::parameter_request_list(&[1, 3, 6]));
        p.push_option(DhcpOption::max_message_size(100));
        p.push_option(DhcpOption::user_class(&[b"wan", b"x"]).unwrap());
        let back = Packet::parse(&p.emit()).unwrap();
        assert_eq!(back.op, BOOTREQUEST);
        assert_eq!(back.message_type(), Some(msg::DISCOVER));
        assert_eq!(back.ethernet_address(), Some([2, 0, 0, 0, 0, 1]));
        assert_eq!(back.option(opt::MAX_MESSAGE_SIZE).unwrap().data, [2, 64]);
        assert_eq!(
            back.option(opt::USER_CLASS).unwrap().data,
            [3, b'w', b'a', b'n', 1, b'x']
        );
        assert_eq!(DhcpOption::user_class(&[b""]), Err(Error::Invalid));
        assert_eq!(DhcpOption::user_class(&[&[0; 256]]), Err(Error::TooLong));
    }

    #[test]
    fn scalars() {
        assert_eq!(decode_prefix_len(&[255, 255, 255, 255]), Ok(32));
        assert_eq!(decode_prefix_len(&[0, 0, 0, 0]), Ok(0));
        assert_eq!(decode_prefix_len(&[255, 255, 254, 0]), Ok(23));
        assert_eq!(decode_prefix_len(&[0, 255, 255, 255]), Err(Error::Invalid));
        assert_eq!(decode_prefix_len(&[255, 255, 255]), Err(Error::Length));
        assert_eq!(decode_addresses(&[]), Err(Error::Length));
        assert_eq!(decode_u32(&[0, 0, 1]), Err(Error::Length));
        assert_eq!(decode_text(b"\0\0"), Err(Error::Invalid));
    }

    fn random_address(rng: &mut Rng) -> Ipv4Addr {
        Ipv4Addr::from(rng.next_u64() as u32)
    }

    fn random_addresses(rng: &mut Rng) -> Vec<Ipv4Addr> {
        (0..1 + rng.below(4)).map(|_| random_address(rng)).collect()
    }

    /// Typed values encoded as options and decoded again come back equal.
    #[test]
    fn round_trip() {
        let mut rng = Rng::new(2132);
        for _ in 0..2000 {
            let mut want = Params {
                message_type: Some(1 + rng.below(8) as u8),
                server_id: Some(random_address(&mut rng)),
                prefix_len: Some(rng.below(33) as u8),
                routers: random_addresses(&mut rng),
                dns_servers: random_addresses(&mut rng),
                domain_name: Some("example.net".into()),
                domain_search: vec!["a.example".into(), "b.example".into()],
                ntp_servers: random_addresses(&mut rng),
                interface_mtu: Some(68 + rng.below(9000) as u16),
                broadcast_address: Some(random_address(&mut rng)),
                lease_time: Some(rng.next_u64() as u32),
                renewal_time: Some(rng.next_u64() as u32),
                rebinding_time: Some(rng.next_u64() as u32),
                classless_routes: (0..1 + rng.below(6))
                    .map(|_| {
                        let prefix_len = rng.below(33) as u8;
                        let mask = u32::MAX
                            .checked_shl(32 - u32::from(prefix_len))
                            .unwrap_or(0);
                        ClasslessRoute {
                            destination: Ipv4Addr::from(rng.next_u64() as u32 & mask),
                            prefix_len,
                            router: random_address(&mut rng),
                        }
                    })
                    .collect(),
                message: None,
                client_id: Some({
                    let len = 2 + rng.below(20);
                    rng.bytes(len)
                }),
                malformed: vec![],
            };
            let mask = u32::MAX
                .checked_shl(32 - u32::from(want.prefix_len.unwrap()))
                .unwrap_or(0);
            let routes = encode_classless_routes(&want.classless_routes);
            let mut options = vec![
                DhcpOption::message_type(want.message_type.unwrap()),
                DhcpOption::address(opt::SERVER_ID, want.server_id.unwrap()),
                DhcpOption::address(opt::SUBNET_MASK, Ipv4Addr::from(mask)),
                DhcpOption::new(opt::ROUTER, flatten(&want.routers)),
                DhcpOption::new(opt::DNS_SERVER, flatten(&want.dns_servers)),
                DhcpOption::new(opt::DOMAIN_NAME, *b"example.net"),
                DhcpOption::new(
                    opt::DOMAIN_SEARCH,
                    name::encode_list(&want.domain_search).unwrap(),
                ),
                DhcpOption::new(opt::NTP_SERVER, flatten(&want.ntp_servers)),
                DhcpOption::new(
                    opt::INTERFACE_MTU,
                    want.interface_mtu.unwrap().to_be_bytes(),
                ),
                DhcpOption::address(opt::BROADCAST_ADDRESS, want.broadcast_address.unwrap()),
                DhcpOption::new(opt::LEASE_TIME, want.lease_time.unwrap().to_be_bytes()),
                DhcpOption::new(opt::RENEWAL_TIME, want.renewal_time.unwrap().to_be_bytes()),
                DhcpOption::new(
                    opt::REBINDING_TIME,
                    want.rebinding_time.unwrap().to_be_bytes(),
                ),
                DhcpOption::new(opt::CLASSLESS_STATIC_ROUTE, routes),
                DhcpOption::new(opt::CLIENT_ID, want.client_id.clone().unwrap()),
            ];
            if rng.chance(2) {
                want.message = Some("ok".into());
                options.push(DhcpOption::new(opt::MESSAGE, *b"ok"));
            }
            // Any order, and the long ones split on the wire by `emit`.
            for i in (1..options.len()).rev() {
                options.swap(i, rng.below(i + 1));
            }
            let wire = reply(options).emit();
            assert_eq!(Params::from_packet(&Packet::parse(&wire).unwrap()), want);
        }
    }

    fn flatten(addresses: &[Ipv4Addr]) -> Vec<u8> {
        addresses.iter().flat_map(|a| a.octets()).collect()
    }

    /// Every decoded code with random values: no panic, and a value is
    /// either decoded or reported, never both.
    #[test]
    fn decode_is_total() {
        let codes = [
            1, 3, 6, 12, 15, 26, 28, 42, 51, 52, 53, 54, 56, 58, 59, 61, 119, 121,
        ];
        let mut rng = Rng::new(3396);
        for _ in 0..20000 {
            let options = (0..1 + rng.below(4))
                .map(|_| {
                    let len = rng.below(40);
                    DhcpOption::new(codes[rng.below(codes.len())], rng.bytes(len))
                })
                .collect();
            let mut p = reply(options);
            if rng.chance(4) {
                p.file.copy_from_slice(&rng.bytes(128));
                p.sname.copy_from_slice(&rng.bytes(64));
            }
            let params = Params::from_packet(&p);
            if let Some(domain) = &params.domain_name {
                assert!(!domain.is_empty());
            }
        }
    }
}
