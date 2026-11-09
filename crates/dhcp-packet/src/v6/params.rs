//! DHCPv6 option values (RFC 8415 §21): what a client reads from an
//! Advertise or Reply ([`Params`]), the identity associations it sends
//! and gets back ([`IaNa`], [`IaPd`]), and the small options and
//! identifiers it sends ([`Dhcp6Option`] constructors, [`duid`]).

use std::net::Ipv6Addr;

use super::{Dhcp6Option, emit_options, opt, parse_options, status};
use crate::{Error, name};

/// A lifetime or T1/T2 that never runs out (RFC 8415 §7.7).
pub const INFINITY: u32 = u32::MAX;

/// DHCP Unique Identifiers (RFC 8415 §11).
pub mod duid {
    pub const LLT: u16 = 1;
    pub const EN: u16 = 2;
    pub const LL: u16 = 3;
    /// RFC 6355.
    pub const UUID: u16 = 4;

    /// The IANA hardware type of Ethernet.
    pub const HTYPE_ETHERNET: u16 = 1;

    /// The longest DUID, type code included (RFC 8415 §11.1).
    pub const MAX_LEN: usize = 130;

    /// DUID-LLT (§11.2). `time` counts seconds since midnight UTC,
    /// 1 January 2000, modulo 2^32.
    pub fn llt(hardware_type: u16, time: u32, link_layer: &[u8]) -> Vec<u8> {
        let mut out = LLT.to_be_bytes().to_vec();
        out.extend_from_slice(&hardware_type.to_be_bytes());
        out.extend_from_slice(&time.to_be_bytes());
        out.extend_from_slice(link_layer);
        out
    }

    /// DUID-LL (§11.4).
    pub fn ll(hardware_type: u16, link_layer: &[u8]) -> Vec<u8> {
        let mut out = LL.to_be_bytes().to_vec();
        out.extend_from_slice(&hardware_type.to_be_bytes());
        out.extend_from_slice(link_layer);
        out
    }
}

/// NTP server sub-option codes (RFC 5908 §4).
pub mod ntp {
    pub const SRV_ADDR: u16 = 1;
    pub const MC_ADDR: u16 = 2;
    pub const SRV_FQDN: u16 = 3;
}

/// Status Code (13): a code from [`status`] and a message for people.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusCode {
    pub code: u16,
    /// Invalid UTF-8 and control characters are replaced, so it is safe
    /// to log.
    pub message: String,
}

impl StatusCode {
    pub fn new(code: u16, message: impl Into<String>) -> StatusCode {
        StatusCode {
            code,
            message: message.into(),
        }
    }

    pub fn parse(data: &[u8]) -> Result<StatusCode, Error> {
        let (code, message) = data.split_first_chunk::<2>().ok_or(Error::Length)?;
        Ok(StatusCode {
            code: u16::from_be_bytes(*code),
            message: String::from_utf8_lossy(message)
                .chars()
                .map(|c| if c.is_control() { '\u{fffd}' } else { c })
                .collect(),
        })
    }

    pub fn emit(&self) -> Dhcp6Option {
        let mut data = self.code.to_be_bytes().to_vec();
        data.extend_from_slice(self.message.as_bytes());
        Dhcp6Option::new(opt::STATUS_CODE, data)
    }

    pub fn is_success(&self) -> bool {
        self.code == status::SUCCESS
    }
}

/// IA Address (5): one address of an IA_NA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IaAddress {
    pub address: Ipv6Addr,
    pub preferred: u32,
    pub valid: u32,
    pub status: Option<StatusCode>,
    /// Other nested options, as received.
    pub other: Vec<Dhcp6Option>,
}

impl IaAddress {
    pub fn parse(data: &[u8]) -> Result<IaAddress, Error> {
        if data.len() < 24 {
            return Err(Error::Length);
        }
        let (status, other) = nested(&data[24..])?;
        Ok(IaAddress {
            address: address_at(data, 0),
            preferred: u32_at(data, 16),
            valid: u32_at(data, 20),
            status,
            other,
        })
    }

    pub fn emit(&self) -> Result<Dhcp6Option, Error> {
        let mut data = self.address.octets().to_vec();
        data.extend_from_slice(&self.preferred.to_be_bytes());
        data.extend_from_slice(&self.valid.to_be_bytes());
        emit_nested(&mut data, &self.status, &self.other)?;
        Ok(Dhcp6Option::new(opt::IA_ADDR, data))
    }
}

/// IA Prefix (26): one prefix of an IA_PD, or a hint in a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IaPrefix {
    /// As received: a server may leave bits set past `prefix_len`.
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub preferred: u32,
    pub valid: u32,
    pub status: Option<StatusCode>,
    pub other: Vec<Dhcp6Option>,
}

impl IaPrefix {
    /// A hint for a Solicit: "a prefix of this length, please".
    pub fn hint(prefix_len: u8) -> IaPrefix {
        IaPrefix {
            prefix: Ipv6Addr::UNSPECIFIED,
            prefix_len,
            preferred: 0,
            valid: 0,
            status: None,
            other: Vec::new(),
        }
    }

    pub fn parse(data: &[u8]) -> Result<IaPrefix, Error> {
        if data.len() < 25 {
            return Err(Error::Length);
        }
        let prefix_len = data[8];
        if prefix_len > 128 {
            return Err(Error::Invalid);
        }
        let (status, other) = nested(&data[25..])?;
        Ok(IaPrefix {
            prefix: address_at(data, 9),
            prefix_len,
            preferred: u32_at(data, 0),
            valid: u32_at(data, 4),
            status,
            other,
        })
    }

    pub fn emit(&self) -> Result<Dhcp6Option, Error> {
        let mut data = self.preferred.to_be_bytes().to_vec();
        data.extend_from_slice(&self.valid.to_be_bytes());
        data.push(self.prefix_len);
        data.extend_from_slice(&self.prefix.octets());
        emit_nested(&mut data, &self.status, &self.other)?;
        Ok(Dhcp6Option::new(opt::IA_PREFIX, data))
    }
}

/// IA_NA (3): non-temporary addresses under one IAID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IaNa {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub addresses: Vec<IaAddress>,
    pub status: Option<StatusCode>,
    pub other: Vec<Dhcp6Option>,
}

impl IaNa {
    /// An empty IA_NA, as a client sends it in a Solicit.
    pub fn new(iaid: u32) -> IaNa {
        IaNa {
            iaid,
            t1: 0,
            t2: 0,
            addresses: Vec::new(),
            status: None,
            other: Vec::new(),
        }
    }

    pub fn parse(data: &[u8]) -> Result<IaNa, Error> {
        let (iaid, t1, t2, rest) = ia_header(data)?;
        let mut ia = IaNa::new(iaid);
        ia.t1 = t1;
        ia.t2 = t2;
        for option in parse_options(rest)? {
            match option.code {
                opt::IA_ADDR => ia.addresses.push(IaAddress::parse(&option.data)?),
                opt::STATUS_CODE if ia.status.is_none() => {
                    ia.status = Some(StatusCode::parse(&option.data)?);
                }
                _ => ia.other.push(option),
            }
        }
        Ok(ia)
    }

    pub fn emit(&self) -> Result<Dhcp6Option, Error> {
        let mut data = ia_header_bytes(self.iaid, self.t1, self.t2);
        for address in &self.addresses {
            emit_options(&mut data, &[address.emit()?])?;
        }
        emit_nested(&mut data, &self.status, &self.other)?;
        Ok(Dhcp6Option::new(opt::IA_NA, data))
    }
}

/// IA_PD (25, RFC 8415 §21.21): delegated prefixes under one IAID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IaPd {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub prefixes: Vec<IaPrefix>,
    pub status: Option<StatusCode>,
    pub other: Vec<Dhcp6Option>,
}

impl IaPd {
    /// An empty IA_PD; push an [`IaPrefix::hint`] to ask for a length.
    pub fn new(iaid: u32) -> IaPd {
        IaPd {
            iaid,
            t1: 0,
            t2: 0,
            prefixes: Vec::new(),
            status: None,
            other: Vec::new(),
        }
    }

    pub fn parse(data: &[u8]) -> Result<IaPd, Error> {
        let (iaid, t1, t2, rest) = ia_header(data)?;
        let mut ia = IaPd::new(iaid);
        ia.t1 = t1;
        ia.t2 = t2;
        for option in parse_options(rest)? {
            match option.code {
                opt::IA_PREFIX => ia.prefixes.push(IaPrefix::parse(&option.data)?),
                opt::STATUS_CODE if ia.status.is_none() => {
                    ia.status = Some(StatusCode::parse(&option.data)?);
                }
                _ => ia.other.push(option),
            }
        }
        Ok(ia)
    }

    pub fn emit(&self) -> Result<Dhcp6Option, Error> {
        let mut data = ia_header_bytes(self.iaid, self.t1, self.t2);
        for prefix in &self.prefixes {
            emit_options(&mut data, &[prefix.emit()?])?;
        }
        emit_nested(&mut data, &self.status, &self.other)?;
        Ok(Dhcp6Option::new(opt::IA_PD, data))
    }
}

/// One entry of the NTP Server option (56, RFC 5908).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NtpServer {
    Address(Ipv6Addr),
    Multicast(Ipv6Addr),
    Fqdn(String),
}

/// Option 56's value: one or more sub-options. Unknown sub-options are
/// skipped.
pub fn decode_ntp_servers(data: &[u8]) -> Result<Vec<NtpServer>, Error> {
    if data.is_empty() {
        return Err(Error::Length);
    }
    let mut servers = Vec::new();
    for sub in parse_options(data)? {
        match sub.code {
            ntp::SRV_ADDR => servers.push(NtpServer::Address(decode_address(&sub.data)?)),
            ntp::MC_ADDR => servers.push(NtpServer::Multicast(decode_address(&sub.data)?)),
            ntp::SRV_FQDN => servers.push(NtpServer::Fqdn(name::decode(&sub.data)?)),
            _ => {}
        }
    }
    Ok(servers)
}

pub fn encode_ntp_servers(servers: &[NtpServer]) -> Result<Vec<u8>, Error> {
    let subs = servers
        .iter()
        .map(|server| {
            Ok(match server {
                NtpServer::Address(a) => Dhcp6Option::new(ntp::SRV_ADDR, a.octets()),
                NtpServer::Multicast(a) => Dhcp6Option::new(ntp::MC_ADDR, a.octets()),
                NtpServer::Fqdn(n) => Dhcp6Option::new(ntp::SRV_FQDN, name::encode(n)?),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let mut out = Vec::new();
    emit_options(&mut out, &subs)?;
    Ok(out)
}

pub fn decode_address(data: &[u8]) -> Result<Ipv6Addr, Error> {
    let octets: [u8; 16] = data.try_into().map_err(|_| Error::Length)?;
    Ok(Ipv6Addr::from(octets))
}

/// A list of addresses (DNS servers, RFC 3646 §3); may be empty.
pub fn decode_addresses(data: &[u8]) -> Result<Vec<Ipv6Addr>, Error> {
    let (addresses, rest) = data.as_chunks::<16>();
    if !rest.is_empty() {
        return Err(Error::Length);
    }
    Ok(addresses.iter().map(|&a| Ipv6Addr::from(a)).collect())
}

/// A Client or Server Identifier's DUID, checked for length only.
pub fn decode_duid(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < 3 || data.len() > duid::MAX_LEN {
        return Err(Error::Length);
    }
    Ok(data.to_vec())
}

/// A server's message, decoded: the options a client acts on or shows.
/// Options it does not use are left out. An option that does not decode
/// is left out too and listed in `malformed`, so one bad option does not
/// cost the whole message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Params {
    pub client_id: Option<Vec<u8>>,
    pub server_id: Option<Vec<u8>>,
    /// Option 7; absent counts as 0 (RFC 8415 §18.2.9).
    pub preference: Option<u8>,
    /// The message's own Status Code; each IA carries its own.
    pub status: Option<StatusCode>,
    pub rapid_commit: bool,
    pub reconfigure_accept: bool,
    pub ia_na: Vec<IaNa>,
    pub ia_pd: Vec<IaPd>,
    pub dns_servers: Vec<Ipv6Addr>,
    pub domain_list: Vec<String>,
    pub ntp_servers: Vec<NtpServer>,
    /// Option 82, raw: RFC 8415 §21.24 has the client ignore values
    /// outside 60..=86400.
    pub sol_max_rt: Option<u32>,
    /// Option 83, raw, with the same range rule.
    pub inf_max_rt: Option<u32>,
    /// Option 32, raw: RFC 8415 §21.23 sets a floor of 600.
    pub information_refresh_time: Option<u32>,
    /// Options present but not decodable, with the reason.
    pub malformed: Vec<(u16, Error)>,
}

/// The options [`Params`] keeps one instance of; later ones are ignored.
const SINGLE: [u16; 12] = [
    opt::CLIENT_ID,
    opt::SERVER_ID,
    opt::PREFERENCE,
    opt::STATUS_CODE,
    opt::RAPID_COMMIT,
    opt::RECONF_ACCEPT,
    opt::DNS_SERVERS,
    opt::DOMAIN_LIST,
    opt::NTP_SERVER,
    opt::SOL_MAX_RT,
    opt::INF_MAX_RT,
    opt::INFORMATION_REFRESH_TIME,
];

impl Params {
    /// Decodes a message's options. IA_NA and IA_PD may repeat, one per
    /// IAID; any other option counts at its first instance only. Never
    /// fails; see `malformed`.
    pub fn from_options(options: &[Dhcp6Option]) -> Params {
        let mut params = Params::default();
        let mut seen = [false; SINGLE.len()];
        for option in options {
            if let Some(i) = SINGLE.iter().position(|&c| c == option.code) {
                if seen[i] {
                    continue;
                }
                seen[i] = true;
            }
            if let Err(error) = params.apply(option.code, &option.data) {
                params.malformed.push((option.code, error));
            }
        }
        params
    }

    fn apply(&mut self, code: u16, data: &[u8]) -> Result<(), Error> {
        match code {
            opt::CLIENT_ID => self.client_id = Some(decode_duid(data)?),
            opt::SERVER_ID => self.server_id = Some(decode_duid(data)?),
            opt::PREFERENCE => match data {
                [p] => self.preference = Some(*p),
                _ => return Err(Error::Length),
            },
            opt::STATUS_CODE => self.status = Some(StatusCode::parse(data)?),
            opt::RAPID_COMMIT => self.rapid_commit = empty(data)?,
            opt::RECONF_ACCEPT => self.reconfigure_accept = empty(data)?,
            opt::IA_NA => self.ia_na.push(IaNa::parse(data)?),
            opt::IA_PD => self.ia_pd.push(IaPd::parse(data)?),
            opt::DNS_SERVERS => self.dns_servers = decode_addresses(data)?,
            opt::DOMAIN_LIST => self.domain_list = name::decode_list(data, false)?,
            opt::NTP_SERVER => self.ntp_servers = decode_ntp_servers(data)?,
            opt::SOL_MAX_RT => self.sol_max_rt = Some(decode_u32(data)?),
            opt::INF_MAX_RT => self.inf_max_rt = Some(decode_u32(data)?),
            opt::INFORMATION_REFRESH_TIME => {
                self.information_refresh_time = Some(decode_u32(data)?);
            }
            _ => {}
        }
        Ok(())
    }
}

impl Dhcp6Option {
    pub fn new(code: u16, data: impl Into<Vec<u8>>) -> Dhcp6Option {
        Dhcp6Option {
            code,
            data: data.into(),
        }
    }

    /// Option 8, in hundredths of a second; RFC 8415 §21.9 caps it at
    /// 0xffff.
    pub fn elapsed_time(centiseconds: u16) -> Dhcp6Option {
        Dhcp6Option::new(opt::ELAPSED_TIME, centiseconds.to_be_bytes())
    }

    /// Option 6, the Option Request Option.
    pub fn oro(codes: &[u16]) -> Dhcp6Option {
        Dhcp6Option::new(
            opt::ORO,
            codes
                .iter()
                .flat_map(|c| c.to_be_bytes())
                .collect::<Vec<u8>>(),
        )
    }

    /// Option 14, which has no value.
    pub fn rapid_commit() -> Dhcp6Option {
        Dhcp6Option::new(opt::RAPID_COMMIT, Vec::new())
    }
}

fn decode_u32(data: &[u8]) -> Result<u32, Error> {
    let bytes: [u8; 4] = data.try_into().map_err(|_| Error::Length)?;
    Ok(u32::from_be_bytes(bytes))
}

/// An option that is only a flag: present means true.
fn empty(data: &[u8]) -> Result<bool, Error> {
    if data.is_empty() {
        Ok(true)
    } else {
        Err(Error::Length)
    }
}

/// IAID, T1, T2, and the nested options after them.
fn ia_header(data: &[u8]) -> Result<(u32, u32, u32, &[u8]), Error> {
    if data.len() < 12 {
        return Err(Error::Length);
    }
    Ok((
        u32_at(data, 0),
        u32_at(data, 4),
        u32_at(data, 8),
        &data[12..],
    ))
}

fn ia_header_bytes(iaid: u32, t1: u32, t2: u32) -> Vec<u8> {
    let mut data = iaid.to_be_bytes().to_vec();
    data.extend_from_slice(&t1.to_be_bytes());
    data.extend_from_slice(&t2.to_be_bytes());
    data
}

/// The first Status Code among nested options, and the rest.
fn nested(data: &[u8]) -> Result<(Option<StatusCode>, Vec<Dhcp6Option>), Error> {
    let mut status = None;
    let mut other = Vec::new();
    for option in parse_options(data)? {
        if option.code == opt::STATUS_CODE && status.is_none() {
            status = Some(StatusCode::parse(&option.data)?);
        } else {
            other.push(option);
        }
    }
    Ok((status, other))
}

fn emit_nested(
    out: &mut Vec<u8>,
    status: &Option<StatusCode>,
    other: &[Dhcp6Option],
) -> Result<(), Error> {
    if let Some(status) = status {
        emit_options(out, &[status.emit()])?;
    }
    emit_options(out, other)
}

/// The caller has checked that `data` holds 4 bytes at `at`.
fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// The caller has checked that `data` holds 16 bytes at `at`.
fn address_at(data: &[u8], at: usize) -> Ipv6Addr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&data[at..at + 16]);
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::super::{ClientMessage, Message, msg};
    use super::*;
    use crate::testutil::Rng;

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// Code, length, value: an option laid out by hand.
    fn tlv(code: u16, value: &[u8]) -> Vec<u8> {
        let mut b = code.to_be_bytes().to_vec();
        b.extend_from_slice(&(value.len() as u16).to_be_bytes());
        b.extend_from_slice(value);
        b
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// A Reply laid out byte by byte: IA_NA with one address, IA_PD with
    /// a /56, DNS, domain list, NTP (an address and a name), SOL_MAX_RT,
    /// preference, rapid commit and both identifiers.
    fn reply_bytes() -> Vec<u8> {
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let iaaddr = cat(&[
            &addr("2001:db8::10").octets(),
            &3600u32.to_be_bytes(),
            &7200u32.to_be_bytes(),
        ]);
        let ia_na = cat(&[
            &0x0a0b_0c0du32.to_be_bytes(),
            &1800u32.to_be_bytes(),
            &2880u32.to_be_bytes(),
            &tlv(5, &iaaddr),
        ]);
        let iaprefix = cat(&[
            &3600u32.to_be_bytes(),
            &7200u32.to_be_bytes(),
            &[56],
            &addr("2001:db8:100::").octets(),
        ]);
        let ia_pd = cat(&[
            &1u32.to_be_bytes(),
            &1800u32.to_be_bytes(),
            &2880u32.to_be_bytes(),
            &tlv(26, &iaprefix),
        ]);
        let ntp = cat(&[
            &tlv(1, &addr("2001:db8::123").octets()),
            &tlv(3, &name::encode("ntp.example.com").unwrap()),
        ]);
        let mut b = vec![msg::REPLY, 0x12, 0x34, 0x56];
        b.extend(tlv(1, &cat(&[&[0, 3, 0, 1], &mac])));
        b.extend(tlv(2, &[0, 3, 0, 1, 2, 0, 0, 0, 0, 0xfe]));
        b.extend(tlv(7, &[255]));
        b.extend(tlv(14, &[]));
        b.extend(tlv(3, &ia_na));
        b.extend(tlv(25, &ia_pd));
        b.extend(tlv(
            23,
            &cat(&[
                &addr("2001:db8::53").octets(),
                &addr("2001:db8::35").octets(),
            ]),
        ));
        b.extend(tlv(24, &name::encode("example.com").unwrap()));
        b.extend(tlv(56, &ntp));
        b.extend(tlv(82, &7200u32.to_be_bytes()));
        b
    }

    #[test]
    fn reply() {
        let m = Message::parse(&reply_bytes()).unwrap();
        let params = Params::from_options(m.options());
        assert_eq!(
            params,
            Params {
                client_id: Some(vec![0, 3, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56]),
                server_id: Some(vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 0xfe]),
                preference: Some(255),
                status: None,
                rapid_commit: true,
                reconfigure_accept: false,
                ia_na: vec![IaNa {
                    iaid: 0x0a0b_0c0d,
                    t1: 1800,
                    t2: 2880,
                    addresses: vec![IaAddress {
                        address: addr("2001:db8::10"),
                        preferred: 3600,
                        valid: 7200,
                        status: None,
                        other: vec![],
                    }],
                    status: None,
                    other: vec![],
                }],
                ia_pd: vec![IaPd {
                    iaid: 1,
                    t1: 1800,
                    t2: 2880,
                    prefixes: vec![IaPrefix {
                        prefix: addr("2001:db8:100::"),
                        prefix_len: 56,
                        preferred: 3600,
                        valid: 7200,
                        status: None,
                        other: vec![],
                    }],
                    status: None,
                    other: vec![],
                }],
                dns_servers: vec![addr("2001:db8::53"), addr("2001:db8::35")],
                domain_list: vec!["example.com".into()],
                ntp_servers: vec![
                    NtpServer::Address(addr("2001:db8::123")),
                    NtpServer::Fqdn("ntp.example.com".into()),
                ],
                sol_max_rt: Some(7200),
                inf_max_rt: None,
                information_refresh_time: None,
                malformed: vec![],
            }
        );
    }

    #[test]
    fn no_prefix_avail() {
        let ia_pd = cat(&[
            &[0, 0, 0, 1],
            &[0; 8],
            &tlv(13, &cat(&[&[0, 6], b"none left"])),
        ]);
        let params = Params::from_options(&[Dhcp6Option::new(opt::IA_PD, ia_pd)]);
        let status = params.ia_pd[0].status.as_ref().unwrap();
        assert_eq!(status.code, status::NO_PREFIX_AVAIL);
        assert_eq!(status.message, "none left");
        assert!(!status.is_success());
        assert!(params.ia_pd[0].prefixes.is_empty());
    }

    #[test]
    fn one_bad_option_costs_only_itself() {
        let short_iaaddr = cat(&[&[0; 12], &tlv(5, &[0; 23])]);
        let long_prefix = cat(&[&[0; 12], &tlv(26, &cat(&[&[0; 8], &[129], &[0; 16]]))]);
        let params = Params::from_options(&[
            Dhcp6Option::new(opt::SERVER_ID, [0, 3]),
            Dhcp6Option::new(opt::PREFERENCE, [1, 2]),
            Dhcp6Option::new(opt::RAPID_COMMIT, [0]),
            Dhcp6Option::new(opt::IA_NA, short_iaaddr),
            Dhcp6Option::new(opt::IA_PD, long_prefix),
            Dhcp6Option::new(opt::IA_NA, [0; 11]),
            Dhcp6Option::new(opt::DNS_SERVERS, [0; 17]),
            Dhcp6Option::new(opt::DOMAIN_LIST, [1, b'a', 0xc0, 0]),
            Dhcp6Option::new(opt::NTP_SERVER, []),
            Dhcp6Option::new(opt::SOL_MAX_RT, [0; 3]),
            Dhcp6Option::new(opt::STATUS_CODE, [0]),
            Dhcp6Option::new(opt::INF_MAX_RT, 3600u32.to_be_bytes()),
        ]);
        assert_eq!(params.inf_max_rt, Some(3600));
        assert_eq!(params.server_id, None);
        assert!(params.ia_na.is_empty() && params.ia_pd.is_empty());
        assert_eq!(
            params.malformed,
            [
                (opt::SERVER_ID, Error::Length),
                (opt::PREFERENCE, Error::Length),
                (opt::RAPID_COMMIT, Error::Length),
                (opt::IA_NA, Error::Length),
                (opt::IA_PD, Error::Invalid),
                (opt::IA_NA, Error::Length),
                (opt::DNS_SERVERS, Error::Length),
                (opt::DOMAIN_LIST, Error::Invalid),
                (opt::NTP_SERVER, Error::Length),
                (opt::SOL_MAX_RT, Error::Length),
                (opt::STATUS_CODE, Error::Length),
            ]
        );
    }

    #[test]
    fn first_instance_wins_except_ias() {
        let dns = |a: &str| Dhcp6Option::new(opt::DNS_SERVERS, addr(a).octets());
        let params = Params::from_options(&[
            dns("2001:db8::1"),
            IaNa::new(1).emit().unwrap(),
            dns("2001:db8::2"),
            IaNa::new(2).emit().unwrap(),
        ]);
        assert_eq!(params.dns_servers, [addr("2001:db8::1")]);
        let iaids: Vec<u32> = params.ia_na.iter().map(|ia| ia.iaid).collect();
        assert_eq!(iaids, [1, 2]);
    }

    #[test]
    fn solicit() {
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let mut pd = IaPd::new(7);
        pd.prefixes.push(IaPrefix::hint(56));
        let mut m = ClientMessage::new(msg::SOLICIT, 0xab_cdef);
        m.options = vec![
            Dhcp6Option::new(opt::CLIENT_ID, duid::ll(duid::HTYPE_ETHERNET, &mac)),
            Dhcp6Option::elapsed_time(0),
            Dhcp6Option::oro(&[opt::DNS_SERVERS, opt::SOL_MAX_RT]),
            Dhcp6Option::rapid_commit(),
            IaNa::new(0x0102_0304).emit().unwrap(),
            pd.emit().unwrap(),
        ];
        let wire = m.emit().unwrap();
        let mut want = vec![msg::SOLICIT, 0xab, 0xcd, 0xef];
        want.extend(tlv(1, &cat(&[&[0, 3, 0, 1], &mac])));
        want.extend(tlv(8, &[0, 0]));
        want.extend(tlv(6, &[0, 23, 0, 82]));
        want.extend(tlv(14, &[]));
        want.extend(tlv(3, &cat(&[&[1, 2, 3, 4], &[0; 8]])));
        want.extend(tlv(
            25,
            &cat(&[
                &[0, 0, 0, 7],
                &[0; 8],
                &tlv(26, &cat(&[&[0; 8], &[56], &[0; 16]])),
            ]),
        ));
        assert_eq!(wire, want);
        let Message::Client(back) = Message::parse(&wire).unwrap() else {
            panic!("not a client message")
        };
        assert_eq!(back, m);
        assert_eq!(back.option(opt::ELAPSED_TIME), Some(&[0, 0][..]));
    }

    #[test]
    fn duids() {
        let mac = [2, 0, 0, 0, 0, 1];
        assert_eq!(
            duid::llt(duid::HTYPE_ETHERNET, 0x0102_0304, &mac),
            [0, 1, 0, 1, 1, 2, 3, 4, 2, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            duid::ll(duid::HTYPE_ETHERNET, &mac),
            [0, 3, 0, 1, 2, 0, 0, 0, 0, 1]
        );
        assert_eq!(decode_duid(&[0; 131]), Err(Error::Length));
        assert!(decode_duid(&[0; 130]).is_ok());
    }

    fn random_status(rng: &mut Rng) -> Option<StatusCode> {
        rng.chance(3).then(|| {
            let message: String = (0..rng.below(12))
                .map(|_| char::from(b'a' + rng.below(26) as u8))
                .collect();
            StatusCode::new(rng.below(7) as u16, message)
        })
    }

    /// Nested options a typed field does not claim.
    fn random_other(rng: &mut Rng) -> Vec<Dhcp6Option> {
        (0..rng.below(2))
            .map(|_| {
                let len = rng.below(8);
                Dhcp6Option::new(100 + rng.below(100) as u16, rng.bytes(len))
            })
            .collect()
    }

    fn random_address(rng: &mut Rng) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(rng.next_u64()) << 64 | u128::from(rng.next_u64()))
    }

    fn random_ia_na(rng: &mut Rng) -> IaNa {
        IaNa {
            iaid: rng.next_u64() as u32,
            t1: rng.next_u64() as u32,
            t2: rng.next_u64() as u32,
            addresses: (0..rng.below(3))
                .map(|_| IaAddress {
                    address: random_address(rng),
                    preferred: rng.next_u64() as u32,
                    valid: rng.next_u64() as u32,
                    status: random_status(rng),
                    other: random_other(rng),
                })
                .collect(),
            status: random_status(rng),
            other: random_other(rng),
        }
    }

    fn random_ia_pd(rng: &mut Rng) -> IaPd {
        IaPd {
            iaid: rng.next_u64() as u32,
            t1: rng.next_u64() as u32,
            t2: rng.next_u64() as u32,
            prefixes: (0..rng.below(3))
                .map(|_| IaPrefix {
                    prefix: random_address(rng),
                    prefix_len: rng.below(129) as u8,
                    preferred: rng.next_u64() as u32,
                    valid: rng.next_u64() as u32,
                    status: random_status(rng),
                    other: random_other(rng),
                })
                .collect(),
            status: random_status(rng),
            other: random_other(rng),
        }
    }

    #[test]
    fn round_trip() {
        let mut rng = Rng::new(8415);
        for _ in 0..2000 {
            let want = Params {
                client_id: Some(duid::ll(duid::HTYPE_ETHERNET, &rng.bytes(6))),
                server_id: Some(duid::llt(
                    duid::HTYPE_ETHERNET,
                    rng.next_u64() as u32,
                    &rng.bytes(6),
                )),
                preference: Some(rng.byte()),
                status: random_status(&mut rng),
                rapid_commit: rng.chance(2),
                reconfigure_accept: rng.chance(2),
                ia_na: (0..rng.below(3)).map(|_| random_ia_na(&mut rng)).collect(),
                ia_pd: (0..rng.below(3)).map(|_| random_ia_pd(&mut rng)).collect(),
                dns_servers: (0..rng.below(3))
                    .map(|_| random_address(&mut rng))
                    .collect(),
                domain_list: vec!["example.com".into(), "lab.example.com".into()],
                ntp_servers: vec![
                    NtpServer::Address(random_address(&mut rng)),
                    NtpServer::Multicast(random_address(&mut rng)),
                    NtpServer::Fqdn("ntp.example.com".into()),
                ],
                sol_max_rt: Some(rng.next_u64() as u32),
                inf_max_rt: Some(rng.next_u64() as u32),
                information_refresh_time: Some(rng.next_u64() as u32),
                malformed: vec![],
            };
            let mut options = vec![
                Dhcp6Option::new(opt::CLIENT_ID, want.client_id.clone().unwrap()),
                Dhcp6Option::new(opt::SERVER_ID, want.server_id.clone().unwrap()),
                Dhcp6Option::new(opt::PREFERENCE, [want.preference.unwrap()]),
                Dhcp6Option::new(
                    opt::DNS_SERVERS,
                    want.dns_servers
                        .iter()
                        .flat_map(|a| a.octets())
                        .collect::<Vec<u8>>(),
                ),
                Dhcp6Option::new(
                    opt::DOMAIN_LIST,
                    name::encode_list(&want.domain_list).unwrap(),
                ),
                Dhcp6Option::new(
                    opt::NTP_SERVER,
                    encode_ntp_servers(&want.ntp_servers).unwrap(),
                ),
                Dhcp6Option::new(opt::SOL_MAX_RT, want.sol_max_rt.unwrap().to_be_bytes()),
                Dhcp6Option::new(opt::INF_MAX_RT, want.inf_max_rt.unwrap().to_be_bytes()),
                Dhcp6Option::new(
                    opt::INFORMATION_REFRESH_TIME,
                    want.information_refresh_time.unwrap().to_be_bytes(),
                ),
            ];
            if let Some(status) = &want.status {
                options.push(status.emit());
            }
            if want.rapid_commit {
                options.push(Dhcp6Option::rapid_commit());
            }
            if want.reconfigure_accept {
                options.push(Dhcp6Option::new(opt::RECONF_ACCEPT, Vec::new()));
            }
            for ia in &want.ia_na {
                options.push(ia.emit().unwrap());
            }
            for ia in &want.ia_pd {
                options.push(ia.emit().unwrap());
            }
            let m = Message::Client(ClientMessage {
                msg_type: msg::REPLY,
                transaction_id: 1,
                options,
            });
            let back = Message::parse(&m.emit().unwrap()).unwrap();
            assert_eq!(Params::from_options(back.options()), want);
        }
    }

    /// Every decoded code with random values: no panic.
    #[test]
    fn decode_is_total() {
        let codes = [1, 2, 3, 5, 7, 13, 14, 20, 23, 24, 25, 26, 32, 56, 82, 83];
        let mut rng = Rng::new(5908);
        let seed = reply_bytes();
        for _ in 0..20000 {
            let options: Vec<Dhcp6Option> = if rng.chance(2) {
                match Message::parse(&rng.mutate(&seed)) {
                    Ok(m) => m.options().to_vec(),
                    Err(_) => continue,
                }
            } else {
                (0..1 + rng.below(4))
                    .map(|_| {
                        let len = rng.below(60);
                        Dhcp6Option::new(codes[rng.below(codes.len())], rng.bytes(len))
                    })
                    .collect()
            };
            let params = Params::from_options(&options);
            for ia in &params.ia_pd {
                assert!(ia.prefixes.iter().all(|p| p.prefix_len <= 128));
            }
        }
    }
}
