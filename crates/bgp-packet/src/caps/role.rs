//! RFC 9234 §4.1 BGP Role capability (capability code 9).
//!
//! A speaker that has a locally configured BGP Role toward an eBGP
//! neighbor advertises it in the OPEN message as a one-octet capability.
//! The session logic (`zebra-rs` `fsm_bgp_open`) compares the received
//! role against the local one per §4.2 and rejects the connection with a
//! Role Mismatch NOTIFICATION (OPEN Message Error, subcode 11) when the
//! pair is invalid, when strict mode is on and no role was received, or
//! when several Role capabilities carry different values.

use std::fmt;
use std::str::FromStr;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit};

/// The BGP Role of the local speaker toward one eBGP neighbor (RFC 9234
/// §4.1, IANA "BGP Role Value" registry).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BgpRole {
    /// The local AS provides transit to the remote AS.
    Provider = 0,
    /// The local speaker is a route server (RFC 7947).
    RouteServer = 1,
    /// The local AS is a client of a route server.
    RouteServerClient = 2,
    /// The local AS receives transit from the remote AS.
    Customer = 3,
    /// Lateral peering: the two ASes exchange routes without providing
    /// transit to each other.
    Peer = 4,
}

impl BgpRole {
    /// Decode a wire value. `None` for the unassigned range 5–255.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Provider),
            1 => Some(Self::RouteServer),
            2 => Some(Self::RouteServerClient),
            3 => Some(Self::Customer),
            4 => Some(Self::Peer),
            _ => None,
        }
    }

    /// The role the remote speaker must announce for the pair to be valid
    /// (RFC 9234 §4.2 Table 2): Provider↔Customer, RS↔RS-Client,
    /// Peer↔Peer. Also the role a loose-mode speaker *infers* for a
    /// neighbor that sent no Role capability.
    pub fn counterpart(self) -> Self {
        match self {
            Self::Provider => Self::Customer,
            Self::Customer => Self::Provider,
            Self::RouteServer => Self::RouteServerClient,
            Self::RouteServerClient => Self::RouteServer,
            Self::Peer => Self::Peer,
        }
    }

    /// Whether `remote` is the valid partner of this role (§4.2).
    pub fn pairs_with(self, remote: Self) -> bool {
        self.counterpart() == remote
    }

    /// Operator-facing spelling, matching Cisco IOS XR's `show bgp
    /// neighbor` output ("OTC Local Role : Provider").
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "Provider",
            Self::RouteServer => "Route Server",
            Self::RouteServerClient => "Route Server Client",
            Self::Customer => "Customer",
            Self::Peer => "Peer",
        }
    }

    /// Configuration token, IOS XR spelling
    /// (`otc-local-role {customer|provider|peer|route-server-client}`;
    /// `route-server` is the zebra-rs superset for the RS side).
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::RouteServer => "route-server",
            Self::RouteServerClient => "route-server-client",
            Self::Customer => "customer",
            Self::Peer => "peer",
        }
    }
}

impl From<BgpRole> for u8 {
    fn from(role: BgpRole) -> Self {
        role as u8
    }
}

impl fmt::Display for BgpRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A configuration token that names no BGP Role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBgpRoleError(pub String);

impl fmt::Display for ParseBgpRoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown BGP role `{}` (expected customer, provider, peer, \
             route-server-client or route-server)",
            self.0
        )
    }
}

impl std::error::Error for ParseBgpRoleError {}

impl FromStr for BgpRole {
    type Err = ParseBgpRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "provider" => Ok(Self::Provider),
            "route-server" => Ok(Self::RouteServer),
            "route-server-client" => Ok(Self::RouteServerClient),
            "customer" => Ok(Self::Customer),
            "peer" => Ok(Self::Peer),
            other => Err(ParseBgpRoleError(other.to_string())),
        }
    }
}

/// The Role capability as carried on the wire: code 9, length 1, one
/// value octet. The raw value is kept (rather than a decoded [`BgpRole`])
/// so an unassigned value 5–255 survives to the session logic, which
/// treats it as a role that pairs with nothing — a Role Mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, NomBE)]
pub struct CapRole {
    pub value: u8,
}

impl CapRole {
    pub fn new(role: BgpRole) -> Self {
        Self { value: role.into() }
    }

    /// The decoded role, or `None` for an unassigned value.
    pub fn role(&self) -> Option<BgpRole> {
        BgpRole::from_u8(self.value)
    }
}

impl CapEmit for CapRole {
    fn code(&self) -> CapCode {
        CapCode::Role
    }

    fn len(&self) -> u8 {
        1
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u8(self.value);
    }
}

impl fmt::Display for CapRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.role() {
            Some(role) => write!(f, "Role: {}", role),
            None => write!(f, "Role: unassigned ({})", self.value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [BgpRole; 5] = [
        BgpRole::Provider,
        BgpRole::RouteServer,
        BgpRole::RouteServerClient,
        BgpRole::Customer,
        BgpRole::Peer,
    ];

    #[test]
    fn wire_values_match_iana_registry() {
        assert_eq!(u8::from(BgpRole::Provider), 0);
        assert_eq!(u8::from(BgpRole::RouteServer), 1);
        assert_eq!(u8::from(BgpRole::RouteServerClient), 2);
        assert_eq!(u8::from(BgpRole::Customer), 3);
        assert_eq!(u8::from(BgpRole::Peer), 4);
        for role in ALL {
            assert_eq!(BgpRole::from_u8(role.into()), Some(role));
        }
        assert_eq!(BgpRole::from_u8(5), None);
        assert_eq!(BgpRole::from_u8(255), None);
    }

    /// RFC 9234 §4.2 Table 2: exactly three valid pairs, symmetric, and
    /// nothing else.
    #[test]
    fn role_pairs_are_the_rfc_table() {
        for local in ALL {
            for remote in ALL {
                let valid = matches!(
                    (local, remote),
                    (BgpRole::Provider, BgpRole::Customer)
                        | (BgpRole::Customer, BgpRole::Provider)
                        | (BgpRole::RouteServer, BgpRole::RouteServerClient)
                        | (BgpRole::RouteServerClient, BgpRole::RouteServer)
                        | (BgpRole::Peer, BgpRole::Peer)
                );
                assert_eq!(local.pairs_with(remote), valid, "{local:?} vs {remote:?}");
                assert_eq!(
                    remote.pairs_with(local),
                    valid,
                    "symmetry {local:?}/{remote:?}"
                );
            }
            assert!(local.pairs_with(local.counterpart()));
            assert_eq!(local.counterpart().counterpart(), local);
        }
    }

    #[test]
    fn cli_tokens_round_trip() {
        for role in ALL {
            assert_eq!(role.cli_name().parse::<BgpRole>().unwrap(), role);
        }
        assert!("rs-server".parse::<BgpRole>().is_err());
        assert!("Provider".parse::<BgpRole>().is_err());
    }

    #[test]
    fn capability_emits_code_9_length_1() {
        let cap = CapRole::new(BgpRole::Customer);
        let mut buf = BytesMut::new();
        cap.emit(&mut buf, true);
        assert_eq!(&buf[..], &[9u8, 1, 3]);

        // Classic optional-parameter framing around it.
        let mut buf = BytesMut::new();
        cap.emit(&mut buf, false);
        assert_eq!(&buf[..], &[2u8, 3, 9, 1, 3]);
    }

    #[test]
    fn capability_value_parses_and_decodes() {
        let (rest, cap) = CapRole::parse_be(&[4u8]).unwrap();
        assert!(rest.is_empty());
        assert_eq!(cap.role(), Some(BgpRole::Peer));
        assert_eq!(cap.to_string(), "Role: Peer");

        let (_, cap) = CapRole::parse_be(&[7u8]).unwrap();
        assert_eq!(cap.role(), None);
        assert_eq!(cap.to_string(), "Role: unassigned (7)");
    }
}
