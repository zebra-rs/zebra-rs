use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsisTlvType {
    #[default]
    AreaAddr = 1,
    IsNeighbor = 6,
    Padding = 8,
    LspEntries = 9,
    /// Authentication Information (ISO 10589 §9.5 / RFC 5304 / RFC 5310).
    /// Carries an Authentication Type byte followed by an algorithm-
    /// specific value (cleartext password, HMAC-MD5 digest, or RFC 5310
    /// generic-crypto Key ID + digest).
    Auth = 10,
    /// Purge Originator Identification (RFC 6232). Carried in
    /// purge LSPs (those with Remaining Lifetime == 0); identifies
    /// the IS that injected the purge and optionally the upstream
    /// IS it was received from, so operators can track a phantom
    /// purge back to its origin instead of staring at a
    /// systemId-anonymous zero-lifetime LSP.
    PurgeOrigId = 13,
    LspBufferSize = 14,
    ExtIsReach = 22,
    MtIsReach = 222,
    Srv6 = 27,
    ProtSupported = 129,
    Ipv4IfAddr = 132,
    TeRouterId = 134,
    ExtIpReach = 135,
    DynamicHostname = 137,
    /// IPv4 Shared Risk Link Group (RFC 5307).
    Srlg = 138,
    /// IPv6 Shared Risk Link Group (RFC 6119).
    Ipv6Srlg = 139,
    Ipv6TeRouterId = 140,
    /// SID/Label Binding TLV (RFC 8667 §2.4). Carries SR mapping-server
    /// bindings and, with the M-flag, RFC 8679 Mirror Context (egress
    /// protection) context-label bindings.
    SidLabelBinding = 149,
    Ipv6IfAddr = 232,
    Ipv6GlobalIfAddr = 233,
    MultiTopology = 229,
    MtIpReach = 235,
    Ipv6Reach = 236,
    MtIpv6Reach = 237,
    P2p3Way = 240,
    RouterCap = 242,
    /// Restart TLV (RFC 5306). Carries Restart Request (RR), Restart
    /// Acknowledgement (RA), and Suppress Adjacency (SA) flags in IIH
    /// PDUs to drive Graceful Restart.
    Restart = 211,
    Unknown(u8),
}

impl IsisTlvType {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let tlv_type: Self = typ.into();
        Ok((input, tlv_type))
    }
}

impl IsisTlvType {
    pub fn is_known(&self) -> bool {
        use IsisTlvType::*;
        matches!(
            self,
            AreaAddr
                | IsNeighbor
                | Padding
                | LspEntries
                | Auth
                | PurgeOrigId
                | LspBufferSize
                | ExtIsReach
                | MtIsReach
                | Srv6
                | ProtSupported
                | Ipv4IfAddr
                | TeRouterId
                | ExtIpReach
                | DynamicHostname
                | Srlg
                | Ipv6Srlg
                | Ipv6TeRouterId
                | SidLabelBinding
                | Ipv6IfAddr
                | Ipv6GlobalIfAddr
                | MultiTopology
                | MtIpReach
                | Ipv6Reach
                | MtIpv6Reach
                | P2p3Way
                | RouterCap
                | Restart
        )
    }
}

impl From<IsisTlvType> for u8 {
    fn from(typ: IsisTlvType) -> Self {
        use IsisTlvType::*;
        match typ {
            AreaAddr => 1,
            IsNeighbor => 6,
            Padding => 8,
            LspEntries => 9,
            Auth => 10,
            PurgeOrigId => 13,
            LspBufferSize => 14,
            ExtIsReach => 22,
            MtIsReach => 222,
            Srv6 => 27,
            ProtSupported => 129,
            Ipv4IfAddr => 132,
            TeRouterId => 134,
            ExtIpReach => 135,
            DynamicHostname => 137,
            Srlg => 138,
            Ipv6Srlg => 139,
            Ipv6TeRouterId => 140,
            SidLabelBinding => 149,
            Ipv6IfAddr => 232,
            Ipv6GlobalIfAddr => 233,
            MultiTopology => 229,
            MtIpReach => 235,
            Ipv6Reach => 236,
            MtIpv6Reach => 237,
            P2p3Way => 240,
            RouterCap => 242,
            Restart => 211,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisTlvType {
    fn from(typ: u8) -> Self {
        use IsisTlvType::*;
        match typ {
            1 => AreaAddr,
            6 => IsNeighbor,
            8 => Padding,
            9 => LspEntries,
            10 => Auth,
            13 => PurgeOrigId,
            14 => LspBufferSize,
            22 => ExtIsReach,
            222 => MtIsReach,
            27 => Srv6,
            129 => ProtSupported,
            132 => Ipv4IfAddr,
            134 => TeRouterId,
            135 => ExtIpReach,
            137 => DynamicHostname,
            138 => Srlg,
            139 => Ipv6Srlg,
            140 => Ipv6TeRouterId,
            149 => SidLabelBinding,
            232 => Ipv6IfAddr,
            233 => Ipv6GlobalIfAddr,
            229 => MultiTopology,
            235 => MtIpReach,
            236 => Ipv6Reach,
            237 => MtIpv6Reach,
            240 => P2p3Way,
            242 => RouterCap,
            211 => Restart,
            v => Unknown(v),
        }
    }
}
