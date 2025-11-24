use std::fmt::{Display, Formatter, Result};

use itertools::Itertools;

use crate::{
    Algo, IsLevel, IsisCsnp, IsisHello, IsisLsp, IsisLspEntry, IsisLspId, IsisNeighborId,
    IsisP2pHello, IsisPacket, IsisPdu, IsisProto, IsisPsnp, IsisSysId, IsisTlv, IsisTlvAreaAddr,
    IsisTlvHostname, IsisTlvIpv4IfAddr, IsisTlvIpv6GlobalIfAddr, IsisTlvIpv6IfAddr,
    IsisTlvIpv6TeRouterId, IsisTlvIsNeighbor, IsisTlvLspEntries, IsisTlvP2p3Way, IsisTlvPadding,
    IsisTlvProtoSupported, IsisTlvSrv6, IsisTlvTeRouterId, NeighborAddr, SidLabelValue,
};

impl Display for IsisPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IRPD: ISIS (0x{:x}) ==
 Length Indicator: {}
 Version/Protocol ID Extension: {}
 ID Length: {}
 PDU Type: {}
 Version: {}
 Reserved: {}
 Maximum Area Address: {}
{}"#,
            self.discriminator,
            self.length_indicator,
            self.id_extension,
            self.id_length,
            self.pdu_type,
            self.version,
            self.resvd,
            self.max_area_addr,
            self.pdu,
        )
    }
}

impl Display for IsisPdu {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisPdu::*;
        match self {
            L1Hello(v) => write!(f, "{}", v),
            L2Hello(v) => write!(f, "{}", v),
            P2pHello(v) => write!(f, "{}", v),
            L1Lsp(v) => write!(f, "{}", v),
            L2Lsp(v) => write!(f, "{}", v),
            L1Csnp(v) => write!(f, "{}", v),
            L2Csnp(v) => write!(f, "{}", v),
            L1Psnp(v) => write!(f, "{}", v),
            L2Psnp(v) => write!(f, "{}", v),
            Unknown(_) => write!(f, "Unknown"),
        }
    }
}

impl Display for IsisLsp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for tlv in self.tlvs.iter() {
            write!(f, "\n{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            IsLevel::L1 => write!(f, "L1"),
            IsLevel::L2 => write!(f, "L2"),
            IsLevel::L1L2 => write!(f, "L1L2"),
        }
    }
}

#[derive(Debug)]
pub struct ParseIsTypeError;

impl Display for ParseIsTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "invalid input for IsType")
    }
}

use std::str::FromStr;

impl FromStr for IsLevel {
    type Err = ParseIsTypeError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "level-1" => Ok(IsLevel::L1),
            "level-2-only" => Ok(IsLevel::L2),
            "level-1-2" => Ok(IsLevel::L1L2),
            _ => Err(ParseIsTypeError),
        }
    }
}

impl Display for IsisHello {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#" Circuit type: {}
 Source ID: {}
 Holding timer: {}
 PDU length: {}
 Priority: {}
 LAN ID {}"#,
            self.circuit_type,
            self.source_id,
            self.hold_time,
            self.pdu_len,
            self.priority,
            self.lan_id
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "\n{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisP2pHello {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#" Circuit type: {}
 Source ID: {}
 Holding timer: {}
 PDU length: {}
 Local Circuit ID: {}"#,
            self.circuit_type, self.source_id, self.hold_time, self.pdu_len, self.circuit_id,
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "\n{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisCsnp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#" PDU length: {}
 Source ID: {:?}
 Source ID Circuit: {}
 Start: {:?}
 End: {:?}"#,
            self.pdu_len, self.source_id, self.source_id_circuit, self.start, self.end
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisPsnp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#" PDU length: {}
 Source ID: {}
 Source ID Curcuit: {}"#,
            self.pdu_len, self.source_id, 0,
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisTlv::*;
        match self {
            AreaAddr(v) => write!(f, "{}", v),
            IsNeighbor(v) => write!(f, "{}", v),
            Padding(v) => write!(f, "{}", v),
            LspEntries(v) => write!(f, "{}", v),
            ExtIsReach(v) => write!(f, "{}", v),
            Srv6(v) => write!(f, "{}", v),
            ProtoSupported(v) => write!(f, "{}", v),
            Ipv4IfAddr(v) => write!(f, "{}", v),
            TeRouterId(v) => write!(f, "{}", v),
            ExtIpReach(v) => write!(f, "{}", v),
            Hostname(v) => write!(f, "{}", v),
            Ipv6TeRouterId(v) => write!(f, "{}", v),
            Ipv6IfAddr(v) => write!(f, "{}", v),
            Ipv6GlobalIfAddr(v) => write!(f, "{}", v),
            Ipv6Reach(v) => write!(f, "{}", v),
            RouterCap(v) => write!(f, "{}", v),
            MtIpReach(_) => write!(f, ""),
            MtIpv6Reach(_) => write!(f, ""),
            P2p3Way(v) => write!(f, "{}", v),
            Unknown(v) => {
                write!(f, "  {:?}", v.typ)
            }
        }
    }
}

impl Display for IsisSysId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            self.id[0], self.id[1], self.id[2], self.id[3], self.id[4], self.id[5],
        )
    }
}

impl Display for IsisNeighborId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}",
            self.id[0], self.id[1], self.id[2], self.id[3], self.id[4], self.id[5], self.id[6],
        )
    }
}

impl Display for IsisLspId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}-{:02x}",
            self.id[0],
            self.id[1],
            self.id[2],
            self.id[3],
            self.id[4],
            self.id[5],
            self.id[6],
            self.id[7],
        )
    }
}

impl Display for IsisTlvAreaAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Area address:")?;
        if !self.area_addr.is_empty() {
            write!(f, " {:02x}", self.area_addr[0])?;

            for (index, id) in self.area_addr.iter().enumerate() {
                if index == 0 {
                    continue;
                }
                if index % 2 == 1 {
                    write!(f, ".")?;
                }
                write!(f, "{:02x}", id)?;
            }
        }
        Ok(())
    }
}

impl Display for NeighborAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "  IS Neighbor: {:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5],
        )
    }
}

impl Display for IsisTlvIsNeighbor {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for neighbor in self.neighbors.iter() {
            write!(f, "{}", neighbor)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvPadding {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Padding: length {}", self.padding.len())
    }
}

impl Display for IsisLspEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#" LSP Entry:
  Lifetime: {}
  Sequence number: 0x{:x}
  Checksum: 0x{:x}
  LSP ID {:?}"#,
            self.hold_time, self.seq_number, self.checksum, self.lsp_id,
        )
    }
}

impl Display for IsisTlvLspEntries {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for entry in self.entries.iter() {
            write!(f, "\n{}", entry)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvSrv6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (pos, locator) in self.locators.iter().enumerate() {
            if pos != 0 {
                writeln!(f)?;
            }
            write!(
                f,
                "  SRv6 Locator: {} (Metric: {})",
                locator.locator, locator.metric
            )?;
            for sub in locator.subs.iter() {
                write!(f, "\n{}", sub)?;
            }
        }
        Ok(())
    }
}

impl Display for IsisTlvProtoSupported {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "  Protocol Supported: {}",
            self.nlpids
                .iter()
                .map(|nlpid| IsisProto::from(*nlpid))
                .format(" ")
        )
    }
}

impl Display for IsisTlvIpv4IfAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  IPv4 Interface Address: {}", self.addr)
    }
}

impl Display for IsisTlvHostname {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Hostname: {}", self.hostname)
    }
}

impl Display for IsisTlvTeRouterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  TE Router ID: {}", self.router_id)
    }
}

impl Display for IsisTlvIpv6TeRouterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  IPv6 TE Router ID: {}", self.router_id)
    }
}

impl Display for IsisTlvIpv6IfAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  IPv6 Interface Address: {}", self.addr)
    }
}

impl Display for IsisTlvIpv6GlobalIfAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  IPv6 Global Interface Address: {}", self.addr)
    }
}

impl Display for SidLabelValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            SidLabelValue::Label(v) => {
                write!(f, "{}", v)
            }
            SidLabelValue::Index(v) => {
                write!(f, "{}", v)
            }
        }
    }
}

impl Display for Algo {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use Algo::*;
        match self {
            Spf => write!(f, "SPF(0)"),
            StrictSpf => write!(f, "StrictSPF(1)"),
            FlexAlgo(v) => write!(f, "FlexAlgo({})", v),
            Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

impl Display for IsisTlvP2p3Way {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "  Three-Way Handshake : State:{}, Local circuit ID:{}",
            self.state, self.circuit_id
        )
    }
}
