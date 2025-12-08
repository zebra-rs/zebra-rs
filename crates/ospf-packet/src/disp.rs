use std::fmt::{Display, Formatter, Result};

use super::*;

impl Display for Ospfv2Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== OSPFv2 ==
 Version: {}
 Type: {}
 Length: {}
 Router ID: {}
 Area ID: {}
 Checksum: {:x}
 Auth type: {}
 Auth: {}
{}"#,
            self.version,
            self.typ,
            self.len,
            self.router_id,
            self.area_id,
            self.checksum,
            self.auth_type,
            self.auth,
            self.payload,
        )
    }
}

impl Display for Ospfv2Auth {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:x}", self.auth)
    }
}

impl Display for Ospfv2Payload {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use Ospfv2Payload::*;
        match self {
            Hello(v) => write!(f, "{}", v),
            DbDesc(v) => write!(f, "{}", v),
            LsRequest(v) => write!(f, "{}", v),
            LsUpdate(v) => write!(f, "{}", v),
            _ => write!(f, "XXX Payload"),
        }
    }
}

impl Display for OspfHello {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== Hello ==
 Network mask: {}
 Hello interval: {}
 Options: {}
 Router priority: {}
 Router dead interval: {}
 DR: {}
 BDR: {}"#,
            self.netmask,
            self.hello_interval,
            self.options,
            self.priority,
            self.router_dead_interval,
            self.d_router,
            self.bd_router,
        )?;
        for nei in self.neighbors.iter() {
            write!(f, "\n Neighbor: {}", nei)?;
        }
        Ok(())
    }
}

impl Display for OspfOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"
  DN: {}
  O: {}
  Demand Circuit: {}
  LLS Data: {}
  NSSA: {}
  Multicast: {}
  External: {}
  MultiTopology: {}"#,
            if self.dn() { "On" } else { "Off" },
            if self.o() { "On" } else { "Off" },
            if self.demand_circuits() { "On" } else { "Off" },
            if self.lls_data() { "On" } else { "Off" },
            if self.nssa() { "On" } else { "Off" },
            if self.multicast() { "On" } else { "Off" },
            if self.external() { "On" } else { "Off" },
            if self.multi_toplogy() { "On" } else { "Off" },
        )?;
        Ok(())
    }
}

impl Display for OspfDbDesc {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== Database Description ==
 Interface MTU: {}
 Options: {}
 Flags: master:{}, more:{}, init:{}, oob:{}
 DD sequence number: {:04x}"#,
            self.if_mtu,
            self.options,
            self.flags.master() as u8,
            self.flags.more() as u8,
            self.flags.init() as u8,
            self.flags.oob_resync() as u8,
            self.seqnum,
        )?;
        for lsa in self.lsa_headers.iter() {
            write!(f, "\n{}", lsa)?;
        }
        Ok(())
    }
}

impl Display for OspfLsaHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#" LS age: {}
  Options: {}
  LS Type: {}
  LS ID: {}
  Advertising router: {}
  LS seq num: {:x}
  LS checksu: {:?}
  Length: {}"#,
            self.ls_age,
            self.options,
            self.ls_type,
            self.ls_id,
            self.adv_router,
            self.ls_seq_number,
            self.ls_checksum,
            self.length,
        )
    }
}

impl Display for OspfLsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, r#"== Link State Request =="#,)?;
        for req in self.reqs.iter() {
            write!(f, "\n{}", req)?;
        }
        Ok(())
    }
}

impl Display for OspfLsRequestEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#" LS Type: {}
  LS ID: {:?}
  Advertising router: {}"#,
            self.ls_type, self.ls_id, self.adv_router
        )
    }
}

impl Display for OspfLsUpdate {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== Link State Update ==
 Num advertisement: {}"#,
            self.num_adv
        )?;
        for req in self.lsas.iter() {
            write!(f, "\n{}", req)?;
        }
        Ok(())
    }
}

impl Display for OspfLsa {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use OspfLsp::*;
        write!(f, "{}", self.h).unwrap();
        match &self.lsp {
            Router(v) => write!(f, "\n{}", v),
            Network(v) => write!(f, "\n{}", v),
            AsExternal(v) => write!(f, "\n{}", v),
            Unknown(_v) => write!(f, "Unknown"),
            _ => write!(f, ""),
        }
    }
}

impl Display for RouterLsa {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== Router LSA ==
  Flags: {}
  Num links: {}"#,
            self.flags, self.num_links
        )?;
        for link in self.links.iter() {
            write!(f, "\n{}", link)?;
        }
        Ok(())
    }
}

impl Display for RouterLsaLink {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== Router LSA Link ==
 Link ID: {}
 Link Data: {}
 Link Type: {}
 Num ToS: {}
 ToS 0 metric: {}
 ToS: {:?}"#,
            self.link_id,
            self.link_data,
            self.link_type,
            self.num_tos,
            self.tos_0_metric,
            self.toses
        )
    }
}

impl Display for NetworkLsa {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== Network LSA ==
  Netmask: {}"#,
            self.netmask
        )?;
        // for link in self.links.iter() {
        //     write!(f, "\n{}", link)?;
        // }
        Ok(())
    }
}

impl Display for AsExternalLsa {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== AS External LSA ==
  Forwarding Address: {}"#,
            self.forwarding_address
        )?;
        // for link in self.links.iter() {
        //     write!(f, "\n{}", link)?;
        // }
        Ok(())
    }
}
