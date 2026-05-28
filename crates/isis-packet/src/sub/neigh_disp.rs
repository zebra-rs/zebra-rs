use std::fmt::{Display, Formatter, Result};

use super::neigh::{
    IsisSubAdjSid, IsisSubAdminGrp, IsisSubAsla, IsisSubAvailableBw, IsisSubDelayVariation,
    IsisSubLinkLoss, IsisSubMinMaxLinkDelay, IsisSubResidualBw, IsisSubTlv, IsisSubUniLinkDelay,
    IsisSubUtilizedBw,
};
use super::{
    AdjSidFlags, IsisSubIpv4IfAddr, IsisSubIpv4NeighAddr, IsisSubIpv6IfAddr, IsisSubIpv6NeighAddr,
    IsisSubLanAdjSid, IsisSubSrv6EndXSid, IsisSubSrv6LanEndXSid, IsisSubTeMetric,
    IsisTlvExtIsReach, IsisTlvExtIsReachEntry, IsisTlvMtIsReach,
};

impl Display for IsisTlvExtIsReach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Extended IS Reachability:")?;
        for entry in self.entries.iter() {
            write!(f, "\n{}", entry)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvExtIsReachEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Neighbor ID: {}, Metric: {}"#,
            self.neighbor_id, self.metric
        )?;
        for sub in self.subs.iter() {
            write!(f, "\n{}", sub)?;
        }
        Ok(())
    }
}

impl Display for IsisSubTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisSubTlv::*;
        match self {
            Ipv4IfAddr(v) => write!(f, "{}", v),
            Ipv4NeighAddr(v) => write!(f, "{}", v),
            Ipv6IfAddr(v) => write!(f, "{}", v),
            Ipv6NeighAddr(v) => write!(f, "{}", v),
            AdminGrp(v) => write!(f, "{}", v),
            TeMetric(v) => write!(f, "{}", v),
            AdjSid(v) => write!(f, "{}", v),
            LanAdjSid(v) => write!(f, "{}", v),
            UniLinkDelay(v) => write!(f, "{}", v),
            MinMaxLinkDelay(v) => write!(f, "{}", v),
            DelayVariation(v) => write!(f, "{}", v),
            LinkLoss(v) => write!(f, "{}", v),
            ResidualBw(v) => write!(f, "{}", v),
            AvailableBw(v) => write!(f, "{}", v),
            UtilizedBw(v) => write!(f, "{}", v),
            Srv6EndXSid(v) => write!(f, "{}", v),
            Asla(v) => write!(f, "{}", v),
            Srv6LanEndXSid(v) => write!(f, "{}", v),
            Unknown(v) => write!(f, "    Unknown: ({:?})", v.code),
        }
    }
}

fn anomalous_str(a: bool) -> &'static str {
    if a { " (A)" } else { "" }
}

impl Display for IsisSubUniLinkDelay {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    Unidirectional Link Delay: {} us{}",
            self.delay,
            anomalous_str(self.anomalous)
        )
    }
}

impl Display for IsisSubMinMaxLinkDelay {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    Min/Max Unidirectional Link Delay: min {} us, max {} us{}",
            self.min_delay,
            self.max_delay,
            anomalous_str(self.anomalous)
        )
    }
}

impl Display for IsisSubDelayVariation {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    Unidirectional Delay Variation: {} us",
            self.variation
        )
    }
}

impl Display for IsisSubLinkLoss {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        // RFC 8570 §4.4: encoded units are 0.000003 % per LSB.
        let pct = self.loss as f64 * 0.000003;
        write!(
            f,
            "    Unidirectional Link Loss: {:.6}%{}",
            pct,
            anomalous_str(self.anomalous)
        )
    }
}

impl Display for IsisSubResidualBw {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    Unidirectional Residual Bandwidth: {} B/s",
            self.bw.bw_bps
        )
    }
}

impl Display for IsisSubAvailableBw {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    Unidirectional Available Bandwidth: {} B/s",
            self.bw.bw_bps
        )
    }
}

impl Display for IsisSubUtilizedBw {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    Unidirectional Utilized Bandwidth: {} B/s",
            self.bw.bw_bps
        )
    }
}

impl Display for IsisSubIpv4IfAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    IPv4 Interface Address: {}", self.addr)
    }
}

impl Display for IsisSubIpv4NeighAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    IPv4 Neighbor Address: {}", self.addr)
    }
}

impl Display for IsisSubIpv6IfAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    IPv6 Interface Address: {}", self.addr)
    }
}

impl Display for IsisSubIpv6NeighAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    IPv6 Neighbor Address: {}", self.addr)
    }
}

impl Display for IsisSubAdminGrp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    Admin Group:")?;
        for (i, group) in self.groups.iter().enumerate() {
            write!(f, " [{}] 0x{:08x}", i, group)?;
        }
        Ok(())
    }
}

impl Display for IsisSubTeMetric {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    Wide Metric: {}", self.metric)
    }
}

impl Display for AdjSidFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "F:{} B:{} V:{} L:{} S:{} P:{}",
            self.f_flag() as u8,
            self.b_flag() as u8,
            self.v_flag() as u8,
            self.l_flag() as u8,
            self.s_flag() as u8,
            self.p_flag() as u8
        )
    }
}

impl Display for IsisSubAdjSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    Adjacency SID: {:?}, Flag: {}, Weight: {}",
            self.sid, self.flags, self.weight
        )
    }
}

impl Display for IsisSubLanAdjSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(
            f,
            "    LAN Adjacency SID: {:?}, Weight: {}, Neighbor ID: {}",
            self.sid, self.weight, self.system_id
        )?;
        write!(f, "     Flags: {}", self.flags)
    }
}

impl Display for IsisSubSrv6EndXSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    SRv6 End.X SID: {}, Algo: {}, Weight: {}, Behavior {}, Flags: {}",
            self.sid, self.algo, self.weight, self.behavior, self.flags
        )?;
        for sub2 in self.sub2s.iter() {
            write!(f, "\n     {}", sub2)?;
        }
        Ok(())
    }
}

impl Display for IsisSubAsla {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let sabm_bits = self.sabm.first().copied().unwrap_or(0);
        let mut apps = Vec::new();
        if sabm_bits & 0x80 != 0 {
            apps.push("RSVP-TE");
        }
        if sabm_bits & 0x40 != 0 {
            apps.push("SR-Policy");
        }
        if sabm_bits & 0x20 != 0 {
            apps.push("LFA");
        }
        if sabm_bits & 0x10 != 0 {
            apps.push("Flex-Algo");
        }
        let app_str = if apps.is_empty() {
            "none".to_string()
        } else {
            apps.join(", ")
        };
        write!(
            f,
            "    Application Specific Link Attributes:\n     L:{} SABM: 0x{} UDABM: 0x{}\n     Applications: {}",
            self.l_flag as u8,
            hex::encode(&self.sabm),
            hex::encode(&self.udabm),
            app_str
        )?;
        for sub in &self.subs {
            write!(f, "\n  {}", sub)?;
        }
        Ok(())
    }
}

impl Display for IsisSubSrv6LanEndXSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(
            f,
            "    Lan End.X SID: {}, Weight: {}, Neighbor ID: {}",
            self.sid, self.weight, self.system_id
        )?;
        write!(
            f,
            "     Flags: {}, Algo: {}, Behavior {}",
            self.flags, self.algo, self.behavior
        )?;
        for sub2 in &self.sub2s {
            write!(f, "\n      {}", sub2)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvMtIsReach {
    /// One "MT Reachability: <neighbor_id> (Metric: N) <topology>"
    /// line per entry, mirroring TLV 222's operator-facing reference
    /// shape. Inlined to avoid the doubled "Neighbor ID:" prefix
    /// the entry's own Display would otherwise produce; sub-TLVs
    /// (Adj-SID, SRv6 End.X, etc.) hang off below the main line.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let topology = super::prefix_disp::mt_topology_name(self.mt.id());
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos != 0 {
                writeln!(f)?;
            }
            write!(
                f,
                "  MT Reachability: {} (Metric: {}) {}",
                entry.neighbor_id, entry.metric, topology,
            )?;
            for sub in &entry.subs {
                write!(f, "\n{sub}")?;
            }
        }
        Ok(())
    }
}
