use std::fmt::{Display, Formatter, Result};

use super::prefix::{
    IsisMirrorSub2Tlv, IsisSub2ProtectedLocators, IsisSub2SidStructure, IsisSub2Tlv,
    IsisSubIpv4SourceRouterId, IsisSubIpv6SourceRouterId, IsisSubSrv6EndSid, IsisSubSrv6MirrorSid,
    IsisSubTlv, PrefixSidFlags,
};
use super::{
    BindingPrefix, IsisBindingSubTlv, IsisSubPrefixSid, IsisTlvExtIpReach, IsisTlvExtIpReachEntry,
    IsisTlvIpv6Reach, IsisTlvIpv6ReachEntry, IsisTlvMtIpReach, IsisTlvMtIpv6Reach,
    IsisTlvMultiTopology, IsisTlvSidLabelBinding, MultiTopologyId,
};

impl Display for BindingPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            BindingPrefix::V4(p) => write!(f, "{}", p),
            BindingPrefix::V6(p) => write!(f, "{}", p),
        }
    }
}

impl Display for IsisTlvSidLabelBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  SID/Label Binding")?;
        if self.flags.m_flag() {
            write!(f, " (Mirror Context)")?;
        }
        write!(f, ": {}", self.prefix)?;
        if self.range > 1 {
            write!(f, " range {}", self.range)?;
        }
        for sub in &self.subs {
            match sub {
                IsisBindingSubTlv::SidLabel(sid) => write!(f, " label/index {}", sid.value())?,
                IsisBindingSubTlv::Unknown { typ, .. } => write!(f, " sub-tlv {}", typ)?,
            }
        }
        Ok(())
    }
}

impl Display for IsisTlvExtIpReach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos != 0 {
                writeln!(f)?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvExtIpReachEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"  Extended IP Reachability: {} (Metric: {})"#,
            self.prefix, self.metric,
        )?;
        for sub in &self.subs {
            write!(f, "\n{}", sub)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvIpv6Reach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos != 0 {
                writeln!(f)?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvIpv6ReachEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"  IPv6 Reachability: {} (Metric: {})"#,
            self.prefix, self.metric,
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
            PrefixSid(v) => write!(f, "{}", v),
            Srv6EndSid(v) => write!(f, "{}", v),
            Srv6MirrorSid(v) => write!(f, "{}", v),
            Ipv4SourceRouterId(v) => write!(f, "{}", v),
            Ipv6SourceRouterId(v) => write!(f, "{}", v),
            Unknown(v) => write!(f, "Unknown: Code {}, Length {}", v.code, v.len),
        }
    }
}

impl Display for IsisSubIpv4SourceRouterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "   IPv4 Source Router ID: {}", self.router_id)
    }
}

impl Display for IsisSubIpv6SourceRouterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "   IPv6 Source Router ID: {}", self.router_id)
    }
}

impl Display for PrefixSidFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "R:{} N:{} P:{} E:{} V:{} L:{}",
            self.r_flag() as u8,
            self.n_flag() as u8,
            self.p_flag() as u8,
            self.e_flag() as u8,
            self.v_flag() as u8,
            self.l_flag() as u8
        )
    }
}

impl Display for IsisSubPrefixSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   SID: {:?}, Algorithm: {}, Flags: {}"#,
            self.sid, self.algo, self.flags,
        )
    }
}

impl Display for IsisSubSrv6EndSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   SRv6 End SID: Behavior: {}, SID value: {}, Flags: {}"#,
            self.behavior, self.sid, self.flags,
        )?;
        for sub2 in &self.sub2s {
            write!(f, "\n    {}", sub2)?;
        }
        Ok(())
    }
}

impl Display for IsisSubSrv6MirrorSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   SRv6 Mirror SID: Behavior: {}, SID value: {}, Flags: {}"#,
            self.behavior, self.sid, self.flags,
        )?;
        for sub2 in &self.sub2s {
            write!(f, "\n    {}", sub2)?;
        }
        Ok(())
    }
}

impl Display for IsisMirrorSub2Tlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisMirrorSub2Tlv::*;
        match self {
            ProtectedLocators(v) => write!(f, "{}", v),
            Unknown(v) => write!(f, "Unknown: Code {}, Length {}", v.code, v.len),
        }
    }
}

impl Display for IsisSub2ProtectedLocators {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "Protected Locator: {}", self.locator)
    }
}

impl Display for IsisSub2Tlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisSub2Tlv::*;
        match self {
            SidStructure(v) => write!(f, "{}", v),
            Unknown(v) => write!(f, "Unknown: Code {}, Length {}", v.code, v.len),
        }
    }
}

impl Display for IsisSub2SidStructure {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "Locator Block Len: {}, Node Len: {}, Func Len: {}, Arg Len: {}",
            self.lb_len, self.ln_len, self.fun_len, self.arg_len
        )
    }
}

impl Display for MultiTopologyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", mt_topology_name(self.id()))
    }
}

/// Operator-facing name for a 12-bit MT identifier per RFC 5120 §1.4
/// and IANA "IS-IS MT IDs". Falls back to a `MT-N` placeholder for
/// unknown / private-use values so the show output stays useful even
/// when peers advertise topologies we don't model locally.
pub fn mt_topology_name(id: u16) -> String {
    match id {
        0 => "ipv4-unicast".to_string(),
        1 => "in-band-management".to_string(),
        2 => "ipv6-unicast".to_string(),
        3 => "ipv4-multicast".to_string(),
        4 => "ipv6-multicast".to_string(),
        n => format!("MT-{n}"),
    }
}

impl Display for IsisTlvMultiTopology {
    /// One "MT Router Info: <name>" line per topology. RFC 5120 §3.1
    /// — the LSP advertises every MT the router participates in;
    /// listing them on separate lines mirrors what other IS-IS
    /// implementations print and matches the operator-facing
    /// reference output.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos != 0 {
                writeln!(f)?;
            }
            write!(f, "  MT Router Info: {entry}")?;
        }
        Ok(())
    }
}

impl Display for IsisTlvMtIpReach {
    /// One "MT IP Reachability: <prefix> (Metric: N) <topology>" line
    /// per entry, with any sub-TLVs hanging off below. The prefix +
    /// metric are inlined here rather than delegated to the entry's
    /// own Display, which prepends "Extended IP Reachability:" and
    /// would otherwise produce a doubled label.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let topology = mt_topology_name(self.mt.id());
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos != 0 {
                writeln!(f)?;
            }
            write!(
                f,
                "  MT IP Reachability: {} (Metric: {}) {}",
                entry.prefix, entry.metric, topology,
            )?;
            for sub in &entry.subs {
                write!(f, "\n{sub}")?;
            }
        }
        Ok(())
    }
}

impl Display for IsisTlvMtIpv6Reach {
    /// One "MT IPv6 Reachability: <prefix> (Metric: N) <topology>"
    /// line per entry. Same prefix/metric inlining as IsisTlvMtIpReach.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let topology = mt_topology_name(self.mt.id());
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos != 0 {
                writeln!(f)?;
            }
            write!(
                f,
                "  MT IPv6 Reachability: {} (Metric: {}) {}",
                entry.prefix, entry.metric, topology,
            )?;
            for sub in &entry.subs {
                write!(f, "\n{sub}")?;
            }
        }
        Ok(())
    }
}
