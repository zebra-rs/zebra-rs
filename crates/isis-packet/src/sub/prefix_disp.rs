use std::fmt::{Display, Formatter, Result};

use super::prefix::{
    IsisSub2SidStructure, IsisSub2Tlv, IsisSubSrv6EndSid, IsisSubTlv, PrefixSidFlags,
};
use super::{
    IsisSubPrefixSid, IsisTlvExtIpReach, IsisTlvExtIpReachEntry, IsisTlvIpv6Reach,
    IsisTlvIpv6ReachEntry,
};

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
            Unknown(v) => write!(f, "Unknown: Code {}, Length {}", v.code, v.len),
        }
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
            r#"   End SID: {}, Behavior: {}, Flags: {}"#,
            self.sid, self.behavior, self.flags,
        )?;
        for sub2 in &self.sub2s {
            write!(f, "\n    {}", sub2)?;
        }
        Ok(())
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
            "LB Len: {}, LN Len: {}, Func Len: {}, Arg Len: {}",
            self.lb_len, self.ln_len, self.fun_len, self.arg_len
        )
    }
}
