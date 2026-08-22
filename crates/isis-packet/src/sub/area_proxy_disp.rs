use std::fmt::{Display, Formatter, Result};

use super::area_proxy::{
    AreaSidFlags, AreaSidPrefix, IsisAreaProxySub, IsisSubAreaSid, IsisSubProxySystemId,
    IsisTlvAreaProxy,
};

impl Display for IsisTlvAreaProxy {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Area Proxy:")?;
        for sub in self.subs.iter() {
            write!(f, "\n{}", sub)?;
        }
        Ok(())
    }
}

impl Display for IsisAreaProxySub {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisAreaProxySub::*;
        match self {
            ProxySystemId(v) => write!(f, "{}", v),
            AreaSid(v) => write!(f, "{}", v),
            Unknown(v) => write!(f, "   Unknown Code: {} Len: {}", v.code, v.len),
        }
    }
}

impl Display for IsisSubProxySystemId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "   Proxy System ID: {}", self.sys_id)
    }
}

impl Display for AreaSidFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "F:{} V:{} L:{}",
            self.f_flag() as u8,
            self.v_flag() as u8,
            self.l_flag() as u8
        )
    }
}

impl Display for IsisSubAreaSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "   Area SID: {}, Prefix: {}, Flags: {}",
            self.sid, self.prefix, self.flags
        )
    }
}

impl Display for AreaSidPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            AreaSidPrefix::V4(p) => write!(f, "{}", p),
            AreaSidPrefix::V6(p) => write!(f, "{}", p),
        }
    }
}
