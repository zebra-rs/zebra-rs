use std::fmt::{Display, Formatter, Result};

use super::cap::{FadSubTlv, IsisSubFlexAlgoDef, IsisSubSrv6, IsisSubTlv, RouterCapFlags};
use super::{
    IsisSubNodeMaxSidDepth, IsisSubSegmentRoutingAlgo, IsisSubSegmentRoutingCap,
    IsisSubSegmentRoutingLB, IsisTlvRouterCap, SegmentRoutingCapFlags,
};

impl Display for RouterCapFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "D:{} S:{}", self.d_flag() as u8, self.s_flag() as u8)
    }
}

impl Display for IsisTlvRouterCap {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"  Router Capability: {}, {}"#,
            self.router_id, self.flags
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
            SegmentRoutingCap(v) => write!(f, "{}", v),
            SegmentRoutingAlgo(v) => write!(f, "{}", v),
            SegmentRoutingLB(v) => write!(f, "{}", v),
            NodeMaxSidDepth(v) => write!(f, "{}", v),
            Srv6(v) => write!(f, "{}", v),
            FlexAlgoDef(v) => write!(f, "{}", v),
            Unknown(v) => write!(f, "   Unknown Code: {} Len: {}", v.code, v.len),
        }
    }
}

impl Display for IsisSubFlexAlgoDef {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "   Flex-Algorithm Definition: Algo {}, Metric-Type {}, Calc-Type {}, Priority {}",
            self.flex_algorithm, self.metric_type, self.calc_type, self.priority
        )?;
        for sub in &self.subs {
            write!(f, "\n{}", sub)?;
        }
        Ok(())
    }
}

impl Display for FadSubTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use FadSubTlv::*;
        match self {
            ExcludeAg(v) => write!(
                f,
                "     FAD Exclude Admin-Group ({} words)",
                v.group.words.len()
            ),
            IncludeAnyAg(v) => write!(
                f,
                "     FAD Include-Any Admin-Group ({} words)",
                v.group.words.len()
            ),
            IncludeAllAg(v) => write!(
                f,
                "     FAD Include-All Admin-Group ({} words)",
                v.group.words.len()
            ),
            Flags(v) => write!(f, "     FAD Flags M:{}", v.m_flag as u8),
            ExcludeSrlg(v) => {
                write!(f, "     FAD Exclude SRLG: {} ids", v.srlgs.len())
            }
            Unknown(v) => write!(f, "     FAD Unknown Code: {} Len: {}", v.code, v.len),
        }
    }
}

impl Display for SegmentRoutingCapFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "I:{} V:{}", self.i_flag() as u8, self.v_flag() as u8,)
    }
}

impl Display for IsisSubSegmentRoutingCap {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Segment Routing: {}, Global Block: {:?}, Range: {}"#,
            self.flags, self.sid_label, self.range
        )
    }
}

impl Display for IsisSubSegmentRoutingAlgo {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, r#"   Segment Routing Algorithm:"#)?;
        for algo in &self.algo {
            write!(f, " {}", algo)?;
        }
        Ok(())
    }
}

impl Display for IsisSubSegmentRoutingLB {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Segment Routing Local Block: {:?}, Range: {}"#,
            self.sid_label, self.range
        )
    }
}

impl Display for IsisSubNodeMaxSidDepth {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Node Maximum SID Depth: Type:{}, Value:{}"#,
            self.flags, self.depth
        )
    }
}

impl Display for IsisSubSrv6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, r#"   SRv6: O:{}"#, self.flags.o_flag() as u8)
    }
}
