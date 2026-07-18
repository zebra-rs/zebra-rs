use std::fmt::{Display, Formatter, Result};

use crate::addr::{EncodedGroup, EncodedSource, EncodedUnicast};
use crate::hello::HelloTlv;
use crate::parser::{PimPacket, PimPayload};

impl Display for EncodedUnicast {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.addr)
    }
}

impl Display for EncodedGroup {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}/{}", self.addr, self.masklen)
    }
}

impl Display for EncodedSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}/{}", self.addr, self.masklen)?;
        if self.sparse {
            write!(f, " S")?;
        }
        if self.wildcard {
            write!(f, " W")?;
        }
        if self.rpt {
            write!(f, " R")?;
        }
        Ok(())
    }
}

impl Display for HelloTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::Holdtime(v) => write!(f, " Holdtime: {v}"),
            Self::LanPruneDelay {
                t_bit,
                propagation_delay,
                override_interval,
            } => write!(
                f,
                " LAN Prune Delay: delay {propagation_delay}ms override {override_interval}ms T={}",
                *t_bit as u8
            ),
            Self::DrPriority(v) => write!(f, " DR Priority: {v}"),
            Self::GenerationId(v) => write!(f, " Generation ID: {v:#010x}"),
            Self::AddressList(addrs) => {
                write!(f, " Address List:")?;
                for addr in addrs {
                    write!(f, " {addr}")?;
                }
                Ok(())
            }
            Self::Unknown { typ, data } => write!(f, " Unknown({typ}): {} bytes", data.len()),
        }
    }
}

impl Display for PimPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(f, "PIMv{} {}", self.version, self.typ)?;
        match &self.payload {
            PimPayload::Hello(hello) => {
                for tlv in &hello.tlvs {
                    writeln!(f, "{tlv}")?;
                }
            }
            PimPayload::Register(register) => {
                writeln!(
                    f,
                    " B={} N={} data {} bytes",
                    register.border as u8,
                    register.null_register as u8,
                    register.data.len()
                )?;
            }
            PimPayload::RegisterStop(stop) => {
                writeln!(f, " Group: {} Source: {}", stop.group, stop.source)?;
            }
            PimPayload::JoinPrune(jp) => {
                writeln!(
                    f,
                    " Upstream neighbor: {} holdtime {}",
                    jp.upstream_neighbor, jp.holdtime
                )?;
                for group in &jp.groups {
                    writeln!(f, " Group: {}", group.group)?;
                    for join in &group.joins {
                        writeln!(f, "  Join: {join}")?;
                    }
                    for prune in &group.prunes {
                        writeln!(f, "  Prune: {prune}")?;
                    }
                }
            }
            PimPayload::Assert(assert) => {
                writeln!(
                    f,
                    " Group: {} Source: {} R={} pref {} metric {}",
                    assert.group,
                    assert.source,
                    assert.rpt_bit as u8,
                    assert.metric_preference,
                    assert.metric
                )?;
            }
            PimPayload::Bootstrap(bsm) => {
                writeln!(
                    f,
                    " BSR: {} priority {} tag {} ({} group range(s))",
                    bsm.bsr_addr,
                    bsm.bsr_priority,
                    bsm.fragment_tag,
                    bsm.groups.len()
                )?;
            }
            PimPayload::CandRpAdv(adv) => {
                writeln!(
                    f,
                    " C-RP: {} priority {} holdtime {} ({} group range(s))",
                    adv.rp_addr,
                    adv.priority,
                    adv.holdtime,
                    adv.groups.len()
                )?;
            }
            PimPayload::Unknown { data, .. } => {
                writeln!(f, " {} bytes", data.len())?;
            }
        }
        Ok(())
    }
}
