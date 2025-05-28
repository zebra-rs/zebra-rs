use anyhow::{Context, Result};
use isis_packet::{
    IsLevel, IsisCsnp, IsisHello, IsisLspEntry, IsisLspId, IsisNeighborId, IsisPacket, IsisPdu,
    IsisProto, IsisSysId, IsisTlv, IsisTlvAreaAddr, IsisTlvIpv4IfAddr, IsisTlvIsNeighbor,
    IsisTlvLspEntries, IsisTlvProtoSupported, IsisType,
};

use crate::isis::link::DisStatus;
use crate::rib::MacAddr;

use super::inst::{Packet, PacketMessage};
use super::link::{Afis, HelloPaddingPolicy, LinkTop};
use super::neigh::Neighbor;
use super::task::Timer;
use super::{IsisLink, Level, Message, NfsmState};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IfsmEvent {
    Start,
    Stop,
    InterfaceUp,
    InterfaceDown,
    HelloTimerExpire,
    CsnpTimerExpire,
    HelloOriginate,
    DisSelection,
}

pub fn proto_supported(enable: &Afis<usize>) -> IsisTlvProtoSupported {
    let mut nlpids = vec![];
    if enable.v4 > 0 {
        nlpids.push(IsisProto::Ipv4.into());
    }
    if enable.v6 > 0 {
        nlpids.push(IsisProto::Ipv6.into());
    }
    IsisTlvProtoSupported { nlpids }
}

pub fn hello_generate(ltop: &LinkTop, level: Level) -> IsisHello {
    let source_id = ltop.up_config.net.sys_id();
    let lan_id = ltop
        .state
        .lan_id
        .get(&level)
        .clone()
        .unwrap_or(IsisNeighborId::default());
    let mut hello = IsisHello {
        circuit_type: ltop.state.level(),
        source_id,
        hold_time: ltop.config.hold_time(),
        pdu_len: 0,
        priority: ltop.config.priority(),
        lan_id,
        tlvs: Vec::new(),
    };
    let tlv = proto_supported(&ltop.up_config.enable);
    hello.tlvs.push(tlv.into());

    let area_addr = vec![0x49, 0, 1];
    let tlv = IsisTlvAreaAddr { area_addr };
    hello.tlvs.push(tlv.into());
    for prefix in &ltop.state.v4addr {
        hello.tlvs.push(
            IsisTlvIpv4IfAddr {
                addr: prefix.addr(),
            }
            .into(),
        );
    }

    for (_, nbr) in ltop.state.nbrs.get(&level).iter() {
        if nbr.state == NfsmState::Init || nbr.state == NfsmState::Up {
            if let Some(mac) = nbr.mac {
                hello.tlvs.push(
                    IsisTlvIsNeighbor {
                        octets: mac.octets(),
                    }
                    .into(),
                );
            }
        }
    }
    if ltop.config.hello_padding() == HelloPaddingPolicy::Always {
        hello.padding(ltop.state.mtu as usize);
    }
    hello
}

fn hello_timer(ltop: &LinkTop, level: Level) -> Timer {
    let tx = ltop.tx.clone();
    let ifindex = ltop.state.ifindex;
    Timer::repeat(ltop.config.hello_interval(), move || {
        let tx = tx.clone();
        async move {
            use IfsmEvent::*;
            let msg = Message::Ifsm(HelloTimerExpire, ifindex, Some(level));
            tx.send(msg);
        }
    })
}

pub fn hello_send(ltop: &mut LinkTop, level: Level) -> Result<()> {
    let hello = ltop.state.hello.get(&level).as_ref().context("")?;
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Hello, IsisPdu::L1Hello(hello.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Hello, IsisPdu::L2Hello(hello.clone())),
    };
    let ifindex = ltop.state.ifindex;
    ltop.ptx
        .send(PacketMessage::Send(Packet::Packet(packet), ifindex, level));
    Ok(())
}

pub fn csnp_send(ltop: &mut LinkTop, level: Level) -> Result<()> {
    println!("XXX CSNP Send");

    let mut lsp_entries = IsisTlvLspEntries::default();
    for (lsp_id, lsa) in ltop.lsdb.get(&level).iter() {
        let hold_time = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec()) as u16;
        let entry = IsisLspEntry {
            hold_time,
            lsp_id: lsp_id.clone(),
            seq_number: lsa.lsp.seq_number,
            checksum: lsa.lsp.checksum,
        };
        lsp_entries.entries.push(entry);
    }
    let mut csnp = IsisCsnp {
        pdu_len: 0,
        source_id: ltop.up_config.net.sys_id().clone(),
        source_id_circuit: 0,
        start: IsisLspId::start(),
        end: IsisLspId::end(),
        tlvs: vec![],
    };
    csnp.tlvs.push(IsisTlv::LspEntries(lsp_entries));
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Csnp, IsisPdu::L1Csnp(csnp.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Csnp, IsisPdu::L2Csnp(csnp.clone())),
    };
    let ifindex = ltop.state.ifindex;
    ltop.ptx
        .send(PacketMessage::Send(Packet::Packet(packet), ifindex, level));
    Ok(())
}

pub fn has_level(is_level: IsLevel, level: Level) -> bool {
    match level {
        Level::L1 => matches!(is_level, IsLevel::L1 | IsLevel::L1L2),
        Level::L2 => matches!(is_level, IsLevel::L2 | IsLevel::L1L2),
    }
}

pub fn hello_originate(ltop: &mut LinkTop, level: Level) {
    if has_level(ltop.state.level(), level) {
        tracing::info!("Hello originate {} on {}", level, ltop.state.name);
        let hello = hello_generate(ltop, level);
        *ltop.state.hello.get_mut(&level) = Some(hello);
        hello_send(ltop, level);
        *ltop.timer.hello.get_mut(&level) = Some(hello_timer(ltop, level));
    }
}

pub fn start(ltop: &mut LinkTop) {
    for level in [Level::L1, Level::L2] {
        hello_originate(ltop, level);
    }
}

pub fn stop(ltop: &mut LinkTop) {
    for level in [Level::L1, Level::L2] {
        *ltop.state.hello.get_mut(&level) = None;
        *ltop.timer.hello.get_mut(&level) = None;
    }
}

pub fn dis_selection(ltop: &mut LinkTop, level: Level) {
    fn is_better(nbr: &Neighbor, curr_priority: u8, curr_mac: &Option<MacAddr>) -> bool {
        nbr.pdu.priority > curr_priority
            || (nbr.pdu.priority == curr_priority
                && match (&nbr.mac, curr_mac) {
                    (Some(n_mac), Some(c_mac)) => n_mac > c_mac,
                    _ => false,
                })
    }

    // Check if DIS selection is dampened
    if ltop.state.dis_stats.get(&level).is_dampened() {
        tracing::debug!(
            "DIS selection dampened on {} level {}",
            ltop.state.name,
            level
        );
        return;
    }

    // Store current DIS state for tracking
    let old_status = *ltop.state.dis_status.get(&level);
    let old_sys_id = ltop.state.dis.get(&level).clone();

    // When curr is None, current candidate DIS is myself.
    let mut best_key: Option<IsisSysId> = None;
    let mut best_priority = ltop.config.priority();
    let mut best_mac = ltop.state.mac.clone();

    // We will check at least one Up state neighbor exists.
    let mut nbrs_up = 0;

    for (key, nbr) in ltop.state.nbrs.get_mut(&level).iter_mut() {
        nbr.dis = false;
        if nbr.state != NfsmState::Up {
            continue;
        }
        if is_better(nbr, best_priority, &best_mac) {
            best_priority = nbr.pdu.priority;
            best_mac = nbr.mac.clone();
            best_key = Some(key.clone());
        }
        nbrs_up += 1;
    }
    *ltop.state.nbrs_up.get_mut(&level) = nbrs_up;

    let (new_status, new_sys_id, reason) = if nbrs_up == 0 {
        let status = DisStatus::NotSelected;
        *ltop.state.dis_status.get_mut(&level) = status.clone();
        (status, None, "No up neighbors".to_string())
    } else if let Some(ref key) = best_key {
        if let Some(nbr) = ltop.state.nbrs.get_mut(&level).get_mut(key) {
            nbr.dis = true;
            let status = DisStatus::Other;
            let sys_id = Some(nbr.sys_id.clone());
            let reason = format!(
                "Neighbor {} elected (priority: {}, mac: {:?})",
                nbr.sys_id, nbr.pdu.priority, nbr.mac
            );

            tracing::info!(
                "DIS selection: {} on {} (priority: {}, neighbors: {})",
                nbr.sys_id,
                ltop.state.name,
                nbr.pdu.priority,
                nbrs_up
            );

            *ltop.state.dis_status.get_mut(&level) = status.clone();
            *ltop.state.dis.get_mut(&level) = sys_id.clone();

            if ltop.state.lan_id.get(&level).is_none() {
                if !nbr.pdu.lan_id.is_empty() {
                    tracing::info!("DIS lan_id {} received in Hello packet", nbr.pdu.lan_id);
                    *ltop.state.lan_id.get_mut(&level) = Some(nbr.pdu.lan_id.clone());
                } else {
                    tracing::debug!("DIS waiting for LAN Id in Hello packet");
                }
            }
            (status, sys_id, reason)
        } else {
            return; // Shouldn't happen
        }
    } else {
        let status = DisStatus::Myself;
        let sys_id = Some(ltop.up_config.net.sys_id());
        let reason = format!(
            "Self elected (priority: {}, neighbors: {})",
            ltop.config.priority(),
            nbrs_up
        );

        tracing::info!(
            "DIS selection: self on {} (priority: {}, neighbors: {})",
            ltop.state.name,
            ltop.config.priority(),
            nbrs_up
        );
        become_dis(ltop, level);
        (status, sys_id, reason)
    };

    // Record DIS change if status actually changed
    if old_status != new_status || old_sys_id != new_sys_id {
        ltop.state
            .dis_stats
            .get_mut(&level)
            .record_change(old_status, new_status, old_sys_id, new_sys_id, reason);
    }
}

fn csnp_timer(ltop: &LinkTop, level: Level) -> Timer {
    let tx = ltop.tx.clone();
    let ifindex = ltop.state.ifindex;
    Timer::repeat(ltop.config.csnp_interval(), move || {
        let tx = tx.clone();
        async move {
            use IfsmEvent::*;
            let msg = Message::Ifsm(CsnpTimerExpire, ifindex, Some(level));
            tx.send(msg);
        }
    })
}

pub fn become_dis(ltop: &mut LinkTop, level: Level) {
    // Generate DIS pseudo node id.
    let pseudo_id: u8 = ltop.state.ifindex as u8;
    let lsp_id = IsisLspId::new(ltop.up_config.net.sys_id(), pseudo_id, 0);
    tracing::info!("Generate DIS LSP_ID {} on {}", lsp_id, ltop.state.name);

    // Set myself as DIS.
    *ltop.state.dis_status.get_mut(&level) = DisStatus::Myself;

    // Register adjacency.
    *ltop.state.adj.get_mut(&level) = Some(lsp_id.neighbor_id());

    // Set LAN ID then generate hello.
    *ltop.state.lan_id.get_mut(&level) = Some(lsp_id.neighbor_id());
    hello_originate(ltop, level);

    // Generate LSP.
    tracing::info!("XXX LspOriginate in become_dis");
    ltop.tx.send(Message::LspOriginate(level)).unwrap();

    // Generate DIS.
    ltop.tx
        .send(Message::DisOriginate(level, ltop.state.ifindex))
        .unwrap();

    // Schedule CSNP.
    *ltop.timer.csnp.get_mut(&level) = Some(csnp_timer(ltop, level));
}

pub fn drop_dis(ltop: &mut LinkTop, level: Level) {
    //
}
