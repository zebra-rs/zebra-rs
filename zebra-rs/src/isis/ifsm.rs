use anyhow::{Context, Result};
use isis_macros::isis_pdu_handler;
use isis_packet::*;

use crate::context::Timer;
use crate::isis::link::DisStatus;
use crate::rib::MacAddr;
use crate::{isis_debug, isis_event_trace, isis_packet_trace, isis_pdu_trace};

use super::inst::{Packet, PacketMessage};
use super::link::{Afis, HelloPaddingPolicy, LinkTop, LinkType};
use super::neigh::Neighbor;
use super::{Level, Message, NfsmState};

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

    let area_addr = ltop.up_config.net.area_id();
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

    let mut neighbors = Vec::new();
    for (_, nbr) in ltop.state.nbrs.get(&level).iter() {
        if nbr.state == NfsmState::Init || nbr.state == NfsmState::Up {
            if let Some(mac) = nbr.mac {
                neighbors.push(NeighborAddr {
                    octets: mac.octets(),
                })
            }
        }
    }
    hello.tlvs.push(IsisTlvIsNeighbor { neighbors }.into());
    if ltop.config.hello_padding() == HelloPaddingPolicy::Always {
        hello.padding(ltop.state.mtu as usize);
    }
    hello
}

pub fn hello_p2p_generate(ltop: &LinkTop, level: Level) -> IsisP2pHello {
    let source_id = ltop.up_config.net.sys_id();

    // P2P Hello doesn't use LAN ID
    let mut hello = IsisP2pHello {
        circuit_type: ltop.state.level(),
        source_id,
        hold_time: ltop.config.hold_time(),
        pdu_len: 0,
        circuit_id: 0,
        tlvs: Vec::new(),
    };

    // Add protocol support TLV
    let tlv = proto_supported(&ltop.up_config.enable);
    hello.tlvs.push(tlv.into());

    // Add area address TLV
    let area_addr = ltop.up_config.net.area_id();
    let tlv = IsisTlvAreaAddr { area_addr };
    hello.tlvs.push(tlv.into());

    // Add IPv4 interface addresses
    for prefix in &ltop.state.v4addr {
        hello.tlvs.push(
            IsisTlvIpv4IfAddr {
                addr: prefix.addr(),
            }
            .into(),
        );
    }

    // Three way handshake.
    let tlv = if let Some((_, nbr)) = ltop.state.nbrs.get(&level).first_key_value() {
        IsisTlvP2p3Way {
            state: nbr.state.into(),
            circuit_id: ltop.ifindex,
            neighbor_id: Some(nbr.sys_id.clone()),
            neighbor_circuit_id: nbr.circuit_id,
        }
    } else {
        IsisTlvP2p3Way {
            state: NfsmState::Down.into(),
            circuit_id: ltop.ifindex,
            neighbor_id: None,
            neighbor_circuit_id: None,
        }
    };
    hello.tlvs.push(tlv.into());

    if ltop.config.hello_padding() == HelloPaddingPolicy::Always {
        hello.padding(ltop.state.mtu as usize);
    }
    hello
}

fn hello_timer(ltop: &LinkTop, level: Level) -> Timer {
    let tx = ltop.tx.clone();
    let ifindex = ltop.ifindex;
    Timer::repeat(ltop.config.hello_interval(), move || {
        let tx = tx.clone();
        async move {
            use IfsmEvent::*;
            let msg = Message::Ifsm(HelloTimerExpire, ifindex, Some(level));
            tx.send(msg);
        }
    })
}

#[isis_pdu_handler(Hello, Send)]
pub fn hello_send(link: &mut LinkTop, level: Level) -> Result<()> {
    let hello = link.state.hello.get(&level).as_ref().context("")?;

    isis_pdu_trace!(link, &level, "[Hello] Send on {}", link.state.name);

    let packet = match hello {
        IsisPdu::P2pHello(hello) => {
            IsisPacket::from(IsisType::P2pHello, IsisPdu::P2pHello(hello.clone()))
        }
        IsisPdu::L1Hello(hello) => {
            IsisPacket::from(IsisType::L1Hello, IsisPdu::L1Hello(hello.clone()))
        }
        IsisPdu::L2Hello(hello) => {
            IsisPacket::from(IsisType::L2Hello, IsisPdu::L2Hello(hello.clone()))
        }
        _ => return Ok(()),
    };

    let ifindex = link.ifindex;
    link.ptx
        .send(PacketMessage::Send(Packet::Packet(packet), ifindex, level));
    Ok(())
}

#[isis_pdu_handler(Csnp, Send)]
pub fn csnp_send(link: &mut LinkTop, level: Level) -> Result<()> {
    // P2P interfaces don't use CSNP for database synchronization
    if link.config.link_type() == LinkType::P2p {
        isis_debug!("Skipping CSNP send for P2P interface {}", link.state.name);
        return Ok(());
    }

    isis_pdu_trace!(link, &level, "CSNP Send on {}", link.state.name);
    isis_packet_trace!(link.tracing, Csnp, Send, &level, "---------");

    const MAX_LSP_ENTRIES_PER_TLV: usize = 15;
    let mut lsp_entries = IsisTlvLspEntries::default();
    let mut entry_count = 0;

    let mut csnp = IsisCsnp {
        pdu_len: 0,
        source_id: link.up_config.net.sys_id().clone(),
        source_id_circuit: 0,
        start: IsisLspId::start(),
        end: IsisLspId::end(),
        tlvs: vec![],
    };

    for (lsp_id, lsa) in link.lsdb.get(&level).iter() {
        let hold_time = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec()) as u16;
        let entry = IsisLspEntry {
            hold_time,
            lsp_id: lsp_id.clone(),
            seq_number: lsa.lsp.seq_number,
            checksum: lsa.lsp.checksum,
        };
        lsp_entries.entries.push(entry);
        entry_count += 1;

        // If we've reached the limit, push this TLV and start a new one
        if entry_count >= MAX_LSP_ENTRIES_PER_TLV {
            csnp.tlvs.push(IsisTlv::LspEntries(lsp_entries));
            lsp_entries = IsisTlvLspEntries::default();
            entry_count = 0;
        }
    }

    // Don't forget to add the last TLV if it has any entries
    if !lsp_entries.entries.is_empty() {
        csnp.tlvs.push(IsisTlv::LspEntries(lsp_entries));
    }

    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Csnp, IsisPdu::L1Csnp(csnp.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Csnp, IsisPdu::L2Csnp(csnp.clone())),
    };
    let ifindex = link.ifindex;
    link.ptx
        .send(PacketMessage::Send(Packet::Packet(packet), ifindex, level));
    isis_packet_trace!(link.tracing, Csnp, Send, &level, "---------");
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
        // isis_packet_trace!(
        //     ltop.tracing,
        //     Hello,
        //     Send,
        //     &level,
        //     "Hello originate {} on {}",
        //     level,
        //     ltop.state.name
        // );

        let hello = if ltop.config.link_type() == LinkType::P2p {
            IsisPdu::P2pHello(hello_p2p_generate(ltop, level))
        } else {
            match level {
                Level::L1 => IsisPdu::L1Hello(hello_generate(ltop, level)),
                Level::L2 => IsisPdu::L2Hello(hello_generate(ltop, level)),
            }
        };

        *ltop.state.hello.get_mut(&level) = Some(hello);
        hello_send(ltop, level);
        *ltop.timer.hello.get_mut(&level) = Some(hello_timer(ltop, level));
    }
}

pub fn start(ltop: &mut LinkTop) {
    if ltop.flags.is_loopback() {
        return;
    }
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

pub fn dis_timer(ltop: &mut LinkTop, level: Level) -> Timer {
    let tx = ltop.tx.clone();
    let ifindex = ltop.ifindex;
    Timer::once(1, move || {
        let tx = tx.clone();
        async move {
            tx.send(Message::DisOriginate(level, ifindex, None))
                .unwrap();
        }
    })
}

pub fn purge_pseudonode_lsp(ltop: &mut LinkTop, level: Level) {
    // Only purge if we have an adjacency (meaning we were DIS)
    let Some(adj) = ltop.state.adj.get(&level) else {
        return;
    };

    isis_event_trace!(
        ltop.tracing,
        LspPurge,
        &level,
        "Purging pseudonode LSP for {} level {} adj {}",
        ltop.state.name,
        level,
        adj
    );

    // Create pseudonode LSP ID from the adjacency
    let pseudonode_lsp_id = IsisLspId::from_neighbor_id(adj.clone(), 0);

    // Send purge message to the main IS-IS instance
    ltop.tx
        .send(Message::LspPurge(level, pseudonode_lsp_id))
        .unwrap();
}

pub fn dis_selection(ltop: &mut LinkTop, level: Level) {
    // P2P interfaces don't need DIS election
    if ltop.config.link_type() == LinkType::P2p {
        isis_debug!(
            "Skipping DIS selection for P2P interface {}",
            ltop.state.name
        );
        return;
    }

    fn is_better(nbr: &Neighbor, curr_priority: u8, curr_mac: &Option<MacAddr>) -> bool {
        nbr.priority > curr_priority
            || (nbr.priority == curr_priority
                && match (&nbr.mac, curr_mac) {
                    (Some(n_mac), Some(c_mac)) => n_mac > c_mac,
                    _ => false,
                })
    }

    // Check if IS selection is dampened
    // if ltop.state.dis_stats.get(&level).is_dampened() {
    //     isis_debug!(
    //         "DIS selection dampened on {} level {}",
    //         ltop.state.name,
    //         level
    //     );
    //     return;
    // }

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
            best_priority = nbr.priority;
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
            let mac_str = if let Some(mac) = nbr.mac {
                format!("{}", mac)
            } else {
                "".to_string()
            };
            let reason = format!(
                "Neighbor {} elected (priority: {}, mac: {})",
                nbr.sys_id, nbr.priority, mac_str,
            );

            isis_event_trace!(
                ltop.tracing,
                Dis,
                &level,
                "DIS selection: {} on {} (priority: {}, neighbors: {})",
                nbr.sys_id,
                ltop.state.name,
                nbr.priority,
                nbrs_up
            );

            *ltop.state.dis_status.get_mut(&level) = status.clone();
            // Only here.
            isis_event_trace!(
                ltop.tracing,
                Dis,
                &level,
                "DIS sysid is set to {} on link {}",
                nbr.sys_id,
                ltop.state.name
            );
            *ltop.state.dis.get_mut(&level) = sys_id.clone();

            if ltop.state.lan_id.get(&level).is_none() {
                use IfsmEvent::*;
                if !nbr.lan_id.is_empty() {
                    isis_event_trace!(
                        ltop.tracing,
                        Dis,
                        &level,
                        "DIS lan_id {} received in Hello packet",
                        nbr.lan_id
                    );
                    *ltop.state.lan_id.get_mut(&level) = Some(nbr.lan_id.clone());
                    nbr.event(Message::Ifsm(HelloOriginate, nbr.ifindex, Some(level)));
                } else {
                    isis_debug!("DIS waiting for LAN Id in Hello packet");
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

        isis_event_trace!(
            ltop.tracing,
            Dis,
            &level,
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
        // Handle DIS status transitions
        if old_status == DisStatus::Myself && new_status != DisStatus::Myself {
            // We were DIS but no longer are
            isis_event_trace!(
                ltop.tracing,
                Dis,
                &level,
                "DIS transition: {} losing DIS status on level {}",
                ltop.state.name,
                level
            );

            // Purge our pseudonode LSP
            purge_pseudonode_lsp(ltop, level);

            // Clear LAN ID
            *ltop.state.lan_id.get_mut(&level) = None;

            // Stop DIS timers
            *ltop.timer.dis.get_mut(&level) = None;
            *ltop.timer.csnp.get_mut(&level) = None;
        } else if new_status == DisStatus::Myself {
            // We are becoming DIS
            isis_event_trace!(
                ltop.tracing,
                Dis,
                &level,
                "DIS transition: {} becoming DIS on level {}",
                ltop.state.name,
                level
            );

            // Start DIS timers
            *ltop.timer.dis.get_mut(&level) = Some(dis_timer(ltop, level));
            *ltop.timer.csnp.get_mut(&level) = Some(csnp_timer(ltop, level));
        } else {
            // Not DIS (either staying non-DIS or switching between Other/NotSelected)
            *ltop.timer.dis.get_mut(&level) = None;
            *ltop.timer.csnp.get_mut(&level) = None;
        }

        // Generate LSP to reflect DIS status change
        isis_event_trace!(
            ltop.tracing,
            LspOriginate,
            &level,
            "LspOriginate from dis_selection"
        );
        ltop.tx.send(Message::LspOriginate(level)).unwrap();

        ltop.state
            .dis_stats
            .get_mut(&level)
            .record_change(old_status, new_status, old_sys_id, new_sys_id, reason);
    }
}

fn csnp_timer(ltop: &LinkTop, level: Level) -> Timer {
    let tx = ltop.tx.clone();
    let ifindex = ltop.ifindex;
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
    let pseudo_id: u8 = ltop.ifindex as u8;
    let lsp_id = IsisLspId::new(ltop.up_config.net.sys_id(), pseudo_id, 0);
    isis_event_trace!(
        ltop.tracing,
        Dis,
        &level,
        "Generate DIS LSP_ID {} on {}",
        lsp_id,
        ltop.state.name
    );

    // Set myself as DIS.
    *ltop.state.dis_status.get_mut(&level) = DisStatus::Myself;

    // Register adjacency.
    *ltop.state.adj.get_mut(&level) = Some(lsp_id.neighbor_id());

    // Set LAN ID then generate hello.
    isis_event_trace!(
        ltop.tracing,
        Dis,
        &level,
        "Set DIS LAN_ID {} on {}",
        lsp_id.neighbor_id(),
        ltop.state.name
    );
    *ltop.state.lan_id.get_mut(&level) = Some(lsp_id.neighbor_id());
    hello_originate(ltop, level);
}

pub fn drop_dis(_ltop: &mut LinkTop, _level: Level) {
    //
}
