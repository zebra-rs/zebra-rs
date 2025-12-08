use anyhow::{Context, Result};
use isis_macros::isis_pdu_handler;
use isis_packet::*;

use crate::context::Timer;
use crate::isis::inst::csnp_generate;
use crate::isis::link::DisStatus;
use crate::isis::network::P2P_ISS;
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

pub fn hello_generate(link: &LinkTop, level: Level) -> IsisHello {
    let source_id = link.up_config.net.sys_id();
    let lan_id = link
        .state
        .adj
        .get(&level)
        .map(|(neighbor_id, _)| neighbor_id)
        .unwrap_or_default();
    tracing::info!("[Hello:Gen] LAN ID:{}", lan_id);
    let mut hello = IsisHello {
        circuit_type: link.state.level(),
        source_id,
        hold_time: link.config.hold_time(),
        pdu_len: 0,
        priority: link.config.priority(),
        lan_id,
        tlvs: Vec::new(),
    };
    let tlv = proto_supported(&link.up_config.enable);
    hello.tlvs.push(tlv.into());

    let area_addr = link.up_config.net.area_id();
    let tlv = IsisTlvAreaAddr { area_addr };
    hello.tlvs.push(tlv.into());
    for prefix in &link.state.v4addr {
        hello.tlvs.push(
            IsisTlvIpv4IfAddr {
                addr: prefix.addr(),
            }
            .into(),
        );
    }

    let mut neighbors = Vec::new();
    for (_, nbr) in link.state.nbrs.get(&level).iter() {
        if nbr.state == NfsmState::Init || nbr.state == NfsmState::Up {
            if let Some(mac) = nbr.mac {
                neighbors.push(NeighborAddr {
                    octets: mac.octets(),
                })
            }
        }
    }
    hello.tlvs.push(IsisTlvIsNeighbor { neighbors }.into());
    if link.config.hello_padding() == HelloPaddingPolicy::Always {
        hello.padding(link.state.mtu as usize);
    }
    hello
}

pub fn hello_p2p_generate(link: &LinkTop, level: Level) -> IsisP2pHello {
    let source_id = link.up_config.net.sys_id();

    // P2P Hello doesn't use LAN ID
    let mut hello = IsisP2pHello {
        circuit_type: link.state.level(),
        source_id,
        hold_time: link.config.hold_time(),
        pdu_len: 0,
        circuit_id: 0,
        tlvs: Vec::new(),
    };

    // Add protocol support TLV
    let tlv = proto_supported(&link.up_config.enable);
    hello.tlvs.push(tlv.into());

    // Add area address TLV
    let area_addr = link.up_config.net.area_id();
    let tlv = IsisTlvAreaAddr { area_addr };
    hello.tlvs.push(tlv.into());

    // Add IPv4 interface addresses
    for prefix in &link.state.v4addr {
        hello.tlvs.push(
            IsisTlvIpv4IfAddr {
                addr: prefix.addr(),
            }
            .into(),
        );
    }

    // Three way handshake.
    let tlv = if let Some((_, nbr)) = link.state.nbrs.get(&level).first_key_value() {
        IsisTlvP2p3Way {
            state: nbr.state.into(),
            circuit_id: link.ifindex,
            neighbor_id: Some(nbr.sys_id.clone()),
            neighbor_circuit_id: nbr.circuit_id,
        }
    } else {
        IsisTlvP2p3Way {
            state: NfsmState::Down.into(),
            circuit_id: link.ifindex,
            neighbor_id: None,
            neighbor_circuit_id: None,
        }
    };
    hello.tlvs.push(tlv.into());

    if link.config.hello_padding() == HelloPaddingPolicy::Always {
        hello.padding(link.state.mtu as usize);
    }
    hello
}

fn hello_timer(link: &LinkTop, level: Level) -> Timer {
    let tx = link.tx.clone();
    let ifindex = link.ifindex;
    Timer::repeat(link.config.hello_interval(), move || {
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

    let (packet, mac) = match hello {
        IsisPdu::L1Hello(hello) => (
            IsisPacket::from(IsisType::L1Hello, IsisPdu::L1Hello(hello.clone())),
            None,
        ),
        IsisPdu::L2Hello(hello) => (
            IsisPacket::from(IsisType::L2Hello, IsisPdu::L2Hello(hello.clone())),
            None,
        ),
        IsisPdu::P2pHello(hello) => (
            IsisPacket::from(IsisType::P2pHello, IsisPdu::P2pHello(hello.clone())),
            MacAddr::from_vec(P2P_ISS.to_vec()),
        ),
        _ => return Ok(()),
    };

    if mac.is_none() {
        isis_pdu_trace!(link, &level, "[Hello:Send] {}", link.state.name);
    } else {
        isis_pdu_trace!(link, &level, "[P2P Hello:Send] {}", link.state.name);
    }

    let ifindex = link.ifindex;
    link.ptx.send(PacketMessage::Send(
        Packet::Packet(packet),
        ifindex,
        level,
        mac,
    ));
    Ok(())
}

pub fn has_level(is_level: IsLevel, level: Level) -> bool {
    match level {
        Level::L1 => matches!(is_level, IsLevel::L1 | IsLevel::L1L2),
        Level::L2 => matches!(is_level, IsLevel::L2 | IsLevel::L1L2),
    }
}

pub fn hello_originate(link: &mut LinkTop, level: Level) {
    if has_level(link.state.level(), level) {
        let hello = if link.config.link_type() == LinkType::P2p {
            IsisPdu::P2pHello(hello_p2p_generate(link, level))
        } else {
            match level {
                Level::L1 => IsisPdu::L1Hello(hello_generate(link, level)),
                Level::L2 => IsisPdu::L2Hello(hello_generate(link, level)),
            }
        };

        *link.state.hello.get_mut(&level) = Some(hello);
        hello_send(link, level);
        *link.timer.hello.get_mut(&level) = Some(hello_timer(link, level));
    }
}

pub fn start(link: &mut LinkTop) {
    if link.flags.is_loopback() {
        return;
    }
    for level in [Level::L1, Level::L2] {
        hello_originate(link, level);
    }
}

pub fn stop(link: &mut LinkTop) {
    for level in [Level::L1, Level::L2] {
        *link.state.hello.get_mut(&level) = None;
        *link.timer.hello.get_mut(&level) = None;
    }
}

pub fn dis_becoming(link: &mut LinkTop, level: Level) {
    use IfsmEvent::*;

    let pseudo_id: u8 = link.ifindex as u8;
    let lsp_id = IsisLspId::new(link.up_config.net.sys_id(), pseudo_id, 0);

    // Register adjacency with LAN ID.
    *link.state.adj.get_mut(&level) = Some((lsp_id.neighbor_id(), None));
    link.lsdb.get_mut(&level).adj_set(link.ifindex);

    // Regenerate Hello.
    link.event(Message::Ifsm(HelloOriginate, link.ifindex, Some(level)));
}

pub fn dis_dropping(link: &mut LinkTop, level: Level) {
    // Only purge if we have an adjacency (meaning we were DIS)
    let Some((adj, _)) = link.state.adj.get(&level) else {
        return;
    };

    // Create pseudonode LSP ID from the adjacency
    let pseudonode_lsp_id = IsisLspId::from_neighbor_id(adj.clone(), 0);

    // Send purge message to the main IS-IS instance
    link.tx
        .send(Message::LspPurge(level, pseudonode_lsp_id))
        .unwrap();

    // LAN_ID is cleared.
    *link.state.adj.get_mut(&level) = None;
}

pub fn mac_str(mac: &Option<MacAddr>) -> String {
    if let Some(mac) = mac {
        format!("{}", mac)
    } else {
        "".to_string()
    }
}

pub fn csnp_timer(link: &LinkTop, level: Level) -> Timer {
    let tx = link.tx.clone();
    let ifindex = link.ifindex;
    Timer::immediate_repeat(link.config.csnp_interval(), move || {
        let tx = tx.clone();
        async move {
            use IfsmEvent::*;
            let msg = Message::Ifsm(CsnpTimerExpire, ifindex, Some(level));
            tx.send(msg);
        }
    })
}

// DIS Selection
pub fn dis_selection(link: &mut LinkTop, level: Level) {
    // 8.4.5 LAN designated intermediate systems
    //
    // A LAN Designated Intermediate System is the highest priority Intermediate
    // system in a particular set on the LAN, with numerically highest MAC
    // source SNPAAddress breaking ties. (See 7.1.8 for how to compare LAN
    // addresses.)
    fn is_better(nbr: &Neighbor, curr_priority: u8, curr_mac: &Option<MacAddr>) -> bool {
        nbr.priority > curr_priority
            || (nbr.priority == curr_priority
                && match (&nbr.mac, curr_mac) {
                    (Some(n_mac), Some(c_mac)) => n_mac > c_mac,
                    _ => false,
                })
    }

    // Logging.
    tracing::info!("DIS selection start");

    // Store current DIS state for tracking
    let old_status = *link.state.dis_status.get(&level);
    // let old_sys_id = *link.state.dis_sys_id.get(&level);

    // Reset current status.
    let mut best_sys_id: Option<IsisSysId> = None;
    let mut best_priority = link.config.priority();
    let mut best_mac = link.state.mac.clone();

    // We will check at least one Up state neighbor exists.
    let mut nbrs_up = 0;

    // Track Up neighbor count and candidate DIS.
    for (sys_id, nbr) in link.state.nbrs.get_mut(&level).iter_mut() {
        // Clear neighbor DIS flag, this will be updated following DIS
        // selection process.
        nbr.is_dis = false;

        // Skip neighbor which state is not Up.
        if nbr.state != NfsmState::Up {
            continue;
        }

        if is_better(nbr, best_priority, &best_mac) {
            best_priority = nbr.priority;
            best_mac = nbr.mac.clone();
            best_sys_id = Some(sys_id.clone());
        }
        nbrs_up += 1;
    }

    // Update link's neighbors Up count.
    *link.state.nbrs_up.get_mut(&level) = nbrs_up;

    // DIS selection and get new status and new sys_id.
    let (new_status, new_sys_id, lan_id, reason) = if nbrs_up == 0 {
        (
            DisStatus::NotSelected,
            None,
            None,
            "No up neighbors".to_string(),
        )
    } else if let Some(ref sys_id) = best_sys_id {
        // DIS is other IS.
        let Some(nbr) = link.state.nbrs.get_mut(&level).get_mut(sys_id) else {
            return;
        };
        nbr.is_dis = true;
        let reason = format!(
            "Neighbor {} elected (priority: {}, mac: {})",
            nbr.sys_id,
            nbr.priority,
            mac_str(&nbr.mac),
        );
        let lan_id = if !nbr.lan_id.is_empty() {
            Some(nbr.lan_id.clone())
        } else {
            None
        };

        (DisStatus::Other, Some(nbr.sys_id), lan_id, reason)
    } else {
        // DIS is myself.
        let sys_id = Some(link.up_config.net.sys_id());
        let reason = format!(
            "Self elected (priority: {}, neighbors: {})",
            link.config.priority(),
            nbrs_up
        );
        (DisStatus::Myself, sys_id, None, reason)
    };

    tracing::info!("DIS selection {:?} {}", new_status, reason);

    // Perform DIS change when status or sys_id has been changed.
    if old_status != new_status {
        match old_status {
            DisStatus::NotSelected => {
                // Nothing to do.
            }
            DisStatus::Myself => {
                // Remove pseudo node LSP and clear LAN_ID.
                dis_dropping(link, level);

                // Stop CSNP timer.
                *link.timer.csnp.get_mut(&level) = None;
            }
            DisStatus::Other => {
                // No need of stopping CSNP timer.
                // No need of removing pseudo node LSP.
                // Clear adj information.
                *link.state.adj.get_mut(&level) = None;
            }
        }
        match new_status {
            DisStatus::NotSelected => {
                // Nothing to do.
            }
            DisStatus::Myself => {
                dis_becoming(link, level);
            }
            DisStatus::Other => {
                use IfsmEvent::*;
                if link.state.adj.get(&level).is_none() {
                    if let Some(lan_id) = lan_id {
                        *link.state.adj.get_mut(&level) = Some((lan_id.clone(), None));
                        link.lsdb.get_mut(&level).adj_set(link.ifindex);
                        link.event(Message::Ifsm(HelloOriginate, link.ifindex, Some(level)));
                    }
                }
            }
        }

        // Update link's DIS status to the new one.
        *link.state.dis_status.get_mut(&level) = new_status;

        // If my role is DIS, we originate DIS.
        if new_status == DisStatus::Myself {
            link.event(Message::DisOriginate(level, link.ifindex, None));
        }

        // LSP Originate.
        link.event(Message::LspOriginate(level));

        // CSNP timer for when DIS is me.
        if new_status == DisStatus::Myself {
            if link.timer.csnp.get(&level).is_none() {
                *link.timer.csnp.get_mut(&level) = Some(csnp_timer(link, level));
            }
        }

        // Record changes.
        link.state
            .dis_stats
            .get_mut(&level)
            .record_change(old_status, new_status, new_sys_id, new_sys_id, reason);
    }
}
