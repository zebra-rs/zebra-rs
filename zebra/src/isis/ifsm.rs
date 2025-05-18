use anyhow::{Context, Result};
use isis_packet::{
    IsLevel, IsisHello, IsisNeighborId, IsisPacket, IsisPdu, IsisProto, IsisSysId, IsisTlvAreaAddr,
    IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvProtoSupported, IsisType,
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

pub fn hello_generate(top: &LinkTop, level: Level) -> IsisHello {
    let source_id = top.up_config.net.sys_id();
    let lan_id = top
        .state
        .lan_id
        .get(&level)
        .clone()
        .unwrap_or(IsisNeighborId::default());
    let mut hello = IsisHello {
        circuit_type: top.state.level(),
        source_id,
        hold_time: top.config.hold_time(),
        pdu_len: 0,
        priority: top.config.priority(),
        lan_id,
        tlvs: Vec::new(),
    };
    let tlv = proto_supported(&top.up_config.enable);
    hello.tlvs.push(tlv.into());

    let area_addr = vec![0x49, 0, 1];
    let tlv = IsisTlvAreaAddr { area_addr };
    hello.tlvs.push(tlv.into());
    for prefix in &top.state.v4addr {
        hello.tlvs.push(
            IsisTlvIpv4IfAddr {
                addr: prefix.addr(),
            }
            .into(),
        );
    }

    for (_, nbr) in top.state.nbrs.get(&level).iter() {
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
    if top.config.hello_padding() == HelloPaddingPolicy::Always {
        hello.padding(top.state.mtu as usize);
    }
    hello
}

fn hello_timer(top: &LinkTop, level: Level) -> Timer {
    let tx = top.tx.clone();
    let ifindex = top.state.ifindex;
    Timer::repeat(top.config.hello_interval(), move || {
        let tx = tx.clone();
        async move {
            use IfsmEvent::*;
            let msg = Message::Ifsm(HelloTimerExpire, ifindex, Some(level));
            tx.send(msg);
        }
    })
}

pub fn hello_send(top: &mut LinkTop, level: Level) -> Result<()> {
    let hello = top.state.hello.get(&level).as_ref().context("")?;
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Hello, IsisPdu::L1Hello(hello.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Hello, IsisPdu::L2Hello(hello.clone())),
    };
    let ifindex = top.state.ifindex;
    top.ptx
        .send(PacketMessage::Send(Packet::Packet(packet), ifindex, level));
    Ok(())
}

fn has_level(is_level: IsLevel, level: Level) -> bool {
    match level {
        Level::L1 => is_level.has_l1(),
        Level::L2 => is_level.has_l2(),
    }
}

pub fn hello_originate(top: &mut LinkTop, level: Level) {
    if has_level(top.state.level(), level) {
        println!("IFSM Hello originate {}", level);
        let hello = hello_generate(top, level);
        *top.state.hello.get_mut(&level) = Some(hello);
        hello_send(top, level);
        *top.timer.hello.get_mut(&level) = Some(hello_timer(top, level));
    }
}

pub fn start(top: &mut LinkTop) {
    for level in [Level::L1, Level::L2] {
        hello_originate(top, level);
    }
}

pub fn stop(top: &mut LinkTop) {
    for level in [Level::L1, Level::L2] {
        *top.state.hello.get_mut(&level) = None;
        *top.timer.hello.get_mut(&level) = None;
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

    // When curr is None, current candidate DIS is myself.
    let mut best_key: Option<IsisSysId> = None;
    let mut best_priority = ltop.config.priority();
    let mut best_mac = ltop.state.mac.clone();

    // We will check at least Up state neighbor exists.
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

    if nbrs_up == 0 {
        println!("DIS no up neighbors");
        *ltop.state.dis_status.get_mut(&level) = DisStatus::NotSelected;
        return;
    }

    if let Some(ref key) = best_key {
        if let Some(nbr) = ltop.state.nbrs.get_mut(&level).get_mut(key) {
            nbr.dis = true;
            println!("DIS is selected {}", nbr.sys_id);
            *ltop.state.dis_status.get_mut(&level) = DisStatus::Other;
            *ltop.state.dis.get_mut(&level) = Some(nbr.sys_id.clone());
            if ltop.state.lan_id.get(&level).is_none() {
                if !nbr.pdu.lan_id.is_empty() {
                    println!("DIS lan_id is in Hello packet");
                    *ltop.state.lan_id.get_mut(&level) = Some(nbr.pdu.lan_id.clone());
                    //
                } else {
                    println!("DIS waiting lan_id");
                }
            }
        }
    } else {
        println!("DIS is selected: self");
        *ltop.state.dis_status.get_mut(&level) = DisStatus::Myself;
    }
}
