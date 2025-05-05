use anyhow::{Context, Result};
use isis_packet::{
    IsLevel, IsisHello, IsisNeighborId, IsisPacket, IsisPdu, IsisSysId, IsisTlvAreaAddr,
    IsisTlvIpv4IfAddr, IsisTlvProtoSupported, IsisType,
};

use crate::isis::Level;

use super::{link::LinkTop, task::Timer, IsisLink, Message, NfsmState};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IfsmEvent {
    Start,
    Stop,
    InterfaceUp,
    InterfaceDown,
    HelloTimerExpire,
    HelloOriginate,
    DisSelection,
    LspSend,
}

pub fn hello_gen(top: &LinkTop, level: Level) -> IsisHello {
    let source_id = top.up_config.net.sys_id();
    let mut hello = IsisHello {
        circuit_type: top.state.level,
        source_id,
        hold_time: top.config.hold_time(),
        pdu_len: 0,
        priority: top.config.priority(),
        lan_id: IsisNeighborId { id: [0u8; 7] },
        tlvs: Vec::new(),
    };
    let tlv = IsisTlvProtoSupported { nlpids: vec![0xcc] };
    hello.tlvs.push(tlv.into());
    let area_addr = vec![0x49, 0, 1];
    let tlv = IsisTlvAreaAddr { area_addr };
    hello.tlvs.push(tlv.into());
    for addr in &top.state.addr {
        hello.tlvs.push(
            IsisTlvIpv4IfAddr {
                addr: addr.prefix.addr(),
            }
            .into(),
        );
    }

    // for (_, nbr) in &self.l2nbrs {
    //     if nbr.state == NfsmState::Init || nbr.state == NfsmState::Up {
    //         if let Some(mac) = nbr.mac {
    //             hello.tlvs.push(
    //                 IsisTlvIsNeighbor {
    //                     octets: mac.octets(),
    //                 }
    //                 .into(),
    //             );
    //         }
    //     }
    // }
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
            tx.send(msg).unwrap();
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
    top.ptx.send(Message::Send(packet, ifindex)).unwrap();
    Ok(())
}

fn has_level(is_level: IsLevel, level: Level) -> bool {
    match level {
        Level::L1 => is_level.has_l1(),
        Level::L2 => is_level.has_l2(),
    }
}

pub fn start(top: &mut LinkTop) {
    for level in [Level::L1, Level::L2] {
        if has_level(top.state.level, level) {
            println!("XX start {}", level);
            let hello = hello_gen(top, level);
            *top.state.hello.get_mut(&level) = Some(hello);
            hello_send(top, level);
            *top.timer.hello.get_mut(&level) = Some(hello_timer(top, level));
        }
    }
}

pub fn stop(link: &mut IsisLink) {
    //
}

pub fn dis_selection(link: &mut IsisLink) {
    let mut dis: Option<IsisSysId> = None;
    let mut priority = link.config.priority();
    for (_, nbr) in &link.state.nbrs.l2 {
        if nbr.state != NfsmState::Up {
            continue;
        }

        if priority < nbr.pdu.priority {
            dis = Some(nbr.pdu.source_id.clone());
            priority = nbr.pdu.priority;
        } else if priority > nbr.pdu.priority {
            //
        } else {
            // Compare MAC Address.
        }
    }

    if let Some(dis) = dis {
        println!("DIS is selected {}", dis);
        link.l2dis = Some(dis);
    }
}
