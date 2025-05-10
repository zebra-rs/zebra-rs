use anyhow::{Context, Result};
use isis_packet::{
    IsLevel, IsisHello, IsisNeighborId, IsisPacket, IsisPdu, IsisProto, IsisSysId, IsisTlvAreaAddr,
    IsisTlvIpv4IfAddr, IsisTlvIsNeighbor, IsisTlvProtoSupported, IsisType,
};

use super::link::{Afis, HelloPaddingPolicy, LinkTop};
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
    let mut hello = IsisHello {
        circuit_type: top.state.level(),
        source_id,
        hold_time: top.config.hold_time(),
        pdu_len: 0,
        priority: top.config.priority(),
        lan_id: IsisNeighborId::default(),
        tlvs: Vec::new(),
    };
    let tlv = proto_supported(&top.up_config.enable);
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
    top.ptx.send(Message::Send(packet, ifindex));
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

pub fn dis_selection(top: &mut LinkTop, level: Level) {
    let mut dis: Option<IsisSysId> = None;
    let mut priority = top.config.priority();
    for (_, nbr) in top.state.nbrs.get(&level).iter() {
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
        *top.state.dis.get_mut(&level) = Some(dis);
    }
}
