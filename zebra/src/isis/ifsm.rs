use isis_packet::{IsisHello, IsisNeighborId, IsisSysId};

use crate::isis::Level;

use super::{link::LinkTop, task::Timer, IsisLink, Message, NfsmState};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IfsmEvent {
    Start,
    Stop,
    InterfaceUp,
    InterfaceDown,
    HelloTimerExpire,
    HelloUpdate,
    DisSelection,
    LspSend,
}

pub fn hello_gen(top: &LinkTop, level: Level) -> IsisHello {
    let mut hello = IsisHello {
        circuit_type: top.state.level,
        source_id: IsisSysId {
            id: [0, 0, 0, 0, 0, 2],
        },
        hold_time: top.config.hold_time(),
        pdu_len: 0,
        priority: top.config.priority(),
        lan_id: IsisNeighborId { id: [0u8; 7] },
        tlvs: Vec::new(),
    };
    hello
}

fn hello_timer(top: &LinkTop, level: Level) -> Timer {
    let tx = top.tx.clone();
    // let ifindex = link.ifindex;
    let ifindex = 3;
    Timer::repeat(top.config.hello_interval(), move || {
        let tx = tx.clone();
        async move {
            use IfsmEvent::*;
            let msg = Message::Ifsm(HelloTimerExpire, ifindex, Some(level));
            tx.send(msg).unwrap();
        }
    })
}

pub fn start(top: &mut LinkTop) {
    if top.state.level.has_l1() {
        // Generate Hello.
        // Start Hello timer.
    }
    if top.state.level.has_l2() {
        println!("Enable L2");
        let hello = hello_gen(top, Level::L2);
        let hello_timer = hello_timer(top, Level::L2);
    }
}

pub fn stop(link: &mut IsisLink) {
    //
}

pub fn dis_selection(link: &mut IsisLink) {
    let mut dis: Option<IsisSysId> = None;
    let mut priority = link.config.priority();
    for (_, nbr) in &link.l2nbrs {
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
