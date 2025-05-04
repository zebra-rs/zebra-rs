use isis_packet::IsisSysId;

use super::{IsisLink, NfsmState};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IfsmEvent {
    InterfaceUp,
    InterfaceDown,
    HelloUpdate,
    DisSelection,
    LspSend,
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
