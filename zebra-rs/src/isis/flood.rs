use std::collections::BTreeMap;

use bytes::BytesMut;
use isis_packet::*;

use crate::context::Timer;

use super::{Level, LinkTop, Lsdb, Message, MsgSender, Packet, PacketMessage, psnp_send_pdu};

#[derive(Default)]
pub struct LspFloodMap(pub BTreeMap<IsisLspId, IsisLspEntry>);

impl LspFloodMap {
    pub fn set(&mut self, lsp: &IsisLspEntry) {
        self.0.insert(lsp.lsp_id, lsp.clone());
    }

    pub fn clear(&mut self, lsp_id: &IsisLspId) {
        self.0.remove(lsp_id);
    }
}

#[derive(Default)]
pub struct LspFlood {
    pub srm: LspFloodMap,
    pub srm_timer: Option<Timer>,
    pub ssn: LspFloodMap,
    pub ssn_timer: Option<Timer>,
}

impl Lsdb {
    pub fn adj_set(&mut self, ifindex: u32) {
        self.adj.entry(ifindex).or_default();
    }

    pub fn adj_clear(&mut self, ifindex: u32) {
        self.adj.remove(&ifindex);
    }

    pub fn srm_set(&mut self, tx: &MsgSender, level: Level, lsp_id: &IsisLspId, ifindex: u32) {
        if let Some(flags) = self.adj.get_mut(&ifindex) {
            flags.srm.set(&IsisLspEntry {
                lsp_id: *lsp_id,
                ..Default::default()
            });
            if flags.srm_timer.is_none() {
                flags.srm_timer = Some(srm_timer(tx, level, ifindex));
            }
        }
    }

    pub fn srm_set_all(&mut self, tx: &MsgSender, level: Level, lsp_id: &IsisLspId) {
        for (link, flags) in self.adj.iter_mut() {
            flags.srm.set(&IsisLspEntry {
                lsp_id: *lsp_id,
                ..Default::default()
            });
            if flags.srm_timer.is_none() {
                flags.srm_timer = Some(srm_timer(tx, level, *link));
            }
        }
    }

    pub fn srm_set_other(
        &mut self,
        tx: &MsgSender,
        level: Level,
        lsp_id: &IsisLspId,
        ifindex: u32,
    ) {
        for (link, flags) in self.adj.iter_mut() {
            if *link != ifindex {
                flags.srm.set(&IsisLspEntry {
                    lsp_id: *lsp_id,
                    ..Default::default()
                });
                if flags.srm_timer.is_none() {
                    flags.srm_timer = Some(srm_timer(tx, level, *link));
                }
            }
        }
    }

    pub fn srm_clear(&mut self, lsp_id: &IsisLspId, ifindex: u32) {
        if let Some(flags) = self.adj.get_mut(&ifindex) {
            flags.srm.clear(lsp_id);
        }
    }

    pub fn ssn_set(&mut self, tx: &MsgSender, level: Level, lsp: &IsisLspEntry, ifindex: u32) {
        if let Some(flags) = self.adj.get_mut(&ifindex) {
            flags.ssn.set(lsp);
            if flags.ssn_timer.is_none() {
                flags.ssn_timer = Some(ssn_timer(tx, level, ifindex));
            }
        }
    }

    pub fn ssn_clear(&mut self, lsp_id: &IsisLspId, ifindex: u32) {
        if let Some(flags) = self.adj.get_mut(&ifindex) {
            flags.ssn.clear(&lsp_id);
        }
    }

    pub fn ssn_clear_other(&mut self, lsp_id: &IsisLspId, ifindex: u32) {
        for (link, flags) in self.adj.iter_mut() {
            if *link != ifindex {
                flags.ssn.clear(&lsp_id);
            }
        }
    }
}

pub fn srm_set(top: &mut LinkTop, level: Level, lsp_id: &IsisLspId) {
    top.lsdb
        .get_mut(&level)
        .srm_set(top.tx, level, lsp_id, top.ifindex);
}

pub fn srm_set_other(top: &mut LinkTop, level: Level, lsp_id: &IsisLspId) {
    top.lsdb
        .get_mut(&level)
        .srm_set_other(top.tx, level, lsp_id, top.ifindex);
}

pub fn srm_clear(top: &mut LinkTop, level: Level, lsp_id: &IsisLspId) {
    top.lsdb.get_mut(&level).srm_clear(lsp_id, top.ifindex);
}

pub fn ssn_set(top: &mut LinkTop, level: Level, lsp: &IsisLspEntry) {
    top.lsdb
        .get_mut(&level)
        .ssn_set(top.tx, level, lsp, top.ifindex);
}

pub fn ssn_clear(top: &mut LinkTop, level: Level, lsp_id: &IsisLspId) {
    top.lsdb.get_mut(&level).ssn_clear(lsp_id, top.ifindex);
}

pub fn ssn_clear_other(top: &mut LinkTop, level: Level, lsp_id: &IsisLspId) {
    top.lsdb
        .get_mut(&level)
        .ssn_clear_other(&lsp_id, top.ifindex);
}

pub fn srm_advertise(top: &mut LinkTop, level: Level, ifindex: u32) {
    // Extract SRM entries first to avoid borrow checker issues.
    let srm_entries: Vec<IsisLspId> = {
        let Some(adj) = top.lsdb.get_mut(&level).adj.get_mut(&ifindex) else {
            return;
        };
        adj.srm_timer = None;

        if adj.srm.0.is_empty() {
            return;
        }

        adj.srm.0.keys().cloned().collect()
    };

    // Send LSPs for each SRM entry.
    for lsp_id in srm_entries {
        let lsdb = top.lsdb.get(&level);
        if let Some(lsa) = lsdb.get(&lsp_id) {
            let hold_time = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec()) as u16;

            if !lsa.bytes.is_empty() {
                let mut buf = BytesMut::from(&lsa.bytes[..]);
                isis_packet::write_hold_time(&mut buf, hold_time);

                top.ptx.send(PacketMessage::Send(
                    Packet::Bytes(buf),
                    ifindex,
                    level,
                    top.dest(level),
                ));
            }
        }

        // Clear SRM flag after sending.
        if let Some(adj) = top.lsdb.get_mut(&level).adj.get_mut(&ifindex) {
            adj.srm.0.remove(&lsp_id);
        }
    }
}

pub fn ssn_advertise(link: &mut LinkTop, level: Level) {
    let Some(adj) = link.lsdb.get_mut(&level).adj.get_mut(&link.ifindex) else {
        return;
    };
    adj.ssn_timer = None;

    if adj.ssn.0.is_empty() {
        return;
    }

    // Interface MTU.
    let mtu = link.state.mtu as usize;

    let available_len = {
        let mut buf = BytesMut::new();

        let mut psnp = IsisPsnp {
            source_id: IsisSysId::default(),
            source_id_circuit: 0,
            ..Default::default()
        };

        let packet = IsisPacket::from(IsisType::L1Psnp, IsisPdu::L1Psnp(psnp.clone()));
        packet.emit(&mut buf);
        if parse(&buf).is_err() {
            return;
        }

        let packet_len = buf.len();
        let base_len = 3;
        let tlv_header_len = 2;

        let total_base_len = packet_len + base_len + tlv_header_len;

        let available_len = mtu - total_base_len;

        available_len
    };

    // 16 is IsisLspEntry's length.
    let entry_size_max = available_len / 16;

    let mut psnps: Vec<IsisPsnp> = vec![];
    let mut tlvs = IsisTlvLspEntries::default();

    let mut entry_size = 0;

    while let Some((_, entry)) = adj.ssn.0.pop_first() {
        tlvs.entries.push(entry);

        entry_size += 1;
        if entry_size == entry_size_max {
            let mut psnp = IsisPsnp {
                pdu_len: 0,
                source_id: link.up_config.net.sys_id(),
                source_id_circuit: 0,
                tlvs: vec![tlvs.clone().into()],
            };
            psnps.push(psnp);

            tlvs.entries.clear();
            entry_size = 0;
        }
    }
    if !tlvs.entries.is_empty() {
        let mut psnp = IsisPsnp {
            pdu_len: 0,
            source_id: link.up_config.net.sys_id(),
            source_id_circuit: 0,
            tlvs: vec![tlvs.into()],
        };
        psnps.push(psnp);
    }

    for psnp in psnps.into_iter() {
        psnp_send_pdu(link, level, psnp);
    }
}

fn srm_timer(tx: &MsgSender, level: Level, ifindex: u32) -> Timer {
    let tx = tx.clone();
    Timer::once(0, move || {
        let tx = tx.clone();
        let msg = Message::Srm(level, ifindex);
        async move {
            tx.send(msg);
        }
    })
}

fn ssn_timer(tx: &MsgSender, level: Level, ifindex: u32) -> Timer {
    let tx = tx.clone();
    Timer::once(1, move || {
        let tx = tx.clone();
        let msg = Message::Ssn(level, ifindex);
        async move {
            tx.send(msg);
        }
    })
}
