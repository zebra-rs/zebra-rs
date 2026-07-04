//! PFCP session table for the MUP controller.
//!
//! Each PFCP session learned over N4 is normalized into a [`MupSession`]
//! — the neutral record the BGP task needs to (in a follow-up) originate
//! Type-1 / Type-2 Session-Transformed routes. The controller is the
//! authoritative holder; a clone rides each
//! [`super::inst::MupCEvent::SessionUp`] into the BGP task.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A mobile session learned from PFCP, normalized for BGP MUP.
#[derive(Debug, Clone)]
pub struct MupSession {
    /// Local SEID we allocated for this session. Returned to the CP in
    /// our F-SEID; the CP then addresses Session Modification / Deletion
    /// with this value as the message SEID, so it is the table key.
    pub seid: u64,
    /// The CP's (SMF's) F-SEID, learned from the Session Establishment
    /// Request's F-SEID IE. Per 3GPP TS 29.244 the SEID in a PFCP message
    /// header is the *receiver's* F-SEID, so every response we send about
    /// this session (Establishment / Modification / Deletion) must carry
    /// this value as the header SEID — not our own [`seid`](Self::seid),
    /// which only goes in the response's F-SEID IE.
    pub cp_seid: u64,
    /// The PFCP peer (SMF) transport address that owns this session.
    pub peer: SocketAddr,
    /// UE IPv4 address/prefix, if assigned.
    pub ue_ipv4: Option<Ipv4Addr>,
    /// UE IPv6 address/prefix, if assigned.
    pub ue_ipv6: Option<Ipv6Addr>,
    /// gNB (access-side) GTP-U TEID, from the downlink FAR's Outer Header
    /// Creation (Destination Interface = Access) — the tunnel the UPF
    /// encapsulates downlink traffic toward, *not* the UPF's own N3 F-TEID.
    /// Used for the **Type-1 ST** route (access side, draft §3.3.7). `0` until
    /// the gNB tunnel is programmed (typically a post-N2 Session Modification).
    pub teid: u32,
    /// gNB (access-side) GTP-U endpoint — the gNB address from the downlink
    /// FAR's Outer Header Creation. Used for the **Type-1 ST** route. `None`
    /// until the gNB tunnel is programmed (post-N2 Session Modification).
    pub endpoint: Option<IpAddr>,
    /// Core-side GTP-U TEID, from a FAR's Outer Header Creation bound for the
    /// Core interface — a core-facing GTP tunnel (e.g. N9 to an anchor UPF).
    /// Used for the **Type-2 ST** route (core side, draft §3.3.10). `0` for a
    /// plain N6 breakout, which has no core-side GTP tunnel.
    pub core_teid: u32,
    /// Core-side GTP-U endpoint — the core address from a Core-bound FAR's
    /// Outer Header Creation. Used for the **Type-2 ST** route. `None` falls
    /// back to the access endpoint so a single-tunnel session still
    /// originates an ST2.
    pub core_endpoint: Option<IpAddr>,
    /// Network Instance (APN/DNN). Correlated to a BGP VRF `mup`
    /// config when routes are originated.
    pub network_instance: Option<String>,
    /// QoS Flow Identifier, if present.
    pub qfi: Option<u8>,
}

/// Session store keyed by local SEID, plus the local-SEID allocator.
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: BTreeMap<u64, MupSession>,
    next_seid: u64,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            next_seid: 1,
        }
    }

    /// Allocate a fresh non-zero local SEID (SEID 0 is invalid in PFCP).
    pub fn alloc_seid(&mut self) -> u64 {
        let seid = self.next_seid.max(1);
        self.next_seid = seid.wrapping_add(1).max(1);
        seid
    }

    pub fn insert(&mut self, session: MupSession) {
        self.sessions.insert(session.seid, session);
    }

    pub fn get(&self, seid: u64) -> Option<&MupSession> {
        self.sessions.get(&seid)
    }

    pub fn remove(&mut self, seid: u64) -> Option<MupSession> {
        self.sessions.remove(&seid)
    }

    /// Number of sessions held (used to bound state — see the
    /// per-listener cap in [`super::pfcp`]).
    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    /// Drop every session owned by `peer` (PFCP association release).
    /// Returns the removed SEIDs so the caller can emit withdrawals.
    pub fn remove_peer(&mut self, peer: SocketAddr) -> Vec<u64> {
        let victims: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.peer == peer)
            .map(|(seid, _)| *seid)
            .collect();
        for seid in &victims {
            self.sessions.remove(seid);
        }
        victims
    }
}
