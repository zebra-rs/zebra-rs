//! Kernel multicast-forwarding plane: the mroute socket
//! (`MRT_INIT`/`MRT_PIM`), VIF allocation and MFC programming, and
//! upcall parsing. All `MRT_*` interaction is confined here — the
//! protocol engine only sees typed [`Upcall`] messages and the
//! [`ForwardingPlane`] methods, mirroring the ZebOS pimd/mribd
//! boundary inside one process.
//!
//! Linux delivers upcalls on the mroute socket disguised as IP
//! packets whose protocol field is zero (`struct igmpmsg` overlays
//! the IP header). Real IGMP packets also arrive here once
//! interfaces are VIFs; those are ignored — the dedicated IGMP
//! socket (`super::socket::igmp_socket`) is the IGMP RX path.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use libc::c_int;
use socket2::{Domain, Protocol, Socket};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

use crate::context::ProtoContext;

// linux/mroute.h — not exposed by the libc crate.
const MRT_INIT: c_int = 200;
const MRT_ADD_VIF: c_int = 202;
const MRT_DEL_VIF: c_int = 203;
const MRT_ADD_MFC: c_int = 204;
const MRT_DEL_MFC: c_int = 205;
const MRT_PIM: c_int = 208;
const MRT_TABLE: c_int = 209;

const VIFF_USE_IFINDEX: u8 = 0x8;
const VIFF_REGISTER: u8 = 0x4;

pub const MAXVIFS: usize = 32;

/// The register VIF: slot 0, created at init. The kernel materializes
/// it as the `pimreg` device; putting it in an (S,G) OIL makes the
/// kernel punt full packets (WHOLEPKT) for Register encapsulation at
/// the DR.
pub const REG_VIF: u16 = 0;

const IGMPMSG_NOCACHE: u8 = 1;
const IGMPMSG_WRONGVIF: u8 = 2;
const IGMPMSG_WHOLEPKT: u8 = 3;
const IGMPMSG_WRVIFWHOLE: u8 = 4;

#[repr(C)]
struct Vifctl {
    vifc_vifi: u16,
    vifc_flags: u8,
    vifc_threshold: u8,
    vifc_rate_limit: u32,
    /// Union of `vifc_lcl_addr` / `vifc_lcl_ifindex`; with
    /// `VIFF_USE_IFINDEX` this carries the ifindex.
    vifc_lcl: u32,
    vifc_rmt_addr: u32,
}

#[repr(C)]
struct Mfcctl {
    mfcc_origin: u32,
    mfcc_mcastgrp: u32,
    mfcc_parent: u16,
    mfcc_ttls: [u8; MAXVIFS],
    mfcc_pkt_cnt: u32,
    mfcc_byte_cnt: u32,
    mfcc_wrong_if: u32,
    mfcc_expire: c_int,
}

/// A kernel upcall, parsed from the igmpmsg overlay.
#[derive(Debug, Clone, Copy)]
pub enum UpcallKind {
    /// First packet of an unknown (S,G) — create forwarding state.
    Nocache,
    /// Data arrived on a non-IIF interface — assert trigger (later
    /// phase).
    WrongVif,
    /// Full packet punt for Register encapsulation (ASM phase).
    WholePkt,
    /// Wrong-VIF with full packet — SPT switchover driver (ASM
    /// phase).
    WrVifWhole,
}

#[derive(Debug, Clone)]
pub struct Upcall {
    pub kind: UpcallKind,
    pub vif: u16,
    pub src: Ipv4Addr,
    pub grp: Ipv4Addr,
    /// The punted original IP packet — populated for WHOLEPKT (the
    /// Register encapsulation payload), empty otherwise.
    pub payload: Vec<u8>,
}

/// Parse one datagram read from the mroute socket. `None` for
/// anything that is not an upcall (real IGMP traffic, runts).
pub fn parse_upcall(buf: &[u8]) -> Option<Upcall> {
    if buf.len() < 20 || buf[9] != 0 {
        // buf[9] is ip->protocol alias im_mbz: nonzero ⇒ a genuine
        // IGMP packet, handled on the IGMP socket.
        return None;
    }
    let kind = match buf[8] {
        IGMPMSG_NOCACHE => UpcallKind::Nocache,
        IGMPMSG_WRONGVIF => UpcallKind::WrongVif,
        IGMPMSG_WHOLEPKT => UpcallKind::WholePkt,
        IGMPMSG_WRVIFWHOLE => UpcallKind::WrVifWhole,
        other => {
            tracing::debug!("mroute: unknown upcall type {other}");
            return None;
        }
    };
    let payload = if matches!(kind, UpcallKind::WholePkt | UpcallKind::WrVifWhole) {
        buf[20..].to_vec()
    } else {
        Vec::new()
    };
    Some(Upcall {
        kind,
        vif: buf[10] as u16 | ((buf[11] as u16) << 8),
        src: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
        grp: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
        payload,
    })
}

fn mrt_setsockopt<T>(sock: &Socket, opt: c_int, val: &T) -> std::io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            opt,
            val as *const T as *const libc::c_void,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Owner of the mroute socket, the VIF table and the kernel MFC.
/// Dropping it closes the socket, which makes the kernel run the
/// implicit `MRT_DONE` cleanup (VIFs and MFC entries flushed).
pub struct ForwardingPlane {
    pub sock: Arc<AsyncFd<Socket>>,
    /// ifindex → VIF. Index 0 stays reserved for the register VIF
    /// (ASM phase).
    vifs: BTreeMap<u32, u16>,
}

impl ForwardingPlane {
    /// `table_id != 0` selects a non-default kernel multicast routing
    /// table (`MRT_TABLE`, must precede `MRT_INIT`) — the per-VRF
    /// instance path. Requires `CONFIG_IP_MROUTE_MULTIPLE_TABLES`.
    pub fn new(ctx: &ProtoContext, table_id: u32) -> std::io::Result<Self> {
        // The mroute socket must be a raw IGMP socket. MRT_INIT
        // claims the (per-table) multicast-routing instance — EADDRINUSE
        // means another daemon owns it.
        let sock = ctx.raw_socket(Domain::IPV4, Protocol::from(super::socket::IGMP_IP_PROTO))?;
        sock.set_nonblocking(true)?;
        // Upcalls burst with traffic; keep a deep receive buffer.
        let _ = sock.set_recv_buffer_size(1024 * 1024);
        if table_id != 0 {
            mrt_setsockopt(&sock, MRT_TABLE, &table_id)?;
        }
        let one: c_int = 1;
        mrt_setsockopt(&sock, MRT_INIT, &one)?;
        // PIM mode: enables register decapsulation and the
        // WRVIFWHOLE upcall used by the ASM phase.
        if let Err(e) = mrt_setsockopt(&sock, MRT_PIM, &one) {
            tracing::warn!("mroute: MRT_PIM failed ({e}); register handling degraded");
        }
        // The register VIF (slot 0) — kernel creates `pimreg`. Needed
        // in an (S,G) OIL for WHOLEPKT punts at the DR.
        let vc = Vifctl {
            vifc_vifi: REG_VIF,
            vifc_flags: VIFF_REGISTER,
            vifc_threshold: 1,
            vifc_rate_limit: 0,
            vifc_lcl: 0,
            vifc_rmt_addr: 0,
        };
        if let Err(e) = mrt_setsockopt(&sock, MRT_ADD_VIF, &vc) {
            tracing::warn!("mroute: register VIF add failed ({e}); registers degraded");
        }
        Ok(Self {
            sock: Arc::new(AsyncFd::new(sock)?),
            vifs: BTreeMap::new(),
        })
    }

    pub fn vif(&self, ifindex: u32) -> Option<u16> {
        self.vifs.get(&ifindex).copied()
    }

    pub fn ifindex_of(&self, vif: u16) -> Option<u32> {
        self.vifs
            .iter()
            .find(|(_, v)| **v == vif)
            .map(|(ifindex, _)| *ifindex)
    }

    pub fn vif_add(&mut self, ifindex: u32) {
        if self.vifs.contains_key(&ifindex) {
            return;
        }
        // VIF 0 is reserved for the future register VIF.
        let mut vif: u16 = 1;
        while self.vifs.values().any(|v| *v == vif) {
            vif += 1;
        }
        if vif as usize >= MAXVIFS {
            tracing::warn!("mroute: out of VIFs for ifindex {ifindex}");
            return;
        }
        let vc = Vifctl {
            vifc_vifi: vif,
            vifc_flags: VIFF_USE_IFINDEX,
            vifc_threshold: 1,
            vifc_rate_limit: 0,
            vifc_lcl: ifindex,
            vifc_rmt_addr: 0,
        };
        match mrt_setsockopt(self.sock.get_ref(), MRT_ADD_VIF, &vc) {
            Ok(()) => {
                self.vifs.insert(ifindex, vif);
                tracing::info!("mroute: VIF {vif} added for ifindex {ifindex}");
            }
            Err(e) => tracing::warn!("mroute: MRT_ADD_VIF ifindex {ifindex} failed: {e}"),
        }
    }

    pub fn vif_del(&mut self, ifindex: u32) {
        let Some(vif) = self.vifs.remove(&ifindex) else {
            return;
        };
        let vc = Vifctl {
            vifc_vifi: vif,
            vifc_flags: VIFF_USE_IFINDEX,
            vifc_threshold: 1,
            vifc_rate_limit: 0,
            vifc_lcl: ifindex,
            vifc_rmt_addr: 0,
        };
        if let Err(e) = mrt_setsockopt(self.sock.get_ref(), MRT_DEL_VIF, &vc) {
            tracing::debug!("mroute: MRT_DEL_VIF ifindex {ifindex} failed: {e}");
        } else {
            tracing::info!("mroute: VIF {vif} deleted for ifindex {ifindex}");
        }
    }

    /// Install or replace the (S,G) MFC entry. `MRT_ADD_MFC` on an
    /// existing (origin, group) updates it in place.
    pub fn mfc_add(&self, src: Ipv4Addr, grp: Ipv4Addr, iif: u16, oifs: &[u16]) {
        let mut mc = Mfcctl {
            mfcc_origin: u32::from_ne_bytes(src.octets()),
            mfcc_mcastgrp: u32::from_ne_bytes(grp.octets()),
            mfcc_parent: iif,
            mfcc_ttls: [0; MAXVIFS],
            mfcc_pkt_cnt: 0,
            mfcc_byte_cnt: 0,
            mfcc_wrong_if: 0,
            mfcc_expire: 0,
        };
        for oif in oifs {
            if (*oif as usize) < MAXVIFS && *oif != iif {
                mc.mfcc_ttls[*oif as usize] = 1;
            }
        }
        if let Err(e) = mrt_setsockopt(self.sock.get_ref(), MRT_ADD_MFC, &mc) {
            tracing::warn!("mroute: MRT_ADD_MFC ({src},{grp}) failed: {e}");
        } else {
            tracing::debug!("mroute: MFC ({src},{grp}) iif {iif} oifs {oifs:?}");
        }
    }

    pub fn mfc_del(&self, src: Ipv4Addr, grp: Ipv4Addr) {
        let mc = Mfcctl {
            mfcc_origin: u32::from_ne_bytes(src.octets()),
            mfcc_mcastgrp: u32::from_ne_bytes(grp.octets()),
            mfcc_parent: 0,
            mfcc_ttls: [0; MAXVIFS],
            mfcc_pkt_cnt: 0,
            mfcc_byte_cnt: 0,
            mfcc_wrong_if: 0,
            mfcc_expire: 0,
        };
        if let Err(e) = mrt_setsockopt(self.sock.get_ref(), MRT_DEL_MFC, &mc) {
            tracing::debug!("mroute: MRT_DEL_MFC ({src},{grp}) failed: {e}");
        } else {
            tracing::debug!("mroute: MFC ({src},{grp}) deleted");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Layout of the hand-declared `linux/mroute.h` structs. If the
    // kernel ABI or our declaration drifts, `MRT_ADD_VIF`/`MRT_ADD_MFC`
    // would silently corrupt kernel state — assert the wire layout
    // instead. `vifi_t` is u16 and `MAXVIFS` is 32 on Linux.
    #[test]
    fn vifctl_layout() {
        assert_eq!(std::mem::size_of::<Vifctl>(), 16);
        assert_eq!(std::mem::offset_of!(Vifctl, vifc_vifi), 0);
        assert_eq!(std::mem::offset_of!(Vifctl, vifc_flags), 2);
        assert_eq!(std::mem::offset_of!(Vifctl, vifc_threshold), 3);
        assert_eq!(std::mem::offset_of!(Vifctl, vifc_rate_limit), 4);
        assert_eq!(std::mem::offset_of!(Vifctl, vifc_lcl), 8);
        assert_eq!(std::mem::offset_of!(Vifctl, vifc_rmt_addr), 12);
    }

    #[test]
    fn mfcctl_layout() {
        assert_eq!(std::mem::size_of::<Mfcctl>(), 60);
        assert_eq!(std::mem::offset_of!(Mfcctl, mfcc_origin), 0);
        assert_eq!(std::mem::offset_of!(Mfcctl, mfcc_mcastgrp), 4);
        assert_eq!(std::mem::offset_of!(Mfcctl, mfcc_parent), 8);
        assert_eq!(std::mem::offset_of!(Mfcctl, mfcc_ttls), 10);
        // The counters follow the 32-byte TTL array with u32 padding.
        assert_eq!(std::mem::offset_of!(Mfcctl, mfcc_pkt_cnt), 44);
        assert_eq!(std::mem::offset_of!(Mfcctl, mfcc_expire), 56);
        assert_eq!(MAXVIFS, 32);
    }

    fn upcall_buf(kind: u8, mbz: u8, vif: u16, src: [u8; 4], grp: [u8; 4]) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[8] = kind;
        b[9] = mbz; // im_mbz alias of ip->protocol
        b[10] = vif as u8;
        b[11] = (vif >> 8) as u8;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&grp);
        b
    }

    #[test]
    fn parse_upcall_accepts_igmpmsg() {
        let b = upcall_buf(IGMPMSG_NOCACHE, 0, 3, [10, 0, 0, 2], [232, 1, 1, 1]);
        let u = parse_upcall(&b).expect("nocache upcall");
        assert!(matches!(u.kind, UpcallKind::Nocache));
        assert_eq!(u.vif, 3);
        assert_eq!(u.src, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(u.grp, Ipv4Addr::new(232, 1, 1, 1));
    }

    #[test]
    fn parse_upcall_rejects_real_igmp() {
        // A genuine IGMP packet has a nonzero protocol byte at [9].
        let b = upcall_buf(0x16, 2, 0, [0; 4], [0; 4]);
        assert!(parse_upcall(&b).is_none());
    }

    #[test]
    fn parse_upcall_carries_wholepkt_payload() {
        let mut v = upcall_buf(IGMPMSG_WHOLEPKT, 0, 0, [10, 0, 0, 2], [239, 1, 1, 1]).to_vec();
        v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let u = parse_upcall(&v).expect("wholepkt upcall");
        assert!(matches!(u.kind, UpcallKind::WholePkt));
        assert_eq!(u.payload, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
