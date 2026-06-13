// Capability for sent and received.

use std::collections::HashMap;

use bgp_packet::*;
use serde::Serialize;

#[derive(Default, Debug, Serialize, Clone)]
pub struct SendRecv {
    pub send: bool,
    pub recv: bool,
}

impl SendRecv {
    pub fn desc(&self) -> &str {
        match (self.send, self.recv) {
            (true, true) => "advertised and received",
            (true, false) => "advertised",
            (false, true) => "received",
            (false, false) => "",
        }
    }
}
#[derive(Default, Debug, Serialize, Clone)]
pub struct CapAfiMap {
    pub entries: HashMap<CapMultiProtocol, SendRecv>,
}

impl CapAfiMap {
    pub fn new() -> Self {
        let mp4uni = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
        let mp4label = CapMultiProtocol::new(&Afi::Ip, &Safi::MplsLabel);
        let mp4vpn = CapMultiProtocol::new(&Afi::Ip, &Safi::MplsVpn);
        let mp4rtc = CapMultiProtocol::new(&Afi::Ip, &Safi::Rtc);
        let mp6uni = CapMultiProtocol::new(&Afi::Ip6, &Safi::Unicast);
        let mp6label = CapMultiProtocol::new(&Afi::Ip6, &Safi::MplsLabel);
        let mp6vpn = CapMultiProtocol::new(&Afi::Ip6, &Safi::MplsVpn);
        let mp6rtc = CapMultiProtocol::new(&Afi::Ip6, &Safi::Rtc);
        let mpevpn = CapMultiProtocol::new(&Afi::L2vpn, &Safi::Evpn);
        let mp4fs = CapMultiProtocol::new(&Afi::Ip, &Safi::Flowspec);
        let mp6fs = CapMultiProtocol::new(&Afi::Ip6, &Safi::Flowspec);
        let mp4srp = CapMultiProtocol::new(&Afi::Ip, &Safi::SrTePolicy);
        let mp6srp = CapMultiProtocol::new(&Afi::Ip6, &Safi::SrTePolicy);
        let mp_ls = CapMultiProtocol::new(&Afi::LinkState, &Safi::LinkState);

        let mut cmap = Self::default();
        cmap.entries.insert(mp4uni, SendRecv::default());
        cmap.entries.insert(mp4label, SendRecv::default());
        cmap.entries.insert(mp4vpn, SendRecv::default());
        cmap.entries.insert(mp4rtc, SendRecv::default());
        cmap.entries.insert(mp6uni, SendRecv::default());
        cmap.entries.insert(mp6label, SendRecv::default());
        cmap.entries.insert(mp6vpn, SendRecv::default());
        cmap.entries.insert(mp6rtc, SendRecv::default());
        cmap.entries.insert(mpevpn, SendRecv::default());
        cmap.entries.insert(mp4fs, SendRecv::default());
        cmap.entries.insert(mp6fs, SendRecv::default());
        cmap.entries.insert(mp4srp, SendRecv::default());
        cmap.entries.insert(mp6srp, SendRecv::default());
        cmap.entries.insert(mp_ls, SendRecv::default());
        cmap
    }

    pub fn get(&self, mp: &CapMultiProtocol) -> Option<&SendRecv> {
        self.entries.get(mp)
    }

    pub fn get_mut(&mut self, mp: &CapMultiProtocol) -> Option<&mut SendRecv> {
        self.entries.get_mut(mp)
    }
}

pub fn cap_register_send(bgp_cap: &BgpCap, cap_map: &mut CapAfiMap) {
    for (_, mp) in bgp_cap.mp.iter() {
        if let Some(entry) = cap_map.get_mut(mp) {
            entry.send = true;
        }
    }
}

pub fn cap_register_recv(bgp_cap: &BgpCap, cap_map: &mut CapAfiMap) {
    for (_, mp) in bgp_cap.mp.iter() {
        if let Some(entry) = cap_map.get_mut(mp) {
            entry.recv = true;
        }
    }
}

/// Families whose advertise plane actually implements the AddPath
/// *send* direction — per-candidate fan-out with allocated path-ids on
/// reach AND withdraw (`route_advertise_to_addpath` /
/// `route_withdraw_from_addpath`). RFC 7911 §3 makes negotiated Send a
/// hard wire contract: every NLRI of that family must then carry a
/// path identifier, so a family without the full per-path pipeline
/// must not negotiate Send at all. The other families today either
/// exclude AddPath peers from their only advertise path (IPv6 unicast)
/// or half-stamp ids (reach with `local_id`, withdraw with 0 — which
/// encodes as *no* path-id field: a malformed MP_UNREACH on an
/// AddPath session) — VPNv6, EVPN, labeled-unicast. Receive is
/// unaffected: parsing path-ids is family-generic (`ParseOption`).
pub fn addpath_send_implemented(afi: Afi, safi: Safi) -> bool {
    matches!(
        (afi, safi),
        (Afi::Ip, Safi::Unicast)
            | (Afi::Ip, Safi::MplsVpn)
            | (Afi::Ip6, Safi::MplsVpn)
            | (Afi::L2vpn, Safi::Evpn)
            | (Afi::Ip, Safi::MplsLabel)
            | (Afi::Ip6, Safi::MplsLabel)
    )
}

pub fn cap_addpath_recv(bgp_cap: &BgpCap, opt: &mut ParseOption, configs: &AfiSafis<AddPathValue>) {
    for (_, cap) in bgp_cap.addpath.iter() {
        for (_, config) in configs.iter() {
            if cap.afi == config.afi && cap.safi == config.safi {
                // Send is additionally gated on the family having a
                // real per-path advertise pipeline. The OPEN we sent
                // already withheld Send for these families (see the
                // capability build in `peer.rs`), so this also keeps
                // the negotiated state honest against a remote that
                // offers Receive regardless.
                let implemented = addpath_send_implemented(cap.afi, cap.safi);
                let send =
                    cap.send_receive.is_receive() && config.send_receive.is_send() && implemented;
                if cap.send_receive.is_receive() && config.send_receive.is_send() && !implemented {
                    tracing::warn!(
                        afi = %cap.afi,
                        safi = %cap.safi,
                        "add-path send is configured but not implemented for this family; \
                         negotiating receive-only"
                    );
                }
                let recv = cap.send_receive.is_send() && config.send_receive.is_receive();
                let afi_safi = AfiSafi::new(cap.afi, cap.safi);
                opt.add_path.insert(afi_safi, Direct { recv, send });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::AddPathSendReceive;

    fn addpath_cap(afi: Afi, safi: Safi, dir: AddPathSendReceive) -> AddPathValue {
        AddPathValue {
            afi,
            safi,
            send_receive: dir,
        }
    }

    /// Negotiated AddPath *send* is gated on the family having the
    /// per-path advertise pipeline. A VPNv6 (or any unimplemented
    /// family) `add-path send` config against a peer offering Receive
    /// must come out send=false — RFC 7911 §3 would otherwise oblige
    /// us to path-id every NLRI of a family whose withdraw path can't.
    #[test]
    fn addpath_send_negotiates_only_for_implemented_families() {
        let mut bgp_cap = BgpCap::default();
        let mut configs: AfiSafis<AddPathValue> = AfiSafis::new();
        for (afi, safi) in [
            (Afi::Ip, Safi::Unicast),
            (Afi::Ip, Safi::MplsVpn),
            (Afi::Ip6, Safi::Unicast),
            (Afi::Ip6, Safi::MplsVpn),
        ] {
            let key = AfiSafi::new(afi, safi);
            // Peer offers both directions; we configure send-receive.
            bgp_cap
                .addpath
                .insert(key, addpath_cap(afi, safi, AddPathSendReceive::SendReceive));
            configs.insert(key, addpath_cap(afi, safi, AddPathSendReceive::SendReceive));
        }

        let mut opt = ParseOption::default();
        cap_addpath_recv(&bgp_cap, &mut opt, &configs);

        // Implemented families negotiate send.
        assert!(opt.is_add_path_send(Afi::Ip, Safi::Unicast));
        assert!(opt.is_add_path_send(Afi::Ip, Safi::MplsVpn));
        assert!(opt.is_add_path_send(Afi::Ip6, Safi::MplsVpn));
        // Unimplemented families are masked to receive-only.
        assert!(!opt.is_add_path_send(Afi::Ip6, Safi::Unicast));
        // Receive negotiates for every family (parsing is generic).
        for (afi, safi) in [
            (Afi::Ip, Safi::Unicast),
            (Afi::Ip, Safi::MplsVpn),
            (Afi::Ip6, Safi::Unicast),
            (Afi::Ip6, Safi::MplsVpn),
        ] {
            let key = AfiSafi::new(afi, safi);
            assert!(
                opt.add_path.get(&key).is_some_and(|d| d.recv),
                "receive must negotiate for {afi} {safi}"
            );
        }
    }

    /// The supported-set itself, pinned. Growing it is deliberate —
    /// each family must be added WITH its per-candidate
    /// advertise/withdraw twins (VPNv6, EVPN, and labeled-unicast v4/v6
    /// each landed alongside theirs). IPv6 unicast is the remaining
    /// unicast family (separate group-cache shape); RTC is the one
    /// family that stays excluded by design (its NLRI carry no per-path
    /// semantics).
    #[test]
    fn addpath_send_implemented_set() {
        for (afi, safi) in [
            (Afi::Ip, Safi::Unicast),
            (Afi::Ip, Safi::MplsVpn),
            (Afi::Ip6, Safi::MplsVpn),
            (Afi::L2vpn, Safi::Evpn),
            (Afi::Ip, Safi::MplsLabel),
            (Afi::Ip6, Safi::MplsLabel),
        ] {
            assert!(
                addpath_send_implemented(afi, safi),
                "{afi} {safi} has a per-path advertise pipeline"
            );
        }
        for (afi, safi) in [
            (Afi::Ip6, Safi::Unicast),
            (Afi::Ip, Safi::Flowspec),
            (Afi::Ip6, Safi::Flowspec),
            (Afi::Ip, Safi::Rtc),
            (Afi::Ip6, Safi::Rtc),
        ] {
            assert!(
                !addpath_send_implemented(afi, safi),
                "{afi} {safi} has no per-path advertise pipeline yet"
            );
        }
    }
}
