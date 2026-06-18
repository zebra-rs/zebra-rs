use anyhow::{Context, Result};

use ipnet::IpNet;
use netlink_packet_route::link::LinkFlags;
use serde::Serialize;
use std::fmt::{self, Write};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::{Args, ConfigOp};
use crate::fib::message::{FibAddr, FibLink};
use crate::fib::os_traffic_dump;
use crate::fib::sysctl::{sysctl_keep_addr_on_down, sysctl_mpls_enable, sysctl_seg6_enable};

use super::entry::RibEntry;
use super::tracing::rib_interface;
use super::util::IpNetExt;
use super::{LinkFlagsExt, MacAddr, Message, Rib, RibType};

mod linkflags_serde {
    use super::*;
    pub fn serialize<S>(flags: &LinkFlags, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", flags))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    /// MTU the kernel reported when this link was first observed,
    /// before any operator-configured MTU was applied. Captured once in
    /// `Link::from` and never updated thereafter, so it survives our own
    /// `link_set_mtu` echoing back. Restored when the operator deletes
    /// `interface <name> mtu`. Internal bookkeeping — not part of any
    /// `show` output, so it stays out of the serialized form.
    #[serde(skip)]
    pub original_mtu: u32,
    pub metric: u32,
    #[serde(with = "linkflags_serde")]
    pub flags: LinkFlags,
    pub link_type: LinkType,
    pub label: bool,
    pub mac: Option<MacAddr>,
    pub addr4: Vec<LinkAddr>,
    pub addr6: Vec<LinkAddr>,
    /// `IFLA_MASTER` ifindex when this link is a slave of a bridge or
    /// VRF master. None for top-level links.
    pub master: Option<u32>,
    /// VNI from the kernel's `IFLA_VXLAN_ID` attribute on VXLAN links.
    /// Used by the EVPN advertise path: a bridge's VXLAN slave maps the
    /// bridge to the L2VPN VNI it carries.
    pub vni: Option<u32>,
    /// Local VTEP source IP from `IFLA_VXLAN_LOCAL` / `IFLA_VXLAN_LOCAL6`
    /// on VXLAN links. Used as the BGP MP_REACH nexthop for EVPN
    /// advertisements per RFC 8365 §5.1.3.
    pub vxlan_local: Option<std::net::IpAddr>,
    /// Last failure reason from applying the operator-configured MTU
    /// (`mtu_config` keyed by name on `Rib`). `None` once a set
    /// succeeds. Rendered by `show interface` so a kernel rejection
    /// (e.g. an MTU below the IPv6 minimum of 1280 on a v6-enabled
    /// link) is visible to the operator. Display-only — the live MTU
    /// is always whatever the kernel reports in `mtu`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu_error: Option<String>,
}

impl Link {
    pub fn from(link: FibLink) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            original_mtu: link.mtu,
            metric: 1,
            flags: link.flags,
            link_type: link.link_type,
            label: false,
            mac: link.mac,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: link.master,
            vni: link.vni,
            vxlan_local: link.vxlan_local,
            mtu_error: None,
        }
    }

    pub fn is_up(&self) -> bool {
        self.flags.is_up()
    }

    pub fn is_loopback(&self) -> bool {
        self.flags.is_loopback()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
pub struct LinkAddr {
    pub addr: IpNet,
    pub ifindex: u32,
    pub secondary: bool,
    pub config: bool,
    pub fib: bool,
}

impl LinkAddr {
    /// Build a LinkAddr from a FIB (kernel netlink) message.
    ///
    /// The kernel just told us about this address, so it is installed in the
    /// kernel FIB by definition (`fib = true`). Whether the address was
    /// configured in zebra-rs is not knowable here — callers that received
    /// the FibAddr from the configuration path flip `config = true` after.
    pub fn from(osaddr: FibAddr) -> Self {
        Self {
            addr: osaddr.addr,
            ifindex: osaddr.link_index,
            secondary: osaddr.secondary,
            config: false,
            fib: true,
        }
    }

    pub fn is_v4(&self) -> bool {
        match self.addr {
            IpNet::V4(_) => true,
            IpNet::V6(_) => false,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
pub enum LinkType {
    #[default]
    Unknown,
    Loopback,
    Ethernet,
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Loopback => write!(f, "Loopback"),
            Self::Ethernet => write!(f, "Ethernet"),
        }
    }
}

fn link_info_show(rib: &Rib, link: &Link, buf: &mut String, cb: &impl Fn(&String, &mut String)) {
    writeln!(buf, "Interface: {}", link.name).unwrap();
    write!(buf, "  Hardware is {}", link.link_type).unwrap();
    if link.link_type == LinkType::Ethernet {
        if let Some(mac) = link.mac {
            writeln!(buf, " {}", mac).unwrap();
        } else {
            writeln!(buf).unwrap();
        }
    } else {
        writeln!(buf).unwrap();
    }
    writeln!(
        buf,
        "  index {} metric {} mtu {}",
        link.index, link.metric, link.mtu
    )
    .unwrap();
    if let Some(err) = &link.mtu_error {
        writeln!(buf, "  {}", err).unwrap();
    }
    write!(
        buf,
        "  Link is {}",
        if link.is_up() { "Up\n" } else { "Down\n" }
    )
    .unwrap();
    writeln!(buf, "  {}", link.flags).unwrap();
    let vrf_label = link_vrf_name(rib, link)
        .map(|n| format!("vrf {}", n))
        .unwrap_or_else(|| "Not bound".to_string());
    writeln!(buf, "  VRF Binding: {}", vrf_label).unwrap();
    writeln!(
        buf,
        "  Label switching is {}",
        if link.label { "enabled" } else { "disabled" }
    )
    .unwrap();
    for addr in link.addr4.iter() {
        write!(buf, "  inet {}", addr.addr).unwrap();
        if addr.secondary {
            writeln!(buf, " secondary").unwrap();
        } else {
            writeln!(buf).unwrap();
        }
    }
    for addr in link.addr6.iter() {
        writeln!(buf, "  inet6 {}", addr.addr).unwrap();
    }
    cb(&link.name, buf);
}

#[derive(Serialize)]
pub struct InterfaceBrief {
    pub interface: String,
    pub status: String,
    pub vrf: String,
    pub addresses: Vec<String>,
}

#[derive(Serialize)]
pub struct InterfaceDetailed {
    pub interface: String,
    pub hardware: String,
    pub index: u32,
    pub metric: u32,
    pub mtu: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu_error: Option<String>,
    pub link_status: String,
    pub flags: String,
    pub vrf_binding: String,
    pub label_switching: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    pub inet_addresses: Vec<InterfaceAddress>,
    pub inet6_addresses: Vec<String>,
}

#[derive(Serialize)]
pub struct InterfaceAddress {
    pub address: String,
    pub secondary: bool,
}

pub fn link_brief_show(rib: &Rib, buf: &mut String) {
    // Write the header just once if there is any link
    if !rib.links.is_empty() {
        writeln!(buf, "Interface        Status VRF            Addresses").unwrap();
        writeln!(buf, "---------        ------ ---            ---------").unwrap();
    }

    for link in rib.links.values() {
        let status = if link.is_up() { "Up" } else { "Down" };
        let vrf = link_vrf_name(rib, link).unwrap_or("default");
        let addrs = link.addr4.iter().chain(link.addr6.iter());

        let mut addrs_iter = addrs.peekable();
        if addrs_iter.peek().is_none() {
            // No addresses
            writeln!(buf, "{:<16} {:<6} {:<14}", link.name, status, vrf).unwrap();
        } else {
            let mut first = true;
            for addr in addrs_iter {
                if first {
                    writeln!(
                        buf,
                        "{:<16} {:<6} {:<14} {}",
                        link.name, status, vrf, addr.addr
                    )
                    .unwrap();
                    first = false;
                } else {
                    writeln!(buf, "{:>39}{}", "", addr.addr).unwrap();
                }
            }
        }
    }
}

pub fn link_brief_show_json(rib: &Rib) -> String {
    let mut interfaces = Vec::new();

    for link in rib.links.values() {
        let addresses: Vec<String> = link
            .addr4
            .iter()
            .chain(link.addr6.iter())
            .map(|addr| addr.addr.to_string())
            .collect();

        let interface_brief = InterfaceBrief {
            interface: link.name.clone(),
            status: if link.is_up() {
                "Up".to_string()
            } else {
                "Down".to_string()
            },
            vrf: link_vrf_name(rib, link)
                .map(str::to_string)
                .unwrap_or_else(|| "default".to_string()),
            addresses,
        };

        interfaces.push(interface_brief);
    }

    serde_json::to_string_pretty(&interfaces).unwrap_or_else(|_| "{}".to_string())
}

pub fn link_detailed_show_json(rib: &Rib, link_name: Option<&str>) -> String {
    let mut interfaces = Vec::new();

    if let Some(name) = link_name {
        // Show single interface
        if let Some(link) = rib.link_by_name(name) {
            interfaces.push(link_to_detailed_json(rib, link));
        } else {
            let error = serde_json::json!({
                "error": format!("interface {} not found", name)
            });
            return serde_json::to_string_pretty(&error).unwrap_or_else(|_| "{}".to_string());
        }
    } else {
        // Show all interfaces
        for link in rib.links.values() {
            interfaces.push(link_to_detailed_json(rib, link));
        }
    }

    serde_json::to_string_pretty(&interfaces).unwrap_or_else(|_| "{}".to_string())
}

fn link_to_detailed_json(rib: &Rib, link: &Link) -> InterfaceDetailed {
    let inet_addresses: Vec<InterfaceAddress> = link
        .addr4
        .iter()
        .map(|addr| InterfaceAddress {
            address: addr.addr.to_string(),
            secondary: addr.secondary,
        })
        .collect();

    let inet6_addresses: Vec<String> = link
        .addr6
        .iter()
        .map(|addr| addr.addr.to_string())
        .collect();

    InterfaceDetailed {
        interface: link.name.clone(),
        hardware: format!("{}", link.link_type),
        index: link.index,
        metric: link.metric,
        mtu: link.mtu,
        mtu_error: link.mtu_error.clone(),
        link_status: if link.is_up() {
            "Up".to_string()
        } else {
            "Down".to_string()
        },
        flags: format!("{}", link.flags),
        vrf_binding: link_vrf_name(rib, link)
            .map(|n| format!("vrf {}", n))
            .unwrap_or_else(|| "Not bound".to_string()),
        label_switching: if link.label {
            "enabled".to_string()
        } else {
            "disabled".to_string()
        },
        mac_address: link.mac.map(|mac| format!("{}", mac)),
        inet_addresses,
        inet6_addresses,
    }
}

pub fn link_show(rib: &Rib, mut args: Args, json: bool) -> String {
    let cb = os_traffic_dump();
    let mut buf = String::new();

    if args.is_empty() {
        if json {
            return link_detailed_show_json(rib, None);
        } else {
            for (_, link) in rib.links.iter() {
                link_info_show(rib, link, &mut buf, &cb);
            }
        }
    } else {
        let link_name = args.string().unwrap();

        if link_name == "brief" {
            if json {
                return link_brief_show_json(rib);
            } else {
                link_brief_show(rib, &mut buf);
                return buf;
            }
        }

        if json {
            return link_detailed_show_json(rib, Some(&link_name));
        } else {
            if let Some(link) = rib.link_by_name(&link_name) {
                link_info_show(rib, link, &mut buf, &cb)
            } else {
                write!(buf, "% interface {} not found", link_name).unwrap();
            }
        }
    }
    buf
}

/// Insert a LinkAddr or merge it into an existing entry with the same address.
///
/// Returns `Some(())` if the address was newly inserted, `None` if a matching
/// entry already existed. In the merge case, the existing entry's `config`
/// and `fib` flags are OR-ed with the incoming flags — this lets the kernel's
/// netlink confirmation of a config-driven address flip `fib` true on the
/// already-present LinkAddr without creating a duplicate.
pub fn link_addr_update(link: &mut Link, addr: LinkAddr) -> Option<()> {
    let bucket = if addr.is_v4() {
        &mut link.addr4
    } else {
        &mut link.addr6
    };
    if let Some(existing) = bucket.iter_mut().find(|a| a.addr == addr.addr) {
        existing.config |= addr.config;
        existing.fib |= addr.fib;
        return None;
    }
    bucket.push(addr);
    Some(())
}

/// Handle a kernel-side address removal, branching on `config`:
///
/// - If the existing entry was configured (`config = true`), keep it but
///   clear its `fib` flag — the kernel no longer has the address but config
///   intent survives so `link_up` can re-install it later.
/// - If the existing entry was kernel-only (`config = false`), remove it.
///
/// Returns `Some(())` if a matching entry was found and processed, `None`
/// otherwise. Callers do not currently differentiate the two branches via
/// the return value.
pub fn link_addr_del(link: &mut Link, addr: LinkAddr) -> Option<()> {
    let bucket = if addr.is_v4() {
        &mut link.addr4
    } else {
        &mut link.addr6
    };
    let pos = bucket.iter().position(|x| x.addr == addr.addr)?;
    if bucket[pos].config {
        bucket[pos].fib = false;
    } else {
        bucket.remove(pos);
    }
    Some(())
}

impl Rib {
    pub async fn link_add(&mut self, fib_link: FibLink) {
        if rib_interface() {
            tracing::info!(
                "link_add: ifindex {} name {} vni {:?} master {:?}",
                fib_link.index,
                fib_link.name,
                fib_link.vni,
                fib_link.master,
            );
        }
        // Capture pre-state so we can detect a VXLAN-bridge association
        // gaining valid `(master, vni)` and trigger an FDB rescan. The
        // common case is operator-driven sequence:
        //   1. ip link add br50 type bridge      (no master/vni)
        //   2. ip link add vxlan100 type vxlan id 100   (vni set, no master)
        //   3. ip link set vxlan100 master br50  (master gained — THIS PATH)
        // Without rescan, FDB entries already learned on `br50` between
        // steps 1 and 3 would never reach the EVPN advertise path until
        // they re-learn; with rescan we re-emit `RibRx::FdbAdd` for them.
        let ifindex = fib_link.index;
        let prev_evpn_bridge: Option<u32> = self
            .links
            .get(&ifindex)
            .and_then(|l| if l.vni.is_some() { l.master } else { None });
        // Pre-update VNI snapshot so the existing-link path can fire
        // `register_vxlan_ifindex` / `unregister_vxlan_ifindex` on
        // transitions. Without this, a VXLAN whose RTM_NEWLINK arrives
        // a second time (e.g. partial first emission, then a full one
        // carrying `IFLA_VXLAN_ID`) only gets its VNI cached on `Link`
        // but never registered with FIB — so subsequent `mac_add`
        // calls find no entry in `vni_ifindex_map` and silently skip.
        let prev_vni: Option<u32> = self.links.get(&ifindex).and_then(|l| l.vni);

        // Capture MTU pre-state and the incoming value so a change on an
        // already-known link (operator `interface X mtu N`, or an
        // external `ip link set ... mtu`) can be fanned out to protocol
        // modules that cache it for packet generation (OSPF DD if_mtu,
        // IS-IS hello padding). `prev_mtu` is None for a brand-new link —
        // its mtu rides along on `api_link_add` instead.
        let prev_mtu: Option<u32> = self.links.get(&ifindex).map(|l| l.mtu);
        let new_mtu: u32 = fib_link.mtu;

        // Capture master pre-state so an existing link crossing a VRF
        // boundary (operator `interface X vrf Y`, applied by the kernel
        // as an RTM_NEWLINK on an already-known ifindex) can be
        // reconciled below. `link_existed` distinguishes this from a
        // brand-new link, whose notification is handled in the `else`
        // branch via `api_link_add`.
        let link_existed = self.links.contains_key(&ifindex);
        let prev_master: Option<u32> = self.links.get(&ifindex).and_then(|l| l.master);
        let now_master: Option<u32> = fib_link.master;

        if let Some(link) = self.links.get_mut(&fib_link.index) {
            // When link already exists, we are going to check interface up &
            // down event handling.
            if link.is_up() {
                if !fib_link.flags.is_up() {
                    if rib_interface() {
                        tracing::info!(
                            "kernel: link {} (ifindex {}) Up => Down",
                            link.name,
                            link.index
                        );
                    }

                    link.flags = fib_link.flags;
                    let _ = self.tx.send(Message::LinkDown {
                        ifindex: link.index,
                    });
                }
            } else if fib_link.flags.is_up() {
                if rib_interface() {
                    tracing::info!(
                        "kernel: link {} (ifindex {}) Down => Up; recovering connected routes",
                        link.name,
                        link.index
                    );
                }
                link.flags = fib_link.flags;
                let _ = self.tx.send(Message::LinkUp {
                    ifindex: link.index,
                });
            }
            // Master / VNI can change on an existing link too — most
            // commonly when a VXLAN device is enslaved or re-enslaved
            // via `ip link set ... master <br>` after creation. Track
            // them so `vni_for_bridge` reflects the current state and
            // FDB resolution gets the right bridge.
            link.master = fib_link.master;
            link.vni = fib_link.vni;
            // Adopt the kernel's current MTU (it may have changed since
            // we last saw this link — our own `link_set_mtu` echoes back
            // here, as does an external `ip link set`). The fan-out to
            // protocols happens after the borrow is released, below.
            link.mtu = fib_link.mtu;
        } else {
            let link = Link::from(fib_link);
            let _ = sysctl_mpls_enable(&link.name);
            let _ = sysctl_seg6_enable(&link.name);
            let _ = sysctl_keep_addr_on_down(&link.name);
            self.api_link_add(&link);
            self.links.insert(link.index, link.clone());

            // Note: VXLAN VNI registration happens in the unified
            // post-block reconciliation below (covers both new-link
            // and existing-link paths uniformly).

            // Replay an operator-configured MTU for a freshly-appeared
            // link (config-before-interface, or interface re-created).
            // Only re-issue when the live value differs; the kernel's
            // echoed RTM_NEWLINK then updates the cached mtu. Scoped to
            // the new-link branch so plain RTM_NEWLINK echoes don't
            // re-attempt a previously-rejected set on every event.
            if let Some(&mtu) = self.mtu_config.get(&link.name)
                && mtu != link.mtu
            {
                let ifindex = link.index;
                let name = link.name.clone();
                match self.fib_handle.link_set_mtu(ifindex, mtu).await {
                    Ok(()) => {
                        if let Some(l) = self.links.get_mut(&ifindex) {
                            l.mtu_error = None;
                        }
                    }
                    Err(e) => {
                        if let Some(l) = self.links.get_mut(&ifindex) {
                            l.mtu_error = Some(format!("MTU set to {mtu} is failed due to {e}"));
                        }
                        tracing::warn!("link_set_mtu({name}, {mtu}) failed: {e}");
                    }
                }
            }

            if !link.is_up() {
                self.make_link_up(link.index).await;
            }
        }

        // Fan out an MTU change on an already-known link to protocol
        // subscribers. `prev_mtu` is Some only when the link existed
        // before this call; a brand-new link carried its mtu on the
        // `api_link_add` above, so this fires only on genuine changes.
        if let Some(prev) = prev_mtu
            && prev != new_mtu
        {
            self.api_link_mtu(ifindex, new_mtu);
        }

        // A master change that crosses a VRF boundary moves this
        // interface between subscriber sets: protocol clients in the
        // *old* VRF must see it leave (DelLink), clients in the *new*
        // VRF must see it arrive (NewLink). The kernel reports the
        // enslave/release as an RTM_NEWLINK on an already-known
        // ifindex, so the new-link branch above (which fires
        // `api_link_add`) is skipped — reconcile the move here. A
        // master change that stays within the same VRF id (e.g. bridge
        // enslave, where the master isn't a VRF device → id 0) is a
        // no-op.
        if link_existed {
            let prev_vrf_id = self.master_vrf_id(prev_master);
            let now_vrf_id = self.master_vrf_id(now_master);
            if prev_vrf_id != now_vrf_id
                && let Some(link) = self.links.get(&ifindex).cloned()
            {
                // Withdraw from the old VRF — addresses first, then the
                // link — so a client tearing down per-interface state
                // sees dependents leave before the interface itself.
                for addr in link.addr4.iter().chain(link.addr6.iter()) {
                    self.api_addr_del_vrf(addr, prev_vrf_id);
                }
                self.api_link_del_vrf(ifindex, prev_vrf_id);
                // Announce to the new VRF — link first, then its
                // addresses — mirroring the subscribe() dump order. The
                // addresses were originally pushed only to the VRF the
                // interface used to sit in, so the new VRF's clients
                // need this replay to learn them.
                self.api_link_add_vrf(&link, now_vrf_id);
                for addr in link.addr4.iter().chain(link.addr6.iter()) {
                    self.api_addr_add_vrf(addr, now_vrf_id);
                }
                // The interface's addresses changed scope: both the
                // VRF it left and the one it joined (and the global
                // pick, which excludes VRF members) may now derive a
                // different Router-ID.
                self.router_id_update();
            }
        }

        // Reconcile FIB's VNI→ifindex map across (prev_vni → now_vni)
        // transitions for both branches uniformly:
        //   None    → Some(n): register (new VXLAN, or pre-existing
        //                      link gained its VXLAN ID)
        //   Some(m) → Some(n), m ≠ n: unregister m, register n
        //   Some(n) → None: unregister n (rare — kernel doesn't
        //                   normally strip the VNI from a live VXLAN)
        //   unchanged: no-op
        // Doing this post-block (rather than only in the new-link
        // branch) is what fixes the case where RTM_NEWLINK is
        // re-emitted with `IFLA_VXLAN_ID` after the link was first
        // observed without it — without reconciliation, the VNI
        // would land on `Link::vni` but never reach `vni_ifindex_map`,
        // and `mac_add` would silently skip every install.
        let now_vni: Option<u32> = self.links.get(&ifindex).and_then(|l| l.vni);
        if prev_vni != now_vni
            && let Some(new) = now_vni
        {
            self.fib_handle.register_vxlan_ifindex(new, ifindex);
            if let Some(local) = self.links.get(&ifindex).and_then(|l| l.vxlan_local) {
                self.api_vxlan_add(new, local);
            }
        }

        // Did this link just gain (or change) its EVPN bridge
        // association? If so, walk the neighbor table and re-emit
        // `RibRx::FdbAdd` for every AF_BRIDGE entry on that bridge.
        // BGP's `evpn_originate_macip` is idempotent (update_evpn
        // replaces same ident+remote_id) so duplicate fires are safe.
        let now_evpn_bridge: Option<u32> = self
            .links
            .get(&ifindex)
            .and_then(|l| if l.vni.is_some() { l.master } else { None });
        if let Some(bridge) = now_evpn_bridge
            && prev_evpn_bridge != Some(bridge)
        {
            // The VXLAN just joined a bridge: apply the EVPN bridge-slave
            // defaults on its port (`neigh_suppress on`, `learning off`).
            self.fib_handle.vxlan_bridge_port_defaults(ifindex).await;
            self.rescan_fdb_for_bridge(bridge);
        }

        // If a VRF binding is pending for this interface (operator
        // configured it before the kernel device appeared, or before
        // the VRF master was created), replay it now.
        let ifname = self
            .links
            .get(&ifindex)
            .map(|l| l.name.clone())
            .unwrap_or_default();
        if let Some(vrf) = self.pending_vrf_bind.get(&ifname).cloned() {
            let _ = self.tx.send(Message::LinkVrfBind { ifname, vrf });
        }
    }

    pub fn link_delete(&mut self, oslink: FibLink) {
        // Unregister via the kernel-derived VNI on the netlink
        // message (mirrors the registration trigger in `link_add`).
        if let Some(vni) = oslink.vni {
            self.fib_handle.unregister_vxlan_ifindex(vni);
            self.api_vxlan_del(vni);
        }
        // Notify subscribers BEFORE removing the link entry, so the
        // VRF lookup in `api_link_del` still resolves to the right
        // subscribers instead of falling through to default VRF.
        self.api_link_del(oslink.index);
        self.links.remove(&oslink.index);
    }

    pub fn link_name(&self, link_index: u32) -> String {
        match self.links.get(&link_index) {
            Some(link) => link.name.clone(),
            None => String::from("unknown"),
        }
    }

    pub fn link_by_name(&self, link_name: &str) -> Option<&Link> {
        self.links
            .iter()
            .find_map(|(_, v)| if v.name == link_name { Some(v) } else { None })
    }

    pub fn link_comps(&self) -> Vec<String> {
        self.links.values().map(|link| link.name.clone()).collect()
    }

    /// Completion candidates for the `rib:vrf` dynamic key — the names
    /// of the VRFs currently applied (one per kernel master device).
    pub fn vrf_comps(&self) -> Vec<String> {
        self.vrfs.keys().cloned().collect()
    }

    /// Add an IPv4 or IPv6 address to an interface link.
    ///
    /// This function validates the address before adding it to prevent invalid configurations:
    /// - Rejects addresses with zero prefix length (/0)
    /// - Rejects 0.0.0.0 as an interface address for IPv4
    ///
    /// # Arguments
    /// * `osaddr` - The FIB address containing the IP address, prefix length, and interface index
    /// * `from_config` - true when the address originates from `link_config_exec`
    ///   (i.e. the user configured it through the configuration manager). Sets
    ///   `LinkAddr::config = true` so we can distinguish configured addresses
    ///   from kernel-only addresses (e.g. SLAAC, manual `ip addr add`) and
    ///   recover them across link bounces.
    pub fn addr_add(&mut self, osaddr: FibAddr, from_config: bool) {
        // Validate against zero prefix length - prevents default route addresses on interfaces
        if osaddr.addr.prefix_len() == 0 {
            println!("FIB: zero prefixlen addr!");
            return;
        }

        // Validate against 0.0.0.0 address for IPv4 - prevents unspecified address on interfaces
        if let ipnet::IpNet::V4(v4_net) = osaddr.addr
            && v4_net.addr().is_unspecified()
        {
            println!("FIB: cannot add 0.0.0.0 as interface address");
            return;
        }

        let mut addr = LinkAddr::from(osaddr);
        if from_config {
            addr.config = true;
        }
        if let Some(link) = self.links.get_mut(&addr.ifindex) {
            let was_addr_added = link_addr_update(link, addr.clone()).is_some();

            // If address was successfully added and the interface is up and running,
            // create a connected route
            if was_addr_added && link.is_up() {
                match addr.addr {
                    IpNet::V4(v4_addr) => {
                        let prefix = v4_addr.apply_mask();
                        // println!("Connected: {:?} - adding to RIB (interface up)", prefix);
                        let mut rib = RibEntry::new(RibType::Connected);
                        rib.ifindex = addr.ifindex;
                        rib.set_valid(true);
                        let msg = Message::Ipv4Add { prefix, rib };
                        let _ = self.tx.send(msg);
                    }
                    IpNet::V6(v6_addr) => {
                        let prefix = v6_addr.apply_mask();
                        // println!(
                        //     "Connected IPv6: {:?} - adding to RIB (interface up)",
                        //     prefix
                        // );
                        let mut rib = RibEntry::new(RibType::Connected);
                        rib.ifindex = addr.ifindex;
                        rib.set_valid(true);
                        let msg = Message::Ipv6Add { prefix, rib };
                        let _ = self.tx.send(msg);
                    }
                }
            }
            self.api_addr_add(&addr);
        }
    }

    pub fn addr_del(&mut self, osaddr: FibAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.ifindex) {
            // TODO: When the deleted address is configured address, we remove
            // installed flag from the address so that when interface goes up we
            // can reinstall the address again.

            // Before removing the address, create connected route removal message if interface is up
            if link.is_up() {
                match addr.addr {
                    IpNet::V4(v4_addr) => {
                        let prefix = v4_addr.apply_mask();
                        // println!(
                        //     "Connected: {:?} - removing from RIB (address deleted)",
                        //     prefix
                        // );
                        let mut rib = RibEntry::new(RibType::Connected);
                        rib.ifindex = addr.ifindex;
                        let msg = Message::Ipv4Del { prefix, rib };
                        let _ = self.tx.send(msg);
                    }
                    IpNet::V6(v6_addr) => {
                        let prefix = v6_addr.apply_mask();
                        // println!(
                        //     "Connected IPv6: {:?} - removing from RIB (address deleted)",
                        //     prefix
                        // );
                        let mut rib = RibEntry::new(RibType::Connected);
                        rib.ifindex = addr.ifindex;
                        let msg = Message::Ipv6Del { prefix, rib };
                        let _ = self.tx.send(msg);
                    }
                }
            }

            link_addr_del(link, addr.clone());

            self.api_addr_del(&addr);
        }
    }
}

pub struct LinkConfig {}

impl LinkConfig {
    pub fn new() -> Self {
        LinkConfig {}
    }

    pub fn commit(&mut self, _tx: UnboundedSender<Message>) {
        //
    }
}

/// Configure interface IPv4 and IPv6 addresses with validation.
///
/// This function handles configuration of both IPv4 and IPv6 addresses on interfaces with validation:
///
/// **IPv4 validation:**
/// - Rejects 0.0.0.0 as an interface address
/// - Rejects addresses with zero prefix length (/0)
///
/// **IPv6 validation:**
/// - Rejects ::0 as an interface address
/// - Rejects addresses with zero prefix length (/0)
/// - Rejects loopback addresses (::1) on non-loopback interfaces
///
/// # Arguments
/// * `rib` - Mutable reference to the RIB instance
/// * `path` - Configuration path (e.g., "/interface/ipv4/address" or "/interface/ipv6/address")
/// * `args` - Command arguments containing interface name and address
/// * `op` - Configuration operation (set/delete)
// Temporary func
pub async fn link_config_exec(
    rib: &mut Rib,
    path: String,
    mut args: Args,
    op: ConfigOp,
) -> Result<()> {
    const LINK_ERR: &str = "missing interface name";
    const IPV4_ADDR_ERR: &str = "missing ipv4 address";
    const IPV6_ADDR_ERR: &str = "missing ipv6 address";

    let ifname = args.string().context(LINK_ERR)?;

    // let func = self.builder.map.get()
    if path == "/interface/ipv4/address" {
        let v4addr = args.v4net().context(IPV4_ADDR_ERR)?;

        if op.is_set() {
            // Validate against 0.0.0.0 address
            if v4addr.addr().is_unspecified() {
                println!("Cannot configure 0.0.0.0 as interface address");
                return Ok(());
            }

            // Validate against zero prefix length
            if v4addr.prefix_len() == 0 {
                println!("Cannot configure address with zero prefix length");
                return Ok(());
            }

            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                // Check if IPv4 address is already configured on the link
                if let Some(link) = rib.links.get(&ifindex) {
                    // Check if this IPv4 address already exists on the interface
                    for existing_addr in &link.addr4 {
                        if let IpNet::V4(existing_v4) = existing_addr.addr
                            && existing_v4 == v4addr
                        {
                            // println!(
                            //     "IPv4 address {} is already configured on interface {}",
                            //     v4addr, ifname
                            // );
                            return Ok(());
                        }
                    }
                }

                let result = rib.fib_handle.addr_add_ipv4(ifindex, &v4addr, false).await;
                match result {
                    Ok(_) => {
                        let addr = FibAddr {
                            addr: ipnet::IpNet::V4(v4addr),
                            link_index: ifindex,
                            secondary: false,
                        };
                        rib.addr_add(addr, true);
                    }
                    Err(_) => {
                        println!("IPaddress add failure");
                    }
                }
            }
        } else {
            // Handle IPv4 address deletion
            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                // Clear `config` on the existing LinkAddr so the kernel's
                // subsequent DelAddr notification removes the entry instead
                // of keeping it as a recovery candidate.
                if let Some(link) = rib.links.get_mut(&ifindex) {
                    let target = IpNet::V4(v4addr);
                    if let Some(existing) = link.addr4.iter_mut().find(|a| a.addr == target) {
                        existing.config = false;
                    }
                }
                rib.fib_handle.addr_del_ipv4(ifindex, &v4addr).await;
                let addr = FibAddr {
                    addr: ipnet::IpNet::V4(v4addr),
                    link_index: ifindex,
                    secondary: false,
                };
                rib.addr_del(addr);
            }
        }
    } else if path == "/interface/ipv6/address" {
        let v6addr = args.v6net().context(IPV6_ADDR_ERR)?;

        if op.is_set() {
            // Validate against ::0 address
            if v6addr.addr().is_unspecified() {
                println!("Cannot configure ::0 as interface address");
                return Ok(());
            }

            // Validate against zero prefix length
            if v6addr.prefix_len() == 0 {
                println!("Cannot configure address with zero prefix length");
                return Ok(());
            }

            // Validate against loopback address on non-loopback interfaces
            if v6addr.addr().is_loopback()
                && let Some(ifindex) = link_lookup(rib, ifname.to_string())
                && let Some(link) = rib.links.get(&ifindex)
                && !link.is_loopback()
            {
                println!("Cannot configure loopback address on non-loopback interface");
                return Ok(());
            }

            // Check if IPv6 address is already configured on the link
            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                if let Some(link) = rib.links.get(&ifindex) {
                    // Check if this IPv6 address already exists on the interface
                    for existing_addr in &link.addr6 {
                        if let IpNet::V6(existing_v6) = existing_addr.addr
                            && existing_v6 == v6addr
                        {
                            // println!(
                            //     "IPv6 address {} is already configured on interface {}",
                            //     v6addr, ifname
                            // );
                            return Ok(());
                        }
                    }
                }
                let result = rib.fib_handle.addr_add_ipv6(ifindex, &v6addr, false).await;
                match result {
                    Ok(_) => {
                        let addr = FibAddr {
                            addr: ipnet::IpNet::V6(v6addr),
                            link_index: ifindex,
                            secondary: false,
                        };
                        rib.addr_add(addr, true);
                    }
                    Err(_) => {
                        println!("IPv6 address add failure");
                    }
                }
            } else {
                println!("Interface {} not found", ifname);
            }
        } else {
            // Handle IPv6 address deletion
            if let Some(ifindex) = link_lookup(rib, ifname.to_string()) {
                // Clear `config` on the existing LinkAddr so the kernel's
                // subsequent DelAddr notification removes the entry instead
                // of keeping it as a recovery candidate.
                if let Some(link) = rib.links.get_mut(&ifindex) {
                    let target = IpNet::V6(v6addr);
                    if let Some(existing) = link.addr6.iter_mut().find(|a| a.addr == target) {
                        existing.config = false;
                    }
                }
                rib.fib_handle.addr_del_ipv6(ifindex, &v6addr).await;
                let addr = FibAddr {
                    addr: ipnet::IpNet::V6(v6addr),
                    link_index: ifindex,
                    secondary: false,
                };
                rib.addr_del(addr);
            } else {
                println!("Interface {} not found", ifname);
            }
        }
    } else if path == "/interface/vrf" {
        // `set interface X vrf Y`   → enslave X to VRF master Y.
        // `delete interface X vrf [Y]` → unbind X from whatever VRF it
        // currently sits in. The optional Y on delete is ignored: the
        // intent is unambiguous and we want to tolerate either form.
        let vrf = if op.is_set() {
            Some(args.string().context("missing vrf name")?)
        } else {
            // Drain any trailing token so it isn't picked up later.
            let _ = args.string();
            None
        };
        let _ = rib.tx.send(Message::LinkVrfBind { ifname, vrf });
    } else if path == "/interface/mtu" {
        // `set interface X mtu N`    → record desired MTU and apply it.
        // `delete interface X mtu`   → drop the desired MTU and restore
        // the per-type kernel default (65536 loopback / 1500 otherwise).
        //
        // The configured value is durable desired-state in
        // `rib.mtu_config` (keyed by name) so it survives the interface
        // disappearing and is replayed by `link_add` when it returns.
        // We only *issue* the netlink set here; the kernel's echoed
        // RTM_NEWLINK updates the cached `Link::mtu` (and fans the
        // change out to protocols) via `link_add`. A rejected set
        // produces no echo, so we capture the reason in `Link::mtu_error`
        // for `show interface`.
        if op.is_set() {
            let mtu = args.u32().context("missing mtu value")?;
            rib.mtu_config.insert(ifname.clone(), mtu);
            if let Some(ifindex) = link_lookup(rib, ifname.clone()) {
                match rib.fib_handle.link_set_mtu(ifindex, mtu).await {
                    Ok(()) => {
                        if let Some(link) = rib.links.get_mut(&ifindex) {
                            link.mtu_error = None;
                        }
                    }
                    Err(e) => {
                        if let Some(link) = rib.links.get_mut(&ifindex) {
                            link.mtu_error = Some(format!("MTU set to {mtu} is failed due to {e}"));
                        }
                        tracing::warn!("link_set_mtu({ifname}, {mtu}) failed: {e}");
                    }
                }
            }
        } else {
            // Drain a trailing value token if the delete carried one.
            let _ = args.u32();
            rib.mtu_config.remove(&ifname);
            if let Some(ifindex) = link_lookup(rib, ifname.clone()) {
                // Restore the MTU the kernel reported when we first
                // observed this link, before any operator MTU was
                // applied (see `Link::original_mtu`).
                let original = rib.links.get(&ifindex).map(|l| l.original_mtu);
                if let Some(original) = original {
                    match rib.fib_handle.link_set_mtu(ifindex, original).await {
                        Ok(()) => {
                            if let Some(link) = rib.links.get_mut(&ifindex) {
                                link.mtu_error = None;
                            }
                        }
                        Err(e) => {
                            if let Some(link) = rib.links.get_mut(&ifindex) {
                                link.mtu_error =
                                    Some(format!("MTU set to {original} is failed due to {e}"));
                            }
                            tracing::warn!("link_set_mtu({ifname}, {original}) failed: {e}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn link_lookup(rib: &Rib, name: String) -> Option<u32> {
    for (_, link) in rib.links.iter() {
        if link.name == name {
            return Some(link.index);
        }
    }

    None
}

/// Resolve the VRF a link is enslaved to, by matching `link.master`
/// against the ifindex of each known VRF master device. Returns
/// `Some(name)` if the link is in a configured VRF, `None` for the
/// default VRF or for slaves of non-VRF masters (e.g. bridges).
pub fn link_vrf_name<'a>(rib: &'a Rib, link: &Link) -> Option<&'a str> {
    let master = link.master?;
    rib.vrfs
        .values()
        .find(|v| v.ifindex == master)
        .map(|v| v.name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fib::message::FibAddr;
    use ipnet::{IpNet, Ipv4Net};
    use std::net::Ipv4Addr;

    #[test]
    fn test_zero_address_validation() {
        // Test validation logic for 0.0.0.0 address
        let zero_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 24).unwrap()),
            link_index: 1,
            secondary: false,
        };

        // Check that 0.0.0.0 is correctly identified as unspecified
        if let IpNet::V4(v4_net) = zero_addr.addr {
            assert!(
                v4_net.addr().is_unspecified(),
                "0.0.0.0 should be identified as unspecified"
            );
        }
    }

    #[test]
    fn test_zero_prefix_length_validation() {
        // Test validation logic for zero prefix length
        let zero_prefix_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 0).unwrap()),
            link_index: 1,
            secondary: false,
        };

        assert_eq!(
            zero_prefix_addr.addr.prefix_len(),
            0,
            "Prefix length should be 0"
        );
    }

    #[test]
    fn test_valid_address_validation() {
        // Test validation logic for valid address
        let valid_addr = FibAddr {
            addr: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
            link_index: 1,
            secondary: false,
        };

        // Should pass both validations
        assert_ne!(
            valid_addr.addr.prefix_len(),
            0,
            "Valid address should have non-zero prefix"
        );

        if let IpNet::V4(v4_net) = valid_addr.addr {
            assert!(
                !v4_net.addr().is_unspecified(),
                "Valid address should not be 0.0.0.0"
            );
        }
    }

    fn test_link() -> Link {
        Link {
            index: 1,
            name: "test0".to_string(),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: LinkFlags::empty(),
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: None,
            vni: None,
            vxlan_local: None,
            mtu_error: None,
        }
    }

    fn test_addr_v4(addr: Ipv4Addr, prefix_len: u8, config: bool, fib: bool) -> LinkAddr {
        LinkAddr {
            addr: IpNet::V4(Ipv4Net::new(addr, prefix_len).unwrap()),
            ifindex: 1,
            secondary: false,
            config,
            fib,
        }
    }

    #[test]
    fn test_link_addr_update() {
        let mut link = test_link();
        let addr = test_addr_v4(Ipv4Addr::new(192, 168, 1, 1), 24, true, true);

        // Test adding a new address
        let result = link_addr_update(&mut link, addr.clone());
        assert!(result.is_some(), "Adding new address should succeed");
        assert_eq!(link.addr4.len(), 1, "Link should have 1 IPv4 address");

        // Test adding duplicate address — link_addr_update returns None and
        // does not duplicate the entry.
        let result = link_addr_update(&mut link, addr);
        assert!(result.is_none(), "Duplicate add should not insert");
        assert_eq!(link.addr4.len(), 1, "Link should still have 1 IPv4 address");
    }

    #[test]
    fn test_link_addr_update_merges_flags() {
        let mut link = test_link();
        // Configured first, fib not yet confirmed.
        let cfg = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, true, false);
        link_addr_update(&mut link, cfg);
        assert!(link.addr4[0].config && !link.addr4[0].fib);

        // Kernel netlink confirmation arrives — should flip fib true on the
        // existing entry, not create a duplicate.
        let kernel = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true);
        let result = link_addr_update(&mut link, kernel);
        assert!(result.is_none(), "Merge case returns None");
        assert_eq!(link.addr4.len(), 1);
        assert!(link.addr4[0].config && link.addr4[0].fib);
    }

    #[test]
    fn test_link_addr_del_keeps_configured_entry() {
        let mut link = test_link();
        link_addr_update(
            &mut link,
            test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, true, true),
        );
        // Kernel removed the address (e.g. interface down + IPv6 flush style).
        let kernel_del = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true);
        let result = link_addr_del(&mut link, kernel_del);
        assert!(result.is_some());
        assert_eq!(link.addr4.len(), 1, "config=true entry kept");
        assert!(link.addr4[0].config);
        assert!(!link.addr4[0].fib, "fib flipped to false");
    }

    #[test]
    fn test_link_addr_del_removes_kernel_only_entry() {
        let mut link = test_link();
        link_addr_update(
            &mut link,
            test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true),
        );
        let kernel_del = test_addr_v4(Ipv4Addr::new(10, 0, 0, 1), 24, false, true);
        let result = link_addr_del(&mut link, kernel_del);
        assert!(result.is_some());
        assert_eq!(link.addr4.len(), 0, "kernel-only entry removed");
    }

    #[test]
    fn test_link_addr_del_legacy() {
        let mut link = test_link();
        let addr1 = test_addr_v4(Ipv4Addr::new(192, 168, 1, 1), 24, false, true);
        let addr2 = test_addr_v4(Ipv4Addr::new(192, 168, 1, 2), 24, false, true);

        // Add two addresses
        link_addr_update(&mut link, addr1.clone());
        link_addr_update(&mut link, addr2.clone());
        assert_eq!(link.addr4.len(), 2, "Link should have 2 IPv4 addresses");

        // Test deleting an existing address
        let result = link_addr_del(&mut link, addr1.clone());
        assert!(result.is_some(), "Deleting existing address should succeed");
        assert_eq!(
            link.addr4.len(),
            1,
            "Link should have 1 IPv4 address after deletion"
        );

        // Test deleting non-existent address
        let result = link_addr_del(&mut link, addr1);
        assert!(
            result.is_none(),
            "Deleting non-existent address should fail"
        );
        assert_eq!(link.addr4.len(), 1, "Link should still have 1 IPv4 address");

        // Delete the remaining address
        let result = link_addr_del(&mut link, addr2);
        assert!(
            result.is_some(),
            "Deleting remaining address should succeed"
        );
        assert_eq!(link.addr4.len(), 0, "Link should have no IPv4 addresses");
    }
}
