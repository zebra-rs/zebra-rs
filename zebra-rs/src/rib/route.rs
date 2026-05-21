use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use crate::fib::FibHandle;
use crate::rib::resolve::{ResolveOpt, rib_resolve, rib_resolve_v6};
use crate::rib::util::IpNetExt;
use crate::rib::{Link, LinkFlagsExt, Nexthop};

use super::entry::RibEntry;
use super::inst::{IlmEntry, RT_TABLE_MAIN, Rib};
use super::nexthop::NexthopUni;
use super::{
    Group, GroupTrait, Message, NexthopList, NexthopMap, NexthopMember, NexthopMulti, RibEntries,
    RibType,
};

// Flip to true to re-enable IPv6 RIB/FIB diagnostic trace.
const DEBUG_V6: bool = false;

// Flip to true to re-enable IP address diagnostic trace.
pub const DEBUG_ADDR: bool = false;

// Flip to true to log EVPN-related diagnostic traces (VXLAN VNI
// register/unregister, mac_add / mac_del / mdb_add / mdb_del,
// link_add EVPN bridge association, BGP RT→VNI extraction). Errors
// from the kernel are reported regardless. Imported by the FIB and
// BGP modules so all EVPN diagnostics share one switch.
pub const DEBUG_EVPN: bool = false;

/// Hold-down policy for kernel-driven address recovery.
///
/// If a configured address is deleted by an external actor (NetworkManager,
/// dhcpcd, an operator script, …) zebra-rs re-installs it from
/// `FibMessage::DelAddr`. To avoid an infinite delete/re-install loop with
/// a misbehaving peer, we track recent deletions per (ifindex, prefix) and
/// suppress recovery for `RECOVERY_COOLDOWN` once we see
/// `RECOVERY_BURST_THRESHOLD` events within `RECOVERY_WINDOW`.
pub const RECOVERY_WINDOW: Duration = Duration::from_secs(60);
pub const RECOVERY_BURST_THRESHOLD: usize = 3;
pub const RECOVERY_COOLDOWN: Duration = Duration::from_secs(600);

#[derive(Debug, Default)]
pub struct AddrRecoveryState {
    /// Timestamps of recent kernel DelAddr events for this address.
    /// Only entries within `RECOVERY_WINDOW` of the current call are kept.
    pub history: VecDeque<Instant>,
    /// When set, recovery is suspended until this instant. Cleared on the
    /// next decision after expiry.
    pub suppressed_until: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// Proceed with re-installing this address to the kernel.
    Recover,
    /// Skip recovery. The reason carries why so the caller can log it.
    Suppress(SuppressReason),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SuppressReason {
    /// Cool-down was already active when this call arrived.
    AlreadySuppressed,
    /// This call pushed the history past `RECOVERY_BURST_THRESHOLD`;
    /// cool-down has just started.
    JustTripped,
}

/// Pure decision: would we recover this address right now? Mutates
/// `state` to record the event and may set `suppressed_until`. Pulled
/// out of the `Rib` so unit tests don't need a `FibHandle`.
pub fn addr_recover_decide(state: &mut AddrRecoveryState, now: Instant) -> RecoveryDecision {
    // Already in cool-down.
    if let Some(until) = state.suppressed_until {
        if until > now {
            return RecoveryDecision::Suppress(SuppressReason::AlreadySuppressed);
        }
        // Cool-down expired — reset and treat this call like a fresh
        // first event after silence.
        state.suppressed_until = None;
        state.history.clear();
    }

    // Drop events outside the rolling window.
    let cutoff = now.checked_sub(RECOVERY_WINDOW).unwrap_or(now);
    while let Some(front) = state.history.front() {
        if *front < cutoff {
            state.history.pop_front();
        } else {
            break;
        }
    }

    state.history.push_back(now);

    if state.history.len() >= RECOVERY_BURST_THRESHOLD {
        state.suppressed_until = Some(now + RECOVERY_COOLDOWN);
        return RecoveryDecision::Suppress(SuppressReason::JustTripped);
    }

    RecoveryDecision::Recover
}

impl Rib {
    /// Push a configured address back to the kernel. Used by both
    /// `link_up` (when the kernel dropped a configured address while
    /// the link was down) and the kernel-driven DelAddr recovery
    /// path. Caller is responsible for the recovery decision; this
    /// helper just performs the netlink call and logs the outcome.
    async fn addr_reinstall(&self, ifindex: u32, link_name: &str, addr: &IpNet) {
        match addr {
            IpNet::V4(net) => {
                if DEBUG_ADDR {
                    tracing::info!(
                        "addr_reinstall: {} re-installing IPv4 {} to kernel",
                        link_name,
                        net
                    );
                }
                if let Err(e) = self.fib_handle.addr_add_ipv4(ifindex, net, false).await {
                    tracing::warn!(
                        "addr_reinstall: {} failed to re-install IPv4 {}: {}",
                        link_name,
                        net,
                        e
                    );
                }
            }
            IpNet::V6(net) => {
                if DEBUG_ADDR {
                    tracing::info!(
                        "addr_reinstall: {} re-installing IPv6 {} to kernel",
                        link_name,
                        net
                    );
                }
                if let Err(e) = self.fib_handle.addr_add_ipv6(ifindex, net, false).await {
                    tracing::warn!(
                        "addr_reinstall: {} failed to re-install IPv6 {}: {}",
                        link_name,
                        net,
                        e
                    );
                }
            }
        }
    }

    /// Decide whether the kernel-deleted address `osaddr` corresponds
    /// to a configured `LinkAddr`, and if so push it back to the
    /// kernel — unless the per-address recovery state is in cool-down
    /// (Step 7 hold-down).
    ///
    /// Returns `true` when the caller should *skip* the normal
    /// `addr_del` teardown path: either we re-installed the address
    /// (kernel will echo NewAddr to flip `fib` back to true) or the
    /// suppression policy decided to leave it absent. Returns `false`
    /// when the address was kernel-only — caller falls through to the
    /// existing `addr_del` flow.
    pub async fn addr_recover_if_configured(&mut self, osaddr: &crate::fib::FibAddr) -> bool {
        let ifindex = osaddr.link_index;
        let prefix = osaddr.addr;

        let Some(link) = self.links.get(&ifindex) else {
            return false;
        };
        let bucket = if matches!(prefix, IpNet::V4(_)) {
            &link.addr4
        } else {
            &link.addr6
        };
        let Some(existing) = bucket.iter().find(|x| x.addr == prefix) else {
            return false;
        };
        if !existing.config {
            return false;
        }
        let link_name = link.name.clone();

        // Suppression decision and event recording.
        let now = Instant::now();
        let state = self.addr_recovery.entry((ifindex, prefix)).or_default();
        let decision = addr_recover_decide(state, now);

        match decision {
            RecoveryDecision::Suppress(reason) => {
                let cooldown_remaining = state
                    .suppressed_until
                    .and_then(|until| until.checked_duration_since(now))
                    .unwrap_or_default();
                match reason {
                    SuppressReason::JustTripped => {
                        tracing::warn!(
                            "addr_recover: {} {} deleted {} times in {}s; \
                             suppressing recovery for {}s — investigate \
                             external actor (NetworkManager? dhcpcd? operator script?)",
                            link_name,
                            prefix,
                            RECOVERY_BURST_THRESHOLD,
                            RECOVERY_WINDOW.as_secs(),
                            RECOVERY_COOLDOWN.as_secs(),
                        );
                    }
                    SuppressReason::AlreadySuppressed => {
                        tracing::info!(
                            "addr_recover: {} {} kernel-delete ignored, \
                             still in cool-down ({}s remaining)",
                            link_name,
                            prefix,
                            cooldown_remaining.as_secs(),
                        );
                    }
                }
                // We still flip the LinkAddr's fib flag to false so the
                // RIB matches reality (kernel doesn't have it). The
                // `config = true` row stays — link_up will retry on
                // the next bounce after the cool-down expires.
                if let Some(link) = self.links.get_mut(&ifindex) {
                    let bucket = if matches!(prefix, IpNet::V4(_)) {
                        &mut link.addr4
                    } else {
                        &mut link.addr6
                    };
                    if let Some(e) = bucket.iter_mut().find(|x| x.addr == prefix) {
                        e.fib = false;
                    }
                }
                true
            }
            RecoveryDecision::Recover => {
                if DEBUG_ADDR {
                    tracing::info!(
                        "addr_recover: {} {} kernel-deleted, still in config — \
                         re-installing (history len now {})",
                        link_name,
                        prefix,
                        state.history.len(),
                    );
                }
                // Drop the &mut self borrow held by `state` before
                // calling the FibHandle.
                let _ = state;
                self.addr_reinstall(ifindex, &link_name, &prefix).await;
                // Mark fib=false until the kernel echoes back the
                // NewAddr we just triggered.
                if let Some(link) = self.links.get_mut(&ifindex) {
                    let bucket = if matches!(prefix, IpNet::V4(_)) {
                        &mut link.addr4
                    } else {
                        &mut link.addr6
                    };
                    if let Some(e) = bucket.iter_mut().find(|x| x.addr == prefix) {
                        e.fib = false;
                    }
                }
                true
            }
        }
    }

    pub async fn link_down(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };

        // Notify protocol daemons.
        self.api_link_down(ifindex);

        // Remove connected route.
        for addr4 in link.addr4.iter() {
            if let IpNet::V4(addr) = addr4.addr {
                let prefix = addr.apply_mask();
                let mut rib = RibEntry::new(RibType::Connected);
                rib.ifindex = ifindex;
                let _ = rib_replace_system(&mut self.table, &prefix, rib);
            }
        }
        // Remove connected IPv6 route.
        for addr6 in link.addr6.iter() {
            if let IpNet::V6(addr) = addr6.addr {
                let prefix = addr.apply_mask();
                // println!("Connected IPv6: {:?} down - removing from RIB", prefix);
                let mut rib = RibEntry::new(RibType::Connected);
                rib.ifindex = ifindex;
                let msg = Message::Ipv6Del { prefix, rib };
                let _ = self.tx.send(msg);
            }
        }
        // Remove DHCP and Kernel routes.
        #[cfg(any())]
        for (prefix, rib) in self.table.iter() {
            for entry in rib.iter() {
                if entry.rtype == RibType::Dhcp || entry.rtype == RibType::Kernel {
                    match &entry.nexthop {
                        Nexthop::Link(_) => {
                            //
                        }
                        Nexthop::Uni(uni) => {
                            if uni.ifindex() == Some(ifindex) {
                                let msg = Message::Ipv4Del {
                                    prefix: *prefix,
                                    rib: entry.clone(),
                                };
                                self.tx.send(msg).unwrap();
                            }
                        }
                        Nexthop::List(_list) => {
                            //
                        }
                        Nexthop::Multi(_multi) => {
                            //
                        }
                    }
                }
            }
        }
        // Remove IPv6 DHCP and Kernel routes.
        #[cfg(any())]
        for (prefix, rib) in self.table_v6.iter() {
            for entry in rib.iter() {
                if entry.rtype == RibType::Dhcp || entry.rtype == RibType::Kernel {
                    match &entry.nexthop {
                        Nexthop::Link(_) => {
                            //
                        }
                        Nexthop::Uni(uni) => {
                            if uni.ifindex() == Some(ifindex) {
                                let msg = Message::Ipv6Del {
                                    prefix: *prefix,
                                    rib: entry.clone(),
                                };
                                self.tx.send(msg).unwrap();
                            }
                        }
                        Nexthop::List(_list) => {
                            //
                        }
                        Nexthop::Multi(_multi) => {
                            //
                        }
                    }
                }
            }
        }

        // Resolve RIB. The first sync pass invalidates groups whose
        // egress link just went down; recursive groups (a static via
        // an IS-IS route, say) need a *second* pass once those IS-IS
        // entries have been deselected, otherwise rib_resolve_v6
        // happily walks the still-present-but-now-invalid entries.
        // The debounced Resolve scheduled below handles that.
        ipv4_nexthop_sync(&mut self.nmap, &self.table, &self.links, &self.fib_handle).await;
        ipv4_route_sync(
            &mut self.table,
            &mut self.nmap,
            &self.fib_handle,
            RT_TABLE_MAIN,
            true,
        )
        .await;
        ipv6_nexthop_sync(
            &mut self.nmap,
            &self.table_v6,
            &self.links,
            &self.fib_handle,
        )
        .await;
        ipv6_route_sync(
            &mut self.table_v6,
            &mut self.nmap,
            &self.fib_handle,
            RT_TABLE_MAIN,
        )
        .await;
        self.schedule_rib_sync();
    }

    pub async fn link_up(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            if DEBUG_ADDR {
                tracing::info!(
                    "link_up: ifindex {} not found in link table; skipping connected route recovery",
                    ifindex
                );
            }
            return;
        };
        let link_name = link.name.clone();

        if DEBUG_ADDR {
            tracing::info!(
                "link_up: {} (ifindex {}) recovering {} IPv4 + {} IPv6 connected addresses",
                link_name,
                ifindex,
                link.addr4.len(),
                link.addr6.len()
            );
        }

        // Notify protocol daemons.
        self.api_link_up(ifindex);

        // Add connected IPv4 routes when link comes up
        for addr4 in link.addr4.iter() {
            if let IpNet::V4(addr) = addr4.addr {
                let prefix = addr.apply_mask();
                let mut entry = RibEntry::new(RibType::Connected);
                entry.ifindex = ifindex;
                entry.set_valid(true);

                if DEBUG_ADDR {
                    tracing::info!(
                        "link_up: {} re-adding IPv4 connected prefix {}",
                        link_name,
                        prefix
                    );
                }

                rib_add_system(&mut self.table, &prefix, entry);
                rib_selection_ipv4(
                    &mut self.table,
                    &prefix,
                    None,
                    &mut self.nmap,
                    &self.fib_handle,
                    RT_TABLE_MAIN,
                )
                .await;
            }
        }

        // Add connected IPv6 routes when link comes up
        for addr6 in link.addr6.iter() {
            if let IpNet::V6(addr) = addr6.addr {
                let prefix = addr.apply_mask();
                let mut entry = RibEntry::new(RibType::Connected);
                entry.ifindex = ifindex;
                entry.set_valid(true);

                if DEBUG_ADDR {
                    tracing::info!(
                        "link_up: {} re-adding IPv6 connected prefix {}",
                        link_name,
                        prefix
                    );
                }

                rib_add_system_v6(&mut self.table_v6, &prefix, entry);
                rib_selection_ipv6(
                    &mut self.table_v6,
                    &prefix,
                    None,
                    &mut self.nmap,
                    &self.fib_handle,
                    RT_TABLE_MAIN,
                )
                .await;
            }
        }

        // Re-install configured addresses that the kernel removed while the
        // link was down (config=true, fib=false). The kernel will respond
        // with NewAddr, which goes through addr_add(_, false) and merges
        // fib=true on the existing LinkAddr without producing a duplicate.
        // This must run before route_sync so the kernel has the address by
        // the time protocol routes (e.g. static routes via this nexthop)
        // are installed to the FIB.
        //
        // Suppression policy is shared with the kernel-driven DelAddr
        // recovery path: if a misbehaving external actor has already
        // triggered the cool-down for an address, link_up respects it.
        let recover: Vec<IpNet> = link
            .addr4
            .iter()
            .chain(link.addr6.iter())
            .filter(|a| a.config && !a.fib)
            .map(|a| a.addr)
            .collect();
        for prefix in recover {
            let now = Instant::now();
            let state = self.addr_recovery.entry((ifindex, prefix)).or_default();
            // Don't record a "delete event" here — link_up isn't the
            // kernel saying "deleted", it's us recovering after a
            // bounce. Just consult the existing suppression state.
            let suppressed = matches!(
                state.suppressed_until,
                Some(until) if until > now
            );
            if suppressed {
                let remaining = state
                    .suppressed_until
                    .and_then(|until| until.checked_duration_since(now))
                    .unwrap_or_default();
                tracing::info!(
                    "link_up: {} skipping re-install of {} ({}s cool-down remaining)",
                    link_name,
                    prefix,
                    remaining.as_secs(),
                );
                continue;
            }
            self.addr_reinstall(ifindex, &link_name, &prefix).await;
        }

        ipv4_nexthop_sync(&mut self.nmap, &self.table, &self.links, &self.fib_handle).await;
        ipv4_route_sync(
            &mut self.table,
            &mut self.nmap,
            &self.fib_handle,
            RT_TABLE_MAIN,
            true,
        )
        .await;
        ipv6_nexthop_sync(
            &mut self.nmap,
            &self.table_v6,
            &self.links,
            &self.fib_handle,
        )
        .await;
        ipv6_route_sync(
            &mut self.table_v6,
            &mut self.nmap,
            &self.fib_handle,
            RT_TABLE_MAIN,
        )
        .await;
        // Mirror link_down: schedule a deferred Resolve so recursive
        // groups (e.g. a static whose first segment was unreachable
        // while the link was down) re-evaluate now that the IS-IS
        // routes are back and selectable.
        self.schedule_rib_sync();
    }

    /// Step 9 dispatcher: route an `Ipv4Add` install into the
    /// matching VRF prefix tree. Best-path resolution + FIB install
    /// inside a VRF table land in step 18; today the prefix is
    /// recorded so the per-VRF show path and the future import
    /// pipeline see it, but the kernel install is deliberately
    /// skipped — the global nexthop map can't resolve per-VRF gw
    /// addresses correctly without step 18's overlay.
    pub fn ipv4_route_add_vrf(&mut self, table_id: u32, prefix: &Ipv4Net, entry: RibEntry) {
        if !vrf_ipv4_insert(&mut self.vrf_tables, table_id, prefix, entry) {
            tracing::warn!(
                table_id,
                %prefix,
                "ipv4_route_add_vrf: vrf table not present; dropping install",
            );
        }
    }

    pub fn ipv4_route_del_vrf(&mut self, table_id: u32, prefix: &Ipv4Net, entry: RibEntry) {
        vrf_ipv4_remove(&mut self.vrf_tables, table_id, prefix, entry.rtype);
    }

    pub fn ipv6_route_add_vrf(&mut self, table_id: u32, prefix: &Ipv6Net, entry: RibEntry) {
        if !vrf_ipv6_insert(&mut self.vrf_tables, table_id, prefix, entry) {
            tracing::warn!(
                table_id,
                %prefix,
                "ipv6_route_add_vrf: vrf table not present; dropping install",
            );
        }
    }

    pub fn ipv6_route_del_vrf(&mut self, table_id: u32, prefix: &Ipv6Net, entry: RibEntry) {
        vrf_ipv6_remove(&mut self.vrf_tables, table_id, prefix, entry.rtype);
    }

    pub async fn ipv4_route_add(&mut self, prefix: &Ipv4Net, mut entry: RibEntry, table_id: u32) {
        let before = selected_v4(&self.table, prefix).cloned();
        if entry.is_protocol() {
            let mut replace = rib_replace(&mut self.table, prefix, entry.rtype);
            rib_resolve_nexthop(&mut entry, &self.table, &mut self.nmap);
            rib_add(&mut self.table, prefix, entry);
            self.rib_selection(prefix, replace.pop(), table_id).await;
        } else {
            rib_add_system(&mut self.table, prefix, entry);
            self.rib_selection(prefix, None, table_id).await;
        }
        let after = selected_v4(&self.table, prefix).cloned();
        super::redist::notify_v4_delta(
            &self.redist_filters,
            &self.client_registry,
            prefix,
            before.as_ref(),
            after.as_ref(),
        );

        // Any RIB add can shift the FIB — debounced resolve catches static /
        // SRv6 nexthops that were unreachable before and are now covered by
        // a freshly-installed underlay route (IS-IS, OSPF, connected, ...).
        self.schedule_rib_sync();
    }

    pub async fn ipv4_route_del(&mut self, prefix: &Ipv4Net, entry: RibEntry, table_id: u32) {
        let before = selected_v4(&self.table, prefix).cloned();
        if entry.is_protocol() {
            let mut replace = rib_replace(&mut self.table, prefix, entry.rtype);
            self.rib_selection(prefix, replace.pop(), table_id).await;
        } else {
            // println!("System route remove");
            let mut replace = rib_replace_system(&mut self.table, prefix, entry);
            self.rib_selection(prefix, replace.pop(), table_id).await;
        }
        let after = selected_v4(&self.table, prefix).cloned();
        super::redist::notify_v4_delta(
            &self.redist_filters,
            &self.client_registry,
            prefix,
            before.as_ref(),
            after.as_ref(),
        );

        self.schedule_rib_sync();
    }

    /// MPLS ILM is a single global kernel table — `AF_MPLS` routes
    /// live outside the IPv4/IPv6 per-table namespace, and `RT_TABLE`
    /// has no meaning here. The per-VRF aspect of a VPN decap lives
    /// inside the ILM action (Oif pointing at the VRF master, or a
    /// table pointer on the inner lookup), not in a separate MPLS
    /// table per VRF. So `ilm_add` / `ilm_del` don't take a
    /// `table_id` parameter, and the inbound dispatcher doesn't pass
    /// one for these variants.
    pub async fn ilm_add(&mut self, label: u32, ilm: IlmEntry) {
        // Need to update ilm table.
        self.ilm.insert(label, ilm.clone());

        self.fib_handle.ilm_del(label, &ilm).await;
        self.fib_handle.ilm_add(label, &ilm).await;
    }

    pub async fn ilm_del(&mut self, label: u32, ilm: IlmEntry) {
        self.ilm.remove(&label);

        self.fib_handle.ilm_del(label, &ilm).await;
    }

    pub async fn make_link_up(&mut self, ifindex: u32) {
        if let Some(_link) = self.links.get(&ifindex) {
            self.fib_handle.link_set_up(ifindex).await;
        }
    }

    pub async fn ipv6_route_add(&mut self, prefix: &Ipv6Net, mut entry: RibEntry, table_id: u32) {
        if DEBUG_V6 {
            tracing::info!(
                "[ipv6_route_add] prefix={} rtype={:?} is_protocol={} is_connected={} valid_in={}",
                prefix,
                entry.rtype,
                entry.is_protocol(),
                entry.is_connected(),
                entry.is_valid(),
            );
        }

        // Static seg6local routes (action End.DT6 / End.DT4 / End / uN
        // configured on a prefix) arrive without an ifindex — the
        // config callback doesn't have access to the link table. Pin
        // the install to sr0 here so resolve_v6 short-circuits and
        // the FIB layer emits the right Oif.
        if let Nexthop::Uni(uni) = &mut entry.nexthop
            && let Some(action) = uni.seg6local_action
            && uni.ifindex_origin.is_none()
            && let Some(ifindex) = self.resolve_sid_ifindex(action)
        {
            uni.ifindex_origin = Some(ifindex);
        }

        let before = selected_v6(&self.table_v6, prefix).cloned();
        if entry.is_protocol() {
            let mut replace = rib_replace_v6(&mut self.table_v6, prefix, entry.rtype);
            rib_resolve_nexthop_v6(&mut entry, &self.table_v6, &mut self.nmap);
            if DEBUG_V6 {
                println!(
                    "[ipv6_route_add] after resolve: entry.valid={} nexthop={:?}",
                    entry.is_valid(),
                    entry.nexthop
                );
            }
            rib_add_v6(&mut self.table_v6, prefix, entry);
            self.rib_selection_v6(prefix, replace.pop(), table_id).await;
        } else {
            rib_add_system_v6(&mut self.table_v6, prefix, entry);
            self.rib_selection_v6(prefix, None, table_id).await;
        }
        let after = selected_v6(&self.table_v6, prefix).cloned();
        super::redist::notify_v6_delta(
            &self.redist_filters,
            &self.client_registry,
            prefix,
            before.as_ref(),
            after.as_ref(),
        );

        // Any RIB add can shift the FIB — debounced resolve catches static /
        // SRv6 nexthops that were unreachable before and are now covered by
        // a freshly-installed underlay route (IS-IS, OSPF, connected, ...).
        self.schedule_rib_sync();
    }

    pub async fn ipv6_route_del(&mut self, prefix: &Ipv6Net, entry: RibEntry, table_id: u32) {
        let before = selected_v6(&self.table_v6, prefix).cloned();
        if entry.is_protocol() {
            let mut replace = rib_replace_v6(&mut self.table_v6, prefix, entry.rtype);
            self.rib_selection_v6(prefix, replace.pop(), table_id).await;
        } else {
            // println!("IPv6 System route remove");
            let mut replace = rib_replace_system_v6(&mut self.table_v6, prefix, entry);
            self.rib_selection_v6(prefix, replace.pop(), table_id).await;
        }
        let after = selected_v6(&self.table_v6, prefix).cloned();
        super::redist::notify_v6_delta(
            &self.redist_filters,
            &self.client_registry,
            prefix,
            before.as_ref(),
            after.as_ref(),
        );

        self.schedule_rib_sync();
    }

    pub async fn ipv6_route_resolve(&mut self) {
        ipv6_nexthop_sync(
            &mut self.nmap,
            &self.table_v6,
            &self.links,
            &self.fib_handle,
        )
        .await;
        ipv6_route_sync(
            &mut self.table_v6,
            &mut self.nmap,
            &self.fib_handle,
            RT_TABLE_MAIN,
        )
        .await;
    }

    pub async fn ipv4_route_resolve(&mut self) {
        ipv4_nexthop_sync(&mut self.nmap, &self.table, &self.links, &self.fib_handle).await;
        // `false` = not an ifdown sweep; this resolve cycle is for FIB-update
        // re-resolution, not link-down recovery.
        ipv4_route_sync(
            &mut self.table,
            &mut self.nmap,
            &self.fib_handle,
            RT_TABLE_MAIN,
            false,
        )
        .await;
    }

    pub async fn rib_selection(
        &mut self,
        prefix: &Ipv4Net,
        replace: Option<RibEntry>,
        table_id: u32,
    ) {
        let Some(entries) = self.table.get_mut(prefix) else {
            return;
        };
        ipv4_entry_selection(
            prefix,
            entries,
            replace,
            &mut self.nmap,
            &self.fib_handle,
            table_id,
            false,
        )
        .await;
    }

    pub async fn rib_selection_v6(
        &mut self,
        prefix: &Ipv6Net,
        replace: Option<RibEntry>,
        table_id: u32,
    ) {
        let Some(entries) = self.table_v6.get_mut(prefix) else {
            return;
        };
        ipv6_entry_selection(
            prefix,
            entries,
            replace,
            &mut self.nmap,
            &self.fib_handle,
            table_id,
        )
        .await;
    }
}

pub async fn rib_selection_ipv4(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
) {
    let Some(entries) = table.get_mut(prefix) else {
        return;
    };
    ipv4_entry_selection(prefix, entries, replace, nmap, fib, table_id, true).await;
}

pub async fn rib_selection_ipv6(
    table: &mut PrefixMap<Ipv6Net, RibEntries>,
    prefix: &Ipv6Net,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
) {
    let Some(entries) = table.get_mut(prefix) else {
        return;
    };
    ipv6_entry_selection(prefix, entries, replace, nmap, fib, table_id).await;
}

pub async fn ipv4_nexthop_sync(
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv4Net, RibEntries>,
    links: &BTreeMap<u32, Link>,
    fib: &FibHandle,
) {
    // Update Group::Uni first, then check Group::Multi.
    for nhop in nmap.groups.iter_mut().flatten() {
        if let Group::Uni(uni) = nhop {
            // Origin shortcut: when the source pinned an egress link
            // (IGP adjacency, seg6local install, connected, configured
            // static) we trust it as long as that link is still up.
            // When it goes down the kernel auto-removes the routes
            // that point at it; sync our view so the next route_sync
            // pass deselects + drops the FIB entries instead of
            // happily marking them installed.
            if let Some(ifindex) = uni.ifindex_origin {
                let link_up = links
                    .get(&ifindex)
                    .is_some_and(|l| l.flags.is_up() && l.flags.is_lower_up());
                if link_up {
                    uni.set_valid(true);
                    if !uni.is_installed() {
                        uni.set_installed(true);
                        fib.nexthop_add(&Group::Uni(uni.clone())).await;
                    }
                } else {
                    uni.set_valid(false);
                    uni.set_installed(false);
                }
                continue;
            }
            let resolve = match uni.addr {
                std::net::IpAddr::V4(ipv4_addr) => {
                    rib_resolve(table, ipv4_addr, &ResolveOpt::default())
                }
                std::net::IpAddr::V6(_) => {
                    // IPv6 addresses should be handled by ipv6_nexthop_sync
                    continue;
                }
            };

            // Update the status of the next hop
            let ifindex = resolve.is_valid();
            if ifindex == 0 {
                uni.ifindex_resolved = None;
                uni.set_valid(false);
                if uni.is_installed() {
                    uni.set_installed(false);
                    // XXX fib.nexthop_del(&Group::Uni(uni.clone())).await;
                }
            } else {
                uni.ifindex_resolved = Some(ifindex);
                uni.set_valid(true);
                if !uni.is_installed() {
                    uni.set_installed(true);
                    fib.nexthop_add(&Group::Uni(uni.clone())).await;
                }
            }
        }
    }

    let mut multi_cache: BTreeMap<usize, BTreeSet<(usize, u8)>> = BTreeMap::new();

    for (idx, nhop) in nmap.groups.iter().enumerate() {
        if let Some(Group::Multi(multi)) = nhop {
            let mut set = BTreeSet::<(usize, u8)>::new();
            for (m, v) in multi.set.iter() {
                if let Some(Some(group)) = nmap.groups.get(*m)
                    && group.is_valid()
                {
                    set.insert((*m, *v));
                }
            }
            multi_cache.insert(idx, set);
        }
    }

    for (idx, set) in multi_cache {
        if let Some(Some(Group::Multi(multi))) = nmap.groups.get_mut(idx) {
            if set.is_empty() {
                if multi.is_valid() {
                    // Uninstall.
                    // XXX fib.nexthop_del(&Group::Multi(multi.clone())).await;
                }
                multi.valid = set;
                multi.set_valid(false);
            } else {
                if !multi.is_valid() {
                    // Install.
                    multi.valid = set;
                    fib.nexthop_add(&Group::Multi(multi.clone())).await;
                } else if multi.valid != set {
                    // Update.
                    println!("XXX NexthopMulti Update {:?} -> {:?}", multi.valid, set);
                    multi.valid = set;
                    fib.nexthop_add(&Group::Multi(multi.clone())).await;
                } else {
                    multi.valid = set;
                }
                multi.set_valid(true);
            }
        }
    }
}

pub async fn ipv4_route_sync(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
    ifdown: bool,
) {
    for (p, entries) in table.iter_mut() {
        ipv4_entry_resolve(entries, nmap, ifdown);
        ipv4_entry_selection(p, entries, None, nmap, fib, table_id, ifdown).await;
    }
}

fn ipv4_entry_resolve(entries: &mut RibEntries, nmap: &NexthopMap, ifdown: bool) {
    for entry in entries.iter_mut() {
        if entry.is_protocol() {
            entry_resolve(entry, nmap, ifdown);
        }
    }
}

async fn ipv4_entry_selection(
    prefix: &Ipv4Net,
    entries: &mut RibEntries,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
    ifdown: bool,
) {
    if let Some(mut replace) = replace
        && replace.is_protocol()
    {
        if replace.is_fib() {
            fib.route_ipv4_del(prefix, &replace, table_id).await;
        }
        replace.nexthop_unsync(nmap, fib).await;
    }
    // Selected.
    let prev = rib_prev(entries);

    // New select.
    if ifdown {
        // println!("P: {}", prefix);
        // for e in entries.iter() {
        //     println!(
        //         "E: {:?} distance {} metric {} valid {}",
        //         e.rtype, e.distance, e.metric, e.valid
        //     )
        // }
    }

    let next = rib_next(entries);

    if prev == next {
        return;
    }
    if ifdown {
        // println!("Change: {} prev: {:?} next: {:?}", prefix, prev, next);
    }
    if let Some(prev) = prev {
        let prev = entries.get_mut(prev).unwrap();
        prev.set_selected(false);
        if ifdown {
            // println!("Remove: {}", prefix);
        } else {
            fib.route_ipv4_del(prefix, prev, table_id).await;
        }
        prev.set_fib(false);
    }
    if let Some(next) = next {
        let next = entries.get_mut(next).unwrap();
        next.set_selected(true);

        if next.is_protocol() {
            next.nexthop_sync(nmap, fib).await;
            fib.route_ipv4_add(prefix, next, table_id).await;
        }
        next.set_fib(true);
    }
}

fn nexthop_uni_resolve(nhop: &mut NexthopUni, nmap: &NexthopMap) {
    if let Some(grp) = nmap.get_uni(nhop.gid) {
        nhop.valid = grp.is_valid();
        // Group carries both halves; copy them through unchanged.
        // Origin must never be lost — that's the whole point of the
        // split, so the show path can name the IGP-supplied link
        // even when the table walk would have picked something else.
        nhop.ifindex_origin = grp.ifindex_origin;
        nhop.ifindex_resolved = grp.ifindex_resolved;
    }
}

fn entry_resolve(entry: &mut RibEntry, nmap: &NexthopMap, _ifdown: bool) {
    match &mut entry.nexthop {
        Nexthop::Link(iflink) => {
            tracing::info!("Nexthop::Link({}): this won't happen", iflink);
        }
        Nexthop::Uni(uni) => {
            nexthop_uni_resolve(uni, nmap);
            entry.valid = uni.valid;
            entry.metric = uni.metric;
        }
        Nexthop::Multi(multi) => {
            for uni in multi.nexthops.iter_mut() {
                nexthop_uni_resolve(uni, nmap);
            }
            for uni in multi.nexthops.iter() {
                if uni.valid {
                    entry.metric = uni.metric;
                    entry.valid = uni.valid;
                    return;
                }
            }
            entry.metric = 0;
            entry.valid = false;
        }
        Nexthop::List(list) => {
            for uni in list.iter_unis_mut() {
                nexthop_uni_resolve(uni, nmap);
            }
            for uni in list.iter_unis() {
                if uni.valid {
                    entry.metric = uni.metric;
                    entry.valid = uni.valid;
                    return;
                }
            }
            entry.metric = 0;
            entry.valid = false;
        }
    }
}

fn resolve_nexthop_uni(
    uni: &mut NexthopUni,
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv4Net, RibEntries>,
) -> bool {
    let Some(Group::Uni(group)) = nmap.fetch(uni) else {
        return false;
    };
    if group.refcnt() == 0 {
        group.resolve(table);
    }
    group.refcnt_inc();

    uni.gid = group.gid();
    // Origin came from the caller, must not be overwritten;
    // resolution may have populated `ifindex_resolved`.
    uni.ifindex_origin = group.ifindex_origin;
    uni.ifindex_resolved = group.ifindex_resolved;

    group.is_valid()
}

fn resolve_nexthop_multi(
    multi: &mut NexthopMulti,
    nmap: &mut NexthopMap,
    valid: BTreeSet<(usize, u8)>,
) {
    // Create set with gid:u32 and weight:u8.
    let mut set: BTreeSet<(usize, u8)> = BTreeSet::new();

    for nhop in multi.nexthops.iter() {
        set.insert((nhop.gid, nhop.weight));
    }

    let Some(Group::Multi(group)) = nmap.fetch_multi(&set) else {
        return;
    };

    group.set_valid(!valid.is_empty());
    group.valid = valid;

    // Reference counter increment.
    group.refcnt_inc();

    // Set the nexthop group id to the nexthop.
    multi.gid = group.gid();
}

// Function is called when rib is added.
fn rib_resolve_nexthop(
    entry: &mut RibEntry,
    table: &PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
) {
    // Only protocol entry.
    if !entry.is_protocol() {
        return;
    }
    if let Nexthop::Uni(uni) = &mut entry.nexthop {
        let _ = resolve_nexthop_uni(uni, nmap, table);
    }
    if let Nexthop::Multi(multi) = &mut entry.nexthop {
        let mut set = BTreeSet::<(usize, u8)>::new();
        for uni in multi.nexthops.iter_mut() {
            let valid = resolve_nexthop_uni(uni, nmap, table);
            if valid {
                set.insert((uni.gid, uni.weight));
            }
        }
        resolve_nexthop_multi(multi, nmap, set);
    }
    if let Nexthop::List(pro) = &mut entry.nexthop {
        // Walk members explicitly (not via `iter_unis_mut`) so each
        // `NexthopMember::Multi` gets a kernel-side group allocated
        // via `resolve_nexthop_multi` — the iter-unis version
        // flattens the structure and leaves the Multi wrapper's
        // `gid` at 0, which makes the FIB install fail with ENODEV
        // (Nhid(0)) at RTM_NEWROUTE time.
        for member in pro.nexthops.iter_mut() {
            match member {
                NexthopMember::Uni(uni) => {
                    let _ = resolve_nexthop_uni(uni, nmap, table);
                }
                NexthopMember::Multi(multi) => {
                    let mut set = BTreeSet::<(usize, u8)>::new();
                    for uni in multi.nexthops.iter_mut() {
                        let valid = resolve_nexthop_uni(uni, nmap, table);
                        if valid {
                            set.insert((uni.gid, uni.weight));
                        }
                    }
                    resolve_nexthop_multi(multi, nmap, set);
                }
            }
        }
    }
    // If one of nexthop is valid, the entry is valid.
    entry.set_valid(entry.is_valid_nexthop(nmap));
}

fn rib_rtype(entries: &[RibEntry], rtype: RibType) -> Option<usize> {
    entries.iter().position(|e| e.rtype == rtype)
}

fn rib_rtype_ifindex(entries: &[RibEntry], rtype: RibType, ifindex: u32) -> Option<usize> {
    entries
        .iter()
        .position(|e| e.rtype == rtype && e.ifindex == ifindex)
}

fn rib_add(table: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, entry: RibEntry) {
    let entries = table.entry(*prefix).or_default();
    entries.push(entry);
}

fn rib_add_system(table: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, entry: RibEntry) {
    let entries = table.entry(*prefix).or_default();
    let index = if entry.is_connected() {
        // For connected routes, check both type and interface index
        rib_rtype_ifindex(entries, entry.rtype, entry.ifindex)
    } else {
        rib_rtype(entries, entry.rtype)
    };
    match index {
        None => {
            entries.push(entry);
        }
        Some(index) => {
            let e = entries.get_mut(index).unwrap();
            let nhop = match &mut e.nexthop {
                Nexthop::Uni(uni) => {
                    let Nexthop::Uni(euni) = entry.nexthop else {
                        return;
                    };
                    if uni.metric == euni.metric {
                        Nexthop::Uni(euni)
                    } else {
                        let mut pro = NexthopList::default();
                        pro.nexthops.push(NexthopMember::Uni(uni.clone()));
                        pro.nexthops.push(NexthopMember::Uni(euni));
                        pro.nexthops.sort_by_key(|m| m.metric());
                        e.metric = pro.metric();
                        Nexthop::List(pro)
                    }
                }
                Nexthop::List(list) => {
                    // Current One.
                    let mut btree = BTreeMap::new();

                    for member in list.nexthops.iter() {
                        btree.insert(member.metric(), member.clone());
                    }

                    let Nexthop::Uni(uni) = entry.nexthop else {
                        return;
                    };

                    btree.insert(uni.metric, NexthopMember::Uni(uni));

                    let vec: Vec<_> = btree.values().cloned().collect();
                    let list = NexthopList { nexthops: vec };

                    Nexthop::List(list)
                }
                _ => {
                    return;
                }
            };
            e.nexthop = nhop;
        }
    }
}

fn rib_replace_system(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    entry: RibEntry,
) -> Vec<RibEntry> {
    // println!("rib_replace_system {}", prefix);
    let entries = table.entry(*prefix).or_default();
    let index = rib_rtype(entries, entry.rtype);
    let Some(index) = index else {
        return vec![];
    };
    // println!("index {}", index);
    let e = entries.get_mut(index).unwrap();
    let replace = match &mut e.nexthop {
        Nexthop::Uni(uni) => uni.metric == entry.metric,
        Nexthop::Multi(multi) => multi.metric == entry.metric,
        Nexthop::List(list) => {
            list.nexthops.retain(|m| m.metric() != entry.metric);
            if list.nexthops.len() == 1 {
                let member = list.nexthops.pop().unwrap();
                e.metric = member.metric();
                e.nexthop = match member {
                    NexthopMember::Uni(u) => Nexthop::Uni(u),
                    NexthopMember::Multi(m) => Nexthop::Multi(m),
                };
            }
            false
        }
        Nexthop::Link(_ifindex) => {
            // For connected routes, only replace if the interface index matches
            e.ifindex == entry.ifindex
        }
    };
    // println!("replace {}", replace);
    if replace {
        return rib_replace(table, prefix, entry.rtype);
    }
    vec![]
}

fn rib_replace(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    rtype: RibType,
) -> Vec<RibEntry> {
    let Some(entries) = table.get_mut(prefix) else {
        return vec![];
    };
    let (remain, replace): (Vec<_>, Vec<_>) = entries.drain(..).partition(|x| x.rtype != rtype);
    *entries = remain;
    replace
}

fn rib_prev(ribs: &RibEntries) -> Option<usize> {
    ribs.iter().position(|e| e.is_selected())
}

/// Snapshot of the currently-selected entry at `prefix`. Used by the
/// redistribute steady-state delta hook to compare before/after a
/// mutation in `ipv{4,6}_route_{add,del}`.
fn selected_v4<'a>(
    table: &'a PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
) -> Option<&'a RibEntry> {
    table.get(prefix)?.iter().find(|e| e.is_selected())
}

fn selected_v6<'a>(
    table: &'a PrefixMap<Ipv6Net, RibEntries>,
    prefix: &Ipv6Net,
) -> Option<&'a RibEntry> {
    table.get(prefix)?.iter().find(|e| e.is_selected())
}

fn rib_next(ribs: &RibEntries) -> Option<usize> {
    ribs.iter()
        .enumerate()
        .filter(|(_, e)| e.is_valid())
        .min_by(|(_, a), (_, b)| {
            a.distance
                .cmp(&b.distance)
                .then(a.metric.cmp(&b.metric))
                .then(a.rtype.u8().cmp(&b.rtype.u8()))
        })
        .map(|(i, _)| i)
}

// IPv6 helper functions

async fn ipv6_entry_selection(
    prefix: &Ipv6Net,
    entries: &mut RibEntries,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
) {
    if DEBUG_V6 {
        println!(
            "[ipv6_entry_selection] prefix={} entries={} replace={}",
            prefix,
            entries.len(),
            replace.is_some(),
        );
        for (i, e) in entries.iter().enumerate() {
            println!(
                "  entry[{}] rtype={:?} valid={} selected={} fib={} distance={} metric={}",
                i, e.rtype, e.valid, e.selected, e.fib, e.distance, e.metric
            );
        }
    }

    if let Some(mut replace) = replace
        && replace.is_protocol()
    {
        if replace.is_fib() {
            fib.route_ipv6_del(prefix, &replace, table_id).await;
        }
        replace.nexthop_unsync(nmap, fib).await;
    }

    // Link-local prefixes (fe80::/10) are link-scoped: every interface
    // legitimately holds the same fe80::/64, and best-route selection would
    // arbitrarily flag only one. Mark every valid entry as selected+FIB.
    if prefix.addr().is_unicast_link_local() {
        for entry in entries.iter_mut() {
            let on = entry.is_valid();
            entry.set_selected(on);
            entry.set_fib(on);
        }
        return;
    }

    // Selected.
    let prev = rib_prev(entries);

    // New select.
    let next = rib_next(entries);

    if DEBUG_V6 {
        println!("[ipv6_entry_selection] prev={:?} next={:?}", prev, next);
    }

    if prev == next {
        return;
    }
    if let Some(prev) = prev {
        let prev = entries.get_mut(prev).unwrap();
        prev.set_selected(false);

        fib.route_ipv6_del(prefix, prev, table_id).await;
        prev.set_fib(false);
    }
    if let Some(next) = next {
        let next = entries.get_mut(next).unwrap();
        next.set_selected(true);

        if next.is_protocol() {
            next.nexthop_sync(nmap, fib).await;
            fib.route_ipv6_add(prefix, next, table_id).await;
        }
        next.set_fib(true);
    }
}

fn rib_add_v6(table: &mut PrefixMap<Ipv6Net, RibEntries>, prefix: &Ipv6Net, entry: RibEntry) {
    let entries = table.entry(*prefix).or_default();
    entries.push(entry);
}

fn rib_add_system_v6(
    table: &mut PrefixMap<Ipv6Net, RibEntries>,
    prefix: &Ipv6Net,
    entry: RibEntry,
) {
    let entries = table.entry(*prefix).or_default();
    let index = if entry.is_connected() {
        // For connected routes, check both type and interface index
        rib_rtype_ifindex(entries, entry.rtype, entry.ifindex)
    } else {
        rib_rtype(entries, entry.rtype)
    };
    match index {
        None => {
            entries.push(entry);
        }
        Some(index) => {
            let e = entries.get_mut(index).unwrap();
            let nhop = match &mut e.nexthop {
                Nexthop::Uni(uni) => {
                    let Nexthop::Uni(euni) = entry.nexthop else {
                        return;
                    };
                    if uni.metric == euni.metric {
                        Nexthop::Uni(euni)
                    } else {
                        let mut pro = NexthopList::default();
                        pro.nexthops.push(NexthopMember::Uni(uni.clone()));
                        pro.nexthops.push(NexthopMember::Uni(euni));
                        pro.nexthops.sort_by_key(|m| m.metric());
                        e.metric = pro.metric();
                        Nexthop::List(pro)
                    }
                }
                Nexthop::List(list) => {
                    // Current One.
                    let mut btree = BTreeMap::new();

                    for member in list.nexthops.iter() {
                        btree.insert(member.metric(), member.clone());
                    }

                    let Nexthop::Uni(uni) = entry.nexthop else {
                        return;
                    };

                    btree.insert(uni.metric, NexthopMember::Uni(uni));

                    let vec: Vec<_> = btree.values().cloned().collect();
                    let list = NexthopList { nexthops: vec };

                    Nexthop::List(list)
                }
                _ => {
                    return;
                }
            };
            e.nexthop = nhop;
        }
    }
}

fn rib_replace_system_v6(
    table: &mut PrefixMap<Ipv6Net, RibEntries>,
    prefix: &Ipv6Net,
    entry: RibEntry,
) -> Vec<RibEntry> {
    let entries = table.entry(*prefix).or_default();
    let index = rib_rtype(entries, entry.rtype);
    let Some(index) = index else {
        return vec![];
    };
    let e = entries.get_mut(index).unwrap();
    let replace = match &mut e.nexthop {
        Nexthop::Uni(uni) => uni.metric == entry.metric,
        Nexthop::Multi(multi) => multi.metric == entry.metric,
        Nexthop::List(list) => {
            list.nexthops.retain(|m| m.metric() != entry.metric);
            if list.nexthops.len() == 1 {
                let member = list.nexthops.pop().unwrap();
                e.metric = member.metric();
                e.nexthop = match member {
                    NexthopMember::Uni(u) => Nexthop::Uni(u),
                    NexthopMember::Multi(m) => Nexthop::Multi(m),
                };
            }
            false
        }
        Nexthop::Link(_ifindex) => {
            // For connected routes, only replace if the interface index matches
            e.ifindex == entry.ifindex
        }
    };
    if replace {
        return rib_replace_v6(table, prefix, entry.rtype);
    }
    vec![]
}

fn rib_replace_v6(
    table: &mut PrefixMap<Ipv6Net, RibEntries>,
    prefix: &Ipv6Net,
    rtype: RibType,
) -> Vec<RibEntry> {
    let Some(entries) = table.get_mut(prefix) else {
        return vec![];
    };
    let (remain, replace): (Vec<_>, Vec<_>) = entries.drain(..).partition(|x| x.rtype != rtype);
    *entries = remain;
    replace
}

pub async fn ipv6_route_sync(
    table: &mut PrefixMap<Ipv6Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
) {
    for (p, entries) in table.iter_mut() {
        ipv6_entry_resolve(entries, nmap);
        ipv6_entry_selection(p, entries, None, nmap, fib, table_id).await;
    }
}

fn ipv6_entry_resolve(entries: &mut RibEntries, nmap: &NexthopMap) {
    for entry in entries.iter_mut() {
        if entry.is_protocol() {
            entry_resolve(entry, nmap, false);
        }
    }
}

// Function is called when IPv6 rib is added.
fn rib_resolve_nexthop_v6(
    entry: &mut RibEntry,
    table: &PrefixMap<Ipv6Net, RibEntries>,
    nmap: &mut NexthopMap,
) {
    // Only protocol entry.
    if !entry.is_protocol() {
        return;
    }
    if let Nexthop::Uni(uni) = &mut entry.nexthop {
        let _ = resolve_nexthop_uni_v6(uni, nmap, table);
    }
    if let Nexthop::Multi(multi) = &mut entry.nexthop {
        let mut set = BTreeSet::<(usize, u8)>::new();
        for uni in multi.nexthops.iter_mut() {
            let valid = resolve_nexthop_uni_v6(uni, nmap, table);
            if valid {
                set.insert((uni.gid, uni.weight));
            }
        }
        resolve_nexthop_multi(multi, nmap, set);
    }
    if let Nexthop::List(pro) = &mut entry.nexthop {
        // Mirror of the v4 fix: walk members explicitly so each
        // `NexthopMember::Multi` gets a kernel-side group allocated
        // (without this, the Multi wrapper's `gid` stays at 0 and
        // the FIB install fails with ENODEV at Nhid(0)).
        for member in pro.nexthops.iter_mut() {
            match member {
                NexthopMember::Uni(uni) => {
                    let _ = resolve_nexthop_uni_v6(uni, nmap, table);
                }
                NexthopMember::Multi(multi) => {
                    let mut set = BTreeSet::<(usize, u8)>::new();
                    for uni in multi.nexthops.iter_mut() {
                        let valid = resolve_nexthop_uni_v6(uni, nmap, table);
                        if valid {
                            set.insert((uni.gid, uni.weight));
                        }
                    }
                    resolve_nexthop_multi(multi, nmap, set);
                }
            }
        }
    }
    // If one of nexthop is valid, the entry is valid.
    entry.set_valid(entry.is_valid_nexthop(nmap));
}

fn resolve_nexthop_uni_v6(
    uni: &mut NexthopUni,
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv6Net, RibEntries>,
) -> bool {
    if DEBUG_V6 {
        println!(
            "[resolve_nexthop_uni_v6] addr={} gid_before={}",
            uni.addr, uni.gid
        );
    }
    let Some(Group::Uni(group)) = nmap.fetch(uni) else {
        if DEBUG_V6 {
            println!("[resolve_nexthop_uni_v6] nmap.fetch returned None");
        }
        return false;
    };
    if DEBUG_V6 {
        println!(
            "[resolve_nexthop_uni_v6] fetched group gid={} refcnt={} valid={} ifindex={:?}",
            group.gid(),
            group.refcnt(),
            group.is_valid(),
            group.ifindex(),
        );
    }
    if group.refcnt() == 0 {
        group.resolve_v6(table);
        if DEBUG_V6 {
            println!(
                "[resolve_nexthop_uni_v6] after resolve_v6 valid={} ifindex={:?}",
                group.is_valid(),
                group.ifindex(),
            );
        }
    }
    group.refcnt_inc();

    uni.gid = group.gid();
    // Both halves flow through unchanged. The caller's origin (if
    // any) was preserved across `fetch` and `resolve_v6`; those
    // routines may have written `ifindex_resolved`.
    uni.ifindex_origin = group.ifindex_origin;
    uni.ifindex_resolved = group.ifindex_resolved;

    let valid = group.is_valid();
    if DEBUG_V6 {
        println!(
            "[resolve_nexthop_uni_v6] returning uni.gid={} uni.ifindex={:?} valid={}",
            uni.gid,
            uni.ifindex(),
            valid
        );
    }
    valid
}

pub async fn ipv6_nexthop_sync(
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv6Net, RibEntries>,
    links: &BTreeMap<u32, Link>,
    fib: &FibHandle,
) {
    if DEBUG_V6 {
        println!("[ipv6_nexthop_sync] start; v6 table size={}", table.len());
    }
    for nhop in nmap.groups.iter_mut().flatten() {
        if let Group::Uni(uni) = nhop {
            if DEBUG_V6 {
                println!(
                    "[ipv6_nexthop_sync] visiting uni gid={} addr={} ifindex={:?} valid={} installed={}",
                    uni.gid(),
                    uni.addr,
                    uni.ifindex(),
                    uni.is_valid(),
                    uni.is_installed(),
                );
            }
            // Origin wins — skip the table walk entirely when the
            // caller pinned the egress link, but only if that link
            // is still up. When it isn't, the kernel removed the
            // route on link-down; mark the group invalid so the
            // route_sync pass deselects and drops the FIB entry.
            if let Some(ifindex) = uni.ifindex_origin {
                let link_up = links
                    .get(&ifindex)
                    .is_some_and(|l| l.flags.is_up() && l.flags.is_lower_up());
                if link_up {
                    uni.set_valid(true);
                    if !uni.is_installed() {
                        uni.set_installed(true);
                        fib.nexthop_add(&Group::Uni(uni.clone())).await;
                    }
                } else {
                    uni.set_valid(false);
                    uni.set_installed(false);
                }
                continue;
            }
            let resolve = match uni.addr {
                std::net::IpAddr::V4(_) => continue,
                std::net::IpAddr::V6(ipv6_addr) => {
                    rib_resolve_v6(table, ipv6_addr, &ResolveOpt::default())
                }
            };

            let ifindex = resolve.is_valid();
            if DEBUG_V6 {
                println!(
                    "[ipv6_nexthop_sync] resolved ifindex={} (0 means unresolved)",
                    ifindex
                );
            }
            if ifindex == 0 {
                uni.ifindex_resolved = None;
                uni.set_valid(false);
                if uni.is_installed() {
                    uni.set_installed(false);
                }
            } else {
                uni.ifindex_resolved = Some(ifindex);
                uni.set_valid(true);
                if !uni.is_installed() {
                    uni.set_installed(true);
                    fib.nexthop_add(&Group::Uni(uni.clone())).await;
                }
            }
        }
    }
    if DEBUG_V6 {
        println!("[ipv6_nexthop_sync] done");
    }
}

// ---- Per-VRF table dispatch helpers ---------------------------------
//
// Step 9 prefers free functions over methods on `Rib` so they can be
// unit-tested against a plain `BTreeMap<u32, VrfRibTables>` without
// having to construct a full `Rib` (which needs a live netlink
// socket via `FibHandle::new`). Return `bool` so the wrappers on
// `Rib` can log a `warn!` if the caller's VRF table id is not yet
// in the map (a kernel `VrfAdd` parks an empty `VrfRibTables` for
// every allocated VRF, so this should only fire for a torn-down or
// never-created VRF).

use super::vrf::VrfRibTables;

pub(super) fn vrf_ipv4_insert(
    vrf_tables: &mut BTreeMap<u32, VrfRibTables>,
    table_id: u32,
    prefix: &Ipv4Net,
    entry: RibEntry,
) -> bool {
    let Some(t) = vrf_tables.get_mut(&table_id) else {
        return false;
    };
    let entries = t.table.entry(*prefix).or_default();
    entries.push(entry);
    true
}

pub(super) fn vrf_ipv4_remove(
    vrf_tables: &mut BTreeMap<u32, VrfRibTables>,
    table_id: u32,
    prefix: &Ipv4Net,
    rtype: RibType,
) {
    let Some(t) = vrf_tables.get_mut(&table_id) else {
        return;
    };
    if let Some(entries) = t.table.get_mut(prefix) {
        if let Some(pos) = entries.iter().position(|e| e.rtype == rtype) {
            entries.remove(pos);
        }
        if entries.is_empty() {
            t.table.remove(prefix);
        }
    }
}

pub(super) fn vrf_ipv6_insert(
    vrf_tables: &mut BTreeMap<u32, VrfRibTables>,
    table_id: u32,
    prefix: &Ipv6Net,
    entry: RibEntry,
) -> bool {
    let Some(t) = vrf_tables.get_mut(&table_id) else {
        return false;
    };
    let entries = t.table_v6.entry(*prefix).or_default();
    entries.push(entry);
    true
}

pub(super) fn vrf_ipv6_remove(
    vrf_tables: &mut BTreeMap<u32, VrfRibTables>,
    table_id: u32,
    prefix: &Ipv6Net,
    rtype: RibType,
) {
    let Some(t) = vrf_tables.get_mut(&table_id) else {
        return;
    };
    if let Some(entries) = t.table_v6.get_mut(prefix) {
        if let Some(pos) = entries.iter().position(|e| e.rtype == rtype) {
            entries.remove(pos);
        }
        if entries.is_empty() {
            t.table_v6.remove(prefix);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddrRecoveryState, RECOVERY_BURST_THRESHOLD, RECOVERY_COOLDOWN, RECOVERY_WINDOW,
        RecoveryDecision, SuppressReason, addr_recover_decide,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn first_delete_recovers() {
        let mut state = AddrRecoveryState::default();
        let t0 = Instant::now();
        assert_eq!(
            addr_recover_decide(&mut state, t0),
            RecoveryDecision::Recover
        );
        assert_eq!(state.history.len(), 1);
        assert!(state.suppressed_until.is_none());
    }

    #[test]
    fn third_delete_within_window_suppresses() {
        let mut state = AddrRecoveryState::default();
        let t0 = Instant::now();

        assert_eq!(
            addr_recover_decide(&mut state, t0),
            RecoveryDecision::Recover
        );
        assert_eq!(
            addr_recover_decide(&mut state, t0 + Duration::from_secs(20)),
            RecoveryDecision::Recover
        );
        // Third delete inside the 60s window — trips the cool-down.
        assert_eq!(
            addr_recover_decide(&mut state, t0 + Duration::from_secs(40)),
            RecoveryDecision::Suppress(SuppressReason::JustTripped)
        );
        assert!(state.suppressed_until.is_some());
        assert_eq!(state.history.len(), RECOVERY_BURST_THRESHOLD);
    }

    #[test]
    fn during_cooldown_keeps_suppressing() {
        let mut state = AddrRecoveryState::default();
        let t0 = Instant::now();

        // Trip the cool-down.
        addr_recover_decide(&mut state, t0);
        addr_recover_decide(&mut state, t0 + Duration::from_secs(10));
        addr_recover_decide(&mut state, t0 + Duration::from_secs(20));

        // Mid cool-down — still suppressed.
        assert_eq!(
            addr_recover_decide(&mut state, t0 + Duration::from_secs(60)),
            RecoveryDecision::Suppress(SuppressReason::AlreadySuppressed)
        );
        assert_eq!(
            addr_recover_decide(&mut state, t0 + Duration::from_secs(300)),
            RecoveryDecision::Suppress(SuppressReason::AlreadySuppressed)
        );
    }

    #[test]
    fn cooldown_expires_and_recovery_resumes() {
        let mut state = AddrRecoveryState::default();
        let t0 = Instant::now();

        addr_recover_decide(&mut state, t0);
        addr_recover_decide(&mut state, t0 + Duration::from_secs(10));
        addr_recover_decide(&mut state, t0 + Duration::from_secs(20));
        assert!(state.suppressed_until.is_some());

        // After cool-down (10 min plus a margin) — fresh start.
        let after_cooldown =
            t0 + Duration::from_secs(20) + RECOVERY_COOLDOWN + Duration::from_secs(1);
        assert_eq!(
            addr_recover_decide(&mut state, after_cooldown),
            RecoveryDecision::Recover
        );
        assert!(state.suppressed_until.is_none());
        assert_eq!(state.history.len(), 1);
    }

    #[test]
    fn old_events_outside_window_dont_count() {
        let mut state = AddrRecoveryState::default();
        let t0 = Instant::now();

        // Two deletes both more than RECOVERY_WINDOW before the third
        // call's "now"; pruning should evict them so the third call
        // is treated as a fresh first event.
        addr_recover_decide(&mut state, t0);
        addr_recover_decide(&mut state, t0 + Duration::from_secs(10));
        let after = t0 + RECOVERY_WINDOW + Duration::from_secs(11);
        assert_eq!(
            addr_recover_decide(&mut state, after),
            RecoveryDecision::Recover
        );
        assert_eq!(state.history.len(), 1);
    }

    /// Regression: `Nexthop::List { Multi(...), Uni(backup) }` must
    /// allocate a kernel-side group for the nested Multi via
    /// `resolve_nexthop_multi`. Before the fix, only the Multi's
    /// leg Unis were resolved (via `iter_unis_mut`) and the Multi
    /// wrapper's `gid` stayed at 0 — the FIB then installed a route
    /// with `Nhid(0)` and the kernel returned ENODEV.
    #[test]
    fn list_with_nested_multi_resolves_multi_gid() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::NexthopUni;
        use super::super::{Nexthop, NexthopList, NexthopMap, NexthopMember, NexthopMulti};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop;
        use ipnet::Ipv4Net;
        use prefix_trie::PrefixMap;

        let leg_a = NexthopUni::new("10.0.0.1".parse().unwrap(), 1011, vec![]);
        let leg_b = NexthopUni::new("10.0.0.2".parse().unwrap(), 1011, vec![]);
        let multi = NexthopMulti {
            metric: 1011,
            nexthops: vec![leg_a, leg_b],
            ..Default::default()
        };
        let backup = NexthopUni::new("10.0.0.3".parse().unwrap(), 1012, vec![]);

        let mut entry = RibEntry::new(RibType::Isis);
        entry.nexthop = Nexthop::List(NexthopList {
            nexthops: vec![NexthopMember::Multi(multi), NexthopMember::Uni(backup)],
        });

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop(&mut entry, &table, &mut nmap);

        let Nexthop::List(pro) = &entry.nexthop else {
            panic!("entry.nexthop should still be List");
        };
        let multi_member = pro
            .nexthops
            .iter()
            .find_map(|m| match m {
                NexthopMember::Multi(m) => Some(m),
                _ => None,
            })
            .expect("multi member preserved");
        assert!(
            multi_member.gid != 0,
            "nested Multi must get a kernel-side group allocated (gid != 0)"
        );
        for leg in &multi_member.nexthops {
            assert!(leg.gid != 0, "each leg also gets a gid");
        }
    }

    /// Step 9 inbound-dispatch invariant: an install destined for
    /// a non-default VRF lands in `vrf_tables[table_id].table`, not
    /// in the global table. Tested at the free-function level so we
    /// don't need to construct a `Rib` (the kernel-bound `FibHandle`
    /// makes that impractical for unit tests).
    #[test]
    fn vrf_ipv4_insert_lands_in_matching_table() {
        use super::super::entry::RibEntry;
        use super::super::vrf::VrfRibTables;
        use super::super::{RibEntries, RibType};
        use super::vrf_ipv4_insert;
        use ipnet::Ipv4Net;
        use std::collections::BTreeMap;

        let mut vrf_tables: BTreeMap<u32, VrfRibTables> = BTreeMap::new();
        vrf_tables.insert(10, VrfRibTables::new());

        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let entry = RibEntry::new(RibType::Bgp);
        assert!(vrf_ipv4_insert(&mut vrf_tables, 10, &prefix, entry));

        // Lands in table 10 only.
        let t10: &RibEntries = vrf_tables
            .get(&10)
            .and_then(|t| t.table.get(&prefix))
            .expect("prefix in vrf table 10");
        assert_eq!(t10.len(), 1);
        assert_eq!(t10[0].rtype, RibType::Bgp);
    }

    #[test]
    fn vrf_ipv4_insert_into_missing_table_is_noop() {
        use super::super::RibType;
        use super::super::entry::RibEntry;
        use super::super::vrf::VrfRibTables;
        use super::vrf_ipv4_insert;
        use ipnet::Ipv4Net;
        use std::collections::BTreeMap;

        // No VRF row for `table_id = 99` — caller has to tolerate
        // it (the warn-log path in `Rib::ipv4_route_add_vrf` covers
        // the operator-visible side).
        let mut vrf_tables: BTreeMap<u32, VrfRibTables> = BTreeMap::new();
        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let inserted = vrf_ipv4_insert(&mut vrf_tables, 99, &prefix, RibEntry::new(RibType::Bgp));
        assert!(!inserted);
        assert!(vrf_tables.is_empty());
    }

    #[test]
    fn vrf_ipv4_remove_drops_prefix_when_last_entry_goes() {
        use super::super::RibType;
        use super::super::entry::RibEntry;
        use super::super::vrf::VrfRibTables;
        use super::{vrf_ipv4_insert, vrf_ipv4_remove};
        use ipnet::Ipv4Net;
        use std::collections::BTreeMap;

        let mut vrf_tables: BTreeMap<u32, VrfRibTables> = BTreeMap::new();
        vrf_tables.insert(10, VrfRibTables::new());

        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        vrf_ipv4_insert(&mut vrf_tables, 10, &prefix, RibEntry::new(RibType::Bgp));
        vrf_ipv4_remove(&mut vrf_tables, 10, &prefix, RibType::Bgp);
        assert!(vrf_tables.get(&10).unwrap().table.get(&prefix).is_none());
    }

    #[test]
    fn vrf_ipv6_insert_and_remove_round_trip() {
        use super::super::RibType;
        use super::super::entry::RibEntry;
        use super::super::vrf::VrfRibTables;
        use super::{vrf_ipv6_insert, vrf_ipv6_remove};
        use ipnet::Ipv6Net;
        use std::collections::BTreeMap;

        let mut vrf_tables: BTreeMap<u32, VrfRibTables> = BTreeMap::new();
        vrf_tables.insert(10, VrfRibTables::new());

        let prefix: Ipv6Net = "2001:db8::/64".parse().unwrap();
        assert!(vrf_ipv6_insert(
            &mut vrf_tables,
            10,
            &prefix,
            RibEntry::new(RibType::Bgp),
        ));
        assert!(vrf_tables.get(&10).unwrap().table_v6.get(&prefix).is_some());
        vrf_ipv6_remove(&mut vrf_tables, 10, &prefix, RibType::Bgp);
        assert!(vrf_tables.get(&10).unwrap().table_v6.get(&prefix).is_none());
    }
}
