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
use super::tracing::{rib_interface, rib_nexthop, rib_route};
use super::{
    Group, GroupTrait, Message, NexthopList, NexthopMap, NexthopMember, NexthopMulti,
    NexthopProtect, ProtectActive, RibEntries, RibType,
};
use std::net::IpAddr;

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
                if rib_interface() {
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
                if rib_interface() {
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
    /// kernel — unless the per-address recovery state is in
    /// hold-down cool-down.
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
                if rib_interface() {
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
        ipv4_nexthop_sync(
            &mut self.nmap,
            &self.table,
            &self.vrf_tables,
            &self.links,
            &self.fib_handle,
        )
        .await;
        self.ipv4_default_sync(true).await;
        ipv6_nexthop_sync(
            &mut self.nmap,
            &self.table_v6,
            &self.vrf_tables,
            &self.links,
            &self.fib_handle,
        )
        .await;
        self.ipv6_default_sync().await;
        // A PE-CE link going down may leave a protected egress VRF unable
        // to deliver — redirect its End.DT46 service SID to the Mirror SID.
        self.reconcile_egress_redirects().await;
        self.schedule_rib_sync();
    }

    pub async fn link_up(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            if rib_interface() {
                tracing::info!(
                    "link_up: ifindex {} not found in link table; skipping connected route recovery",
                    ifindex
                );
            }
            return;
        };
        let link_name = link.name.clone();

        if rib_interface() {
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

                if rib_interface() {
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

                if rib_interface() {
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

        ipv4_nexthop_sync(
            &mut self.nmap,
            &self.table,
            &self.vrf_tables,
            &self.links,
            &self.fib_handle,
        )
        .await;
        self.ipv4_default_sync(true).await;
        ipv6_nexthop_sync(
            &mut self.nmap,
            &self.table_v6,
            &self.vrf_tables,
            &self.links,
            &self.fib_handle,
        )
        .await;
        self.ipv6_default_sync().await;
        // A recovered PE-CE link can deliver again — restore any protected
        // End.DT46 service SID from its Mirror SID redirect form.
        self.reconcile_egress_redirects().await;
        // Mirror link_down: schedule a deferred Resolve so recursive
        // groups (e.g. a static whose first segment was unreachable
        // while the link was down) re-evaluate now that the IS-IS
        // routes are back and selectable.
        self.schedule_rib_sync();
    }

    /// Per-VRF dispatcher: install an `Ipv4Add` into the VRF's routing
    /// table with best-path selection and FIB install. Nexthops resolve
    /// against the VRF's own table (a CE gateway is reachable via the
    /// VRF's connected routes), and the selected protocol route is
    /// programmed into the kernel VRF table (`table_id`). Connected
    /// routes are already in the kernel (created on enslave), so
    /// selection marks them installed without re-programming — see
    /// `ipv4_entry_selection`'s non-protocol arm.
    pub async fn ipv4_route_add_vrf(
        &mut self,
        table_id: u32,
        prefix: &Ipv4Net,
        mut entry: RibEntry,
    ) {
        let replace = {
            let Some(t) = self.vrf_tables.get_mut(&table_id) else {
                tracing::warn!(
                    table_id,
                    %prefix,
                    "ipv4_route_add_vrf: vrf table not present; dropping install",
                );
                return;
            };
            if entry.is_protocol() {
                let mut replace = rib_replace(&mut t.table, prefix, entry.rtype);
                rib_resolve_nexthop(&mut entry, &t.table, &mut self.nmap, table_id);
                rib_add(&mut t.table, prefix, entry);
                replace.pop()
            } else {
                rib_add_system(&mut t.table, prefix, entry);
                None
            }
        };
        self.vrf_rib_selection(table_id, prefix, replace).await;
    }

    pub async fn ipv4_route_del_vrf(&mut self, table_id: u32, prefix: &Ipv4Net, entry: RibEntry) {
        let replace = {
            let Some(t) = self.vrf_tables.get_mut(&table_id) else {
                return;
            };
            if entry.is_protocol() {
                rib_replace(&mut t.table, prefix, entry.rtype).pop()
            } else {
                rib_replace_system(&mut t.table, prefix, entry).pop()
            }
        };
        self.vrf_rib_selection(table_id, prefix, replace).await;
    }

    pub async fn ipv6_route_add_vrf(
        &mut self,
        table_id: u32,
        prefix: &Ipv6Net,
        mut entry: RibEntry,
    ) {
        let replace = {
            let Some(t) = self.vrf_tables.get_mut(&table_id) else {
                tracing::warn!(
                    table_id,
                    %prefix,
                    "ipv6_route_add_vrf: vrf table not present; dropping install",
                );
                return;
            };
            if entry.is_protocol() {
                let mut replace = rib_replace_v6(&mut t.table_v6, prefix, entry.rtype);
                rib_resolve_nexthop_v6(&mut entry, &t.table_v6, &mut self.nmap, table_id);
                rib_add_v6(&mut t.table_v6, prefix, entry);
                replace.pop()
            } else {
                rib_add_system_v6(&mut t.table_v6, prefix, entry);
                None
            }
        };
        self.vrf_rib_selection_v6(table_id, prefix, replace).await;
    }

    pub async fn ipv6_route_del_vrf(&mut self, table_id: u32, prefix: &Ipv6Net, entry: RibEntry) {
        let replace = {
            let Some(t) = self.vrf_tables.get_mut(&table_id) else {
                return;
            };
            if entry.is_protocol() {
                rib_replace_v6(&mut t.table_v6, prefix, entry.rtype).pop()
            } else {
                rib_replace_system_v6(&mut t.table_v6, prefix, entry).pop()
            }
        };
        self.vrf_rib_selection_v6(table_id, prefix, replace).await;
    }

    /// Best-path selection + FIB reconcile for one VRF prefix. Mirrors
    /// [`Self::rib_selection`] but on `vrf_tables[table_id]`, passing
    /// `table_id` so the install/withdraw targets the kernel VRF table.
    async fn vrf_rib_selection(
        &mut self,
        table_id: u32,
        prefix: &Ipv4Net,
        replace: Option<RibEntry>,
    ) {
        let retry = {
            let Some(t) = self.vrf_tables.get_mut(&table_id) else {
                return;
            };
            // `rib_replace` leaves an empty `Vec` at a drained prefix
            // (it doesn't remove the key), so the selector still runs
            // and processes `replace`'s FIB withdraw.
            let Some(entries) = t.table.get_mut(prefix) else {
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
            .await
        };
        if retry {
            self.schedule_rib_sync();
        }
    }

    async fn vrf_rib_selection_v6(
        &mut self,
        table_id: u32,
        prefix: &Ipv6Net,
        replace: Option<RibEntry>,
    ) {
        let retry = {
            let Some(t) = self.vrf_tables.get_mut(&table_id) else {
                return;
            };
            let Some(entries) = t.table_v6.get_mut(prefix) else {
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
            .await
        };
        if retry {
            self.schedule_rib_sync();
        }
    }

    pub async fn ipv4_route_add(&mut self, prefix: &Ipv4Net, mut entry: RibEntry, table_id: u32) {
        let before = selected_v4(&self.table, prefix).cloned();
        if entry.is_protocol() {
            let mut replace = rib_replace(&mut self.table, prefix, entry.rtype);
            rib_resolve_nexthop(&mut entry, &self.table, &mut self.nmap, table_id);
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
        let prev = self.ilm_installed(label);
        let entries = self.ilm.entry(label).or_default();
        // One candidate per protocol: drop this protocol's previous
        // entry before pushing the new one (mirrors `rib_replace`).
        entries.retain(|e| e.rtype != ilm.rtype);
        entries.push(ilm);
        self.ilm_select_sync(label, prev).await;
    }

    pub async fn ilm_del(&mut self, label: u32, ilm: IlmEntry) {
        let prev = self.ilm_installed(label);
        if let Some(entries) = self.ilm.get_mut(&label) {
            entries.retain(|e| e.rtype != ilm.rtype);
            if entries.is_empty() {
                self.ilm.remove(&label);
            }
        }
        self.ilm_select_sync(label, prev).await;
    }

    /// The candidate currently installed in the kernel LFIB for
    /// `label` (the `selected` one), cloned so it can be handed to the
    /// FIB delete after the in-memory Vec has been mutated.
    fn ilm_installed(&self, label: u32) -> Option<IlmEntry> {
        self.ilm.get(&label)?.iter().find(|e| e.selected).cloned()
    }

    /// Re-run ILM selection for `label` and reconcile the kernel LFIB.
    /// `prev` is the entry installed before the Vec was mutated. The
    /// kernel holds one AF_MPLS route per label, so we delete the old
    /// install (keyed on the label) and add the new winner. Always
    /// del+add when a winner exists so a same-protocol content change
    /// (e.g. OSPF nexthop churn) reaches the kernel.
    async fn ilm_select_sync(&mut self, label: u32, prev: Option<IlmEntry>) {
        let winner = if let Some(entries) = self.ilm.get_mut(&label) {
            let best = ilm_next(entries);
            for (i, e) in entries.iter_mut().enumerate() {
                e.selected = best == Some(i);
            }
            best.map(|i| entries[i].clone())
        } else {
            None
        };

        if let Some(prev) = &prev {
            self.fib_handle.ilm_del(label, prev).await;
        }
        if let Some(win) = &winner {
            self.fib_handle.ilm_add(label, win).await;
        }
    }

    pub async fn make_link_up(&mut self, ifindex: u32) {
        if let Some(_link) = self.links.get(&ifindex) {
            self.fib_handle.link_set_up(ifindex).await;
        }
    }

    pub async fn ipv6_route_add(&mut self, prefix: &Ipv6Net, mut entry: RibEntry, table_id: u32) {
        if rib_route() {
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
            rib_resolve_nexthop_v6(&mut entry, &self.table_v6, &mut self.nmap, table_id);
            if rib_route() {
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

    /// Sync the default IPv4 table, then push any selected-entry
    /// transitions to redistribute subscribers. This is the steady-state
    /// hook that closes the resolve-path gap: selection changes driven by
    /// nexthop resolution / topology churn (link up/down, address add/del,
    /// the debounced resolve) flow to subscribers, not just explicit
    /// route add/del. When no subscriber is registered the plain sync runs
    /// with zero snapshot overhead.
    pub(super) async fn ipv4_default_sync(&mut self, ifdown: bool) -> bool {
        if self.redist_filters.is_empty() {
            return ipv4_route_sync(
                &mut self.table,
                &mut self.nmap,
                &self.fib_handle,
                RT_TABLE_MAIN,
                ifdown,
            )
            .await;
        }
        let (retry, deltas) = ipv4_route_sync_collect(
            &mut self.table,
            &mut self.nmap,
            &self.fib_handle,
            RT_TABLE_MAIN,
            ifdown,
        )
        .await;
        for (prefix, before, after) in deltas {
            super::redist::notify_v4_delta(
                &self.redist_filters,
                &self.client_registry,
                &prefix,
                before.as_ref(),
                after.as_ref(),
            );
        }
        retry
    }

    /// IPv6 sibling of `ipv4_default_sync`.
    pub(super) async fn ipv6_default_sync(&mut self) -> bool {
        if self.redist_filters.is_empty() {
            return ipv6_route_sync(
                &mut self.table_v6,
                &mut self.nmap,
                &self.fib_handle,
                RT_TABLE_MAIN,
            )
            .await;
        }
        let (retry, deltas) = ipv6_route_sync_collect(
            &mut self.table_v6,
            &mut self.nmap,
            &self.fib_handle,
            RT_TABLE_MAIN,
        )
        .await;
        for (prefix, before, after) in deltas {
            super::redist::notify_v6_delta(
                &self.redist_filters,
                &self.client_registry,
                &prefix,
                before.as_ref(),
                after.as_ref(),
            );
        }
        retry
    }

    pub async fn ipv6_route_resolve(&mut self) {
        ipv6_nexthop_sync(
            &mut self.nmap,
            &self.table_v6,
            &self.vrf_tables,
            &self.links,
            &self.fib_handle,
        )
        .await;
        let mut retry = self.ipv6_default_sync().await;
        let table_ids: Vec<u32> = self.vrf_tables.keys().copied().collect();
        for table_id in table_ids {
            if let Some(t) = self.vrf_tables.get_mut(&table_id) {
                retry |=
                    ipv6_route_sync(&mut t.table_v6, &mut self.nmap, &self.fib_handle, table_id)
                        .await;
            }
        }
        if retry {
            self.schedule_rib_sync();
        }
    }

    pub async fn ipv4_route_resolve(&mut self) {
        // One nexthop sync handles every table: each group resolves
        // against the table its `table_id` names (default or a VRF).
        ipv4_nexthop_sync(
            &mut self.nmap,
            &self.table,
            &self.vrf_tables,
            &self.links,
            &self.fib_handle,
        )
        .await;
        // `false` = not an ifdown sweep; this resolve cycle is for FIB-update
        // re-resolution, not link-down recovery.
        let mut retry = self.ipv4_default_sync(false).await;
        // Re-sync each VRF table against its own kernel table id so a
        // VRF route whose nexthop only just became resolvable gets
        // installed.
        let table_ids: Vec<u32> = self.vrf_tables.keys().copied().collect();
        for table_id in table_ids {
            if let Some(t) = self.vrf_tables.get_mut(&table_id) {
                retry |= ipv4_route_sync(
                    &mut t.table,
                    &mut self.nmap,
                    &self.fib_handle,
                    table_id,
                    false,
                )
                .await;
            }
        }
        // A failed install forced a nexthop recreation; arm another
        // pass so the recreated nexthop and the pending route both land.
        if retry {
            self.schedule_rib_sync();
        }
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
        let retry = ipv4_entry_selection(
            prefix,
            entries,
            replace,
            &mut self.nmap,
            &self.fib_handle,
            table_id,
            false,
        )
        .await;
        if retry {
            self.schedule_rib_sync();
        }
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
        let retry = ipv6_entry_selection(
            prefix,
            entries,
            replace,
            &mut self.nmap,
            &self.fib_handle,
            table_id,
        )
        .await;
        if retry {
            self.schedule_rib_sync();
        }
    }
}

pub async fn rib_selection_ipv4(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
) -> bool {
    let Some(entries) = table.get_mut(prefix) else {
        return false;
    };
    ipv4_entry_selection(prefix, entries, replace, nmap, fib, table_id, true).await
}

pub async fn rib_selection_ipv6(
    table: &mut PrefixMap<Ipv6Net, RibEntries>,
    prefix: &Ipv6Net,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
) -> bool {
    let Some(entries) = table.get_mut(prefix) else {
        return false;
    };
    ipv6_entry_selection(prefix, entries, replace, nmap, fib, table_id).await
}

pub async fn ipv4_nexthop_sync(
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv4Net, RibEntries>,
    vrf_tables: &BTreeMap<u32, VrfRibTables>,
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
            let ipv4_addr = match uni.addr {
                std::net::IpAddr::V4(a) => a,
                std::net::IpAddr::V6(_) => {
                    // IPv6 addresses should be handled by ipv6_nexthop_sync
                    continue;
                }
            };
            // Resolve each gateway against the table its VRF names —
            // a VRF nexthop's gateway lives in the VRF's connected
            // routes, not the default table. A missing VRF table
            // (torn down) leaves the nexthop unresolved.
            let resolve_table = if uni.table_id == RT_TABLE_MAIN {
                Some(table)
            } else {
                vrf_tables.get(&uni.table_id).map(|t| &t.table)
            };
            let ifindex = match resolve_table {
                Some(rt) => rib_resolve(rt, ipv4_addr, &ResolveOpt::default()).is_valid(),
                None => 0,
            };
            if ifindex == 0 {
                uni.ifindex_resolved = None;
                uni.set_valid(false);
                // Keep `installed`: the kernel nexthop object still
                // exists. `nexthop_orphan_gc` removes it *after*
                // `ipv4_route_sync` has withdrawn the routes that
                // referenced it — deleting a still-referenced nexthop
                // would cascade-remove those routes out from under the
                // route sync.
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
                    tracing::debug!(
                        "NexthopMulti update gid={} {:?} -> {:?}",
                        multi.gid(),
                        multi.valid,
                        set
                    );
                    multi.valid = set;
                    fib.nexthop_add(&Group::Multi(multi.clone())).await;
                } else {
                    multi.valid = set;
                }
                multi.set_valid(true);
            }
        }
    }

    protect_groups_sync(nmap, fib).await;
}

/// Re-derive each protection indirection group's validity from its
/// primary member and (re)install on the valid transition. Family-
/// agnostic, but called from BOTH the v4 and v6 nexthop syncs: the v4
/// pass runs before v6 Uni groups revalidate, so a v6-primaried
/// protect group synced only there would lag a cycle behind.
async fn protect_groups_sync(nmap: &mut NexthopMap, fib: &FibHandle) {
    let mut cache: Vec<(usize, bool)> = Vec::new();
    for (idx, nhop) in nmap.groups.iter().enumerate() {
        if let Some(Group::Protect(pro)) = nhop {
            // Validity follows whichever member the kernel group
            // holds — after a switchover that's the repair.
            let valid = nmap.get(pro.active_gid()).is_some_and(|g| g.is_valid());
            cache.push((idx, valid));
        }
    }
    for (idx, valid) in cache {
        if let Some(Some(Group::Protect(pro))) = nmap.groups.get_mut(idx) {
            if valid {
                pro.set_valid(true);
                if !pro.is_installed() {
                    fib.nexthop_add(&Group::Protect(pro.clone())).await;
                    pro.set_installed(true);
                }
            } else {
                // The member died (link down) — the kernel flushed it,
                // the emptied group, and the routes referencing it
                // (probe 4 in the design doc); sync our view so the
                // next valid transition re-creates the object.
                pro.set_valid(false);
                pro.set_installed(false);
            }
        }
    }
}

/// Per-prefix selected-entry transition produced by a sync pass:
/// `(prefix, before, after)`. Fed to the redistribute steady-state
/// delta hook so resolution/topology-driven selection changes reach
/// subscribers, not just explicit route add/del.
pub type RedistDeltaV4 = (Ipv4Net, Option<RibEntry>, Option<RibEntry>);
pub type RedistDeltaV6 = (Ipv6Net, Option<RibEntry>, Option<RibEntry>);

pub async fn ipv4_route_sync(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
    ifdown: bool,
) -> bool {
    ipv4_route_sync_inner(table, nmap, fib, table_id, ifdown, false)
        .await
        .0
}

/// Like `ipv4_route_sync` but also returns the per-prefix selected-entry
/// transitions (so the caller can notify redistribute subscribers about
/// resolution/topology-driven selection changes). Only the default
/// table should collect: `notify_v4_delta` delivers to `vrf_id == 0`
/// subscribers, so VRF-table deltas must not flow through it.
pub async fn ipv4_route_sync_collect(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
    ifdown: bool,
) -> (bool, Vec<RedistDeltaV4>) {
    ipv4_route_sync_inner(table, nmap, fib, table_id, ifdown, true).await
}

async fn ipv4_route_sync_inner(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
    ifdown: bool,
    collect: bool,
) -> (bool, Vec<RedistDeltaV4>) {
    // Collect prefixes first so we don't hold the !Send `IterMut`
    // across the `ipv4_entry_selection` await.
    let prefixes: Vec<Ipv4Net> = table.iter().map(|(p, _)| p).collect();
    let mut retry = false;
    let mut deltas: Vec<RedistDeltaV4> = Vec::new();
    for p in prefixes {
        let Some(entries) = table.get_mut(&p) else {
            continue;
        };
        let before = collect
            .then(|| entries.iter().find(|e| e.is_selected()).cloned())
            .flatten();
        ipv4_entry_resolve(entries, nmap, ifdown);
        retry |= ipv4_entry_selection(&p, entries, None, nmap, fib, table_id, ifdown).await;
        if collect {
            let after = entries.iter().find(|e| e.is_selected()).cloned();
            if super::redist::selected_changed_v4(&p, before.as_ref(), after.as_ref()) {
                deltas.push((p, before, after));
            }
        }
    }
    (retry, deltas)
}

fn ipv4_entry_resolve(entries: &mut RibEntries, nmap: &NexthopMap, ifdown: bool) {
    for entry in entries.iter_mut() {
        if entry.is_protocol() {
            entry_resolve(entry, nmap, ifdown);
        }
    }
}

/// Returns `true` when a route install came back from the kernel as a
/// failure and we forced a nexthop recreation — the caller should
/// schedule another resolve pass so the recreated nexthop and the
/// pending route both land.
async fn ipv4_entry_selection(
    prefix: &Ipv4Net,
    entries: &mut RibEntries,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
    ifdown: bool,
) -> bool {
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
    let next = rib_next(entries);

    if prev == next {
        // No selection change. The selected route may still be missing
        // from the FIB — the kernel drops routes (and their nexthops)
        // on link down without an RTM_DELROUTE, leaving it selected but
        // `fib == false`. Re-add it once its nexthop is resolvable.
        // Skip during an ifdown sweep (the route is on its way out).
        if !ifdown && let Some(idx) = next {
            let e = entries.get_mut(idx).unwrap();
            if e.is_protocol() && e.is_valid() && !e.is_fib() {
                e.nexthop_sync(nmap, fib).await;
                let ok = fib.route_ipv4_add(prefix, e, table_id).await;
                e.set_fib(ok);
                if !ok {
                    nexthop_force_reinstall(&e.nexthop, nmap);
                    return true;
                }
            }
        }
        return false;
    }
    if let Some(prev) = prev {
        let prev = entries.get_mut(prev).unwrap();
        prev.set_selected(false);
        if !ifdown {
            fib.route_ipv4_del(prefix, prev, table_id).await;
        }
        prev.set_fib(false);
    }
    let mut retry = false;
    if let Some(next) = next {
        let next = entries.get_mut(next).unwrap();
        next.set_selected(true);

        if next.is_protocol() {
            next.nexthop_sync(nmap, fib).await;
            let ok = fib.route_ipv4_add(prefix, next, table_id).await;
            next.set_fib(ok);
            if !ok {
                nexthop_force_reinstall(&next.nexthop, nmap);
                retry = true;
            }
        } else {
            next.set_fib(true);
        }
    }
    retry
}

/// Drop our "installed" belief for an entry's nexthop so the next
/// `*_nexthop_sync` recreates it in the kernel. Used when a route
/// install comes back as an error — the most common cause is the
/// kernel having silently dropped the nexthop object on link down, so
/// the route's `Nhid` now points at nothing. A Uni group is
/// reinstalled while `!installed`; a Multi group while `!valid`, so
/// clear the flag the relevant sync loop watches.
fn nexthop_force_reinstall(nexthop: &Nexthop, nmap: &mut NexthopMap) {
    fn force(nmap: &mut NexthopMap, gid: usize) {
        if let Some(group) = nmap.get_mut(gid) {
            match group {
                Group::Uni(_) => group.set_installed(false),
                Group::Multi(_) | Group::Protect(_) => {
                    group.set_valid(false);
                    group.set_installed(false);
                }
            }
        }
    }
    match nexthop {
        Nexthop::Uni(uni) => force(nmap, uni.gid),
        Nexthop::Multi(multi) => {
            force(nmap, multi.gid);
            for uni in &multi.nexthops {
                force(nmap, uni.gid);
            }
        }
        Nexthop::List(list) => {
            for member in &list.nexthops {
                member_force_reinstall(member, nmap);
            }
        }
        Nexthop::Protect(pro) => {
            force(nmap, pro.gid);
            for member in pro.members() {
                member_force_reinstall(member, nmap);
            }
        }
        _ => {}
    }

    fn member_force_reinstall(member: &NexthopMember, nmap: &mut NexthopMap) {
        match member {
            NexthopMember::Uni(uni) => force(nmap, uni.gid),
            NexthopMember::Multi(multi) => {
                force(nmap, multi.gid);
                for uni in &multi.nexthops {
                    force(nmap, uni.gid);
                }
            }
        }
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
        // Primary first, then the repair — the first valid leaf wins,
        // so the entry stays at the primary's metric while the
        // primary's group is alive and falls back to the repair's
        // when it is not.
        Nexthop::Protect(pro) => {
            for uni in pro.iter_unis_mut() {
                nexthop_uni_resolve(uni, nmap);
            }
            for uni in pro.iter_unis() {
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
    table_id: u32,
) -> bool {
    let Some(Group::Uni(group)) = nmap.fetch(uni, table_id) else {
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
    table_id: u32,
) {
    // Only protocol entry.
    if !entry.is_protocol() {
        return;
    }
    if let Nexthop::Uni(uni) = &mut entry.nexthop {
        let _ = resolve_nexthop_uni(uni, nmap, table, table_id);
    }
    if let Nexthop::Multi(multi) = &mut entry.nexthop {
        let mut set = BTreeSet::<(usize, u8)>::new();
        for uni in multi.nexthops.iter_mut() {
            let valid = resolve_nexthop_uni(uni, nmap, table, table_id);
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
            resolve_nexthop_member(member, nmap, table, table_id);
        }
    }
    if let Nexthop::Protect(pro) = &mut entry.nexthop {
        // Same member-wise walk as List, for the same Nhid(0) reason.
        for member in pro.members_mut() {
            resolve_nexthop_member(member, nmap, table, table_id);
        }
        resolve_nexthop_protect(pro, nmap);
    }
    // If one of nexthop is valid, the entry is valid.
    entry.set_valid(entry.is_valid_nexthop(nmap));
}

/// Allocate (or refetch) the kernel indirection group for a protected
/// primary and stamp its id into `pro.gid`. Only a Uni primary gets
/// one — kernel groups can't nest, so a Multi primary's ECMP group is
/// itself the future switch point and `pro.gid` stays 0 (routes then
/// reference the member gids directly, exactly as before phase 1).
fn resolve_nexthop_protect(pro: &mut NexthopProtect, nmap: &mut NexthopMap) {
    let NexthopMember::Uni(primary) = &pro.primary else {
        return;
    };
    if primary.gid == 0 {
        return;
    }
    let backup_gid = match &pro.backup {
        NexthopMember::Uni(u) => u.gid,
        NexthopMember::Multi(m) => m.gid,
    };
    let primary_gid = primary.gid;
    // The indirection group is installable exactly when its sole
    // member is — the sync passes keep this in step afterwards.
    let primary_valid = nmap.get(primary_gid).is_some_and(|g| g.is_valid());
    let Some(group) = nmap.fetch_protect(primary_gid, backup_gid) else {
        return;
    };
    if let Group::Protect(gp) = &mut *group
        && gp.active == ProtectActive::Switched
    {
        // The producer re-asserted this pair, so it believes the
        // primary is healthy again (post-flap SPF). Revert: clearing
        // `installed` makes the next protect_group_sync re-send the
        // group with the primary as member — NLM_F_REPLACE makes
        // that the atomic swap back. (A pre-failure route add racing
        // the switchover can revert early; the SPF output right
        // behind it settles the question either way.)
        gp.active = ProtectActive::Primary;
        gp.set_installed(false);
    }
    group.set_valid(primary_valid);
    group.refcnt_inc();
    pro.gid = group.gid();
}

/// Fast-reroute switchover (phase 2 of the kernel-failover design):
/// rewire every protection indirection group whose primary rides the
/// failed `(table_id, addr)` adjacency onto its repair — one atomic
/// `RTM_NEWNEXTHOP` replace per group, O(protected adjacencies) and
/// independent of how many prefixes reference each group. SPF
/// reconvergence then replaces the routes at its own pace; a re-add
/// of the same (primary, backup) pair reverts the group (see
/// `resolve_nexthop_protect`). Returns how many groups switched.
pub async fn protect_switch(
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
    addr: IpAddr,
) -> (usize, usize) {
    let candidates = nmap.protect_switch_candidates(table_id, addr);
    let mut switched = 0;
    for gid in candidates {
        let Some(Group::Protect(pro)) = nmap.get_mut(gid) else {
            continue;
        };
        pro.active = ProtectActive::Switched;
        let snapshot = Group::Protect(pro.clone());
        // CREATE|REPLACE on the same id = atomic membership swap.
        fib.nexthop_add(&snapshot).await;
        if let Some(group) = nmap.get_mut(gid) {
            group.set_installed(true);
            group.set_valid(true);
        }
        switched += 1;
    }

    // ECMP leg eviction (phase 5): TI-LFA computes no repair for
    // SPF-level ECMP destinations — the surviving legs are the
    // protection — so for Multi groups the fast path is dropping the
    // dead leg from the kernel membership, one atomic replace per
    // group. The failed member is marked invalid exactly as the
    // link-down path would mark it (BFD is just another down
    // detector), so the sync passes don't resurrect the leg before
    // SPF replaces these routes; across the failure the member and
    // group drain via refcnt and are recreated fresh on recovery.
    let evict = nmap.protect_evict_candidates(table_id, addr);
    for (_, member_gid) in evict.iter() {
        if let Some(member) = nmap.get_mut(*member_gid) {
            member.set_valid(false);
        }
    }
    let mut evicted = 0;
    for (gid, member_gid) in evict {
        let Some(Group::Multi(multi)) = nmap.get_mut(gid) else {
            continue;
        };
        multi.valid.retain(|(m, _)| *m != member_gid);
        if multi.valid.is_empty() {
            // Last leg died: there is nothing usable to re-send, and
            // deleting the group would cascade-remove its routes out
            // from under the route sync. Mark it invalid and let the
            // teardown-driven SPF replace the routes (same blackhole
            // window as before phase 5).
            multi.set_valid(false);
            continue;
        }
        let snapshot = Group::Multi(multi.clone());
        fib.nexthop_add(&snapshot).await;
        evicted += 1;
    }
    (switched, evicted)
}

fn resolve_nexthop_member(
    member: &mut NexthopMember,
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv4Net, RibEntries>,
    table_id: u32,
) {
    match member {
        NexthopMember::Uni(uni) => {
            let _ = resolve_nexthop_uni(uni, nmap, table, table_id);
        }
        NexthopMember::Multi(multi) => {
            let mut set = BTreeSet::<(usize, u8)>::new();
            for uni in multi.nexthops.iter_mut() {
                let valid = resolve_nexthop_uni(uni, nmap, table, table_id);
                if valid {
                    set.insert((uni.gid, uni.weight));
                }
            }
            resolve_nexthop_multi(multi, nmap, set);
        }
    }
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
        // System (kernel) routes are never primary+backup protected.
        Nexthop::Protect(_) => false,
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

/// Pick the winning ILM candidate, mirroring `rib_next` for the IP
/// table: lowest admin distance, then lowest metric, then protocol
/// order as a stable final tie-break. Returns the index into
/// `entries`, or `None` when empty.
fn ilm_next(entries: &[IlmEntry]) -> Option<usize> {
    entries
        .iter()
        .enumerate()
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
) -> bool {
    if rib_route() {
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
        return false;
    }

    // Selected.
    let prev = rib_prev(entries);

    // New select.
    let next = rib_next(entries);

    if rib_route() {
        println!("[ipv6_entry_selection] prev={:?} next={:?}", prev, next);
    }

    if prev == next {
        // No selection change — re-add a selected route the kernel
        // dropped on link down (no RTM_DELROUTE), once it resolves.
        if let Some(idx) = next {
            let e = entries.get_mut(idx).unwrap();
            if e.is_protocol() && e.is_valid() && !e.is_fib() {
                e.nexthop_sync(nmap, fib).await;
                let ok = fib.route_ipv6_add(prefix, e, table_id).await;
                e.set_fib(ok);
                if !ok {
                    nexthop_force_reinstall(&e.nexthop, nmap);
                    return true;
                }
            }
        }
        return false;
    }
    if let Some(prev) = prev {
        let prev = entries.get_mut(prev).unwrap();
        prev.set_selected(false);

        fib.route_ipv6_del(prefix, prev, table_id).await;
        prev.set_fib(false);
    }
    let mut retry = false;
    if let Some(next) = next {
        let next = entries.get_mut(next).unwrap();
        next.set_selected(true);

        if next.is_protocol() {
            next.nexthop_sync(nmap, fib).await;
            let ok = fib.route_ipv6_add(prefix, next, table_id).await;
            next.set_fib(ok);
            if !ok {
                nexthop_force_reinstall(&next.nexthop, nmap);
                retry = true;
            }
        } else {
            next.set_fib(true);
        }
    }
    retry
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
        // System (kernel) routes are never primary+backup protected.
        Nexthop::Protect(_) => false,
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
) -> bool {
    ipv6_route_sync_inner(table, nmap, fib, table_id, false)
        .await
        .0
}

/// IPv6 sibling of `ipv4_route_sync_collect`. See its docstring for the
/// default-table-only collection rule.
pub async fn ipv6_route_sync_collect(
    table: &mut PrefixMap<Ipv6Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
) -> (bool, Vec<RedistDeltaV6>) {
    ipv6_route_sync_inner(table, nmap, fib, table_id, true).await
}

async fn ipv6_route_sync_inner(
    table: &mut PrefixMap<Ipv6Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
    table_id: u32,
    collect: bool,
) -> (bool, Vec<RedistDeltaV6>) {
    // Collect prefixes first so we don't hold the !Send `IterMut`
    // across the `ipv6_entry_selection` await.
    let prefixes: Vec<Ipv6Net> = table.iter().map(|(p, _)| p).collect();
    let mut retry = false;
    let mut deltas: Vec<RedistDeltaV6> = Vec::new();
    for p in prefixes {
        let Some(entries) = table.get_mut(&p) else {
            continue;
        };
        let before = collect
            .then(|| entries.iter().find(|e| e.is_selected()).cloned())
            .flatten();
        ipv6_entry_resolve(entries, nmap);
        retry |= ipv6_entry_selection(&p, entries, None, nmap, fib, table_id).await;
        if collect {
            let after = entries.iter().find(|e| e.is_selected()).cloned();
            if super::redist::selected_changed_v6(&p, before.as_ref(), after.as_ref()) {
                deltas.push((p, before, after));
            }
        }
    }
    (retry, deltas)
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
    table_id: u32,
) {
    // Only protocol entry.
    if !entry.is_protocol() {
        return;
    }
    if let Nexthop::Uni(uni) = &mut entry.nexthop {
        let _ = resolve_nexthop_uni_v6(uni, nmap, table, table_id);
    }
    if let Nexthop::Multi(multi) = &mut entry.nexthop {
        let mut set = BTreeSet::<(usize, u8)>::new();
        for uni in multi.nexthops.iter_mut() {
            let valid = resolve_nexthop_uni_v6(uni, nmap, table, table_id);
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
            resolve_nexthop_member_v6(member, nmap, table, table_id);
        }
    }
    if let Nexthop::Protect(pro) = &mut entry.nexthop {
        // Same member-wise walk as List. Missing this block left v6
        // Protect entries (IS-IS v6 / OSPFv3 / SRv6 TI-LFA) with
        // every gid at 0 — `is_valid_nexthop` then never validated
        // the entry, so protected v6 routes silently never installed.
        for member in pro.members_mut() {
            resolve_nexthop_member_v6(member, nmap, table, table_id);
        }
        resolve_nexthop_protect(pro, nmap);
    }
    // If one of nexthop is valid, the entry is valid.
    entry.set_valid(entry.is_valid_nexthop(nmap));
}

/// v6 sibling of `resolve_nexthop_member`: resolve one List / Protect
/// member, allocating the kernel-side Multi group for ECMP members.
fn resolve_nexthop_member_v6(
    member: &mut NexthopMember,
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv6Net, RibEntries>,
    table_id: u32,
) {
    match member {
        NexthopMember::Uni(uni) => {
            let _ = resolve_nexthop_uni_v6(uni, nmap, table, table_id);
        }
        NexthopMember::Multi(multi) => {
            let mut set = BTreeSet::<(usize, u8)>::new();
            for uni in multi.nexthops.iter_mut() {
                let valid = resolve_nexthop_uni_v6(uni, nmap, table, table_id);
                if valid {
                    set.insert((uni.gid, uni.weight));
                }
            }
            resolve_nexthop_multi(multi, nmap, set);
        }
    }
}

fn resolve_nexthop_uni_v6(
    uni: &mut NexthopUni,
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv6Net, RibEntries>,
    table_id: u32,
) -> bool {
    if rib_nexthop() {
        println!(
            "[resolve_nexthop_uni_v6] addr={} gid_before={}",
            uni.addr, uni.gid
        );
    }
    let Some(Group::Uni(group)) = nmap.fetch(uni, table_id) else {
        if rib_nexthop() {
            println!("[resolve_nexthop_uni_v6] nmap.fetch returned None");
        }
        return false;
    };
    if rib_nexthop() {
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
        if rib_nexthop() {
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
    if rib_nexthop() {
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
    vrf_tables: &BTreeMap<u32, VrfRibTables>,
    links: &BTreeMap<u32, Link>,
    fib: &FibHandle,
) {
    if rib_nexthop() {
        println!("[ipv6_nexthop_sync] start; v6 table size={}", table.len());
    }
    for nhop in nmap.groups.iter_mut().flatten() {
        if let Group::Uni(uni) = nhop {
            if rib_nexthop() {
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
            let ipv6_addr = match uni.addr {
                std::net::IpAddr::V4(_) => continue,
                std::net::IpAddr::V6(a) => a,
            };
            // Resolve against the table the nexthop's VRF names.
            let resolve_table = if uni.table_id == RT_TABLE_MAIN {
                Some(table)
            } else {
                vrf_tables.get(&uni.table_id).map(|t| &t.table_v6)
            };
            let ifindex = match resolve_table {
                Some(rt) => rib_resolve_v6(rt, ipv6_addr, &ResolveOpt::default()).is_valid(),
                None => 0,
            };
            if rib_nexthop() {
                println!(
                    "[ipv6_nexthop_sync] resolved ifindex={} (0 means unresolved)",
                    ifindex
                );
            }
            if ifindex == 0 {
                uni.ifindex_resolved = None;
                uni.set_valid(false);
                // Keep `installed`; `nexthop_orphan_gc` removes the
                // kernel object after `ipv6_route_sync` (see the v4
                // path for the ordering rationale).
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
    protect_groups_sync(nmap, fib).await;

    if rib_nexthop() {
        println!("[ipv6_nexthop_sync] done");
    }
}

/// Remove kernel nexthop objects for recursive `Uni` groups that went
/// unresolvable (`!valid` but still `installed`). MUST run after the
/// IPv4 **and** IPv6 route syncs have withdrawn every route that
/// referenced them: a nexthop object can't be deleted while a route
/// still points at it without the kernel cascade-removing that route.
/// Address-family-agnostic — the kernel object is keyed by `gid`, so a
/// single pass over `nmap.groups` covers both families.
pub async fn nexthop_orphan_gc(nmap: &mut NexthopMap, fib: &FibHandle) {
    for nhop in nmap.groups.iter_mut().flatten() {
        if let Group::Uni(uni) = nhop
            && !uni.is_valid()
            && uni.is_installed()
        {
            fib.nexthop_del(&Group::Uni(uni.clone())).await;
            uni.set_installed(false);
        }
    }
}

use super::vrf::VrfRibTables;

#[cfg(test)]
mod tests {
    use super::{
        AddrRecoveryState, RECOVERY_BURST_THRESHOLD, RECOVERY_COOLDOWN, RECOVERY_WINDOW,
        RecoveryDecision, SuppressReason, addr_recover_decide,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn ilm_next_picks_lowest_distance() {
        use super::IlmEntry;
        use super::ilm_next;
        use crate::rib::RibType;

        // Empty table has no winner.
        assert_eq!(ilm_next(&[]), None);

        // A lone candidate always wins.
        let isis = IlmEntry::new(RibType::Isis);
        assert_eq!(ilm_next(std::slice::from_ref(&isis)), Some(0));

        // OSPF (110) beats IS-IS (115) regardless of insertion order.
        let ospf = IlmEntry::new(RibType::Ospf);
        assert_eq!(ilm_next(&[isis.clone(), ospf.clone()]), Some(1));
        assert_eq!(ilm_next(&[ospf, isis]), Some(0));

        // Static (1) outranks BGP (20) and OSPF (110).
        let entries = [
            IlmEntry::new(RibType::Bgp),
            IlmEntry::new(RibType::Static),
            IlmEntry::new(RibType::Ospf),
        ];
        assert_eq!(ilm_next(&entries), Some(1));
    }

    #[test]
    fn ilm_next_metric_breaks_distance_tie() {
        use super::IlmEntry;
        use super::ilm_next;
        use crate::rib::RibType;

        // Same protocol and distance: the lower metric wins.
        let mut hi = IlmEntry::new(RibType::Ospf);
        let mut lo = IlmEntry::new(RibType::Ospf);
        hi.metric = 100;
        lo.metric = 10;
        assert_eq!(ilm_next(&[hi, lo]), Some(1));

        // Metric outranks the rtype tie-break: at equal distance, the
        // higher-code protocol wins when it has the lower metric.
        let mut a = IlmEntry::new(RibType::Other(10)); // lower rtype code
        let mut b = IlmEntry::new(RibType::Other(20)); // higher rtype code
        a.distance = 50;
        b.distance = 50;
        a.metric = 50;
        b.metric = 5;
        assert_eq!(ilm_next(&[a, b]), Some(1));
    }

    #[test]
    fn ilm_next_tie_breaks_on_rtype() {
        use super::IlmEntry;
        use super::ilm_next;
        use crate::rib::RibType;

        // Equal distance and metric: the lower protocol code wins.
        // Other(10).u8() = 10 < Other(20).u8() = 20, so index 1 wins.
        let mut a = IlmEntry::new(RibType::Other(20));
        let mut b = IlmEntry::new(RibType::Other(10));
        a.distance = 50;
        b.distance = 50;
        assert_eq!(ilm_next(&[a, b]), Some(1));
    }

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
        rib_resolve_nexthop(&mut entry, &table, &mut nmap, 0);

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

    /// `Nexthop::Protect` twin of the test above: the ECMP primary
    /// member must get its kernel-side Multi group allocated, and the
    /// Uni backup its own group, when the IGPs hand the RIB a
    /// primary+repair pair.
    #[test]
    fn protect_with_nested_multi_resolves_multi_gid() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{NexthopProtect, NexthopUni};
        use super::super::{Nexthop, NexthopMap, NexthopMember, NexthopMulti};
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
        entry.nexthop = Nexthop::Protect(NexthopProtect {
            primary: NexthopMember::Multi(multi),
            backup: NexthopMember::Uni(backup),
            gid: 0,
        });

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop(&mut entry, &table, &mut nmap, 0);

        let Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("entry.nexthop should still be Protect");
        };
        let NexthopMember::Multi(multi_member) = &pro.primary else {
            panic!("primary Multi preserved");
        };
        assert!(
            multi_member.gid != 0,
            "primary Multi must get a kernel-side group allocated (gid != 0)"
        );
        for leg in &multi_member.nexthops {
            assert!(leg.gid != 0, "each leg also gets a gid");
        }
        let NexthopMember::Uni(backup_uni) = &pro.backup else {
            panic!("backup Uni preserved");
        };
        assert!(backup_uni.gid != 0, "backup Uni gets its own group");
    }

    /// Phase 1 of the kernel-failover design: a Uni primary gets a
    /// protection indirection group allocated and stamped into
    /// `pro.gid`; the same (primary, backup) pair on a second entry
    /// dedupes onto the same gid (that sharing is what makes the
    /// phase-2 switchover O(1) in prefixes).
    #[test]
    fn protect_uni_primary_allocates_indirection_group() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{GroupTrait, NexthopProtect, NexthopUni};
        use super::super::{Group, Nexthop, NexthopMap, NexthopMember};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop;
        use ipnet::Ipv4Net;
        use prefix_trie::PrefixMap;

        let mk_entry = || {
            let mut primary = NexthopUni::new("10.0.0.1".parse().unwrap(), 20, vec![]);
            primary.ifindex_origin = Some(10);
            let mut backup = NexthopUni::new("10.0.0.5".parse().unwrap(), 21, vec![]);
            backup.ifindex_origin = Some(20);
            let mut entry = RibEntry::new(RibType::Isis);
            entry.nexthop = Nexthop::Protect(NexthopProtect {
                primary: NexthopMember::Uni(primary),
                backup: NexthopMember::Uni(backup),
                gid: 0,
            });
            entry
        };

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();

        let mut entry_a = mk_entry();
        rib_resolve_nexthop(&mut entry_a, &table, &mut nmap, 0);
        let Nexthop::Protect(pro_a) = &entry_a.nexthop else {
            panic!("still Protect");
        };
        assert_ne!(pro_a.gid, 0, "Uni primary must get an indirection group");

        let Some(Group::Protect(grp)) = nmap.get(pro_a.gid) else {
            panic!("Group::Protect allocated in nmap");
        };
        let (NexthopMember::Uni(p), NexthopMember::Uni(b)) = (&pro_a.primary, &pro_a.backup) else {
            panic!("members stay Uni");
        };
        assert_eq!(grp.primary_gid, p.gid);
        assert_eq!(grp.backup_gid, b.gid);
        // ifindex_origin pinned both members valid, so the wrapper is
        // installable straight away.
        assert!(grp.is_valid());

        // Second entry with the same pair: same indirection gid.
        let mut entry_b = mk_entry();
        rib_resolve_nexthop(&mut entry_b, &table, &mut nmap, 0);
        let Nexthop::Protect(pro_b) = &entry_b.nexthop else {
            panic!("still Protect");
        };
        assert_eq!(pro_a.gid, pro_b.gid, "same (primary, backup) pair dedupes");
        assert_eq!(nmap.get(pro_b.gid).unwrap().refcnt(), 2);
    }

    /// Phase 2: candidate selection for the switchover walks only
    /// protection groups whose ACTIVE primary rides the failed
    /// (table, addr) adjacency and whose repair is actually usable.
    #[test]
    fn protect_switch_candidates_match_and_gate() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{GroupTrait, NexthopProtect, NexthopUni, ProtectActive};
        use super::super::{Group, Nexthop, NexthopMap, NexthopMember};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop;
        use ipnet::Ipv4Net;
        use prefix_trie::PrefixMap;

        let mut primary = NexthopUni::new("10.0.0.1".parse().unwrap(), 20, vec![]);
        primary.ifindex_origin = Some(10);
        let mut backup = NexthopUni::new("10.0.0.5".parse().unwrap(), 21, vec![]);
        backup.ifindex_origin = Some(20);
        let mut entry = RibEntry::new(RibType::Isis);
        entry.nexthop = Nexthop::Protect(NexthopProtect {
            primary: NexthopMember::Uni(primary),
            backup: NexthopMember::Uni(backup),
            gid: 0,
        });

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop(&mut entry, &table, &mut nmap, 0);
        let Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("still Protect");
        };
        let (pro_gid, backup_gid) = match (&pro.backup, pro.gid) {
            (NexthopMember::Uni(b), gid) => (gid, b.gid),
            _ => panic!("backup stays Uni"),
        };

        // Repair not yet installed in the kernel: not a candidate.
        let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        assert!(nmap.protect_switch_candidates(0, addr).is_empty());

        // Live repair: candidate, keyed by the primary's (table, addr).
        nmap.get_mut(backup_gid).unwrap().set_installed(true);
        assert_eq!(nmap.protect_switch_candidates(0, addr), vec![pro_gid]);
        assert!(
            nmap.protect_switch_candidates(0, "10.0.0.9".parse().unwrap())
                .is_empty(),
            "other gateways unaffected"
        );
        assert!(
            nmap.protect_switch_candidates(254, addr).is_empty(),
            "other tables unaffected"
        );

        // Already switched: nothing left to protect with.
        if let Some(Group::Protect(gp)) = nmap.get_mut(pro_gid) {
            gp.active = ProtectActive::Switched;
        }
        assert!(nmap.protect_switch_candidates(0, addr).is_empty());
    }

    /// A seg6 repair is switchover-eligible like any other live Uni
    /// backup: seg6 members forward correctly through groups (the
    /// black-hole theory was refuted — design doc correction), so
    /// SRv6 TI-LFA gets the same kernel fast path.
    #[test]
    fn protect_switch_candidates_include_seg6_backup() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{GroupTrait, NexthopProtect, NexthopUni};
        use super::super::{Nexthop, NexthopMap, NexthopMember};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop_v6;
        use ipnet::Ipv6Net;
        use prefix_trie::PrefixMap;

        let mut primary = NexthopUni::new("fe80::1".parse().unwrap(), 2, vec![]);
        primary.ifindex_origin = Some(10);
        let mut backup = NexthopUni::new("fe80::2".parse().unwrap(), 3, vec![]);
        backup.ifindex_origin = Some(20);
        backup.segs = vec!["fcbb:bbbb:8::".parse().unwrap()];
        backup.encap_type = Some(isis_packet::srv6::EncapType::HInsert);
        let mut entry = RibEntry::new(RibType::Ospf);
        entry.nexthop = Nexthop::Protect(NexthopProtect {
            primary: NexthopMember::Uni(primary),
            backup: NexthopMember::Uni(backup),
            gid: 0,
        });

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv6Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop_v6(&mut entry, &table, &mut nmap, 254);
        let Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("still Protect");
        };
        assert_ne!(pro.gid, 0, "plain primary still gets its group");
        let NexthopMember::Uni(b) = &pro.backup else {
            panic!("backup Uni");
        };
        nmap.get_mut(b.gid).unwrap().set_installed(true);
        assert_eq!(
            nmap.protect_switch_candidates(254, "fe80::1".parse().unwrap()),
            vec![pro.gid],
            "a live seg6 repair is a switchover candidate"
        );
    }

    /// Phase 2: a switched group encodes the repair as its kernel
    /// member, and a producer re-adding the same pair (post-flap SPF)
    /// reverts it to the primary with a pending re-install.
    #[test]
    fn protect_switch_flips_active_and_reassert_reverts() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{GroupTrait, NexthopProtect, NexthopUni, ProtectActive};
        use super::super::{Group, Nexthop, NexthopMap, NexthopMember};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop;
        use ipnet::Ipv4Net;
        use prefix_trie::PrefixMap;

        let mk_entry = || {
            let mut primary = NexthopUni::new("10.0.0.1".parse().unwrap(), 20, vec![]);
            primary.ifindex_origin = Some(10);
            let mut backup = NexthopUni::new("10.0.0.5".parse().unwrap(), 21, vec![]);
            backup.ifindex_origin = Some(20);
            let mut entry = RibEntry::new(RibType::Isis);
            entry.nexthop = Nexthop::Protect(NexthopProtect {
                primary: NexthopMember::Uni(primary),
                backup: NexthopMember::Uni(backup),
                gid: 0,
            });
            entry
        };

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        let mut entry = mk_entry();
        rib_resolve_nexthop(&mut entry, &table, &mut nmap, 0);
        let Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("still Protect");
        };
        let (primary_gid, backup_gid) = match (&pro.primary, &pro.backup) {
            (NexthopMember::Uni(p), NexthopMember::Uni(b)) => (p.gid, b.gid),
            _ => panic!("members stay Uni"),
        };

        // Simulate the switchover state flip.
        let Some(Group::Protect(gp)) = nmap.get_mut(pro.gid) else {
            panic!("protect group");
        };
        assert_eq!(gp.active_gid(), primary_gid, "steady state holds primary");
        gp.active = ProtectActive::Switched;
        gp.set_installed(true);
        assert_eq!(gp.active_gid(), backup_gid, "switched state holds repair");

        // Same pair re-added (the producer believes the primary is
        // healthy again): the group reverts and queues a re-install.
        let pro_gid = pro.gid;
        let mut entry2 = mk_entry();
        rib_resolve_nexthop(&mut entry2, &table, &mut nmap, 0);
        let Some(Group::Protect(gp)) = nmap.get_mut(pro_gid) else {
            panic!("protect group");
        };
        assert_eq!(gp.active, ProtectActive::Primary, "reassert reverts");
        assert!(
            !gp.is_installed(),
            "pending re-install so the sync pass re-sends the group"
        );
    }

    /// Phase 5: a BFD-dead leg makes its ECMP groups eviction
    /// candidates, keyed by the leg's (table, addr); the leg itself
    /// is marked invalid so the sync passes can't resurrect it.
    #[test]
    fn protect_evict_candidates_match_ecmp_groups() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{GroupTrait, NexthopUni};
        use super::super::{Group, Nexthop, NexthopMap, NexthopMulti};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop;
        use ipnet::Ipv4Net;
        use prefix_trie::PrefixMap;

        let mut leg_a = NexthopUni::new("10.1.0.2".parse().unwrap(), 10, vec![]);
        leg_a.ifindex_origin = Some(10);
        let mut leg_b = NexthopUni::new("10.2.0.2".parse().unwrap(), 10, vec![]);
        leg_b.ifindex_origin = Some(20);
        let multi = NexthopMulti {
            metric: 10,
            nexthops: vec![leg_a, leg_b],
            ..Default::default()
        };
        let mut entry = RibEntry::new(RibType::Isis);
        entry.nexthop = Nexthop::Multi(multi);

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop(&mut entry, &table, &mut nmap, 0);
        let Nexthop::Multi(multi) = &entry.nexthop else {
            panic!("still Multi");
        };
        let (a_gid, b_gid, multi_gid) = (multi.nexthops[0].gid, multi.nexthops[1].gid, multi.gid);
        assert_ne!(multi_gid, 0, "ECMP group allocated");

        let addr_a: std::net::IpAddr = "10.1.0.2".parse().unwrap();
        assert_eq!(
            nmap.protect_evict_candidates(0, addr_a),
            vec![(multi_gid, a_gid)]
        );
        assert!(
            nmap.protect_evict_candidates(254, addr_a).is_empty(),
            "other tables unaffected"
        );
        assert!(
            nmap.protect_evict_candidates(0, "10.9.9.9".parse().unwrap())
                .is_empty(),
            "other gateways unaffected"
        );

        // Simulate the eviction state change the async path performs.
        nmap.get_mut(a_gid).unwrap().set_valid(false);
        if let Some(Group::Multi(m)) = nmap.get_mut(multi_gid) {
            m.valid.retain(|(g, _)| *g != a_gid);
        }
        // The dead leg left the LIVE membership: no longer a candidate
        // (idempotence), and the surviving leg is intact.
        assert!(nmap.protect_evict_candidates(0, addr_a).is_empty());
        let Some(Group::Multi(m)) = nmap.get(multi_gid) else {
            panic!("multi group survives");
        };
        assert_eq!(m.valid.len(), 1);
        assert!(m.valid.iter().any(|(g, _)| *g == b_gid));
        assert_eq!(m.set.len(), 2, "configured membership untouched");
    }

    /// SRv6-encap'd primaries get the indirection group like any
    /// other Uni primary. (They were excluded for a while on a
    /// "seg6-inline-in-group black-holes" theory that kfree_skb
    /// drop-reason tracing later refuted — see the design doc
    /// correction; this test pins the un-exclusion.)
    #[test]
    fn protect_srv6_primary_gets_indirection_group() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{NexthopProtect, NexthopUni};
        use super::super::{Nexthop, NexthopMap, NexthopMember};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop_v6;
        use ipnet::Ipv6Net;
        use prefix_trie::PrefixMap;

        // Repair promoted to primary (backup-as-primary): inline SRH
        // via the repair neighbor.
        let mut primary = NexthopUni::new("2001:db8:0:2::2".parse().unwrap(), 12, vec![]);
        primary.ifindex_origin = Some(10);
        primary.segs = vec!["fcbb:bbbb:8::".parse().unwrap()];
        primary.encap_type = Some(isis_packet::srv6::EncapType::HInsert);
        let mut backup = NexthopUni::new("2001:db8:0:1::2".parse().unwrap(), 13, vec![]);
        backup.ifindex_origin = Some(20);

        let mut entry = RibEntry::new(RibType::Isis);
        entry.nexthop = Nexthop::Protect(NexthopProtect {
            primary: NexthopMember::Uni(primary),
            backup: NexthopMember::Uni(backup),
            gid: 0,
        });

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv6Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop_v6(&mut entry, &table, &mut nmap, 0);

        let Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("still Protect");
        };
        let NexthopMember::Uni(p) = &pro.primary else {
            panic!("primary stays Uni");
        };
        assert_ne!(p.gid, 0, "the seg6 member gets its own group");
        assert_ne!(
            pro.gid, 0,
            "SRv6 primary is wrapped in an indirection group like any other"
        );
    }

    /// The nesting constraint: a Multi (ECMP) primary gets NO
    /// indirection group — its own ECMP group is the future switch
    /// point — so `pro.gid` stays 0 and routes reference member gids
    /// exactly as before phase 1.
    #[test]
    fn protect_multi_primary_gets_no_indirection_group() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{NexthopProtect, NexthopUni};
        use super::super::{Nexthop, NexthopMap, NexthopMember, NexthopMulti};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop;
        use ipnet::Ipv4Net;
        use prefix_trie::PrefixMap;

        let leg_a = NexthopUni::new("10.0.0.1".parse().unwrap(), 20, vec![]);
        let leg_b = NexthopUni::new("10.0.0.2".parse().unwrap(), 20, vec![]);
        let multi = NexthopMulti {
            metric: 20,
            nexthops: vec![leg_a, leg_b],
            ..Default::default()
        };
        let backup = NexthopUni::new("10.0.0.5".parse().unwrap(), 21, vec![]);

        let mut entry = RibEntry::new(RibType::Isis);
        entry.nexthop = Nexthop::Protect(NexthopProtect {
            primary: NexthopMember::Multi(multi),
            backup: NexthopMember::Uni(backup),
            gid: 0,
        });

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop(&mut entry, &table, &mut nmap, 0);

        let Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("still Protect");
        };
        assert_eq!(pro.gid, 0, "Multi primary: ECMP group is the switch point");
    }

    /// Regression: the v6 resolver was missing the `Protect` block
    /// entirely, so v6 protected entries (IS-IS v6 / OSPFv3 / SRv6
    /// TI-LFA) kept every gid at 0, never validated, and silently
    /// never installed. The v4 twin above passed all along — this
    /// pins the v6 path.
    #[test]
    fn protect_resolves_gids_on_v6_path() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{NexthopProtect, NexthopUni};
        use super::super::{Nexthop, NexthopMap, NexthopMember, NexthopMulti};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop_v6;
        use ipnet::Ipv6Net;
        use prefix_trie::PrefixMap;

        let leg_a = NexthopUni::new("fe80::a:1".parse().unwrap(), 1011, vec![]);
        let leg_b = NexthopUni::new("fe80::a:2".parse().unwrap(), 1011, vec![]);
        let multi = NexthopMulti {
            metric: 1011,
            nexthops: vec![leg_a, leg_b],
            ..Default::default()
        };
        let backup = NexthopUni::new("fe80::a:3".parse().unwrap(), 1012, vec![]);

        let mut entry = RibEntry::new(RibType::Isis);
        entry.nexthop = Nexthop::Protect(NexthopProtect {
            primary: NexthopMember::Multi(multi),
            backup: NexthopMember::Uni(backup),
            gid: 0,
        });

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv6Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop_v6(&mut entry, &table, &mut nmap, 0);

        let Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("entry.nexthop should still be Protect");
        };
        let NexthopMember::Multi(multi_member) = &pro.primary else {
            panic!("primary Multi preserved");
        };
        assert!(
            multi_member.gid != 0,
            "primary Multi must get a kernel-side group allocated (gid != 0)"
        );
        for leg in &multi_member.nexthops {
            assert!(leg.gid != 0, "each leg also gets a gid");
        }
        let NexthopMember::Uni(backup_uni) = &pro.backup else {
            panic!("backup Uni preserved");
        };
        assert!(backup_uni.gid != 0, "backup Uni gets its own group");
    }

    /// Sibling of the test above with the SRv6 TI-LFA member shape:
    /// a link-local primary plus a seg6-encap (H.Insert carrier)
    /// backup must resolve both members and validate the entry, or
    /// the protected route never installs.
    #[test]
    fn protect_v6_with_seg6_backup_resolves_and_validates() {
        use super::super::entry::RibEntry;
        use super::super::nexthop::{NexthopProtect, NexthopUni};
        use super::super::{Nexthop, NexthopMap, NexthopMember};
        use super::super::{RibEntries, RibType};
        use super::rib_resolve_nexthop_v6;
        use ipnet::Ipv6Net;
        use prefix_trie::PrefixMap;

        let mut primary = NexthopUni::new("fe80::1".parse().unwrap(), 2, vec![]);
        primary.ifindex_origin = Some(10);
        let mut backup = NexthopUni::new("fe80::2".parse().unwrap(), 3, vec![]);
        backup.ifindex_origin = Some(11);
        backup.segs = vec!["fcbb:bbbb:5:e003:e002::".parse().unwrap()];
        backup.encap_type = Some(isis_packet::srv6::EncapType::HInsert);

        let mut entry = RibEntry::new(RibType::Ospf);
        entry.nexthop = Nexthop::Protect(NexthopProtect {
            primary: NexthopMember::Uni(primary),
            backup: NexthopMember::Uni(backup),
            gid: 0,
        });

        let mut nmap = NexthopMap::default();
        let table: PrefixMap<Ipv6Net, RibEntries> = PrefixMap::new();
        rib_resolve_nexthop_v6(&mut entry, &table, &mut nmap, 254);

        let Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("entry.nexthop should still be Protect");
        };
        let NexthopMember::Uni(p) = &pro.primary else {
            panic!("primary Uni preserved");
        };
        let NexthopMember::Uni(b) = &pro.backup else {
            panic!("backup Uni preserved");
        };
        assert!(p.gid != 0, "primary resolves to a group");
        assert!(b.gid != 0, "seg6 backup resolves to its own group");
        assert!(
            entry.is_valid(),
            "a Protect route with resolvable members must validate"
        );
    }
}
