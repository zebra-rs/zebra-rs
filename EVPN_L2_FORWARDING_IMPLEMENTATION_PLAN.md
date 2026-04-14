# EVPN L2 MAC Forwarding - Implementation Plan

## Overview

Full implementation of EVPN L2 MAC address learning and kernel FIB installation requires coordinated changes across three layers:

1. **BGP Layer** — Export selected EVPN routes to RIB subsystem
2. **RIB Layer** — Receive, store, and manage L2 state
3. **FIB/Kernel Layer** — Install MACs in kernel via netlink (with workaround for remote VTEP gap)

This plan sequences work to enable **end-to-end testing** as early as Phase 2, while high-value netlink improvements happen in parallel.

---

## Dependency Graph

```
Phase 1: Foundation (RIB)
  ├─ Add Message::MacAdd/Del types ...................... [CRITICAL]
  ├─ Add mac_table to Rib struct ........................ [BLOCKING]
  └─ Implement mac_add/mac_del handlers ................. [BLOCKING]
         ↓
Phase 2: BGP Export (BGP → RIB)
  ├─ route_evpn_export_selected() function .............. [CORE]
  ├─ Extract VNI from RouteDistinguisher ................ [CORE]
  ├─ Extract flags/seq from BgpAttr ..................... [CORE]
  └─ Call export after select_best_path ................. [CORE]
       ↓ (now MAC entries flow to RIB)
       ├─ TEST: Verify Message::MacAdd reaches RIB handler
       ├─ TEST: Verify mac_table populated
       └─ Can proceed to Phase 3 in parallel with Phase 2
         ↓
Phase 3A: FIB Install (kernel, workaround path)
  ├─ Handle Message::MacAdd in FIB ...................... [UNBLOCK E2E]
  ├─ Build RTM_NEWNEIGH neighbour message ............... [UNBLOCK E2E]
  ├─ Set NDA_LLADDR, NDA_VNI, NDA_SRC_VNI ............... [UNBLOCK E2E]
  ├─ Use message_mut() for port/extra attrs ............. [UNBLOCK E2E]
  ├─ Send to kernel via rtnetlink ....................... [UNBLOCK E2E]
  └─ ⚠️ LIMITATION: Remote VTEP requires workaround ..... [KNOWN]
         ↓ (end-to-end flow works)
         
Phase 3B: Remote VTEP Support (netlink gap fix)
  ├─ Add NDA_REMOTE_VTEP or similar to netlink-packet-route [OPTIONAL]
  │   └─ OR create custom attribute encoding ............ [OPTIONAL]
  ├─ Extend NeighbourAttribute enum ..................... [OPTIONAL]
  ├─ Add builder methods to rtnetlink ................... [OPTIONAL]
  └─ Update FIB to use remote VTEP ...................... [OPTIONAL]
         ↓ (production-ready)

Phase 4: Advanced Features (PARALLEL)
  ├─ MDB support (Type 3 multicast routes)
  ├─ ESI handling (multi-homing)
  ├─ MAC mobility sequence tracking
  ├─ Multi-VNI support
  └─ Integration tests with VXLAN
```

---

## Phase 1: RIB Foundation [1-2 days]

**Goal:** Add infrastructure for L2 state management in RIB subsystem.

### 1.1 Extend Message Enum
**File:** `zebra-rs/src/rib/inst.rs`

```rust
pub enum Message {
    // ... existing variants ...
    
    MacAdd {
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,  // Remote VTEP (optional in Phase 1)
        flags: u8,                         // Sticky, Gateway, Router, etc
        seq: u32,                          // MAC mobility sequence
        esi: Option<[u8; 10]>,            // Ethernet Segment ID (Phase 4)
    },
    MacDel {
        vni: u32,
        mac: MacAddr,
    },
}
```

**Rationale:**
- Matches structure needed from BGP (MAC, VNI, flags, sequence)
- Tunnel endpoint optional (can be set via separate VXLAN config initially)
- ESI reserved for Phase 4 multi-homing

### 1.2 Add L2 State Table to Rib Struct
**File:** `zebra-rs/src/rib/inst.rs`

```rust
pub struct Rib {
    // ... existing fields ...
    pub mac_table: BTreeMap<(u32, MacAddr), MacEntry>,
}

#[derive(Debug, Clone)]
pub struct MacEntry {
    pub vni: u32,
    pub mac: MacAddr,
    pub tunnel_endpoint: Option<IpAddr>,
    pub flags: u8,
    pub seq: u32,
    pub ifindex: Option<u32>,  // Kernel VXLAN interface index
    pub installed: bool,        // Kernel FIB state
}
```

**Rationale:**
- Key by (VNI, MAC) — matches EVPN semantics
- Store tunnel endpoint for FIB operations
- Track installation status for debug/replay

### 1.3 Implement Message Handlers
**File:** `zebra-rs/src/rib/inst.rs` — in `Rib::process_msg()`

```rust
async fn process_msg(&mut self, msg: Message) {
    match msg {
        // ... existing ...
        Message::MacAdd { vni, mac, tunnel_endpoint, flags, seq, .. } => {
            self.mac_add(vni, mac, tunnel_endpoint, flags, seq).await;
        }
        Message::MacDel { vni, mac } => {
            self.mac_del(vni, mac).await;
        }
    }
}

impl Rib {
    async fn mac_add(
        &mut self,
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        seq: u32,
    ) {
        let entry = MacEntry {
            vni,
            mac,
            tunnel_endpoint,
            flags,
            seq,
            ifindex: None,  // Resolve in Phase 3
            installed: false,
        };
        
        self.mac_table.insert((vni, mac), entry.clone());
        
        // Send to FIB for kernel install (Phase 3)
        self.fib_install_mac(&entry).await;
    }
    
    async fn mac_del(&mut self, vni: u32, mac: MacAddr) {
        if let Some(mut entry) = self.mac_table.remove(&(vni, mac)) {
            entry.installed = false;
            self.fib_delete_mac(&entry).await;
        }
    }
}
```

### 1.4 Logging & Monitoring
**Add show command:** `show l2 mac table [vni N] [bridge NAME]`

```rust
pub fn show_mac_table(&self, args: Args) -> String {
    // Display VNI, MAC, tunnel endpoint, flags, installed status
}
```

**Milestone:** RIB can receive, store, and track L2 MAC entries. No kernel install yet.

**Tests:**
- Unit: Create/delete MAC entries, verify table state
- Integration: Send Message::MacAdd from test harness, verify storage

---

## Phase 2: BGP Export to RIB [2-3 days]

**Goal:** Connect BGP EVPN route selection to RIB MAC installation.

### 2.1 Helper Functions: Extract EVPN Data from Attributes
**File:** `zebra-rs/src/bgp/route.rs`

```rust
/// Extract VNI from Route Distinguisher (Type 2 RD)
fn extract_vni_from_rd(rd: &RouteDistinguisher) -> Option<u32> {
    // RFC 7432: Type 2 RD = [2 bytes: 0,0] [3 bytes: VNI] [2 bytes: index]
    // Parse from rd.value (if RD structure supports it)
}

/// Extract flags (sticky, gateway, router) from extended communities
fn extract_flags_from_attr(attr: &BgpAttr) -> u8 {
    let mut flags = 0u8;
    
    // Check sticky MAC (EVPN extended community)
    if attr.ecom.iter().any(|ec| is_sticky_mac_extended_community(ec)) {
        flags |= 0x01;
    }
    
    // Check gateway MAC
    if attr.ecom.iter().any(|ec| is_gateway_mac_extended_community(ec)) {
        flags |= 0x02;
    }
    
    // Check router flag (for IPv6 scenarios)
    if attr.ecom.iter().any(|ec| is_router_extended_community(ec)) {
        flags |= 0x04;
    }
    
    flags
}

/// Extract MAC mobility sequence number
fn extract_mac_mobility_seq(attr: &BgpAttr) -> u32 {
    attr.ecom
        .iter()
        .find_map(|ec| parse_mac_mobility_extended_community(ec))
        .unwrap_or(0)
}

/// Extract tunnel endpoint from BGP nexthop
fn extract_tunnel_endpoint_from_rib(rib: &BgpRib) -> Option<IpAddr> {
    rib.nexthop.as_ref().and_then(|nh| {
        // Extract from Vpnv4Nexthop structure
        // This is the VTEP IP from the BGP route's NEXT_HOP attribute
    })
}
```

**Rationale:**
- Encapsulate extraction logic for testability
- Reusable across different export scenarios
- Handles current attribute encoding in bgp-packet crate

### 2.2 Export Function: Route Selection → RIB
**File:** `zebra-rs/src/bgp/route.rs`

```rust
/// Called after EVPN best path selection to export to RIB
fn route_evpn_export_selected(
    rd: RouteDistinguisher,
    prefix: &EvpnPrefix,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
) {
    // If no selected path, withdraw
    if selected.is_empty() {
        if let EvpnPrefix::MacIp { mac, .. } = prefix {
            let msg = rib::Message::MacDel {
                vni: extract_vni_from_rd(&rd)?,
                mac: MacAddr::from(*mac),
            };
            let _ = bgp.rib_tx.send(msg);
        }
        return;
    }

    // Get best path (last entry in selected vector)
    let best = &selected[selected.len() - 1];
    
    if let EvpnPrefix::MacIp { mac, .. } = prefix {
        let msg = rib::Message::MacAdd {
            vni: extract_vni_from_rd(&rd)?,
            mac: MacAddr::from(*mac),
            tunnel_endpoint: extract_tunnel_endpoint_from_rib(best),
            flags: extract_flags_from_attr(&best.attr),
            seq: extract_mac_mobility_seq(&best.attr),
            esi: None,  // Phase 4
        };
        let _ = bgp.rib_tx.send(msg);
    }
}
```

**Rationale:**
- Symmetric to `route_evpn_withdraw()` — withdraw when best path removed
- Extracts all necessary data from selected route
- Handles both route add and implicit delete scenarios

### 2.3 Integration Point: Call After Best Path Selection
**File:** `zebra-rs/src/bgp/route.rs` — in `route_evpn_withdraw()`

```rust
pub fn route_evpn_withdraw(ident: usize, route: &EvpnRoute, bgp: &mut BgpTop, peers: &mut PeerMap) {
    let (rd, prefix) = EvpnPrefix::from_route(route);
    // ... existing AdjRIB operations ...
    
    let _ = bgp.local_rib.remove_evpn(rd, &prefix, id, ident);
    let selected = bgp.local_rib.select_best_path_evpn(&rd, &prefix);
    
    // ✨ NEW: Export to RIB
    route_evpn_export_selected(rd, &prefix, &selected, bgp);
}
```

And in `route_evpn_update()` after `select_best_path_evpn()`:

```rust
pub fn route_evpn_update(...) {
    let (rd, prefix) = EvpnPrefix::from_route(route);
    // ... existing code ...
    
    let _ = bgp.local_rib.update_evpn(rd, prefix.clone(), rib);
    let selected = bgp.local_rib.select_best_path_evpn(&rd, &prefix);
    
    // ✨ NEW: Export to RIB
    route_evpn_export_selected(rd, &prefix, &selected, bgp);
}
```

### 2.4 Testing: Message Flow
**Test script:**
1. Create BGP session with peer
2. Advertise Type-2 (MAC/IP) route
3. Verify Message::MacAdd received in RIB
4. Verify mac_table populated
5. Withdraw route, verify Message::MacDel sent

**Milestone:** MAC entries flow from BGP → RIB. Can now test end-to-end kernel install in Phase 3.

**Tests:**
- Unit: Extract functions (VNI, flags, tunnel endpoint)
- Integration: BGP update → RIB message → mac_table entry
- Functional: EVPN route advertisement → kernel MAC (basic FDB, no remote VTEP)

---

## Phase 3A: FIB Kernel Install [2-3 days] — UNBLOCK E2E

**Goal:** Get MACs into kernel FIB via RTM_NEWNEIGH. Accept workaround for remote VTEP.

### 3A.1 Handle Message::MacAdd in FIB
**File:** `zebra-rs/src/fib/mod.rs` — message dispatch

```rust
FibMessage::MacAdd { vni, mac, tunnel_endpoint, flags, seq, .. } => {
    self.handle_fib_mac_add(vni, mac, tunnel_endpoint, flags, seq).await
}
```

### 3A.2 Build RTM_NEWNEIGH Message
**File:** `zebra-rs/src/fib/netlink/handle.rs`

```rust
async fn handle_fib_mac_add(
    &mut self,
    vni: u32,
    mac: MacAddr,
    tunnel_endpoint: Option<IpAddr>,
    flags: u8,
    seq: u32,
) -> Result<()> {
    // Resolve VNI → VXLAN interface index
    let vxlan_ifindex = self.resolve_vxlan_ifindex(vni)?;
    
    // Build neighbour message for bridge FDB
    let mut msg = NeighbourMessage::default();
    msg.header.family = AddressFamily::Bridge;
    msg.header.ifindex = vxlan_ifindex;
    msg.header.state = NeighbourState::Permanent;
    msg.header.flags = NeighbourFlags::from_bits_retain(
        NTF_SELF | NTF_EXT_LEARNED
        | if (flags & 0x01) != 0 { NTF_STICKY } else { 0 }
        | if (flags & 0x02) != 0 { NTF_ROUTER } else { 0 }
    );
    
    // Set MAC address (NDA_LLADDR)
    msg.attributes.push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));
    
    // Set VNI (NDA_VNI)
    msg.attributes.push(NeighbourAttribute::Vni(vni));
    
    // Set source VNI (NDA_SRC_VNI) — same as VNI for single-VNI scenario
    msg.attributes.push(NeighbourAttribute::SourceVni(vni));
    
    // Set port (NDA_PORT) — standard VXLAN port 4789
    msg.attributes.push(NeighbourAttribute::Port(4789));
    
    // ⚠️ WORKAROUND (Phase 3B will improve):
    // Remote VTEP cannot be set via standard netlink attributes
    // Options:
    // A) Set via separate VXLAN config (`ip link set vxlan0 remote X.X.X.X`)
    // B) Use message_mut() for custom attribute encoding (fragile)
    // C) Accept that remote VTEP is not set via FIB for Phase 3A
    
    // Send to kernel
    self.send_neighbour_message(msg, NLM_F_REPLACE).await?;
    
    Ok(())
}

fn resolve_vxlan_ifindex(&self, vni: u32) -> Result<u32> {
    // Look up VXLAN interface index by VNI
    // Could use: link_table, or VXLAN config from RIB
    // For Phase 3A: Accept command-line vxlan_ifindex mapping
}
```

### 3A.3 Send Netlink Message
**File:** `zebra-rs/src/fib/netlink/handle.rs`

```rust
async fn send_neighbour_message(
    &mut self,
    msg: NeighbourMessage,
    flags: u16,
) -> Result<()> {
    let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewNeighbour(msg));
    req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | flags;
    
    let mut response = self.handle.request(req)?;
    while let Some(message) = response.next().await {
        match message.payload {
            NetlinkPayload::Error(err) => {
                return Err(format!("netlink error: {:?}", err).into());
            }
            NetlinkPayload::Done(_) => break,
            _ => {}
        }
    }
    
    Ok(())
}
```

### 3A.4 Deletion Handler
**File:** `zebra-rs/src/fib/netlink/handle.rs`

```rust
async fn handle_fib_mac_del(
    &mut self,
    vni: u32,
    mac: MacAddr,
) -> Result<()> {
    let vxlan_ifindex = self.resolve_vxlan_ifindex(vni)?;
    
    let mut msg = NeighbourMessage::default();
    msg.header.family = AddressFamily::Bridge;
    msg.header.ifindex = vxlan_ifindex;
    msg.header.state = NeighbourState::Permanent;
    msg.attributes.push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));
    
    self.send_neighbour_message(msg, NLM_F_ACK).await?;
    
    Ok(())
}
```

### 3A.5 Configuration: Map VNI to VXLAN Interface
**Interim solution (Phase 3A):**
```toml
# Example config
[vxlan.vni_map]
100 = "vxlan100"  # VNI 100 → vxlan100 interface
200 = "vxlan200"
```

Or accept via CLI/management API.

### 3A.6 Testing: End-to-End
**Functional test:**
1. Set up VXLAN interface: `ip link add vxlan100 type vxlan id 100 dev eth0`
2. Set up bridge: `ip link add br0 type bridge && ip link set vxlan100 master br0`
3. Start zebra-rs with BGP + EVPN config
4. Advertise Type-2 route from peer
5. Verify: `bridge fdb show` shows MAC entry
6. Send VXLAN packet, verify FDB lookup works

**Limitation to document:**
```
⚠️ Phase 3A Limitation: Remote VTEP
The remote tunnel endpoint IP cannot be set via netlink RTM_NEWNEIGH.
Workaround: Configure VXLAN tunnel endpoints separately:
  ip link set vxlan100 remote <PEER_IP> [remote <PEER_IP2>] ...
  
Phase 3B will improve this by extending netlink-packet-route.
```

**Milestone:** MACs installed in kernel via RTM_NEWNEIGH. End-to-end forwarding works with pre-configured VXLAN tunnels.

---

## Phase 3B: Remote VTEP Support [3-5 days] — PARALLEL

**Goal:** Extend netlink-packet-route to support remote VTEP, eliminate Phase 3A workaround.

### 3B.1 Investigate Kernel Encoding
**Research:**
- Check Linux `drivers/net/vxlan.c` for how remote VTEP is encoded
- Review `iproute2` source for bridge FDB handling
- Determine: Is remote VTEP in netlink attribute or separate message type?

**Likely options:**
1. **NDA_FDB_EXT_ATTRS** (extended FDB attributes) — uncomment & extend
2. **Custom attribute in NDA_LLADDR packet** — parse special cases
3. **Separate netlink message type** — RTM_NEWMDB or vendor extension

### 3B.2 Extend netlink-packet-route
**File:** `../netlink-packet-route/src/neighbour/attribute.rs`

```rust
// Uncomment and extend
const NDA_FDB_EXT_ATTRS: u16 = 14;
const NDA_REMOTE_VTEP: u16 = 15;  // Proposed (may not exist in kernel)

#[derive(Debug, Clone)]
pub enum NeighbourAttribute {
    // ... existing ...
    RemoteVtep(IpAddr),         // If kernel supports it
    FdbExtAttrs(FdbExtAttrs),   // If we use extended attrs
    // ... other ...
}

#[derive(Debug, Clone)]
pub struct FdbExtAttrs {
    pub flags: u8,
    pub nh_id: Option<u32>,     // Nexthop object ID
}
```

### 3B.3 Extend rtnetlink Builder
**File:** `../rtnetlink/src/neighbour/add.rs`

```rust
impl NeighbourAddRequest {
    pub fn remote_vtep(mut self, addr: IpAddr) -> Self {
        // Set NDA_REMOTE_VTEP or equivalent
        self.message_mut()
            .attributes
            .push(NeighbourAttribute::RemoteVtep(addr));
        self
    }
}
```

### 3B.4 Update FIB to Use Remote VTEP
**File:** `zebra-rs/src/fib/netlink/handle.rs`

```rust
async fn handle_fib_mac_add(
    &mut self,
    vni: u32,
    mac: MacAddr,
    tunnel_endpoint: Option<IpAddr>,  // Now used!
    flags: u8,
    seq: u32,
) -> Result<()> {
    // ... existing setup ...
    
    // ✨ NEW: Set remote VTEP (Phase 3B)
    if let Some(vtep_ip) = tunnel_endpoint {
        msg.attributes.push(NeighbourAttribute::RemoteVtep(vtep_ip));
    }
    
    self.send_neighbour_message(msg, NLM_F_REPLACE).await?;
    Ok(())
}
```

**Milestone:** Remote VTEP is configurable via netlink. Full production-ready FIB install.

---

## Phase 4: Advanced Features [PARALLEL, 5+ days]

Can happen in parallel with Phase 3B. No blocking dependencies.

### 4.1 Multicast (Type 3) Routes — MDB Support
**Requires:** RTM_NEWMDB implementation in netlink-packet-route

```rust
// Uncomment in netlink-packet-route/src/message.rs:68-70
const RTM_NEWMDB: u16 = 84;
const RTM_DELMDB: u16 = 85;
const RTM_GETMDB: u16 = 86;

// Implement MdbMessage structures + rtnetlink builders
```

### 4.2 ESI Handling (Multi-Homing)
**Add to Phase 1 structures:**
```rust
esi: Option<[u8; 10]>,  // Already reserved in Message::MacAdd
```

**Extraction from attributes:**
```rust
fn extract_esi_from_evpn_route(rib: &BgpRib) -> Option<[u8; 10]> {
    // Extract Ethernet Segment ID from route attributes
}
```

### 4.3 MAC Mobility Tracking
**Already captured in Phase 2:**
```rust
seq: u32  // MAC mobility sequence number
```

**Use for:**
- Detect MAC flapping (seq goes backward → likely loop)
- Prevent blackholes during MAC move
- Sticky MAC handling

### 4.4 Multi-VNI Support
**Phase 1 already supports:** `(vni, mac)` tuple allows same MAC across VNIs.

**Add monitoring:**
```rust
pub fn show_mac_table_summary(&self) -> String {
    // Group by VNI, show counts
}
```

### 4.5 Integration Tests
**Setup:**
- Containerized VXLAN topology (netns)
- BGP speaker (e.g., frr in container)
- Packet capture + verification

**Test scenarios:**
- Type 2 route → MAC installed → forwarding works
- MAC move (sticky sequence)
- Multi-homing failover
- Type 3 multicast routes

---

## Timeline & Milestones

| Phase | Component | Duration | Blocker? | Testable? |
|-------|-----------|----------|----------|-----------|
| **1** | RIB (Message, mac_table) | 1-2 days | YES | Unit tests |
| **2** | BGP export (route_evpn_export) | 2-3 days | YES | Integration (MAC→RIB) |
| **3A** | FIB kernel install (RTM_NEWNEIGH) | 2-3 days | NO | E2E (MAC in kernel) |
| **3B** | netlink remote VTEP | 3-5 days | NO | Production-ready |
| **4** | Advanced (MDB, ESI, etc) | 5+ days | NO | Optional enhancements |

**Critical path:** Phase 1 → Phase 2 → Phase 3A (5-8 days for E2E)

**Parallel work:** Phase 3B while finishing Phase 2/3A

---

## Work Breakdown

### Phase 1: RIB Foundation
**Tasks:**
- [ ] Define Message::MacAdd/Del in rib/inst.rs
- [ ] Add MacEntry struct and mac_table to Rib
- [ ] Implement mac_add/mac_del handlers
- [ ] Add show l2 mac table command
- [ ] Unit tests: message creation, table operations
- **Estimated:** 8-10 hours

### Phase 2: BGP Export
**Tasks:**
- [ ] Extract helper functions (VNI, flags, tunnel_endpoint)
- [ ] Implement route_evpn_export_selected()
- [ ] Integrate with route_evpn_update() and route_evpn_withdraw()
- [ ] Unit tests: extraction functions
- [ ] Integration tests: BGP → RIB message flow
- **Estimated:** 12-16 hours

### Phase 3A: FIB Kernel Install
**Tasks:**
- [ ] Implement handle_fib_mac_add/del in FIB
- [ ] Build RTM_NEWNEIGH NeighbourMessage
- [ ] Set NDA_LLADDR, NDA_VNI, NDA_SRC_VNI, NDA_PORT
- [ ] Send via rtnetlink
- [ ] Add VNI→VXLAN ifindex mapping
- [ ] Functional tests: kernel FDB verification
- [ ] Document Phase 3A limitations
- **Estimated:** 12-16 hours

### Phase 3B: Remote VTEP (Parallel)
**Tasks:**
- [ ] Research kernel encoding of remote VTEP
- [ ] Extend netlink-packet-route (NeighbourAttribute)
- [ ] Extend rtnetlink (NeighbourAddRequest builder)
- [ ] Update FIB to use remote VTEP
- [ ] Tests: netlink with remote endpoint
- **Estimated:** 16-24 hours (research-dependent)

### Phase 4: Advanced Features (Parallel)
**Tasks per feature:**
- [ ] MDB (Type 3): Implement RTM_NEWMDB handling
- [ ] ESI: Extract from attributes, pass to kernel
- [ ] MAC mobility: Track & use sequence number
- [ ] Tests: per-feature scenarios
- **Estimated:** 16-32 hours (varies by feature)

---

## Risk Mitigation

### Risk: netlink-packet-route gaps block remote VTEP
**Mitigation:**
- Phase 3A provides working baseline (workaround)
- Phase 3B can happen in parallel without blocking E2E
- If netlink extension is complex, use message_mut() + custom encoding temporarily

### Risk: VXLAN interface discovery is complex
**Mitigation:**
- Phase 3A: Accept manual VNI→ifindex mapping
- Phase 3B: Integrate with RIB's VXLAN state table
- Fallback: CLI parameter for ifindex

### Risk: BgpRib/BgpAttr structures don't support required extraction
**Mitigation:**
- Phase 2: Add stub implementations that return defaults
- Iterate on attribute parsing as bgp-packet improves
- Document assumptions about attribute presence

### Risk: Kernel version differences in netlink FDB
**Mitigation:**
- Phase 3A: Target modern kernels (5.0+)
- Phase 3B: Use feature flags for optional attributes
- Add kernel version check on startup

---

## Definition of Done

### Phase 1
- [x] Message types defined and buildable
- [x] RIB handler processes MacAdd/MacDel
- [x] mac_table populated and queryable
- [x] show l2 mac table works

### Phase 2
- [x] BGP EVPN routes flow to RIB as MacAdd
- [x] Withdrawal triggers MacDel
- [x] Extracted VNI, flags, seq match expected values
- [x] Integration test: EVPN update → RIB storage

### Phase 3A
- [x] RTM_NEWNEIGH sent to kernel
- [x] bridge fdb show displays installed MACs
- [x] Packets forwarded via VXLAN FDB
- [x] Phase 3A limitation documented & communicated

### Phase 3B
- [x] Remote VTEP sent via netlink
- [x] No workaround needed
- [x] netlink-packet-route extended (if needed)

### Phase 4 (each feature)
- [x] Type 3 routes installed in kernel
- [x] ESI handled without errors
- [x] MAC mobility sequence tracked
- [x] Integration tests passing

---

## Testing Strategy

### Unit Tests
- Extraction functions (VNI, flags, seq from attributes)
- Message creation and serialization
- mac_table operations

### Integration Tests
- BGP peer sends EVPN Type 2 → MAC in RIB → FDB in kernel
- Withdrawal → MAC deleted from kernel
- Multiple VNIs simultaneously
- Flag combinations (sticky, gateway, router)

### Functional Tests
- Containerized VXLAN topology
- packet-in-packet verification (VXLAN encapsulation)
- Failover scenarios
- MAC mobility

### Load Tests (Phase 4)
- 1000+ MACs per VNI
- 100+ VNIs
- Kernel FDB scalability

---

## Documentation & Communication

### Interim Deliverables
After Phase 3A:
```markdown
# EVPN L2 Forwarding Implementation Status

## What Works
- Type 2 (MAC/IP) routes learned via BGP EVPN
- MACs installed in kernel FIB via RTM_NEWNEIGH
- Forwarding via VXLAN with pre-configured tunnels

## Known Limitations (Phase 3A)
- Remote VTEP IP must be configured separately:
  `ip link set vxlan0 remote <PEER_IP>`
- Not settable via BGP attribute (Phase 3B planned)

## Next Phase
- Extend netlink to support remote VTEP via BGP
- MDB support for Type 3 multicast routes
- Multi-homing (ESI) handling
```

### Final Documentation (Phase 3B+)
```markdown
# EVPN L2 Forwarding — Production Ready

## Feature Complete
- Full Type 2 route support with remote VTEP
- Type 3 multicast routes
- Multi-homing with ESI
- MAC mobility detection
- [more features]

## Configuration
[Examples with VXLAN + BGP]

## Troubleshooting
[Common issues and mitigation]
```

---

## Decision Points

### Decision 1: VNI→VXLAN ifindex Mapping
**Option A (Phase 3A):** Manual config file or CLI
- **Pros:** Simple, no dependencies
- **Cons:** Requires manual configuration
- **Recommendation:** START HERE, defer autodetection

**Option B (Phase 3B+):** Auto-discover from RIB/VXLAN config
- **Pros:** Zero config
- **Cons:** More complex, depends on RIB state

### Decision 2: Remote VTEP Netlink Encoding
**Option A:** Use extended attributes (NDA_FDB_EXT_ATTRS)
- **Pros:** Standards-based
- **Cons:** May need kernel upgrade for full support

**Option B:** Custom attribute + message_mut()
- **Pros:** Works today
- **Cons:** Fragile, not future-proof

**Option C:** Via separate netlink command
- **Pros:** Flexible
- **Cons:** Multiple messages per MAC

**Recommendation:** Research during Phase 2, decide in Phase 3B kickoff

### Decision 3: Phase 4 Priority
**High:** Type 3 routes (multicast) — required for full EVPN
**Medium:** ESI/multi-homing — advanced but common
**Low:** MAC mobility sequence tracking — nice-to-have

---

## Success Metrics

### End of Phase 3A
✅ EVPN Type 2 MACs forwarded via VXLAN  
✅ Kernel FIB populated by BGP EVPN routes  
✅ Functional tests passing  
⚠️ Remote VTEP requires manual config

### End of Phase 3B
✅ All Phase 3A + remote VTEP via netlink  
✅ No manual tunnel config needed  
✅ Production deployment ready  

### End of Phase 4
✅ Type 3 multicast support  
✅ Multi-homing (ESI) support  
✅ Comprehensive test coverage  
✅ Full RFC 7432 compliance  

