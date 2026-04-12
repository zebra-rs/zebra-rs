# BGP EVPN L2 MAC Address Installation - Gap Analysis & Implementation Plan

## Executive Summary

**Gap:** EVPN MAC/IP advertisement routes are received and stored in BGP Local-RIB with best path selection, but **no mechanism exists to export these MAC entries to the kernel FIB for L2 table installation**. The data stops at route selection—it never reaches the dataplane.

**FRR Reference:** FRR closes this gap via:
1. `evpn_route_select_install()` — called after route selection
2. `evpn_zebra_install()` — extracts MAC info and sends to zebra daemon
3. `bgp_zebra_send_remote_macip()` — ZEBRA_REMOTE_MACIP_ADD/DEL netlink messages

---

## Current State in zebra-rs

### What Exists ✅
- **EVPN route parsing** (`crates/bgp-packet/src/attrs/nlri_evpn.rs`)
  - `EvpnRouteType::MacIpAdvRoute` (Type 2)
  - `EvpnRoute::Mac` struct with: MAC address, VNI, ESI, ether tag

- **BGP EVPN RIB storage** (`zebra-rs/src/bgp/route.rs`)
  - Per-RD Adj-RIB-In/Out tables for EVPN
  - Local-RIB with best path selection: `select_best_path_evpn()` at line 1103
  - Route update/withdraw handling in `route_evpn_update()` / `route_evpn_withdraw()`

- **Display/monitoring** (`zebra-rs/src/bgp/show.rs`)
  - `show ip bgp l2vpn evpn` commands

### What's Missing ❌
1. **No RIB Message Type for MAC entries**
   - `rib/inst.rs` defines: `Ipv4Add/Del`, `Ipv6Add/Del`, `IlmAdd/Del`, `BridgeAdd/Del`, `VxlanAdd/Del`
   - Missing: `MacAdd { vni, mac, tunnel_endpoint }`  / `MacDel { vni, mac }`

2. **No Export Path After Best Path Selection**
   - IPv4 routes → `route_advertise_to_peers()` (advertise to BGP peers)
   - **EVPN routes → silence** (no further processing)
   - Missing function analogous to FRR's `evpn_route_select_install()`

3. **No Tunnel/Nexthop Binding**
   - EVPN nexthop is encoded in BGP attributes (`BgpAttr::nexthop`), but unused for L2
   - No code to extract tunnel endpoint IP from route attributes

4. **No L2 State Management in RIB**
   - No per-VNI MAC table (`mac_table: BTreeMap<(VNI, MacAddr), RibEntry>`)
   - No tracking of installed vs. pending MACs
   - No mechanism to handle MAC mobility or aging

5. **No FIB Integration**
   - FIB message.rs has no L2-specific messages
   - No netlink construction for L2 table operations

---

## Reference: FRR Implementation Pattern

### Data Flow in FRR

```
BGP Receives EVPN UPDATE
  ↓ route_evpn_update()
  → Store in Adj-RIB-In
  ↓ evpn_route_select_install()  ← KEY FUNCTION
  → Compute best path
  → If best path changed:
    → Check route type (MAC-IP vs multicast)
    → Extract:
      • MAC address
      • VNI
      • VTEP IP (from attr->mp_nexthop_global_in)
      • Flags (sticky, gateway, router, sync)
      • MAC mobility sequence number
    → Call evpn_zebra_install()
  ↓ evpn_zebra_install()
  → Determine nexthop family (IPv4 vs IPv6)
  → Extract VTEP IP: pi->attr->mp_nexthop_global_in (v4) or mp_nexthop_global (v6)
  → Call bgp_zebra_send_remote_macip()
  ↓ bgp_zebra_send_remote_macip()
  → Create zclient message: ZEBRA_REMOTE_MACIP_ADD
  → Populate:
    • VNI: vpn->vni
    • MAC: mac->octet (6 bytes)
    • IP: p->prefix.macip_addr.ip (IPv4/v6, optional)
    • Remote VTEP: vtep_ip (from nexthop)
    • Flags: STICKY | GW | ROUTER | SYNC_PATH | PROXY
    • Sequence number: mac_mobility_seqnum()
    • ESI (Ethernet Segment ID, may be zero)
  → Send to zebra daemon

Zebra Receives ZEBRA_REMOTE_MACIP_ADD
  ↓ Process in zebra/zapi_sock.c
  → Update kernel via netlink (bridge FDB or vxlan)
  → Maintain L2 state table
  → Generate learning notifications (for mac aging)
```

**Key FRR structures:**
```c
// bgp_evpn.c:918
static enum zclient_send_status bgp_zebra_send_remote_macip(
  struct bgp *bgp,
  struct bgpevpn *vpn,              // VNI context
  const struct prefix_evpn *p,      // EVPN prefix (contains MAC)
  const struct ethaddr *mac,        // Optional override MAC
  struct ipaddr *remote_vtep_ip,    // Tunnel endpoint
  int add,                           // 1=add, 0=delete
  uint8_t flags,                     // STICKY | GW | ROUTER | etc
  uint32_t seq,                      // MAC mobility sequence
  esi_t *esi                         // Ethernet Segment ID
)

// bgp_evpn.c:1283
enum zclient_send_status evpn_zebra_install(
  struct bgp *bgp,
  struct bgpevpn *vpn,
  const struct prefix_evpn *p,
  struct bgp_path_info *pi          // Selected route
)
// Extracts vtep_ip from pi->attr->mp_nexthop_global_in

// bgp_evpn.c:1499
int evpn_route_select_install(
  struct bgp *bgp,
  struct bgpevpn *vpn,
  struct bgp_dest *dest,
  struct bgp_path_info *pi
)
// Called after best path changes, triggers evpn_zebra_install()
```

---

## Implementation Plan for zebra-rs

### Phase 1: Extend RIB Message Types
**File:** `zebra-rs/src/rib/inst.rs`

Add to `Message` enum:
```rust
pub enum Message {
    // ... existing ...
    MacAdd {
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,           // STICKY=0x01, GW=0x02, ROUTER=0x04, SYNC=0x08
        seq: u32,            // MAC mobility sequence
        esi: Option<[u8; 10]>,  // Ethernet Segment ID
    },
    MacDel {
        vni: u32,
        mac: MacAddr,
    },
}
```

Add handlers in `Rib::process_msg()`:
- `Message::MacAdd` → call `mac_add()` method
- `Message::MacDel` → call `mac_del()` method

### Phase 2: L2 State Management in RIB
**File:** `zebra-rs/src/rib/inst.rs`

Add to `Rib` struct:
```rust
pub struct Rib {
    // ... existing ...
    pub mac_table: BTreeMap<(u32, MacAddr), RibEntry>,  // (VNI, MAC) → entry
}
```

Implement methods:
```rust
fn mac_add(&mut self, vni: u32, mac: MacAddr, entry: RibEntry) {
    self.mac_table.insert((vni, mac), entry);
}

fn mac_del(&mut self, vni: u32, mac: MacAddr) {
    self.mac_table.remove(&(vni, mac));
}
```

### Phase 3: Create EVPN Export Function
**File:** `zebra-rs/src/bgp/route.rs`

New function after `route_evpn_withdraw()`:
```rust
/// Export selected EVPN MAC entry to RIB for kernel installation
fn route_evpn_export_selected(
    rd: RouteDistinguisher,
    prefix: &EvpnPrefix,
    selected: &[BgpRib],  // Best path selection result
    bgp: &mut BgpTop,
) {
    // If no selected path, withdraw
    if selected.is_empty() {
        if let EvpnPrefix::MacIp { mac, .. } = prefix {
            let msg = Message::MacDel {
                vni: extract_vni_from_rd(rd),
                mac: MacAddr::from(*mac),
            };
            let _ = bgp.rib_tx.send(msg);
        }
        return;
    }

    // Extract best path
    let best = &selected[selected.len() - 1];
    
    if let EvpnPrefix::MacIp { mac, eth_tag, ip_addr, .. } = prefix {
        // Extract tunnel endpoint from nexthop
        let tunnel_endpoint = best.nexthop.as_ref()
            .and_then(|nh| extract_ip_from_nexthop(nh));

        let msg = Message::MacAdd {
            vni: extract_vni_from_rd(rd),
            mac: MacAddr::from(*mac),
            tunnel_endpoint,
            flags: 0,  // TODO: extract from attributes
            seq: 0,    // TODO: extract from attributes
            esi: None, // TODO: extract from attributes
        };
        let _ = bgp.rib_tx.send(msg);
    }
}
```

Call site: In `route_evpn_update()` after `select_best_path_evpn()`:
```rust
pub fn route_evpn_update(...) {
    // ... existing code ...
    let _ = bgp.local_rib.update_evpn(rd, prefix.clone(), rib);
    
    // NEW: Export to RIB
    let selected = bgp.local_rib.select_best_path_evpn(&rd, &prefix);
    route_evpn_export_selected(rd, &prefix, &selected, bgp);
}
```

### Phase 4: Extract EVPN Data from Attributes
**File:** `zebra-rs/src/bgp/route.rs`

Helper functions:
```rust
fn extract_vni_from_rd(rd: RouteDistinguisher) -> u32 {
    // VNI encoded in RD: Type 2 RD: [0:VNI][0:0]
    // Type: 2-byte (0, 0 for Type 2)
    // Value: 3 bytes VNI + 2 bytes index
    match rd {
        // Extract from RD structure
    }
}

fn extract_flags_from_attr(attr: &BgpAttr) -> u8 {
    let mut flags = 0u8;
    
    // Check for sticky MAC (extended community)
    if attr.ecom.iter().any(|ec| is_sticky_mac(ec)) {
        flags |= 0x01; // STICKY
    }
    
    // Check for gateway MAC
    if attr.ecom.iter().any(|ec| is_gateway_mac(ec)) {
        flags |= 0x02; // GW
    }
    
    flags
}

fn extract_mac_mobility_seq(attr: &BgpAttr) -> u32 {
    // Extract from MAC Mobility extended community
    attr.ecom.iter()
        .find_map(|ec| parse_mac_mobility_seq(ec))
        .unwrap_or(0)
}
```

### Phase 5: FIB Integration (Linux netlink)
**File:** `zebra-rs/src/fib/netlink/handle.rs`

Add handlers for `Message::MacAdd` / `Message::MacDel`:
```rust
FibMessage::MacAdd { vni, mac, tunnel_endpoint, seq, flags } => {
    // Use netlink bridge MDB or vxlan FDB
    // ip link set dev vxlan0 type vxlan vni $vni
    // bridge fdb add $mac dev vxlan0 src_vni $vni dst $tunnel_endpoint static
}

FibMessage::MacDel { vni, mac } => {
    // bridge fdb del $mac dev vxlan0 src_vni $vni
}
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **MAC keyed by (VNI, MAC) tuple** | EVPN does not bind MACs to local bridges—entries are tunnel-based. Multiple VNIs can have same MAC. |
| **Store tunnel_endpoint in RIB entry** | Needed for FIB lookup; avoids re-fetching from BGP route each time. |
| **Flags field in Message** | Matches FRR: sticky, gateway, router, sync status determine kernel behavior. |
| **Sequence number for MAC mobility** | FRR requires this for proper MAC move detection; prevents blackholes during mobility. |
| **Export after select_best_path** | Mirrors IPv4 flow: selection triggers downstream exports (peers + RIB). |

---

## Testing Strategy

1. **Unit:** Test `extract_vni_from_rd()` with RFC 7432 RD examples
2. **Integration:**
   - Create EVPN BGP session, advertise Type-2 (MAC-IP) route
   - Verify RIB receives `MacAdd` message
   - Verify FIB installs entry in kernel
   - Withdraw route, verify `MacDel` sent
3. **Functional:**
   - VXLAN traffic forwarding for learned MACs
   - MAC mobility (sticky bit, sequence number)
   - Multi-homing (ESI handling, sync paths)

---

## Appendix: FRR Message Format (for reference)

```c
// From bgp_evpn.c:951-988
stream_putl(s, vpn ? vpn->vni : 0);           // 4 bytes VNI
stream_put(s, &mac->octet, ETH_ALEN);         // 6 bytes MAC
stream_putw(s, ipa_len);                      // 2 bytes IP addr length
if (ipa_len) stream_put(s, ip_addr, ipa_len); // 0, 4, or 16 bytes IP
stream_put_ipaddr(s, &vtep_ip);               // 4 or 16 bytes VTEP
stream_putc(s, flags);                        // 1 byte flags
stream_putl(s, seq);                          // 4 bytes MAC mobility seq
stream_put(s, esi, 10);                       // 10 bytes ESI
```

Total: 4 + 6 + 2 + [IP] + [VTEP] + 1 + 4 + 10 = ~35+ bytes per entry

---

## Next Steps

1. **Design review** with user on Message structure and flag definitions
2. **Phase 1 implementation:** RIB message types + handlers
3. **Phase 2:** L2 state tracking
4. **Phase 3-4:** BGP export logic + attribute extraction
5. **Phase 5:** FIB netlink integration (detailed bridge MDB/VXLAN FDB syntax)
6. **Testing:** Unit + integration tests with real VXLAN interfaces
