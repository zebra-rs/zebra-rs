# EVPN L2 MAC FIB Installation - Kernel Interface Gap Analysis

## Overview

This document analyzes the capability gap in netlink-packet-route and rtnetlink crates for installing EVPN-learned L2 MAC addresses into the Linux kernel via netlink.

**Status:** rtnetlink provides basic bridge FDB support via neighbour messages, but **missing critical attributes for VXLAN tunnel endpoints and advanced EVPN features**.

---

## Current Capabilities

### ✅ Available: Bridge FDB via RTM_NEWNEIGH/RTM_DELNEIGH

**netlink-packet-route:**
- Message type: `RTM_NEWNEIGH` (28), `RTM_DELNEIGH` (29), `RTM_GETNEIGH` (30)
- Family: `AddressFamily::Bridge`
- Header: `NeighbourHeader` (12 bytes)
  - `family: u8` (AF_BRIDGE = 7)
  - `ifindex: u32` (bridge interface index)
  - `state: u16` (NUD_* flags like PERMANENT)
  - `flags: u8` (NTF_* flags like SELF, MASTER)
  - `kind: u8` (RouteType, typically UNSPEC for FDB)

**Supported NeighbourAttributes:**
```
NDA_LLADDR (2)        → MAC address (6 bytes)        ✅ Available
NDA_VLAN (5)          → VLAN ID (2 bytes)            ✅ Available
NDA_PORT (6)          → UDP port (2 bytes, for VXLAN)✅ Available
NDA_VNI (7)           → VXLAN VNI (4 bytes)          ✅ Available
NDA_IFINDEX (8)       → Interface index (4 bytes)    ✅ Available
NDA_SRC_VNI (11)      → Source VNI (4 bytes)         ✅ Available
NDA_PROTOCOL (12)     → Route protocol (1 byte)      ✅ Available
```

**rtnetlink:**
```rust
pub fn add_bridge(&self, index: u32, lla: &[u8]) -> NeighbourAddRequest
pub fn del(&self, message: NeighbourMessage) -> NeighbourDelRequest
pub fn message_mut(&mut self) -> &mut NeighbourMessage  // Access to raw attributes
```

### ❌ Missing: MDB (Multicast Database) & Advanced VXLAN Features

**Not implemented (commented out):**
```c
// const RTM_NEWMDB: u16 = 84;   // Multicast group management
// const RTM_DELMDB: u16 = 85;   // (commented in netlink-packet-route/src/message.rs:68)
// const RTM_GETMDB: u16 = 86;
```

**Missing attributes in NeighbourAttribute enum:**
```
// const NDA_FDB_EXT_ATTRS: u16 = 14;   // Extended FDB attributes (commented out)
// const NDA_NH_ID: u16 = 13;           // Nexthop object ID
```

**Not accessible via rtnetlink builder pattern:**
- No direct method for setting `NDA_VNI` / `NDA_SRC_VNI` on NeighbourAddRequest
- No method for setting tunnel destination IP (remote VTEP)
- No helper methods for VXLAN-specific FDB attributes
- Port and VNI require manual `message_mut()` manipulation

---

## What's Missing for EVPN L2 MAC Installation

### Gap 1: Remote VTEP (Tunnel Endpoint) Address

**Required:** To install MAC in VXLAN tunnel, kernel needs:
- Remote VTEP IP address (tunnel destination)
- Port (UDP 4789 for VXLAN)

**Linux kernel expects:** (via `bridge fdb add`)
```bash
bridge fdb add <MAC> dev vxlan0 dst <REMOTE_IP> src_vni <VNI> vni <VNI>
```

**Netlink encoding:** 
- Remote destination typically encoded in:
  - `NDA_DST` attribute (destination address) — but this is for IP neighbors, not VXLAN FDB
  - Or as a nested `NDA_FDB_EXT_ATTRS` (not implemented)

**Current limitation:** RTM_NEWNEIGH neighbour messages don't have a standard way to specify the tunnel endpoint. The port is available (`NDA_PORT`), but not the IP address of the remote VTEP.

**Workaround:** Use raw `message_mut()` to add custom attributes, but requires manual encoding.

### Gap 2: Extended FDB Attributes (NDA_FDB_EXT_ATTRS)

**Missing:** RFC calls for extended FDB attributes structure:
```c
struct nda_fdb_ext_attrs {
    u8 flags;    // NDA_FDB_EXT_FLAG_STATIC, etc
    u8 __pad;
    u16 __pad2;
    u32 nh_id;   // Nexthop object ID
};
```

**Used for:**
- Static vs dynamic FDB entries
- Nexthop object IDs (for advanced routing)
- Multi-homing (MH) flags

**Status:** Commented out in netlink-packet-route, not exposed in rtnetlink builders.

### Gap 3: ESI (Ethernet Segment Identifier) Handling

**Required for:** Multi-homing scenarios (RFC 8365)

**Missing:** No netlink attribute for ESI in current implementation.

**FRR sends:** 10-byte ESI value with every MAC advertisement (see bgp_evpn.c:985)

**Kernel handling:** Typically encoded in extended FDB attributes or as part of MDB entries.

### Gap 4: MAC Mobility Sequence Number

**Required for:** Detecting and handling MAC moves (sticky MAC, MAC flapping)

**FRR sends:** 32-bit sequence number with MAC entries

**Missing:** No standard netlink attribute for MAC mobility sequence number in neighbour messages.

**Kernel handling:** Can be inferred from STICKY flag + timestamp, but explicit sequence number not available.

### Gap 5: Missing Netlink Message Types

**MDB (Multicast Database)** — RTM_NEWMDB not implemented:
- Used for multicast group membership
- Needed for EVPN Type 3 (Inclusive Multicast) routes
- Requires separate message structure from NeighbourMessage

---

## Technical Details: Bridge FDB Entry Format

### Working Example (Basic Bridge FDB)
```rust
use rtnetlink::{new_connection, Handle};
use netlink_packet_route::neighbour::NeighbourAttribute;

async fn add_bridge_fdb() {
    let (conn, handle, _) = new_connection().unwrap();
    tokio::spawn(conn);
    
    // Add bridge FDB entry: MAC 00:11:22:33:44:55 on interface vxlan0 (index 3)
    handle
        .neighbour()
        .add_bridge(3, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        .replace()  // NLM_F_REPLACE flag
        .execute()
        .await
        .unwrap();
}
```

### Missing: VXLAN FDB with Remote Endpoint
```rust
// DESIRED (doesn't exist)
handle
    .neighbour()
    .add_vxlan_fdb(vxlan_ifindex, mac)
    .vni(100)
    .src_vni(100)
    .remote_vtep(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))  // ← MISSING
    .execute()
    .await
```

### Workaround: Manual Attribute Manipulation
```rust
handle
    .neighbour()
    .add_bridge(vxlan_ifindex, mac)
    .replace()
    .message_mut()
    .attributes
    .push(NeighbourAttribute::Vni(vni));
    
.message_mut()
    .attributes
    .push(NeighbourAttribute::SourceVni(src_vni));

// Still can't easily add remote VTEP IP — would need custom attribute
.execute()
    .await
```

---

## Linux Kernel Bridge FIB Format Reference

### Bridge FDB Entry (via netlink)
```
RTM_NEWNEIGH / RTM_DELNEIGH
  header.family = AF_BRIDGE (7)
  header.ifindex = <vxlan_dev_index>
  header.state = NUD_PERMANENT | NUD_REACHABLE
  header.flags = NTF_SELF | NTF_EXT_LEARNED | NTF_STICKY
  
  attributes:
    NDA_LLADDR → MAC [6 bytes]
    NDA_VNI → VNI [4 bytes]
    NDA_SRC_VNI → Source VNI [4 bytes]
    NDA_PORT → UDP port [2 bytes]
    NDA_IFINDEX → Target interface index [4 bytes]
    NDA_PROTOCOL → Route protocol [1 byte]
    [NDA_FDB_EXT_ATTRS → Extended attributes] ← NOT SUPPORTED
```

### Kernel Source Reference
- **Linux:** `include/uapi/linux/neighbour.h` (NDA_* constants)
- **Bridge kernel module:** `net/bridge/br_fdb.c` (fdb_add, fdb_delete)
- **VXLAN module:** `drivers/net/vxlan.c` (vxlan_fdb_parse)

---

## Implementation Options

### Option A: Use Existing RTM_NEWNEIGH + Manual Attributes
**Pros:**
- Works today with existing netlink-packet-route + rtnetlink
- No upstream changes needed
- Sufficient for basic VXLAN FDB

**Cons:**
- Requires manual attribute construction
- Can't set remote VTEP IP (blocker for many EVPN scenarios)
- Workaround is fragile and not future-proof

**Example:**
```rust
let mut req = handle.neighbour().add_bridge(ifindex, &mac);
req.message_mut().attributes.push(NeighbourAttribute::Vni(vni));
req.message_mut().attributes.push(NeighbourAttribute::SourceVni(vni));
// Can't easily add remote VTEP without encoding custom attribute bytes
req.execute().await?;
```

### Option B: Extend rtnetlink with VXLAN FDB Builder
**Pros:**
- Type-safe builder pattern
- Encapsulates complexity
- Future-proof for new attributes

**Cons:**
- Requires changes to rtnetlink crate
- Still need netlink-packet-route to expose missing attributes

**Implementation:**
1. Add `pub fn add_vxlan_fdb()` to NeighbourHandle
2. Extend NeighbourAddRequest with:
   - `.vni(u32)`
   - `.src_vni(u32)`
   - `.remote_vtep(IpAddr)` ← requires netlink-packet-route support
   - `.port(u16)`

### Option C: Add Remote VTEP Support to netlink-packet-route
**Pros:**
- Solves fundamental gap
- Needed for production EVPN

**Cons:**
- Requires changes to netlink-packet-route
- Need to determine correct netlink attribute encoding
- May need custom/extended attributes (NDA_FDB_EXT_ATTRS)

**Implementation:**
1. Uncomment/enable NDA_FDB_EXT_ATTRS
2. Add NeighbourAttribute::RemoteVtep(IpAddr) or similar
3. Handle in encode/decode logic

---

## Recommended Path Forward

### Phase 1: Unblock Basic VXLAN FDB Installation
**Use Option A (workaround)** via `message_mut()`:
- Sufficient for Type-2 (MAC/IP) routes with known tunnel
- Works with current crates, no external changes needed
- Note remote VTEP limitation for future

### Phase 2: Extend netlink-packet-route
**Enable NDA_FDB_EXT_ATTRS support:**
- Uncomment RTM_*MDB constants if multicast support needed
- Extend NeighbourAttribute to include remote endpoint info
- Consider how FRR encodes remote VTEP (may be in separate netlink msg type)

### Phase 3: Upstream Changes to rtnetlink
**Add fluent builder methods:**
```rust
pub fn add_vxlan_fdb() → NeighbourAddRequest
    .vni(u32)
    .src_vni(u32)
    .port(u16)
    .remote_vtep(IpAddr)  // Once netlink-packet-route supports this
```

---

## FRR Reference: How Zebra Handles VXLAN FDB

**From ref/zebra/zapi_sock.c:**
```c
// Zebra receives ZEBRA_REMOTE_MACIP_ADD from bgpd
struct zapi_macip_msg {
    vni_t vni;              // VXLAN VNI
    struct ethaddr mac;     // 6-byte MAC
    struct ipaddr ip;       // IPv4/v6 (optional)
    struct ipaddr rmac;     // Remote MAC (for gateway)
    uint16_t flags;         // NTF_* flags
    uint32_t seq;           // MAC mobility sequence
    struct ipaddr vtep_ip;  // Remote VTEP ← KEY
    esi_t esi;              // Ethernet Segment ID
};

// Zebra → Linux kernel (RTM_NEWNEIGH)
neighbor_add/delete(
    vni, mac, vtep_ip, port,
    src_vni, flags, seq
)
```

The remote VTEP IP is critical—without it, the kernel can't forward frames. Zebra encodes it into the netlink message.

---

## Summary: What zebra-rs FIB Needs

### Current State
- ✅ Can send RTM_NEWNEIGH with basic bridge FDB attributes
- ✅ RTM_NEWNEIGH supports NDA_VNI, NDA_SRC_VNI, NDA_PORT
- ❌ Cannot specify remote VTEP IP (blocker)
- ❌ No MDB support (needed for Type 3 multicast routes)
- ❌ No extended FDB attributes (NDA_FDB_EXT_ATTRS)

### Workaround (Phase 1)
Use `message_mut()` to manually add VNI/SRC_VNI attributes, accept limitation that remote VTEP must be configured separately (via separate VXLAN configuration).

### Long-term Fix (Phase 2-3)
Extend netlink-packet-route with remote VTEP support, enable MDB message types, add fluent builders to rtnetlink.

---

## Appendix: Linux Kernel Netlink Constants

```c
// From include/uapi/linux/neighbour.h
enum {
    NDA_UNSPEC,
    NDA_DST,          // 1: IP address
    NDA_LLADDR,       // 2: Link layer address (MAC)
    NDA_CACHEINFO,    // 3: Cache info
    NDA_PROBES,       // 4: Probes
    NDA_VLAN,         // 5: VLAN ID
    NDA_PORT,         // 6: Port (VXLAN UDP)
    NDA_VNI,          // 7: VNI
    NDA_IFINDEX,      // 8: Interface index
    NDA_MASTER,       // 9: Master/controller index
    NDA_LINK_NETNSID, // 10: Link namespace ID
    NDA_SRC_VNI,      // 11: Source VNI (VXLAN)
    NDA_PROTOCOL,     // 12: Protocol
    NDA_NH_ID,        // 13: Nexthop ID
    NDA_FDB_EXT_ATTRS,// 14: Extended FDB attributes
    __NDA_MAX
};

#define NUD_INCOMPLETE  0x01
#define NUD_REACHABLE   0x02
#define NUD_STALE       0x04
#define NUD_DELAY       0x08
#define NUD_PROBE       0x10
#define NUD_FAILED      0x20
#define NUD_NOARP       0x40
#define NUD_PERMANENT   0x80

#define NTF_USE      0x01
#define NTF_SELF     0x02
#define NTF_MASTER   0x04
#define NTF_PROXY    0x08
#define NTF_EXT_LEARNED 0x10
#define NTF_OFFLOADED   0x20
#define NTF_STICKY      0x40
#define NTF_ROUTER      0x80
```

