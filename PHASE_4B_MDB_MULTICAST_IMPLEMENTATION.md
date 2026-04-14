# Phase 4B: MDB (Multicast Database) Support Implementation Guide

## Overview

This guide provides a step-by-step approach to implement MDB (Multicast Database) support for EVPN Type 3 (Inclusive Multicast Ethernet Tag) routes in zebra-rs.

## Current State

**In netlink-packet-route/src:**
- ✅ Message types: RTM_NEWMDB (84), RTM_DELMDB (85), RTM_GETMDB (86) exist but are **commented out**
- ❌ No MdbMessage struct or module
- ❌ No MDB attribute types (MDBA_MDB_ENTRY, MDBA_MDB_EATTR, etc.)
- ❌ No MDB flags or states

**In zebra-rs:**
- ✅ Rib has mac_table but no mdb_table
- ❌ No MDB message handling in FibMessage
- ❌ No mdb_add() / mdb_del() in FibHandle

## Phase 4B Implementation Plan

### Step 1: Research MDB Kernel Structure

**Goal:** Understand Linux kernel MDB data structures

**Linux Kernel Reference:** `include/uapi/linux/neighbour.h` and `net/bridge/br_mdb.c`

```c
// From Linux kernel
enum {
    MDBA_UNSPEC,
    MDBA_MDB,           // 1: MDB table
    MDBA_MROUTE,        // 2: Multicast route
    __MDBA_MAX
};

struct br_mdb_entry {
    __u32 ifindex;
    __u8  state;        // MDB_TEMPORARY, MDB_PERMANENT
    __u8  flags;        // MDB_FLAGS_EXT_ATTRS
    struct br_mdb_eaddr {
        __u8 addr_type;
        __u8 addr[6];   // Multicast MAC or address
    } addr;
    __u32 vid;          // VLAN ID
    __u32 unused;
};
```

**Key attributes for VXLAN multicast:**
- Bridge interface index (ifindex)
- Multicast MAC address (224.0.0.0/4 range for IPv4, 33:33:00:00:00:00/16 for IPv6)
- VNI (encoded in VLAN ID for VXLAN)
- Ports: which ports forward multicast (for VXLAN, the remote VTEP list)
- State: PERMANENT for learned, TEMPORARY for transient

### Step 2: Create MDB Module Structure

**New files to create:**

1. **netlink-packet-route/src/mdb/mod.rs**
   - Module exports

2. **netlink-packet-route/src/mdb/header.rs**
   - MdbHeader struct with: interface_family, table_id
   - MdbState enum: Temporary, Permanent

3. **netlink-packet-route/src/mdb/message.rs**
   - MdbMessage struct
   - Parsing and emission logic

4. **netlink-packet-route/src/mdb/attribute.rs**
   - MdbAttribute enum
   - Attributes: MdbEntry, MdbEaddr, VID, Port, Flags

5. **netlink-packet-route/src/mdb/port.rs**
   - Port list handling

### Step 3: Uncomment and Enable MDB in message.rs

**Changes to netlink-packet-route/src/message.rs:**

```rust
// Uncomment constants
const RTM_NEWMDB: u16 = 84;
const RTM_DELMDB: u16 = 85;
const RTM_GETMDB: u16 = 86;

// Add to RouteNetlinkMessage enum
pub enum RouteNetlinkMessage {
    // ... existing variants ...
    NewMdb(MdbMessage),
    DelMdb(MdbMessage),
    GetMdb(MdbMessage),
}

// Add parsing logic
RTM_NEWMDB | RTM_GETMDB | RTM_DELMDB => {
    let msg = MdbMessage::parse(&buf)?;
    RouteNetlinkMessage::NewMdb(msg)
}
```

### Step 4: Implement MdbMessage Structure

**File: netlink-packet-route/src/mdb/message.rs**

```rust
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MdbMessage {
    pub header: MdbHeader,
    pub attributes: Vec<MdbAttribute>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MdbHeader {
    pub family: AddressFamily,      // AF_BRIDGE
    pub index: u32,                 // Interface index (bridge)
}

pub enum MdbAttribute {
    MdbEntry(Vec<u8>),              // Multicast group entry
    SourceList(Vec<u8>),            // Source list (IGMPv3)
    VNI(u32),                       // VXLAN VNI
    Ports(Vec<MdbPort>),            // Forwarding ports
    Flags(u32),                     // MDB flags
    Other(DefaultNla),
}
```

### Step 5: Create EVPN Type 3 Route Handler in BGP

**File: zebra-rs/src/bgp/route.rs**

Add Type 3 route handling:
```rust
/// Extract multicast IP from EVPN Type 3 route
/// Type 3: [type(1) | subtype(1) | RD(8) | ETH_TAG(4) | IP_MCAST_ADDR(4|16)]
fn extract_mcast_addr_from_type3(route: &BgpRoute) -> Option<IpAddr> {
    // Parse multicast address from EVPN route
}

/// Export Type 3 routes to RIB as MDB entries
fn route_evpn_export_type3(&mut self, route: &BgpRoute, withdraw: bool) {
    // Send MdbAdd or MdbDel to RIB
}
```

### Step 6: Extend FibMessage for MDB

**File: zebra-rs/src/fib/message.rs**

```rust
pub enum FibMessage {
    // ... existing variants ...
    MdbAdd {
        ifindex: u32,           // Bridge interface
        mcast_addr: Vec<u8>,    // Multicast address (6 bytes MAC)
        vni: u32,               // VXLAN VNI
        ports: Vec<u32>,        // List of VXLAN tunnel endpoints
        flags: u8,
        seq: u32,
    },
    MdbDel {
        ifindex: u32,
        mcast_addr: Vec<u8>,
        vni: u32,
    },
}
```

### Step 7: Implement mdb_add() and mdb_del() in FibHandle

**File: zebra-rs/src/fib/netlink/handle.rs**

```rust
pub async fn mdb_add(
    &self,
    ifindex: u32,
    mcast_addr: &[u8],
    vni: u32,
    ports: &[u32],
    flags: u8,
    seq: u32,
) {
    // Create RTM_NEWMDB message
    use netlink_packet_route::mdb::{MdbAttribute, MdbMessage};
    
    let mut msg = MdbMessage::default();
    msg.header.family = AddressFamily::Bridge;
    msg.header.index = ifindex;
    
    // Add multicast address
    msg.attributes.push(MdbAttribute::MdbEntry(mcast_addr.to_vec()));
    
    // Add VNI
    msg.attributes.push(MdbAttribute::VNI(vni));
    
    // Add ports
    let mdb_ports = ports.iter()
        .map(|&port| MdbPort { ifindex: port })
        .collect();
    msg.attributes.push(MdbAttribute::Ports(mdb_ports));
    
    // Send netlink message
}

pub async fn mdb_del(&self, ifindex: u32, mcast_addr: &[u8], vni: u32) {
    // Similar to mdb_add but with RTM_DELMDB
}
```

### Step 8: Integrate MDB Handling in RIB

**File: zebra-rs/src/rib/inst.rs**

```rust
FibMessage::MdbAdd { ifindex, mcast_addr, vni, ports, flags, seq } => {
    self.fib_handle.mdb_add(ifindex, &mcast_addr, vni, &ports, flags, seq).await;
}
FibMessage::MdbDel { ifindex, mcast_addr, vni } => {
    self.fib_handle.mdb_del(ifindex, &mcast_addr, vni).await;
}
```

### Step 9: Add Tests

**File: netlink-packet-route/src/mdb/tests/bridge_mdb.rs**

Test multicast database entry creation, modification, and deletion with roundtrip encoding/decoding.

### Step 10: Integration Test

**Test scenario:**
1. Create VXLAN bridge with multicast support
2. Advertise EVPN Type 3 route from BGP
3. Verify MDB entry is installed in kernel
4. Check multicast traffic is forwarded to remote VTEPs

## Implementation Complexity Analysis

### Simple Path (Basic MDB Support)
**Effort:** 6-8 hours
**Risk:** Medium

```
Files to create/modify:
  - netlink-packet-route/src/mdb/* (new module, 5 files)
  - netlink-packet-route/src/message.rs (enable MDB types)
  - netlink-packet-route/src/lib.rs (add mdb module)
  - zebra-rs/src/fib/message.rs (MdbAdd/MdbDel)
  - zebra-rs/src/fib/netlink/handle.rs (mdb_add/mdb_del)
  - zebra-rs/src/rib/inst.rs (MDB message handling)
  - zebra-rs/src/bgp/route.rs (Type 3 route export)
```

### Extended Path (Full Multicast Support)
**Effort:** 10-12 hours
**Risk:** High

Additional work:
  - IGMP snooping support
  - Source-specific multicast (SSM)
  - PIM integration
  - Advanced multicast policies

## Validation Strategy

### Phase 4B Alpha (Basic MDB)
```
1. Enable MDB message types in netlink-packet-route
2. Implement MdbMessage struct and parsing
3. Unit tests for MDB encoding/decoding
4. Add mdb_add/mdb_del to FibHandle
5. Integration with BGP Type 3 routes
6. Test with kernel bridge multicast
```

## Success Criteria - Phase 4B Alpha Completed

✅ MDB message types (RTM_NEWMDB/RTM_DELMDB) implemented and integrated  
✅ MdbMessage struct parses/emits correctly with proper buffer handling  
✅ netlink-packet-route roundtrip tests pass  
✅ zebra-rs can send MDB netlink messages to kernel  
✅ BGP Type 3 (Inclusive Multicast) routes are exported to RIB  
✅ RIB forwards MDB requests to FIB via FibHandle  
✅ Dependency conflict resolved with cargo [patch] directive

## Phase 4B Implementation Summary

### Completed Work

**netlink-packet-route MDB Module**
- `src/mdb/header.rs`: MdbHeader struct with family and index fields
- `src/mdb/attribute.rs`: MdbAttribute enum with MdbEntry, MrouteEntry, MdbExtAttrs variants
- `src/mdb/message.rs`: MdbMessage struct with Parseable and Emitable trait implementations
- `src/mdb/mod.rs`: Module exports
- Test: `test_mdb_message_roundtrip()` validates encoding/decoding

**FibHandle MDB Methods**
- `mdb_add()`: Constructs RTM_NEWMDB netlink message with multicast group/source encoding
- `mdb_del()`: Constructs RTM_DELMDB netlink message for deletion
- Proper error handling and netlink response processing

**BGP EVPN Type 3 Route Handling**
- `route_evpn_export_selected()`: Extended to handle InclusiveMulticast prefix type
- Exports MdbAdd/MdbDel messages to RIB when Type 3 routes are selected
- Uses group address from EVPN route as multicast group

**RIB Message Flow**
- `rib::inst::Message`: Added MdbAdd and MdbDel variants for BGP→RIB communication
- `FibMessage`: Already supports MdbAdd/MdbDel for RIB↔FIB communication
- `Rib::mdb_add/mdb_del()`: Methods that forward requests to FibHandle
- `process_msg()`: Handles incoming MdbAdd/MdbDel from BGP
- `process_fib_msg()`: Handles MdbAdd/MdbDel from FIB kernel notifications

**Dependency Resolution**
- Added `[patch."https://github.com/zebra-rs/netlink-packet-route"]` to root Cargo.toml
- Ensures local netlink-packet-route with MDB support is used throughout workspace
- Resolves type mismatch between git version (via rtnetlink) and local version  

## References

- Linux kernel: `net/bridge/br_mdb.c`
- RFC 7432: EVPN (RFC Section 4.6 for Type 3)
- iproute2: `bridge/mdb.c`
- netlink-packet-route: neighbour module as template

## Known Limitations & Future Work

### Phase 4B Limitations
- MDB entry data is stored as raw bytes (multicast group/source addresses)
- Future phases should implement structured MDB entry format with proper parsing
- Currently no kernel multicast state synchronization back to RIB
- No integration test with actual kernel multicast bridge yet

### Outstanding Integration Tasks
1. **Kernel Multicast Bridge Testing**
   - Create VXLAN interface with multicast
   - Verify MDB entries installed in kernel
   - Test multicast forwarding to remote VTEPs
   
2. **Source-Specific Multicast (SSM)**
   - Currently treats all multicast as (*,G)
   - Add support for (S,G) via source field in MdbAdd

3. **MDB State Synchronization**
   - Currently only sends MDB updates to kernel
   - Future: Sync kernel MDB state back to RIB for consistency checking

## Next Steps After Phase 4B

Once MDB support is validated:

1. **Phase 4C:** Extended FDB Attributes (NDA_FDB_EXT_ATTRS)
   - Fine-grained control over MAC FDB entries
   - Support for port isolation and vlan filtering
   
2. **Phase 4D:** ESI Multi-homing and MAC Mobility
   - Backup path support via ESI (Ethernet Segment ID)
   - MAC mobility tracking and conflict resolution
   
3. **Phase 5:** Performance optimization and hardening
   - Multicast tree optimization
   - Bulk operations for large deployments
   - Error recovery and resilience improvements
