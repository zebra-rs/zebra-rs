# Phase 3B: Remote VTEP Support Implementation Guide

## Overview

This guide provides a step-by-step approach to extend `netlink-packet-route` with remote VTEP (tunnel endpoint) IP address support for EVPN L2 MAC FDB entries.

## Current State

**In netlink-packet-route/src/neighbour/attribute.rs:**
- ✅ NDA_DST (type 1) exists for IP neighbor addresses (IPv4/IPv6)
- ✅ NDA_VNI (type 7), NDA_SRC_VNI (type 11), NDA_PORT (type 6) implemented
- ❌ NDA_FDB_EXT_ATTRS (type 14) commented out - needed for extended FDB features
- ❌ No standard way to encode tunnel endpoint in FDB entries

## Phase 3B Implementation Plan

### Research Phase (Step 1-3)

#### Step 1: Understand Linux Kernel Encoding
**Goal:** Determine the correct netlink attribute for remote VTEP

**Investigation Points:**
1. Check Linux kernel source: `drivers/net/vxlan.c` and `net/bridge/br_fdb.c`
2. Understand two approaches:
   - **Approach A:** Use NDA_DST for tunnel endpoints (non-standard but works)
     - Pros: Reuses existing infrastructure
     - Cons: NDA_DST is semantically for IP neighbors, not tunnels
   
   - **Approach B:** Use NDA_FDB_EXT_ATTRS (RFC standard)
     - Pros: Proper kernel-approved mechanism
     - Cons: Requires implementing extended attributes structure
   
   - **Approach C:** Separate message type (future)
     - Pros: Clean separation of concerns
     - Cons: Complex, requires kernel support

**Recommendation:** Start with **Approach A** (use NDA_DST), then migrate to **Approach B** later

**Research Command:**
```bash
# Check if kernel vxlan driver uses NDA_DST for remote endpoints
grep -n "NDA_DST\|nda_dst" drivers/net/vxlan.c
```

#### Step 2: Verify via iproute2
**Goal:** Understand how `ip link` and `bridge fdb` commands encode tunnel endpoints

**Commands to test:**
```bash
# Check if netlink library (used by iproute2) sends NDA_DST for tunnel endpoints
strace -e write bridge fdb add <MAC> dev vxlan0 dst <REMOTE_IP> vni 100 src_vni 100

# Examine iproute2 source for comparison
# File: iproute2/bridge/fdb.c - look for fdb_modify() function
```

#### Step 3: Test Current Behavior
**Goal:** Verify what attributes kernel accepts for bridge FDB

**Test Program:**
```rust
// Test if NDA_DST works for VXLAN FDB entries
let mut msg = NeighbourMessage::default();
msg.header.family = AddressFamily::Bridge;
msg.header.ifindex = vxlan_ifindex;

msg.attributes.push(NeighbourAttribute::LinkLocalAddress(mac.octets().to_vec()));
msg.attributes.push(NeighbourAttribute::Vni(vni));
msg.attributes.push(NeighbourAttribute::Destination(
    NeighbourAddress::Inet(tunnel_endpoint_ipv4)
));

// Send and observe if kernel accepts it
```

### Implementation Phase (Step 4-7)

#### Step 4: Add RemoteVtep Variant to NeighbourAttribute
**File:** `netlink-packet-route/src/neighbour/attribute.rs`

**Changes:**

1. **Define new constants:**
   ```rust
   const NDA_DST: u16 = 1;
   // ... existing constants ...
   const NDA_TUNNEL_ENDPOINT: u16 = 1;  // Reuse NDA_DST type for tunnel endpoints
   // OR if using separate attribute:
   const NDA_VXLAN_TUNNEL_ENDPOINT: u16 = 15;  // New attribute type (non-standard)
   ```

2. **Add enum variant:**
   ```rust
   pub enum NeighbourAttribute {
       // ... existing variants ...
       Destination(NeighbourAddress),  // For IP neighbors (NDA_DST type 1)
       TunnelEndpoint(NeighbourAddress),  // For VXLAN tunnel IPs (NDA_DST type 1)
       // Option B: Separate attribute
       // RemoteVtep(NeighbourAddress),  // Custom attribute (needs kernel support)
   }
   ```

3. **Why two approaches?**
   - **Approach A (TunnelEndpoint):** Uses existing NDA_DST, kernel already understands it
   - **Approach B (RemoteVtep):** New attribute, requires kernel 5.8+

#### Step 5: Implement Nla Trait Methods
**File:** `netlink-packet-route/src/neighbour/attribute.rs`

**Update value_len():**
```rust
fn value_len(&self) -> usize {
    match self {
        // ... existing cases ...
        Self::TunnelEndpoint(v) => v.buffer_len(),  // 4 bytes for IPv4, 16 for IPv6
        // ...
    }
}
```

**Update emit_value():**
```rust
fn emit_value(&self, buffer: &mut [u8]) {
    match self {
        // ... existing cases ...
        Self::TunnelEndpoint(v) => v.emit(buffer),
        // ...
    }
}
```

**Update kind():**
```rust
fn kind(&self) -> u16 {
    match self {
        // ... existing cases ...
        Self::TunnelEndpoint(_) => NDA_DST,  // or NDA_VXLAN_TUNNEL_ENDPOINT
        // ...
    }
}
```

#### Step 6: Implement Parsing in ParseableParametrized
**File:** `netlink-packet-route/src/neighbour/attribute.rs`

**Update parse_with_param():**
```rust
fn parse_with_param(
    buf: &NlaBuffer<&'a T>,
    address_family: AddressFamily,
) -> Result<Self, DecodeError> {
    let payload = buf.value();
    Ok(match buf.kind() {
        // ... existing cases ...
        NDA_DST => {
            // Distinguish between IP neighbor and tunnel endpoint based on context
            // For now, create both Destination and TunnelEndpoint variants
            let addr = NeighbourAddress::parse_with_param(address_family, payload)?;
            Self::TunnelEndpoint(addr)  // Prefer TunnelEndpoint interpretation
        }
        // ...
    })
}
```

#### Step 7: Add Test Cases
**File:** `netlink-packet-route/src/neighbour/tests/bridge.rs`

**Add VXLAN FDB with tunnel endpoint test:**
```rust
#[test]
fn test_vxlan_fdb_with_tunnel_endpoint() {
    // Create neighbour message with tunnel endpoint
    let mut msg = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Bridge,
            ifindex: 3,  // vxlan0
            state: 0x80,  // NUD_PERMANENT
            flags: 0x02,  // NTF_SELF
            kind: RouteType::Unspec,
        },
        attributes: vec![
            NeighbourAttribute::LinkLocalAddress(vec![0, 0x11, 0x22, 0x33, 0x44, 0x55]),
            NeighbourAttribute::Vni(100),
            NeighbourAttribute::SourceVni(100),
            NeighbourAttribute::Port(4789),
            NeighbourAttribute::TunnelEndpoint(
                NeighbourAddress::Inet("10.0.0.2".parse().unwrap())
            ),
        ],
    };

    // Test roundtrip: emit -> parse
    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);
    
    let parsed = NeighbourMessage::parse(&NeighbourMessageBuffer::new_checked(&buffer).unwrap())
        .unwrap();
    
    assert_eq!(parsed, msg);
}
```

### Integration Phase (Step 8-10)

#### Step 8: Update rtnetlink Builders
**File:** `../rtnetlink/src/neighbour/add.rs` (if using rtnetlink)

**Add builder method:**
```rust
impl NeighbourAddRequest {
    pub fn tunnel_endpoint(mut self, addr: IpAddr) -> Self {
        let addr = match addr {
            IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
            IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
        };
        self.message_mut()
            .attributes
            .push(NeighbourAttribute::TunnelEndpoint(addr));
        self
    }
}
```

#### Step 9: Update zebra-rs FibHandle
**File:** `zebra-rs/src/fib/netlink/handle.rs`

**Update mac_add() to use tunnel endpoint:**
```rust
pub async fn mac_add(
    &self,
    vni: u32,
    mac: &MacAddr,
    tunnel_endpoint: Option<IpAddr>,
    flags: u8,
    seq: u32,
) {
    // ... existing code ...
    
    // Add tunnel endpoint if available
    if let Some(endpoint) = tunnel_endpoint {
        msg.attributes.push(NeighbourAttribute::TunnelEndpoint(
            match endpoint {
                IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
                IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
            }
        ));
    }
    
    // ... send message ...
}
```

#### Step 10: Add VNI Registry Integration
**File:** `zebra-rs/src/rib/inst.rs`

**Register VXLAN interfaces:**
```rust
// After VXLAN interface is created by kernel:
pub fn register_vxlan_with_fib(&mut self, vni: u32, ifindex: u32) {
    // Called when kernel notifies us of new VXLAN link
    self.fib_handle.register_vxlan_ifindex(vni, ifindex);
}

// In LinkManager::link_add():
if let Some(vxlan) = self.vxlan.get(&link.name) {
    if let Some(vni) = vxlan.vni {
        self.register_vxlan_with_fib(vni, link.index);
    }
}
```

## Implementation Complexity Analysis

### Simple Path (Approach A: Reuse NDA_DST)
**Effort:** 2-3 hours  
**Risk:** Low  
**Testing:** Medium  

```
4-6 files modified:
  - netlink-packet-route/src/neighbour/attribute.rs  (1 variant, 3 trait impls)
  - netlink-packet-route/src/neighbour/tests/bridge.rs  (1 test)
  - zebra-rs/src/fib/netlink/handle.rs  (emit logic update)
  - Optional: rtnetlink builder method
```

### Extended Path (Approach B: NDA_FDB_EXT_ATTRS)
**Effort:** 5-7 hours  
**Risk:** Medium  
**Testing:** High  

```
Additional work:
  - Create struct FdbExtAttrs { flags, nh_id, ... }
  - Implement nested attribute parsing
  - Multiple test cases for parsing variants
  - Kernel compatibility checks
```

## Validation Strategy

### Phase 3B Alpha (Approach A: NDA_DST)
```
1. Add TunnelEndpoint variant
2. Implement parsing/emission
3. Unit tests in netlink-packet-route
4. Integration test: mac_add() with tunnel_endpoint
5. Kernel test: "ip link show vxlan0" after FDB install
```

### Phase 3B Beta (Approach B: Extended Attributes)
```
1. Uncomment NDA_FDB_EXT_ATTRS
2. Define extended attribute structure
3. Add complex parsing logic
4. Compatibility tests for different kernel versions
5. Regression tests for existing FDB operations
```

## Fallback Strategy

If kernel doesn't accept NDA_DST for tunnel endpoints:

```rust
// Fallback: Configure tunnel endpoints separately
eprintln!("Kernel FDB tunnel endpoint setup failed.");
eprintln!("Configure remote endpoints manually:");
eprintln!("  ip link set {} remote {} [remote ...] endpoint {}", 
    vxlan_ifname, peer_ip, remote_vtep);
```

## Timeline Estimate

- **Step 1-3 (Research):** 2-4 hours (parallel reading + simple test)
- **Step 4-6 (Implementation):** 2-3 hours (straightforward changes)
- **Step 7 (Testing):** 1-2 hours (unit + integration tests)
- **Step 8-10 (Integration):** 1-2 hours (FibHandle updates)

**Total:** 6-11 hours (depends on kernel compatibility findings)

## Success Criteria

✅ NeighbourAttribute supports TunnelEndpoint variant  
✅ netlink-packet-route roundtrip tests pass  
✅ zebra-rs mac_add() can include tunnel endpoint in netlink message  
✅ Kernel accepts message (via: bridge fdb show)  
✅ VXLAN forwarding table contains remote VTEP IP  
✅ Fallback mechanism works if kernel doesn't support  

## References

- Linux kernel: `drivers/net/vxlan.c` (vxlan_fdb_parse)
- Linux kernel: `net/bridge/br_fdb.c` (br_fdb_add)
- RFC 7432: BGP MPLS-Based Ethernet VPN (EVPN)
- iproute2 source: `bridge/fdb.c` (implementation reference)
- netlink-packet-route: Existing Destination attribute handling

---

## Next Steps After Phase 3B

Once remote VTEP support is working:

1. **Phase 4A:** Enable MDB (RTM_NEWMDB) for Type 3 multicast routes
2. **Phase 4B:** ESI multi-homing with extended community parsing
3. **Phase 4C:** MAC mobility sequence tracking and validation
4. **Phase 4D:** Production hardening and performance optimization
