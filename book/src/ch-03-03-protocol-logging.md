# Protocol-Specific Logging

Zebra-rs includes protocol-aware logging that automatically tags log messages with protocol information, making it easy to filter and analyze protocol-specific events.

## Protocol Fields

All protocol-specific logs include a `proto` field that identifies the source protocol:

| Protocol | Field Value | Example Usage |
|----------|-------------|---------------|
| ISIS | `proto="isis"` | ISIS adjacency, LSP processing |
| BGP | `proto="bgp"` | BGP sessions, route updates |
| OSPF | `proto="ospf"` | OSPF neighbors, LSA processing |

## ISIS Logging

ISIS module uses custom macros that automatically include the protocol field:

```rust
// In ISIS code
isis_info!("Hello originate {} on {}", level, interface);
isis_warn!("DIS flapping detected, applying dampening");
isis_debug!("LSP received from {}", neighbor);
```

**Common ISIS Log Messages:**

### Hello Processing
```json
{
  "message": "Hello originate L1 on eth0",
  "proto": "isis"
}
```

### DIS (Designated Intermediate System) Selection
```json
{
  "message": "DIS selection: self on eth0 (priority: 64, neighbors: 2)",
  "proto": "isis"
}
```

### LSP (Link State PDU) Processing
```json
{
  "message": "Self originated LSP is updated seq number: 0x0042",
  "proto": "isis"
}
```

### Adjacency State Changes
```json
{
  "message": "NFSM State Transition Init -> Up",
  "proto": "isis"
}
```

## BGP Logging

BGP-related logs include protocol identification:

**Common BGP Log Messages:**

### Session Management
```json
{
  "message": "BGP session established with 192.168.1.1",
  "proto": "bgp"
}
```

### Route Processing
```json
{
  "message": "Received 1000 routes from peer 192.168.1.1",
  "proto": "bgp"
}
```

### Error Conditions
```json
{
  "message": "BGP notification sent: cease/administrative-shutdown",
  "proto": "bgp"
}
```

## OSPF Logging

OSPF-related logs include protocol identification:

**Common OSPF Log Messages:**

### Neighbor State
```json
{
  "message": "Neighbor 10.0.0.1 state change: Loading -> Full",
  "proto": "ospf"
}
```

### DR Election
```json
{
  "message": "DR election completed on eth0: DR=10.0.0.1",
  "proto": "ospf"
}
```

### LSA Processing
```json
{
  "message": "Router LSA originated for area 0.0.0.0",
  "proto": "ospf"
}
```

## Filtering by Protocol

### Using grep
```bash
# Show only ISIS logs
grep '"proto":"isis"' /var/log/zebra-rs.log

# Show only BGP errors
grep '"proto":"bgp"' /var/log/zebra-rs.log | grep '"level":"error"'
```

### Using jq
```bash
# Extract ISIS messages
jq 'select(.proto == "isis") | .message' /var/log/zebra-rs.log

# Get BGP session events
jq 'select(.proto == "bgp" and (.message | contains("session")))' /var/log/zebra-rs.log
```

### Using Elasticsearch
```
# All ISIS protocol logs
protocol:isis

# BGP errors in the last hour
protocol:bgp AND level:error AND @timestamp:[now-1h TO now]

# OSPF DR election events
protocol:ospf AND message:*DR*election*
```

## Protocol-Specific Debug Levels

You can enable debug logging for specific protocols:

```bash
# Debug ISIS only
RUST_LOG=zebra_rs::isis=debug zebra-rs

# Debug BGP and OSPF
RUST_LOG=zebra_rs::bgp=debug,zebra_rs::ospf=debug zebra-rs

# Trace level for ISIS interface state machine
RUST_LOG=zebra_rs::isis::ifsm=trace zebra-rs
```

## Protocol Logging Benefits

1. **Focused Troubleshooting**: Quickly isolate protocol-specific issues
2. **Performance Analysis**: Monitor protocol behavior independently
3. **Compliance**: Track protocol events for audit requirements
4. **Integration**: Feed protocol-specific logs to specialized tools
5. **Alerting**: Create protocol-aware monitoring rules

## Example: ISIS Troubleshooting

To troubleshoot ISIS adjacency issues:

```bash
# 1. Enable ISIS debug logging
RUST_LOG=zebra_rs::isis=debug zebra-rs --log-format=json

# 2. Filter for adjacency-related messages
jq 'select(.proto == "isis" and (.message | contains("NFSM") or contains("Hello")))' 

# 3. Look for specific interface
jq 'select(.proto == "isis" and (.message | contains("eth0")))'
```

## Example: Multi-Protocol Monitoring

Create a dashboard showing protocol health:

```bash
# Count messages by protocol and level
jq -r '[.proto, .level] | @tsv' /var/log/zebra-rs.log | \
  sort | uniq -c | sort -rn

# Result:
# 1523 isis info
#  234 bgp info
#  187 ospf info
#   12 isis warn
#    3 bgp error
```