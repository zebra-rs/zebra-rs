# BGP L2VPN/EVPN capability negotiation

## Overview

As a network operator
I want two zebra-rs instances to negotiate the L2VPN/EVPN multiprotocol
No EVPN routes flow in this scenario — capability negotiation is the
Multicast) lands in follow-up features.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65001 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1-1.yaml: AS 65001, peer to 192.168.0.2, evpn enabled
- z2-1.yaml: AS 65001, peer to 192.168.0.1, evpn enabled

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish iBGP session with EVPN capability | |
| L2VPN/EVPN capability is advertised and received on both sides | |
