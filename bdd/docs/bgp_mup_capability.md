# BGP Mobile User Plane (MUP) capability negotiation

## Overview

As a network operator
I want two zebra-rs instances to negotiate the BGP MUP multiprotocol
capability (SAFI 85, draft-ietf-bess-mup-safi) for BOTH IPv4-MUP (AFI 1) and IPv6-MUP
(AFI 2) from a single `afi-safi mup enabled true` knob, and
bring an iBGP session to Established, so the foundation for MUP route
exchange (ISD / DSD / ST1 / ST2) is validated before origination is
implemented.

No MUP routes flow in this scenario — capability negotiation is the unit
under test. zebra-rs cannot originate MUP routes yet (controller phase),
so route exchange is exercised in a later feature once a peer can emit
them.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65001 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Notes

Both peers enable two AFI/SAFIs:
  - ipv4 (so the session has a fallback AF and matches the
    established BDD pattern)
  - mup (the single knob this scenario validates; it
    negotiates IPv4-MUP and IPv6-MUP)

## Config Files

- z1-1.yaml: AS 65001, peer to 192.168.0.2, mup enabled
- z2-1.yaml: AS 65001, peer to 192.168.0.1, mup enabled

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish iBGP session with MUP capability | |
| IPv4 and IPv6 MUP capabilities are advertised and received on both sides | |
| show bgp mup renders the (empty) MUP RIB header | |
| Teardown topology | |
