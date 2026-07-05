# BGP Basic Session Test with RR

## Overview

As a network operator
I want to test basic BGP session establishment with RR
Using an isolated test topology with four zebra-rs instances with RR and iBGP connection.

## Test Topology

```
  ┌───────────────────────────────────────────────────────────────┐
  │                             br0                               │
  └───────┬───────────────┬───────────────┬───────────────┬───────┘
          │               │               │               │
     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
     │   rr    │     │   z1    │     │   z2    │     │   z3    │
     │ AS64512 │     │ AS64512 │     │ AS64512 │     │ AS64512 │
     │  (RR)   │     │(client) │     │(client) │     │(client) │
     │192.168. │     │192.168. │     │192.168. │     │192.168. │
     │  0.1/24 │     │  0.2/24 │     │  0.3/24 │     │  0.4/24 │
     └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

## Config Files

- rr.yaml: AS 64512, route-reflector with z1/z2/z3 as clients
- z1.yaml: AS 64512, peer to RR (z1-network.yaml adds network 10.0.0.1/32)
- z2.yaml: AS 64512, peer to RR
- z3.yaml: AS 64512, peer to RR

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP session | |
| A client route is reflected to the other clients with next-hop unchanged | |
| Withdrawing the client route removes it from the other clients | |
| Teardown topology | |
