# BGP Basic Session Test on eBGP

## Overview

As a network operator
I want to test basic BGP session establishment
Using an isolated test topology with two zebra-rs instances with eBGP connection.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1.yaml: AS 65001, peer to 192.168.0.2
- z2.yaml: AS 65002, peer to 192.168.0.1

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP session | |
| Apply config change and verify BGP session drops | |
| Apply config change and verify BGP session recovered | |
| Advertise a network 10.0.0.1/32 | |
| Withdraw a network 10.0.0.1/32 | |
| Advertise a network 10.0.0.1/32 and 10.0.0.2/32 | |
| Withdraw a network 10.0.0.1/32 and 10.0.0.2/32 | |
| Apply output policy with prefix-set | |
| Teardown topology | |
