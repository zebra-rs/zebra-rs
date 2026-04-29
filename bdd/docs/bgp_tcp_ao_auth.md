# BGP TCP Authentication Option (RFC 5925 / RFC 5926)

## Overview

As a network operator
I want to protect a BGP session with TCP-AO using an RFC 8177 key

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

- z1-1.yaml: AS 65001, tcp-ao key-chain BGP-AO (hmac-sha-1,
- z2-1.yaml: AS 65002, mirror configuration.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Establish a TCP-AO authenticated BGP session | |
| Teardown topology | |
