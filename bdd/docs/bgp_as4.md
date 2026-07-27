# BGP 4-octet AS support (RFC 6793)

## Overview

As a network operator
I want sessions with 4-byte-ASN routers to establish and carry real AS paths,
including toward legacy 2-octet (OLD) speakers via AS_TRANS + AS4_PATH.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS70000 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1-1.yaml: AS 70000 (4-byte), peer to 192.168.0.2, network 10.0.0.1/32
- z2-1.yaml: AS 65002, peer to 192.168.0.1, network 10.1.0.1/32
- z2-2.yaml: z2-1 plus `capability four-octet false` — z2 presents
  itself as an OLD (2-octet) speaker, so z1 must fall back to a
  2-octet AS_PATH with AS_TRANS plus the AS4_PATH attribute.

AS 70000 renders as "1.4464" in asdot notation (RFC 5396).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A 4-byte-ASN neighbor establishes via AS_TRANS + AS4 capability | |
| Routes carry the real 4-byte AS path on an AS4 session | |
| OLD speaker recovers the 4-byte AS path via AS4_PATH | |
| Teardown topology | |
