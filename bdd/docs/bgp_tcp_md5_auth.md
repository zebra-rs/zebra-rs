# BGP TCP MD5 Authentication (RFC 2385)

## Overview

As a network operator
I want to protect a BGP session with a TCP MD5 shared secret and

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

- z1-1.yaml: AS 65001, tcp-md5 password "shared-md5-secret".
- z2-1.yaml: AS 65002, tcp-md5 password "shared-md5-secret" (match).
- z2-2.yaml: AS 65002, tcp-md5 password "WRONG-md5-secret"

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Establish a TCP MD5 authenticated BGP session | |
| Mismatched password drops the session | |
| Restoring the matching password re-establishes the session | |
| Teardown topology | |
