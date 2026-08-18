# IS-IS no-NET hello gate (no identity, no wire)

## Overview

As a network operator
I want an IS-IS instance without a configured NET to stay silent on
the wire — an enabled circuit must not emit Hellos under the default
all-zero system-id (0000.0000.0000), which peers would key a phantom
neighbor under — and to come up promptly once the NET is configured.

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
```

## Config Files

- z1-1.yaml: IS-IS L2 with IPv6 on lo + vz1ns, but NO net configured.
- z2-1.yaml: full IS-IS L2 config with net 49.0001.0000.0000.0002.00.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology with z1 enabled but identity-less | |
| An identity-less z1 sends no Hellos, so z2 learns no neighbor | |
| Configuring the NET brings the adjacency up promptly | |
| Teardown topology | |
