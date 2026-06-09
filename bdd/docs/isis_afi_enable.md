# IS-IS re-originates its LSP when an interface address-family is toggled

## Overview

As a network operator
I want enabling (or disabling) an address-family on an IS-IS interface to
immediately update the self-originated LSP, so a newly-enabled prefix is
advertised without waiting for the periodic LSP refresh.
Regression: enabling IPv6 on a loopback that already had IPv4 enabled used
to leave the loopback's IPv6 prefix out of the LSP, because re-origination
only fired on a 0<->non-zero *global* protocols-supported (NLPID)
transition — and the global IPv6 count was already non-zero thanks to the
dual-stack backbone link. The fix re-originates on any per-interface AFI
flip.

## Test Topology

```
   a1 ───────────── a2
   i2  10.0.12.0/30  i1
       2001:db8:12::/64
   lo 10.0.0.1/32      lo 10.0.0.2/32
      2001:db8::1/128     2001:db8::2/128
```

## Notes

Both routers are level-2-only and the a1–a2 link is dual-stack, so the
global IPv6 interface count on a1 is already non-zero. a1's loopback starts
with **only IPv4** enabled in IS-IS; its IPv6 address exists on the kernel
interface but is not advertised. A later scenario enables IPv6 on a1's
loopback at runtime and proves a2 then learns 2001:db8::1/128.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology — the IPv4 loopback is advertised, the IPv6 loopback is not | |
| Enabling IPv6 on the loopback re-originates the LSP and advertises the prefix | |
| Teardown topology | |
