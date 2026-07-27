# PIMv6 Embedded-RP (RFC 3956) ASM with no RP configuration

## Overview

As a network operator
I want an IPv6 multicast group that embeds its RP address in its own
bits (RFC 3956, ff70::/12) to run the full ASM control loop with no
static RP and no BSR — every router derives the same RP straight from
the group address.
The group ff7e:240:2001:db8:22::9 embeds RP 2001:db8:22::2 (flags R=P=T,
RIID 2, prefix length 64, network prefix 2001:db8:22::). r2 owns that
address and therefore acts as the RP purely by derivation. No router
carries any `rp static` or `bsr` config.

## Test Topology

```
    h1 (2001:db8:21::10, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(RP=2001:db8:22::2) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (2001:db8:24::10, receiver)
                                       2001:db8:21::1   2001:db8:22::1/.2         2001:db8:23::1/.2         2001:db8:24::1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The embedded RP is derived and the ASM loop runs | |
| Teardown topology | |
