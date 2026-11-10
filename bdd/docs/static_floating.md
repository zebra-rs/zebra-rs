# Floating static route (nexthops at different metrics)

## Overview

A static route whose nexthops carry different metrics is a floating
route: one kernel route per nexthop, each at its own metric, so the
kernel forwards through the lowest one that is there and falls back by
itself. zebra-rs keeps exactly the members whose gateway resolves in
the kernel — a member that is down neither blocks the others nor is
retried, one whose gateway stops resolving while its link stays up is
withdrawn, and either comes back when it can — and `show ip route`
marks each member installed on its own.

The primary is left at the default metric, 0. IPv6 has no kernel
priority 0 (Linux installs such a route at 1024, which would rank it
behind the backup at 10), so there the primary goes in at priority 1.

Both gateways answer for 203.0.113.1 and 2001:db8:113::1, so a ping
from z1 succeeds through whichever member the kernel is using; only
g1 answers for 203.0.113.101 and 2001:db8:113::101, so that ping
succeeds only while the kernel prefers the primary.

```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and install both members | |
| The route stays installed while its backup is down | |
| The backup carries the route while the primary's link is down | |
| A member whose gateway stops resolving leaves the kernel | |
| A backup that is unreachable when the route is committed | |
| Teardown topology | |
