# Static blackhole routes install RTN_BLACKHOLE discard entries

## Overview

As a network operator
I want `router static <afi> route <prefix> nexthop blackhole` to
install a discard route in the forwarding plane (kernel
RTN_BLACKHOLE) with no gateway — so that traffic to the prefix is
dropped at this router instead of forwarded or looped. This
exercises the RIB `Nexthop::Blackhole` type end to end (config →
RIB → netlink → kernel FIB).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| IPv4 and IPv6 blackhole static routes reach the kernel FIB | |
| Teardown topology | |
