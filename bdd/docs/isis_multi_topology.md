# IS-IS multi-topology (RFC 5120)

## Overview

As a network operator
I want two zebra-rs instances to participate in IS-IS multi-topology
Test Topology (same shape as isis_ipv6 but both sides emit MT TLVs):
Both configs add `multi-topology ipv6-unicast;` under `router/isis/`
TLV 237 (MT IPv6 Reach).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup IS-IS L2 with MT 2 over a shared bridge and confirm the link is up | |
| MT 2 SPF installs reciprocal IPv6 routes to peer loopbacks | |
| LSPs carry the multi-topology TLVs | |
