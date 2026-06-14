# BGP AddPath Send for IPv6 unicast (RFC 7911)

## Overview

As a network operator
I want a BGP speaker with two paths for one IPv6 prefix to advertise
BOTH of them — each with its own path identifier — to a neighbor that
negotiated AddPath, instead of only the best path.
The IPv6-unicast twin of @bgp_addpath_ipv4. It exercises the
IPv6-specific AddPath path: the per-candidate fan-out bucketed into
the update-group cache (`flush_ipv6`) and the `adj_out.v6` path-id
tracking used to withdraw precisely.

## Test Topology

```
     2001:db8:beef::/64        2001:db8:beef::/64
      (origin AS65001)          (origin AS65002)
           z1 ──┐                  ┌── z2
       2001:db8: │  2001:db8:      │  2001:db8:
          ::1/64 └──→  ::3/64  ←───┘     ::2/64
                       z3 (AS65003)
                        │  add-path send-receive
                        ↓
                       z4 (AS65004)  2001:db8::4/64
```

## Notes

z3 learns 2001:db8:beef::/64 over eBGP from BOTH z1 (AS_PATH 65001)
and z2 (AS_PATH 65002), so its Loc-RIB holds two candidate paths.
With AddPath Send negotiated toward z4, z3 advertises both — so z4
sees TWO paths for the prefix, not just the best one.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| The AddPath receiver sees both paths for the prefix | |
| Teardown topology | |
