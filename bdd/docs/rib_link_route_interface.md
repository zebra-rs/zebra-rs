# A route with no gateway names its interface in every RIB view

## Overview

A connected route, and a kernel route out of an interface with no
gateway, carry their interface in the RIB entry; the nexthop holds no
interface of its own. The one-line views read the entry, but the JSON
and the detail view read the nexthop and named the interface
"unknown". An IPv4 route added out of an interface (scope link) is
filed as connected; an IPv6 one is a kernel route.

## Test Topology

```
   host ── z1 (vc1: 172.16.10.1/24, 2001:db8:10::1/64)
           ip route add 10.9.9.0/24 / 2001:db8:9::/64 dev vc1
```

## Config Files

- z1.yaml: vc1's addresses only; no routing protocol runs.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the router | |
| A connected route's JSON nexthop names its interface | |
| An IPv4 route added out of an interface is connected and names it | |
| An IPv6 kernel route out of an interface names it in detail and JSON | |
| Teardown | |
