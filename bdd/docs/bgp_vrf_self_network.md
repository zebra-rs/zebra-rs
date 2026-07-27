# Per-VRF self-originated `network` reaches CE neighbors

## Overview

As an operator of an L3VPN PE
I want a `network` under `router bgp vrf X afi-safi {ipv4,ipv6}` to be
advertised to the VRF's CE (unicast) neighbors
So that a PE can originate a prefix into a customer VRF without a
static route + redistribute workaround.
Regression guard for two bugs:
1. Split-horizon collision — the self-originated Loc-RIB row carried
2. Runtime edits were never advertised — `originate_self_network_*` /

## Test Topology

```
   ce1 ───────────────── pe1
   AS 65001            AS 65000
   global              vrf-cust (RD 65000:1)
                        network 10.9.0.0/24
                        network 2001:db8:9::/64
        .2 ── .1   (10.1.0.0/30)
        ::2 ── ::1 (2001:db8:1::/64)
```

## Config Files

- pe1.yaml: AS 65000, vrf-cust with ipv4 (10.1.0.2) + ipv6 (2001:db8:1::2)
- ce1.yaml: AS 65001, global neighbors to the PE (ipv4 + ipv6).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the PE-CE dual-stack topology and establish sessions | |
| CE receives the PE's self-originated ipv4 network (ident-0 peer) | |
| CE receives the PE's self-originated ipv6 network | |
| An ipv4 network added at runtime is advertised to the CE | |
| Removing the runtime ipv4 network withdraws it from the CE | |
| An ipv6 network added at runtime is advertised to the CE | |
| Removing the runtime ipv6 network withdraws it from the CE | |
| Teardown topology | |
