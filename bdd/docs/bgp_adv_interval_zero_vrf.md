# Per-VRF BGP neighbor zero adv-interval delivers ipv4/ipv6 unicast

## Overview

As an operator of an L3VPN PE
I want `router bgp vrf <name> neighbor <ce> timers advertisement-interval 0`
to disable the MRAI for a per-VRF CE neighbor
So that PE-CE ipv4/ipv6 unicast converges without waiting out the stock
MRAI — the instance-level `router bgp timer adv-interval` never reaches
the per-VRF task, so the per-neighbor knob is the only lever.

Regression guard for wiring the per-neighbor `advertisement-interval`
into the update-group signature (`adv_interval_override`) and arming
path: with 0 the per-VRF ipv4/ipv6-unicast advertise debounce arms a
~1 ms next-tick timer instead of the stock 30s eBGP one. The CE side
uses the same knob as a plain global neighbor, so both directions are
covered.

## Test Topology

```
   ce1 ───────────────── pe1
   AS 65001            AS 65000
   global              vrf-cust (RD 65000:1)
   lo 10.0.1.1/32      net 10.9.0.0/24
      2001:db8:8::1/128    2001:db8:9::/64
        .2 ── .1   (10.1.0.0/30)
        ::2 ── ::1 (2001:db8:1::/64)
   adv-interval 0      adv-interval 0 (per VRF neighbor)
```

## Config Files

- pe1.yaml: AS 65000, vrf-cust with two CE neighbors (10.1.0.2 ipv4,
- ce1.yaml: AS 65001, global neighbors to the PE (ipv4 + ipv6), each

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the PE-CE dual-stack topology and establish sessions | |
| PE advertises its vrf-cust ipv4 network to the CE with adv-interval 0 | |
| PE advertises its vrf-cust ipv6 network to the CE with adv-interval 0 | |
| CE advertises its ipv4/ipv6 loopbacks to the PE vrf with adv-interval 0 | |
| Teardown topology | |
