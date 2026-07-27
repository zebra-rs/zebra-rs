# Interface-to-VRF enslavement (`interface <name> vrf <vrf>`)

## Overview

As a network operator
I want to enslave individual interfaces to a VRF master device
So that traffic on those interfaces is routed in the VRF's table instead
of the default routing instance.

The binding is operator intent, not an immediate netlink call: either
half can be missing when the config is committed. `link_vrf_bind` records
the intent in `pending_vrf_bind` and replays it when the missing piece
arrives — a kernel `NewLink` for the interface, or `VrfAdd` for the
master — so config order is free. That deferral is what scenarios D and
E pin; the rest pin the steady state and the show surfaces.

Kernel state is asserted with `ip -d link show <if>` (`master <vrf>`)
rather than through zebra-rs, so a show-layer bug cannot make a missing
enslavement look present.

## Test Topology

```
              ┌─────────────────────────────┐
              │              z1             │
              │   ┌─────────────────────┐   │
              │   │      vrf vrf1       │   │  table-id allocated
              │   └──────────┬──────────┘   │
              │              │ master       │
              │   ┌──────────┴──────────┐   │
              │   │         vi1         │   │  192.168.10.1/24
              │   └─────────────────────┘   │
              │                             │
              │             vi2             │  10.0.0.1/24, default VRF
              └─────────────────────────────┘
```

## Notes

vi1 and vi2 are dummy interfaces created before the daemon starts; vi3 is
created mid-run by scenario D to prove a binding survives the netdev not
existing yet. vi2 never joins a VRF and is the control for the `default`
rendering in `show interface brief`.

## Config Files

- z1.yaml: vrf1, vi1 enslaved to it with 192.168.10.1/24, unbound vi2.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup — a VRF master with one member, bound in a single commit | |
| A - an address committed with the binding lands in the VRF table | |
| B - show vrf lists the member and show interface brief names the VRF | |
| C - unbinding returns the interface to the default VRF | |
| D - a binding set before the netdev exists fires on create | |
| E - re-binding moves the interface to a second VRF | |
| F - deleting the VRF detaches its members, re-creating re-enslaves | |
| Teardown topology | |
