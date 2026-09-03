# IS-IS LAN adjacency survives a change of the interface hardware address

## Overview

As a network operator
I want IS-IS to follow the kernel when an interface's MAC address changes,
so an adjacency on that circuit stays up (and the SNPA I see in
`show isis interface detail` is the one on the wire) instead of being pinned
at Init for the rest of the process.

Why this can happen without anyone touching the address by hand: the
kernel recomputes a bridge's MAC from its port set on every enslave or
release, and a bond adopts its first slave's. Both are ordinary
results of our own configuration. `ip link set ... address` is the
operator's version of the same event and is what this feature uses.

The mechanism it pins: IS-IS caches the interface MAC as the circuit
SNPA and compares it against the IS Neighbors TLV of every LAN IIH it
receives (ISO 10589 8.4.2.5). Once the neighbour has learnt our new
source address, its IIHs list only that, so a stale SNPA fails the
check on each one: the adjacency drops to Init and never recovers. The
RIB now fans the kernel's new address out (`RibRx::LinkMac`) and IS-IS
refreshes the SNPA in place, sends an immediate Hello and re-runs DIS
election.

## Test Topology

```
 a1 ───────────── a2
 i2  10.0.12.0/30  i1
 lo 10.0.0.1/32   lo 10.0.0.2/32
```

Both routers are level-2-only on a broadcast (LAN) circuit with 1 s
Hellos and hold-time 5 s, so the fallout of the address change lands
within seconds either way.

## Notes

- The address is changed with `ip link set dev i2 address` inside a1's
  namespace; zebra-rs has no MAC configuration leaf and mirrors the
  kernel value through netlink (`Rib::link_add` adopts it, then fans
  `RibRx::LinkMac` out to protocol subscribers).
- The 10 s wait after the change is twice the hold time: long enough
  for a2's IS Neighbors TLV to have turned over to the new address and
  for a1 to have received several IIHs carrying it. Before the fix each
  of those IIHs failed a1's three-way check, so the decisive
  assertions (a1's adjacency Up, a2 reaching a1's loopback) failed
  deterministically rather than by timing.
- `show isis interface detail` renders the SNPA in colon form
  (`02:00:00:00:12:01`); the neighbour table renders it dotted
  (`0200.0000.1201`).

## Test Scenarios

### Changing a1's interface address keeps the adjacency up and refreshes the SNPA on both sides

Bring the adjacency up and confirm reachability, move a1's address,
wait out the hold time, then assert: a1 reports the new SNPA on the
circuit, a2's neighbour table shows it, both adjacencies are Up, and
loopback reachability holds in both directions (a2 to a1 depends on
a1's LSP still listing a2, i.e. on a1's adjacency not having dropped).

### Teardown topology

Stop both daemons, delete the namespaces, and verify the environment
is clean.
