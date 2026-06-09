# IS-IS passive interfaces and the self-sourced-Hello guard

## Overview

As a network operator
I want IS-IS to advertise a loopback / stub prefix without running the
Hello protocol on it, and I never want a router to form an adjacency with
itself when its own Hellos loop back to it.
Two independent guarantees are exercised here:
1. A loopback is implicitly passive, and an explicitly `passive` interface
2. The self-sourced-IIH guard: if an IIH arrives carrying this router's own

## Test Topology

```
        z3 (IS-IS active, but ISOLATED — z1's side of the link is passive)
        │
        │ z3:i1 ── 10.0.13.2/30
        │ z1:i3 ── 10.0.13.1/30   (PASSIVE on z1)
        │
   z2 ══════════════ z1                 z4
   i1   10.0.12.0/30  i2           sa ─┐  (sa<->sb are one veth pair
   .2                 .1           sb ─┘   inside z4: a self-loop)

    loopbacks: zI -> 10.0.0.I/32  and  2001:db8::I/128
```

## Notes

z1–z2 is an ordinary point-to-point Level-2 backbone link and forms an
adjacency. z1–z3 has z1 configured `passive`, so even though z3 runs IS-IS
actively it never hears a Hello and z3 stays isolated; z1 still advertises
10.0.13.0/30 so z2 can reach it. z4 is wired to itself (sa and sb are the
two ends of one veth pair in the same namespace) to force its own Hellos
back at it, exercising the self-sourced-IIH guard. Every router also runs
IS-IS on its loopback (network-type defaults to LAN, the configuration that
used to make a router peer with itself over `lo`).
All routers are level-2-only.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology — a real adjacency forms, no router self-peers | |
| A passive interface forms no adjacency but still advertises its prefix | |
| A self-looped circuit never peers with itself (self-sourced-IIH guard) | |
| Teardown topology | |
