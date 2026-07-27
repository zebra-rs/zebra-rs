# OSPFv2 passive interfaces advertise their prefix without forming adjacencies

## Overview

As a network operator
I want `area <id> interface <n> passive true` to keep advertising
the interface's prefix into the area while sending and accepting no
Hellos — so stub networks are reachable without exposing an
adjacency on them.

## Test Topology

```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2) -- 10.0.23.0/30 -- c (10.0.0.3)
                     active link       ethc PASSIVE on b   c runs OSPF actively

    on router X the interface toward router Y is named "ethY".
```

## Notes

b's ethc is passive. Its /30 must appear in a's routing table (the
stub prefix rides b's Router-LSA), while c — actively speaking OSPF
on that segment — must never become b's neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Passive interface prefix advertises; no adjacency forms across it | |
| Teardown topology | |
