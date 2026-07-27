# IS-IS LAN DIS re-election converges when priority changes

## Overview

Regression for a DIS-election convergence bug on a broadcast LAN.
Three L2 routers (a1, a2, a3) share one LAN (br0), loopbacks
10.0.0.{1,2,3}/32. a3 starts as DIS (LAN priority 100; a1/a2 at the
default 64). Raising a1's LAN priority to 200 must move the DIS to a1 on
*every* speaker while full loopback reachability is preserved.
The bug: a non-DIS bystander (a2) that switched its elected DIS from a3
to a1 while staying a non-DIS member (DisStatus Other -> Other) never
re-registered its pseudonode adjacency — the adjacency update was gated
on a DIS *status* change, and Other -> Other is not one. a2 kept
pointing at a3's old pseudonode LSP, which the resigning DIS a3 had
purged, so a2's SPF routed through a pseudonode that no longer existed
and it lost the route to a1's loopback. The decisive assertions are
that after the DIS moves, a2's interface adjacency points at a1's
pseudonode (0000.0000.0001.*) and a2 still reaches 10.0.0.1/32.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| raising a non-DIS router's priority moves the DIS and the LAN stays reachable | |
| Teardown topology | |
