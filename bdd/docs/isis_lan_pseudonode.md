# IS-IS DIS pseudonode LSP lists every LAN member

## Overview

Regression for a DIS pseudonode-LSP bug. On a broadcast LAN the
Designated IS originates a pseudonode LSP whose TLV 22 must list every
Up IS adjacency on the circuit (ISO 10589 §7.3.16). We previously
(re)originated it only on a DIS *status* change, so a router that came
up after DIS election — while the DIS stayed DIS — was never folded
into the pseudonode's IS-reach list and was unreachable in every
speaker's SPF.

Three L2 routers (a1, a2, a3) share one broadcast LAN (br0), with
loopbacks 10.0.0.{1,2,3}/32. Whichever wins DIS must list all three in
its pseudonode LSP; the decisive assertion is that every router has an
IS-IS route to every other loopback — including the last member to
converge, which the bug dropped.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| every router on the LAN reaches every loopback | |
| Teardown topology | |
