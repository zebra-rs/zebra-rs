# A VPNv6 transit configured before any route arrives labels the routes at receive

## Overview

The ordering twin of `bgp_vpnv6_rr_transit_label`, whose transit knob
is turned on after the routes are in the table (so the reconcile labels
them). Here the reflector is an Option B transit toward pe2 from its
initial configuration: the shard's label pool is still empty when the
first VPNv6 route arrives, so the receive path itself must draw a
label from the central block and program the swap ILM. Review
follow-up on finding #8: the live VPNv6 ingest handed the shard no
central allocator, so nothing was minted, and the route went to pe2
behind the reflector's next-hop with pe1's label — a label the
reflector holds no ILM for.

## Test Topology

```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology with the reflector already a transit toward pe2 | |
| The route received under transit reaches pe2 behind the reflector with a swap ILM behind it | |
| Teardown topology | |
