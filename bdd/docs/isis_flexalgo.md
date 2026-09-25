# IS-IS Flexible Algorithm with affinity-based topology constraints

## Overview

As a network operator running a global backbone (inspired by the Graphiant
backbone topology), I want IS-IS Flex-Algo (RFC 9350) to confine traffic to
specific regional sub-topologies so that data-sovereignty and compliance
policies (HIPAA, GDPR) are enforced at the routing layer.

Five zebra-rs instances form a two-region backbone.  Each link is tagged
with one or more affinity names from the global /affinity-map table.
Two custom algorithms restrict the SPF graph by excluding non-compliant
link colors:

The FAD (Flex-Algorithm Definition) for both algorithms is originated by
the Chicago (ch) router; every other router participates without
advertising a FAD. Every router computes with the winning definition
(RFC 9350 §5.3) — the greatest priority, then the greatest System-ID —
not its own configuration, and stops participating in an algorithm whose
winning definition asks for something it cannot support.

Topology (all links point-to-point; default metric 10):

Affinity map:

Per-algo prefix-SIDs (SRGB base 16000):

## Config Files


## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the Flex-Algo topology and confirm IS-IS adjacencies | |
| FAD advertisement is visible from the originating router | |
| FAD floods to non-originating routers | |
| Algo 128 (US-only) route table contains only US-region nodes | |
| Algo 129 (EU-only) route table contains only EU-region nodes | |
| Default algo-0 topology has full-mesh connectivity | |
| Every router computes with the winning definition | |
| A router that cannot support the winning definition stops participating | |
| Teardown Flex-Algo topology | |
