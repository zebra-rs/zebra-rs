# BGP IPv4 sync cursor egress backpressure — park + resume (Tier 1b)

## Overview

z2 originates 16384 IPv4-unicast routes and runs the resumable cursor
with a low egress watermark and a slowed egress writer
(ZEBRA_BGP_WRITER_DELAY_MS — a slow peer simulated at the app layer).
When the late peer z3 establishes, z2's session-up dump outruns the
slow writer: the pending-UPDATE queue grows past the watermark and the
cursor PARKS, then resumes as the writer drains. Pins that the park
engages (log) and the slowed dump still converges (z3 gets the routes)
— the proof Tier 1b works.

## Test Topology

```
  z2 (AS65002, cursor, slow egress writer) ── z3 (AS65003) late peer
   16384 routes, sync chunk 500, egress high 4, writer delay 20ms
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| z2 comes up with the large RIB and a slowed egress writer | |
| late peer z3 triggers a slowed dump; the cursor parks then converges | |
| Teardown topology | |
