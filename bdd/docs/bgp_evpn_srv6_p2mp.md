# BGP EVPN BUM over SRv6 P2MP replication (RFC 9524) — cradle engine

## Overview

As a network operator
I want the BGP control plane to program EVPN BUM replication into the cradle
eBPF engine: two SRv6 EVPN PEs exchange their End.DT2M SIDs over a Type-3
IMET, and each daemon (with `system ebpf enabled`) tees the datapath to
cradle — its own End.DT2M leaf SID into the SRv6 table, and each remote PE's
End.DT2M SID as a VNI-10 replication slot.

Scope is the control plane and the tee, not forwarding: no frames are sent
here. BUM forwarding is the cradle engine's job (the standalone
tc-evpn-replicate offload this feature was originally written against has
been retired), and its packet path is covered in cradle-rs by
`cradle_evpn_srv6_zebra_multi` — three PEs, this same BGP control plane, a
real eBPF data plane and CE-to-CE traffic. What is proven here is the
session, the SID exchange, and the engine programming.

Requires /usr/bin/cradle — see the cradle_spawn feature header for install
instructions.

Test Topology — z1 and z2 are SRv6 EVPN PEs on a direct underlay link, each a
root + leaf for VNI 10. Each runs the cradle engine, which encaps BUM toward
the remote End.DT2M SID and decaps a replicated copy onto its bridge. The
bridge holding the config-created vxlan10 is zebra's VNI declaration — it is
what makes the EVI exist and the Type-3 originate; cradle owns the flood
path itself (it creates its own replication-slot veths).
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 EVPN topology and confirm the SR P2MP exchange | |
| The cradle engine is programmed with the SRv6 EVPN replication datapath | |
| Teardown topology | |
