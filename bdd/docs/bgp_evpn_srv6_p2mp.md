# BGP EVPN BUM over SRv6 P2MP replication (RFC 9524) — cradle engine

## Overview

As a network operator
I want the BGP control plane to program EVPN BUM replication into the cradle
eBPF engine: two SRv6 EVPN PEs exchange their End.DT2M SIDs over a Type-3 IMET,
and each daemon (with `system ebpf enabled`) tees the datapath to cradle — its
own End.DT2M leaf SID into the SRv6 table, and each remote PE's End.DT2M SID as
a VNI-10 replication slot. This proves the control-plane -> cradle-tee
integration end to end (session, SID exchange, engine programming). BUM
forwarding is the cradle engine's job (the standalone tc-evpn-replicate offload
is retired); its packet path is exercised by the veth scripts in cradle-rs
(crates/tc-evpn-replicate/scripts/veth-*.sh). Requires /usr/bin/cradle.

Test Topology — z1 and z2 are SRv6 EVPN PEs on a direct underlay link, each a
root + leaf for VNI 10, each running the cradle engine.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 EVPN topology and confirm the SR P2MP exchange | |
| The cradle engine is programmed with the SRv6 EVPN replication datapath | |
| Teardown topology | |
