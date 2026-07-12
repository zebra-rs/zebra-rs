# BGP EVPN BUM over SRv6 P2MP replication (RFC 9524) — daemon-driven offload

## Overview

As a network operator
I want the BGP control plane to drive the tc-evpn-replicate eBPF offload: two
SRv6 EVPN PEs exchange their End.DT2M SIDs over an SR P2MP IMET, the root
forms a replication segment, and the daemon spawns + feeds the ingress
(End.Replicate / End.DT2M) and encap (root H.Encaps) children that move BUM.
This proves the control-plane -> supervisor -> loader integration end to end
(session, SID exchange, ReplSeg, child spawn). Each datapath's actual packet
forwarding is proven standalone by the tc-evpn-replicate veth scripts in
cradle-rs (crates/tc-evpn-replicate/scripts/veth-*.sh — End.Replicate, End.DT2M,
H.Encaps); wiring the netns packet capture through all three is a follow-up.
Test Topology — z1 and z2 are SRv6 EVPN PEs on a direct underlay link, each a
root + leaf for VNI 10. z1 sources a BUM frame on its access port; the offload
encaps it toward z2's End.DT2M SID; z2 decaps it onto its bridge.
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 EVPN topology and confirm the SR P2MP exchange | |
| The daemon spawns the offload children and programs the tree | |
| Teardown topology | |
