# BGP SR Policy Binding-SID steering — end-to-end forwarding (RFC 9256 §8.5)

## Overview

A headend (crs1) receives a service route AND an SR Policy over SAFI 73
from a controller (crs2), colours the route on ingress, and steers it
onto the policy. With `steering-mode binding-sid` the installed route
pushes only the policy's Binding SID (label 16100); with
`steering-mode segment-list` it pushes the policy's whole SID list
(label 16002). The two labels are distinct, so `show ip route` proves,
at the FIB, both that steering fires on *received* SR-policy state and
that the mode selects the Binding SID vs the inline segment list.
This is the forwarding-plane companion to @bgp_sr_policy_bsid_steering
(which covers the config/show surface). It exercises the real receive →
consume → colour → steer path, not just config.
Topology (single link, iBGP AS 65000):
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| crs1 consumes the received SR Policy and installs the service route | |
| Colouring the route inbound steers it onto the Binding SID | |
| Switching to segment-list mode pushes the inline SID list instead | |
| Teardown topology | |
