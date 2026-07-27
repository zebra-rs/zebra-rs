# BGP SR Policy Binding-SID steering mode (RFC 9256 §8.5)

## Overview

An operator selects how colour-matched service routes are steered onto
an SR Policy: the whole SID list imposed inline (`segment-list`, the
historical default) or just the policy's Binding SID (`binding-sid`,
which the BSID's own forwarding entry — an SR-MPLS ILM or an SRv6
End.B6.Encaps SID — expands). This feature validates the new
`steering-mode` config surface end to end in a running daemon: the YANG
parses, the callback stages the mode onto the Loc-RIB SR Policy DB, and
`show bgp sr-policy` reflects it (both values). The steering *decision*
logic — BSID selection, the RFC 9256 §8.8.1 CO-bit endpoint fallback,
and the SR-MPLS ILM-installed gate — is covered by the unit tests in
`zebra-rs/src/bgp/sr_policy.rs`.
Topology:
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The binding-sid steering mode is configured and shown | |
| Flipping the mode back to segment-list takes effect live | |
| Deleting the mode restores the segment-list default | |
| Teardown topology | |
