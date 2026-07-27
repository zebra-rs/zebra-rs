# zebra-rs operator replication-segment programs the cradle End.Replicate datapath (RFC 9524)

## Overview

An operator `segment-routing replication-segment` declares a local SRv6
End.Replicate SID and its downstream branches. zebra-rs registers the SID —
which tees into the managed cradle engine's SRV6_LOCALSID, so the XDP stage
hands matching frames to the TC replication path — and tees the branch set to
cradle's REPL_SEG (SetReplSeg). This is the control-plane half of RFC 9524
SR-P2MP replication; the datapath fan-out itself is proven by the cradle-rs
`cradle_srv6_replicate` BDD.

Prerequisite: /usr/bin/cradle (the cradle-rs engine binary) with the
SetReplSeg RPC. Install from a cradle-rs checkout: `cargo build --release`
then `install -m755 target/release/cradle /usr/bin/cradle`.

Topology:
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A replication-segment registers an End.Replicate SID and tees its branches | |
| Deleting the replication-segment withdraws the End.Replicate SID | |
| Teardown topology | |
