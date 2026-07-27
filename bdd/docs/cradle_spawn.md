# system ebpf spawns and supervises the cradle eBPF engine

## Overview

`system ebpf enabled true` makes zebra-rs run the cradle data-plane
daemon as a managed child: spawn it, attach `interface <name> ebpf
enabled` ports, respawn it with backoff when it dies (re-attaching the
ports and replaying the mirrored FIB tee), and stop it when disabled.

Prerequisite: /usr/bin/cradle (the cradle-rs engine binary). Install it
from a cradle-rs checkout: `cargo build --release` then
`install -m755 target/release/cradle /usr/bin/cradle`.

Topology:
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Managed engine spawns with a data-plane port | |
| The engine's tables and counters render through show ebpf | |
| A crashed engine respawns, re-attaches the port, and replays the FIB | |
| A VRF-enslaved port binds to the VRF's kernel table | |
| A bridge-enslaved port becomes an L2 port in the bridge's flood domain | |
| Disabling system ebpf stops the engine | |
| Enabling ebpf after routes exist resyncs them into the engine | |
| Teardown topology | |
