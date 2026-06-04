# IS-IS LSP fragmentation (IPv4) at lsp-mtu-size 400 and 1500

## Overview

As a network operator
I want zebra-rs to fragment its self-originated LSP across multiple
PDUs when the IPv4 TLV 135 (Extended IP Reachability) content exceeds
`lsp-mtu-size`, deliver every fragment to peers via the standard
flooding path, and have the receiver correctly merge those fragments
back into a single logical origin so SPF can still install routes to
the originator's loopback.
This is verified at two LSP MTUs over one topology: first a tight
400-byte cap (fragmentation with only 60 networks), then — after a
live reconfiguration of z1 — the standard 1500-byte Ethernet MTU
(fragmentation needs 200 networks), confirming both the small-MTU
path and that a runtime lsp-mtu-size change re-fragments correctly.
Finally, the same topology exercises the separate transmit-side
`lsp-mtu` knob: raising it above an interface's MTU makes the flood
path drop z1's LSP on send (logged at warning level), which `show isis
interface detail` flags and a receiver can prove by never learning a
freshly-added prefix until lsp-mtu is lowered back under the MTU.

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
         10.0.1.1/24      10.0.1.2/24
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          │ 400→1500│     │         │
          │ 60→200  │     │         │
          └─────────┘     └─────────┘
     lo: 10.255.0.1/32     lo: 10.255.0.2/32
```

## Config Files

- z1-1.yaml: lsp-mtu-size 400 + 60 IPv4 /32 networks. Each /32 entry
- z1-2.yaml: lsp-mtu-size 1500 + 200 IPv4 /32 networks. At the standard
- z2-1.yaml: default config; verifies the receiver-side rebuild from a

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup fragmentation topology at lsp-mtu-size 400 | |
| MTU 400 — lsp-mtu-size shows up in show isis summary | |
| MTU 400 — z2 observes z1's self-LSP as multiple fragments | |
| MTU 400 — z2 reaches z1's loopback despite z1's self-LSP being fragmented | |
| MTU 400 — z2 installs a /32 network carried in one of z1's higher fragments | |
| Reconfigure z1 to the standard 1500-byte LSP MTU | |
| MTU 1500 — lsp-mtu-size shows up in show isis summary | |
| MTU 1500 — z2 still observes z1's self-LSP as multiple fragments | |
| MTU 1500 — z2 reaches z1's loopback despite z1's self-LSP being fragmented | |
| MTU 1500 — z2 installs a /32 network carried in one of z1's higher fragments | |
| lsp-mtu above the interface MTU is flagged in show isis interface detail | |
| lsp-mtu above the interface MTU drops z1's LSP on send so z2 never learns the new prefix | |
| Lowering lsp-mtu under the interface MTU lets z1's LSP flood again | |
| Teardown topology | |
