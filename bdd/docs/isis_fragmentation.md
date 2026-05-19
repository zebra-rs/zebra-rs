# IS-IS LSP fragmentation under a tight lsp-mtu-size

## Overview

As a network operator
I want zebra-rs to fragment its self-originated LSP across multiple
PDUs when the TLV content exceeds `lsp-mtu-size`, deliver every
fragment to peers via the standard flooding path, and have the
receiver correctly merge those fragments back into a single logical
origin so SPF can still install routes to the originator's loopback.

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          │ MTU 400 │     │         │
          │ 40 net  │     │         │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
```

## Config Files

- z1-1.yaml: lsp-mtu-size 400 + 40 IPv6 networks. Forces the packer
- z2-1.yaml: default config; verifies the receiver-side rebuild from

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup fragmentation topology | |
| lsp-mtu-size shows up in show isis summary | |
| z2 observes z1's self-LSP as multiple fragments | |
| z2 reaches z1's loopback despite z1's self-LSP being fragmented | |
| Teardown topology | |
