# Neighbor Discovery, BFD and STAMP

This page covers the operational views for IPv6 Neighbor Discovery, BFD
liveness sessions, and STAMP delay measurement. Every command honors
`-j` / `--json`.

## IPv6 Neighbor Discovery

These views report what the ND task has observed on each interface —
the Router Advertisements it sends and the solicitations / neighbor
messages it sees — so they double as a passive neighbor-cache and RA
diagnostic.

### `show ipv6 nd`

A one-line-per-interface summary of ND activity: whether the daemon is
sending Router Advertisements, the learned-neighbor count, and total
RX/TX packet counts.

```
r1> show ipv6 nd
Interface  RA   Neighbors  RX-total  TX-total  Ifindex
eth0       on           5        42        12        2
eth1       off          0         0         0        3
```

JSON: an array of `{ name, ifindex, ra_enabled, neighbor_count,
rx_total, tx_total }`.

### `show ipv6 nd interface [<ifname>]`

A detailed per-interface block: the RA scheduler state (intervals,
lifetime, hop-limit, managed/other flags, next unsolicited RA), the
daemon-observed and kernel counters, and per-neighbor statistics. Add an
`<ifname>` to filter to one interface.

```
r1> show ipv6 nd interface eth0
Interface eth0 (ifindex 2)
  Router advertisement: enabled
    interval 200-600s, lifetime 1800s, hop-limit 64, managed=0 other=0
  Counters (daemon-observed)   Sent  Received
    Router advertisements        12         8
    Router solicitations          -         5
  Neighbors (1):
    fe80::1   RA 1 RS 0 NS 1 NA 0   first 5m ago, last 2m ago
```

JSON: an array of interface objects with `ra_scheduler`, `counters`,
`kernel_counters`, and a `neighbors` array.

## BFD

See [BFD](ch-10-00-bfd.md) for configuration and the
[BFD offload in the eBPF data plane](ch-10-01-bfd-xdp-helper.md).

### `show bfd`

A summary table of every BFD session: state, the local/remote
discriminators, uptime, and interface.

```
r1> show bfd
Peer       State  Local/Remote Disc  Uptime    Iface
10.0.0.2   Up     0xf001/0x2222      01:23:45  eth0
10.0.0.3   Down   0x1234/0x0000      -         eth1
```

JSON: an array of `{ peer, local, interface, multihop, local_state,
remote_state, local_discr, remote_discr, uptime_secs }`.

### `show bfd peers [<addr>]`

FRR-style detailed blocks per session: the full timer negotiation
(configured / negotiated / actual transmit and receive intervals,
detection time), echo settings, diagnostics, the remote session
parameters, and the control-packet counters. Add an `<addr>` to filter
to one peer.

```
r1> show bfd peers 10.0.0.2
peer 10.0.0.2 (single-hop)
    ID: 0xf001  Remote ID: 0x2222
    Local address: 10.0.0.1  Interface: eth0
    Status: up   Uptime: 123 second(s)
    Local timers:
        Detect-multiplier: 3
        Receive interval: 1000ms  Transmit interval: 1000ms
        Echo transmit interval: disabled
```

JSON: an array of detailed session objects (discriminators, states,
diagnostics, the `*_interval_us` timers, echo fields, remote-state
fields, and RX/TX counters).

### `show bfd counters`

Per-session control-packet counters: received, received-invalid,
transmitted, and transmit-failed.

```
r1> show bfd counters
Peer       RX  RX-Invalid  TX  TX-Failed
10.0.0.2   42           0  40          0
```

JSON: an array of `{ peer, rx_count, rx_invalid_count, tx_count,
tx_failed_count }`.

## STAMP

See [STAMP](ch-09-00-twamp-stamp.md) for configuration.

### `show stamp`

A one-line-per-session summary: the local/remote endpoints, session
state, sent/received counts, loss percentage, and the last exported
delay metric (min/avg/max).

```
r1> show stamp
Interface  Local      Remote     State   Sent  Recv  Loss%  Last (min/avg/max)
eth0       10.0.0.1   10.0.0.2   Active    10     8    20%   42/43/45us (3us)
eth1       10.0.1.1   10.0.1.2   Idle       0     0     -    -
```

JSON: an array of session objects (`interface`, `local`, `remote`,
`state`, `ssid`, counters, `window_*`, and an optional `last_export`
snapshot with `min`/`avg`/`max`/`variation`).

### `show stamp session`

The same session data rendered as a detail block per session — SSID,
probe interval, damping period, uptime, counters, the timestamp source
(kernel vs. userspace), and the current measurement window.

JSON: the same array of session objects as `show stamp`.

### `show stamp statistics`

Aggregated sender and reflector packet counters across all sessions,
including the kernel-vs-userspace timestamp split.

```
r1> show stamp statistics
Sender:    probes sent 50, replies received 48, invalid 1, failed 0
           T4 kernel 48 (userspace fallback 0)
Reflector: probes received 50, reflected 48, unauthorized 2
           T2 kernel 48 (userspace fallback 0)
```

JSON: a single object with the `sender_*` and `reflector_*` counters.
