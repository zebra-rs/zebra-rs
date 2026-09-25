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
state, sent/received counts, round-trip probe loss, and the last
exported delay metric (min/avg/max).

```
r1> show stamp
Interface  Local      Remote     State   Sent  Recv     Loss%  Last (min/avg/max)
eth0       10.0.0.1   10.0.0.2   Active   130   129     0.833  42/43/45us (3us)
eth1       10.0.1.1   10.0.1.2   Idle       0     0         -  -
```

`Loss%` is the share of probes lost over the last 120 seconds, counted
on the session's own 30-second loss clock. A probe counts as lost when no
reply arrives within 3 seconds (RFC 7680's waiting time). It is
round-trip loss: a lost probe and a lost reply look the same to the
sender. While a session is younger than 120 seconds the figure covers
the 30-second buckets closed so far, and it reads `-` until the first
one closes.

JSON: an array of session objects (`interface`, `local`, `remote`,
`state`, `ssid`, counters, a `loss` object, and an optional
`last_snapshot` with `min`/`avg`/`max`/`variation`). `loss` carries
`direction`, `window_secs`, `buckets` / `buckets_wanted`, `settled`,
`lost`, and, once any probe has settled, `percent`,
`resolution_percent`, `integrity_percent` and `encoded` (RFC 8570 units
of 0.000003 %). It also counts `late`, `duplicate` and `unmatched`
replies. `forward`, `reverse` and `unresolved` split `lost` by
direction. They mean something only against a stateful peer reflector:
against a stateless one, every loss that can be placed at all reads as
reverse (see [Direction](ch-09-00-twamp-stamp.md)).

### `show stamp session`

The same session data rendered as a detail block per session: SSID,
probe interval, damping period, uptime, counters, the timestamp source
(kernel vs. userspace), how this router reflects the peer's probes,
probe loss, the last delay sample, and one entry for each IGP measuring
the link. The loss line has three states:

```
        Loss (round-trip, 120s window): measuring, first bucket not closed yet
        Loss (round-trip, 120s window): filling, 2 of 4 buckets; so far 0.000% (0 of 60 probes)
        Loss (round-trip, 120s window): 0.833% (1 of 120 probes), resolution 0.833%, integrity 100%
        Loss replies: late 0 duplicate 0 unmatched 0
```

`resolution` is one probe as a percentage: the smallest loss the window
can express at the current probe rate. `integrity` is the share of the
probes the probe interval should have produced that actually settled. A
*late* reply arrived after its probe had already been counted lost, and
it stays lost.

`Reflector:` reads `stateless`, or `stateful, sequence N` while any IGP
measuring the link sets `measurement reflector stateful`. `N` is this
router's counter for the peer's probes.

Each IGP measuring the link gets its own entry under `Subscribers:`,
because each applies its own delay-anomaly bounds and loss settings to
the shared session. The first line gives the delay anomaly bounds and
bits. The second is the loss that IGP advertises, with the settings
behind it. Here every lost packet was a reply on the way back, and the
peer reflects statefully. IS-IS declares that, and advertises the forward
loss: none. OSPF does not, and advertises the round-trip 10 %, which is
over its 5 % anomaly bound:

```
        Reflector: stateful, sequence 1042
        Loss (round-trip, 120s window): 10.000% (12 of 120 probes), resolution 0.833%, integrity 100%
        Loss replies: late 0 duplicate 0 unmatched 0
        Last sample:
            Min delay: 42 usec
            Max delay: 45 usec
            Average delay: 43 usec
            Delay variation: 3 usec
        Subscribers:
            isis: anomaly-threshold none, Anomalous: avg no, min no, max no
                loss: advertised 0.000000% forward (interval 120s, threshold 10%, minimum-change 0.999999%, integrity 90%, peer-reflector stateful)
                  direction over 120s: forward 0, reverse 12, unresolved 0 of 120 probes
            ospf: anomaly-threshold none, Anomalous: avg no, min no, max no
                loss: advertised 9.999999% (A) (interval 120s, threshold 10%, minimum-change 0.999999%, integrity 90%, anomaly 5.000000%, reuse 1.000000%)
```

The loss line reads `disabled` when the IGP has `loss enabled false`,
and `not advertised` until a full, trusted window exists. After the
value:

- `forward` marks forward loss, advertised because the IGP declares
  `peer-reflector stateful`. Without it the value is round-trip. Such an
  IGP also gets a `direction` line for its own window.
- `(A)` marks an advertisement carrying the Anomalous bit.
- `anomaly` / `reuse` appear once bounds are configured, printed exactly
  as configured.

The value and the change thresholds print in the sub-TLV's units of
0.000003 %, so a configured 1.0 % reads 0.999999 %.

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
