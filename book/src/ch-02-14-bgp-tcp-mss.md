# BGP TCP MSS (`tcp-mss`)

BGP rides on TCP, and every TCP connection negotiates a **Maximum
Segment Size** (MSS) — the largest payload a single segment may carry.
By default the kernel derives it from the outgoing interface MTU (1460
bytes on a 1500-byte Ethernet link). When the real path MTU is smaller
than the interface MTU — a tunnel, an MPLS core, a link that cannot
carry full-size frames — a full-size BGP segment can be black-holed, and
the session stalls on a large UPDATE that never gets through. The
per-neighbor `tcp-mss` knob caps the MSS so BGP segments stay within the
path.

## Configuration

`tcp-mss` is a per-neighbor value in the range 1–65535 (bytes):

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 192.168.0.1
    neighbor:
    - remote-address: 192.168.0.2
      remote-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      tcp-mss: 500
```

The FRR / IOS-style CLI form is the same path:

```
set router bgp neighbor 192.168.0.2 tcp-mss 500
```

Like the other per-neighbor transport knobs, `tcp-mss` can also be set
on a [neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited by
every member; a statement on the neighbor itself wins. The listener
clamp is re-derived across all members when the group value changes;
live sessions pick the new clamp up at their next connect.

## How it is applied

TCP negotiates the MSS once, in the SYN / SYN-ACK exchange of the
three-way handshake. After that the kernel caches the result
(`tp->mss_cache`) and a later change has no effect on the live
connection. So the clamp must be installed on the socket **before** the
handshake. zebra-rs does this in two places:

- **Active side** — the value is set on the connect socket before
  `connect(2)`, so the SYN we send advertises the reduced MSS.
- **Passive side** — the value is set on the **listening** socket, so a
  passively-accepted connection inherits the clamp on its SYN-ACK.

A listening socket carries a single `TCP_MAXSEG` for every peer, so when
more than one neighbor configures `tcp-mss` the daemon installs the
**minimum** value across the configured peers of that address family on
the listener (the active connect path still applies each peer's own
value exactly). This matches FRR's behaviour.

Because the MSS each side *advertises* bounds what the **other** side
sends, both ends must configure `tcp-mss` for both to see a reduced
value: your `tcp-mss` shrinks the segments your peer sends to you, and
your peer's `tcp-mss` shrinks the segments you send to it.

## Configured vs. synced

`show ip bgp neighbor <addr>` reports two numbers:

```
  Configured tcp-mss is 500, synced tcp-mss is 488
```

- **Configured** is the value you set (`peer.config.transport.tcp_mss`).
- **Synced** is the MSS the kernel actually negotiated on the live
  socket, read back with `getsockopt(TCP_MAXSEG)`. It is shown as `0`
  until the session reaches Established.

The synced value is typically a little **below** the configured value:
the kernel subtracts the TCP options carried in every segment, so with
TCP timestamps enabled (the Linux default) a configured `500` syncs to
`488` (500 − 12).

The two can also differ because **a change to `tcp-mss` does not bounce
a running session**. Like FRR, the new value takes effect on the next
connect, so a freshly-changed neighbor may report, say, a configured
`500` against a still-synced `1460` until you reset the session:

```
clear bgp 192.168.0.2
```

A neighbor configured before its first session comes up needs no reset —
the clamp is already in place when the connection forms.

## Verification

After the session establishes, confirm the negotiated value:

```
> show ip bgp neighbor 192.168.0.2
BGP neighbor is 192.168.0.2, remote AS 65002, local AS 65001, external link
  ...
  Configured tcp-mss is 500, synced tcp-mss is 488
  ...
```

To confirm the option reached the kernel, trace the `setsockopt` calls as
the session establishes:

```
sudo strace -e trace=setsockopt -f -p $(pgrep zebra-rs)
```

You should see a `TCP_MAXSEG` set to the configured value on the
connection's socket (and, for a passively-accepted peer, on the
listening socket) before the handshake completes.
