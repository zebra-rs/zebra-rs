# Passive Interfaces

A **passive** IS-IS interface still advertises its IPv4/IPv6 prefixes
into the router's Link State PDU, but it sends and processes **no Hello
PDUs** — so it forms no adjacency. This is the standard way to inject a
loopback or a stub LAN into the IS-IS topology without trying (and
failing) to find a neighbour on it, and without wasting Hellos on a link
that has no IS-IS peer.

The classic case is a loopback. You want its address (often a `/32` or
`/128` used as the router-id, BGP next-hop, or the anchor for a
Prefix-SID) reachable from the whole area, which means it must appear in
your LSP — but a loopback has no neighbour to talk to. Worse, a loopback
*reflects every frame it transmits*: if IS-IS runs the Hello protocol on
it, the router receives its own Hellos and would form an adjacency **with
itself**. Marking the interface passive (loopbacks are passive
automatically — see below) advertises the prefix while keeping the Hello
machinery off.

## Configuration

`passive` is a per-interface boolean under `router isis`:

```text
router isis {
  net 49.0000.0000.0000.0001.00;
  interface lo {
    ipv4 {
      enabled true;
      prefix-sid {
        index 100;
      }
    }
  }
  interface eth2 {
    passive true;          // advertise eth2's subnet, run no Hellos on it
    ipv4 {
      enabled true;
    }
  }
}
```

In a YAML configuration the same knob is:

```yaml
router:
  isis:
    interface:
    - if-name: eth2
      passive: true
      ipv4:
        enabled: true
```

What `passive` changes, and what it does not:

- **No Hellos** are sent on the interface, and incoming Hellos are
  ignored, so **no adjacency** ever forms over it.
- The interface's prefixes **are still advertised** into the LSP. Prefix
  advertisement is gated on the interface being IS-IS-enabled
  (`ipv4`/`ipv6 enabled`) and participating at the circuit's level — not
  on any adjacency — so a passive circuit's subnet stays reachable from
  the rest of the network.
- Any Prefix-SID configured on the interface is advertised as usual.

Toggling `passive` bounces the circuit: an adjacency that had formed
while it was active is torn down, the self-LSP is re-originated, and SPF
is re-run.

## Loopbacks are implicitly passive

A loopback interface is treated as passive **even when `passive` is not
set**. Running the Hello protocol on a loopback would make the router
peer with itself (the loopback echoes its own Hellos), which is never
useful, so zebra-rs suppresses Hellos on every loopback and still
advertises its prefixes. You therefore do **not** need to write `passive
true` on `lo`; enabling IS-IS (`ipv4 { enabled true; }`) is enough to get
the loopback advertised.

## The self-sourced-Hello guard

Independently of the passive setting, IS-IS **drops any received Hello
whose source system-id is the router's own**. A router must never form an
adjacency with itself, and a self-sourced Hello can arrive in several
ways:

- a loopback (or any interface) reflecting its own Hello,
- an L2 loop in the network looping a Hello back, or
- a duplicate system-id misconfiguration.

In all of these the Hello is discarded before the neighbour table is
touched, so no spurious self-adjacency is ever created. This guard is a
safety net that complements the passive/loopback Hello suppression
above.

## Verification

A passive interface shows no neighbour, and a router never lists *itself*
as a neighbour:

```text
> show isis neighbor
System Id    Interface   L  State    Holdtime  SNPA
z2           eth1        2  Up       27        001c.42e8.0c23
```

The passive interface (and the loopback) are absent from the neighbour
list, and the local router's own hostname never appears there — while
its loopback/stub prefixes are present in `show isis database` and
reachable from peers.
