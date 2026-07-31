# Multiple IPv4 Addresses and the Secondary Flag

An interface may carry any number of IPv4 addresses. The
`ipv4 address` leaf of the [`interface`](ch-00-02-interface-configuration.md)
block is a leaf-list — repeat it once per address:

```
interface enp0s6 {
  ipv4 {
    address 10.0.1.1/24;
    address 10.0.1.2/24;
    address 10.2.0.1/24;
  }
}
```

or, in command form:

```
set interface enp0s6 ipv4 address 10.0.1.1/24
set interface enp0s6 ipv4 address 10.0.1.2/24
set interface enp0s6 ipv4 address 10.2.0.1/24
```

## The kernel computes the secondary flag

There is deliberately **no `secondary` keyword** in the configuration.
On Linux the kernel itself decides: an address whose prefix length and
network match an address already present on the device is marked
`IFA_F_SECONDARY` at insert time; an address in a different subnet is a
primary regardless of order. In the example above, `10.0.1.2/24`
becomes a secondary of `10.0.1.1/24`, while `10.2.0.1/24` is a second
primary. zebra-rs reads the verdict back and displays it:

```
> show interface enp0s6
Interface: enp0s6
  ...
  inet 10.0.1.1/24
  inet 10.0.1.2/24 secondary
  inet 10.2.0.1/24
```

The same flag appears in `ip addr show` as `scope global secondary`.

This differs from Cisco IOS, where `ip address ... secondary` is an
explicit keyword usually used to number a *different* subnet on the
same wire. On Linux that intent needs no keyword — just configure the
second subnet's address, and it is a primary of its own subnet. What
Linux calls secondary is strictly a same-subnet duplicate.

Because the flag is positional — *primary = first installed in its
subnet* — configuration order matters within a subnet: the first
`address` line of a subnet becomes its primary. After a daemon restart
the addresses are re-installed in configuration order, so keeping the
intended primary first in the list keeps the flag assignment stable
across restarts.

## One connected route per subnet

The kernel installs one connected route per *primary* (one per
subnet), never one per address. zebra-rs mirrors that: deleting a
secondary leaves the subnet's connected route — and everything routed
over it — untouched:

```
delete interface enp0s6 ipv4 address 10.0.1.2/24   # route to 10.0.1.0/24 stays
```

## Deleting a primary

Deleting a subnet's primary while it still has secondaries is the one
operation with kernel-version-of-events semantics, governed by the
`net.ipv4.conf.<if>.promote_secondaries` sysctl:

- `promote_secondaries=0` (kernel default): the kernel deletes the
  primary **and cascades the delete to its secondaries**.
- `promote_secondaries=1` (the default on many distributions):
  the kernel promotes the first secondary to primary in place.

zebra-rs handles both. When a configured primary is deleted but a
same-subnet sibling is still configured, the sibling is re-installed
after a cascade — so from the operator's point of view the outcome is
uniform: **the remaining configured address becomes the subnet's new
primary**, the connected route survives, and the secondary tag moves
accordingly in `show interface`.

## How routing protocols treat secondaries

The guiding rule is that a subnet is advertised once and the primary
address is the interface's identity. A kernel secondary is a
same-subnet duplicate whose subnet the primary already covers, so:

- **OSPFv2** — Hellos are sourced from (and carry the netmask of) the
  primary; the Router-LSA emits one link per subnet (the DR's subnet
  as a Transit link, additional subnets as Stub links); secondaries
  contribute no links. Deleting or promoting a primary re-originates
  the Router-LSA immediately.
- **IS-IS** — TLV 132 in Hellos lists *every* interface address
  (secondaries included — they are real, pingable addresses), but
  Extended IP Reachability advertises each subnet once, and the
  self-LSP re-originates as soon as an address is added or removed.
  When choosing the neighbor's address for SPF nexthops and
  BFD/STAMP session endpoints, the peer address sharing a subnet with
  the local primary is preferred.
- **Router-ID selection** — kernel-secondary addresses are never
  [router-id candidates](ch-00-01-router-id.md); the automatic pick
  considers primaries only.
- **BGP** — needs no special handling: the TCP source and NEXT_HOP
  come from kernel source-address selection, which prefers the
  primary.

The practical consequence: a route learned from a multi-address
neighbor resolves via that neighbor's *primary* address, and the
secondary never appears as a nexthop.

## Cross-reference — Cisco IOS / iproute2

| zebra-rs | Cisco IOS | iproute2 |
|---|---|---|
| `set interface <n> ipv4 address <p>` (repeatable) | `ip address <a> <m>` + `ip address <a> <m> secondary` | `ip addr add <p> dev <n>` |
| secondary flag | explicit `secondary` keyword | kernel-computed (`scope global secondary`) |
| delete primary, sibling configured | n/a (primary/secondary are distinct commands) | cascade or promote per `promote_secondaries` |
