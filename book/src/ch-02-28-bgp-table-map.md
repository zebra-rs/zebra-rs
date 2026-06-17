# Table-Map (Policy at the BGP→RIB Install Point)

BGP keeps two distinct route collections: the **Loc-RIB** (every best
path BGP selected, the table peers are advertised from) and the
**RIB/FIB** (what is actually programmed into the kernel for
forwarding). Normally every Loc-RIB winner with a usable next-hop is
installed. `table-map` inserts a policy at exactly that boundary:

```
  Adj-RIB-In ──policy in──▶ Loc-RIB ──policy out──▶ Adj-RIB-Out
                               │
                          table-map        ◀── this chapter
                               │
                               ▼
                          kernel RIB
```

A **deny** keeps the route out of the kernel; permit-side **set**
clauses rewrite the installed entry. Either way the Loc-RIB and what
peers receive are completely untouched — `show bgp` still shows the
route as best, and downstream neighbors still learn it. This is the
same separation of reachability information from forwarding decision
described in
[the introduction](ch-00-01-reachability-information.md), exposed as
an operator knob. The command mirrors FRR's / IOS's `table-map`.

Typical uses:

- a route server or route reflector that must *know and re-advertise*
  full tables but only *forward* on a small subset (or nothing);
- keeping more-specifics out of the FIB on a box with limited
  forwarding table capacity, while still propagating them in BGP;
- stamping the kernel route metric from BGP attributes via `set med`.

## Configuration

`table-map` takes the name of a [policy](ch-05-00-policy.md) and sits
directly under the global `afi-safi` entry, bare-leaf FRR-style. Each
address family binds its own policy independently — `afi-safi ipv4
table-map A` and `afi-safi ipv6 table-map B` never see each other's
routes. The IPv4 walk-through first:

```yaml
prefix-set:
- name: DENY
  prefixes:
  - prefix: 1.1.1.1/32
- name: MED
  prefixes:
  - prefix: 2.2.2.2/32
policy:
- name: TMAP
  entry:
  - number: 10
    action: deny
    match:
      prefix: DENY
  - number: 20
    action: permit
    match:
      prefix: MED
    set:
      med:
        set: 50
  - number: 30
    action: permit
router:
  bgp:
    global:
      as: 65002
      router-id: 192.168.0.2
    neighbor:
    - remote-address: 192.168.0.1
      remote-as: 65001
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
    afi-safi:
    - name: ipv4
      table-map: TMAP
```

The CLI form is the same path:

```
set router bgp afi-safi ipv4 table-map TMAP
```

With a peer advertising `1.1.1.1/32`, `2.2.2.2/32` and `3.3.3.3/32`,
this configuration:

- keeps `1.1.1.1/32` out of the kernel RIB (entry 10 deny),
- installs `2.2.2.2/32` with kernel metric 50 (entry 20 `set med` —
  MED is what BGP contributes to the RIB metric),
- installs `3.3.3.3/32` unchanged (entry 30 permit-all).

Remember the [policy control flow](ch-05-01-policy-control-flow.md):
a policy ends in an implicit deny, so a table-map consisting only of
deny entries filters *everything* — close with a bare `permit` entry
(number 30 above) for "and install the rest".

### IPv6

The IPv6 binding is the same shape under `afi-safi ipv6`, and the
policy matches v6 prefix-sets — `prefix-set` entries are
family-agnostic, so a dedicated v6 policy is just one whose sets hold
v6 prefixes:

```yaml
prefix-set:
- name: DENY6
  prefixes:
  - prefix: 2001:db8:100::/48
policy:
- name: TMAP6
  entry:
  - number: 10
    action: deny
    match:
      prefix: DENY6
  - number: 20
    action: permit
router:
  bgp:
    afi-safi:
    - name: ipv6
      table-map: TMAP6
```

```
set router bgp afi-safi ipv6 table-map TMAP6
```

With this on a router also carrying the IPv4 table-map above, the two
filters operate side by side: `2001:db8:100::/48` stays out of the v6
kernel table while every v4 install follows TMAP, and removing one
binding leaves the other untouched. Verification is the v6 spelling
of the same disagreement — the prefix is present in `show bgp ipv6`
but absent from `ip -6 route show`, and a `set med` lands as the
kernel metric:

```
$ ip -6 route show 2001:db8:200::/48
2001:db8:200::/48 via 2001:db8:12::1 dev z2-z1 proto bgp metric 50
```

## Semantics

**Install-time only.** The policy runs on a transient copy of the best
path each time it is (re)installed. The Loc-RIB original is never
modified, so best-path selection, `show bgp` output, and
advertisements to peers are identical with and without the table-map.

**Useful set clauses.** At the install boundary only attributes that
shape the kernel route matter: `set med` lands in the kernel route
metric, `set next-hop` rewrites the installed next-hop. Other set
clauses (`local-preference`, communities, prepend, …) execute but
their result is discarded with the copy — they belong in
[`policy in`/`policy out`](ch-05-00-policy.md) instead.

**Live edits resync.** Editing the referenced policy — or a prefix-set
the policy matches on — re-evaluates every installed prefix
immediately, with no session clear. Binding, rebinding, or deleting
the `table-map` itself does the same.

**Unresolved policy = install nothing.** A `table-map` that names a
policy which does not (yet) exist denies every install for that
address family, matching FRR (a missing referenced route-map filters
everything). Note the contrast with per-neighbor `policy in`/`out`,
where an unresolved name passes routes through unchanged. Deleting
the `table-map` — not just fixing the name — is what restores
unfiltered installs.

**Scope.** IPv4 and IPv6 unicast on the global instance, each family
bound independently (`afi-safi ipv4 table-map A`,
`afi-safi ipv6 table-map B`) — a binding never touches the other
family's installs. Committing a `table-map` under the labeled / VPN /
EVPN families is rejected; they install through their own paths. For
IPv6, `set med` works as for IPv4; the `set next-hop` rewrite is
IPv4-only for now.

## Verification

The signature of a working table-map is the *disagreement* between the
BGP table and the kernel:

```
show bgp
```

still lists `1.1.1.1/32` as a valid best path (`*>`), while the kernel
has no route for it:

```
$ ip route show 1.1.1.1/32
$
```

and the MED rewrite is visible as the kernel metric:

```
$ ip route show 2.2.2.2/32
2.2.2.2 via 192.168.0.1 dev eth0 proto bgp metric 50
```

A downstream neighbor of this router still receives all three
prefixes — the table-map filtered forwarding, not reachability
information.

## Troubleshooting

- **Everything disappeared from the kernel after binding the
  table-map.** Either the policy name doesn't resolve (typo, or the
  policy not committed yet — unresolved is deny-all), or the policy
  has no terminal permit entry and every route falls through to the
  implicit deny.
- **A `set` clause "does nothing".** Only `set med` and
  `set next-hop` affect the installed route; everything else is
  meaningful only in `policy in`/`policy out`.
- **The route is gone from the kernel but the neighbor still has
  it.** That's the feature, not a bug: table-map never affects
  advertisement. To filter what peers learn, use
  [`policy out`](ch-05-00-policy.md).
