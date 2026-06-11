# BGP AS Override

RFC 4271 loop prevention makes a BGP speaker **reject any route whose
AS_PATH already contains its own AS**. That rule is correct almost
always, but it breaks one common topology: two customer sites that reuse
the **same AS number** behind a shared provider. A route originated at
one site arrives at the other carrying that shared AS, trips the loop
check, and is dropped.

`neighbor X as-override` resolves this on the **advertising** side. When
the provider re-advertises a route to such a neighbor, it first rewrites
every occurrence of that neighbor's AS in the AS_PATH to its own AS, so
the neighbor no longer sees its own AS and accepts the route.

## The problem

Consider a provider in AS 65002 with two customers, both numbered
AS 65001:

```
 ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
 │   ce1   │ ──────────────── │ provider│ ──────────────── │   ce2   │
 │ AS65001 │                  │ AS65002 │                  │ AS65001 │
 └─────────┘                  └─────────┘                  └─────────┘
 originates                                                  must learn
 10.0.0.1/32                                                 10.0.0.1/32
```

`ce1` originates `10.0.0.1/32`; the provider learns it with AS_PATH
`65001`. When the provider re-advertises it to `ce2`, it prepends its
own AS, sending `65002 65001`. `ce2` is AS 65001, sees `65001` in the
path, and drops the route as a loop. The two sites cannot reach each
other even though the provider has the route.

## What as-override does

With `as-override` configured on the provider's session toward `ce2`,
the egress transform changes to **replace, then prepend**:

1. Replace every `65001` (the neighbor's remote-AS) in the AS_PATH with
   `65002` (the local AS): `65001` → `65002`.
2. Prepend the local AS as usual: `65002` → `65002 65002`.

`ce2` receives `65002 65002`, finds no occurrence of its own AS 65001,
and installs the route. The replacement happens **before** the prepend;
doing it the other way around would leave the neighbor's AS in the path
and re-introduce the loop.

This is the send-side counterpart to
[`allowas-in`](ch-02-13-bgp-allowas-in.md), which relaxes the same loop
check on the **receiving** side. `as-override` keeps the
neighbor's loop check strict and instead removes the offending AS before
it ever reaches the neighbor — the originator's AS is hidden from that
neighbor, which is exactly the intent in a shared-AS VPN/customer design.

`as-override` only affects **eBGP** sessions. iBGP never prepends the
local AS, so the knob is a no-op there and is ignored. The transform is
applied uniformly across every address family the session carries
(IPv4/IPv6 unicast, labeled-unicast, L3VPN, EVPN, flow-spec).

## Configuration

`as-override` is a per-neighbor flag. Configure it on the provider end,
on the session toward each shared-AS customer:

```yaml
router:
  bgp:
    global:
      as: 65002
      router-id: 192.168.0.2
    neighbor:
    - remote-address: 192.168.1.3
      remote-as: 65001
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      as-override: {}
```

`as-override: {}` is the YAML spelling of a presence container — the
key is present with no children, which the loader turns into
`set router bgp neighbor 192.168.1.3 as-override`. The FRR / IOS-style
CLI form is the same path:

```
set router bgp neighbor 192.168.1.3 as-override
```

Enabling `as-override` on an already-established session does not by
itself re-send routes already in the neighbor's Adj-RIB-Out. Bounce the
session so the provider re-advertises with the new AS_PATH:

```
clear bgp ipv4 neighbor 192.168.1.3
```

Like the other per-neighbor knobs, `as-override` can also be set on a
[neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited by
every member; a statement on the neighbor itself wins.

## Verification

`show ip bgp neighbor <addr>` reports whether the knob is active:

```
  AS-Override enabled (outbound AS_PATH replacement)
```

On the neighbor, confirm the rewritten path arrived loop-free. `ce2`
should now hold `10.0.0.1/32` with an AS_PATH of `65002 65002` rather
than the rejected `65002 65001`:

```
show ip bgp 10.0.0.1/32
```

### Interaction with update-groups

zebra-rs batches identical outbound work into **update-groups** and
encodes one UPDATE for every member of a group (see the design notes in
`docs/design/bgp-update-groups.md`). Because `as-override` rewrites the
path using the neighbor's own remote-AS, its result is peer-specific: two
eBGP neighbors that override **different** remote-AS values cannot share a
single encoded UPDATE. A neighbor with `as-override` is therefore keyed
into its own update-group, separate from non-override peers and from
peers overriding a different AS. `show bgp update-group` makes this
visible:

```
  Signature:
    ...
    AS-override target:         65001
```

A `—` in that field means the group's members do not override (the common
case). This separation is automatic; no extra configuration is required.

## Troubleshooting

The usual mistake is configuring `as-override` on the **wrong end**. It
belongs on the side that *advertises* into the shared-AS neighbor — the
provider in the example above — not on the customer that needs to
*accept* the route. If you control only the receiving side, the
equivalent receive-side relaxation is
[`allowas-in`](ch-02-13-bgp-allowas-in.md).

If the route still does not appear after enabling `as-override`, check
that:

- the session is **eBGP** (`as-override` is ignored on iBGP);
- the AS actually being rewritten is the neighbor's **remote-as** — only
  occurrences equal to the configured `remote-as` of *that* session are
  replaced; an unrelated AS deeper in the path is left untouched;
- the session was **bounced** (`clear bgp ipv4 neighbor <addr>`) after
  the configuration change, so the route was re-advertised under the new
  policy.
