# BGP Remove Private AS

Private Autonomous System numbers — `64512`–`65535` (RFC 6996) and the
32-bit range `4200000000`–`4294967294` — are meant to stay **inside** a
network. They commonly number the customer or internal sites that sit
behind a provider's public AS. When the provider re-advertises those
routes to an upstream or peering neighbor, the private ASNs would
normally travel in the AS_PATH, leaking the internal numbering and
sometimes causing the neighbor to reject the route on a private-AS
filter.

`neighbor X remove-private-as` strips those private ASNs from the
AS_PATH on the **advertising** side, before the local AS is prepended,
so the neighbor only ever sees public ASNs.

## The problem

A provider in public AS 100 has a customer site numbered with the
private AS 65001:

```
 ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
 │   z1    │ ──────────────── │   z2    │ ──────────────── │   z3    │
 │ AS65001 │                  │ AS 100  │                  │ AS 200  │
 └─────────┘                  └─────────┘                  └─────────┘
 private AS                    public AS                    public AS
 originates                                                 learns it with
 10.0.0.1/32                                                AS_PATH "100 65001"
```

`z1` originates `10.0.0.1/32`; `z2` learns it with AS_PATH `65001`. When
`z2` re-advertises it to `z3` it prepends its own AS, sending
`100 65001`. `z3` now sees the customer's private AS 65001 in the path —
information that should never have left `z2`'s network, and a path that a
peer applying `bgp bestpath ... no-private-as` filtering may reject.

## What remove-private-as does

With `remove-private-as` configured on `z2`'s session toward `z3`, the
egress transform changes to **strip, then prepend**:

1. Remove every private AS from the AS_PATH (here `65001`), keeping any
   public ASNs.
2. Prepend the local AS as usual: the path becomes just `100`.

`z3` receives `100`, with no trace of the customer's private AS.

### The neighbor's own AS is always kept

If the AS being stripped happens to be the **neighbor's own** AS, it is
left in the path. Removing it could hide a genuine loop from the
neighbor's RFC 4271 check, so — exactly like FRR — `remove-private-as`
preserves the neighbor's AS even when it is private. (If you *want* a
neighbor to accept a path that legitimately transited its own AS, that
is the job of [`as-override`](ch-02-12-bgp-as-override.md), the
send-side, or [`allowas-in`](ch-02-13-bgp-allowas-in.md), the
receive-side relaxation.)

### The four forms

FRR exposes four variants, which are two orthogonal modifiers on the
same transform:

| Form | When it acts | What it does to a private AS |
|------|--------------|------------------------------|
| `remove-private-as`                | only when the **whole** path is private | removes it |
| `remove-private-as all`            | on **any** path containing a private AS | removes it |
| `remove-private-as replace-as`     | only when the whole path is private     | rewrites it to the local AS |
| `remove-private-as all replace-as` | on any path containing a private AS     | rewrites it to the local AS |

- **`all`** widens the trigger. Without it, the strip is conservative:
  it only runs when *every* AS in the path is private, leaving any path
  that already mixes public and private ASNs untouched. With `all`, the
  private ASNs are stripped from a mixed path too, keeping the public
  ones.
- **`replace-as`** changes the action from *remove* to *substitute*:
  each private AS is rewritten to the local AS instead of being dropped,
  which keeps the AS_PATH length (and therefore the path-length tiebreak)
  unchanged.

`remove-private-as` only affects **eBGP** sessions. iBGP never prepends
the local AS, so the knob is a no-op there and is ignored. The transform
is applied uniformly across every address family the session carries
(IPv4/IPv6 unicast, labeled-unicast, L3VPN, EVPN, flow-spec).

## Configuration

`remove-private-as` is a per-neighbor presence container. Configure it on
the provider end, on the session toward the upstream/peer:

```yaml
router:
  bgp:
    global:
      as: 100
      router-id: 192.168.0.2
    neighbor:
    - remote-address: 192.168.1.3
      remote-as: 200
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      remove-private-as:
```

`remove-private-as:` with no value is the YAML spelling of a bare
presence container, which the loader turns into
`set router bgp neighbor 192.168.1.3 remove-private-as`. The FRR /
IOS-style CLI form is the same path:

```
set router bgp neighbor 192.168.1.3 remove-private-as
```

To enable the modifiers, set the corresponding leaves. In YAML:

```yaml
      remove-private-as:
        all: null
        replace-as: null
```

or, on the CLI, as separate `set` lines (each `set` targets one node):

```
set router bgp neighbor 192.168.1.3 remove-private-as
set router bgp neighbor 192.168.1.3 remove-private-as all
set router bgp neighbor 192.168.1.3 remove-private-as replace-as
```

Enabling `remove-private-as` on an already-established session does not
by itself re-send routes already in the neighbor's Adj-RIB-Out. Bounce
the session so the provider re-advertises with the stripped AS_PATH:

```
clear bgp ipv4 neighbor 192.168.1.3
```

Like the other per-neighbor knobs, `remove-private-as` can also be set
on a [neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited by
every member; a statement on the neighbor itself wins.

## Verification

`show bgp neighbors <addr>` reports the configured form:

```
  Private AS removal: remove-private-AS (outbound)
```

(or `remove-private-AS all replace-AS (outbound)` with both modifiers).

On the neighbor, confirm the stripped path arrived. `z3` should now hold
`10.0.0.1/32` with an AS_PATH of `100` rather than `100 65001`:

```
show bgp 10.0.0.1/32
```

### Interaction with update-groups

zebra-rs batches identical outbound work into **update-groups** and
encodes one UPDATE for every member of a group (see the design notes in
`docs/design/bgp-update-groups.md`). Because the stripped AS_PATH depends
on the modifiers in force *and* on the neighbor's own AS (which is kept),
the result is peer-specific: two eBGP neighbors strip identically only
when they share the same modifiers and keep the same AS. A neighbor with
`remove-private-as` is therefore keyed into its own update-group,
separate from peers that strip differently or not at all. `show bgp
update-group` makes this visible:

```
  Signature:
    ...
    Remove-private-AS:          on (keep 200)
```

A `—` in that field means the group's members do not strip private ASNs
(the common case). This separation is automatic; no extra configuration
is required.

## Troubleshooting

If the private AS still appears at the neighbor after enabling
`remove-private-as`, check that:

- the session is **eBGP** (`remove-private-as` is ignored on iBGP);
- the AS you expect to disappear is actually **private** — only
  `64512`–`65535` and `4200000000`–`4294967294` are stripped; a public
  AS is always kept;
- the AS being stripped is **not the neighbor's own** remote-as — that
  one is deliberately preserved for loop prevention;
- if the path mixes public and private ASNs and nothing was stripped,
  add the **`all`** modifier — the bare form only acts on an
  all-private path;
- the session was **bounced** (`clear bgp ipv4 neighbor <addr>`) after
  the configuration change, so the route was re-advertised under the new
  policy.
