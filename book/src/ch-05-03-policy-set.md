# Set

`set` clauses modify the route's attributes when the entry fires
with action `permit` or `next`. (A `deny` action drops the route
without applying any `set` — a denied route never picks up
incidental modifications.)

This chapter walks every `set` clause grouped by what it touches:

1. **Numeric attributes (signed deltas)** — `local-preference`
   and `med` accept `set`/`add`/`sub`; arithmetic saturates.
2. **Numeric attribute (plain assign)** — `weight`.
3. **Enum** — `origin`.
4. **Address** — `next-hop` (IPv4 / IPv6 / `self`).
5. **Communities** — `community` (replace / additive / delete).
6. **AS path** — `as-path-prepend`.

## Numeric attributes with deltas

### `set local-preference`

`local-preference` and `med` use the same shape: a presence
container with a mandatory `op` choice between three cases.

```console
policy SET-LP {
    entry 10 {
        action permit;
        set {
            local-preference {
                set 200;
            }
        }
    }
}
```

`set 200` overwrites the route's LOCAL_PREF, regardless of what
the route arrived with. The two delta forms are:

```console
policy BUMP-LP {
    entry 10 {
        action permit;
        match {
            community {
                name PREFERRED;
            }
        }
        set {
            local-preference {
                add 50;
            }
        }
    }
    entry 20 {
        action permit;
        match {
            community {
                name DEPRIORITIZE;
            }
        }
        set {
            local-preference {
                sub 50;
            }
        }
    }
    entry 30 {
        action permit;
    }
}
```

`add 50` adds 50 to whatever the route currently has; `sub 50`
subtracts 50. If the route has no LOCAL_PREF on it (the
attribute is absent), the current value is treated as 0.

**Saturation.** Underflow on `sub` clamps at 0, never wraps.
Overflow on `add` clamps at `u32::MAX`. A `sub 200` against a
route with `LOCAL_PREF=100` produces 0 — not -100, not
`u32::MAX-100`.

### `set med`

Identical shape:

```console
policy SHIFT-MED {
    entry 10 {
        action permit;
        set {
            med {
                add 1000;
            }
        }
    }
}
```

## `set weight`

A plain `uint32` assignment — no `add` / `sub`. Higher weight
wins in best-path selection. Weight is per-router and is not
advertised to peers; it lives on the local RIB entry.

```console
policy PREFER-PEER1 {
    entry 10 {
        action permit;
        match {
            next-hop 192.168.0.1;
        }
        set {
            weight 32768;
        }
    }
    entry 20 {
        action permit;
    }
}
```

A route arriving from `192.168.0.1` enters the local RIB with
`weight=32768`; routes from other peers default to 0, so the
`192.168.0.1` route wins ties.

## `set origin`

```console
policy MARK-AS-IGP {
    entry 10 {
        action permit;
        set {
            origin igp;
        }
    }
}
```

Three values are accepted: `igp`, `egp`, `incomplete` — the same
three that `match origin` accepts.

## `set next-hop`

A presence container with a mandatory choice: an explicit
IPv4 / IPv6 address, or the bare keyword `self`.

### Explicit address

```console
policy NH-EXPLICIT {
    entry 10 {
        action permit;
        set {
            next-hop {
                address 10.0.0.1;
            }
        }
    }
}
```

### `self` — local router

`set next-hop self` resolves at apply time to the local
router-id of the BGP session that's advertising the route. The
typical use case is iBGP route reflection or "next-hop-self"
toward eBGP peers.

```console
policy IBGP-NH-SELF {
    entry 10 {
        action permit;
        set {
            next-hop {
                self;
            }
        }
    }
}

router bgp {
    neighbor 10.0.0.2 {
        policy {
            out IBGP-NH-SELF;
        }
    }
}
```

When the route is sent to `10.0.0.2`, its NEXT_HOP attribute is
rewritten to the local router-id of the local↔10.0.0.2 session.

### IPv6 (today)

An IPv6 address parses cleanly but does not currently affect the
route — `BgpNexthop` is IPv4-only today. The clause is in the
schema for forward compatibility; a follow-up adds the IPv6
unicast nexthop and emit path.

## `set community`

Apply a `community-set` to the route's COMMUNITIES attribute,
with three modes:

- **replace** (default) — overwrite the COMMUNITIES attribute
  with the set's members.
- **additive** — merge the set's members into whatever
  COMMUNITIES the route already carries.
- **delete** — remove the set's members from the route's
  COMMUNITIES (set difference).

```console
community-set TAG-INTERNAL {
    members {
        65001:100;
        65001:200;
    }
}

policy ADD-INTERNAL-TAG {
    entry 10 {
        action permit;
        match {
            prefix-set INTERNAL-NETS;
        }
        set {
            community {
                name TAG-INTERNAL;
                additive;
            }
        }
    }
}
```

The `additive` keyword is what makes this *add* the tags; without
it the route's existing communities would be replaced wholesale:

```console
policy CLEAR-AND-RESET {
    entry 10 {
        action permit;
        set {
            community {
                name TAG-INTERNAL;
            }
        }
    }
}
```

Any communities the route arrived with are gone after this entry
fires. To explicitly remove tags:

```console
community-set NO-EXPORT-TAGS {
    members {
        no-export;
        no-advertise;
    }
}

policy STRIP-NO-EXPORT {
    entry 10 {
        action permit;
        set {
            community {
                name NO-EXPORT-TAGS;
                delete;
            }
        }
    }
}
```

## `set as-path-prepend`

Prepend an ASN onto the AS_PATH a configurable number of times.
Used in outbound policy to make a path artificially longer and
discourage upstreams from preferring it.

```console
policy PREPEND-OUT {
    entry 10 {
        action permit;
        set {
            as-path-prepend {
                asn 65001;
                repeat 3;
            }
        }
    }
}
```

`repeat 3` adds the ASN three times. The default is `repeat 1`
when omitted. The ASN to prepend is independent of the local
ASN — typically an operator prepends their own ASN, but the
schema doesn't enforce that.

## Apply order within a single entry

When an entry has several `set` clauses, they apply in this
order against the working attribute set:

1. `local-preference`
2. `med`
3. `weight`
4. `community`
5. `as-path-prepend`
6. `next-hop`
7. `origin`

The order matters in two cases:

- `as-path-prepend` after `set community` means a regex on the
  *prepended* AS_PATH won't see the prepend if a downstream entry
  uses `match as-path` — that downstream match runs against the
  already-modified path.
- For `community` with `additive`, the set's members are merged
  into whatever COMMUNITIES the route had at the *start of the
  entry* — a `set community` earlier in the same entry would
  have replaced/cleared first.

Within a single entry these orderings are usually invisible. If
you need fine control, split into multiple entries chained by
`action next`.

## Worked example: combining set clauses

```console
prefix-set CUSTOMER-A {
    prefix 10.10.0.0/16 {
        le 24;
    }
}

community-set TAG-CUST-A {
    members {
        65001:100;
    }
}

policy IN-CUSTOMER-A {
    entry 10 {
        action permit;
        match {
            prefix-set CUSTOMER-A;
        }
        set {
            local-preference {
                set 200;
            }
            community {
                name TAG-CUST-A;
                additive;
            }
            origin igp;
            weight 100;
        }
    }
    entry 20 {
        action permit;
    }
}
```

For a route 10.10.5.0/24 from this peer with `LOCAL_PREF=100`,
`ORIGIN=incomplete`, and existing community `65000:42`:

1. `local-preference set 200` → `LOCAL_PREF=200`
2. `community { name TAG-CUST-A; additive; }` →
   `COMMUNITIES = {65000:42, 65001:100}`
3. `origin igp` → `ORIGIN=igp`
4. `weight 100` → local rib entry weight = 100
5. `permit` → route is accepted, walker stops.

For a route 192.168.0.0/24 (not in `CUSTOMER-A`):

1. Entry 10's `match prefix-set` fails. Entry skipped.
2. Entry 20: unconditional `permit`. Accepted unchanged.
