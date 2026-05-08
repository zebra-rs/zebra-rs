# Match

`match` clauses select which routes an entry applies to. All
clauses inside a single `match` block are AND'd together — every
clause must succeed for the entry to fire. An empty `match` block
(or no `match` block at all) means the entry matches every route.

This chapter covers all match clauses grouped by shape:

1. **Set references** — `prefix`, `community`, `ext-community`,
   `large-community`, `as-path` — name a separately-defined set.
2. **Direct address** — `next-hop` — exact equality against the
   route's NEXT_HOP attribute.
3. **Numeric** — `med`, `as-path-len`, `as-path-len-uniq`,
   `local-preference`, `weight` — compare against a single
   `eq` / `le` / `ge` operator.
4. **Enum** — `origin` — one of `igp` / `egp` / `incomplete`.

## Set references

### `match prefix`

References a `prefix-set`. The route's prefix is checked against
each entry of the set; if any matches (with optional `le` / `ge`
length bounds), the clause succeeds.

```console
prefix-set CUSTOMER-NETS {
    prefix 10.0.0.0/8 {
        le 32;
    }
    prefix 192.168.0.0/16 {
        le 24;
        ge 24;
    }
}

policy IN-CUSTOMER {
    entry 10 {
        action permit;
        match {
            prefix CUSTOMER-NETS;
        }
    }
}
```

The set permits anything inside `10.0.0.0/8` of any length up to
/32, plus exactly /24 prefixes inside `192.168.0.0/16`.

### `match community`

References a `community-set`. The set's members are matched
against the route's COMMUNITIES attribute. Members can be:

- standard community values (`100:200`, `no-export`, …)
- standard community regex patterns (`^65001:.*`)
- extended community exact values (`rt:65001:100`, `soo:1.2.3.4:50`)
- extended community regex patterns (`rt:^65001:.*`)

```console
community-set INTERNAL {
    members {
        no-export;
        65001:100;
        ^65001:42[0-9]+$;
    }
}

policy DROP-INTERNAL {
    entry 10 {
        action deny;
        match {
            community INTERNAL;
        }
    }
    entry 20 {
        action permit;
    }
}
```

### `match ext-community`

References an `ext-community-set`. Like `community` but only
accepts extended-community syntax — `rt:` and `soo:` only;
standard-community values are rejected at parse time.

```console
ext-community-set TENANT-A {
    members {
        rt:65001:100;
        rt:1.2.3.4:200;
        soo:^65001:.*;
    }
}

policy IN-TENANT-A {
    entry 10 {
        action permit;
        match {
            ext-community TENANT-A;
        }
    }
}
```

### `match large-community`

References a `large-community-set`. Members are either an exact
`A:B:C` triple of `uint32`s (RFC 8092) or a regex matched against
the textual `A:B:C` form of each LARGE_COMMUNITIES element.

```console
large-community-set ASN-65001 {
    members {
        65001:100:200;
        ^65001:.*:.*$;
    }
}

policy MATCH-LARGE {
    entry 10 {
        action permit;
        match {
            large-community ASN-65001;
        }
    }
}
```

### `match as-path`

References an `as-path-set`. Each member is a regex matched
against the AS_PATH formatted as a space-separated list of ASNs.

```console
as-path-set FROM-65003 {
    members {
        \\b65003\\b;
    }
}

policy DROP-65003-TRANSIT {
    entry 10 {
        action deny;
        match {
            as-path FROM-65003;
        }
    }
    entry 20 {
        action permit;
    }
}
```

`\\b` is a regex word-boundary anchor that prevents `65003` from
matching `650030` or `650031`.

## Direct address

### `match next-hop`

Takes an IPv4 *or* IPv6 address — not a prefix-set name — and
compares it for **exact equality** against the route's BGP
NEXT_HOP attribute. To match a *range* of addresses, use a
prefix-set with `match prefix` against the route prefix, or
write multiple entries.

```console
policy ONLY-FROM-PEER1 {
    entry 10 {
        action permit;
        match {
            next-hop 192.168.0.1;
        }
    }
}
```

Note: `BgpNexthop` is IPv4-only today, so an IPv6 address parses
cleanly but never matches a route. That gap closes when IPv6
unicast nexthop is wired through.

## Numeric match

`med`, `as-path-len`, `as-path-len-uniq`, `local-preference`, and
`weight` all share the same shape: a presence container with a
mandatory `op` choice between `eq NUM`, `le NUM`, and `ge NUM`.
At most one operator per clause; combine with `next` actions or
multiple entries to express ranges.

### `match med`

```console
policy LOW-MED-ONLY {
    entry 10 {
        action permit;
        match {
            med {
                le 100;
            }
        }
    }
}
```

To express "MED between 50 and 200":

```console
policy MED-RANGE {
    entry 10 {
        action permit;
        match {
            med {
                ge 50;
            }
        }
        set {
            ...;
        }
    }
}
```

Combined with another entry that filters out high values, or
with a single `match` block carrying both `match med ge 50` and a
second AND'd clause from a separate `next`-chained entry. (Today
each `match` block has exactly one `med` clause; the spec admits
range-by-chain.)

### `match as-path-len`

The total number of ASes in the AS_PATH, counting prepends.

```console
policy SHORT-PATHS-ONLY {
    entry 10 {
        action permit;
        match {
            as-path-len {
                le 3;
            }
        }
    }
    entry 20 {
        action deny;
    }
}
```

### `match as-path-len-uniq`

The number of *distinct* ASes — same as `as-path-len` but
collapses duplicates. Useful for catching pathological prepend
counts:

```console
policy NO-WEIRD-PREPENDS {
    entry 10 {
        action deny;
        match {
            as-path-len {
                ge 20;
            }
            as-path-len-uniq {
                le 3;
            }
        }
    }
    entry 20 {
        action permit;
    }
}
```

A path of 20+ ASes that are really only 3 distinct ones (e.g.
`65001 65001 65001 ... 65002 65003`) trips this filter.

### `match local-preference`

```console
policy KEEP-HIGH-LP {
    entry 10 {
        action permit;
        match {
            local-preference {
                ge 150;
            }
        }
    }
}
```

### `match weight`

BGP weight is a per-router value (not on the wire) that lives on
the local RIB entry. The matcher reads the route's current
weight as carried through the policy apply path.

```console
policy WEIGHT-1000 {
    entry 10 {
        action permit;
        match {
            weight {
                eq 1000;
            }
        }
    }
}
```

For a route arriving on a peer where no `set weight` has been
applied yet, the carried weight is 0. `match weight eq 0`
matches; `match weight ge 1` does not.

## Enum match

### `match origin`

Matches the route's ORIGIN attribute against one of the three
RFC 4271 values:

```console
policy IGP-ONLY {
    entry 10 {
        action permit;
        match {
            origin igp;
        }
    }
    entry 20 {
        action deny;
    }
}
```

## All clauses are AND'd

```console
policy STRICT {
    entry 10 {
        action permit;
        match {
            prefix CUSTOMER-NETS;
            as-path FROM-65003;
            med {
                le 100;
            }
            origin igp;
        }
    }
}
```

A route is permitted only if it is in `CUSTOMER-NETS`, has an
AS_PATH containing `65003`, has `MED <= 100`, and has `ORIGIN =
igp`. Any one missing — and the clause fails, the entry skips,
default-deny applies.
