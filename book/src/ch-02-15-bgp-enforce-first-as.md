# BGP Enforce First AS

A well-behaved eBGP speaker **prepends its own AS** to the AS_PATH of
every UPDATE it sends. The left-most (first) AS a receiver sees is
therefore always the directly-connected peer's AS — that is the basic
accounting that makes the path-vector loop check work.

`neighbor X enforce-first-as` makes that guarantee **mandatory** on the
receiving side. An inbound UPDATE from this eBGP neighbor is discarded
unless its AS_PATH begins with an `AS_SEQUENCE` whose left-most AS is the
neighbor's own AS. It defends against a misconfigured or malicious peer
that forwards routes **without** prepending its AS, which would otherwise
let it inject paths that bypass the normal hop-by-hop accounting (and, for
example, pretend a route is one AS hop shorter than it really is).

## What the check does

For each route received from a neighbor that has `enforce-first-as`
enabled, zebra-rs inspects the AS_PATH:

- The first segment must be an `AS_SEQUENCE` (not an `AS_SET` and not a
  confederation segment), **and**
- its left-most AS must equal the neighbor's configured `remote-as`.

If either condition fails — including an **empty or absent** AS_PATH — the
update is dropped (treated as a withdraw). A route whose path starts with
some other AS, or with a `{…}` AS_SET, never enters the Adj-RIB-In.

The check applies to **eBGP sessions only**. iBGP never prepends the local
AS, so an iBGP UPDATE legitimately starts with whatever AS originated or
last-prepended the route; the knob is a no-op on iBGP peers and is
ignored.

## The problem it catches

```
 ┌─────────┐                    ┌─────────┐
 │   z1    │ ──── eBGP ──────── │   z2    │
 │ AS65001 │                    │ AS65002 │
 └─────────┘                    └─────────┘
 originates 10.0.0.1/32
```

Suppose `z1` advertises `10.0.0.1/32` to `z2` but the AS_PATH that arrives
is `65099 65001` — the left-most AS is `65099`, not `z1`'s own `65001`
(perhaps `z1` is a transparent box that prepended a foreign AS, or simply
failed to prepend its own). Without `enforce-first-as`, `z2` accepts the
path at face value. The route looks like it traverses AS 65099 first, even
though `z2`'s actual neighbor is AS 65001.

With `enforce-first-as` on `z2`'s session toward `z1`, `z2` requires the
left-most AS to be `65001` and discards the update, because it starts with
`65099`.

## Configuration

`enforce-first-as` is a per-neighbor flag. Configure it on the receiving
end, on the session toward the peer whose first AS you want to police:

```yaml
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
      enforce-first-as: null
```

`enforce-first-as: null` is the YAML spelling of a presence container —
the key is present with no value, which the loader turns into
`set router bgp neighbor 192.168.0.1 enforce-first-as`. The FRR / IOS-style
CLI form is the same path:

```
set router bgp neighbor 192.168.0.1 enforce-first-as
```

Enabling `enforce-first-as` on an already-established session does not by
itself re-screen routes already in the neighbor's Adj-RIB-In. Bounce the
session so the routes are re-received and re-checked under the new policy:

```
clear bgp ipv4 neighbor 192.168.0.1
```

Like the other per-neighbor knobs, `enforce-first-as` can also be set on
a [neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited by
every member; a statement on the neighbor itself wins.

## Verification

`show ip bgp neighbor <addr>` reports whether the knob is active:

```
  Enforce-first-AS enabled (drop inbound updates not starting with peer AS)
```

After enabling it (and bouncing the session), a route that fails the
check simply will not appear in the table:

```
show ip bgp 10.0.0.1/32
```

## Relationship to allowas-in and as-override

All three are AS_PATH knobs, but they police different things:

- [`allowas-in`](ch-02-13-bgp-allowas-in.md) relaxes the inbound check for
  the **local** AS appearing *anywhere* in the path (loop relaxation).
- [`as-override`](ch-02-12-bgp-as-override.md) rewrites the **neighbor's**
  AS on the *outbound* path.
- `enforce-first-as` tightens the inbound check on the **left-most** AS:
  it must be the neighbor's own AS.

They are independent and may be combined.

## Troubleshooting

If routes from a peer disappear unexpectedly after enabling
`enforce-first-as`, the peer is sending a path that does not start with its
own AS. The most important case to recognise is a **transparent route
server** (RFC 7947): a route server deliberately does **not** prepend its
own AS, so every UPDATE it sends starts with a *client's* AS. Enabling
`enforce-first-as` on a session toward a route server will drop **all** of
its routes — do not enable it there.

Other things to check:

- the session is **eBGP** (`enforce-first-as` is ignored on iBGP);
- the left-most AS really is the neighbor's **remote-as** — a leading
  `AS_SET` (`{…}`) or confederation segment also fails the check, even if
  it contains the right AS;
- the session was **bounced** (`clear bgp ipv4 neighbor <addr>`) after the
  configuration change, so the routes were re-screened under the new
  policy.
