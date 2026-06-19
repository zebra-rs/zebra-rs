# BGP Local AS (AS Migration)

An eBGP session is pinned to AS numbers on both ends: each side
configures the other's AS as `remote-as`, and the OPEN message carries
the sender's own AS for the peer to validate. That coupling becomes a
problem the day a network **changes its AS number** — after a merger,
an acquisition, or a registry renumbering. The router can switch its
global AS in one commit, but every external peer validates the session
against the *old* AS and refuses the new one until its operator edits
their side. Hundreds of sessions cannot be re-coordinated in one
maintenance window.

`neighbor X local-as N` decouples the two: the router keeps its new
global AS internally while **presenting the old AS `N` to one
neighbor**. The session keeps validating, routes keep flowing, and each
peer migrates to the new AS on its own schedule (RFC 7705 describes the
mechanism family).

## What local-as does

With `local-as 64999` configured on a session (router's real AS
65100), three things change — one per plane:

1. **Session**: the OPEN message's My-AS field (and the four-octet AS
   capability) carry `64999`, so a peer configured with
   `remote-as 64999` accepts the session.
2. **Outbound**: routes advertised to this neighbor get the real AS
   prepended first and then the substitute, so the peer sees an
   AS_PATH beginning `64999 65100 …`.
3. **Inbound**: routes received from this neighbor get `64999`
   prepended at ingress, so the rest of the network — iBGP peers and
   every other neighbor — sees the path as if it still transited the
   old AS, and loop prevention through `64999` keeps working.

The bare form therefore inflates the AS_PATH by one hop in **both**
directions. That is deliberate (it preserves the pre-migration
topology as seen from outside), but it also lengthens paths and can
shift best-path decisions — which is what the modifiers are for.

## The modifiers

Three independent boolean flags refine the bare behavior, one per
plane:

| Flag | Plane | Effect when `true` |
|------|-------|--------------------|
| `no-prepend` | inbound | Do not prepend `64999` to routes received from this neighbor. |
| `replace-as` | outbound | Prepend only `64999` to routes sent to this neighbor — hide the real AS entirely. |
| `dual-as` | session | Let the neighbor peer with **either** AS: after a Bad Peer AS notification the next OPEN retries with the other AS number. |

FRR and IOS nest these on the command line (`replace-as` requires
`no-prepend`, `dual-as` requires both), but that nesting is CLI
convention, not semantics — the flags act on different planes and are
modeled independently here, as in FRR's own northbound data model.

A concrete AS_PATH walkthrough — real AS 65100, `local-as 64999`,
advertising a route whose path is currently `65010`, and receiving a
route with path `65001` from the same neighbor:

```
                        peer sees (outbound)     network sees (inbound)
 no local-as            65100 65010              65001
 local-as (bare)        64999 65100 65010        64999 65001
 + replace-as           64999 65010              64999 65001
 + no-prepend           64999 65100 65010        65001
 + both                 64999 65010              65001
```

With both flags set, the substitute AS exists *only* on the wire of
this one session — the peer sees a clean `64999`-originated world and
the local network sees no trace of `64999`. This is the usual end-state
configuration during a migration; the bare form is the conservative
starting point.

`dual-as` is the no-coordination knob: while it is set, the neighbor's
operator may flip their `remote-as` from `64999` to `65100` at any
moment. The next session attempt fails AS validation once, the router
falls back to the other AS number, and the session re-establishes —
no maintenance window on either side. Once the peer has migrated,
remove `local-as` entirely.

## Configuration

`local-as` takes the substitute AS number directly after the keyword,
followed by the optional flags:

```yaml
router:
  bgp:
    global:
      as: 65100
      router-id: 192.168.0.2
    neighbor:
    - remote-address: 192.168.1.3
      remote-as: 65001
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      local-as:
      - as-number: 64999
        no-prepend: true
        replace-as: true
        dual-as: true
```

The equivalent CLI paths:

```
set router bgp neighbor 192.168.1.3 local-as 64999
set router bgp neighbor 192.168.1.3 local-as 64999 no-prepend true
set router bgp neighbor 192.168.1.3 local-as 64999 replace-as true
set router bgp neighbor 192.168.1.3 local-as 64999 dual-as true
```

which renders in the running configuration as:

```
neighbor 192.168.1.3 {
    local-as 64999 {
        no-prepend true;
        replace-as true;
        dual-as true;
    }
}
```

Two constraints are enforced at commit time:

- the substitute AS must **differ from the router's global AS** —
  `local-as 65100` on an AS 65100 router is rejected, matching FRR;
- `local-as` is **single-instance per neighbor** — it is modeled as a
  list keyed by the AS number so the CLI reads like FRR's, but a
  second entry is refused. To change the substitute AS, delete the old
  entry first:

```
delete router bgp neighbor 192.168.1.3 local-as 64999
set router bgp neighbor 192.168.1.3 local-as 65555
```

`local-as` is an eBGP-session tool: it changes which AS the session
speaks and how eBGP prepending behaves. Changing it on an established
session re-negotiates the session (the OPEN must carry the new AS), so
expect a bounce on commit.

## Verification

The fastest check is the peer's view. On an FRR neighbor configured
with `remote-as 64999`:

```
show bgp neighbor 192.168.1.3   # remote AS shows 64999, session Established
show bgp 10.0.0.0/24         # AS_PATH begins 64999 …
```

On the local router, `show bgp neighbor <addr>` reports the
substitute AS for the session, and `show bgp <prefix>` on a route
learned from the neighbor shows whether the ingress prepend is active
(`64999` leading the path, unless `no-prepend true`).

## Troubleshooting

- **Session won't establish after configuring local-as** — the peer is
  still validating against the AS your OPEN no longer carries. Check
  which AS the peer's `remote-as` expects: with `local-as` set, your
  OPEN carries the substitute AS, not the global one. `dual-as true`
  makes the router tolerate either expectation.
- **Peer rejects routes as loops** — the peer's own AS appears in the
  prepended path. Remember the bare form adds *two* ASes outbound
  (substitute + real); if the peer previously relied on seeing only
  one, use `replace-as true`.
- **Internal best-path changed after enabling local-as** — the ingress
  prepend lengthens received paths by one. If pre-migration path
  lengths must be preserved inside the network, set `no-prepend true`.
- **Substitute AS equals the global AS** — rejected by design; if the
  goal is to peer under the global AS, simply remove `local-as`.

Like [`as-override`](ch-02-12-bgp-as-override.md) and the other
egress-affecting per-neighbor knobs, `local-as` is part of the
update-group signature: neighbors with different `local-as` settings
never share an encoded UPDATE, so no cross-peer leakage of the
substitute AS can occur.
