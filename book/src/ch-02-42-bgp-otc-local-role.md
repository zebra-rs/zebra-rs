# BGP Roles and Only-to-Customer (RFC 9234)

A **route leak** is a route that travels in a direction the business
relationships between ASes do not allow — most commonly a customer
re-advertising what it learned from one provider to another provider
(or to a peer), turning itself into unintended transit. RFC 9234 stops
the common cases with two small additions to BGP:

- a **BGP Role** for each eBGP session, negotiated in the OPEN message so
  both ends agree on what the relationship is, and
- an **Only-to-Customer (OTC)** path attribute that marks a route as "may
  only be advertised to customers from here on".

zebra-rs implements both, with the Cisco IOS XR command syntax:

```
router bgp {
  neighbor 10.10.10.2 {
    remote-as 65540;
    otc-local-role customer;           // loose mode (default)
    otc-local-role provider strict;    // strict mode
  }
}
```

## Roles

The role is configured from the **local** AS's point of view, on the
session toward the neighbor. The neighbor configures the matching role on
its side.

| Local role | Meaning | Valid remote role |
|---|---|---|
| `provider` | The local AS provides transit to the neighbor. | `customer` |
| `customer` | The local AS receives transit from the neighbor. | `provider` |
| `peer` | Settlement-free lateral peering: routes are exchanged, transit is not provided in either direction. | `peer` |
| `route-server-client` | The neighbor is an IXP route server (RFC 7947). | `route-server` |
| `route-server` | This router is the route server. A zebra-rs superset over IOS XR, which has no route-server function; note that zebra-rs itself has no route-server (transparent AS_PATH) mode yet, so this value only completes the wire-level pair. | `route-server-client` |

Any other combination — provider/provider, customer/peer, … — is a
**Role Mismatch**, and the session is refused.

Roles are defined for **eBGP** only. The knob is accepted on an iBGP
neighbor but inert (no Role capability is sent, nothing is checked, no
OTC processing happens); `show bgp neighbor` says `(ignored on iBGP)`.

## What happens at session start

If a role is configured, the OPEN message carries the **BGP Role
capability** (code 9). When the neighbor's OPEN arrives:

| Neighbor sent a role? | Pair valid? | Loose mode (default) | `strict` |
|---|---|---|---|
| yes | yes | session proceeds; remote role shown as `(received)` | same |
| yes | no | **Role Mismatch NOTIFICATION** (OPEN Message Error, subcode 11); session does not come up | same |
| no | — | session proceeds; the remote role is **inferred** as the counterpart of ours and shown as `(inferred)` | **Role Mismatch NOTIFICATION** |

A neighbor that sends several Role capabilities with different values,
or a role value outside the assigned range 0–4, is also a mismatch.

Loose mode is the backward-compatible default: it lets you enable roles on
your side before the neighbor supports or configures them, and your side
already applies the OTC procedures below using the inferred role. Strict
mode is for when you want the configuration on both ends verified before
any routes flow.

Roles are exchanged only in the OPEN, so **changing the role or the mode
on a live session resets it** (the same as IOS XR: `Down - OTC local role
changed`).

## What happens to routes

OTC (path attribute type 35, optional transitive) carries one AS number:
the AS that marked the route. Once set, it is never changed — it rides
through iBGP and route reflectors untouched, and zebra-rs does not offer
a policy action to strip or rewrite it (RFC 9234 §6 forbids one).

The procedures apply to **IPv4 unicast and IPv6 unicast** only; VPN,
labeled and EVPN families are never touched (§6).

| Rule | Direction | When | Action |
|---|---|---|---|
| IR1 | receive | OTC present on a route from a **customer** (we are `provider`) or an **RS-client** (we are `route-server`) | Route leak: the route is **ineligible** — not stored, not selected, not re-advertised. Counted per neighbor. |
| IR2 | receive | OTC present on a route from a **peer** (we are `peer`) and OTC ≠ the peer's AS | Route leak, ineligible, counted. |
| IR3 | receive | OTC absent on a route from a **provider**, **peer** or **RS** (we are `customer`, `peer` or `route-server-client`) | Add OTC = the neighbor's AS. The stored route carries it. |
| ER1 | advertise | OTC absent, toward a **customer**, **peer** or **RS-client** (we are `provider`, `peer` or `route-server`) | Add OTC = our AS (the [`local-as`](ch-02-30-bgp-local-as.md) substitute when one is active — the AS the neighbor sees). |
| ER2 | advertise | OTC present, toward a **provider**, **peer** or **RS** (we are `customer`, `peer` or `route-server-client`) | **Do not advertise.** |

Only the side that has a role configured runs the procedures. In loose
mode with a role on one side only, that side still stamps (IR3 / ER1) and
polices (IR1 / IR2 / ER2) on its own, using the inferred remote role.

### The classic leak

```
 ┌─────────┐  provider ─ customer  ┌─────────┐  customer ─ provider  ┌─────────┐
 │   z1    │ ───────────────────── │   z2    │ ───────────────────── │   z3    │
 │ AS65001 │                       │ AS65002 │                       │ AS65003 │
 └─────────┘                       └─────────┘                       └─────────┘
 originates 10.0.0.1/32
```

`z1` (provider toward `z2`) advertises `10.0.0.1/32` with `OTC-AS: 65001`
(ER1). `z2` is a customer of both `z1` and `z3`; because the route
carries OTC, `z2` must not advertise it to its other provider `z3` (ER2).
`z3` never sees the route — the leak is **prevented** on `z2`.

If `z2` had no role configured toward `z3` it would forward the marked
route anyway; `z3`, configured as `provider` toward `z2`, then
**detects** the leak on receipt (IR1) and refuses it.

## Configuration

Per neighbor, in YAML — the list is keyed by the role, with an optional
`strict` leaf:

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
      otc-local-role:
      - role: customer          # customer | provider | peer |
                                # route-server-client | route-server
        strict: null            # optional; `strict` is a type-empty leaf
```

The equivalent CLI:

```
set router bgp neighbor 192.168.0.1 otc-local-role customer
set router bgp neighbor 192.168.0.1 otc-local-role customer strict
```

`otc-local-role` is single-instance: setting a second role while one is
configured is refused with a warning — delete the current one first, as
with [`local-as`](ch-02-30-bgp-local-as.md):

```
delete router bgp neighbor 192.168.0.1 otc-local-role customer
set router bgp neighbor 192.168.0.1 otc-local-role provider
```

Like the other per-neighbor knobs it can be set on a
[neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited by every
member (a statement on the neighbor itself wins), and on a
[VRF](ch-02-04-bgp-l3vpn.md) neighbor.

## Verification

`show bgp neighbor` uses the IOS XR lines:

```
  OTC Local Mode: Loose
  OTC Local Role : Provider
  OTC Remote Role: Customer (received)
    By OTC ingress rule 1: 0, By OTC ingress rule 2: 0

  Neighbor Capabilities:
    4 Octet AS: advertised and received
    OTC Role: advertised (Provider) and received (Customer)
```

`(received)` means the neighbor sent its role; `(inferred)` means it sent
none and loose mode derived it from ours. A session refused for a role
problem never reaches Established, so the reason is shown explicitly:

```
  BGP state = Idle
  OTC Local Mode: Strict
  OTC Local Role : Provider
  OTC Remote Role: Customer (inferred)
  OTC Role Mismatch: no BGP Role capability received (strict mode) (sent Role Mismatch NOTIFICATION)
```

or, for an invalid pair:

```
  OTC Role Mismatch: received Provider, local Provider (not a valid pair) (sent Role Mismatch NOTIFICATION)
```

The `By OTC ingress rule 1/2` counters increment for every leak the
neighbor sent that was refused (IR1 / IR2). With `tracing adj-in` enabled
on the neighbor, each refusal is logged as
`UPDATE received from <peer> DENIED due to OTC ingress rule 1: route leak
from Customer/RS-Client`.

A marked route shows the attribute in `show bgp <prefix>`:

```
show bgp 10.0.0.1/32
...
    OTC-AS: 65001
```

and as `otc_as` in `show bgp -j` (JSON).

## Interplay with other knobs

- [`enforce-first-as`](ch-02-15-bgp-enforce-first-as.md),
  [`allowas-in`](ch-02-13-bgp-allowas-in.md),
  [`as-override`](ch-02-12-bgp-as-override.md) and
  [`remove-private-as`](ch-02-14-bgp-remove-private-as.md) act on the
  AS_PATH and are independent of roles; they may be combined freely.
- [`local-as`](ch-02-30-bgp-local-as.md): ER1 stamps the AS the neighbor
  sees — the substitute — so the mark agrees with what the neighbor's own
  IR3 would have written.
- Outbound and inbound route policies still apply; a route ER2 suppresses
  is withdrawn from that neighbor exactly like one an outbound policy
  denies.
- Update groups: the local role is part of the update-group signature, so
  neighbors under different roles never share an encoded UPDATE (see
  `docs/design/bgp-update-groups.md`).

## Limitations

- **eBGP only**, IPv4/IPv6 unicast only — as the RFC specifies.
- No per-prefix role override (IOS XR's RPL `set otc-local-role`). RFC
  9234 §6 says roles must not be configured on sessions with a *complex*
  relationship; use separate sessions instead.
- `route-server` completes the role pair on the wire, but zebra-rs has no
  route-server mode (transparent AS_PATH) yet; that is a separate,
  planned feature.

## References

- [RFC 9234](https://www.rfc-editor.org/rfc/rfc9234.html) — Route Leak
  Prevention and Detection Using Roles in UPDATE and OPEN Messages.
- Cisco IOS XR 26.4.1, *RFC 9234 BGP Only-to-Customer (OTC) on IOS XR*
  (xrdocs) — the syntax and output format zebra-rs follows.
