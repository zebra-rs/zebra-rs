# BGP Route Reflector

A route reflector (RR, RFC 4456) relaxes the iBGP full-mesh
requirement: instead of every iBGP speaker peering with every other,
clients peer only with the reflector, which re-advertises
("reflects") their routes on their behalf. zebra-rs implements the
reflection rules with two per-neighbor knobs and adds one
instance-level knob for the common case where the reflector is *not*
in the forwarding path.

## Reflection (per neighbor)

A neighbor is marked as a client, and the cluster is identified, under
the IETF `route-reflector` container:

```
router bgp {
  neighbor 10.0.0.1 {
    route-reflector {
      client true;
      cluster-id 1.1.1.1;
    }
  }
}
```

| YANG leaf | Default | Meaning |
|---|---|---|
| `…/neighbor/route-reflector/client` | `false` | Treat this neighbor as a reflector client. |
| `…/neighbor/route-reflector/cluster-id` | router-id | Cluster identifier used for loop detection. |

The reflection rule zebra-rs enforces is the standard one: an
iBGP-learned route is re-advertised to a peer only when that peer is a
reflector client (eBGP peers always receive it). Plain
iBGP→iBGP advertisement between non-clients is suppressed, which is
what removes the need for a full mesh.

`route-reflector client` can also be set on a
[neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited by every
member; a statement on the neighbor itself wins. Setting it on the group
marks every member as a client — iBGP members only, as ever.

## Keeping reflected routes out of the FIB

A dedicated route reflector usually sits *outside* the data path: it
reflects routes between clients but never forwards transit traffic for
them. On such a box, programming every selected BGP best-path into the
kernel forwarding table is pure overhead — it consumes memory and
netlink/FIB churn for entries no packet will ever hit, and on a large
RR holding the full table that cost is significant.

`no-fib-install` makes the instance run as a pure control-plane
speaker:

```
router bgp {
  global {
    no-fib-install true;
  }
}
```

| YANG leaf | Default | Meaning |
|---|---|---|
| `/router/bgp/global/no-fib-install` | `false` | Suppress installation of selected routes into the FIB. |

When enabled:

- **The control plane is unchanged.** The Loc-RIB is still built,
  best-path selection still runs, next-hop tracking still validates
  next-hops, and routes are still reflected and advertised to peers.
- **No forwarding entry is programmed.** IPv4 and IPv6 unicast routes,
  and the MPLS entries behind VPN, EVPN and labeled-unicast routes,
  are all withheld from the kernel. The suppression is applied
  centrally on the instance's RIB client, so every address family is
  covered by the single knob — there is no per-AFI gap to forget.

This is the difference between a reflector that merely *reflects* and
one that also tries to *forward*: with `no-fib-install` the speaker
contributes only to the control plane.

### Scope and semantics

- **Instance scope.** The knob applies to the default-VRF BGP
  instance. Per-VRF suppression (for a VPN route reflector that also
  carries per-VRF routes) is a separate, future knob; today a non-zero
  VRF still installs normally.
- **Set it at startup.** The intended use is to configure
  `no-fib-install` before sessions come up, so no forwarding entry is
  ever programmed. The flag takes effect immediately for every
  *subsequent* route update.
- **Runtime toggling is not retroactive.** Turning the flag *on* does
  not walk back and withdraw routes that were already installed while
  it was off; those entries are removed as normal route churn
  (withdrawals, best-path changes) flows through — withdrawals are
  never suppressed. If you need an immediate clean slate, clear the
  affected routes or restart the instance.

### Relationship to reflection

`no-fib-install` is independent of the `route-reflector` client
configuration. A speaker can reflect without it (a reflector that is
also a forwarding router) or enable it without marking any clients (a
control-plane-only collector). The common route-reflector deployment
combines the two: clients marked under `route-reflector`, and
`no-fib-install true` so the reflector stays out of the data path.
