# BGP SRv6 Encapsulation Type (per-neighbor)

In an SRv6 network, an IPv6 unicast route can carry an **SRv6 service
SID** in the BGP Prefix-SID attribute (RFC 9252 / RFC 8669) — the SID a
remote PE programs to deliver traffic for that prefix. `encapsulation-type`
is a per-neighbor, per-address-family knob that declares how strict the
session is about that SID for the **IPv6 unicast** family:

- **`srv6`** — *SRv6-only* peer. Only routes carrying an SRv6 service SID
  are exchanged with the neighbor; a route without a SID is filtered out
  on the session.
- **`srv6-relax`** — *mixed* session. Routes with or without an SRv6 SID
  may be exchanged with the neighbor.

It is the BGP-session counterpart to the data-plane SRv6 encapsulation
configured elsewhere (see [SRv6](ch-04-00-srv6.md) and
[L3VPN over an SRv6 Underlay](ch-02-05-bgp-l3vpn-srv6.md)): those chapters
cover *how* a SID is programmed into the forwarding plane, while this knob
governs *which* IPv6 unicast routes are allowed to ride a given session
based on whether they carry a SID.

## When you need it

Use `srv6` on a session that must stay SRv6-pure — for example a fabric
where every IPv6 prefix is expected to resolve to an SRv6 SID and a
SID-less route would represent a misconfiguration or a non-SRv6 leak that
should not be propagated. Use `srv6-relax` on a boundary session that
carries a mix of SRv6 and plain IPv6 unicast routes to the same peer and
must not drop the SID-less ones.

When the knob is **absent** the family behaves as ordinary IPv6 unicast:
no SID-based filtering is applied in either direction.

## Modes at a glance

| Mode         | SID-bearing routes | SID-less routes |
|--------------|--------------------|-----------------|
| *(unset)*    | exchanged          | exchanged       |
| `srv6`       | exchanged          | **filtered**    |
| `srv6-relax` | exchanged          | exchanged       |

`srv6-relax` differs from the unset default in *intent*: it marks the
session as SRv6-aware (so SID-bearing routes are treated as first-class)
while explicitly tolerating SID-less routes, whereas the unset default is
simply SRv6-agnostic.

## Configuration

`encapsulation-type` lives under the neighbor's IPv6 `afi-safi` entry. The
schema restricts it to the `ipv6` family (`when name = 'ipv6'`), so it is
only valid there.

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.255.0.1
    neighbor:
    - remote-address: 2001:db8::8
      remote-as: 65002
      enabled: true
      afi-safi:
      - name: ipv6
        enabled: true
        encapsulation-type: srv6
```

The equivalent CLI form is the same path:

```
set router bgp neighbor 2001:db8::8 afi-safi ipv6 encapsulation-type srv6
```

Replace `srv6` with `srv6-relax` for the mixed-session variant. Delete the
leaf to return the family to the SRv6-agnostic default:

```
delete router bgp neighbor 2001:db8::8 afi-safi ipv6 encapsulation-type
```

## Verification

`show ip bgp neighbor <addr>` echoes the configured mode for the IPv6
unicast family:

```
  IPv6 Unicast encapsulation-type: srv6
```

The line is omitted when the knob is unset.

## Enforcement

The filter is applied symmetrically on a `srv6` session:

- **Receive** — a plain IPv6 unicast route that arrives without an SRv6
  service SID is dropped before it reaches the Adj-RIB-In / Loc-RIB.
- **Advertise** — a route without an SRv6 service SID is withheld from
  the peer (no NLRI is emitted for it).

A route's SID rides in the BGP Prefix-SID attribute, so a route learned
*with* a SID propagates through unchanged and passes the filter at the
next `srv6` hop. `srv6-relax` and the unset default apply no filtering.

## Originating SRv6 SIDs for the global IPv6 table

For the local router to *advertise* its own IPv6 unicast routes
(`network`, redistribution) to a `srv6` peer, those routes must carry a
SID. Enable End.DT6 origination for the global (default-table) IPv6
unicast family under `segment-routing srv6`:

```yaml
router:
  bgp:
    segment-routing:
      srv6:
        locator: LOC1
        ipv6-unicast: null    # presence: originate an End.DT6 SID
```

```
set router bgp segment-routing srv6 locator LOC1
set router bgp segment-routing srv6 ipv6-unicast
```

`ipv6-unicast` is the global-table analogue of a per-VRF `encapsulation
srv6`. When it is set and the `locator` resolves, the BGP speaker carves a
single **End.DT6** service SID from the locator, advertises locally-
originated IPv6 unicast routes with that SID (in the BGP Prefix-SID
attribute) and the locator as the next-hop, and programs a `seg6local`
End.DT6 decap into the main table. A remote PE then H.Encaps traffic to
the locator, and the local End.DT6 decapsulates and forwards via the
global IPv6 table. Until the `locator` resolves, origination is SID-less
(and such routes are withheld from `srv6` peers).

Routes *received* with a SID are re-advertised preserving their SID, so a
transit router needs `ipv6-unicast` only if it also originates routes of
its own.

> The per-neighbor `encapsulation-type` (the session filter) and the
> instance `ipv6-unicast` (SID origination) are independent: a route
> reflector might originate nothing yet still filter, while an edge PE
> originates SIDs that any downstream `srv6` peer then accepts.

See also [L3VPN over an SRv6 Underlay](ch-02-05-bgp-l3vpn-srv6.md), which
uses the same locator machinery to carve per-VRF End.DT46 SIDs.
