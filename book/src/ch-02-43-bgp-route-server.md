# BGP Route Server (RFC 7947)

At an Internet Exchange, members would rather not maintain a full mesh of
bilateral eBGP sessions. A **route server** takes their routes and hands
them to every other member — but unlike an ordinary transit router it
must be **transparent**: the member receiving a route must see it exactly
as the originating member sent it, so that the AS_PATH still reflects
the real AS-level topology and traffic flows member-to-member across the
exchange LAN, never through the server.

`neighbor X route-server-client` makes zebra-rs behave as that server
toward the named neighbor.

```
router bgp {
  neighbor 192.168.0.1 {
    remote-as 65001;
    route-server-client;
  }
}
```

## What changes toward a route-server client

RFC 7947 lists what a route server must *not* do to a route it
re-advertises. Toward a `route-server-client` neighbor zebra-rs:

| RFC 7947 | Ordinary eBGP advertisement | Toward a route-server client |
|---|---|---|
| §2.2.2 AS_PATH | prepend the local AS (after `remove-private-as` / `as-override` / `local-as` rewrites) | **leave it untouched** — no prepend, and none of the rewrites, which only exist to shape a prepended path |
| §2.2.1 NEXT_HOP | rewrite to this router's address | **keep the received next-hop** on forwarded routes, so the client forwards straight to the originating member on the exchange LAN. Locally originated routes still carry this router's address |
| §2.2.2.1 MED | pass through | pass through |
| §2.2.2.2 communities | pass through | pass through |

It applies to **IPv4 and IPv6 unicast** and to **eBGP** neighbors (an
iBGP neighbor never prepends or rewrites anyway). Inbound processing from
a client is ordinary eBGP — the server's own AS never appears in a
client's AS_PATH, so the loop check is unaffected.

### Path hiding

With a single best path per prefix, a route server that has *two*
members announcing the same prefix would advertise only its own winner
to everyone — hiding the other path from members that would prefer it
(RFC 7947 §2.3). The RFC's remedies are a per-client Loc-RIB or
**ADD-PATH** (RFC 7911). zebra-rs takes the second: enable `add-path
send` on the client sessions and every member path is advertised.

```yaml
      afi-safi:
      - name: ipv4
        enabled: true
        add-path: send
```

## Topology

```
┌────────────────────────────────────────────────────────────┐
│                       exchange LAN                         │
└──────────┬──────────────────┬──────────────────┬───────────┘
      ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
      │   z1    │        │   rs    │        │   z3    │
      │ AS65001 │        │ AS65000 │        │ AS65003 │
      │  .0.1   │        │  .0.2   │        │  .0.3   │
      └─────────┘        └─────────┘        └─────────┘
 originates 10.0.0.1/32                originates 10.0.0.3/32
```

Without the knob, `z3` receives `10.0.0.1/32` with AS_PATH `65000 65001`
and next-hop `192.168.0.2` — the server is in the data path and in the
AS path. With `route-server-client` on both of `rs`'s sessions, `z3`
receives AS_PATH `65001` with next-hop `192.168.0.1` and forwards to
`z1` directly.

## Configuration

On the route server, per member:

```yaml
router:
  bgp:
    global:
      as: 65000
      router-id: 192.168.0.2
    neighbor:
    - remote-address: 192.168.0.1
      remote-as: 65001
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      route-server-client: {}
    - remote-address: 192.168.0.3
      remote-as: 65003
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      route-server-client: {}
```

`route-server-client: {}` is the YAML spelling of a presence container;
the CLI form is

```
set router bgp neighbor 192.168.0.1 route-server-client
```

An exchange normally puts every member into one
[neighbor-group](ch-02-26-bgp-neighbor-group.md) and sets the knob once
there; a statement on the neighbor itself wins. It is also available on
[VRF](ch-02-04-bgp-l3vpn.md) neighbors.

Setting or clearing the knob on a live session **resets the session**:
every route already advertised to the client carries the old AS_PATH and
next-hop, and the cleanest way to replace them all is to let the client
re-receive the table.

**On the member side**, do not enable
[`enforce-first-as`](ch-02-15-bgp-enforce-first-as.md) toward a route
server — every route it sends starts with *another member's* AS, so the
check would drop all of them.

## Verification

```
show bgp neighbor 192.168.0.1
...
  Route-server client: enabled (transparent AS_PATH and next-hop, RFC 7947)
```

On a member, `show bgp 10.0.0.1/32` shows the originating member's path
and next-hop:

```
  65001
    192.168.0.1 from 192.168.0.2
```

## With RFC 9234 roles

The [BGP Role](ch-02-42-bgp-otc-local-role.md) pair for this topology is
`otc-local-role route-server` on the server and `otc-local-role
route-server-client` on each member. The server then marks every route it
hands out with `OTC-AS: 65000` (ER1) and refuses an OTC-marked route a
member tries to push back through it (IR1); a member refuses to leak a
marked route toward the server (ER2). Note that the OTC value is the
**server's** AS, exactly as RFC 9234 specifies — not the originating
member's.

## Interplay and precedence

- `as-override`, `remove-private-as` and `local-as` are ignored toward a
  route-server client (a warning is logged when they overlap): there is no
  prepend for them to shape.
- `afi-safi … next-hop-self` does not override the transparent next-hop
  for forwarded routes; `next-hop-unchanged` is implied.
- Outbound policy still applies per client — this is how an exchange
  implements member-specific export filtering.
- Update groups: route-server clients form their own update group (the
  signature carries the knob), so they never share an encoded UPDATE with
  ordinary eBGP neighbors.

## Limitations

- No per-client Loc-RIB (RFC 7947 §2.3.2.1); use ADD-PATH for path
  hiding.
- IPv4/IPv6 unicast only.

## References

- [RFC 7947](https://www.rfc-editor.org/rfc/rfc7947.html) — Internet
  Exchange BGP Route Server.
- [RFC 7948](https://www.rfc-editor.org/rfc/rfc7948.html) — Internet
  Exchange BGP Route Server Operations (background on path hiding and
  member filtering).
