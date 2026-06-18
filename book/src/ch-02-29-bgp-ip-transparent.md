# ip-transparent (peer as an address you don't own)

`ip-transparent` sets the **IP_TRANSPARENT** (IPv4) / **IPV6_TRANSPARENT**
(IPv6) socket option on one neighbor's TCP session. With it, the session
can use a local address that is **not configured anywhere on the host**:
normally the kernel rejects a `bind()` to a non-local address and refuses
to emit packets with a non-local source; IP_TRANSPARENT (which requires
`CAP_NET_ADMIN`) bypasses both checks. The address itself comes from
[`update-source`](ch-02-11-bgp-ttl-security.md), so the two are configured
together: **`update-source` names the address you don't own,
`ip-transparent` makes the kernel accept it.**

This mirrors FRR 10.4 `neighbor PEER ip-transparent`
(FRRouting/frr PR #18789).

## When you need it

- **Containers** — bgpd runs in a netns that does not have the router's
  loopback plumbed, but must peer *as* the loopback address.
- **Hitless VRRP/keepalived takeover** — the standby pre-binds the virtual
  IP and establishes immediately after failover, instead of waiting for
  the VIP to be plumbed and then re-dialing. Pairs naturally with
  `passive`: pre-bind, wait, accept once traffic arrives.
- **Transparent firewalls** — a bump-in-the-wire box terminating or
  originating BGP with addresses that belong to the devices around it.

## The caveat: return traffic is your problem

IP_TRANSPARENT only liberates the **local socket**. The kernel still has
to deliver inbound packets destined to the non-local address to the
daemon, and nothing on the host does that by default — outbound SYNs
leave with the foreign source, but the SYN-ACK coming back is *forwarded*
(or dropped), never delivered locally. You need one of the usual
mechanisms on top:

- an AnyIP-style local route: `ip route add local 10.255.0.0/24 dev lo`;
- TPROXY-style policy routing:

  ```
  iptables -t mangle -A PREROUTING -p tcp -j MARK --set-mark 0x100
  ip rule add fwmark 0x100 lookup 100
  ip route add local default dev lo table 100
  ```

- or, in the VRRP case, the fact that the peer simply does not route to
  the VIP until this node owns it.

Path-side anti-spoofing (uRPF on the upstream, etc.) must also tolerate
the non-local source.

## Configuration

`ip-transparent` is a per-neighbor presence flag:

```yaml
router:
  bgp:
    global:
      as: 65002
      router-id: 10.0.0.2
    neighbor:
    - remote-address: 10.0.0.1
      remote-as: 65001
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      update-source: 10.255.0.99   # an address this host does NOT own
      ip-transparent: {}
```

The CLI form is the same path:

```
set router bgp neighbor 10.0.0.1 ip-transparent
```

Like the other per-neighbor knobs, `ip-transparent` can also be set on a
[neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited by every
member; a statement on the neighbor itself wins.

Semantics worth knowing:

- On the **active connect** path the option is applied only when
  `update-source` is also configured (matching FRR's gate) — without a
  foreign source address there is nothing for it to liberate. A
  `setsockopt` failure (daemon lacking `CAP_NET_ADMIN`) fails the dial
  loudly rather than surfacing as a confusing `EADDRNOTAVAIL` from the
  bind.
- The flag is also folded onto the **BGP listening sockets** while any
  neighbor of that address family has it, so a passively accepted session
  destined to a non-local address (e.g. one steered to the daemon with
  the TPROXY recipe above) can be accepted and answered. The option is
  inert for ordinary inbound sessions. (FRR leaves its listener alone;
  zebra-rs covers the passive scenarios too.)
- **Toggling the flag bounces a live session** (the same teardown
  `clear bgp <peer>` performs): the option must be on the socket before
  `bind()`/`connect()`, so only a reconnect can apply it.
- The connected check still applies: a single-hop eBGP neighbor that is
  not on a connected subnet additionally needs
  [`disable-connected-check`](ch-02-16-bgp-disable-connected-check.md)
  (or `ebgp-multihop` where genuinely multi-hop).

## Verification

`show bgp neighbors <addr>` reports the active policy:

```
  IP transparent enabled (session may use a non-local update-source address)
```

The classic symptom of a **missing** `ip-transparent` is a session with a
non-local `update-source` that never leaves `Active`/`Connect`: every dial
dies on `bind()` with `EADDRNOTAVAIL` before a single SYN is sent. The
classic symptom of missing **return-path delivery** is the opposite —
SYNs leave with the foreign source (visible in `tcpdump`), the peer
answers, and the SYN-ACK is forwarded onward or dropped instead of
reaching the daemon.
