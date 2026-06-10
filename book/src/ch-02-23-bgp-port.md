# BGP TCP Port (`port`)

A BGP session is a TCP connection to the IANA well-known port **179**.
Two knobs let a session run somewhere else:

- **`router bgp port <0-65535>`** — the port this router's BGP
  **listener** binds, for sessions *other* routers open toward it. The
  special value `0` closes the server socket entirely: the router
  refuses every inbound BGP connection and can only have sessions it
  dials itself.
- **`neighbor X port <1-65535>`** — the destination port this router
  **dials** when it actively opens the session toward neighbor X.

The two are a pair: point `neighbor X port <N>` at a router whose
`router bgp port` is `<N>`. Typical uses are lab setups where several
daemons share one network namespace, environments where 179 is filtered
or reserved, and (`port 0`) route servers or strict dial-out designs
that must never accept a connection.

Deleting either leaf returns to the default 179.

```
delete router bgp port
delete router bgp neighbor 192.168.0.2 port
```

FRR offers the same pair, with one difference: FRR's listen port is the
`-p/--bgp_port` *startup option* of bgpd (0 likewise meaning
do-not-listen) and cannot change at runtime, while in zebra-rs it is
ordinary configuration — a change closes the listeners and reopens them
on the new port on the spot.

## Configuration

The dialing side sets the port on the neighbor:

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 192.168.0.1
    neighbor:
    - remote-address: 192.168.0.2
      remote-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      port: 1790            # dial z2 on TCP 1790 instead of 179
```

The listening side moves its server socket (both the IPv4 and IPv6
listeners) with the instance-level leaf, directly under `router bgp`:

```yaml
router:
  bgp:
    port: 1790              # listen on TCP 1790; 0 = do not listen
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
```

The CLI forms share the same paths:

```
set router bgp neighbor 192.168.0.2 port 1790
set router bgp port 1790
set router bgp port 0
```

The per-neighbor `port` knob (the dial-side destination port) can also be
set on a [neighbor-group](ch-02-26-bgp-neighbor-group.md) and inherited
by every member; a statement on the neighbor itself wins. The instance
listen port (`router bgp port`) is not inheritable — it is an
instance-level setting, not a per-neighbor knob.

## How it is applied

**Neighbor port (dial side).** The configured port is used when the
connect task is spawned, replacing 179 as the TCP destination. Only the
active connection is affected: an inbound connection is matched to its
neighbor by **source address alone, never by port** (same as FRR), so
this leaf does not change what the local listener accepts. Changing or
deleting the value on a session that is already up bounces it — the
same hard teardown `clear bgp <peer>` performs — so the session
re-establishes on the new port immediately (FRR resets the peer on this
flag too). A neighbor still Idle simply picks the port up on its first
connect.

**Listen port (server side).** A change closes the current IPv4 and
IPv6 listeners and binds fresh ones on the new port; with `0` it stops
after the close. Per-peer options that live on the listening socket —
TCP MD5 keys, TCP-AO keys, the listener's TCP MSS clamp — are
re-installed on the new socket automatically.

Two things deliberately survive a listen-port change:

- **Established sessions.** Closing a listening socket does not touch
  connections already accepted from it. Only *future* inbound
  connections are affected; an existing session keeps running on the
  old port until something else resets it. (This also means `port 0`
  does not tear down sessions that are already up — it stops new ones
  from being accepted.)
- **Outgoing connections.** Dials toward neighbors are unaffected: they
  go to each neighbor's default or configured `port`, from an ephemeral
  local source port, whether or not this router listens anywhere.

Scope is the default-VRF instance's listener; per-VRF BGP instances
keep their own default-port listeners.

## Verification

`show ip bgp neighbors` reports the actual TCP endpoints of the live
session, FRR-style. On the router that dialed a custom port, the
**foreign** port is the configured one:

```
> show ip bgp neighbors
BGP neighbor is 192.168.0.2, remote AS 65002, local AS 65001, external link
  Local host: 192.168.0.1, Local port: 38766
  Foreign host: 192.168.0.2, Foreign port: 1790
  BGP state = Established, up for 00:01:12
  ...
```

On the router that accepted it, the **local** port is its listen port
and the foreign port is the peer's ephemeral source port:

```
> show ip bgp neighbors
BGP neighbor is 192.168.0.1, remote AS 65001, local AS 65002, external link
  Local host: 192.168.0.2, Local port: 1790
  Foreign host: 192.168.0.1, Foreign port: 38766
  BGP state = Established, up for 00:01:12
  ...
```

To confirm the listener itself, look at the sockets:

```
# ss -tlnp | grep zebra-rs
LISTEN 0 1024  0.0.0.0:1790  0.0.0.0:*  users:(("zebra-rs",...))
LISTEN 0 1024     [::]:1790     [::]:*  users:(("zebra-rs",...))
```

With `port 0` the two LISTEN rows are gone, and a peer dialing this
router is refused (RST) by the kernel.

## Troubleshooting

- **Session stays in Active/Connect after setting `neighbor X port`.**
  The far end is not listening on that port — check its
  `router bgp port` (and that its listener actually rebound: `ss -tln`).
  Remember both directions dial by default; if the *other* router's
  dial toward your unchanged listener establishes first, the session
  may come up on 179 even though your custom-port dial is broken. Make
  the far end passive (`transport: { passive-mode: true }`) when you
  need to prove the custom-port direction works.
- **Set `port 0` but an old session is still Established.** Expected —
  the change only closes the listener. Reset the session
  (`clear bgp <peer>`) to drop it; with no listener and no active dial
  from this side it will not come back.
- **A peer still connects to 179 after you moved the listener.** It
  cannot — new connections to the old port are refused the moment the
  rebind happens. If you see an Established session "on 179" it
  predates the change (see above).
