# Lua Scripting

Beyond the declarative [policy](ch-05-00-policy.md) engine, zebra-rs can
run **Lua scripts** at well-defined points in the BGP route lifecycle.
A script sees the route's prefix, its full path attributes (including
extended communities), and the peer, and may observe, deny, or rewrite
the route — or trigger a non-blocking side effect such as programming
nftables. This is zebra-rs's analogue of FRR's `route-map match script`,
redesigned around that feature's limitations.

The embedded Lua 5.4 engine is **on by default**. Builds without it
(`cargo build --no-default-features`) compile every hook to a no-op.

## Hook points

A script is bound to a hook on the **Adj-RIB-In → Loc-RIB** boundary
(receive) or the **Adj-RIB-Out** boundary (advertise), per address
family (IPv4-unicast and L2VPN-EVPN today):

| Hook | Fires | Sees | May |
|------|-------|------|-----|
| `import`   | a received route enters the Loc-RIB | prefix, attributes, peer | observe / **deny** / **rewrite** attributes |
| `withdraw` | a route leaves the Loc-RIB | prefix, the **stored** attributes, peer | observe only (tables are **read-only**) |
| `export`   | a route is advertised to a peer | prefix, attributes, peer | observe / **suppress** / **rewrite** attributes |

The `withdraw` hook is the half FRR cannot do: a wire withdrawal carries
only the NLRI, but because zebra-rs is a single process the hook reads
the **stored Loc-RIB attributes of the path being removed** — so a script
can recover, say, a tag and tear down what the `import` hook set up.

## The script contract

A hook is a Lua function named for the hook (`loc_rib_import`,
`loc_rib_withdraw`, or `adj_rib_out`). It receives the route context and
the four result constants, and returns an action:

```lua
function loc_rib_import(prefix, attributes, peer,
                        RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
    -- ... inspect prefix / attributes / peer ...
    return { action = RM_NOMATCH }   -- admit unchanged
    -- or { action = RM_FAILURE }                                  -- deny
    -- or { action = RM_MATCH_AND_CHANGE, attributes = attributes } -- rewrite
end
```

- `prefix` — `prefix.network`, `prefix.afi` (`"ipv4"`/`"evpn"`), and for
  EVPN a structured `prefix.evpn` (`route_type`, `mac`, `vni`, `rd`, …).
- `attributes` — `med`, `local_pref`, `origin`, `as_path`, `next_hop`,
  `community`, and `ext_community` (a list of 8-octet values, so
  `string.unpack(">BBHHH", ec)` works). On `import`/`export`, mutate the
  table and return `RM_MATCH_AND_CHANGE` to have the change land.
- `peer` — `remote_as`, `local_as`, `remote_id`, `local_id`,
  `remote_address`, `is_ibgp`, `state`.

Scripts are **sandboxed**: `os`, `io`, `package`, `require`, `load*`, and
`debug` are absent. Any script error fails safe (logged, treated as
admit-unchanged), so a broken script never blackholes traffic.

### Host helpers

| Helper | Purpose |
|--------|---------|
| `ecom.gpi(tag)` / `ecom.parse_gpi(value)` | build / decode a Group-Policy-ID ext-community (type `0x03`, sub-type `0x17`) |
| `map.get(ns, key)` | non-blocking read of a config-seeded lookup table |
| `zlog.info/warn/error(msg)` | write to the daemon log |
| `sideeffect.nft{ op=, table=, set=, elem= }` | enqueue an `nft add/delete element` onto a background drainer (never blocks the route path) |

## Configuration

Define named scripts (and optional lookup tables), then bind them:

```
router bgp 65000 {
  lua-script GBP { source-path /etc/zebra-rs/lua/gbp-example.lua; }
  lua-map sgt    { source-path /etc/zebra-rs/lua/sgt.json; }      // MAC -> tag JSON

  loc-rib-hook {
    ipv4-unicast { import GBP; withdraw GBP; }
    l2vpn-evpn   { import GBP; withdraw GBP; }
  }
  adj-rib-out-hook {
    ipv4-unicast { export GBP; }
    l2vpn-evpn   { export GBP; }
  }
}
```

`lua-script … source-path` loads the script from a file at config time;
`lua-map … source-path` loads a flat JSON object (`{"aa:bb:..": "100"}`)
into a `map.get` namespace.

> **Egress and update groups.** zebra-rs coalesces identical advertised
> UPDATEs into *update groups* and encodes each once. Because an egress
> script is an arbitrary transform, binding `adj-rib-out-hook … export`
> places each affected peer in its **own** update group, so the script
> runs per-peer with full peer context. Expect reduced advertise
> coalescing for peers with an egress script bound.

## Example: GBP over EVPN

The package ships a complete example at
`/etc/zebra-rs/lua/gbp-example.lua` implementing Group-Based Policy over
EVPN: the `export` hook stamps the EVPN Type-2 (MAC) route with the
endpoint's group tag (looked up MAC → tag via `map.get`) as a GPI
extended community; the `import` hook recovers the tag and programs an
nftables set member; the `withdraw` hook removes it. The receive → enforce
→ teardown loop runs without any blocking I/O on the route path.
