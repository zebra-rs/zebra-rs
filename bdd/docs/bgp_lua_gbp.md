# BGP EVPN Group-Based Policy via Lua scripting

## Overview

DISABLED for now: the embedded Lua scripting engine is off (the `lua`
build feature defaults off and its BGP config schema is commented out),
so this scenario's lua-script / lua-map / adj-rib-out-hook config no
longer applies. The `@disabled` tag makes the harness skip this feature
in every run (full suite and explicit --tags). To re-enable: remove
`@disabled`, rebuild with `--features lua`, and uncomment the
zebra-bgp-lua schema.
As a network operator
I want zebra-rs to carry a Group-Based Policy tag on EVPN Type-2 routes
and enforce it in the dataplane, driven entirely by embedded Lua hooks,
so the FRR-scripting "GBP over EVPN" demo runs end to end without any
blocking I/O on the route path.
Two iBGP (AS 65001) EVPN speakers on a shared transport bridge br0, each
with a local VXLAN (VNI 10) enslaved to a per-node bridge br10:
```
┌───────────────────────────────────────────┐
│                    br0                     │
└───────────┬───────────────────┬───────────┘
```
Flow: z1 learns local MAC aa:bb:cc:dd:ee:01 and originates an EVPN
Type-2 route. z1's egress Lua hook looks the MAC up in the `sgt` map
(-> tag 100) and stamps a Group-Policy-ID extended community. z2's
import Lua hook recovers the tag and runs `nft add element` to put the
MAC in set `tag_100`; the withdraw hook removes it. The scripts are the
shipped /usr/share/zebra-rs/lua/gbp-example.lua.

## Notes

Flow: z1 learns local MAC aa:bb:cc:dd:ee:01 and originates an EVPN
Type-2 route. z1's egress Lua hook looks the MAC up in the `sgt` map
(-> tag 100) and stamps a Group-Policy-ID extended community. z2's
import Lua hook recovers the tag and runs `nft add element` to put the
MAC in set `tag_100`; the withdraw hook removes it. The scripts are the
shipped /usr/share/zebra-rs/lua/gbp-example.lua.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology, EVPN iBGP, GBP scripts, and the enforcement table | |
| A local MAC makes z1 originate a Type-2 route z2 receives | |
| z2's import hook programs the GBP tag set from the GPI community | |
| Withdrawing the MAC tears the GBP set element down | |
| Teardown topology | |
