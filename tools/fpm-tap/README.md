# fpm-tap

Record, replay and decode the FPM wire protocol as **SONiC** speaks it.

Groundwork for the zebra-rs SONiC port: before zebra-rs can emit FPM, we
need to know exactly what SONiC's FRR emits. SONiC does not run upstream
FRR's `dplane_fpm_nl` — it ships a fork, `dplane_fpm_sonic`
(`src/sonic-frr/dplane_fpm_sonic/`, ~3.7k lines), which adds private
netlink message types on top of rtnetlink. The only trustworthy
specification for that dialect is the bytes themselves, so this tool
captures them and keeps them byte-for-byte.

## Commands

```
fpm-tap record --out FILE [--listen ADDR] [--forward ADDR] [--once]
fpm-tap replay FILE [--target ADDR] [--realtime|--pace-ms N]
fpm-tap decode FILE [--verbose] [--type NAME|NUM] [--dir to-fpm|to-zebra]
fpm-tap stats  FILE
```

`fpmsyncd` is the **server** side of FPM — it listens on TCP 2620 and
zebra dials out — so `record` only has to occupy that port.

* Without `--forward` the tap terminates the connection: a clean capture
  with nothing else running.
* With `--forward` it proxies to a real `fpmsyncd` and records **both**
  directions. That is the only way to capture the reverse channel, the
  `RTM_F_OFFLOAD` acknowledgements, since those only exist when something
  is really writing APPL_DB and reading APPL_STATE_DB.

## Capture rig

`rig/capture.sh` runs the real `docker-fpm-frr` image with zebra started
on exactly SONiC's supervisord command line, drives routes in through a
scenario script, and copies the capture out.

```shell
docker load < <sonic-buildimage>/target/docker-fpm-frr.gz
cargo build --release -p fpm-tap
cd rig
./capture.sh --scenario scenarios/basic.sh --out ../golden/basic.fpm
./capture.sh --scenario scenarios/basic.sh --out ../golden/basic-nhg.fpm --nhg
./capture.sh --scenario scenarios/vrf.sh   --out ../golden/vrf.fpm
```

The `vrf` scenario deliberately puts the VRF on kernel table 100 while
its device lands on a single-digit ifindex, so the two numbers cannot be
confused — an encoder that sent the table id would still look correct if
they happened to match.

`rig/capture-offload.sh` additionally captures the **acknowledgement**
direction. It needs `docker-database:latest` too, and stands up redis, a
real `fpmsyncd`, and `fake-orchagent.py` in place of orchagent:

```shell
docker load < <sonic-buildimage>/target/docker-database.gz
./capture-offload.sh --out ../golden/offload.fpm
```

```text
zebra --(2621)--> fpm-tap --(2620)--> fpmsyncd --> APPL_DB
      <----------         <----------          <-- offload ack
                                                   ^
                                fake-orchagent.py -+
```

`fpmsyncd`'s listen port is hardcoded, so the tap takes 2621 and zebra is
pointed at it with `fpm address 127.0.0.1 port 2621`. Everything shares
one network namespace so ifindexes agree between zebra and fpmsyncd.

Two rig details that cost time to rediscover:

* **`/etc/frr/frr.conf` must be removed.** If it exists, FRR loads that
  integrated config and silently ignores `zebra.conf` — so the `fpm
  address` line never takes effect and FPM stays disabled. SONiC's
  `docker_init.sh` removes it in `separated` mode for the same reason.
* **`mgmtd` is required.** Since FRR 9 it owns staticd's YANG config, so
  `ip route ...` from vtysh goes to mgmtd; `staticd` has no `-f` flag at
  all any more.

## Verifying the zebra-rs encoder

`rig/ab-diff.sh` answers the question byte-comparison cannot: does
`fpmsyncd` derive the *same APPL_DB rows* from zebra-rs's messages as
from FRR's? It replays both into the same real `fpmsyncd` — FRR's own
recording, then a capture encoded by `zebra-rs/src/fib/fpm` — and diffs
the resulting rows.

```shell
./ab-diff.sh
```

Neither routing daemon runs, so it takes seconds. The comparison is
restricted to the scenario's static prefixes: FRR's capture also contains
connected routes and the container's default route, but those come from
zebra's kernel dump rather than from anything an encoder produces.

Interface indexes are load-bearing — `fpmsyncd` resolves a nexthop
ifindex to APPL_DB's `ifname` in its own netns, so the replay side
creates the same dummy links in the same order as the capture side.

`rig/live-tee.sh` goes one step further and takes FRR out of the picture
entirely: it runs **zebra-rs itself** with the FPM tee enabled against a
real `fpmsyncd`, and checks the routes it computes land in APPL_DB.

```shell
cargo build -p zebra-rs -p vtyctl
./live-tee.sh
```

Two things that cost time to work out, both worth knowing before writing
any rig of your own:

* Configuration goes in as a **startup config file** (`zebra-rs -c`), not
  through `vtyctl`. zebra-rs ties a VTY session to the caller's parent
  shell and rejects any client whose ppid is `<= 1`
  (`SessionError::OrphanClient`) — which is every `docker exec`, and
  `bash -c "vtyctl ..."` does not help because bash execs a lone command
  and inherits the same orphaned parent. Using a config file is also
  closer to the real deployment, where a container renders its config and
  starts the daemon on it.
* The tee is enabled with `set system fpm enabled true` in that config.
  Address and port default to `127.0.0.1:2620`, where fpmsyncd listens in
  SONiC's bgp container; `system fpm address` / `system fpm port` override
  them. (`SONIC_FPM=host:port` still works as a startup env fallback,
  mirroring `CRADLE_GRPC`.)

The rig also restarts `fpmsyncd` mid-run and checks the routes come back
into a wiped APPL_DB. That exercises FPM's reconnect contract — *"send
the FPM a complete copy of the forwarding table(s) when it
reconnects"* — which is the difference between a `fpmsyncd` restart being
a blip and it silently freezing the ASIC's view of the routing table
until something unrelated churns.

## What the golden traces show

Captured from FRR 10.5.4-sonic-0 with `dplane_fpm_sonic`. These are the
rules the zebra-rs encoder has to reproduce — several are traps where the
obvious choice is the wrong one.

| Observation | Consequence for the encoder |
|---|---|
| Default VRF routes carry `rtm_table = 0` and **no `RTA_TABLE`** | Do **not** send `RT_TABLE_MAIN` (254). `fpmsyncd` treats any non-zero table as a **VRF ifindex** and looks up an interface name that must start with `Vrf` (`routesync.cpp:920-942`); 254 would fail that lookup. |
| Static routes use protocol **196** (`RTPROT_ZSTATIC`), not 4 | FRR has its own protocol numbering in `zebra/rt_netlink.h` (186-198). `zebra2proto()` maps `ZEBRA_ROUTE_STATIC` → 196. |
| Connected/local/kernel routes all use protocol **2** (`RTPROT_KERNEL`), not 11 | Same mapping. `protocol` reaches APPL_DB verbatim, so a "semantically equivalent" value is still a diff. |
| One nexthop → flat `RTA_GATEWAY` + `RTA_OIF`; two or more → `RTA_MULTIPATH` | The encoding switches on nexthop count, not on whether the route is ECMP-capable. |
| `RTA_MULTIPATH` is sent with the `NLA_F_NESTED` bit (0x8000) set | This is why `fpmsyncd` masks that bit off in `netlink_parse_rtattr` (`fpmlink.cpp:24-31`). |
| Inside `RTA_MULTIPATH`, the ifindex lives in the `rtnexthop` struct — there is no nested `RTA_OIF` | |
| `RTA_PRIORITY` is always present, even when 0 | Omitting it when zero is a byte-level diff. |
| Adds: `REQUEST\|REPLACE\|CREATE`. Deletes: `REQUEST\|CREATE`, `rtm_type` 0 (`unspec`), no nexthop attributes | |
| `nlmsg_seq` is 0; `nlmsg_pid` is a per-session random nonce | Neither is a sequence to be tracked. |
| Blackhole/reject are `rtm_type` 6/7 with no nexthops | Note `fpmsyncd` logs an error and **drops** these (`routesync.cpp` `RTN_BLACKHOLE` case) — they never reach APPL_DB. |
| Administrative distance never reaches the wire | It is a RIB-selection input only. |
| A VRF route's table field is the VRF **device ifindex**, not the kernel table id | `golden/vrf.fpm` puts Vrf1 on table 100 with ifindex 6, and the wire says `table=6`. The plugin substitutes one for the other explicitly (`dplane_fpm_sonic.c:1232`, "Put vrf if_index instead of table id") and `fpmsyncd` resolves it with `getIfName()`, rejecting any name that does not start with `Vrf`. An ifindex of 256+ moves to `RTA_TABLE`. |
| With `fpm use-next-hop-groups`: `RTM_NEWNEXTHOP` (`NHA_ID`/`NHA_GATEWAY`/`NHA_OIF`) precedes the route, which then carries only `RTA_NH_ID` | SONiC's `docker_init.sh` writes `no fpm use-next-hop-groups` by default, so the inline form is primary — but both must work, and both are captured. |

Note the last row is independent of how zebra-rs programs the *kernel*.
zebra-rs installs kernel routes with nexthop IDs unless `--no-nhid`; the
FPM encoding is a separate choice and must not be tied to it.

## The acknowledgement direction

What `bgp suppress-fib-pending` waits on. **Every `RTM_NEWROUTE` is
acknowledged** — but there are two different acknowledgements, and which
one you get is decided by a single CONFIG_DB flag,
`DEVICE_METADATA|localhost` `suppress-fib-pending`:

| `suppress-fib-pending` | Acknowledgement | Meaning |
|---|---|---|
| **disabled** (default) | **Optimistic.** fpmsyncd replies the instant it parses the route, before APPL_DB is even written (`routesync.cpp:2631` — note the check is `if (!isSuppressionEnabled())`) | "Nothing else will ever tell you, so assume it worked." |
| **enabled** | **Real.** The immediate reply is skipped; the acknowledgement comes later from `onRouteResponse` when orchagent publishes to the APPL_STATE_DB channel `APPL_DB_ROUTE_TABLE_RESPONSE_CHANNEL` | "SAI programmed it." |

The two are not the same message. The optimistic one is the parsed route
rebuilt in full (`rtnl_route_build_add_request`), so it carries
`RTA_GATEWAY`/`RTA_OIF`/`RTA_MULTIPATH`; the real one is synthesized from
scratch and carries no nexthop at all. A client must accept both and
depend on neither:

| Observation | Consequence for the client |
|---|---|
| The orchagent-driven ack is **not an echo** — fpmsyncd builds a fresh route from the response (`routesync.cpp:3700-3730`) carrying only `RTA_DST` + `RTA_TABLE` | The **only** key that works in both modes is `(family, prefix, table, protocol)`. Matching on a nexthop fails the moment suppression is on. |
| The optimistic ack echoes the full route, including nexthops | Do not treat the presence of nexthop attributes as meaningful. |
| `nlmsg_pid` and `nlmsg_seq` are both 0 in either mode | Not a correlation id. There is no sequence to track. |
| `RTA_TABLE` **is** present and explicitly 0, unlike the outbound direction which omits it | Parse both forms. |
| Flags are `REQUEST\|CREATE`. `rtm_scope` is `link` on the synthesized ack and `universe` on the optimistic one — an artifact of libnl defaults | Do not read meaning into scope. |
| **Deletes are never acknowledged**, in either mode. With suppression on, fpmsyncd identifies a DEL response by the *absence* of a `protocol` field and returns early (`routesync.cpp:3678`); with it off, the immediate reply is only sent on the `RTM_NEWROUTE` path | A client that waits for a delete ack waits forever. |
| A response whose `protocol` is empty is dropped as "programmed without FRR knowledge" | |
| APPL_DB's `protocol` value for FRR static routes is the string **`0xc4`** (196 in hex), because libnl's `rt_protos` table has no name for it; connected routes come out as `kernel` | It round-trips: fpmsyncd parses it back with `rtnl_route_str2proto()`, falling back to a numeric parse. |

`golden/offload.fpm` is the suppression-enabled trace,
`golden/offload-optimistic.fpm` the default one; `capture-offload.sh
--no-suppression` records the latter.

Route writes reach APPL_DB through a **ProducerStateTable**, so they are
staged as `_ROUTE_TABLE:<key>` plus a `ROUTE_TABLE_KEY_SET` until a
ConsumerStateTable drains them. With no orchagent, reading
`ROUTE_TABLE` directly finds nothing — the routes are there, just still
staged. `fake-orchagent.py` consumes them the same way orchagent does.

## Not yet captured

* **BGP** routes — needs a peer; a two-container topology.
* **VRF** routes — the non-zero `RTA_TABLE` path.
* **SONiC private types** — SRv6 local SID (1000/1001), PIC context
  (2000/2001), SRv6 VPN route (3000/3001), and the EVPN multihoming
  block (140-148). The decoder already names them; nothing has produced
  them yet.

## Why keep the captures

They are the regression oracle for the encoder, and they stay useful
afterwards: `dplane_fpm_sonic` is a SONiC fork that moves when SONiC
bumps FRR. Re-record after a bump and diff to see exactly what changed in
the dialect.
