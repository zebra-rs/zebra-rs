# zebra-rs on SONiC — Current Architecture

What is built and running today, module by module: what was changed, what was
added, and what was deliberately left alone. The plan of record, with phases
and open work, is [`sonic-zebra-rs-plan.md`](sonic-zebra-rs-plan.md); this
document describes the state that plan has reached.

State described: zebra-rs `main` at `5b003a5c`, sonic-buildimage
`zebra-rs/sonic-buildimage` branch `zebra-rs-container` at `c01c37c8e`,
sonic-utilities `zebra-rs/sonic-utilities` branch `zebra-rs-routing-stack` at
`a6e35897`. A `sonic-vs` image built from those three boots from a stock
`config_db.json`, peers with an FRR SONiC over eBGP, and programs the ASIC.

## 1. The idea in one paragraph

SONiC does not let a routing daemon touch the ASIC. The daemon hands routes to
`fpmsyncd` over the FPM protocol, `fpmsyncd` writes them to APPL_DB, and
everything below that — `orchagent`, ASIC_DB, `syncd`, SAI — is common to every
routing stack. So replacing FRR does not need a new dataplane path. It needs
three seams to be filled, and nothing below them changes:

| Seam | FRR | zebra-rs |
|---|---|---|
| Southbound: routes to the ASIC | zebra's `dplane_fpm_sonic` plugin | `fib/fpm/` tee in the daemon |
| Northbound: CONFIG_DB to daemon config | `bgpcfgd` → `vtysh -f` | `bgpcfgd` → `vtyctl apply -f`, new backend and templates |
| Operational: `show`, monitoring | `vtysh -c '…'` | `vtyctl` run as `vtysh`, FRR-schema JSON |

## 2. The running system

```text
                      host (SONiC)                         bgp container (docker-fpm-zebra-rs)
 ┌──────────────────────────────────────┐   ┌──────────────────────────────────────────────────────┐
 │ CONFIG_DB ───────────────────────────┼───┼─▶ bgpcfgd ──render templates──▶ vtyctl apply -f ──┐    │
 │   BGP_NEIGHBOR, BGP_PEER_RANGE,      │   │   (zebra-rs backend)                              │    │
 │   BGP_SENTINELS, DEVICE_METADATA     │   │                                             gRPC  ▼    │
 │                                      │   │ docker_init.sh ──▶ zebra-rs.conf ──▶ ┌──────────────┐  │
 │ show / sonic-clear / route_check     │   │                                      │   zebra-rs   │  │
 │   └▶ /usr/bin/vtysh, rvtysh ─────────┼───┼─▶ /usr/bin/vtysh ──gRPC──────────────▶│ BGP + RIB +  │  │
 │       (docker exec bgp vtysh)        │   │   (= vtyctl, FRR mode)               │ FIB, 1 proc  │  │
 │                                      │   │ bgpmon ──▶ vtysh -c 'show bgp        └──┬────────┬──┘  │
 │ STATE_DB ◀───────────────────────────┼───┼── summary json'                 netlink  │        │ FPM │
 │   NEIGH_STATE_TABLE                  │   │                                         │        │ TCP │
 │                                      │   │                                         ▼        ▼ 2620│
 │ kernel routing table ◀───────────────┼───┼──────────────── (host netns) ───────────┘   fpmsyncd    │
 │                                      │   │                                    offload acks ▲  │   │
 │ APPL_DB ROUTE_TABLE ◀────────────────┼───┼────────────────────────────────────────────────┼──┘   │
 │   │            APPL_STATE_DB ────────┼───┼────────────────────────────────────────────────┘      │
 │   ▼                ▲                 │   └──────────────────────────────────────────────────────┘
 │ orchagent ─────────┘                 │
 │   ▼                                  │      unchanged: fpmsyncd, APPL_DB, orchagent, ASIC_DB,
 │ ASIC_DB ─▶ syncd ─▶ SAI ─▶ ASIC      │                 syncd, SAI, the bgp.service unit
 └──────────────────────────────────────┘
```

The container takes the same slot as `docker-fpm-frr`: same container name
(`bgp`), same `bgp.service`, same host network namespace. One daemon replaces
FRR's `mgmtd`/`zebra`/`staticd`/`bgpd`/`bfdd` set, so there are no inter-daemon
sockets and no `zsocket.sh` equivalent.

Processes under supervisord, in start order: `rsyslogd`, `zebra-rs`,
`fpmsyncd`, `bgpcfgd`, `bgpmon`. `zebra-rs`, `fpmsyncd` and `bgpcfgd` are
critical processes; `bgpmon` is restarted if it exits, as in the FRR container.

## 3. Southbound — routes to the ASIC

### 3.1 New module: `zebra-rs/src/fib/fpm/`

Everything that speaks FPM. It is a *tee*: the kernel install is unchanged and
stays primary, because SONiC wants both a kernel route and an ASIC route for
every prefix.

| File | Role |
|---|---|
| `frame.rs` | The 4-byte FPM header (version 1, type netlink, big-endian length), max message 16384, default port 2620. |
| `encode.rs` | `encode_route()`: a `RibEntry` to the netlink `RTM_NEWROUTE`/`RTM_DELROUTE` bytes SONiC's FRR sends. `RTA_MULTIPATH` for ECMP, `RTA_VIA` where the gateway's family differs from the prefix's. `set_msg_to_del()` turns a stored add into its delete. |
| `decode.rs` | `parse_ack()`: the offload acknowledgement `fpmsyncd` sends back — the same route message with `RTM_F_OFFLOAD` or `RTM_F_OFFLOAD_FAILED` set. |
| `mirror.rs` | `Mirror`: the encoded message last sent for each `(prefix, VRF ifindex)`. |
| `client.rs` | `FpmFib`: the handle the FIB calls, and the background task that owns the TCP connection. |
| `mod.rs` | `is_fpm_prefix()`: which prefixes are teed at all. |

**The dialect is SONiC's, not upstream FRR's.** The rules were read off
captures of a real SONiC FRR (`tools/fpm-tap/golden/`), and the encoder's tests
require byte equality with them, because `fpmsyncd` copies several fields
straight into APPL_DB — an encoding that is merely valid is a behaviour change.
The rules that differ from what one would guess:

- The netlink *table* field carries the VRF **device ifindex**, not a kernel
  table id; 0 is the default VRF. `fpmsyncd` resolves it to a name and rejects
  anything not starting with `Vrf`.
- Protocol bytes: BGP 186, IS-IS 187, OSPF 188, static 196, connected and
  kernel 2. `fpmsyncd` writes the protocol into the APPL_DB row.
- Deletes are never acknowledged; adds are, keyed by `(family, prefix, table,
  protocol)` with no nexthop and no correlation id.

**Direction and reconnects.** `fpmsyncd` is the server; zebra-rs dials
`127.0.0.1:2620`. The client never blocks a caller: `route_add`/`route_del`
update the `Mirror` first and then offer the message to the connection task
through a channel. A message offered while disconnected is dropped, which costs
nothing — on reconnect the task replays the whole mirror, which is what the FPM
contract requires and what keeps APPL_DB correct across a `fpmsyncd` restart.
Deleted routes leave a tombstone so the replay also carries the deletes that
were missed. Backoff is 200 ms rising to 5 s.

**What is teed** (`FibHandle::fpm_prepare` in `fib/netlink/handle.rs`):
protocol routes and connected routes, minus `127.0.0.0/8`, `::1/128` and
`fe80::/10`. That last gate (`is_fpm_prefix`) was added after the first run on a
SONiC VS: zebra-rs carries the loopback net and link-locals as ordinary
connected routes, and without the gate they reached APPL_DB as rows SONiC's FRR
never produces.

### 3.2 Changed: `fib/netlink/handle.rs`

`FibHandle` is the kernel FIB writer. It gained the tee calls and nothing about
its kernel behaviour changed.

- `fpm_prepare()` decides whether a route is teed and encodes it, translating
  the kernel table id to the VRF device ifindex.
- `fpm_tee()` / `fpm_tee_add()` are called beside each kernel route add,
  replace and delete in this file, and from `rib/route.rs` for the two
  selection paths that do not go through them.
- `fpm_flush_vrf()` drains a VRF's routes from the mirror when the VRF goes
  away.
- **Restart leftovers.** `leftover_rtype()` decides which kernel routes found
  at startup are an earlier run's: they enter the RIB stale under their owner's
  type, the owner's fresh route replaces them, the rest are swept after
  `--leftover-sweep-time`. Main-table `proto bgp` was excluded, since another
  daemon may own it. A new flag, `--claim-main-bgp` (`set_claim_main_bgp()`),
  includes it. SONiC's container passes the flag: it shares the host's network
  namespace, so a container restart leaves the previous instance's BGP routes in
  the kernel, and unclaimed they came back as distance-0 kernel routes that
  outranked the BGP routes learned again.

### 3.3 Changed: the RIB (`rib/`)

- `rib/inst.rs`: the configuration `system fpm enabled|address|port`
  (`fpm_enabled_config_exec` and friends). `fpm_apply()` creates or tears down
  the `FpmFib`; `fpm_rib_walk()` sends every already-installed route when FPM is
  enabled after routes exist, so nothing depends on configuration order.
- `rib/inst.rs` `route_offload()`: handles `FibMessage::RouteOffload` from the
  FPM client, sets `RibEntry.offloaded` on the matching entry, and forwards the
  event to subscribed protocols as `RibRx::RouteOffload`.
- `rib/entry.rs`: the `offloaded` flag on a RIB entry.
- `fib/message.rs`: `RouteOffload { prefix, vrf_ifindex, protocol, success }`,
  named for the concept rather than for FPM.
- `rib/show.rs`: `show ip route` prints `offloaded` on an acknowledged route,
  and the JSON carries `offloaded` and `uptime` (added for §5).

### 3.4 Changed: BGP — `suppress-fib-pending`

`router bgp global suppress-fib-pending` (`yang/zebra-bgp-suppress-fib-pending.yang`,
[`bgp-suppress-fib-pending.md`](bgp-suppress-fib-pending.md)). With it on, BGP
holds a best path back from advertisement until the RIB reports the prefix
offloaded (`RibRx::RouteOffload` in `bgp/inst.rs`), with a timeout so a lagging
ASIC cannot hold routes forever. `show bgp summary` shows how many prefixes are
held and how many were released by the timeout. This is the SONiC behaviour
that keeps a router from attracting traffic for a route its ASIC cannot yet
forward.

### 3.5 The route's whole path

1. BGP selects a best path and hands it to the RIB.
2. The RIB selects it and calls the FIB: netlink install to the kernel, and
   `fpm_tee` beside it.
3. `fpm_prepare` encodes; `FpmFib::route_add` records it in the mirror and
   offers it to the connection.
4. `fpmsyncd` writes `ROUTE_TABLE:<prefix>` to APPL_DB.
5. `orchagent` programs ASIC_DB; `syncd` programs the ASIC through SAI.
6. `orchagent` reports the result in APPL_STATE_DB; `fpmsyncd` sends the route
   back over FPM with `RTM_F_OFFLOAD`.
7. The client parses the acknowledgement and raises `FibMessage::RouteOffload`;
   the RIB marks the entry `offloaded` and tells BGP, which releases the prefix
   if it was holding it.

## 4. Northbound — CONFIG_DB to daemon configuration

### 4.1 Two stages

**At container start**, `docker_init.sh` runs `sonic-cfggen` over
`zebra-rs.conf.j2` and the daemon reads the result with `--config-file`. It
carries what is not per-neighbor: `system fpm enabled true`, router id and
hostname, the BGP instance (AS, router id, multipath, graceful restart,
`suppress-fib-pending` when DEVICE_METADATA asks for it), the loopback and VLAN
prefix-sets, and the common policies. It is a port of FRR's
`bgpd.main.conf.j2`.

**At runtime**, `bgpcfgd` — the same daemon the FRR container runs — watches
CONFIG_DB and pushes per-neighbor configuration as rows appear, change and
disappear.

### 4.2 The dialect difference

zebra-rs configuration is `set`/`delete` lines applied as **one atomic
commit**: one line the daemon does not accept discards the whole push. FRR
applies line by line and keeps what parsed. Two consequences shape everything
below: templates must be exactly right, not approximately, and the backend must
detect a rejected commit rather than assume success.

### 4.3 Changed: `src/sonic-bgpcfgd` (sonic-buildimage)

| File | Change |
|---|---|
| `bgpcfgd/dialect.py` (new) | `routing_stack()` / `is_zebra_rs()`, read from the `SONIC_ROUTING_STACK` environment variable that the container's supervisord sets. Unset, bgpcfgd behaves exactly as before. |
| `bgpcfgd/zebra_rs.py` (new) | `ZebraRs`, the counterpart of `frr.py`'s `FRR` class, with the same interface. `write()` runs `vtyctl apply -f` and looks for `error reply:` in the output, because `vtyctl apply` exits 0 on a rejected commit. `get_config()` reads `show running-config formal`. `reconcile()` filters a batch against the running config before it is pushed: it removes `set` lines already present, because `set` on a leaf-list appends and would duplicate members on every re-push, and `delete` lines whose path is not configured, because zebra-rs rejects those and one rejected line discards the whole commit. |
| `bgpcfgd/main.py` | `do_work()` dispatches on `is_zebra_rs()`. `do_work_zebra_rs()` builds the `ZebraRs` backend and starts only the managers whose templates are ported: the metadata and interface managers, and `BGPPeerMgrBase` for `BGP_NEIGHBOR` (`general`), `BGP_PEER_RANGE` (`dynamic`) and `BGP_SENTINELS` (`sentinels`), and `DeviceGlobalCfgMgr` for `BGP_DEVICE_GLOBAL`. The tables it ignores are named in a startup warning. |
| `bgpcfgd/managers_bgp.py` | zebra-rs branches where FRR syntax was built in code rather than in a template: peer-group text is pushed as plain lines instead of being wrapped in vtysh context; delete is `delete router bgp neighbor X` or `… neighbor-group X` for the listen-range families; admin shutdown is `neighbor X enabled false`; known peers are read from the formal running config; a neighbor in a non-default VRF is refused. A peer configured while the device is isolated gets the TSA entries in the same commit. |
| `bgpcfgd/managers_device_global.py` | Runs under zebra-rs for TSA: on a change of `tsa_enabled` it finds the outbound policies in the formal running config (`policy out` of a neighbor or a neighbor-group) and renders the isolate or unisolate template for each. W-ECMP and IDF isolation are refused with a log message. |
| `tests/test_zebra_rs.py`, `tests/test_zebra_rs_tsa.py` | Tests for the backend and for TSA. |
| `tests/conftest.py` (new) | Clears `SONIC_ROUTING_STACK` for every test. The build exports a variable of that name, so in a zebra-rs build the FRR tests would otherwise run against the zebra-rs backend. |

**Left out under zebra-rs**, and therefore not functional on a zebra-rs image:
W-ECMP and IDF isolation (the other two functions of the device-global
manager), the allow-list manager, BFD, static-route, SRv6, route-map,
prefix-list, and the monitor, internal and VoQ-chassis peer families.

### 4.4 New: templates, `dockers/docker-fpm-zebra-rs/zebra-rs/`

Ports of the FRR templates of the same names, in the `set` dialect.

- `zebra-rs.conf.j2` — the startup configuration of §4.1. Its header records
  the FRR-to-zebra-rs mapping for each construct, and the constructs that have
  no zebra-rs equivalent.
- `bgpd/templates/general/` — `instance`, `peer-group`, `policies` for
  `BGP_NEIGHBOR`.
- `bgpd/templates/dynamic/` — the same plus `update` and `delete` for
  `BGP_PEER_RANGE` (listen ranges on a neighbor-group).
- `bgpd/templates/sentinels/` — for `BGP_SENTINELS`.
- `bgpd/tsa/` — isolate and unisolate. Isolating adds three entries to an
  outbound policy of external peers: 20 permits the loopbacks and tags them
  with the traffic-shift community, 30 does the same for routes carrying the
  internal tag, 40 denies the rest. An internal policy gets one entry adding
  `no-export`. Unisolating deletes them.
- `common/functions.conf.j2` — shared macros.

Differences in meaning the templates have to absorb, each found by running:

- An FRR peer-group is a zebra-rs **neighbor-group**, a separate list from
  neighbors. Deleting a dynamic peer therefore deletes the group.
- A zebra-rs community-set matches **any** member; FRR's community-list in
  these templates requires **all**. The sentinels policy expresses the AND as a
  `call` chain.
- `ge` and `le` on a prefix-set entry are separate leaves, so separate lines.

`validate-templates.sh` renders every ported template from bgpcfgd's own test
fixtures and applies each to a live daemon; all 32 are accepted.

### 4.5 Changed in zebra-rs for this seam

- `bgp/config.rs` `config_peer_enabled`, `bgp/peer.rs` `PeerConfig.shutdown`:
  `neighbor X enabled false` is an administrative shutdown. The YANG leaf
  existed with no handler, so SONiC's `config bgp shutdown neighbor` was
  accepted and did nothing. It now stops the session, refuses both dial and
  accept (`is_dialable()`), and shows as `Idle (Admin)`.
- `maximum-prefix` per neighbor and address family, which the general
  templates need.

## 5. Operational — `show`, `clear`, monitoring

### 5.1 New module: `vtyctl/src/frr/`

SONiC's tooling runs `vtysh -c '<FRR command>'` and reads the output: text for
operators, FRR's JSON for programs. The module makes `vtyctl` answer that
command line.

| File | Role |
|---|---|
| `mod.rs` | `is_vtysh_name()`: the binary behaves as vtysh when started under that name; `vtyctl vtysh …` is the same thing explicitly. `parse_args()` takes FRR's options — `-c` repeated, and `-H`, `-n`, `-d` accepted and ignored, as is the tty tag SONiC's host wrapper passes. `run()` executes each command and returns FRR-style status. |
| `command.rs` | `translate()`: an FRR command line to an `Action`. Pure, no I/O. |
| `json.rs` | `summary()`, `routes()`, `bgp_header()`: zebra-rs JSON re-shaped into FRR's schema. |

`Action` is one of: `SummaryJson`, `RouteJson`, `BgpHeaderJson` (re-shaped),
`Show` (zebra-rs text, command respelled where the two differ), `Clear`, or
`Unsupported`.

**The rule that defines the module:** a `json` command it does not know is
refused — `% Unknown command`, non-zero exit — never passed through. zebra-rs's
own JSON has a different schema, and an FRR-schema consumer would read it as
"no peers" or "no routes" without an error.

What is mapped:

| FRR command | Answered from | Consumer |
|---|---|---|
| `show [ip] bgp [vrf default\|all] [ipv4\|ipv6] summary json` | `show bgp summary` JSON | bgpmon, `show ip bgp summary` |
| `show ip\|ipv6 route [PROTOCOL\|ADDR\|PREFIX] json` | `show ip route` JSON | `show ip route`, `route_check.py`, `fast-reboot-filter-routes.py` |
| `show ip bgp json` | summary JSON, header only | `show ipv6 bgp summary` with no neighbors |
| `show … neighbors [X] [advertised-routes\|received-routes]` | `show bgp neighbor …` text | `show ip bgp neighbors` |
| `show ip bgp`, `show bgp ipv6`, `show running-config`, other text | same or respelled | operators |
| `clear [ip\|ipv6] bgp <*\|ADDR> [soft] [in\|out]` | `clear bgp <family> <all\|ADDR> …` | `sonic-clear ip bgp` |

Fields FRR fills from state zebra-rs does not keep — table versions, queue
depths, memory figures — are emitted as zero so a consumer that indexes them
does not raise. `show ip bgp json` has no `routes` key: there is no BGP-table
JSON to fill it from, and an empty one would be a false answer.

Refused today: neighbor, peer-group and BFD JSON; any non-default VRF;
`clear bgp peer-group`; `-f`; configuration commands; completion and help.

### 5.2 Changed: `vtyctl/src/{main,show,clear}.rs`

- `main.rs`: the `argv[0]` check and the `vtysh` subcommand.
- `show.rs`: `fetch()` returns a show command's whole output or a typed
  `FetchError` (`Connect`, `Rejected`, `Failed`), where `show()` prints as it
  goes and exits the process on failure.
- `clear.rs`: `run()`, the same for clear, which also reports a command the
  daemon does not have.

### 5.3 Changed in the daemon for this seam

Additive JSON fields only; no existing field changed meaning.

- `rib/show.rs`: `offloaded` and `uptime` on a route.
- `bgp/show.rs`: on a summary peer, `session_state` (the existing `state`
  follows the text column and becomes the received-prefix count once
  Established, so it cannot be read as a state), `established_msec`,
  `local_as`, `description`, `hostname`; per family, `rib_entries`.

### 5.4 Changed outside zebra-rs

- **The `.deb`** links `/usr/bin/vtysh` to `vtyctl` in the container.
- **Host wrappers** `vtysh` and `rvtysh` (`base_image_files/`), the same two
  scripts `docker-fpm-frr` installs: they `docker exec bgp vtysh`.
- **`vty`**, zebra-rs's interactive shell (completion, `?` help, configure
  mode), is in the `.deb`, and a host wrapper of the same name opens it in the
  container. `CLI_PAGER=cat vty` turns the pager off. Configuration committed
  there bypasses CONFIG_DB and is lost when the container restarts.
- **`TSA`, `TSB`, `TSC`** on the host are `docker-fpm-frr`'s own scripts,
  referenced from there: they only write and read CONFIG_DB. The container has
  its own `TSC`, which reads the formal running config and checks entries 20,
  30 and 40 of the outbound policies of external peers.
- **bgpmon** runs in the container and fills STATE_DB `NEIGH_STATE_TABLE`.
- **sonic-utilities** (fork, one commit): it names the routing stack from the
  bgp container's image name — `docker-fpm-zebra-rs` reads as `zebra` — and
  only registered `show ip bgp` and `clear ip bgp` for `frr` and `quagga`.
  `show/main.py` and `clear/main.py` now register the FRR flavour for `zebra`
  too.

## 6. Build and packaging (sonic-buildimage)

| File | What it does |
|---|---|
| `rules/config` | `SONIC_ROUTING_STACK` accepts `zebra-rs`. It has to be set in `rules/config.user`; the make command line does not reach the build slave. |
| `rules/docker-fpm.mk` | Installs exactly one of `docker-fpm-frr` and `docker-fpm-zebra-rs`. |
| `rules/zebra-rs.mk` | The `.deb` target, version, and `ZEBRA_RS_RUST_VERSION`. |
| `rules/docker-fpm-zebra-rs.mk` | The container: depends on the zebra-rs `.deb` and swss, installs the bgpcfgd wheel, container name `bgp`, host wrappers and the traffic-shift commands. |
| `sonic-slave-trixie/Dockerfile.j2` | A **second** pinned Rust toolchain (1.97.0) and `cargo-auditable` 0.7.7 under `/usr/.cargo-zebra-rs`. The slave's default Rust (1.86) cannot build zebra-rs and its `cargo-auditable` 0.6.4 panics on edition-2024 crates; raising the default would change what every other Rust package is built with. |
| `src/sonic-zebra-rs/Makefile` | Builds `zebra-rs`, `vtyctl`, `vtyhelper` with that toolchain and `vty` (a patched GNU bash 5.3, whose tarball is fetched and checked against a pinned SHA-256), and assembles the `.deb` by hand with `dpkg-deb`: binaries, the YANG schemas the daemon loads at runtime, the `vtysh` link. |
| `src/sonic-zebra-rs/Cargo.lock` | zebra-rs does not commit a lock file, so the submodule SHA alone does not pin dependencies. This one does, with `--locked`. |
| `src/sonic-zebra-rs/zebra-rs` | Submodule, pinned to zebra-rs `main`. |
| `dockers/docker-fpm-zebra-rs/` | `Dockerfile.j2`, `docker_init.sh`, `supervisord.conf.j2`, `critical_processes.j2`, `TSC`, the templates of §4.4, the validators. |

`docker_init.sh` renders supervisord's configuration, the critical-process list
and `zebra-rs.conf` with `sonic-cfggen`, then starts supervisord. The daemon is
started as `zebra-rs --claim-main-bgp --config-file /etc/zebra-rs/zebra-rs.conf`.

## 7. What was deliberately not changed

- `fpmsyncd`, APPL_DB's schema, `orchagent`, `syncd`, SAI. The FPM tee exists so
  that none of them has to know which daemon is above them.
- zebra-rs does not write APPL_DB directly.
- The kernel install path. The tee is beside it, not in place of it.
- `bgpcfgd`'s FRR path. Every zebra-rs branch is behind `is_zebra_rs()`.
- The `bgp` container name and `bgp.service`, so everything that addresses the
  routing container by name keeps working.
- `docker-fpm-frr`. FRR remains the default routing stack and both images build.

## 8. Where things are

| Concern | Repository | Path |
|---|---|---|
| FPM encode, decode, client, mirror | zebra-rs | `zebra-rs/src/fib/fpm/` |
| Tee call sites, leftovers, `--claim-main-bgp` | zebra-rs | `zebra-rs/src/fib/netlink/handle.rs` |
| FPM configuration, offload handling | zebra-rs | `zebra-rs/src/rib/inst.rs` |
| `suppress-fib-pending` | zebra-rs | `zebra-rs/src/bgp/`, `yang/zebra-bgp-suppress-fib-pending.yang` |
| Admin shutdown | zebra-rs | `zebra-rs/src/bgp/config.rs`, `peer.rs` |
| FRR vtysh compatibility | zebra-rs | `vtyctl/src/frr/` |
| FPM capture tool, golden captures, rigs | zebra-rs | `tools/fpm-tap/` |
| bgpcfgd backend | sonic-buildimage | `src/sonic-bgpcfgd/bgpcfgd/{dialect,zebra_rs,main,managers_bgp,managers_device_global}.py` |
| Container, templates | sonic-buildimage | `dockers/docker-fpm-zebra-rs/` |
| Package and build rules | sonic-buildimage | `rules/zebra-rs.mk`, `rules/docker-fpm-zebra-rs.mk`, `src/sonic-zebra-rs/` |
| BGP CLI registration | sonic-utilities (fork) | `show/main.py`, `clear/main.py` |

## 9. Limits of the current state

Verified on a `sonic-vs` under KVM against an FRR `sonic-vs`: first boot from a
stock configuration, eBGP IPv4 with ECMP, APPL_DB parity with FRR (34 rows),
ASIC_DB, forwarding, `show ip bgp summary`, `show ip route`, `route_check.py`,
bgpmon, `sonic-clear ip bgp`, the `vty` shell from the host, and `sudo TSA` /
`TSC` / `TSB` through CONFIG_DB (a test prefix withdrawn and the loopback
re-advertised with the traffic-shift community, then both restored; the mode
kept across a restart of the container). On an earlier image of the same code: IPv6 eBGP,
and neighbor shutdown, startup, remove and re-add through CONFIG_DB, and a
container restart with leftover routes.

Not covered, and the reason a zebra-rs image is not a drop-in replacement yet:

- **The bgpcfgd managers left out** (§4.3), W-ECMP and IDF isolation among
  them. TSA was observed for IPv4 only, on a single-ASIC VS; the multi-ASIC and
  chassis paths of the host scripts have not run.
- **Three template families** wait on zebra-rs features: `update-source
  <interface>`, `set originator-id`, `bestpath peer-type multipath-relax`.
- **`dynamic` and `sentinels`** are accepted by the daemon but have not run on
  a VM.
- **Default VRF only**, in bgpcfgd and in the vtysh compatibility.
- **FPM carries plain IPv4/IPv6 unicast.** SONiC's private message types
  (SRv6 local SIDs, PIC contexts, EVPN multihoming) and nexthop-group mode are
  not implemented.
- **Warm and fast reboot** have not been exercised.
- **A new neighbor can take up to a minute to come up**: with more than ten
  peers zebra-rs jitters the first dial 5–60 s.
- Tested on the virtual switch only; no hardware, no sonic-mgmt run.

Each of these is tracked, with its phase, in
[`sonic-zebra-rs-plan.md`](sonic-zebra-rs-plan.md) and
[`bgp-sonic-gaps.md`](bgp-sonic-gaps.md).
