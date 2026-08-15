# Replacing FRR with zebra-rs in SONiC — Porting Plan

Status: proposal / working plan
Scope: `sonic-buildimage` (this tree) + `zebra-rs` (`../zebra-rs`, v26.8.2)

---

## 0. Verdict on the strategy

`sonic-port.md` proposes: keep SONiC's southbound stack, teach zebra-rs to speak
FPM like FRR's zebra, don't touch orchagent/SAI. **That is the right call and this
plan adopts it.** Research below confirms the seam is clean: `fpmsyncd` is a
protocol-agnostic TCP server that only ever sees netlink bytes, and zebra-rs
already has a pluggable southbound tee (`CradleFib`) built exactly for this shape.

Three corrections to `sonic-port.md`, all evidence-based:

1. **"FPM like FRR" is not enough — SONiC has its own FPM dialect.** SONiC ships a
   *forked* FRR dataplane plugin, `src/sonic-frr/dplane_fpm_sonic/dplane_fpm_sonic.c`
   (3670 lines), and `fpmsyncd` parses private message types that upstream FRR's
   `dplane_fpm_nl` never sends: `RTM_NEWSRV6LOCALSID` (1000/1001),
   `RTM_NEWPICCONTEXT` (2000/2001), `RTM_NEWSRV6VPNROUTE` (3000/3001), plus
   `RTM_FPM_*` and `RTM_NEWTFILTER`-carried EVPN multihoming state
   (`src/sonic-swss/fpmsyncd/fpmlink.h:19-24`, `fpmlink.cpp:36-66`). Plain-IP
   parity is small; full parity is a second, much larger surface. Phase them.

2. **The offload feedback loop is mandatory, not "later".** SONiC's default bgpd
   template emits `bgp suppress-fib-pending`
   (`dockers/docker-fpm-frr/frr/bgpd/bgpd.main.conf.j2:110`) and runs zebra with
   `--asic-offload=notify_on_offload`
   (`dockers/docker-fpm-frr/frr/supervisord/supervisord.conf.common.j2:26`).
   `fpmsyncd` writes routes to APPL_DB, waits for APPL_STATE_DB, then sends an
   `RTM_NEWROUTE` *back over the same TCP socket* with `RTM_F_OFFLOAD` set
   (`routesync.cpp:3570-3623`, `RouteSync::onRouteResponse` at `routesync.cpp:3635`).
   Without the read side, BGP never un-suppresses and advertisement stalls. This
   is Phase 2, not Phase C.

3. **The operational/CLI surface is the largest hidden cost.** `sonic-utilities`
   calls `vtysh` in **416 places**, all expecting FRR's JSON schemas
   (`utilities_common/bgp_util.py`, `scripts/route_check.py:415`,
   `scripts/fast-reboot-filter-routes.py:14`), and `bgpmon`
   (`src/sonic-bgpcfgd/bgpmon/bgpmon.py:80`) and `bgp_eoiu_marker.py`
   (`src/sonic-swss/fpmsyncd/bgp_eoiu_marker.py:50,104`) poll
   `show bgp summary json` / `show bgp neighbors <x> json` to populate STATE_DB.
   `sonic-port.md` does not mention this at all. It deserves its own phase and is
   roughly the same size as the config bridge.

Also: `sonic-port.md`'s milestone order puts the config bridge (D) *after* warm
reboot (C). Swap them — you cannot build a realistic warm-reboot test without
CONFIG_DB-driven configuration first.

---

## 1. The integration surface (researched)

### 1.1 Southbound — FIB

Today's path:

```
bgpd/staticd → zebra RIB → kernel netlink  ─┐
                        └→ dplane_fpm_sonic ─┴→ TCP 2620 → fpmsyncd → APPL_DB → orchagent → ASIC_DB → syncd → SAI
```

Facts that constrain the encoder:

| Fact | Evidence |
|---|---|
| `fpmsyncd` is the TCP **server** (port 2620); zebra dials out | `fpmsyncd/fpmlink.h:29-31`, `fpm/fpm.h:90` |
| Framing = `fpm_msg_hdr_t` (version 1, type `FPM_MSG_TYPE_NETLINK`), 4-byte aligned, 16 KiB max | `fpm/fpm.h:100-143` |
| Default mode is **inline `RTA_MULTIPATH`**, not kernel nexthop groups — `docker_init.sh` writes `no fpm use-next-hop-groups` into zebra.conf | `dockers/docker-fpm-frr/docker_init.sh:46-53`, `dplane_fpm_sonic.c:395-410` |
| Route protocol matters: `rtm_protocol` → `rtnl_route_proto2str` → APPL_DB `protocol` field | `routesync.cpp:960` |
| VRF is resolved from `RTA_TABLE`/`rtm_table` → ifindex → **ifname, which must start with `Vrf`** | `routesync.cpp:920-942` (`VRF_PREFIX` at `routesync.cpp:37`) |
| Offload ack flows *back* on the same socket with `RTM_F_OFFLOAD` | `routesync.cpp:3570-3623`, `routesync.h:385-392` |
| Nexthop-group mode writes `APP_NEXTHOP_GROUP_TABLE` keyed by NHG id | `routesync.cpp:173`, `routesync.cpp:1966` |

zebra-rs side:

- `FibHandle` (`zebra-rs/src/fib/netlink/handle.rs`, 4833 lines) is the single
  southbound choke point: `route_ipv4_add/del`, `route_ipv6_add/del`,
  `nexthop_add/del`, `ilm_*`, `route_sid_*`, `mac_add/del`, `mdb_*`.
- `CradleFib` (`zebra-rs/src/fib/cradle.rs`, 2237 lines) is a working precedent
  for a **tee**: same call sites, a desired-state mirror (`CradleMirror`), and a
  `replay()` for reconnect. An FPM client is structurally the same object with a
  different wire format.
- Protocol tagging already exists: `RibType::{Static,Bgp,Ospf,Isis}` →
  `RouteProtocol::*` at `handle.rs:825-829` and `handle.rs:1105-1109`.
- **No FPM code exists in zebra-rs today** (grep for `fpm` across `zebra-rs/src`,
  `book/`, `docs/` returns only unrelated `nfpm` packaging hits).

### 1.2 Northbound — configuration

Two SONiC modes, both selected in `docker_init.sh`:

- **`bgpcfgd`** (default): 16 managers under `src/sonic-bgpcfgd/bgpcfgd/`
  (`managers_bgp`, `managers_rm`, `managers_prefix_list`, `managers_allow_list`,
  `managers_bfd`, `managers_static_rt`, `managers_srv6`, `managers_device_global`,
  `managers_bbr`, `managers_aggregate_address`, `managers_as_path`,
  `managers_advertise_rt`, `managers_setsrc`, `managers_intf`,
  `managers_chassis_app_db`, `managers_db`). They watch CONFIG_DB, render Jinja
  templates, and push text through **`vtysh -f <tmpfile>`**
  (`src/sonic-bgpcfgd/bgpcfgd/frr.py:41-56`). Initial config comes from
  `sonic-cfggen` rendering `dockers/docker-fpm-frr/frr/**` into `/etc/frr/*.conf`.
- **`frrcfgd`** (`src/sonic-frr-mgmt-framework/`) when
  `DEVICE_METADATA.localhost.frr_mgmt_framework_config == "true"`.

zebra-rs equivalent exists and is a good match:

- Startup: `--config-file` accepts **CLI brace, JSON, YAML, or set/delete**
  format (`zebra-rs/src/main.rs:60-66`; JSON/YAML lowering in
  `zebra-rs/src/config/json.rs`).
- Runtime: `vtyctl apply -c "set …\nset …"` / `-f file` over the gRPC VTY socket
  (`vtyctl/src/apply.rs:18-60`) — a direct, line-oriented replacement for
  `vtysh -f`, with candidate/commit semantics.
- Schema is YANG (93 modules under `zebra-rs/yang/`), so config is validated, not
  string-matched.

### 1.3 Operational — CLI, JSON, telemetry

- Host `vtysh` is a shim: `docker exec -ti bgp$DEV vtysh "$@"`
  (`dockers/docker-fpm-frr/base_image_files/vtysh`), installed via
  `$(DOCKER_FPM_FRR)_BASE_IMAGE_FILES` in `rules/docker-fpm-frr.mk:43-51`
  (also `rvtysh`, `TSA/TSB/TSC/TS`, `idf_isolation`, `prefix_list`).
- Consumers: `sonic-utilities` (416 `vtysh` references), `bgpmon` → STATE_DB
  `BGP_NEIGHBOR` table, `bfdmon`, `bgp_eoiu_marker.py`, `route_check.py`,
  `fast-reboot-filter-routes.py`, plus `bgpcfgd` itself (`show daemons`,
  `show running-config`, `clear bgp peer-group … soft in`,
  `show bgp peer-group … json`, `show bfd peers json`).
- zebra-rs has a rich `show` tree with `--json`
  (`zebra-rs/src/bgp/show.rs`: `/show/bgp/summary`, `/show/bgp/neighbor`,
  `/show/bgp/ipv4|ipv6`, VPN tables, EVPN) — but the **JSON schema is zebra-rs's
  own, not FRR's**. This is a translation problem, not a missing-feature problem.

### 1.4 Lifecycle

- Warm restart: `fpmsyncd` runs a `WarmStartHelper`, defers deletes, and waits for
  BGP EOIU flags in STATE_DB (`fpmsyncd.cpp:48-69,129-200`) that
  `bgp_eoiu_marker.py` sets by polling FRR JSON.
- FRR-side: `bgp graceful-restart` + `preserve-fw-state` +
  `select-defer-time` (`bgpd.main.conf.j2:126-134`), `long-lived-graceful-restart`
  for `UpperRegionalHub`.
- Container ordering: `$(DOCKER_FPM_FRR)_WARM_SHUTDOWN_BEFORE = swss`,
  `_WARM_SHUTDOWN_AFTER = radv` (`rules/docker-fpm-frr.mk:26-29`).
- TSA/TSB now route through CONFIG_DB (`BGP_DEVICE_GLOBAL.STATE.tsa_enabled`) →
  `managers_device_global`, so they follow the config bridge rather than needing
  their own port (`dockers/docker-fpm-frr/base_image_files/TSA`).

### 1.5 Build & packaging

Good news — the tree is already Rust-ready:

- `sonic-slave-trixie/Dockerfile.j2:793-833`: rustup toolchain **1.86.0**,
  cross targets for `armv7`/`aarch64`, `cargo-auditable` wrapper at
  `/usr/local/bin/cargo`, `cargo-tarpaulin`, `rust-audit-info` for SBOM.
- Precedents for Rust `.deb`s in-tree: `src/sonic-dash-ha` (`rules/dash-ha.mk`,
  `SONIC_DPKG_DEBS`), `src/sonic-nettools`, `src/sonic-ctrmgrd-rs`,
  `src/sonic-supervisord-utilities-rs`.
- zebra-rs is edition 2024 (needs ≥1.85 — 1.86 is fine) and packages with
  `cargo-deb` (`packaging/Makefile`), shipping `/usr/bin/zebra-rs`, `vtyctl`,
  `vtyhelper`, `vtypam`, `/usr/share/zebra-rs/yang/`, and a `vty` shell.
- `dockers/docker-fpm-gobgp/` is a precedent for an alternative-routing-stack
  container image in this tree.

---

## 2. Gap analysis — zebra-rs vs what SONiC's templates ask for

Derived from `dockers/docker-fpm-frr/frr/bgpd/**` and the bgpcfgd managers.

**Already present in zebra-rs** (verified in `zebra-rs/src/bgp/` and `zebra-rs/yang/`):
peer-groups (`zebra-bgp-neighbor-group.yang`), `allowas-in`, `route-reflector-client`,
`next-hop-self`, `soft-reconfiguration` (`bgp/peer.rs`, `bgp/route.rs`),
`maximum-paths`, add-path (`bgp/cap.rs`), graceful restart + LLGR
(`zebra-bgp-afi-knobs.yang`), `update-source`/`ebgp-multihop`
(`zebra-bgp-transport.yang`), dynamic neighbors / listen-range
(`zebra-bgp-dynamic-neighbors.yang`), `table-map` (`zebra-bgp-table-map.yang`),
redistribute + policy (`zebra-bgp-redistribute.yang`), full policy engine —
prefix-list, as-path-set (FRR-regex compatible, `yang/config.yang:4819-4835`),
community / large-community / ext-community, `advertise-all-vni`
(`zebra-bgp-evpn.yang`), BFD, MD5/auth, VRF/L3VPN, SRv6, EVPN, IS-IS, OSPF.

**Gaps to close** (no hits in source or YANG):

| Gap | Where SONiC needs it | Phase |
|---|---|---|
| FPM client / encoder | everything | 1 |
| Offload-ack ingest + route "offloaded" state | `suppress-fib-pending` | 2 |
| `bgp suppress-fib-pending` semantics (gate advertisement on FIB ack) | `bgpd.main.conf.j2:110` | 2 |
| `bestpath as-path multipath-relax` | `bgpd.main.conf.j2:120` | 4 |
| BMP client (`bmp targets` / `bmp monitor` / `bmp connect`) | `bgpd.main.conf.j2:145-155`, `docker-sonic-bmp` | 8 (optional) |
| FRR-schema JSON emulation | 416 `vtysh` call sites | 5 |
| EOIU / end-of-RIB signalling to STATE_DB | warm reboot | 6 |
| SONiC private FPM types (SRv6 localsid, PIC context, SRv6 VPN route, EVPN MH) | SRv6/EVPN features | 8 |
| `aggregate-address` (confirm; `managers_aggregate_address` uses it) | bgpcfgd | 4 |

---

## 3. Phases

Each phase lists internal steps, deliverables, and an exit criterion. Phases 1–3
are the risky, load-bearing part; 4–7 are volume work; 8–9 are scope-expansion
and rollout.

---

### Phase 0 — Groundwork and harness

Goal: be able to observe and replay the exact bytes FRR sends, before writing any
encoder.

1. **Stand up a SONiC VS baseline.** Build/boot `sonic-vs` with stock
   `docker-fpm-frr`, a small eBGP topology, and confirm routes land in APPL_DB.
2. **Build an FPM recorder.** Small tool that sits on TCP 2620, accepts zebra's
   connection, dumps every `fpm_msg_hdr_t` + netlink payload to a file, and
   forwards to the real `fpmsyncd` (man-in-the-middle). This gives a golden corpus.
3. **Capture golden traces** for: IPv4/IPv6 unicast add/del, ECMP (inline
   multipath), route replace, blackhole, connected, VRF routes, static routes,
   the offload-ack direction, and — separately — NHG mode
   (`fpm use-next-hop-groups`).
4. **Build a replay harness** that feeds a recorded trace into a *real* `fpmsyncd`
   and diffs the resulting APPL_DB. This becomes the Phase-1 acceptance test:
   *zebra-rs's bytes must produce a byte-identical APPL_DB to FRR's bytes.*
5. **Decide the repo layout.** Recommendation: FPM code lives in **zebra-rs**
   (`zebra-rs/src/fib/fpm/`), SONiC integration lives in **sonic-buildimage**
   (new `src/sonic-zebra-rs/` submodule pointer + `dockers/docker-fpm-zebra-rs/`).
   Nothing SONiC-specific in zebra-rs beyond the wire format, which is generic FPM.
6. **Pin the toolchain question.** Confirm zebra-rs builds under the slave's Rust
   1.86.0; if not, raise `sonic-slave-*/Dockerfile.j2` and note the blast radius
   for the other Rust packages.

**Exit:** golden traces recorded; replay harness reproduces stock APPL_DB content.

---

### Phase 1 — FPM client tee in zebra-rs (southbound v1)

Goal: zebra-rs-computed routes appear in APPL_DB, unchanged SONiC below.

1. **New module `zebra-rs/src/fib/fpm/`**, modeled on `fib/cradle.rs`:
   - `mod.rs` — `SonicFpm` handle, config, lifecycle
   - `client.rs` — TCP client to `127.0.0.1:2620`, reconnect with backoff,
     framing per `fpm/fpm.h`
   - `encode.rs` — netlink `RTM_NEWROUTE`/`RTM_DELROUTE` builders
   - `mirror.rs` — desired-state mirror + `replay()` on reconnect (mirror the
     `CradleMirror` pattern; a reconnect must not leave APPL_DB stale)
2. **Wire into `FibHandle`** at the same call sites the cradle tee uses:
   `route_ipv4_add/del`, `route_ipv6_add/del`, `route_*_blackhole`. Kernel install
   is unchanged and stays primary — SONiC expects both.
3. **Encoder v1 (inline multipath only)**: `rtm_family`, `rtm_dst_len`,
   `rtm_protocol` from `RibType` (reuse `handle.rs:825-829`), `rtm_type`
   (`RTN_UNICAST`/`RTN_BLACKHOLE`), `RTA_DST`, `RTA_GATEWAY`, `RTA_OIF`,
   `RTA_PRIORITY`, `RTA_TABLE`, and `RTA_MULTIPATH` for ECMP with per-hop
   `rtnh_flags`/weights.
4. **VRF mapping**: emit the kernel table id in `RTA_TABLE` such that
   `fpmsyncd`'s ifindex→ifname lookup yields a `Vrf*` device
   (`routesync.cpp:929-942`). Reuse zebra-rs's `vrf_index_table_by_name`
   (`handle.rs:3003`).
5. **Config knobs** (new YANG module, e.g. `zebra-fpm.yang`), mirroring the
   cradle knobs' shape:
   `system fpm { enabled true; address 127.0.0.1; port 2620; use-next-hop-groups false; }`
6. **Optional NHG mode**: emit `RTM_NEWNEXTHOP`/`RTM_DELNEXTHOP` + `RTA_NH_ID`
   when `use-next-hop-groups` is on. Keep it decoupled from the kernel-side
   `--no-nhid` flag — the two are independent choices.
7. **Tests**: unit tests asserting encoder output equals the Phase-0 golden bytes;
   an integration test that runs zebra-rs against a real `fpmsyncd` + Redis and
   diffs APPL_DB against the FRR baseline.

**Exit:** for a static + eBGP IPv4/IPv6 scenario, APPL_DB after zebra-rs is
field-identical to APPL_DB after FRR.

**Risks:** subtle attribute-ordering or alignment differences; `NLM_F_REPLACE`
semantics on route churn. Mitigation: golden-byte diffing from day one.

---

### Phase 2 — Offload feedback and FIB-pending suppression

Goal: close the control loop so BGP advertisement is gated on real hardware
programming — the behavior SONiC's default template assumes.

1. **Read side in the FPM client**: parse inbound `RTM_NEWROUTE` on the same
   socket, detect `RTM_F_OFFLOAD` (0x4000) / `RTM_F_TRAP`, map back to
   `(prefix, table)`.
2. **RIB state**: add an `offloaded` flag to the RIB entry, orthogonal to the
   existing `installed` (`zebra-rs/src/rib/entry.rs`). Set on ack, clear on
   re-announce, age out on timeout.
3. **BGP gate**: implement `suppress-fib-pending` — hold a prefix out of the
   Adj-RIB-Out until offload-acked; release on ack or on a configurable timeout.
   Hook where the existing FIB-install path already notifies BGP.
4. **Config**: `router bgp { suppress-fib-pending true; }` in YANG + CLI.
5. **Startup resync**: `fpmsyncd` replays acks for the whole APPL_DB route table
   on (re)connect (`routesync.cpp:3742-3765`) — make sure the mirror/replay logic
   from Phase 1 tolerates the flood and doesn't double-count.
6. **Tests**: kill/restart `fpmsyncd` mid-convergence; verify no permanently
   suppressed prefixes and no stale APPL_DB rows.

**Exit:** with `suppress-fib-pending` on, a route is advertised only after the ack
returns; forced-failure injection produces bounded, self-healing behavior.

---

### Phase 3 — `docker-fpm-zebra-rs` container on VS

Goal: a bootable SONiC VS image whose `bgp` container runs zebra-rs, configured
by hand, doing real eBGP.

1. **New image dir** `dockers/docker-fpm-zebra-rs/` — start from
   `docker-fpm-frr/` and `docker-fpm-gobgp/` as templates.
2. **Supervisord program set**: replace `mgmtd`/`zebra`/`staticd`/`bgpd`/`bfdd`
   with a single `zebra-rs` program (one process, all protocols), keep
   `fpmsyncd`, keep the readiness gate (a `zsocket.sh` analogue that waits on the
   VTY gRPC socket instead of TCP 2601).
3. **Capabilities**: `zebra-rs` needs `cap_net_admin`, `cap_net_raw`,
   `cap_net_bind_service`, `cap_net_broadcast` — the container already has
   `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN` (`rules/docker-fpm-frr.mk:36`);
   confirm file caps survive the `.deb` install path.
4. **`docker_init.sh`**: keep the default-gateway demotion logic verbatim
   (it matters for containerized routing), keep `sr0` dummy creation, replace the
   `sonic-cfggen` FRR-template block with a zebra-rs config render (Phase 4 fills
   this in; here it can be a static file).
5. **rules/**: `rules/zebra-rs.mk` (the `.deb`) + `rules/docker-fpm-zebra-rs.mk`,
   modeled on `rules/dash-ha.mk` + `rules/docker-dash-ha.mk`. Gate the whole thing
   behind `INCLUDE_ZEBRA_RS` / a `ROUTING_STACK` variable so the FRR image remains
   the default and both can be built.
6. **Bring-up**: two-node VS eBGP leaf/spine, IPv4 + IPv6 + static, verify APPL_DB,
   ASIC_DB, and dataplane forwarding.

**Exit:** VS topology converges on zebra-rs and forwards traffic; FRR image still
builds and passes unchanged.

---

### Phase 4 — Config bridge (CONFIG_DB → zebra-rs)

Goal: SONiC's existing CONFIG_DB semantics drive zebra-rs, with no change to
CONFIG_DB schema or to how operators configure the box.

Recommended approach: **keep bgpcfgd's architecture, swap its backend and its
templates.** The managers already encode the CONFIG_DB semantics correctly;
rewriting them is wasted risk.

1. **Backend swap**: new `bgpcfgd/zebra_rs.py` implementing the same interface as
   `bgpcfgd/frr.py` — `write()` → `vtyctl apply -f <tmpfile>`,
   `get_config()` → `vtyctl show running-config`, `wait_for_daemons()` → poll the
   VTY gRPC socket, `restart_peer_groups()` → the zebra-rs `clear bgp` equivalent
   (`zebra-bgp-clear.yang`). Select via a constant/feature flag so one wheel
   supports both stacks.
2. **Template port, by manager, in dependency order.** Each is a self-contained
   unit of work with its own unit tests under `src/sonic-bgpcfgd/tests/`:
   1. `managers_bgp` (neighbors, peer-groups, the `templates/{general,dynamic,voq_chassis,internal,monitors,sentinels}/` families)
   2. `managers_prefix_list`, `managers_rm`, `managers_as_path` (policy)
   3. `managers_allow_list` (built on the above)
   4. `managers_static_rt` (replaces staticd)
   5. `managers_bfd` (zebra-rs has native BFD — this gets *simpler*)
   6. `managers_device_global` (TSA/TSB, WCMP, IDF isolation)
   7. `managers_bbr`, `managers_aggregate_address`, `managers_advertise_rt`,
      `managers_setsrc`, `managers_intf`, `managers_srv6`, `managers_chassis_app_db`
3. **Startup config render**: port `dockers/docker-fpm-frr/frr/**` Jinja templates
   to a zebra-rs equivalent tree. **Prefer emitting YAML/JSON** over CLI-brace
   text — `sonic-cfggen` already produces structured data, zebra-rs's loader
   ingests JSON/YAML natively (`src/config/json.rs`), and structured output kills
   a whole class of whitespace/ordering bugs that plague the current templates.
4. **Close the small feature gaps** surfaced in §2 as they are hit:
   `multipath-relax`, `aggregate-address`, `suppress-fib-pending` config leaf.
5. **`frrcfgd` decision**: do *not* port it in this phase. Declare
   `frr_mgmt_framework_config == "true"` unsupported on zebra-rs for now and fail
   loudly at container start. Revisit only if a consumer appears.
6. **Golden-config tests**: for each CONFIG_DB fixture in
   `src/sonic-bgpcfgd/tests/data/`, assert the generated zebra-rs config commits
   cleanly against the YANG schema and yields the intended running config.

**Exit:** a stock `config_db.json` for T0 and T1 roles boots the zebra-rs
container to the same protocol state as FRR, with no manual steps.

---

### Phase 5 — Operational compatibility (`vtysh`, JSON, telemetry)

Goal: `show ip bgp summary`, `show ip route`, `bgpmon`, and `route_check` keep
working — for operators, tooling, and every existing sonic-mgmt test.

1. **Inventory and classify** all 416 `vtysh` call sites. Expect three buckets:
   (a) `show … json` consumed programmatically — must be schema-exact;
   (b) `show …` human text — must be *reasonable*, not identical;
   (c) config/clear commands — route to `vtyctl`.
2. **Build a `vtysh` compatibility shim** in the container: a small binary/script
   accepting FRR's argv (`-c`, `-f`, `-H`, `-n`, the tty tag the host shim passes),
   translating the FRR command string to the zebra-rs `show`/`apply` path, and —
   for `json` forms — **re-shaping zebra-rs JSON into FRR's schema**. This one
   component protects the entire 416-site surface and every existing test.
   Implement it in Rust next to `vtyctl` so the schema mapping is type-checked.
3. **Priority order for JSON schemas** (highest-value first):
   `show bgp summary json` and `show bgp vrf <v> summary json` (bgpmon, `show ip bgp summary`),
   `show ip route json` / `show ipv6 route json` (`route_check.py`),
   `show ip route connected json` (`fast-reboot-filter-routes.py`),
   `show bgp neighbors <ip> json` (EOIU marker, `show ip bgp neighbors`),
   `show bfd peers json` (`bfdmon`, `managers_bfd`),
   `show bgp peer-group <pg> json` (`managers_bgp`),
   `show daemons` / `show running-config` (bgpcfgd startup).
4. **Contract tests**: capture FRR JSON on VS for each command, and assert the
   shim's output validates against the same consumer code paths
   (`bgp_util.process_bgp_summary_json`, `route_check.py`'s parser, etc.). Reuse
   `src/sonic-utilities/tests/bgp_commands_test.py` fixtures as the oracle.
5. **Native path, longer term**: for new SONiC code, prefer zebra-rs's gRPC/JSON
   or its MCP server (`vtyctl/src/mcp/`) directly. The shim is compatibility, not
   architecture — mark it as such so it doesn't calcify.
6. **Host-side files**: ship `vtysh`, `rvtysh`, `TSA/TSB/TSC/TS`,
   `idf_isolation`, `prefix_list` from the new image via `_BASE_IMAGE_FILES`
   pointing at the `bgp` container as before.

**Exit:** `show ip bgp summary`, `show ip route`, `show bfd peers`, `bgpmon`
STATE_DB population, and `route_check.py` all pass on VS against zebra-rs.

---

### Phase 6 — Lifecycle: warm reboot, fast reboot, GR, TSA

1. **Graceful restart**: map SONiC's template knobs
   (`restart-time`, `preserve-fw-state`, `select-defer-time`, LLGR stale-time)
   onto zebra-rs GR config; verify helper *and* restarting-speaker roles.
2. **EOIU signalling**: `bgp_eoiu_marker.py` polls FRR JSON to write
   `BGP_STATE_TABLE|IPv4|eoiu` in STATE_DB, which `fpmsyncd` waits on
   (`fpmsyncd.cpp:52-69`). Two options — (a) let the Phase-5 shim satisfy the
   existing script, or (b) have zebra-rs write the STATE_DB flags natively on
   end-of-RIB. **Recommend (a) first** (zero new coupling), (b) later as cleanup.
3. **Warm shutdown ordering**: set `_WARM_SHUTDOWN_BEFORE/_AFTER` and
   `_FAST_SHUTDOWN_BEFORE/_AFTER` in `rules/docker-fpm-zebra-rs.mk` to match FRR's
   (`before swss`, `after radv`).
4. **Config persistence across restart**: zebra-rs's candidate/running model plus
   `/etc/zebra-rs/zebra-rs.conf` must survive container restart identically to
   `/etc/frr/*.conf`; verify the conffile is on a persisted mount or regenerated.
5. **FIB reconciliation**: on warm start, zebra-rs's FPM mirror must re-send the
   full RIB so `fpmsyncd`'s `WarmStartHelper` can reconcile and delete stale
   APPL_DB rows. Test the "route disappeared during downtime" case explicitly.
6. **Fast reboot**: verify `fast-reboot-filter-routes.py` path (needs
   `show ip route connected json`).
7. **TSA/TSB/TSC**: exercise via CONFIG_DB (`BGP_DEVICE_GLOBAL.STATE.tsa_enabled`)
   and confirm route-map application and withdrawal.

**Exit:** warm reboot on VS with zebra-rs shows no dataplane loss and clean
APPL_DB reconciliation; fast reboot and TSA/TSB behave as with FRR.

---

### Phase 7 — Build, packaging, CI

1. **Source integration**: add zebra-rs as a submodule at `src/sonic-zebra-rs`
   (matching how `src/sonic-frr/frr` is carried), with a `Makefile` following
   `src/sonic-dash-ha/Makefile`.
2. **`rules/zebra-rs.mk`**: produce `zebra-rs_<ver>_<arch>.deb` via
   `SONIC_DPKG_DEBS`, plus a `-dbgsym` derived package
   (`add_derived_package`), matching `rules/dash-ha.mk`. Decide `cargo-deb` vs a
   `debian/` dir — `cargo-deb` is already working upstream; a thin `debian/rules`
   wrapper is the lower-friction path into SONiC's `SONIC_DPKG_DEBS` flow.
3. **Multi-arch**: build for `amd64`, `arm64`, `armhf` using the slave's existing
   cross targets (`sonic-slave-trixie/Dockerfile.j2:796-802`).
4. **Reproducibility/SBOM**: the `cargo` wrapper injects `cargo auditable`
   automatically — verify `rust-audit-info` reads the resulting binary so
   `scripts/sbom_fragment.py` produces a fragment.
5. **Versioning/buildinfo**: add `versions-*` entries under the new docker's
   `buildinfo/` so the version-lock machinery is satisfied.
6. **Feature flag**: `INCLUDE_ZEBRA_RS` (default `n`) in `rules/config`, with
   `SONIC_INSTALL_DOCKER_IMAGES` gating, so mainline is unaffected until Phase 9.
7. **CI**: add a VS pipeline stage that builds the zebra-rs image and runs the
   Phase 3/5 smoke tests.

**Exit:** `make target/sonic-vs.img.gz` with `INCLUDE_ZEBRA_RS=y` builds clean from
scratch on all three arches; default builds unchanged.

---

### Phase 8 — Advanced features (only where SONiC already has orch support)

Order by SONiC demand, not by protocol elegance. Each item is independently
shippable.

1. **VRF / L3VPN**: multi-VRF FPM encoding (`RTA_TABLE` per VRF), `Vrf*` device
   naming, `managers_bgp` VRF keys.
2. **SRv6**: implement SONiC's private FPM types —
   `RTM_NEWSRV6LOCALSID`/`RTM_DELSRV6LOCALSID` (1000/1001) with the
   `custom_rtattr_srv6_localsid*` attribute enums
   (`dplane_fpm_sonic.c:113-171`), `RTM_NEWSRV6VPNROUTE` (3000/3001), and
   `RTM_NEWPICCONTEXT` (2000/2001). zebra-rs already has the SRv6 RIB
   (`src/rib/srv6/`, `src/fib/netlink/srv6.rs`) — this is encoding work.
3. **EVPN**: VXLAN/Type-2/Type-3 via `fpmsyncd`'s VXLAN paths; EVPN multihoming
   (split-horizon label, DF election, backup NHG) via `RTM_FPM_*` and
   `RTM_NEWTFILTER` (`fpmlink.cpp:47-64`, `routesync.cpp:2061-2400`).
4. **BMP**: implement a BMP client in zebra-rs if `docker-sonic-bmp` is in scope
   for the target deployment; otherwise document as unsupported.
5. **Multi-ASIC**: per-namespace containers (`bgp0`, `bgp1`, …), namespace-aware
   VTY socket paths, `-n` handling in the `vtysh` shim, `managers_chassis_app_db`.
6. **PIM / multicast, OSPF, IS-IS**: zebra-rs has all three natively; expose them
   through CONFIG_DB only if a consumer exists.

---

### Phase 9 — Rollout

1. **Coexistence period**: both images build; `ROUTING_STACK`/`INCLUDE_ZEBRA_RS`
   selects. Keep FRR the default.
2. **sonic-mgmt**: run the full `bgp/` and `route/` test suites against a
   zebra-rs VS testbed; triage failures into "zebra-rs bug" vs "test hard-codes
   FRR output" and fix the former, upstream test changes for the latter.
3. **Hardware validation** on at least one real platform per ASIC vendor in scope.
4. **Scale**: full-table eBGP (≥1M routes), convergence timing vs FRR, memory and
   CPU under churn. zebra-rs's sharded BGP RIB should win here — measure it, since
   it is the main *positive* argument for the migration.
5. **Documentation**: operator-facing differences (CLI syntax, config file format,
   `show` output), plus a migration guide.
6. **Default flip** and FRR deprecation — only after 2–4 above are green, and keep
   the FRR image buildable for at least one release.

---

## 4. Sequencing summary

| Phase | Outcome | Blocks |
|---|---|---|
| 0 | FPM recorder + golden traces + replay harness | 1 |
| 1 | FPM tee in zebra-rs; routes reach APPL_DB byte-identically | 2, 3 |
| 2 | Offload ack + `suppress-fib-pending` | 3 |
| 3 | `docker-fpm-zebra-rs` boots on VS; eBGP works | 4, 5 |
| 4 | CONFIG_DB → zebra-rs bridge (bgpcfgd backend + templates) | 5, 6 |
| 5 | `vtysh` shim + FRR-schema JSON; tooling works | 6, 9 |
| 6 | Warm/fast reboot, GR, TSA | 9 |
| 7 | `.deb` + docker + CI in sonic-buildimage | 9 |
| 8 | VRF, SRv6, EVPN, BMP, multi-ASIC | 9 |
| 9 | sonic-mgmt, scale, hardware, default flip | — |

Phases 4 and 5 are independent of each other and can run in parallel once Phase 3
lands; 7 can start as soon as Phase 3's image layout is settled.

## 5. Explicit non-goals

- Do **not** replace `orchagent`, `fpmsyncd`, or invent a parallel SAI path.
- Do **not** write APPL_DB from zebra-rs directly. It duplicates `fpmsyncd`,
  tightens coupling, and buys nothing until a feature FPM genuinely cannot encode.
- Do **not** bypass the kernel FIB. SONiC's consistency model, `route_check.py`,
  and containerized default-route handling all assume kernel routes exist.
- Do **not** chase full FRR feature parity before the FPM loop works end to end.
- Do **not** port `frrcfgd` until a consumer demands it.

## 6. Biggest risks

1. **The `vtysh`/JSON surface (Phase 5)** — 416 call sites, schemas that were
   never specified, only observed. Largest source of long-tail breakage.
   *Mitigation:* the shim + contract tests against captured FRR output.
2. **FPM dialect drift (Phase 8)** — `dplane_fpm_sonic.c` is a SONiC fork that
   changes with FRR upgrades. *Mitigation:* the Phase-0 recorder becomes a
   permanent regression tool; re-capture on every SONiC FRR bump.
3. **Warm reboot** — the most integration-sensitive behavior in the system, and
   the hardest to test convincingly. *Mitigation:* automate it on VS in CI early
   (Phase 6), not manually at the end.
4. **Scale regressions found late** — measure at Phase 3 (rough) and Phase 9
   (rigorous), not only at the end.
