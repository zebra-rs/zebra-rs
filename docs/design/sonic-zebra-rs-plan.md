# Replacing FRR with zebra-rs in SONiC — Porting Plan

Status: in progress — Phases 0–3 landed, Phase 4 underway; zebra-rs runs on SONiC VS from CONFIG_DB
Scope: `zebra-rs` (this tree, v26.11.4) + `sonic-buildimage` (`../sonic-buildimage`, branch `zebra-rs-container`)
Last audited: 2026-11-16

This file is the plan of record. A copy at the root of `sonic-buildimage`
(`sonic-zebra-rs-plan.md`, last touched 2026-08-09) is older than this one; its
content has been merged here.

**Where this is now** (§2 has the detail, §4 the full table):

| Phase | State |
|---|---|
| 0 — harness, golden traces | done (`tools/fpm-tap`) |
| 1 — FPM tee | done for IPv4/IPv6 unicast incl. ECMP, VRF, connected; NHG mode not implemented |
| 2 — offload ack + `suppress-fib-pending` | done |
| 3 — `docker-fpm-zebra-rs` | done; selected by `SONIC_ROUTING_STACK=zebra-rs` |
| 4 — config bridge | startup instance template ported; 3 of 6 peer families ported; **bgpcfgd backend wired** for those three |
| 5 — `vtysh` / JSON compatibility | not started |
| 6 — lifecycle | shutdown ordering set; restart leftovers handled; restarting-speaker GR (`select-defer-time`) open |
| 7 — packaging | **the full image builds**: `make target/sonic-vs.img.gz` with `SONIC_ROUTING_STACK = zebra-rs`, through the slave, and boots |
| 8, 9 | not started |

**Verified on a SONiC VS, 2026-11-16** (§2.7). A `sonic-vs` image built by the
ordinary SONiC `make` with zebra-rs selected as the routing stack — no FRR image
on the box — was booted under KVM beside a stock FRR `sonic-vs`, back to back on
two links. From the image's stock `config_db.json`, with no manual configuration:
bgpcfgd configures all 32 neighbors, both real sessions establish, the ECMP route
is acknowledged as offloaded, APPL_DB holds the same 34 route rows as the FRR
baseline with the same fields, ASIC_DB is programmed, and traffic forwards. The
caveat that matters: the zebra-rs in that image carried the three fixes of §2.7
as an uncommitted patch on the submodule's working tree.

**What to do next, in order:**

1. **Land the zebra-rs changes of §2.7 upstream and move the pin again.** The
   SONiC tree now passes `--claim-main-bgp`, which only a zebra-rs carrying that
   change accepts; built from the committed pin, the daemon does not start. Then
   commit the SONiC-side changes of §2.6, which are also uncommitted.
2. **Repeat the build and the VS run from committed trees only**, so the result
   no longer rests on a working-tree patch. Add the lab's checks (session state,
   APPL_DB row diff against FRR, ASIC_DB, ping, neighbor shutdown/remove/re-add,
   restart with leftovers) as the Phase 7 CI smoke test.
3. **Finish Phase 4**: port the managers bgpcfgd currently leaves out under
   zebra-rs (§2.6), device-global (TSA) first; give `managers_allow_list` a
   dialect. `sentinels` is ported; the three remaining families are read and
   each waits on a zebra-rs feature (§2.5).
4. **Start Phase 5 in parallel** — `show ip bgp summary` and every other
   `vtysh`-backed command fail on a zebra-rs box today.
5. **Close the zebra-rs feature gaps** that block families: `update-source
   <interface>` first (it unblocks `monitors` outright), then `bestpath
   peer-type multipath-relax`, `set originator-id`, `clear bgp neighbor-group`,
   `network … policy`.

**How this was established, and what it does not establish.** Statements about
zebra-rs were first checked by reading the source and the YANG at `8b59b250`, and
statements about the SONiC side by reading `zebra-rs-container` at `6dfa41ea5`.
The rigs and validators were then re-run against that zebra-rs (`live-tee.sh`,
both template validators: all pass), and the VS run of §2.7 followed. What is
still read-only evidence is marked *schema read*: §2.1 exists to say that is
weaker than a live `vtyctl apply`, and such entries need a live probe before a
template depends on them. The 50k-prefix scale figure is from August.

Line numbers into `sonic-buildimage` drift with every submodule bump. The ones in
`bgpd.main.conf.j2`, `supervisord.conf.common.j2`, `docker_init.sh` and the
`routesync.cpp` suppression path were re-checked for this revision; treat the
rest as "near here" and trust the symbol name.

---

## 0. Verdict on the strategy

`sonic-port.md` (in `sonic-buildimage`) proposes: keep SONiC's southbound stack,
teach zebra-rs to speak FPM like FRR's zebra, don't touch orchagent/SAI. **That
was the right call, and Phases 0–3 have borne it out.** `fpmsyncd` is a
protocol-agnostic TCP server that only ever sees netlink bytes, and zebra-rs's
southbound tee pattern (`CradleFib`) fit an FPM client without restructuring.

Three corrections to `sonic-port.md`, all evidence-based:

1. **"FPM like FRR" is not enough — SONiC has its own FPM dialect.** SONiC ships a
   *forked* FRR dataplane plugin, `src/sonic-frr/dplane_fpm_sonic/dplane_fpm_sonic.c`
   (3670 lines), and `fpmsyncd` parses private message types that upstream FRR's
   `dplane_fpm_nl` never sends: `RTM_NEWSRV6LOCALSID` (1000/1001),
   `RTM_NEWPICCONTEXT` (2000/2001), `RTM_NEWSRV6VPNROUTE` (3000/3001), plus
   `RTM_FPM_*` and `RTM_NEWTFILTER`-carried EVPN multihoming state
   (`src/sonic-swss/fpmsyncd/fpmlink.h`, `fpmlink.cpp`). Plain-IP parity is small
   and done; full parity is a second, much larger surface (Phase 8).

2. **The offload feedback loop is mandatory, not "later".** SONiC's default bgpd
   template emits `bgp suppress-fib-pending`
   (`dockers/docker-fpm-frr/frr/bgpd/bgpd.main.conf.j2:107`) and runs zebra with
   `--asic-offload=notify_on_offload`
   (`dockers/docker-fpm-frr/frr/supervisord/supervisord.conf.common.j2:27`).
   `fpmsyncd` sends an `RTM_NEWROUTE` *back over the same TCP socket* with
   `RTM_F_OFFLOAD` set (`RouteSync::onRouteResponse`, `routesync.cpp:3635`).
   Without the read side, BGP never un-suppresses. Done in Phase 2.

3. **The operational/CLI surface is the largest hidden cost.** `sonic-utilities`
   references `vtysh` on roughly 300 lines across 15 non-test files (about 530
   lines with tests; an earlier revision of this plan said 416, which neither
   count reproduces), all expecting FRR's JSON schemas
   (`utilities_common/bgp_util.py`, `scripts/route_check.py`,
   `scripts/fast-reboot-filter-routes.py`), and `bgpmon`
   (`src/sonic-bgpcfgd/bgpmon/bgpmon.py`) and `bgp_eoiu_marker.py`
   (`src/sonic-swss/fpmsyncd/bgp_eoiu_marker.py`) poll `show bgp summary json` /
   `show bgp neighbors <x> json` to populate STATE_DB. `sonic-port.md` does not
   mention this at all. It is its own phase and is not started.

Also: `sonic-port.md`'s milestone order puts the config bridge *after* warm
reboot. Swap them — you cannot build a realistic warm-reboot test without
CONFIG_DB-driven configuration first.

---

## 1. The integration surface

### 1.1 Southbound — FIB

```
bgpd/staticd → zebra RIB → kernel netlink  ─┐
                        └→ dplane_fpm_sonic ─┴→ TCP 2620 → fpmsyncd → APPL_DB → orchagent → ASIC_DB → syncd → SAI
```

Structural facts:

| Fact | Evidence |
|---|---|
| `fpmsyncd` is the TCP **server** (port 2620, not configurable on its side); zebra dials out | `fpmsyncd/fpmlink.h`, `fpm/fpm.h` |
| Framing = `fpm_msg_hdr_t` (version 1, type `FPM_MSG_TYPE_NETLINK`), 4-byte aligned, 16 KiB max | `fpm/fpm.h` |
| Default mode is **inline `RTA_MULTIPATH`**, not nexthop groups — `docker_init.sh` writes `no fpm use-next-hop-groups` | `dockers/docker-fpm-frr/docker_init.sh:48-49` |
| `rtm_protocol` → `rtnl_route_proto2str` → APPL_DB `protocol` field, verbatim | `routesync.cpp` |
| Nexthop-group mode writes `APP_NEXTHOP_GROUP_TABLE` keyed by NHG id | `routesync.cpp` |
| `fpmsyncd` silently drops routes whose nexthop interface is `eth0`, `docker0` or `eth1-midplane` | `routesync.cpp`; cost a day in `rig/bgp-tee.sh` |

**Wire rules read off the golden traces** (FRR 10.5.4-sonic-0). These replaced
several assumptions in the first revision of this plan; `tools/fpm-tap/README.md`
has the full table and the reasoning.

- Default-VRF routes carry `rtm_table = 0` and **no `RTA_TABLE`**. Sending
  `RT_TABLE_MAIN` (254) would be read as a VRF ifindex and fail the lookup.
- A VRF route's table field is the **VRF device ifindex, not the kernel table
  id** (`dplane_fpm_sonic.c`: "Put vrf if_index instead of table id"); `fpmsyncd`
  resolves it with `getIfName()` and rejects any name not starting with `Vrf`
  (`VRF_PREFIX`, `routesync.cpp:37`). The first revision said to emit the kernel
  table id. That was wrong.
- Protocol numbers are FRR's private ones: static is **196** (`RTPROT_ZSTATIC`),
  connected/local/kernel are **2**. APPL_DB ends up with the string `0xc4` for
  static.
- One nexthop → flat `RTA_GATEWAY` + `RTA_OIF`; two or more → `RTA_MULTIPATH`
  with `NLA_F_NESTED` set and the ifindex in the `rtnexthop` struct.
- `RTA_PRIORITY` is always present, even when 0. Adds are
  `REQUEST|REPLACE|CREATE`; deletes are `REQUEST|CREATE` with `rtm_type` 0 and no
  nexthops. `nlmsg_seq` is 0.
- Blackhole/reject go on the wire (`rtm_type` 6/7) and `fpmsyncd` then **drops**
  them — they never reach APPL_DB.

**The acknowledgement direction.** Every `RTM_NEWROUTE` is acknowledged, but
which acknowledgement depends on CONFIG_DB `DEVICE_METADATA|localhost`
`suppress-fib-pending`:

- **disabled** (default): optimistic — `fpmsyncd` echoes the route the instant it
  parses it, before APPL_DB is written (`routesync.cpp:2631`).
- **enabled**: real — the echo is skipped and the ack is synthesized later from
  orchagent's APPL_STATE_DB response, carrying only `RTA_DST` + `RTA_TABLE`.

So the only key that works in both modes is `(family, prefix, table, protocol)`;
`nlmsg_pid`/`nlmsg_seq` are 0 and correlate nothing; and **deletes are never
acknowledged** in either mode.

zebra-rs side, as built:

- `zebra-rs/src/fib/fpm/` — `client.rs` (`FpmFib`: dial, reconnect, ack reader),
  `encode.rs`, `decode.rs`, `frame.rs`, `mirror.rs` (desired state + full replay
  on reconnect). Tests assert byte-equality with the golden traces.
- Wired into `FibHandle` (`fib/netlink/handle.rs`: `set_fpm`, `fpm_tee`,
  `fpm_prepare`, `fpm_flush_vrf`) at the route add/delete/replace sites. The
  kernel install is unchanged and stays primary. The tee is independent of
  kernel-install success, matching FRR.
- Config: `system fpm { enabled; address; port }` in `yang/config.yang`, defaults
  `127.0.0.1:2620`. `SONIC_FPM=host:port` remains as a startup env fallback.
- **Not built:** NHG mode (`RTM_NEWNEXTHOP` + `RTA_NH_ID`), MPLS/SRv6/EVPN
  encodings, the SONiC private types.

### 1.2 Northbound — configuration

Two SONiC modes, both selected in `docker_init.sh`:

- **`bgpcfgd`** (default): 16 managers under `src/sonic-bgpcfgd/bgpcfgd/`
  (`managers_bgp`, `managers_rm`, `managers_prefix_list`, `managers_allow_list`,
  `managers_bfd`, `managers_static_rt`, `managers_srv6`, `managers_device_global`,
  `managers_bbr`, `managers_aggregate_address`, `managers_as_path`,
  `managers_advertise_rt`, `managers_setsrc`, `managers_intf`,
  `managers_chassis_app_db`, `managers_db`). They watch CONFIG_DB, render Jinja
  templates, and push text through **`vtysh -f <tmpfile>`**
  (`src/sonic-bgpcfgd/bgpcfgd/frr.py`). Initial config comes from `sonic-cfggen`
  rendering `dockers/docker-fpm-frr/frr/**` into `/etc/frr/*.conf`.
- **`frrcfgd`** (`src/sonic-frr-mgmt-framework/`) when
  `DEVICE_METADATA.localhost.frr_mgmt_framework_config == "true"`.

zebra-rs equivalent:

- Startup: `--config-file` accepts CLI brace, JSON, YAML, or `set`/`delete`
  lines. The container renders **`set` lines** (`zebra-rs.conf.j2`).
- Runtime: `vtyctl apply -f file` over the gRPC VTY socket, with candidate/commit
  semantics. Two properties of it shape everything in Phase 4:
  - **`vtyctl apply` exits 0 when the daemon rejects a line**, printing
    `error reply: <line>`. Check the marker, never the exit code.
  - **A commit is atomic**, so one bad line discards the batch.
- Schema is YANG (100 modules under `zebra-rs/yang/`), so config is validated,
  not string-matched.

### 1.3 Operational — CLI, JSON, telemetry

- Host `vtysh` is a shim: `docker exec -ti bgp$DEV vtysh "$@"`
  (`dockers/docker-fpm-frr/base_image_files/vtysh`), installed via
  `$(DOCKER_FPM_FRR)_BASE_IMAGE_FILES` (also `rvtysh`, `TSA/TSB/TSC/TS`,
  `idf_isolation`, `prefix_list`). `rules/docker-fpm-zebra-rs.mk` sets no
  `_BASE_IMAGE_FILES` yet, so on a zebra-rs image the host has no `vtysh` at all.
- Consumers: `sonic-utilities`, `bgpmon` → STATE_DB `BGP_NEIGHBOR` table,
  `bfdmon`, `bgp_eoiu_marker.py`, `route_check.py`,
  `fast-reboot-filter-routes.py`, plus `bgpcfgd` itself (`show daemons`,
  `show running-config`, `clear bgp peer-group … soft in`,
  `show bgp peer-group … json`, `show bfd peers json`).
- zebra-rs has a rich `show` tree with `--json` — but the **JSON schema is
  zebra-rs's own, not FRR's**. This is a translation problem, not a
  missing-feature problem. No FRR-compatibility code exists in `vtyctl` today.

### 1.4 Lifecycle

- Warm restart: `fpmsyncd` runs a `WarmStartHelper`, defers deletes, and waits for
  BGP EOIU flags in STATE_DB (`fpmsyncd.cpp`) that `bgp_eoiu_marker.py` sets by
  polling FRR JSON.
- FRR-side: `bgp graceful-restart` + `restart-time` + `preserve-fw-state` +
  `select-defer-time` (`bgpd.main.conf.j2:119-122`),
  `graceful-restart-disable` + `long-lived-graceful-restart stale-time` for
  `UpperRegionalHub` (`:125-126`).
- Container ordering: warm and fast shutdown `before swss`, `after radv` — set
  identically in `rules/docker-fpm-zebra-rs.mk`.
- TSA/TSB route through CONFIG_DB (`BGP_DEVICE_GLOBAL.STATE.tsa_enabled`) →
  `managers_device_global`, so they follow the config bridge rather than needing
  their own port.

### 1.5 Build & packaging

- The slave has a Rust toolchain: `sonic-slave-trixie/Dockerfile.j2:793-833`,
  rustup **1.86.0**, cross targets for `armv7`/`aarch64`, a `cargo-auditable`
  wrapper, `rust-audit-info` for SBOM.
- **1.86.0 is not enough**, and neither is the slave's `cargo-auditable`. The
  first revision reasoned "edition 2024 needs ≥1.85, so 1.86 is fine". Run on the
  slave, cargo refuses before compiling a line of zebra-rs: `tonic`, `time`,
  `sha2`, `encoding_rs` and others in the dependency graph require 1.88, as do
  zebra-rs's own `let` chains. And the slave's `/usr/local/bin/cargo` wrapper
  routes every `cargo build` through `cargo-auditable` 0.6.4, which panics on an
  edition-2024 manifest (``unknown variant `2024` ``). The slave now carries a
  second pinned toolchain (1.97.0) and `cargo-auditable` 0.7.7 under
  `/usr/.cargo-zebra-rs`, used only by `src/sonic-zebra-rs/Makefile`; the binary
  still carries the `.dep-v0` section and `rust-audit-info` reads it.
- Precedents for Rust `.deb`s in-tree: `src/sonic-dash-ha` (`rules/dash-ha.mk`),
  `src/sonic-nettools`, `src/sonic-ctrmgrd-rs`,
  `src/sonic-supervisord-utilities-rs`.
- `cargo-deb` is not on the slave, so `src/sonic-zebra-rs/Makefile` assembles the
  tree by hand and seals it with `dpkg-deb`: `zebra-rs`, `vtyctl`, `vtyhelper`,
  the YANG under `/usr/share/zebra-rs/yang/`, and a placeholder
  `/etc/zebra-rs/zebra-rs.conf`.
- zebra-rs gitignores `Cargo.lock`, so `src/sonic-zebra-rs/Cargo.lock` is what
  pins the dependency graph for a given SONiC commit.

---

## 2. Gap analysis — zebra-rs vs what SONiC's templates ask for

The live list, with what was tried for each item, is `bgp-sonic-gaps.md` in this
directory. This section is the plan-level summary. Where the two disagree,
whichever was touched more recently is right, and the other needs fixing —
`bgp-sonic-gaps.md` currently still lists `maximum-prefix` as absent, which it no
longer is.

**Present in zebra-rs** (config surface verified live in August unless noted):
peer-groups as `neighbor-group`, `allowas-in`, `route-reflector-client`,
`next-hop-self`, per-neighbor and instance-level graceful restart + LLGR,
add-path on neighbors and neighbor-groups, `maximum-paths` and
`bestpath as-path multipath-relax` (`zebra-bgp-multipath.yang`),
`suppress-fib-pending`, `maximum-prefix` (*schema read*), `update-source` by
address, `ebgp-multihop`, dynamic neighbors / listen-range, `table-map`,
redistribute + policy, the policy engine — prefix-set, as-path-set, community /
large-community / ext-community, `call`, `set tag` / `match tag`,
`action next` — `advertise-all-vni`, BFD, MD5/TCP-AO, VRF/L3VPN, SRv6, EVPN,
IS-IS, OSPF.

### 2.1 Method — how these are established

The first revision listed `soft-reconfiguration`, `add-path` and `maximum-paths`
as present on the strength of grepping `src/bgp/` and the vendored YANG. All three
were wrong in the same direction. **A string in the source, or a grouping in
vendored YANG, is not a config surface** — only a live `vtyctl apply` that is not
rejected proves that, and only a live measurement proves the behaviour behind it.

`soft-reconfiguration` is the standing example, and it is still true today:
`bgp/config.rs` registers a `/soft-reconfiguration/inbound` callback and its
comment names `zebra-bgp-soft-reconfiguration.yang`, but no such module exists
under `yang/`, so the leaf cannot be set.

The traps, all now guarded against by `validate-templates.sh` and
`validate-instance-template.sh` in `dockers/docker-fpm-zebra-rs/`:

- **`vtyctl apply` exits 0 on rejection.** Grep for `error reply:`.
- **A batch probe blames the wrong line.** Probe one construct per commit, on a
  known-good preamble.
- **A rejected probe means "not with that syntax".** `on-match next` is
  `action next`; `peer-as` is `remote-as`.
- **Neighbor and neighbor-group are different surfaces.** Inheritance is
  implemented knob by knob; for a listen-range group only the group form counts.
- **One leaf per line.** `prefix-set X prefixes P ge 31 le 31` is rejected; two
  lines are accepted.
- **A refusal reports only the first bad line.** Count refusals in the rendered
  text.

### 2.2 Infrastructure gaps

| Gap | Where SONiC needs it | Phase | State |
|---|---|---|---|
| FPM client / encoder | everything | 1 | **done** |
| FPM nexthop-group mode | only if `fpm use-next-hop-groups` is turned on | 1 | open, optional; golden trace captured (`basic-nhg.fpm`) |
| Offload-ack ingest + route `offloaded` state | `suppress-fib-pending` | 2 | **done** |
| `suppress-fib-pending` gate | `bgpd.main.conf.j2:107` | 2 | **done** (`bgp-suppress-fib-pending.md`) |
| `bestpath as-path multipath-relax` | `bgpd.main.conf.j2:115` | 4 | **done** (`bgp-multipath.md`) |
| `aggregate-address` | `managers_aggregate_address` | 4 | open — no BGP aggregate in the schema (*schema read*) |
| FRR-schema JSON emulation | every `vtysh … json` consumer | 5 | not started |
| EOIU / end-of-RIB signalling to STATE_DB | warm reboot | 6 | not started |
| Restarting-speaker GR (`select-defer-time`) | warm reboot | 6 | open — see §2.4 |
| BMP client | `bgpd.main.conf.j2:129-140`, `docker-sonic-bmp` | 8 | open (optional) |
| SONiC private FPM types | SRv6/EVPN features | 8 | not started; decoder in `fpm-tap` already names them |

### 2.3 BGP config gaps blocking Phase 4 template families

| Gap | Blocks | State |
|---|---|---|
| `send-community` | `monitors`, `internal`, `voq_chassis` | **not a gap.** Measured on VS: a community set by a zebra-rs egress policy reached the FRR eBGP peer with nothing configured. zebra-rs always sends, so the FRR line is dropped by the template with that stated. Extended/large communities and iBGP not measured. |
| `update-source <interface>` | `monitors` | open. The leaf is a union of IPv4/IPv6 address only. SONiC uses the interface form so the source follows the loopback. |
| `soft-reconfiguration inbound` | `general`, `sentinels`, `dynamic` | open, and **silently dropped** rather than refused. The assumption that zebra-rs's own soft-reset handling makes this a no-op is untested. |
| per-neighbour `keepalive` | any tuned timer | open, silently degraded. Only `connect-retry-time` and `hold-time` exist; bgpcfgd's own `timers_1` fixture sets keepalive 5 with a default hold time, which ports to 60. |
| `set ipv6 next-hop prefer-global` | `general` policy | open, silently degraded. |
| `clear bgp peer-group <pg> soft in` | BBR manager | open. `clear bgp` takes a neighbor or `all`. The backend refuses rather than widening to `clear bgp all` — soft-clearing every session because one group changed is an availability event. |

**Closed:**

| Gap | Note |
|---|---|
| `maximum-prefix` | Implemented on neighbors and neighbor-groups, IPv4/IPv6 unicast, with `limit`, `warning-threshold`, `warning-only`, `force`, `restart`; teardown is Cease/Maximum Number of Prefixes Reached. Landed after the pinned SHA, so the SONiC templates still refuse it. Three limits to carry into the port: a **VRF neighbor has no such block**; above `rib-sharding 1` the IPv4 check lags the shards, so more than the limit can be accepted before teardown; and the monitors use is `maximum-prefix 1` as a tripwire, which should be measured, not assumed. |
| `call` (policy chaining) | No depth limit, exact cycle detection (`policy-call.md`). Needed because `managers_allow_list.py` owns the callee at runtime. |
| `set tag` / `match tag` | SONiC stamps on ingress, matches on egress. |
| `add-path` on a neighbor-group | Load-bearing: the sentinels group is a listen range, so no per-neighbor statement exists to carry the capability. |
| `on-match next` | Was never missing — it is `action next`. |

**Verified-config, unverified-behaviour** — the class most likely to bite, because
nothing errors:

- **RFC 7911 `send` vs FRR `addpath-tx-all-paths`.** `send` says the capability is
  advertised, not which paths are selected. The sentinel wants *all* paths. If
  zebra-rs sends only the bestpath, the config commits, the capability
  negotiates, and the sentinel quietly sees less than it asked for. Needs a live
  two-path session and a count of what crosses the wire. Still unmeasured.

### 2.4 Instance-level gaps — every device, not just a role

Found porting `bgpd.main.conf.j2`.

| Gap | State |
|---|---|
| BGP multipath / `maximum-paths` | **closed.** Was an absent capability, not a missing leaf. |
| `suppress-fib-pending` | **closed.** Withdrawals are never suppressed; a lost ack releases on a timeout. |
| global graceful restart | **closed** for `enabled`, `restart-time`, `preserve-fw-state`, `disable`, LLGR `stale-time`. |
| `select-defer-time` | **open — the last refusal on a stock T0.** Not a leaf: zebra-rs implements the GR helper role only, so there is no restart deferral for the timer to govern. Needs restarting-speaker behaviour (defer best-path and FIB install until End-of-RIB from every GR peer, or the timer). Phase 6, and to be tested together with `suppress-fib-pending`, since during a restart every prefix is briefly pending. |
| `network <prefix> route-map <rm>` | open. `network` takes no policy. SONiC uses it to attach `no-export` to an internal loopback, so degrading would leak an internal prefix. Refused. |
| `confederation identifier` / `peers` | open. Disaggregated T2 / Regional Hub. |
| `coalesce-time`, `log-neighbor-changes` | open. Dualtor tuning; cosmetic. |

Deliberately *not* gaps: `no bgp default ipv4-unicast` and
`no bgp ebgp-requires-policy` turn off FRR behaviours zebra-rs does not have.

### 2.5 Phase 4 template families

| Family | State |
|---|---|
| global instance (`zebra-rs.conf.j2`) | **ported**; refuses `select-defer-time`, `network … route-map`, confederation |
| `general` | **ported**, all fixtures accepted by a live daemon |
| `dynamic` (BGP_SPEAKER) | **ported** |
| `sentinels` | **ported**, all fixtures accepted by a live daemon, and `BGP_SENTINELS` is driven by bgpcfgd. Drops `soft-reconfiguration`; `add-path send` vs tx-all-paths still unmeasured (§2.3). FRR's two-community `community-list` entry means *both*; a zebra-rs community-set matches *any*, so the conjunction is spelled out with `call`. |
| `monitors` | blocked: `update-source <interface>` only (`send-community` turned out not to be a gap, §2.3) |
| `internal` | **read; blocked.** Multi-ASIC only. Needs `set originator-id` (no such policy action — *schema read*) and `update-source Loopback4096` (interface form). Its `timers 3 10` ports exactly. Present: `set tag`, `set local-preference`, `set community … delete`, `ttl-security`, `allowas-in`, route-reflector client, `next-hop-self` (whether it has FRR's `force` meaning is unchecked). |
| `voq_chassis` | **read; blocked** — on a closer read than the first pass, which called it portable. It needs `bgp bestpath peer-type multipath-relax` (ECMP across eBGP and iBGP paths; no such leaf — *schema read*), which is forwarding behaviour and so refused rather than dropped. What does port: `timers 2 7` exactly (zebra-rs derives keepalive as hold/3), per-neighbor default shutdown, `maximum-paths ibgp` as `maximum-paths-ibgp`, and the policy half, which is `internal`'s under other names. `addpath-tx-all-paths` again. |

`managers_allow_list.py` is **not ported**: it emits FRR syntax and parses FRR's
running-config to allocate sequence numbers, so it needs a dialect abstraction.
The `general` template lays down the static half of the allow-list chain, which
makes that half correct but does not make the feature work.

### 2.6 SONiC-side integration debt

Found by the audit and by the first real runs. The first block is fixed in the
`zebra-rs-container` working tree (uncommitted as of this revision); the second
is still open.

| Fixed | Detail |
|---|---|
| Slave toolchain too old | Second pinned toolchain + `cargo-auditable` in `sonic-slave-trixie/Dockerfile.j2`, selected in `src/sonic-zebra-rs/Makefile` (§1.5). |
| Submodule pin stale | Moved from `88f59938` (2026-08-09, 1126 commits behind) to `8b59b250`; `.gitmodules` now tracks `main`; `ZEBRA_RS_VERSION` 26.11.4; `Cargo.lock` regenerated. |
| Image build never ran | It failed on its first run: the container's `.dockerignore` excluded `buildinfo`, which every SONiC docker build copies in. Now `Dockerfile.j2` only, as in `docker-fpm-frr`. |
| bgpcfgd backend not wired | `bgpcfgd/dialect.py` reads `SONIC_ROUTING_STACK` from bgpcfgd's environment; the container's supervisord runs bgpcfgd with it set; `main.py` and `managers_bgp.py` branch on it. The wheel is now an image dependency. |
| A commit always "failed" | `ConfigMgr.commit()` calls `restart_peer_groups()` on every commit; the zebra-rs backend returned failure for the empty list. |
| Pushes were not idempotent | bgpcfgd re-pushes a peer-group's policy for every peer. A leaf-list `set` appends in zebra-rs, so a stock T1 ended up with 32 copies of each community-set member. The backend now drops `set` lines the running config already has. The underlying zebra-rs behaviour is unchanged and deliberate (a leaf-list doubles as an ordered sequence, e.g. a label stack), so anything else that pushes config must do the same. |

| Open | Detail |
|---|---|
| **Managers left out under zebra-rs** | Only `BGP_NEIGHBOR` (`general`), `BGP_PEER_RANGE` (`dynamic`) and `BGP_SENTINELS` are driven. Ignored, with one warning at start: internal, monitors, voq_chassis, allow-list, BBR, static routes, advertise-network, BGP profiles, device-global (**TSA, WCMP, IDF isolation**), aggregate-address, SRv6, prefix-list, software BFD, set-src. A box with TSA enabled in CONFIG_DB is **not** isolated. |
| No route source address | FRR's set-src route-map gives BGP routes `src <Loopback0>` in the kernel; zebra-rs installs them without. Locally originated traffic to BGP destinations uses the egress interface address. |
| Kernel routes carry `onlink` | zebra-rs installs BGP nexthops `onlink`; FRR does not. No effect seen; recorded because it is a visible diff. |
| VRF peers | The zebra-rs branches of `managers_bgp.py` refuse a non-default VRF. |
| `dynamic` range update | `get_existing_ip_ranges` still shells out to `vtysh`, so changing a BGP_PEER_RANGE's `ip_range` in place does not work. (Deleting one does: the listen-range families now delete the neighbor-group, not a neighbor of that name.) Neither `dynamic` nor `sentinels` has been exercised on VS — template acceptance only. |
| Stale APPL_DB rows across a stack swap | Rows written under one stack and not re-announced by the next stay in APPL_DB until an `fpmsyncd` restart replays into a clean table. Belongs to Phase 6 reconciliation. |
| No host-side files | No `_BASE_IMAGE_FILES`, so no host `vtysh`, `TSA`/`TSB`/`TSC`. |
| Flag naming | The selector is `SONIC_ROUTING_STACK = zebra-rs`; there is no `INCLUDE_ZEBRA_RS`. |

### 2.7 What the VS run found in zebra-rs

Three defects, each invisible to every rig and validator, each found by doing on
a real SONiC what an operator does. All three are fixed in this tree; none is in
the pinned SHA yet.

| Finding | Fix |
|---|---|
| **Loopback and link-local routes reached the ASIC.** zebra-rs teed `127.0.0.0/16`, `::1` and `fe80::/64` as connected routes; SONiC's FRR never sends them. Seen as three extra APPL_DB rows against the FRR baseline. | `fib::fpm::is_fpm_prefix` gates them out of the tee. After a replay APPL_DB holds exactly the FRR baseline's 34 rows. |
| **A restart froze the previous instance's BGP routes in place.** The bgp container shares the host namespace, so a restart finds the old `proto bgp` routes in the kernel. Main-table BGP leftovers were deliberately not claimed (another bgpd might own them), so they came back as distance-0 kernel routes that outranked the BGP routes learned again. Nothing about those prefixes was ever re-sent over FPM: a removed neighbor's next hop stayed in the kernel and in APPL_DB. | `--claim-main-bgp`, off by default, passed by the container's supervisord. Main-table BGP leftovers are then treated like every other leftover: replaced by the fresh route, swept after `--leftover-sweep-time`. |
| **`config bgp shutdown neighbor` did nothing.** The template maps it to `neighbor X enabled false`. That leaf was in the schema, documented as accepted and inert, and listed as a known orphan — so the commit succeeded and the session stayed up. Exactly the §2.1 trap, in the one place it had been written down as harmless. | `enabled false` is now administrative shutdown: the session ends, the peer rests in Idle (shown as `Idle (Admin)`), is not dialed, and its inbound connections are dropped. `true` remains a no-op. |

What the run confirmed without change: sessions from CONFIG_DB, ECMP, the
offload acknowledgement end to end against a real orchagent and the VS SAI,
neighbor remove and re-add at runtime, `fpmsyncd` restart replay, and an IPv6
eBGP session (`PEER_V6`) with its route in APPL_DB, ASIC_DB and forwarding.

All of it was repeated on the image that `make target/docker-fpm-zebra-rs.gz`
produces — slave-built `.deb`, bgpcfgd wheel (its 646 tests pass in the slave)
— and the first-boot checks again on the full `sonic-vs.img.gz` built with
`SONIC_ROUTING_STACK = zebra-rs`. Both carried the zebra-rs changes above as a
patch on the submodule's working tree, since they are not upstream yet.

Two things the full build turned up that are not about zebra-rs but will stop
the next person: `SONIC_ROUTING_STACK` on the `make` command line does not reach
the slave, so it has to go in `rules/config.user`; and a cached
`*__rfs.squashfs` from an earlier build carries that build's DNS server, so the
image stage fails with "Temporary failure resolving" after a network change
until the squashfs is removed and regenerated.

And one that is: on a zebra-rs image `show ip bgp summary` answers `No such
command 'bgp'` — sonic-utilities loads its BGP commands per routing stack.
Phase 5 starts there.

One behavioural difference found and **left as it is**, because it is a
deliberate zebra-rs default and the right value for SONiC is a decision, not a
fix:

- **A new neighbor waits up to a minute before its first dial, and refuses the
  peer's dials meanwhile.** For a peer whose index is above 10 the first
  idle-hold is random in 5–60 s (start-up jitter, `bgp/timer.rs`), and a peer
  in Idle drops inbound connections. A stock T1 has 32 neighbors, so most are in
  that band. Captured on the wire: FRR dialled every 10 s and was reset four
  times; zebra-rs dialled at 37 s and the session came up at once. FRR starts a
  new peer in about a second. The per-neighbor `timers idle-hold-time` leaf
  overrides the jitter, so the template can set it, but that value also governs
  the hold after a failure, where FRR backs off exponentially instead.

Not exercised: anything in the "left out" row of §2.6, VRFs, warm or fast
reboot, and every `vtysh`-backed command.

---

## 3. Phases

Phases 1–3 were the risky, load-bearing part and are done. 4–7 are volume work;
8–9 are scope-expansion and rollout.

---

### Phase 0 — Groundwork and harness — DONE

Delivered as `tools/fpm-tap` (`record`, `replay`, `decode`, `stats`) plus the rigs
under `tools/fpm-tap/rig/`:

- `capture.sh`, `capture-offload.sh` — run the real `docker-fpm-frr` image and
  record both directions; `fake-orchagent.py` stands in for orchagent.
- Golden traces in `tools/fpm-tap/golden/`: `basic`, `basic-nhg`, `vrf`,
  `offload`, `offload-optimistic`.
- `ab-diff.sh` — replays FRR's bytes and zebra-rs's into the same real
  `fpmsyncd` and diffs APPL_DB. This is the acceptance test the plan asked for.

Carried forward:

1. **Captures of BGP-learned routes from FRR and of the private types do not
   exist.** The README's "Not yet captured" list still names VRF, which *is*
   captured; fix the README when next touching it.
2. **Re-record on every SONiC FRR bump.** The traces are from FRR 10.5.4-sonic-0.
   `dplane_fpm_sonic` moves with FRR; a re-capture and diff is the only way to
   see the dialect change.

---

### Phase 1 — FPM client tee in zebra-rs — DONE (NHG mode open)

Delivered: `zebra-rs/src/fib/fpm/`, wired into `FibHandle`, configured by
`system fpm`. Verified by byte-equality against the golden traces, the APPL_DB
A/B diff, a live tee against a real `fpmsyncd` (`live-tee.sh`), real eBGP
(`bgp-tee.sh`), ECMP (`multipath-tee.sh`), reconnect replay into a wiped APPL_DB,
and 50k prefixes (`scale-tee.sh`: all in APPL_DB in ~7s, ~111 MiB RSS, full replay
after an `fpmsyncd` restart in ~7s).

Remaining:

1. **NHG mode** — `RTM_NEWNEXTHOP`/`RTM_DELNEXTHOP` + `RTA_NH_ID` behind a
   `system fpm use-next-hop-groups` leaf. SONiC's default is off, so this is not
   on the critical path; do it when a platform that turns it on is in scope. Keep
   it independent of the kernel-side `--no-nhid` choice.
2. **Scale beyond 50k** belongs to Phase 9, but note the 50k run used loopback
   nexthops that the kernel refuses, so it measured the tee and not the kernel
   path.

---

### Phase 2 — Offload feedback and FIB-pending suppression — DONE

Delivered: ack parsing on the FPM socket (`fpm/decode.rs`, keyed on
`(family, prefix, table, protocol)`), `RibEntry.offloaded` shown in `show ip route`,
`RibRx::RouteOffload` delivered to BGP only, and the `suppress-fib-pending` gate
(`zebra-bgp-suppress-fib-pending.yang`, `bgp-suppress-fib-pending.md`), including
the sharded-RIB and AddPath paths. End-to-end rig:
`suppress-fib-pending-tee.sh`.

Carried forward:

1. **The two ack modes must agree with the template.** `fpmsyncd` chooses
   optimistic vs real acks from CONFIG_DB
   `DEVICE_METADATA|localhost|suppress-fib-pending`. The zebra-rs template must
   emit `suppress-fib-pending` under the same condition FRR's does, or BGP waits
   on real acks while `fpmsyncd` sends optimistic ones (harmless) or the reverse
   (advertises before the ASIC is programmed).
2. **Restart interaction** — during a restart every prefix is briefly pending.
   Test with Phase 6's restarting-speaker work, not separately.

---

### Phase 3 — `docker-fpm-zebra-rs` container on VS — DONE

Delivered in `sonic-buildimage`: `dockers/docker-fpm-zebra-rs/` (Dockerfile,
`docker_init.sh` with the default-gateway demotion carried over verbatim,
supervisord with `zebra-rs` + `fpmsyncd`), `rules/zebra-rs.mk`,
`rules/docker-fpm-zebra-rs.mk`, and selection through `SONIC_ROUTING_STACK` in
`rules/docker-fpm.mk`. Same container name (`bgp`) and service slot as
`docker-fpm-frr`. Recorded in August as booting on VS and running eBGP.

Carried forward: the image was assembled and validated directly, not through the
slave's `make`. That is Phase 7 step 1 and is now the first thing to do.

---

### Phase 4 — Config bridge (CONFIG_DB → zebra-rs) — IN PROGRESS

Goal: SONiC's existing CONFIG_DB semantics drive zebra-rs, with no change to
CONFIG_DB schema or to how operators configure the box.

Approach, unchanged: **keep bgpcfgd's architecture, swap its backend and its
templates.**

Done: `bgpcfgd/zebra_rs.py` (the backend, with tests); the global instance
template; the `general` and `dynamic` families; the two validation scripts.

A decision that went differently from the first revision: it recommended emitting
YAML/JSON for the startup config. The port emits **`set` lines**, and that should
stay — the runtime path through `vtyctl apply` is `set`/`delete` lines too, so one
dialect serves both startup and runtime templates, and the refusal mechanism (an
`UNSUPPORTED-` token that is deliberately invalid config) depends on it.

Remaining, in order:

1. **Wire the backend — done for `general` and `dynamic`** (§2.6). A neighbor
   shutdown / startup / remove / re-add cycle through CONFIG_DB works on VS. What
   it showed about the "no FRR-style diffing needed" claim: true for scalar
   leaves, false for leaf-lists, hence the backend's filter against the running
   config. Next here is porting the managers still left out, device-global (TSA)
   first, since leaving it out is the one omission that is unsafe rather than
   merely missing.
2. **`sentinels` — done** (§2.5), including `maximum-prefix`.
3. **`voq_chassis`, `internal`, `monitors`** — each waits on one or two
   zebra-rs features: `update-source <interface>` (`internal`, `monitors`),
   `set originator-id` (`internal`), `bestpath peer-type multipath-relax`
   (`voq_chassis`). `update-source <interface>` unblocks the most, and
   `monitors` outright.
5. **`managers_allow_list` dialect abstraction.** It both emits FRR syntax and
   parses FRR running-config for sequence numbers. With `call` in place the
   zebra-rs side can own a separate policy per allow-list and skip sequence
   allocation; design that before writing it.
6. **Remaining managers**, each with unit tests under `src/sonic-bgpcfgd/tests/`:
   `managers_prefix_list`, `managers_rm`, `managers_as_path`, `managers_static_rt`
   (replaces staticd), `managers_bfd` (native BFD — this gets simpler),
   `managers_device_global` (TSA/TSB, WCMP, IDF isolation), `managers_bbr` (needs
   `clear bgp neighbor-group`), `managers_aggregate_address` (needs BGP
   `aggregate-address`), `managers_advertise_rt`, `managers_setsrc`,
   `managers_intf`, `managers_srv6`, `managers_chassis_app_db`.
7. **Retire the silently-degraded list** (§2.3) with measurements:
   `soft-reconfiguration`, `keepalive`, `prefer-global`, add-path tx-all-paths.
8. **`frrcfgd`**: do not port. `docker_init.sh` should fail loudly when
   `frr_mgmt_framework_config == "true"`; check that it does.
9. **Golden-config tests**: for each CONFIG_DB fixture in
   `src/sonic-bgpcfgd/tests/data/`, assert the generated config commits cleanly
   and yields the intended running config.

**Exit:** a stock `config_db.json` for T0 and T1 roles boots the zebra-rs
container to the same protocol state as FRR, with no manual steps and no refusal
— which requires `select-defer-time` to be either implemented or consciously
waived for the exit.

---

### Phase 5 — Operational compatibility (`vtysh`, JSON, telemetry) — NOT STARTED

Goal: `show ip bgp summary`, `show ip route`, `bgpmon`, and `route_check` keep
working — for operators, tooling, and every existing sonic-mgmt test.

1. **Inventory and classify** the `vtysh` call sites (15 non-test files in
   `sonic-utilities`, plus `bgpmon`, `bfdmon`, `bgp_eoiu_marker.py`, bgpcfgd).
   Three buckets: (a) `show … json` consumed programmatically — must be
   schema-exact; (b) `show …` human text — must be reasonable, not identical;
   (c) config/clear commands — route to `vtyctl`. Do the inventory first; the
   count in earlier revisions was not reproducible and the estimate hangs on it.
2. **Build a `vtysh` compatibility shim** in the container: accepts FRR's argv
   (`-c`, `-f`, `-H`, `-n`), translates the FRR command string to the zebra-rs
   `show`/`apply` path, and for `json` forms **re-shapes zebra-rs JSON into FRR's
   schema**. Implement it in Rust next to `vtyctl` so the schema mapping is
   type-checked. `docker exec` needs no special handling since D30.
3. **Priority order for JSON schemas:**
   `show bgp summary json` and `show bgp vrf <v> summary json` (bgpmon, `show ip bgp summary`),
   `show ip route json` / `show ipv6 route json` (`route_check.py`),
   `show ip route connected json` (`fast-reboot-filter-routes.py`),
   `show bgp neighbors <ip> json` (EOIU marker),
   `show bfd peers json` (`bfdmon`, `managers_bfd`),
   `show bgp peer-group <pg> json` (`managers_bgp`),
   `show daemons` / `show running-config` (bgpcfgd startup).
   `route_check.py` compares against APPL_DB and will see the `offloaded` state;
   map it onto FRR's `offloaded` field.
4. **Contract tests**: capture FRR JSON on VS for each command, and run the
   shim's output through the real consumer code
   (`bgp_util.process_bgp_summary_json`, `route_check.py`'s parser). Reuse
   `src/sonic-utilities/tests/bgp_commands_test.py` fixtures as the oracle.
5. **Host-side files**: ship `vtysh`, `rvtysh`, `TSA/TSB/TSC/TS`,
   `idf_isolation`, `prefix_list` via `$(DOCKER_FPM_ZEBRA_RS)_BASE_IMAGE_FILES`.
6. **Native path, longer term**: new SONiC code should use zebra-rs's gRPC/JSON
   or MCP server (`vtyctl/src/mcp/`) directly. The shim is compatibility, not
   architecture.

**Exit:** `show ip bgp summary`, `show ip route`, `show bfd peers`, `bgpmon`
STATE_DB population, and `route_check.py` all pass on VS against zebra-rs.

---

### Phase 6 — Lifecycle: warm reboot, fast reboot, GR, TSA — MOSTLY OPEN

Done: shutdown ordering in `rules/docker-fpm-zebra-rs.mk`; the helper-side GR
knobs and `preserve-fw-state`.

1. **Restarting-speaker graceful restart** — the substantive item. Defer
   best-path selection and FIB install after a restart until End-of-RIB from
   every GR-capable peer or `select-defer-time`. `preserve-fw-state` is already
   advertised when configured; claiming it while forwarding does *not* survive
   blackholes traffic for the whole restart window, so the FIB-preservation half
   (do not flush kernel and FPM state on start, reconcile instead) has to land
   with it. The IS-IS and OSPF restarter designs in this directory are prior art
   for the shape.
2. **EOIU signalling**: `bgp_eoiu_marker.py` polls FRR JSON to write
   `BGP_STATE_TABLE|IPv4|eoiu`, which `fpmsyncd` waits on. Options — (a) let the
   Phase-5 shim satisfy the existing script, or (b) have zebra-rs write the flags
   natively. **(a) first** (zero new coupling), (b) later as cleanup.
3. **FIB reconciliation**: on warm start the FPM mirror must re-send the full RIB
   so `WarmStartHelper` can reconcile and delete stale APPL_DB rows. The
   reconnect replay already does the send; what is untested is the
   "route disappeared during downtime" case.
4. **Config persistence across restart**: `/etc/zebra-rs/zebra-rs.conf` is
   re-rendered by `docker_init.sh`; confirm runtime changes made through bgpcfgd
   are replayed by bgpcfgd on start rather than expected to persist.
5. **Fast reboot**: `fast-reboot-filter-routes.py` path (needs
   `show ip route connected json`).
6. **TSA/TSB/TSC** via CONFIG_DB; confirm route-map application and withdrawal.

**Exit:** warm reboot on VS with zebra-rs shows no dataplane loss and clean
APPL_DB reconciliation; fast reboot and TSA/TSB behave as with FRR.

---

### Phase 7 — Build, packaging, CI — STEPS 1–3 DONE

Done: submodule at `src/sonic-zebra-rs/zebra-rs`, hand-assembled `.deb`
(`src/sonic-zebra-rs/Makefile`), `rules/zebra-rs.mk`, pinned `Cargo.lock`,
`SONIC_ROUTING_STACK` selection.

1. **Toolchain — done** as recommended: a second pinned toolchain and its own
   `cargo-auditable` on the slave, selected by `RUSTUP_TOOLCHAIN` and by path in
   `src/sonic-zebra-rs/Makefile` (§1.5). Not `cargo +<version>`: the slave's
   cargo wrapper dispatches on its first argument. Still to do: add
   `rust-version` to zebra-rs's workspace `Cargo.toml` so an old toolchain fails
   with one clear line, and raise the slave default upstream as the end state.
2. **Move the pin — done** to `8b59b250`; both template validators pass against
   it. It has to move once more, to a SHA carrying §2.7.
3. **Run the full build — done once**, on a working-tree patch:
   `SONIC_ROUTING_STACK = zebra-rs` in `rules/config.user`, then
   `make target/sonic-vs.img.gz`. The image boots and passes the §2.7 checks.
   Still owed: the same from committed trees, and a default (`frr`) build to
   show it is unchanged — the slave image and `sonic-bgpcfgd` are shared, and
   only bgpcfgd's own tests (646 pass) have covered the FRR path so far.
4. **`-dbgsym` derived package** via `add_derived_package`. The Makefile strips
   and discards symbols today.
5. **File capabilities**: `zebra-rs` wants `cap_net_admin`, `cap_net_raw`,
   `cap_net_bind_service`, `cap_net_broadcast`. `dpkg-deb` on a hand-built tree
   does not carry file caps; confirm the container's root + `--cap-add` is what
   is actually relied on.
6. **Multi-arch**: `arm64`, `armhf` using the slave's cross targets. Any second
   toolchain needs those targets added too.
7. **SBOM**: verify `rust-audit-info` reads the binary so
   `scripts/sbom_fragment.py` produces a fragment.
8. **Versioning/buildinfo**: `versions-*` entries under the docker's `buildinfo/`.
9. **CI**: a VS pipeline stage that builds the zebra-rs image and runs the
   Phase 3/5 smoke tests. Add a job on the zebra-rs side that builds with the
   slave's toolchain version, so the next language feature does not break the
   SONiC build silently.

**Exit:** the full build with `SONIC_ROUTING_STACK=zebra-rs` is clean from scratch
on all three arches; default builds unchanged.

---

### Phase 8 — Advanced features (only where SONiC already has orch support)

Order by SONiC demand, not by protocol elegance. Each item is independently
shippable.

1. **VRF / L3VPN**: the FPM encoding is done (device ifindex, `Vrf*` naming);
   what remains is `managers_bgp` VRF keys and the templates. Note
   `maximum-prefix` does not exist on a VRF neighbor.
2. **SRv6**: SONiC's private FPM types — `RTM_NEWSRV6LOCALSID`/`DEL` (1000/1001),
   `RTM_NEWSRV6VPNROUTE` (3000/3001), `RTM_NEWPICCONTEXT` (2000/2001). zebra-rs
   has the SRv6 RIB; this is encoding work, and it needs golden captures first.
3. **EVPN**: VXLAN/Type-2/Type-3 via `fpmsyncd`'s VXLAN paths; EVPN multihoming
   via `RTM_FPM_*` and `RTM_NEWTFILTER`.
4. **BMP**: a BMP client in zebra-rs if `docker-sonic-bmp` is in scope;
   otherwise document as unsupported and have the template refuse it.
5. **Multi-ASIC**: per-namespace containers (`bgp0`, `bgp1`, …), namespace-aware
   VTY socket paths, `-n` handling in the shim, `managers_chassis_app_db`.
6. **PIM / multicast, OSPF, IS-IS**: zebra-rs has all three; expose through
   CONFIG_DB only if a consumer exists.

---

### Phase 9 — Rollout

1. **Coexistence period**: both images build; `SONIC_ROUTING_STACK` selects. FRR
   stays the default.
2. **sonic-mgmt**: run the full `bgp/` and `route/` suites against a zebra-rs VS
   testbed; triage into "zebra-rs bug" vs "test hard-codes FRR output".
3. **Hardware validation** on at least one real platform per ASIC vendor in scope.
4. **Scale**: full-table eBGP (≥1M routes), convergence timing vs FRR, memory and
   CPU under churn. zebra-rs's sharded BGP RIB should win here — measure it, since
   it is the main *positive* argument for the migration. Include `maximum-prefix`
   and `suppress-fib-pending` under `rib-sharding > 1`, where both have documented
   lag.
5. **Documentation**: operator-facing differences, plus a migration guide.
6. **Default flip** and FRR deprecation — only after 2–4 are green, and keep the
   FRR image buildable for at least one release.

---

## 4. Sequencing summary

| Phase | Outcome | Blocks | State |
|---|---|---|---|
| 0 | FPM recorder + golden traces + replay harness | 1 | done |
| 1 | FPM tee; routes reach APPL_DB byte-identically | 2, 3 | done (NHG mode optional, open) |
| 2 | Offload ack + `suppress-fib-pending` | 3 | done |
| 3 | `docker-fpm-zebra-rs` boots on VS; eBGP works | 4, 5 | done |
| 4 | CONFIG_DB → zebra-rs bridge | 5, 6 | instance + 3/6 families, backend wired; most managers not ported |
| 5 | `vtysh` shim + FRR-schema JSON | 6, 9 | not started |
| 6 | Warm/fast reboot, GR, TSA | 9 | ordering done; restarter open |
| 7 | `.deb` + docker + CI in sonic-buildimage | 9, and in practice 4 | full VS image builds and boots; dbgsym, multi-arch, CI open |
| 8 | VRF, SRv6, EVPN, BMP, multi-ASIC | 9 | VRF encoding only |
| 9 | sonic-mgmt, scale, hardware, default flip | — | not started |

Phase 7 steps 1–3 are done, step 3 on a working-tree patch; it needs repeating
once §2.7 is upstream and pinned. 4 and 5 are independent and can run in
parallel.

## 5. Explicit non-goals

- Do **not** replace `orchagent`, `fpmsyncd`, or invent a parallel SAI path.
- Do **not** write APPL_DB from zebra-rs directly. It duplicates `fpmsyncd`,
  tightens coupling, and buys nothing until a feature FPM genuinely cannot encode.
- Do **not** bypass the kernel FIB. SONiC's consistency model, `route_check.py`,
  and containerized default-route handling all assume kernel routes exist.
- Do **not** chase full FRR feature parity before a stock T0/T1 works end to end.
- Do **not** port `frrcfgd` until a consumer demands it.
- Do **not** accept a config leaf that does nothing. Refuse it in the template
  instead; `select-defer-time` is the model.

## 6. Biggest risks

1. **The `vtysh`/JSON surface (Phase 5)** — schemas that were never specified,
   only observed, and a call-site count nobody has reproduced. Largest source of
   long-tail breakage. *Mitigation:* inventory first, then the shim + contract
   tests against captured FRR output.
2. **Silent behavioural divergence** — the risk the first revision missed, and the
   one Phase 4 keeps surfacing. A construct that is *accepted* is not a construct
   that *behaves the same*: `add-path send` may advertise only the bestpath; a
   dropped `soft-reconfiguration` or `keepalive` changes behaviour with nothing in
   any log. *Mitigation:* keep the "silently degraded" and "unverified-behaviour"
   lists in §2.3 explicit, and close each with a **live measurement**.
3. **The SONiC build has never run end to end, and cannot today** (§2.6). The
   `.deb`, the image and the runtime were each validated directly. Cheap to
   retire, and first in the queue.
4. **Drift between the two trees.** zebra-rs moved 1126 commits while the SONiC
   branch stood still, and the plan itself forked into two copies. *Mitigation:*
   one plan (this file), a pin that moves on a schedule, and the zebra-rs-side CI
   job from Phase 7 step 9.
5. **FPM dialect drift (Phase 8)** — `dplane_fpm_sonic.c` changes with FRR
   upgrades. *Mitigation:* `fpm-tap` is a permanent regression tool; re-capture on
   every SONiC FRR bump.
6. **Warm reboot** — the most integration-sensitive behaviour in the system, the
   hardest to test convincingly, and it now carries a real feature
   (restarting-speaker GR) rather than only wiring. *Mitigation:* automate it on
   VS in CI early, not manually at the end.
7. **Scale regressions found late** — measure at Phase 3 (rough, done at 50k for
   the tee) and Phase 9 (rigorous).
