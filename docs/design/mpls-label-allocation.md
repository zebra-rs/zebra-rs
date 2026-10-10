# MPLS Label Allocation — the RIB as the Label Authority

Status: **design; phases 1, 2, 3a, 3b, 4a and 4b implemented** (2026-10-08: `rib/label_space.rs`; OSPF reads the `default` block; the IGPs' local labels come from the RIB's label space; configured Adjacency-SIDs claim their SRLB label; ILM candidates keyed by owner; a moved Prefix-SID's old label held). Supersedes the ad-hoc split
between the RIB `LabelManager`, the node-shared `LocalLabels` set
(#2479, #2480) and the hard-coded OSPF SR constants.

The node has one kernel MPLS label table. Today four mechanisms put labels
into it without knowing about each other, and the only thing keeping them
apart is a comment asking operators to "keep the SR blocks clear". This
document makes the RIB the single owner of the 20-bit label space. The
layout and defaults follow Cisco IOS XR; Adjacency-SIDs follow FRR:

1. The RIB is the label authority, holding one node-wide SRGB and SRLB.
2. OSPFv2, OSPFv3 and IS-IS all read that block.
3. The dynamic pool sits outside the SR blocks, from 24000 by default.
4. Dynamic Adjacency-SIDs come from the SRLB, one node-wide range shared by
   every IGP (the FRR model, not Cisco's). The default SRLB is Cisco's,
   15000–15999. A configured local SID takes its label from a dynamic
   holder (IOS XR's precedence rule, applied at commit).
5. BGP allocates **chunk-based** from the dynamic pool, with FRR's
   adaptive chunk sizes; IGPs allocate **per label** from the SRLB (§5).

Read together with:
- [`bgp-labeled-unicast.md`](bgp-labeled-unicast.md) — LU local labels,
  swap ILMs, the "no async relabel" gap this design removes.
- [`bgp-rib-sharding-plan.md`](bgp-rib-sharding-plan.md) §B.2 — why a
  shard cannot call main per route, and the `LabelBlockLow` refill that was
  never built.
- [`bgp-evpn-ethernet-segment.md`](bgp-evpn-ethernet-segment.md) — ESI
  labels from the dynamic block.
- [`bgp-sr-policy-plan.md`](bgp-sr-policy-plan.md) — Binding-SID labels.
- [`ospf-sr-mpls-status.md`](ospf-sr-mpls-status.md) — OSPF SR-MPLS.

## 1. Where labels come from today

| Source | Who picks the value | Range | Arbitration |
| ------ | ------------------- | ----- | ----------- |
| BGP dynamic labels (per-VRF, per-EVI, ESI, VPWS, LU/VPN transit) | RIB `LabelManager` grants 1024-label blocks; BGP allocates inside them | 16 upward (`DYNAMIC_START`, `rib/label_manager.rs:24`) | none against SR blocks; the module doc only *asks* operators to keep blocks clear (`label_manager.rs:10-13`) |
| SRGB (Prefix-SIDs) | nobody: label = SRGB base + index | IS-IS: RIB `default` block 16000/8000 (`rib/segment_routing/block.rs:31-34`); OSPF: hard-coded `SRGB_START 16000`, `SRGB_RANGE 2001` (`ospf/srmpls.rs:17-18`) | none; the ILM keeps one candidate per rtype per label and installs the lowest distance (`rib/route.rs:850-881`, `ilm_next` `:2331`), silently |
| SRLB (dynamic Adj-SIDs, IS-IS Mirror Context labels) | node-shared `LocalLabels` set (`spf/label_pool.rs`), owned by `ConfigManager`, reached through `RibSubscriber::local_labels` | IS-IS: block 15000/100; OSPF: hard-coded 15000/1000 (`ospf/srmpls.rs:21-22`) | the shared set: no two instances hold one label (#2479, #2480) |
| Static `mpls label` bindings, explicit Binding-SIDs, absolute Prefix/Adj-SIDs | operator | anything | none; no range validation (`rib/mpls/config.rs:30-48`, `zebra-bgp-sr-policy.yang:119`) |

Consequences:

- **BGP grows into the SR blocks.** Blocks are carved upward from 16; the
  15th 1024-label block (14352–15375) overlaps the SRLB, the 16th the SRGB.
- **Two sources of truth for SR ranges.** OSPF ignores the RIB block
  (`RibSrRx::Block {..} => {}`, `ospf/inst.rs:13331`) and advertises its
  constants; IS-IS advertises the block. The book says OSPFv3 uses the
  global block (`book/src/ch-15-10-ospfv3-segment-routing.md:36`); the code
  does not.
- **The RIB does not know which local labels are in use.** `LocalLabels`
  lives outside it, so the RIB cannot steer the dynamic pool around them.
- **Nothing reads the kernel's label table at startup.** `fib_dump` covers
  IPv4/IPv6 only (`fib/netlink/dump.rs:22-48`); an ILM left by a crashed
  run makes the next run's `NLM_F_EXCL` add fail with EEXIST, which is only
  logged (`fib/netlink/handle.rs:3671-3675`, `:3820-3822`).
- **A block change is accepted unchecked and only partly applied.**
  - The RIB stores any `segment-routing block` change and notifies its
    watchers (`rib/inst.rs:3752-3756`).
  - IS-IS re-advertises the new SRGB and SRLB, but builds its Adj-SID pool
    only when it has none (`reconcile_local_pool`,
    `isis/inst.rs:3521-3545`). After an SRLB change, its Adj-SIDs, old and
    new, still come from the old range while it advertises the new one.
  - OSPF ignores the block.
  - Nothing checks BGP's blocks or static bindings. A new SRGB over a block
    BGP holds puts both at the same labels, and `ilm_next` picks the lower
    distance (`ilm_distance`, `rib/inst.rs:888-898`): BGP (20) beats OSPF
    (110) and IS-IS (115), so the Prefix-SIDs lose silently.
- **Prefix-SID labels come from the advertiser's SRGB, not RFC 8660's.**
  IS-IS and OSPF both compute a remote Prefix-SID's label as the
  *originating* router's SRGB start + index (`resolve_sid`,
  `isis/rib.rs:164-191`; `label_map.get(&adv_router)`,
  `ospf/inst.rs:15731-15758`). That one label is then used three ways: as
  our incoming ILM label, as the swap label (`make_ilm_entry` pushes the
  incoming label, `isis/rib.rs:749-763`, `ospf/inst.rs:18376-18388`), and
  as the label imposed on IP routes. RFC 8660 takes the incoming label from
  our own SRGB and the outgoing one from the next hop's. The two agree only
  when every node uses the same SRGB. Otherwise:
  - an incoming label can fall outside our own SRGB, into the static or
    dynamic region;
  - an RFC 8660 neighbour sends us our-SRGB + index, a label we never
    installed, and expects its own SRGB + index from us, not the
    originator's.

  An all-zebra-rs network forwards consistently, since every node uses the
  originator's label, as long as that label is free on every node. Interop
  breaks as soon as SRGBs differ.

## 2. Reference models

### 2.1 Cisco IOS XR (layout and defaults)

IOS XR keeps one Label Switching Database (LSD) that every label client —
IS-IS, OSPF, LDP, BGP, TE — asks for labels:

- **SRGB** `segment-routing global-block`, default **16000–23999**. LSD
  keeps the default SRGB reserved even when SR is off, so **dynamic labels
  start at 24000**. A per-IGP-instance SRGB can override the global one;
  instances may share one SRGB or use non-overlapping ones. Cisco Live 2024
  recommends the global setting over per-IGP configuration.
- **SRLB** `segment-routing local-block`, default **15000–15999**
  (per Cisco community material), node-wide, used for *explicitly assigned*
  local SIDs: manual Adjacency-SIDs and Binding-SIDs.
- **Dynamic Adjacency-SIDs** come from the dynamic range (24000 and up),
  not the SRLB (per secondary sources; verify against the release's
  configuration guide).
- Prefix-SID indexes must be unique across IGPs and address families,
  since they share the SRGB; that is the operator's job.
- **Static labels** may use any label outside the dynamic range, which
  `mpls label range table 0 <min> <max>` sets (the YANG floor for `min` is
  16000, so 16–15999 is always outside it). The router does not check them
  when they are configured. A static label that another client already
  holds is a *discrepancy*: it is logged, listed by
  `show mpls static local-label discrepancy`, and cleared by
  `clear mpls static local-label discrepancy {label | all}`, which gives
  the dynamic holder a new label. The static configuration takes precedence,
  and traffic on the relabelled entry can be lost. The static-labeling guide
  does not say how static labels inside the SRGB or SRLB are treated.
- Because dynamic Adjacency-SIDs come from the dynamic range, a manual
  Adjacency-SID in the SRLB cannot collide with a dynamic one.

One IS-IS instance advertises one SRGB (RFC 8667), shared by its IPv4 and
IPv6 Prefix-SIDs (distinct indexes). OSPFv2 (RFC 8665) and OSPFv3 (RFC 8666)
each advertise their own SRGB/SRLB; nothing stops them advertising the same
range, which is what a node-wide block gives.

Junos differs (per-protocol `source-packet-routing srgb start-label /
index-range`) but also routes every range through one label manager in rpd,
which refuses an overlapping SRGB (`RPD_ISIS_SRGBALLOCATIONFAIL`) rather than
colliding silently.

### 2.2 FRR (Adjacency-SIDs and BGP chunks)

From the FRR source (checkout 6a306e1fbe, 2026-08-17):

- **One label manager in zebra.** Every daemon asks zebra for label ranges
  (`ZEBRA_GET_LABEL_CHUNK`). `mpls label dynamic-block <start> <end>`
  sets the dynamic range, default 16–1048575 (`zebra/label_manager.c:219`);
  a request for a specific range that conflicts with a configured dynamic
  block is rejected (`:256`, `:359`).
- **isisd and ospfd reserve their SRGB and SRLB as explicit ranges**
  (`isisd/isis_sr.c:257`, `:482`; `ospfd/ospf_sr.c:268`). Defaults for both:
  SRGB 16000–23999, SRLB 15000–15999 (`yang/frr-isisd.yang`,
  `ospfd/ospf_sr.h:176-183`).
- **SR blocks are per daemon, and two daemons cannot share one.** The SRGB
  and SRLB are set under `router isis` or `router ospf` (there is no
  node-wide setting). zebra refuses a specific range that touches a chunk
  another client holds (`zebra/label_manager.c:382-384`). So isisd and
  ospfd running SR together must use disjoint SRGBs *and* SRLBs. With the
  shared defaults, the daemon that asks second keeps SR down
  (`ospfd/ospf_sr.c:505-515`, `isisd/isis_sr.c:255-262`).
- **Dynamic Adjacency-SIDs are taken one label at a time from the SRLB**
  (`sr_local_block_request_label`, `isisd/isis_sr.c:540`;
  `ospfd/ospf_sr.c:239`), not from the dynamic range.
- **bgpd allocates in adaptive chunks** (`bgpd/bgp_labelpool.c`): the first
  chunk is 128 labels (`LP_CHUNK_SIZE_MIN`), each further request doubles
  up to 65536 (`LP_CHUNK_SIZE_MAX`, 1/16 of the label space, lines 61-62,
  529-537), and the size resets to 128 when a wholly free chunk goes back to
  zebra (lines 600-608). Requests are asynchronous and queued until a chunk
  arrives; ldpd uses fixed 64-label chunks (`ldpd/lde.h:123`).

### 2.3 What this design takes

| Aspect | Model | Why |
| ------ | ----- | --- |
| One label authority | both | the RIB, like LSD / zebra's label manager |
| SRGB 16000–23999, SRLB 15000–15999 | IOS XR (FRR's defaults agree) | the de facto defaults; the SRLB grows from 100 to 1000 |
| Dynamic pool from 24000 | IOS XR | keeps the default SRGB reserved even before SR is on |
| Dynamic Adj-SIDs from the SRLB | FRR | Adj-SIDs stay inside the advertised SRLB, and today's labels (15000+) do not change |
| A configured SID takes its label from a dynamic holder | IOS XR (the precedence of `clear mpls static local-label discrepancy`) | with dynamic Adj-SIDs in the SRLB, configured and dynamic ones can collide (IOS XR avoids this by placing dynamic ones elsewhere); done at commit, with no `clear` command |
| Static labels: any label outside the SRGB, SRLB and dynamic range | IOS XR | no fixed static block to size; checked at commit instead of reported later as a discrepancy (§7) |
| SRLB change moves dynamic Adj-SIDs to new labels | FRR | cheap, and it keeps Adj-SIDs inside the advertised SRLB (§6.1) |
| A block change over BGP labels or static bindings is rejected at commit | none exactly (IOS XR: pending or reload; Junos: rpd restart; Nokia: SR shutdown) | the RIB knows every label in use, so the operator learns at commit, and the running state never diverges from the configuration (§6.1) |
| BGP in adaptive chunks (128 → 65536) | FRR | per-route minting cannot take a lock or a round trip per label; small chunks while demand is small, few allocations when it is large |

## 3. Label space layout

Defaults, all reserved in one RIB-owned structure:

| Labels | Region | Allocated by | Notes |
| ------ | ------ | ------------ | ----- |
| 0–15 | reserved | — | IANA special-purpose |
| 16–14999 | static | operator | `mpls label` static bindings; never handed out dynamically. Static bindings may use any label outside the SRLB, SRGB and dynamic range (§7); this is what that leaves by default |
| 15000–15999 | SRLB | RIB `LabelSpace` per label, or the operator explicitly | dynamic Adj-SIDs of every IGP and address family, IS-IS Mirror Context labels; configured Adj-SIDs (`adjacency-sid absolute`) and explicit Binding-SIDs; default block SRLB grows from 100 to **1000** |
| 16000–23999 | SRGB | nobody (base + index) | Prefix-SIDs of every IGP and address family |
| 24000–1048574 | dynamic | RIB `LabelSpace` in chunks | BGP labels, dynamic Binding-SIDs (later) |

Rules:

- The SRGB and SRLB are the `default` entry of `segment-routing block`
  (existing YANG, `config.yang:5381-5420`). Every *configured* block is
  reserved, so an operator can pre-reserve a range; only `default` is read
  by the IGPs. A per-IGP SRGB override (IOS XR's) is deferred, and the
  design keeps it cheap to add (§11, question 3).
- The dynamic range is configurable (`mpls label-range dynamic`, §8) and
  always skips every configured block, even where one falls inside it.
  Static bindings are kept out of it at commit (§7). A change applies to
  blocks handed out from then on: one already outside the new range stays
  until its owner returns it (phase 6c).
- The upper bound is the kernel's: `net.mpls.platform_labels = N` admits
  labels `0..N-1`, and the kernel caps N at 2^20 − 1 (`label_limit` in
  `net/mpls/af_mpls.c`; writing 1048576 fails with EINVAL, checked in a
  scratch namespace). So with the sysctl at its maximum, 1048575
  (`fib/netlink/sysctl.rs`), the last usable label is **1048574**, and the
  last 20-bit label, 1048575, can never be installed (`ip -f mpls route add
  1048575` fails with "Label >= configured maximum in platform_labels").
  The former `LabelManager` could hand it out (its end was 0x100000); the
  dynamic region now ends at 1048574 (`label_space::PLATFORM_LABELS`, which
  a test ties to the sysctl).

## 4. The RIB `LabelSpace`

One structure replaces `LabelManager` and `LocalLabels`:

```text
LabelSpace (owned by Rib, created in Rib::new)
  regions:   reserved | static | blocks (SRGB/SRLB, every configured block) | dynamic
  per label: Free | Held { owner, kind } | Releasing { owner }
             | Revoking { from, to } | Stale
  per chunk: Held { owner, range, in_use } | Releasing { owner, range }
  owners:    ProtoId (the subscription that holds it)
```

- **Ownership by `ProtoId`, not by protocol name.** Name-keyed release
  (`label_manager.release_all("bgp")` in `proto_cleanup`) is the pattern the
  respawn races of #2478 came from. A label is held by the subscription
  that allocated it.
- **Synchronous handles.** The IGPs allocate inline (OSPF's NFSM Full
  transition, IS-IS Hello processing) and BGP shards allocate on worker
  threads; neither can wait for a RIB round trip. So `LabelSpace` sits
  behind a mutex, and each subscription gets a handle bound to its
  `ProtoId`, reached through its `RibClient` (`ctx.rib.labels()`). The RIB
  holds the same structure, so it sees every label in use, steers the
  dynamic region around the blocks, validates config and answers `show`.
  The lock is taken once per IGP label and once per BGP chunk, never per
  BGP route.
- **Release goes through the RIB.** Freeing a label the moment its owner
  lets go is unsafe: the owner's `IlmDel` is still queued on the inbound
  channel, and if the label is reallocated and the new owner's `IlmAdd`
  lands first, the stale `IlmDel` removes it (same-rtype case, e.g. OSPFv2
  then OSPFv3), or, with a different rtype, the stale entry can outrank it
  (lower distance) until cleanup. So:
  - `release(label)` and dropping a handle move labels to `Releasing`.
  - The RIB moves a `Releasing` label to `Free` once no ILM entry of that
    owner remains at it — on the owner's `IlmDel`, or in `proto_cleanup`
    after the owner's ILMs are withdrawn. A despawned instance's labels
    therefore come back exactly when its forwarding state is gone.
  - ILM candidates are keyed by owner (`ProtoId`) as well as rtype, so a
    stale `IlmDel` can only remove its own owner's candidate (fixes
    OSPFv2/OSPFv3 overwriting each other at one label).
- **Kernel seeding.** At startup the RIB dumps the kernel's AF_MPLS routes
  and marks their labels `Stale`. A protocol that re-learns one takes it
  over (graceful restart); the rest are swept, like `SweepStale` for IP
  routes, once the protocols have converged. ILM installs of labels we own
  use `NLM_F_REPLACE`.

### 4.1 Where it lives

The label manager is **part of the RIB**: `LabelSpace` is a module of
`rib/` (e.g. `rib/label_space.rs`), created in `Rib::new` and owned by
`Rib`. It replaces the RIB's `LabelManager` (`rib/label_manager.rs`) and
the `LocalLabels` set that `ConfigManager` holds today
(`spf/label_pool.rs`). There is no separate label-manager task or process.

What is hybrid is the access, not the ownership:

```text
+---------------------------------- RIB (rib/) -----------------------------------+
|  Rib task (event loop) does everything that needs RIB state:                    |
|   - SR block config, static bindings, dynamic range  -> sets the regions        |
|   - ILM add/del, proto_cleanup                        -> Releasing -> Free       |
|   - startup AF_MPLS dump                              -> Stale, then swept      |
|   - commit validation, show mpls label range/table                              |
|                              |                                                  |
|                  Arc<Mutex<LabelSpace>>   (rib/label_space.rs)                  |
+------------------------------|--------------------------------------------------+
                               |  one handle per subscription (ProtoId), via RibClient
        +---------------+------+-------------+------------------+
      IS-IS         OSPFv2/v3          BGP main task      BGP shards (threads)
   per label,      per label,        chunks from the     chunks from the
   from SRLB       from SRLB         dynamic region      dynamic region
```

- **Allocation is synchronous and bypasses the RIB's event loop.** A
  protocol calls its handle, which takes the mutex and returns a label or a
  chunk at once. OSPF allocates inline on the NFSM Full transition, IS-IS
  inline while processing a Hello, and BGP shards per route on worker
  threads; none can wait for a message round trip.
- **Release completes in the RIB.** Releasing (or dropping a handle) only
  marks labels `Releasing`; the RIB task frees them when the owner's ILM
  entries are gone, which only the RIB can see.

Compared with the references: FRR's label manager also lives in the RIB
daemon (zebra, `zebra/label_manager.c`), but daemons are separate processes,
so access is asynchronous ZAPI messages with queued requests; zebra-rs is
one process, so a shared handle gives synchronous access. Cisco's LSD is a
separate process from the RIB, reached over IPC.

Rejected alternatives:
- *A separate label-manager task* (like LSD): allocation becomes
  asynchronous, and the task would still need the RIB's ILM state to
  complete a release safely.
- *Messages to the RIB only* (like FRR's ZAPI): asynchronous on the IGP and
  BGP-shard hot paths; that is today's `LabelBlockRequest` flow, with the
  pending-request and relabel complexity listed in §5.2.

## 5. Allocation granularity: BGP chunks, IGPs per label

### 5.1 IGPs: per label, from the SRLB

IS-IS, OSPFv2 and OSPFv3 allocate each dynamic Adjacency-SID (and IS-IS
each Mirror Context label) as one label from the SRLB, through their
handle — the FRR model. Rates are low (adjacency events), and per-label
ownership is what an operator wants to see in `show mpls label table`.

- **One SRLB for the node.** Every IGP instance and address family draws
  from the same region, so no two hold one label. This is what #2479 and
  #2480 built with `LocalLabels`; the set moves into the RIB's `LabelSpace`
  as its SRLB region, so the RIB finally sees which local labels are in use.
- **Lowest free label.** A dynamic allocation takes the lowest SRLB label
  that is neither held nor explicitly reserved, as today.
- **Configured labels take precedence (IOS XR's rule).** Configured
  absolute Adj-SIDs (`adjacency-sid absolute`, OSPFv2 and OSPFv3 today)
  and explicit Binding-SIDs (`binding-sid-label`) must lie in the SRLB.
  At commit, the claimed label is handled by its state:
  - free: it becomes `Held { kind: explicit }` for the claimant;
  - held by another configured SID: the commit is rejected, since two
    configured claims on one label are an operator error;
  - held by a dynamic Adj-SID or Mirror Context label: the commit is
    accepted, and the dynamic holder is moved. Dynamic allocation takes the
    lowest free label, so an operator cannot know which low SRLB labels are
    taken. Rejecting would make the most natural choices (15000, 15001, ...)
    succeed or fail depending on the order adjacencies came up.

  Index-form Adj-SIDs (`adjacency-sid index`) derive their label from the
  SRGB, like a Prefix-SID, and claim nothing in the SRLB.

  Binding-SIDs are not claimed yet (phase 3c). A local SR Policy's
  `binding-sid-label` is only advertised, over BGP (SAFI 73); the ILM for
  it is installed by the headend that receives the policy
  (`MplsIlmAction`), at a label its originator chose. So there is no
  commit at which to claim it: the headend's claim on a received label is
  what 3c designs.
- **Moving a dynamic holder.** The steps run in this order, so a label never
  points at two adjacencies:
  1. The label becomes `Revoking { from, to }`, and no dynamic allocation
     can take it. The holder is told: inline when the holder is the
     claiming instance itself, otherwise by `RibRx::LabelRevoked { label }`.
  2. The holder allocates a new lowest-free label for that adjacency,
     re-originates its LSA or LSP, and withdraws the ILM at the old label.
  3. When no ILM of the holder remains at the label (the same trigger as
     `Releasing` → `Free`, §4), the label becomes
     `Held { kind: explicit }` for the claimant. The claimant is told by
     `RibRx::LabelGranted { label }`, and only then advertises and
     installs it. If the configuration is removed meanwhile, the label
     goes to `Free` instead.

  When the holder is the claimant itself, steps 2 and 3 are one
  re-origination: the instance relabels the dynamic adjacency and replaces
  the ILM at the label with the configured one.

  The moved adjacency's Adj-SID changes. Traffic steered by the old label
  (SR policies, other nodes' TI-LFA repair lists) is disrupted until it is
  recomputed, the same impact Cisco documents for clearing a discrepancy.
  The move is logged with the old and new label.
- **Exhaustion.** The default SRLB holds 1000 labels for every adjacency of
  every IGP (OSPF: one per Full neighbor; IS-IS: one per neighbor IPv4
  address). When it is spent, a new adjacency gets no Adj-SID and the
  allocation is logged; the operator enlarges the SRLB.
- **Why not Cisco's dynamic range.** Adj-SIDs stay inside the range the
  node advertises as its SRLB, so whoever reads the SRLB (a controller, an
  operator) sees where every local SID lives, and today's Adj-SID labels
  (15000, 15001, ...) do not change. The cost is the collision with
  configured SIDs that IOS XR's layout avoids, which the precedence rule
  above handles.
- The `LocalLabels` / `LocalLabelPool` RAII contract (#2479, #2480) carries
  over: a pool gives its labels back when dropped. The difference is that
  "back" now means `Releasing` until the RIB has withdrawn the ILMs.

### 5.2 BGP: chunk based

**BGP allocates in chunks, sized adaptively as FRR's bgpd does.** Every
BGP label allocator — the main task and each RIB shard, including
pool-worker shards — holds one or more chunks taken synchronously from the
dynamic region through its handle. BGP hands out individual labels inside
its chunks; the RIB tracks the chunk, not the label.

Why not per label:

| | Per label from the RIB | Chunks |
| - | --------------------- | ------ |
| Hot-path cost | one lock (or IPC) per minted label; LU/VPN transit mint per route, at full-table scale on parallel shards | one lock per chunk (128 up to 65536 labels); shard-local allocation is lock-free |
| Fit with sharding | the reason B.2 ruled out a per-route call to main | what B.2 designed, now actually filled |
| Visibility | exact owner per label | owner per chunk; BGP's own `show` lists label → prefix |
| Waste | none | at most one partly used chunk per allocator; adaptive sizing keeps it at 128 labels for an allocator with little demand |
| Release | per label | a chunk goes back when wholly free |

Per-label wins only on visibility and waste, and with chunks starting at
128 labels neither matters out of a million. The per-route cost is what
the sharding design exists to avoid.

Chunk rules:

- **Adaptive size, per allocator** (FRR's `bgp_labelpool.c`, §2.2). Each
  allocator — the main task and each shard — keeps its own next chunk
  size:
  - the first chunk is **128** labels;
  - each further chunk doubles the size, up to **65536** (1/16 of the
    label space, so one busy allocator cannot take a greedy share);
  - when a wholly free chunk goes back to the RIB, the next size resets to
    128.

  A busy shard minting transit labels for a full table climbs to large
  chunks within a few allocations; the main task, with a handful of
  per-VRF and per-EVI labels, stays at 128. This replaces today's fixed
  1024 (`VRF_LABEL_BLOCK_SIZE`, `SHARD_LABEL_CHUNK`).
- **Refill on empty, synchronously.** No `LabelBlockRequest` /
  `RibRx::LabelBlock` round trip, no `vrf_label_request_pending`, no
  label-0 VRF spawned and later respawned by `relabel_vrf`. Labels exist
  the moment a VRF, EVI, ES or VPWS is configured.
- **Main task vs shards.** The main task's chunks serve per-object labels
  (per-VRF, per-EVI, ESI, VPWS, Type-5 per-VRF). Each shard holds its own
  chunks for per-route labels (LU v4/v6 and VPNv4/v6 transit). There is no
  carving of one allocator's block by another.
- **Return.** A chunk whose labels are all free goes to `Releasing` and
  back to the RIB once its ILMs are gone, and the allocator's next size
  resets to 128, as in FRR. Every chunk goes back when the BGP instance
  stops.
- **Exhaustion.** If the dynamic region cannot supply the next size, the
  allocator retries at halving sizes down to 128 (our addition: a nearly
  full or fragmented region still yields a small chunk). If even 128 is not
  available, allocation returns `None` and logs; the next allocation
  retries. There is no request flag that can stick.

What this replaces in today's BGP (from reading the code; not reproduced):

- A shard fills itself by `carve(1024)` from the main allocator, which needs
  1024 contiguous labels inside one 1024-label block (`bgp/vrf/label.rs:99-111`):
  it succeeds only on a block nothing else has touched. Once a VRF, EVI, ES
  or VPWS label has used any of the only block, LU/VPN transit minting
  returns `None`, and a failed carve does not request another block
  (`bgp/shard/mod.rs:85-93`; `request_label_block` callers are the VRF,
  EVI, ES, VPWS and config paths only).
- Pool-worker shards are called with no central allocator
  (`bgp/shard/pool.rs:16-19`, `:60`) and cannot mint at all; the
  `LabelBlockLow` refill was never built.
- Shard sub-blocks are never returned, and a carved central block can never
  become wholly free, so it never goes back to the RIB.
- An exhausted RIB pool sent no reply, and `vrf_label_request_pending`
  never cleared, so BGP never asked again. A configurable dynamic range
  (phase 6c) made this reachable, so the RIB now keeps a request it has no
  room for and serves it once labels are freed, SR blocks change, or a
  commit grows the range (`retry_label_block_requests`); BGP's reply
  handling already clears the flag and labels whatever waited.
- `label-mode per-route|per-nexthop` is parsed (`vrf_config.rs:501-509`)
  but unused; only per-VRF labels exist. Per-route mode, when built, mints
  from the same shard chunks.

## 6. SR blocks, read by every IGP

- OSPFv2 and OSPFv3 watch the `default` block by name (`SrBlockWatch`),
  as IS-IS does (`isis/inst.rs:3490-3511`), and drop `SRGB_START/RANGE` and
  `SRLB_START/RANGE`. Advertisement (`router_info_tlvs`,
  `ospf/srmpls.rs:79-87`), self Prefix-SID / Adj-SID labels
  (`ospf/inst.rs:18601-19029`) and `show` read the block.
- With no block (SR-MPLS on, block not yet delivered) an IGP advertises no
  SR capabilities, as IS-IS does today.
- **Changing a block at runtime** is applied live, or rejected at commit,
  depending on what the new range covers (§6.1).
- **SRGB conflicts** (two IGPs, or two prefixes, mapping to one label) are
  not prevented — the label is derived, not allocated — but they become
  visible: an `IlmAdd` at an SRGB label held for a different FEC logs a
  conflict. RFC 8660 §2.5 defines tie-breaking for such an incoming label
  collision; `ilm_next` already selects by administrative distance first.

### 6.1 Changing the SRGB or SRLB

How the reference implementations handle a change:

| | Change into a free range | New range covers labels in use | Recovery |
| - | - | - | - |
| IOS XR | Applied; an SRGB change is "disruptive for traffic" | SRLB: "accepted, but not applied (pending state)", and the old range stays active. SRGB: needs a reload | Reload. For the SRLB, `clear segment-routing local-block discrepancy all` instead forces the other applications onto new labels, which is disruptive. `show segment-routing local-block inconsistencies` shows the conflict |
| Junos | Applied | The label manager cannot reserve the range and logs `RPD_ISIS_SRGBALLOCATIONFAIL` | Pick a free range and restart rpd |
| Nokia SR OS | SR must first be shut down in every IGP, unless the change does not shrink the IGPs' configured `prefix-sid-range` | Fails if an allocated SID index or label would fall outside the range. The SRGB is carved from the dynamic range; the static range is off-limits to SR | Shut SR down, change the range, re-enter `prefix-sid-range` |
| FRR | Releases the old block and reserves the new one (`isisd/isis_sr.c:230-250`). An SRLB change gives every Adj-SID a new label and re-floods (`:289-325`) | zebra refuses the range, and SR stays down until a range can be reserved (`ospfd/ospf_sr.c:2347-2372`) | Reconfigure |

None of them moves conflicting labels without a reload, a process
restart, an SR shutdown, or a disruptive clear. IOS XR also stops
reserving the default SRGB and SRLB once `mpls label range` is configured
over them.

The RIB knows every label in use, so it can do better. A change is
handled by what the new range covers:

| New range covers | Handling | Why |
| - | - | - |
| Only free labels, or part of the dynamic range with no labels in use | Apply live; the dynamic allocator skips the block (§3) | No reload needed: nothing else holds those labels |
| Static bindings | Reject at commit | Both are configuration, so the operator moves one (§7). Nokia also keeps SR off the static range |
| Dynamic Adj-SIDs or Mirror Context labels | Accept, and give them new labels | Cheap, and what FRR does on an SRLB change. Uses the same `Revoking` mechanism as a configured SID (§5.1) |
| BGP chunks | Reject at commit, naming the holder and the nearest free range of the requested size | Moving them means re-advertising every route using those labels. An IOS XR-style pending state would rarely clear, because a chunk only goes back once it is wholly free, and committed-but-unapplied configuration is what §7 avoids. To take that range, the operator restarts BGP or picks another |
| Our own configured SIDs falling outside: a Prefix-SID index beyond the new SRGB, an absolute Adj-SID or Binding-SID outside the new SRLB | Reject at commit | Nokia does the same for indexes. The operator moves them in the same commit |

An accepted change is applied without a forwarding gap on this node:

- **SRGB.** Each IGP installs its Prefix-SID ILMs at the new labels (new
  start + index) and re-advertises its SR capabilities. The old ILMs stay
  for a hold time, so neighbours still sending the old labels keep
  forwarding until they process the new advertisement; then the old
  region is freed. Where the old and new ranges overlap, the new entry
  replaces the old at once.

  Today a Prefix-SID's label is its *originator's* SRGB start + index
  (§1, last bullet), so a change moves the labels of the changed router's
  prefixes on every router, not only on that router. Every router
  therefore holds: whenever a Prefix-SID's ILM moves to a new label, the
  old label stays for the hold (phase 4b). That covers an upstream still
  sending the old label to a router that has moved. It does not cover the
  reverse: an upstream that has moved sends the new label to a downstream
  that has not installed it yet, and that is dropped for as long as the
  two routers' processing of the new advertisement differs, typically
  under a few seconds. RFC 8660 labels remove that window, since then
  only the changed router's incoming labels move and its neighbours
  switch only once it advertises them. Delaying the switch (impose the
  old label for a while after a move) would close it without RFC 8660,
  at the cost of touching route publication and TI-LFA repair labels.
- **SRLB.** Each dynamic Adj-SID and Mirror Context label gets a new label
  in the new SRLB, is re-advertised, and its old label goes through
  `Releasing`, as on any release (§4).
- **Shrinking the SRLB below current use.** The adjacencies that do not fit
  get no Adj-SID, and it is logged, as on exhaustion (§5.1).

This needs OSPF to read the block (phase 2) and IS-IS to rebuild its
Adj-SID pool when the SRLB changes (phase 3).

## 7. Validation at commit

IOS XR accepts any static label and reports a collision later as a
discrepancy for the operator to clear (§2.1). Here, everything that can be
checked is checked at commit. The dynamic allocators take labels only from
the SRLB and the dynamic range, so a static binding kept out of both can
never collide, and no discrepancy state or `clear` command is needed.

- Static `mpls label` bindings: 16 ≤ label < platform_labels, and not in
  the SRGB, SRLB or dynamic range, nor in a label block handed out (one
  handed out before the dynamic range moved can lie outside it). Any other
  label is allowed. The static
  region is whatever those leave: 16–14999 by default, plus the labels above
  the dynamic range if the operator ends it early (IOS XR's definition).
- Configured local SIDs (`adjacency-sid absolute`, `binding-sid-label`): in
  the SRLB and not held by another configured SID. A label held by a
  dynamic Adj-SID or Mirror Context label is accepted, and its holder is
  moved (§5.1).
- `segment-routing block`, new or changed (§6.1):
  - start + range inside the label space;
  - global and local not overlapping each other or another configured
    block;
  - not covering a static binding or a label held by a BGP chunk;
  - every configured Prefix-SID index of ours fits the new SRGB, and every
    configured absolute Adj-SID and Binding-SID lies in the new SRLB.

  Labels held by dynamic Adj-SIDs or Mirror Context labels do not block
  the change; their holders are moved.
- Dynamic range: inside the label space (the schema bounds each end to
  16–1048574) and not empty. Moving it is not refused for the label blocks
  already handed out: they stay where they are, possibly outside the new
  range, until released, and the static check above keeps bindings off
  them (phase 6c).

The checks (phase 6a, `config::label_check`) run in
`ConfigManager::commit`, after the mandatory-node and leaf-value checks and
before anything is dispatched, so a refused commit changes nothing. They
read the whole candidate and the label blocks the RIB's `LabelSpace` has
handed out at that moment, but refuse a commit only for a violation the
running config does not already have. A violation an earlier release let
in therefore does not block every later commit, while a change that
creates one, a block moved over an untouched static binding say, is still
refused.

A commit that passes puts its dynamic range and segment-routing blocks
into the `LabelSpace` itself, under the same lock as the checks and before
anything is dispatched. The RIB applies them only after the commit, and a
block request reaches it on another channel (BGP sends one as it starts),
so a request served first would otherwise come from the old range, or land
on a new SR block, over labels the checks had just cleared. The SR blocks
are added to the reserved set; the RIB then replaces the set as it applies
the blocks, with any SRGB it still holds for a move (§6.1).

The startup config is checked the same way but only warned
about: refusing it would leave the router unconfigured, and a config an
earlier release accepted can fail a check added since. The IGPs keep their
interim handling for that case (§10, phase 3b). The Binding-SID checks
come with phase 3c, which claims them; the dynamic range ones came with
phase 6c, which made it configurable.

## 8. Configuration and show

- Existing: `segment-routing block default global {start, range}` /
  `local {start, range}`. Defaults become SRGB 16000/8000 (unchanged) and
  SRLB 15000/1000 (was 100).
- New: `mpls label-range dynamic {start, end}`, default 24000 /
  platform_labels − 1. Phase 6c implements it: each bound defaults on its
  own, and the commit applies the two together to the label space (§7), so
  a commit moving both never passes through an empty range. A change
  applies to blocks handed out from then on (`LabelSpace::set_dynamic`,
  which reports the blocks left outside; they are logged).
- New: `show mpls label range` (regions and their owners, like IOS XR's
  `show mpls label range`) and `show mpls label table [label <n>]`
  (label or chunk, owner, kind, state).

  Phase 6b implements both (`rib::label_show`, reading
  `LabelSpace::entries`). The table lists allocations only: label blocks,
  and IGP local labels with their state (held, claimed, releasing,
  draining, and a claim waiting on them). Static bindings and Prefix-SID
  labels are configuration and stay in `show mpls ilm`; `label <n>` names
  the region a label is in, so it answers for those too. The range lists
  the reserved labels, each block's SRGB and SRLB, a retired SRGB still
  held (§6.1), the dynamic range, and static as whatever those leave,
  with how much of each is allocated.

## 9. Compatibility

| Change | Visible effect | BDD to update |
| ------ | -------------- | ------------- |
| BGP labels from 24000 | VPN/LU/EVPN labels move from 16+ to 24000+ | none assert a concrete BGP label value (checked) |
| OSPF reads the block | OSPF advertises SRGB 16000/8000 (was 2001) and SRLB 15000/1000 | `ospf_sr_router_id_change`, `ospfv3_router_info` (`SRGB: [16000/18000]`) |
| Default SRLB 1000 | IS-IS advertises SRLB 15000/1000 (was 100); OSPF's advertised SRLB is unchanged | none found |
| Adj-SIDs from the RIB's SRLB | none: still 15000 upward, lowest free first | none |
| Configured Adj-SID on a dynamically held label | the dynamic holder moves to a new label, logged; today both adjacencies can advertise the same label | new scenario |
| Configured local SIDs must lie in the SRLB | `binding-sid-label 16100`, inside the SRGB, is rejected at commit | `bgp_sr_policy_bsid_steering`, `bgp_sr_policy_bsid_forwarding` (move to the SRLB); the example in `zebra-bgp-sr-policy.yang:53` |
| OSPFv2 `show` | prints `end` − 1, as v3 does (v2 prints the raw end today, `ospf/show.rs:2385`) | the two features above |
| Kernel seeding | stale ILMs from a crashed run are reclaimed or swept instead of blocking installs | new feature |

Interop: the advertised SRGB range changes for OSPF and the SRLB range for
IS-IS; Adj-SIDs stay inside the advertised SRLB. Peers use the advertised
SRGB for Prefix-SIDs and take Adj-SID labels as given.

## 10. Phasing

Each phase is one PR, smallest and most urgent first.

| # | Phase | Fixes |
| - | ----- | ----- |
| 1 | `LabelSpace` in the RIB serving today's `LabelBlockRequest` from 24000, skipping every configured block; the dynamic region ends at 1048574, the kernel's last usable label | BGP growing into the SR blocks; the off-by-one |
| 2 | OSPFv2/v3 read the `default` block and follow its changes (§6.1); default SRLB 1000; OSPFv2 `show` end | two sources of truth for SR ranges; OSPF ignoring a block change |
| 3 | IGP dynamic Adj-SIDs and Mirror Context labels per label from the `LabelSpace` SRLB region; configured Adj-SIDs and Binding-SIDs claimed there, moving a dynamic holder (§5.1); an SRLB change moves every dynamic Adj-SID (§6.1); `LocalLabels` retired | RIB blind to local labels; a dynamic Adj-SID could take a configured label; IS-IS Adj-SIDs left in the old SRLB after a change |
| 4 | ILM candidates keyed by owner; `Releasing` and `Revoking` complete only once the RIB withdraws the owner's ILMs; old Prefix-SID ILMs held through an SRGB change (§6.1) | reuse races; OSPFv2/v3 overwrite at one label; forwarding gap on an SRGB change |
| 5 | BGP synchronous adaptive chunks (128 → 65536, reset on return) for the main task and every shard; retire `LabelBlockRequest`, `vrf_label_request_pending`, `relabel_vrf`, `carve` | transit minting failure, worker shards unable to mint, chunks never returned (the stuck request flag is fixed already, with 6c) |
| 6 | Commit validation (§7), including block changes (§6.1), and `show mpls label range/table` | silent overlaps; a new SRGB silently losing to BGP labels |
| 7 | AF_MPLS dump at startup, `Stale` labels, sweep; IGP graceful restart re-reserves its checkpointed Adj-SIDs | EEXIST after a crash; OSPF GR replay not reserving `lan_adj_sids` |

Phase 1 alone removes the live overlap hazard without touching BGP's
allocation flow; it is also the one that moves BGP labels to 24000+. It
keeps `LabelSpace` inside the RIB task, owned by protocol name as the old
`LabelManager` was; the shared handles and `ProtoId` ownership of §4 come
with phases 3 to 5. Allocation is lowest-first-fit, so a released block's
space is reused by the next request that fits in it, not only by one of the
same size. A new SR block over labels already handed out is logged; phase
6a refuses it at commit.

Phase 2 makes OSPFv2 and OSPFv3 SR-block clients like IS-IS: each watches
`default` while SR-MPLS is on (`reconcile_block_watch`), and a block update
re-runs one per-version refresh (`sr_mpls_refresh`, `sr_mpls_refresh_v3`)
that the SR-MPLS config toggle runs too. Until the block arrives, no SRGB
or SRLB is advertised and Index-form SIDs get no label; Adj-SID labels
already held (a graceful restart's) are kept. OSPF already follows an SRLB
move here, rebuilding its pool and drawing every dynamic Adj-SID again
(§6.1); IS-IS does so from phase 3.

Phase 3 lands in two parts. 3a retires `LocalLabels`: the RIB's
`LabelSpace` becomes a `SharedLabelSpace` (`Arc<Mutex<LabelSpace>>`),
created by the RIB and handed through `ConfigManager` to every protocol as
`RibSubscriber::label_space()`. An IGP instance's `LocalLabelPool` over its
SRLB draws single labels from it, inline, and gives them back when dropped;
labels are owned by pool, and `ProtoId` ownership (§4) is still to come.
One structure means a dynamic block is never handed out over a label an IGP
holds, nor an IGP label inside a handed-out block. IS-IS's
`reconcile_local_pool` now matches OSPF's: it rebuilds the pool when the
SRLB moves (every Adjacency-SID and Mirror Context label is drawn again),
and gives every neighbour address without a label one. Before, an adjacency
that came up while there was no pool (SR-MPLS enabled later, or the block
late) never got an Adjacency-SID, because `nbr_hello_interpret` labels an
address only the first time it sees it. 3b, configured Adjacency-SIDs
claiming their label from a dynamic holder (§5.1), came after phase 4:
moving a label between OSPFv2 and OSPFv3 is only safe once their ILM
candidates are told apart.

Phase 4 lands in two parts. 4a keys ILM candidates by owner and adds
`Releasing`:
- `IlmEntry::owner` is the subscription that installed the candidate,
  stamped by `Rib::process_inbound` from the envelope (`None` for the RIB's
  own static bindings). `ilm_add` and `ilm_del` match on (rtype, owner), so
  a stale withdrawal from one instance never removes another's entry at the
  label, OSPFv2's and OSPFv3's included (both `RibType::Ospf`).
  `proto_cleanup` withdraws only the cleaned-up instances' entries.
- An instance's pool (`SharedLabelSpace::pool_for`, owned by its
  `RibClient`) gives a label back as `Releasing`, and sends
  `Message::LocalLabelRelease` on the instance's own channel, behind its ILM
  messages. Only that release decides: a withdrawal queued ahead of it may
  be followed by an install that re-adds the entry. When the RIB handles the
  release the label is free if the instance has no entry at it, else
  `Draining` until `ilm_del` withdraws that entry. A release from an
  instance already cleaned up frees the label; one whose subscription
  failed never registered, installed nothing, and has its labels freed with
  its deferred envelopes.
- An SRLB change moves a pool (`LocalLabelPool::retarget`) instead of
  replacing it: labels still inside the new SRLB stay, so growing or
  shrinking it no longer changes every Adjacency-SID. An owner whose pool
  found no free label (one may be `Releasing`) is told when labels are
  freed (`RibRx::LocalLabelsFreed`) and reconciles its labels again.
- Found on the way: IS-IS's `diff_ilm_apply` sent no `IlmDel` for an entry
  whose nexthops had emptied first (a link failure leaves the Adjacency-SID
  in the LSP with no neighbour), so it leaked; reusing the same label used
  to hide that. It now withdraws as OSPF's does.

4b keeps a moved Prefix-SID's old label forwarding through an SRGB change
(§6.1):
- Every IGP ILM entry says which Prefix-SID it forwards for (`fec`: the
  prefix and its algorithm; none for an Adjacency-SID). When a table is
  rebuilt, `spf::ilm_hold::IlmHold` keeps each label whose Prefix-SID now
  sits at another label for `SID_MOVE_HOLD` (60 s), carrying that
  Prefix-SID's current entry, so the old label follows the new path. The
  held label stays in the table, so the usual diff neither withdraws it
  nor needs to know about holds. A held label goes at once if its
  Prefix-SID goes away or a new entry takes the label.
- IS-IS holds its per-level tables and its own (self-SID) entries; OSPFv2
  and OSPFv3 hold theirs. Each instance keeps one timer on the first held
  label to run out, re-armed after every event.
- The RIB keeps an SRGB that a block change drops reserved for the same
  hold, and after it until the last ILM entry in it is withdrawn, so
  dynamic blocks are not handed out over held labels. A timer alone is not
  enough: an IGP starts its hold only once the block update and its SPF
  reach it, so its old labels outlive a timer the RIB started at the
  change. The withdrawal is the confirmation.
- What is not covered: the window where an upstream already sends the
  new label to a router that has not installed it (§6.1).

3b gives configured absolute Adjacency-SIDs (OSPFv2 and OSPFv3) their SRLB
label with precedence over dynamic ones (§5.1):
- An instance claims each configured label through its pool
  (`LocalLabelPool::claim`). A free label is the claimant's at once
  (`Local::Claimed`); so is one the claimant's own dynamic Adj-SID holds,
  and that Adj-SID is given another label.
- A label another instance holds dynamically, or that is on its way back,
  waits. The holder is told (`RibRx::LabelRevoked`, which the claimant
  asks the RIB to send with `Message::LocalLabelClaimed`). It gives its SID
  another label and releases this one like any other (§4). Once the RIB
  frees it, the label goes to the claimant (`RibRx::LabelGranted`), not
  back to the pool. `Revoking` is therefore not a state of its own: it is a
  held or releasing label with a waiting claim.
- A grant is only a prompt. It can be stale: the claim it answered may
  have been dropped and a new one made, which waits again while another
  instance holds the label. So the claimant takes the grant only if its
  pool holds the claim now (`LocalLabelPool::holds_claim`); the new
  claim's own grant follows.
- While a claim waits, the configured SID is not advertised, and the
  adjacency keeps its dynamic label. A point-to-point adjacency holds that
  label only while its configured SID is not advertised (a claim waiting
  or refused, the label configured on another link too, none configured):
  held beside an advertised configured SID, it would be neither advertised
  nor installed. It goes back once the configured SID is advertised, and
  the adjacency draws one again if that stops. A LAN adjacency always
  holds one, its LAN Adj-SID.
- `unclaim`, a dropped pool, or an SRLB change that leaves the label
  outside gives a claimed label back through `Releasing`, like any other.
- Commit validation (phase 6a) refuses both of the following, but a
  startup config is only warned about (§7), so OSPF still handles them:
  - a configured label outside the SRLB is advertised unclaimed, as before,
    with a warning;
  - of two configured SIDs on one label, the first keeps it and the other is
    not advertised, also with a warning. Two links of one instance with the
    same label count as two SIDs; the one that had it keeps it, else the
    lowest ifindex.
- IS-IS has no configured Adjacency-SID, so it claims nothing. It gives up a
  revoked label as OSPF does: another label for the adjacency or Mirror
  Context, then the release.
- Binding-SIDs are phase 3c (§5.1).

Phase 6 lands in three parts. 6a is commit validation (§7), with the
Binding-SID checks left to 3c. 6b adds `show mpls label range` and `show
mpls label table` (§8). 6c makes the dynamic range configurable (`mpls
label-range dynamic`) and checks it.

Phase 2 changes OSPF's advertised SRGB. No phase changes Adjacency-SID
labels by itself; from phase 3, a configured Adj-SID on a dynamically held
label moves that holder. Phase 5 is the largest, through the VPN, LU, EVPN
and transit-label code.

## 11. Open questions

1. Dynamic-range default: 24000 (IOS XR) — confirm.
2. ~~Static region: enforce 16–14999 strictly, or only forbid the SRGB,
   SRLB and dynamic region?~~ **Resolved (2026-10-08):** IOS XR's
   definition, any label outside the SRGB, SRLB and dynamic range (§3),
   checked at commit rather than reported later as a discrepancy (§7). A
   configured local SID takes its label from a dynamic holder (§5.1).
3. ~~Per-IGP-instance SRGB override (IOS XR has it): needed?~~
   **Deferred (2026-10-08):** not built now, but kept cheap to add.

   *What it changes.* A Prefix-SID's label is SRGB start + index. Per
   RFC 8660, our own SRGB gives the incoming label for a prefix, and the
   next hop's advertised SRGB gives the outgoing label. An override changes
   the range one of *our* IGPs advertises, so its incoming labels differ
   from what nodes on the default SRGB would compute. That is only correct
   once the labels follow RFC 8660; today they do not (§1, last bullet).
   In zebra-rs, "per instance" means "per protocol": there is one IS-IS
   instance, plus one OSPFv2 and one OSPFv3 in the default VRF, and the
   per-VRF IGPs do not offer segment routing yet.

   *When the shared SRGB is not enough.* With one SRGB, a Prefix-SID index
   must be unique across every IGP on the node. If IS-IS and OSPF give
   different prefixes the same index, both claim one incoming label. One
   ILM wins by administrative distance, and the other prefix's traffic is
   misforwarded. This matters:
   - on a node bordering two separately run SR domains (e.g. an IS-IS core
     and OSPF access), each with its own index plan; and
   - when migrating an FRR configuration, whose daemons must already use
     disjoint SRGBs (§2.2).

   It does not matter during an IGP migration that gives a prefix the same
   index in both IGPs: one shared label for one prefix is what is wanted
   there, and preference picks the IGP.

   *How it would be added.*
   - Prerequisite: Prefix-SID labels per RFC 8660 (§1, last bullet).
   - One block-name leaf per IGP (`segment-routing mpls block <name>`),
     naming a `segment-routing block` entry. IS-IS already watches its
     block by name (`SrBlockWatch { name }`) and only hard-codes `default`
     (`target_block_name`, `isis/lsp.rs:81-86`). OSPF gets the same watch
     in phase 2 (§6), and the YANG description of `segment-routing block`
     already expects protocols to refer to blocks by name.
   - `LabelSpace` holds one SRGB region per distinct range. At commit, two
     IGPs' SRGBs must be equal or disjoint: a partial overlap gives the
     index collision without separating the plans.
   - Only the SRGB is overridable; the SRLB stays node-wide, as in IOS XR.
     Adj-SIDs are allocated, not derived from an index, so splitting the
     SRLB gains nothing and divides the pool.
   - Switching an IGP to another block is the runtime block change of §6:
     re-originate and recompute the incoming Prefix-SID labels.

   Build it when a deployment borders two index plans or migrates an FRR
   configuration with disjoint SRGBs.

## References

- Cisco Live 2024, BRKMPL-2135 (SRGB default, LSD reserving it, dynamic
  from 24000):
  <https://www.ciscolive.com/c/dam/r/ciscolive/global-event/docs/2024/pdf/BRKMPL-2135.pdf>
- Segment Routing TOI, SRGB:
  <https://www.segment-routing.net/images/tutorials/0030-SR-TOI-SRGB_v10.pdf>
- Segment Routing TOI, SR IGP control plane:
  <https://www.segment-routing.net/images/tutorials/0040-SR-TOI-SR_IGP_control_plane_v11a.pdf>
- Cisco Community, ASR9000/XR introduction to Segment Routing (SRLB
  default, dynamic Adj-SIDs from 24000):
  <https://community.cisco.com/t5/service-providers-knowledge-base/asr9000-xr-introduction-to-segment-routing/tac-p/3824842/highlight/true>
- Cisco Community, Embark on a journey into Segment Routing:
  <https://community.cisco.com/t5/other-service-provider-subjects/embark-on-a-journey-into-segment-routing/m-p/5232198/highlight/true>
- Cisco, MPLS Configuration Guide for ASR 9000, IOS XR 7.11.x, Implementing
  MPLS Static Labeling (static labels outside the dynamic range, not
  checked at configuration, discrepancy and its clearing, static precedence):
  <https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/711x/mpls/configuration/guide/b-mpls-cg-asr9000-711x/implementing-mpls-static-labeling.html>
- Cisco, MPLS Configuration Guide for NCS 5500, IOS XR 7.9.x, Implementing
  MPLS Static Labeling:
  <https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/mpls/79x/b-mpls-cg-ncs5500-79x/implementing-mpls-static-labeling.html>
- Cisco-IOS-XR-mpls-lsd-cfg YANG, `label-range` (dynamic minimum
  16000..1048575):
  <https://www.netconfcentral.org/modules/Cisco-IOS-XR-mpls-lsd-cfg/2020-11-26/source/cooked/>
- Juniper, Configuring SRGB label range:
  <https://www.juniper.net/documentation/us/en/software/junos/segment-routing/topics/task/configuring-srgb-label-range.html>
- Juniper, Configuring SRGB label ranges in SPRING for IS-IS (overlap,
  `RPD_ISIS_SRGBALLOCATIONFAIL`, rpd restart):
  <https://www.juniper.net/documentation/us/en/software/junos/is-is/topics/task/configuring-srgb-label-range.html>
- Cisco, Segment Routing Configuration Guide for Cisco 8000, IOS XR 24.x,
  Configure SRGB and SRLB (pending SRLB, reload, `clear segment-routing
  local-block discrepancy`):
  <https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/segment-routing/24xx/configuration/guide/b-segment-routing-cg-cisco8000-24xx/configuring-sr-global-block-and-sr-local-block.html>
- Cisco Live 2024, BRKSPG-3624, Troubleshooting Segment Routing:
  <https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2024/pdf/BRKSPG-3624.pdf>
- Nokia SR OS 22.10, Segment routing with MPLS data plane (changing
  `sr-labels`, SRLB for provisioned Adj-SIDs):
  <https://documentation.nokia.com/sr/22-10/books/Segment%20Routing%20and%20PCE%20User%20Guide/segment-rout-with-mpls-data-plane-sr-mpls.html>
- FRR source, checkout 6a306e1fbe (2026-08-17): `zebra/label_manager.c`,
  `bgpd/bgp_labelpool.c`, `isisd/isis_sr.c`, `ospfd/ospf_sr.c`,
  `ospfd/ospf_sr.h`, `ldpd/lde.h`, `yang/frr-isisd.yang`.
- RFC 8402 (SR architecture), RFC 8660 (SR-MPLS, §2.5 incoming label
  collision), RFC 8665 (OSPFv2 SR), RFC 8666 (OSPFv3 SR), RFC 8667 (IS-IS SR).
