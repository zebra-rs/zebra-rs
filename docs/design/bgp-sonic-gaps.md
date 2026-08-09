# SONiC BGP gaps

Status: living list
Context: the SONiC port (`sonic-buildimage` branch `zebra-rs-container`)

What SONiC's `bgpcfgd` templates ask for that zebra-rs cannot currently
express, found while translating them from FRR syntax. Each entry says
what SONiC needs it for, what was tried, and what already exists — so the
next person can tell "add a leaf" apart from "implement a feature".

## How these were established

By applying candidate config to a running daemon and checking whether it
was accepted, not by reading the schema. That matters because of two
traps this list has already fallen into:

**`vtyctl apply` exits 0 when the daemon rejects a line.** It prints
`error reply: <line>` on the stream and returns success. Every check here
greps for that marker; an exit-code-only check reports everything as
supported.

**A rejected probe means "not with that syntax", not "not supported".**
Twice a construct was recorded as missing and turned out to exist under
another name — `on-match next` is `action next`, and `soft-reconfiguration`
still might be something. Entries below are therefore split by confidence:
*confirmed absent* means the schema was also checked, *syntax unknown*
means the daemon rejected what was tried but there is evidence the feature
is reachable.

**A batch probe attributes its rejection to the wrong line.** A commit is
atomic, so one bad line discards the batch and every construct in it looks
unsupported. This is how `add-path` came to be listed: the probe's *second*
line said `peer-as` where zebra-rs spells it `remote-as`, and `add-path` on
the third line took the blame. Probe one construct per commit, on top of a
known-good preamble, and confirm the preamble alone is accepted first.

**Group and neighbor are different surfaces.** A knob on
`neighbor <addr>` need not exist on `neighbor-group <name>`; inheritance is
implemented knob by knob. Probe at the level the template actually uses —
for a listen-range group there is no per-neighbor fallback, so only the
group form counts.

## Blocking a template family

These stop a per-role family from being ported at all.

### `maximum-prefix` — confirmed absent

SONiC: `neighbor BGPMON maximum-prefix 1` (monitors, a deliberate
tripwire — a BGP monitor should never receive routes) and
`neighbor <sentinel> maximum-prefix 200`.

Rejected on both a neighbor and a neighbor-group, in every spelling
tried (`maximum-prefix N`, `prefix-limit max-prefixes N`, at the
afi-safi level and above).

Partly built already: `ietf-bgp-common-multiprotocol@2023-07-05.yang`
defines a `prefix-limit-config-common` grouping with `max-prefixes`,
`warning-threshold-pct`, `restart-timer` and friends — but nothing
`uses` it, so it is schema that is not wired into the neighbor or the
neighbor-group. Closing this unblocks **two** families, which makes it
the highest-value item on the list.

Note the enforcement semantics matter as much as the leaf: FRR tears the
session down when the limit is exceeded, and the monitors use of
`maximum-prefix 1` depends on that.

### `send-community` — confirmed absent

SONiC: `neighbor BGPMON send-community` (monitors).

No config path on a neighbor or a neighbor-group, and no
`send_community` anywhere in `src/bgp/`.

Worth establishing before implementing: zebra-rs may already send
standard communities unconditionally, in which case the gap is only a
no-op compatibility leaf rather than behaviour. FRR needs the knob
because it defaults to not sending communities to eBGP peers.

### `update-source <interface>` — confirmed absent

SONiC: `neighbor BGPMON update-source Loopback4096` (monitors, on voq
and chassis-packet).

The address form works — `neighbor-group X update-source <ip>`, and
`neighbor X transport local-address <ip>` — but an interface name is
rejected. SONiC uses the interface form specifically so the source
follows the loopback's address rather than pinning a literal, which a
template cannot always resolve at render time.

## Reachable but not confirmed

### `addpath-tx-all-paths` — semantics unverified

The config surface is **closed** (see below); what remains is a
behavioural question, and it is the one that decides whether the
sentinel actually works.

RFC 7911 `send` is not the same thing as FRR's `addpath-tx-all-paths`.
FRR distinguishes tx-all-paths from tx-bestpath-per-AS; `send` only says
the capability is advertised, not which paths are selected for
advertisement. Which paths zebra-rs actually sends in `send` mode has
**not** been checked against the sentinel use case, which wants *all*
paths. If it advertises only the bestpath, the config is accepted, the
capability is negotiated, and the sentinel quietly sees less than it
asked for — a failure with no error anywhere.

Checking this needs a live session with two paths to one prefix and a
count of what crosses the wire, not another config probe.

## Silently degraded

These are dropped by the porting templates rather than refused, so a
deployment works but does not behave identically. Each is an assumed
equivalence that has **not** been measured.

### `soft-reconfiguration inbound`

SONiC sets it unconditionally on the general peer-groups, on the
sentinels, and on the dynamic speakers. zebra-rs has the capability
internally (`bgp/peer.rs`, `bgp/route.rs` reference `soft_reconfig`) but
exposes no config leaf; several spellings were rejected.

The assumption is that zebra-rs retains received routes for its own
soft-reset handling and the operational effect is nil. That assumption
has not been tested. It is the most likely of these three to be a
non-issue, and the most embarrassing to be wrong about.

### per-neighbour `keepalive`

SONiC emits `neighbor X timers <keepalive> <holdtime>` whenever either
differs from the default. zebra-rs's per-neighbour `timers` container
carries only `connect-retry-time` and `hold-time` — there is no
keepalive leaf, RFC 4271 deriving it from the hold time.

Not hypothetical: bgpcfgd's own `timers_1` fixture sets keepalive 5 with
a default hold time, for which FRR emits `timers 5 180`. Ported, that
peer runs with the default keepalive of 60 instead of 5. Any deployment
that tunes keepalive independently of hold time gets different timer
behaviour.

### `set ipv6 next-hop prefer-global`

SONiC: `route-map FROM_BGP_PEER_V6 permit 1 / set ipv6 next-hop
prefer-global`.

No equivalent leaf. Dropped rather than refused because it is additive
on a session whose peer already sends a global next-hop — but that is
reasoning, not a measurement.

## Outside the policy/neighbour config

### peer-group soft-clear

`bgpcfgd`'s BBR manager calls `clear bgp peer-group <name> soft in` after
changing a group's policy. zebra-rs's `clear bgp` takes a neighbor or
`all` (`zebra-bgp-clear.yang`), not a peer-group.

The bgpcfgd backend refuses rather than widening to `clear bgp all`:
soft-clearing every session because one peer-group's policy changed is an
availability event, not an implementation detail. Closing this needs
either a `clear bgp peer-group` command here, or membership resolution in
the backend.

## Closed during the port

Recorded so the list reads as a state, not a history:

* **`call`** — implemented (`docs/design/policy-call.md`). Needed because
  SONiC's allow-list chain calls a policy that `managers_allow_list.py`
  owns at runtime, so it cannot be flattened at render time.
* **`set tag` / `match tag`** — implemented. SONiC stamps on ingress and
  matches on egress, so the tag persists on the RIB entry.
* **`on-match next`** — was never missing; it is `action next`, and the
  walker has always implemented it. Recorded because it was wrongly
  listed as a gap first, and refusing it would have denied working policy
  to every upstream line card.
* **`add-path` on a neighbor-group** — implemented. The per-neighbor knob
  existed all along (the original probe was invalid, see above), but the
  group's `afi-safi` list carried only `enabled` and `next-hop-self`, so
  the mode could not be inherited. That is load-bearing rather than
  cosmetic: the sentinels group is a **listen range**, whose members are
  materialized on accept, so no per-neighbor statement exists to carry
  the capability. The group opinion resolves with explicit-wins
  precedence, is applied on peer materialization (so a dynamic member
  gets it), bounces an Established member whose mode actually changed
  (ADD-PATH is negotiated in the OPEN), and is resolved on the per-VRF
  path too so the two neighbor surfaces do not drift.

## Not yet examined

The `voq_chassis` and `internal` template families have not been read
yet, so this list is not complete. `internal` uses `set tag`, which now
exists.
