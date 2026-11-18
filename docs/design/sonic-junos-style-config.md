# A Junos-style configuration experience on SONiC — Design

A proposal, not a description of something built. It asks whether `vty` and
zebra-rs can front the whole configuration of a SONiC device — ports, VLANs,
ACLs and routing alike — with a candidate configuration, `commit`, `compare`,
`rollback` and `commit confirmed`, and it recommends how.

Related: [`sonic-zebra-rs-architecture.md`](sonic-zebra-rs-architecture.md)
for what runs today, [`sonic-zebra-rs-plan.md`](sonic-zebra-rs-plan.md) for the
port's plan of record. This document is a direction beyond that plan, not a
phase of it.

Statements marked *measured* were observed on the two-VM `sonic-vs` lab on
2026-11-16. Statements marked *read* come from the source tree and were not
run. Everything else is design.

## 1. Goal

An operator logs in, types `vty`, and configures the device the way they would
a Junos or zebra-rs router:

```
sonic> configure
sonic# set sonic PORT Ethernet0 admin_status up
sonic# set sonic VLAN Vlan100 vlanid 100
sonic# set sonic VLAN_MEMBER Vlan100 Ethernet0 tagging_mode untagged
sonic# show | compare
sonic# commit confirmed 5
sonic# commit
sonic# rollback 1
```

Nothing takes effect until `commit`. A commit is validated as a whole and
either goes in or is refused. Earlier configurations can be compared and
restored. A change that cuts the operator off reverts by itself.

### Non-goals

- Replacing SONiC's own interfaces. `config`, `show`, gNMI, REST, ZTP and
  `config reload` keep working and keep their meaning.
- Changing anything below CONFIG_DB. The daemons that consume CONFIG_DB are
  untouched.
- A Junos configuration *language*. The aim is Junos's transaction model. A
  friendlier hierarchy than SONiC's tables is a later, separable step (§5.2).

## 2. Where things stand

**SONiC.** Configuration is CONFIG_DB, a Redis database of tables. A writer
changes a table and the daemon that subscribes to it reacts. There is no
candidate: a change is live when written. `config checkpoint` and `config
rollback` exist (*read*: `sonic-utilities`, Generic Config Updater); rollback
is applied as an ordered sequence of small CONFIG_DB changes, validated against
SONiC's YANG models, and is not atomic. There is no commit-confirm.

**zebra-rs.** It has the transaction half: a YANG-driven configuration tree, a
candidate and a running configuration, and `commit` that validates the
candidate and dispatches the difference, refusing the whole commit when one
line is rejected. Configure mode has `set`, `delete`, `commit`, `discard`,
`load`, `save`, `compare` and `rollback` (*read*: `yang/configure.yang`), over
a history of the last 50 commits that is kept in memory. It has no `commit
confirmed`.

**zebra-rs on SONiC today.** Routing configuration flows one way:
CONFIG_DB → bgpcfgd → `vtyctl apply` → zebra-rs. Configuration typed into `vty`
goes straight to zebra-rs, is not in CONFIG_DB, and is lost when the `bgp`
container restarts.

**Two facts that shape the design:**

- zebra-rs already exports its commits. `zebra.config.v1.ConfigService/
  Subscribe` (*read*: `proto/config.proto`) streams a snapshot and then one
  event per commit, as `set`/`delete` path changes or as a JSON subtree. An
  out-of-process daemon consumes its part of the configuration this way now.
- zebra-rs has **one candidate, shared by every configure-mode session**. A
  writer that applies a document no longer commits what a session has pending
  in it (§8.1).

## 3. The central decision: who owns the truth

Two designs are possible.

**A. zebra-rs is the master.** Its running configuration is authoritative and
CONFIG_DB is an output it regenerates.

**B. CONFIG_DB stays the master.** zebra-rs holds a mirror of it, edits a
candidate against that mirror, and a commit is a validated write to CONFIG_DB.

**This document recommends B.** The reasons:

- SONiC has many writers to CONFIG_DB that we do not control: the `config`
  commands, gNMI and REST through the management framework, ZTP, `config
  reload`, `load_minigraph`, the config updater, and daemons that write
  CONFIG_DB themselves. Under A each is a second master and the two copies
  drift. Under B each is just another change to the mirror.
- Every existing SONiC procedure — upgrade, warm reboot, `config save`,
  troubleshooting with `sonic-db-cli` — reads CONFIG_DB and stays correct.
- B can be adopted table by table and abandoned without migration. A cannot.

The cost of B is that "commit" means *accepted, validated and written to
CONFIG_DB*, not *applied to hardware* (§6.3). That is a property of SONiC, and
A would not change it.

## 4. Architecture

```
            operator
               │  vty (configure, set, show | compare, commit, rollback)
               ▼
        ┌─────────────────────────────┐
        │ zebra-rs config manager     │
        │  candidate / running        │
        │  subtree `sonic` (mirror)   │◄──── other subtrees (router bgp, …)
        │  commit history             │      stay as they are
        └───────┬─────────────▲───────┘
   pre-commit   │ changes     │ import of external changes
   check, then  ▼             │
        ┌─────────────────────┴───────┐
        │ CONFIG_DB bridge (new)      │   validate against SONiC YANG,
        │                             │   order the changes, write
        └───────┬─────────────▲───────┘
                ▼             │ keyspace notifications
            ┌───────────────────────┐
            │       CONFIG_DB       │◄──── config, gNMI, ZTP, reload, …
            └───────────┬───────────┘
                        ▼
        portsyncd, vlanmgrd, intfmgrd, bgpcfgd, …   (unchanged)
```

Three pieces are new:

1. **A `sonic` subtree** in zebra-rs's configuration, whose schema is SONiC's
   own YANG (§5).
2. **The CONFIG_DB bridge**, which keeps that subtree and CONFIG_DB equal in
   both directions (§6, §7).
3. **Transaction features in zebra-rs** that it lacks today: commit history,
   `rollback`, `compare`, `commit confirmed`, and a candidate that is safe with
   several writers (§8).

## 5. Schema

### 5.1 First: the tables as they are

SONiC ships a YANG model for its tables (*read*: `src/sonic-yang-models`, 147
model files in the tree we build). The first schema is generated from those
models, not written by hand:

| SONiC YANG | In `vty` |
|---|---|
| table container `PORT` with list `PORT_LIST` keyed `name` | `set sonic PORT Ethernet0 …` |
| leaf `admin_status` | `set sonic PORT Ethernet0 admin_status up` |
| list with two keys (`VLAN_MEMBER`: vlan, port) | `set sonic VLAN_MEMBER Vlan100 Ethernet0 …` |
| a table with two lists (`INTERFACE_LIST`, `INTERFACE_IPPREFIX_LIST`) | one keyword for each: `set sonic INTERFACE Ethernet0`, `set sonic INTERFACE_IPPREFIX Ethernet0 10.0.0.0/31` |
| leaf-list (`BGP_PEER_RANGE` `ip_range`) | one `set` line per member |
| a single fixed-key entry (`DEVICE_METADATA` `localhost`) | `set sonic DEVICE_METADATA localhost hostname …` |

**Built** (`zebra-rs/src/config/sonic.rs`, `--feature sonic`). The rule is one
keyword under `sonic` for each list, named after the list without `_LIST`; a
table whose rows have fixed keys stays as it is. Each keyword records the
table and the list it stands for, which is what a row is in CONFIG_DB. Of the
146 modules of the tree we build, 160 tables have one list, 14 have several,
46 have fixed-key rows and one has both; the `sonic-events-*` modules are not
configuration and are left out. No two keywords collide.

Completion comes with the schema: `vty` builds it from the YANG zebra-rs has
loaded, enumerations included. Help is each node's `description`, cut to its
first sentence: zebra-rs takes help from an `ext:help` statement, which
SONiC's models do not have. A string leaf with no `pattern` takes the rest of
the line, since CONFIG_DB holds such values with spaces in them and this CLI
has no quoting.

This is not pretty — it is CONFIG_DB with a transaction around it — but it
covers every modelled table on the first day, needs no per-feature code, and
cannot disagree with SONiC about what is valid.

What it took in zebra-rs and its schema library, none of it particular to
SONiC:

- libyang read none of the models. Twelve forms the grammar refused and three
  faults of the tree it built are fixed in libyang 2.5 (its
  `docs/sonic-yang-gaps.md`).
- The configuration tree had no list with more than one key; 58 of SONiC's
  lists have. An entry is now the node under one key node for each key.
- A string with a `pattern` was the rest of the line, so a patterned key could
  not be followed by a leaf. Patterns were also matched unanchored, which
  refused `10.0.0.0/31` under the usual prefix pattern.
- The block format dropped the characters of a value that are not letters,
  digits or `_.-/:` when loading it: `lanes 1,2,3,4` came back as four values.

### 5.2 Later: a hierarchy people would choose

`set interface Ethernet0 vlan members 100` instead of three table rows needs a
mapping per feature, in both directions, kept current as SONiC's tables change.
SONiC's management framework took this route (OpenConfig models translated to
CONFIG_DB) and the translation layer is where its effort went.

It is deliberately out of the first phases. It can be added one feature at a
time on top of §5.1 — a friendly subtree whose commit rewrites into `sonic`
table lines before the bridge sees them — and the table form stays as the
complete fallback.

### 5.3 What is not in the models

Tables without a YANG model cannot be in the subtree. The bridge leaves them
alone: it writes only keys under tables it has a schema for, and never deletes
a key it does not model. (The config updater has the same boundary, with its
`--ignore-non-yang-tables` option.)

## 6. Commit

### 6.1 Sequence

1. **Baseline.** The `sonic` subtree of the running configuration equals
   CONFIG_DB, kept so by the import path (§7). The candidate starts from it.
2. **Edit.** `set`/`delete` change only the candidate.
3. **`commit`.** zebra-rs runs its own schema validation, then asks the bridge
   to check the resulting `sonic` subtree (pre-commit, §8.3). The bridge
   validates it against SONiC's YANG, including the cross-table constraints
   (a VLAN member needs its VLAN and its port).
4. **Refuse or proceed.** A failed check refuses the commit and changes
   nothing, as a rejected line does today.
5. **Write.** The bridge orders the changes so that every intermediate state
   is valid — create before reference, dereference before delete — and writes
   them to CONFIG_DB.
6. **Record.** zebra-rs stores the committed configuration in its history.

### 6.2 Reuse the config updater for steps 3 and 5

Validation against SONiC's YANG and the ordering of a change set are exactly
what the Generic Config Updater does for `config apply-patch` and `config
replace` (*read*: `generic_config_updater/`: `gu_common.py`, `patch_sorter.py`,
`change_applier.py`, and per-table service validators). The bridge should call
it as a library with "make CONFIG_DB equal this target", not reimplement it.

That brings its limits with it. Sorting a large change is slow, the applier
waits on service validators, and only tables the updater supports can be
changed. Those are acceptable for interactive commits and should be measured
before anything is promised (§11).

### 6.3 What commit means, stated honestly

| Junos | Here |
|---|---|
| Commit is atomic across the device | Atomic in zebra-rs: all of the candidate or none. The write to CONFIG_DB is a sequence. |
| Commit fails if a daemon rejects it | A SONiC daemon applies its table asynchronously and usually reports a failure only in the log. |
| Commit returns when applied | Commit returns when CONFIG_DB is written and the updater's validators pass. |

If the write fails midway the bridge must say so and reconcile: the mirror is
re-imported from CONFIG_DB, so the running configuration shows the device's
real state, and the operator is told the commit was partial. Hiding a partial
write behind a successful `commit` would be the worst outcome of this design.

## 7. Keeping the mirror true

**The import is built, as a whole copy.** A document `{"CONFIG_DB": {…}}`
given to `vtyctl apply` replaces the `sonic` subtree with the translation of
those tables (`zebra-rs/src/config/configdb.rs`): a row goes to the list of
its table that has as many keys as its key has `|`-separated parts, or to the
container of its fixed key. A map (`DSCP_TO_TC_MAP|AZURE` is `{"0": "1", …}`)
is a row whose fields are the entries of the one list its model has inside it,
the field's name being the entry's key: the eleven QoS and cable-length tables
of the tree we build. An import is not a commit of the history, is not
held to the models' mandatory leaves, and leaves out and logs what it cannot
copy. A leaf-list is left out whole when one member of it cannot be held (a
member is one word): the field is one value in CONFIG_DB, and copied in part
it would be written back in part. An import is committed by itself, with
whatever the candidate holds set aside and put back as an edit of the new
running configuration: a session's uncommitted edits, or a startup
configuration whose commit was refused and that waits to be completed. *Measured* on a SONiC VS: all 21 tables of its CONFIG_DB are modelled,
306 rows became 1,282 lines, two values were left out (an empty string and one
of several lines), and a `config vlan add` on the host showed in the running
configuration at the next copy. What follows is the design for the rest: the
process that reads CONFIG_DB is so far a script that polls, and nothing below
about open candidates, coalescing or echo is built.

CONFIG_DB changes that did not come from a commit — a `config` command, gNMI,
a daemon — must reach zebra-rs, or `compare` and `rollback` lie.

- The bridge subscribes to CONFIG_DB keyspace notifications and applies each
  external change to the `sonic` subtree of the running configuration.
- An import is not a commit by an operator. It must not create a rollback
  point on every keystroke of someone's script; imports are coalesced, and
  recorded in the history as external changes.
- **Open candidates.** If an operator has uncommitted edits when an external
  change arrives, the candidate is rebased onto the new baseline. A conflict —
  both changed the same leaf — is reported at `commit`, which is refused until
  the operator resolves it. Junos's private candidate behaves this way: a
  commit is refused when the database changed underneath it, until the
  operator updates. zebra-rs rebases already (§8.1), but settles a conflict
  for the applied value without a word; reporting it, and refusing the commit,
  needs the per-session candidate of §8.1.
- **Echo.** The bridge sees its own writes come back as notifications and must
  not import them as external changes.

At start, the mirror is built from CONFIG_DB before the first session is
accepted. `/etc/zebra-rs/zebra-rs.conf` does not carry the `sonic` subtree:
persistence of SONiC configuration stays `config save` and `config_db.json`
(§9).

## 8. What zebra-rs needs first

### 8.1 A candidate per session — the apply half is done

*Measured, before the fix.* zebra-rs has one candidate. An uncommitted `set`
typed in one configure session was committed by an unrelated `vtyctl apply`
from another writer:

```
session 1:  set router bgp neighbor 10.0.0.1 description shared-candidate-probe   (no commit)
session 2:  vtyctl apply  →  set router bgp neighbor 10.0.0.3 description other-writer
running:    both lines present
```

On a zebra-rs SONiC image that was live: bgpcfgd applies a batch whenever
CONFIG_DB changes, and it published whatever an operator had half-typed in
`vty`.

**Closed for an apply.** An apply now commits only its own lines
(`ConfigManager::deploy`). When the candidate holds uncommitted edits it sets
them aside, runs its document on a copy of the running config and commits
that. The edits are then put back as edits of the new running config: what the
commit changed is changed in them too (`zebra-rs/src/config/rebase.rs`, which
states what becomes of an edit the commit meets). A refused apply leaves the
edits as they were. *Measured* on a SONiC VS with the first version of the
fix: an uncommitted neighbor description stayed out of the running config
while bgpcfgd committed a static route. The version that is merged has run in
the unit suite and BDD only.

What that does not give:

- **Sessions still share one candidate.** Two operators in configure mode edit
  the same tree, and either one's `commit` commits both. So does `load`.
- **A conflict is settled, not reported.** Where an apply and an edit set the
  same leaf, the candidate takes the applied value and the operator is not
  told. The rebase of §7 wants the commit refused until the operator has looked.
- **A whole-config document** (CLI block, JSON, YAML) replaces the
  configuration and the pending edits with it. Only an apply of `set`/`delete`
  lines keeps them.

What remains to build is therefore the private candidate per session (Junos
`configure private`), with the machine writers — bgpcfgd's `vtyctl apply`, and
the bridge — each using their own. A global configure lock (`configure
exclusive`) is simpler and is not enough here, because bgpcfgd must never be
blocked by an idle operator.

### 8.2 History, compare, rollback, commit confirmed

- **History** is built, in memory: the configurations of the last 50
  commits, with the time and the revision of each (`show commit history`). A
  commit's number is its place in the list and moves with every commit after
  it; its revision (`<daemon start>-<count>`) does not, and is what a writer
  that is not alone on the box names a commit by. Still to do: keep it
  across a restart, and record the user and a comment (`commit comment
  "…"`).
- **`show | compare`** is built: configure mode has `compare` and `compare
  formal`, and `show | compare` reaches the same command. `compare rollback
  N` compares the candidate with commit N.
- **`rollback N`** is built, and `rollback revision ID` beside it. It loads
  that configuration into the candidate and takes effect on `commit`, like
  any other change, and so goes through the same validation and ordered
  write.
- **`commit confirmed M`** commits, then reverts after M minutes unless a
  plain `commit` arrives. The revert must survive the loss of the session that
  asked for it — that is the case it exists for — so the timer belongs to the
  daemon, not the shell.

These are useful to zebra-rs off SONiC as well and can ship first.

### 8.3 A pre-commit check by an external party

`ConfigService/Subscribe` delivers after the commit, by design. The bridge
needs to be asked *before*: "would this subtree be acceptable?", with the power
to refuse and a message for the operator. That is a new RPC, with a timeout and
a defined answer when the checker is absent (refuse changes to `sonic`; let
everything else through).

### 8.4 Ownership of a subtree

Under this design some configuration in zebra-rs is derived, not typed: the
`router bgp …` lines that bgpcfgd writes from `BGP_NEIGHBOR`. If the operator
edits them directly, the next bgpcfgd batch may overwrite the edit, and the
edit is not in CONFIG_DB. zebra-rs needs to know which writer owns which
subtree, and to refuse or warn on an edit by anyone else. §10 uses this.

## 9. Persistence

| What | Where it is saved | By |
|---|---|---|
| The `sonic` subtree | CONFIG_DB, then `config_db.json` | the bridge writes CONFIG_DB; `config save` persists it |
| Commit history | zebra-rs's own store, outside the container's ephemeral filesystem | zebra-rs |
| Native zebra-rs configuration | `zebra-rs.conf`, re-rendered from CONFIG_DB at container start | unchanged |

Two consequences to settle in the open questions: whether `commit` should
imply `config save` (Junos persists on commit; SONiC does not), and where the
history lives so that it survives a restart of the `bgp` container.

## 10. Routing configuration

BGP is the one area with a loop. If the operator writes `set sonic BGP_NEIGHBOR
…`, the bridge writes CONFIG_DB, bgpcfgd reads it and applies `router bgp …`
to the same zebra-rs. That works and needs no new code: bgpcfgd is just another
CONFIG_DB consumer.

What must be prevented is the second path, editing `router bgp …` directly.
Three stages:

1. **First:** the native routing subtrees stay writable as today, with the
   known limit that such edits bypass CONFIG_DB. Nothing regresses.
2. **Then:** with §8.4, the lines bgpcfgd owns are read-only to operators, who
   are pointed at the `sonic` tables.
3. **Eventually, for features SONiC has no table for** — IS-IS, OSPF, most of
   BGP policy — native configuration is the only way, and it has to persist. A
   single opaque CONFIG_DB entry holding that configuration, restored by
   `docker_init.sh`, would give it `config save` and reload without modelling
   it in SONiC. This is the piece that turns zebra-rs's wider feature set into
   something a SONiC operator can use, and it deserves its own design.

## 11. Where the bridge runs

| | In the daemon | Separate process (recommended) |
|---|---|---|
| Redis and SONiC libraries in zebra-rs | Yes | No |
| Reuse of the config updater (Python) | Awkward | Direct: the bridge can be Python |
| A fault in the bridge | Can take routing down | Cannot |
| zebra-rs off SONiC | Carries dead code | Unaffected |
| Pre-commit check | A function call | An RPC (§8.3) |

A separate process in the `bgp` container, under supervisord, next to bgpcfgd.
It uses the interfaces zebra-rs already serves — `Subscribe` for commits,
`Apply` for imports — plus the one new pre-commit RPC. This is the same shape
as bgpcfgd and as the existing out-of-process subscriber, and it keeps SONiC
out of the daemon.

The generated schema (§5.1) is the one SONiC-specific thing zebra-rs loads, and
it loads it as data: YANG files in the image, present only on SONiC.

## 12. Phases

Each phase is useful on its own and none commits us to the next.

1. **zebra-rs transaction features**, no SONiC involved: per-session candidate
   (§8.1; the hazard it was to close is closed for an apply already), history,
   `compare`, `rollback`, `commit confirmed`.
2. **Read-only mirror.** The `sonic` subtree generated from SONiC's YANG, the
   bridge importing CONFIG_DB. `show configuration sonic …` in `vty` with
   completion and help; no writes. Proves the schema generation and the import
   path, and is safe. *The schema and the import are built (§5.1, §7), and
   the subtree is read-only: a session's `set sonic …` is refused and pointed
   at SONiC's `config` command, `save` leaves the subtree out, and `rollback`
   keeps it as CONFIG_DB has it now. So does a document that is a whole
   configuration given to `vtyctl apply` (block format, JSON, YAML): it
   replaces what was configured here and leaves `sonic` as it is running. Still to do, outside zebra-rs: the
   process that follows CONFIG_DB by its keyspace notifications, and the
   models in the `bgp` container's image.*
3. **Commit for a few tables**: *the first half is built.* `sonic` is edited
   in the candidate, and `compare config-db` gives the pending edits as the
   JSON Patch that SONiC's `config apply-patch` takes; a `commit` of them is
   still refused and says so. *Measured* on a SONiC VS: a VLAN, an MTU, a
   description and an interface address typed in `vty`, applied on the host
   with `config apply-patch`, were in CONFIG_DB and the kernel, and the copy
   that followed left nothing pending.

   *`commit` now does that itself.* A commit that changes `sonic` hands the
   patch to a writer on the device and is made when the writer answers
   (`proto/configdb.proto`, `zebra-rs/src/config/writer.rs`). The writer is a
   script on the host, where SONiC's updater is: it takes each order with
   `vtyctl config-db wait`, runs `config apply-patch`, and answers with
   `vtyctl config-db done`. A refusal by the updater is the commit's refusal,
   word for word; with no writer connected the commit is refused at once.
   The commit is parked while the writer works and the config task goes on:
   `config apply-patch` begins by asking zebra-rs for its running config
   (`show runningconfiguration all` runs `vtysh -c 'show running-config'`),
   and held, the two waited for each other. *Measured* on a SONiC VS: a
   commit of a VLAN, an MTU, a description and an address took 6.1 s and
   was in CONFIG_DB and the kernel; a member of a VLAN that does not exist
   was refused with the updater's leafref error; the changes were undone
   by a second commit.

   What such a commit is held to:

   - **The writer is whoever may commit.** `Wait` and `Done` need the admin
     role of the vty socket, as `vtyctl apply` does: the writer runs as root.
     A commit is made on the writer's word, so a caller without the role
     neither takes an order nor answers for one. A writer is there while it
     waits, and for 15 seconds after its last wait or answer: an order may
     take longer to apply than that.
   - **No patch before the first copy.** Until CONFIG_DB has been copied once
     the running subtree is empty because nothing is known, and a row typed
     then would be added as the first of its table, replacing the table.
     `compare config-db` and `commit` say so and do nothing.
   - **A patch knows what the copy left out.** A table is added with its first
     row and removed with its last, and which those are is CONFIG_DB's to say.
     zebra-rs keeps the keys of the rows the last copy had and the subtree
     does not (a key no list takes, a row the model refuses, a table with no
     model). A table that has such a row is neither added nor removed, and a
     row that is there is not added: its fields are.
   - **Nothing is written that the patch does not say.** What is typed under
     `sonic` and is no row and no field of one (an entry of a map with no
     value; in a model that has them, a leaf of `type empty` or a container
     in a row) has no form in CONFIG_DB. The commit is refused and names the
     lines.
   - **Refused before the write, or said after it.** Every check of a commit
     runs before the writer is asked, on the candidate as it will be
     committed. A commit can still be refused when the writer has answered,
     if another writer committed meanwhile what it cannot be beside; the
     refusal then says that CONFIG_DB has the change.
   - **The candidate is held while the writer works.** The commit is made of
     the candidate when the writer has answered, with `sonic` open to it. An
     edit typed meanwhile would be committed here without having been
     written, so `set`, `delete`, `discard`, `rollback`, `load` and a second
     `commit` are refused until the commit is made; `show` and `compare` are
     answered. This is per daemon while there is one candidate (§8.1).

   Not closed: the patch is made against CONFIG_DB as of the last copy. A
   change another writer makes after that copy and before the commit is not
   seen, and where it created a table the commit also creates, the commit's
   `add` of the table replaces it. JSON Patch has no test for "not there";
   closing this needs the writer to make the comparison, or a copy taken as
   part of the commit.

   Not done: the writer as a service of the image; `commit confirmed` and
   `rollback` of a change of CONFIG_DB (an earlier commit is still taken
   with `sonic` as it is now); and such a commit in `show commit history`
   when the copy of CONFIG_DB lands before the commit is made here, which
   it usually does. The plan was:
   `PORT`, `VLAN`, `VLAN_MEMBER`, `INTERFACE`,
   `STATIC_ROUTE`, `BGP_NEIGHBOR`. Pre-commit check, ordered write through the
   config updater, partial-write handling. Measure commit latency.
4. **All modelled tables**, and conflict handling for external changes during
   an open candidate.
5. **Ownership** of derived subtrees (§8.4, §10 stage 2).
6. **Native configuration that persists** (§10 stage 3) and a friendlier
   hierarchy (§5.2), each its own design.

## 13. Open questions

1. **Can zebra-rs load SONiC's YANG as it is?** *Answered: yes, from libyang
   2.5 on.* All 146 modules load. `must` (281 uses), `when` (131) and the
   targets of leafrefs (211) are parsed and not enforced, which is left to
   the bridge's pre-commit check as planned.
2. **How slow is a commit through the config updater?** *Measured* on a
   SONiC VS, `config apply-patch` from the shell: one leaf 2.8 s, one new row
   2.8 s, a leaf on each of 32 ports 3.6 s, `config rollback` to a checkpoint
   4.4 s. A dry run of the 32-port patch is 2.0 s, so most of each is starting
   the command and loading the models, not the change: called as a library by
   a process that stays up, it should be well under a second for a small
   change. Good enough for a commit an operator types. The updater is on the
   host only; the `bgp` container does not have it.
3. **Does `commit` imply `config save`?** Junos operators expect a committed
   configuration to survive a reboot. SONiC separates the two on purpose.
4. **Multi-ASIC and chassis.** CONFIG_DB is per namespace and there is one
   `bgp` container per ASIC. Whether one `vty` session spans them, and where
   the mirror lives, is not addressed here.
5. **Where does `vty` run?** A box-wide configuration front end living in the
   `bgp` container is odd, and restarting that container would drop the
   operator's session. A host-side or dedicated container for the config
   manager may be right once it fronts more than routing.
6. **Authorization.** SONiC has its own users, roles and TACACS+; zebra-rs has
   its own `enable` and PAM path. One has to follow the other.
7. **gNMI.** If zebra-rs becomes the transactional front end, the management
   framework's gNMI writes still go around it. Acceptable under design B, but
   it means two northbound paths with different guarantees.

## 14. Risks

- **A commit that claims more than happened.** The gap between "written to
  CONFIG_DB" and "applied" (§6.3) is the central weakness. The mitigation is to
  say exactly what commit guarantees, and to surface a partial write loudly.
- **Dependence on SONiC internals.** The schema and the config updater change
  between SONiC releases. Generating the schema and calling the updater as a
  library, not copying either, keeps that cost in one place.
- **Scope.** This is a product direction, larger than the routing port. The
  phases are ordered so that the first one is worth doing for zebra-rs alone.
