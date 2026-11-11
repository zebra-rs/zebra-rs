# `system hostname` sets the real host name (with `--feature insomnia`)

**Status: all three steps (§11) are implemented.** Steps 1 and 2 are in
this repository; step 3 is in the insomnia repository. The decisions in
§12 were all taken as recommended (2026-11-11). Where the code turned out
different from what this document first assumed, the text says what was
built.

Today `set system hostname r1` is a label inside the daemon. It changes
the vty prompt, `show hostname` and the DHCP client's option 12, and
nothing outside zebra-rs: `hostname` in a shell still prints the old name.
That is the right behaviour when zebra-rs is a routing daemon on somebody
else's server (the FRR model, chosen on purpose in #1838).

When zebra-rs runs with `--feature insomnia` it is the configuration owner
of the whole box (firewall, IPsec, VRRP, DHCP server), and a hostname that
does not reach the operating system is a surprise. This document proposes
that, with the feature on and zebra-rs running in the default network
namespace, a committed `system hostname` becomes the system's host name:
the kernel name and `/etc/hostname`. Without the feature, or in any other
network namespace, nothing changes.

---

## 1. Goals and non-goals

**Goals**

- With `--feature insomnia`, after `set system hostname r1` and `commit`:
  - `hostname`, `uname -n` and `hostnamectl` report `r1` at once;
  - the name is still `r1` after a reboot, from the start of the boot.
- `delete system hostname` gives the box back the name it had before
  zebra-rs took it over.
- Without the feature, zebra-rs never touches the OS host name.
- Only a zebra-rs in the default network namespace changes it. One
  started by `ip netns exec` never does, with or without the feature.
  That covers every BDD run.
- No new dependency, no D-Bus, no child process.

**Non-goals**

- `system domain-name`, `system static-host-mapping`, and managing
  `/etc/hosts` in general (§8 covers the one line that matters).
- Taking the host name from a DHCP lease (option 12 from the server).
- Watching for somebody else changing the name later (`hostnamectl
  hostname foo` by hand). The configured name is applied when it is
  committed and when zebra-rs starts, not continuously.
- A pretty hostname, chassis type, or anything else `hostnamectl` holds.

---

## 2. Where things stand

**The leaf.** `system hostname` (`config.yang`) is a string with the
pattern `[A-Za-z0-9][A-Za-z0-9.-]*`. It is not gated on any feature, and
it has no length limit.

**Who reads it** (before this work; §7 has what steps 1 and 2 changed)

| Consumer | Source |
|---|---|
| vty prompt | `system hostname`, else `$(hostname)` (`ExecReply.hostname`) |
| `show hostname` | `system hostname`, else the OS name (`rib/show.rs`) |
| DHCP client option 12 | interface `host-name`, else `system hostname` |
| IS-IS TLV 137 | `router isis hostname`, else the **OS** name |
| BGP FQDN capability | `router bgp … hostname`, else the **OS** name |
| Elasticsearch-format log records | the OS name, read per record |

The RIB task stores the value (`Rib::hostname_config`,
`hostname_config_exec`), whose comment says "no `sethostname(2)`, no OS
side effects". IS-IS and BGP do not look at `system hostname` at all, so a
router named `r1` in the config can advertise the image's name in its LSPs.

**The feature.** `--feature insomnia` is known only to `ConfigManager`,
which uses it to prune the YANG tree. No runtime code path asks whether a
feature is on. The feature's description says it covers configuration
"that zebra-rs stores but does not enforce itself".

**Facts checked on the dev box** (Ubuntu 24.04, systemd 255):

- `ip netns exec` and `unshare -m` both leave the process in the host's
  UTS namespace: `/proc/self/ns/uts` was `uts:[4026531838]` in a fresh
  network namespace, under `unshare -m`, and for PID 1. Both BDD harnesses
  (zebra-rs's and insomnia's) start daemons this way. A `sethostname(2)`
  from any of them would rename the development machine.
- Inside `unshare --uts` a 64-character name is accepted and a
  65-character name is refused ("name too long"). Setting the name there
  left the host's name unchanged.
- `/proc/1/ns/*` cannot be read without root.
- `zebra-rs.service` runs as root with no `ProtectHostname=` and no
  capability bounding set, so the daemon can call `sethostname(2)`.
- The Makefile `run` target starts zebra-rs as the invoking user with
  network file capabilities only. It has no `CAP_SYS_ADMIN`, so it cannot
  rename the box even with the feature on.

**Not checked** (it needs a throwaway VM with a real systemd, because it
changes the real name): that journald, systemd-resolved and `hostnamectl`
pick up a direct `sethostname(2)` and a rewritten `/etc/hostname` without
a restart. The systemd sources say they do (journald and resolved poll
`/proc/sys/kernel/hostname`; hostnamed re-reads `/etc/hostname`). §10 has
this as the manual step that remains. The call itself and the file were
checked in a sandbox (§10).

---

## 3. Who applies the name: zebra-rs itself

**Recommendation: the RIB task in zebra-rs applies it.** The insomnia
daemon is not involved.

Reasons:

- It is kernel state plus one small file, the same kind of thing the RIB
  task already owns (links, addresses, sysctls). The trees insomnia
  enforces are different: each one renders a config for a separate service
  and supervises it.
- Every in-daemon reader of the name (IS-IS, BGP, the DHCP client, the
  logger, the prompt) lives in zebra-rs. Applying it in the same process
  lets a later step (§7) tell them when the name changes. An external
  daemon would change the name behind their backs.
- It works with the feature on and the insomnia daemon stopped, crashed
  or not installed yet.
- `sethostname(2)` acts on the caller's own UTS namespace, so a daemon in
  a container names the container and not the host.

**Alternative considered: the insomnia daemon** subscribes to
`/system/hostname` over `zebra.config.v1` and applies it. This keeps the
sentence "zebra-rs stores, insomnia enforces" true without exception, and
needs no runtime feature check in zebra-rs. Against it: the name is applied
only while insomnia runs, the leaf is not feature-gated so the condition
"with feature insomnia" would hold only by convention, and zebra-rs's own
readers cannot be told about the change.

**Alternative rejected: `hostnamectl` or the hostnamed D-Bus API.**
hostnamed changes the name of the namespace *it* runs in, which is the
host's, whatever namespace the caller is in. A daemon in a container or a
test namespace would rename the wrong machine. It also needs a bus, polkit
and a timeout, and is absent from minimal images.

Consequence: the feature description in `zebra-features.yang` gains one
sentence, and `system hostname`'s help and the `hostname_config_exec`
comment are corrected.

---

## 4. What is changed

Two things, both only while `system hostname` is in the running config:

1. **The kernel host name**, with `sethostname(2)` (the `hostname`
   crate's `set`, already a dependency for reading the name). This is what
   `hostname`, `uname -n` and every new process see.
2. **The static host name**, `/etc/hostname`: one line, the name and a
   newline, mode 0644. systemd reads it early in the boot, so the next
   boot has the right name before zebra-rs starts. Without this the
   console login prompt and the first seconds of the journal carry the
   image's name on every boot.

The file is replaced atomically (temporary file in `/etc`, `fsync`,
`rename`, then `fsync` of the directories, see §6). When the rename is
refused because `/etc/hostname` is itself a mount point (`EBUSY`; Docker
bind-mounts it), the applier falls back to rewriting the file in place. No
other failure falls back: the point of the atomic write is that a full
disk leaves the old name in the file.

The value is applied as configured. A short name is recommended; a dotted
name works but Linux expects the kernel name to be a single label.

**What is not changed:** `/etc/hosts` (§8), `/etc/machine-info`, running
processes that cached the old name (open shells, rsyslog until its next
reload).

---

## 5. The feature switch and the namespace rule

**Switch.** `main.rs` resolves the feature once, through the same alias
table `ConfigManager` uses (so `--feature iso` counts), and hands the RIB
an applier only when it is on:

```
Rib::system_hostname: Option<SystemHostname>   // None without the feature
```

With `None` the RIB behaves exactly as it does today. This is the first
runtime behaviour that depends on a YANG feature. The helper that answers
"is `zebra-features:insomnia` on" sits next to `feature_spec` in
`config/manager.rs` (`config::feature_enabled`).

**Namespace rule (decided 2026-11-11): the default network namespace
only.** The feature alone is not enough: insomnia's BDD scripts start
zebra-rs with `--feature insomnia` inside `ip netns exec`, where the UTS
namespace is the host's (§2). So the applier works only when zebra-rs runs
in the default network namespace, and the test is one comparison at
start-up:

```
readlink(/proc/self/ns/net) == readlink(/proc/1/ns/net)
```

- Equal: this is the box's own daemon. Apply.
- Different: this instance was started in a network namespace of its own
  (`ip netns exec`: every BDD daemon, or one daemon per namespace on a
  shared host). **Never apply.**
- Unreadable: never apply. That is a non-root zebra-rs (`make run`),
  which could not call `sethostname(2)` anyway, and any system without
  `/proc`.

"Default" here means PID 1's namespace as this process sees it. In a
container PID 1 is the container's init, so a zebra-rs there is in the
container's default namespace and names the container.

The name-server work in progress (branch `dhcp-dns-server`) guards
`resolvectl` with the same comparison. Whichever lands second moves it
into one shared helper.

When the rule says no, the applier logs one line at start-up and does
nothing afterwards: no syscall, no file, no record. The rest of
`system hostname` (prompt, `show hostname`, option 12) works as before.

A unit file with `ProtectHostname=` would put the daemon in a private UTS
namespace while it stays in the default network namespace, and the name
would not reach the host. The shipped unit has no such line and must not
gain one.

There is no opt-out knob in this design. An operator who wants insomnia's
trees but manages the host name elsewhere leaves `system hostname` unset.
§12 asks whether that is enough.

---

## 6. Applying, restoring, and the saved name

**Module.** `zebra-rs/src/rib/hostname.rs` holds `SystemHostname`, the
`Backend` it writes through, and `reconcile`. The RIB's existing
`/system/hostname` handler keeps storing the value; the applier runs at
`CommitEnd`, not at the `set` line. A commit that replaces the name (a
delete and a set) then applies once, and candidate edits do nothing.

**Saved name.** The first time zebra-rs takes the name over it records
what was there:

```
/var/lib/zebra-rs/system/hostname.json
{"static": "debian", "kernel": "debian"}      // "static": null when /etc/hostname was absent
```

**Stand-in for tests.** The applier reaches the system through a small
backend: read and set the kernel name, read and replace the static name,
read and write the record. `ZEBRA_HOSTNAME_STUB_DIR=<dir>` selects a
file-backed backend instead of the real one: `<dir>/kernel`,
`<dir>/hostname` and `<dir>/saved.json`. It never calls `sethostname(2)`
and never opens `/etc/hostname`, so it is safe in any namespace and the
namespace rule does not apply to it. Its kernel name before anything set
one is `localhost`, and it has no static name. Unit tests use the same
backend on a temporary directory. The two backends share the file code;
only the kernel name differs (a syscall or a file).

The daemon writes there as root, so the directory must be one nobody else
can rearrange. The BDD harness uses `/run/zebra-rs-bdd/hostname/<ns>`, not
a predictable name under world-writable `/tmp`, where another user could
put a symbolic link first. zebra-rs also turns away a stand-in that is a
symbolic link or belongs to another user, creates its temporary files
with `O_EXCL`, and never follows a link when it writes.

**Reconcile**, with `wanted` = the running config's name:

| `wanted` | Record | Action |
|---|---|---|
| `r1` | absent | write the record, then apply `r1` |
| `r1` | present | apply `r1` (the record is left alone) |
| none | present | restore the saved name, then remove the record |
| none | absent | nothing |

"Apply" compares first: the file is rewritten only when its content
differs and `sethostname(2)` is called only when the kernel name differs.
A restart with an unchanged config writes nothing.

"Restore" writes the saved static name back to `/etc/hostname` (or removes
the file when there was none) and sets the kernel name to the saved static
name, or to the saved kernel name when there was no file.

`/etc/hostname` is read as systemd reads it: the first line that is
neither empty nor a comment. A file that already says the name is not
rewritten, whatever else it holds.

A record that does not parse stops the applier, with the error in
`show hostname`. Treating it as absent would make the next takeover save
the name zebra-rs itself had set.

**Order**, so that a crash between two steps is repaired by running the
same reconcile again: record, file, kernel when applying; file, kernel,
record removal when restoring.

**On disk, not only in view.** The order protects the saved name only if
"record first" means the record has reached the disk. Otherwise a power
failure can keep the new `/etc/hostname` and lose the record, and the next
start saves zebra-rs's own name as the one to give back. (A review of the
first implementation found exactly this: the directory sync after the
rename was best effort, and a directory created for the record was never
synced.) Three rules:

- **A write returns only once it is on disk.** After the rename, the
  file's directory and every directory above it are synced, up to `/`.
  All of them, because an entry survives only if each entry leading to it
  does, and which are already on disk is not known: `system`, or
  `zebra-rs` on a fresh install, may have been created a moment ago by
  this write, or by a run that was interrupted before it synced anything.
  Syncing a directory with nothing pending costs nothing. A removal is
  synced the same way.
- **A failure to sync fails the write**, so `reconcile` stops before the
  next step. One failure is excused: `EINVAL` from `fsync(2)`, a
  filesystem saying it has no way to sync a directory.
- **A value found in place is synced before it is relied on.** A write
  that failed, or a run that was killed between the rename and the sync,
  leaves the new value in view, and the rerun finds nothing to write. So
  the rerun syncs what it finds: the record before the name it holds is
  overwritten, the restored name before the record is removed, and the
  absence of a record when there is none (a removal that came back with
  the power would be "restored" over whatever the system was called
  since). A start with nothing to change therefore makes about ten
  `fsync` calls on clean files, and no write.

**When it runs**

- At every `CommitEnd` in which the hostname line was touched.
- At the first `CommitEnd` after start, whether or not the file set a
  hostname. This is what restores the saved name when the line was removed
  from the config file while zebra-rs was down. `load_config` commits even
  an empty or missing start-up file, so that commit always comes. (This
  document first said the empty file skips the commit; it skips only the
  parsers.) The one start with no commit is a start-up config that
  validation rejects. Nothing of it is applied, the hostname included.
- At the next `CommitEnd` of any kind after a failure.

**Failure.** `EPERM` (an unprivileged container) or an unwritable `/etc`
is logged as an error and shown by `show hostname` (§9). The commit is
not refused: the value is valid, and the applier runs after the commit,
like every other kernel install. The next commit tries again, whatever it
is about, because the operator cannot commit the same name twice. The
error is logged once and not at every retry.

**Turning the feature off** while `system hostname` is still configured
leaves the box with the last applied name and leaves the record in place.
A zebra-rs without the feature must not touch the name, so it cannot
restore it either. Turning the feature back on resumes where it stopped.

---

## 7. Readers inside zebra-rs (second step)

With the first step alone, IS-IS and BGP followed the new name only
because they read the OS name, and nothing told them it changed:

- IS-IS re-read it at the next LSP origination. After a rename the old
  name stayed in TLV 137 until something else regenerated the LSP or the
  refresh timer fired, 15 minutes later.
- BGP sends the FQDN capability in OPEN, so a session keeps the old name
  until it is re-established. This is how `router bgp global hostname`
  behaves too, and is not changed.
- Neither looked at `system hostname` at all. Without the feature a
  router named `r1` in the config advertised the machine's name.

**As built.** `system hostname` is now the name a protocol advertises
when it has none of its own: *protocol hostname → `system hostname` → OS
name*, with or without the feature.

- **The RIB tells the protocols** with `RibRx::HostnameUpdate(Option<String>)`,
  the pattern of `RouterIdUpdate`. It goes to every subscriber, whatever
  its VRF, at the end of a commit that changed the name. Not at the `set`
  line: a commit replacing the name would pass through "no name", and
  IS-IS would regenerate its LSP with the OS name and again with the new
  one. A protocol that subscribes later is told the committed name then.
- **The system is renamed first** (step 1 runs before the message is
  sent), so a protocol reading the OS name on being told reads the new
  one.
- **The message is sent again, unchanged, when only the system's name
  moved.** That happens when a failed apply is retried at a later commit.
  A router with neither a protocol hostname nor a system hostname
  advertises the OS name, and has to learn that it changed.
- **IS-IS** keeps the value in `IsisConfig::system_hostname` and
  regenerates the self LSP at each level whose LSP carries another name.
  It compares with the name the LSP was built with, not the stored value
  with the new one: the OS name is read when asked for, so a renamed
  system resolves to the new name before and after.
  `router isis hostname` goes through the same check.
- **BGP** keeps it in `Bgp::system_hostname` and refreshes every
  neighbor's snapshot (`Peer::local_hostname`), which is what the next
  OPEN advertises.

Not changed: per-VRF BGP sessions send no FQDN capability at all
(`bgp/vrf/spawn.rs` creates their peers without a hostname). That was so
before and is a separate matter. OSPF has no hostname to advertise.

**The change every router sees:** one with `system hostname r1` on a
machine called `debian`, and no protocol hostname, advertises `r1` where
it advertised `debian`.

---

## 8. `/etc/hosts`

Debian installs carry `127.0.1.1 <name>` in `/etc/hosts`. After a rename
that line still names the old host. Where systemd-resolved or
`nss-myhostname` is in use, the new name resolves anyway. Where neither
is, `sudo` prints "unable to resolve host r1" and `hostname -f` fails.

Checked in a sandbox (a private UTS namespace and an overlay on `/etc`,
with the dev box's `hosts: files mdns4_minimal [NOTFOUND=return] dns`):
after a rename `getent hosts <name>` fails and `sudo` prints
`unable to resolve host <name>: Temporary failure in name resolution`;
with `myhostname` at the end of the `hosts:` line both work.

**`/etc/hosts` is not edited.** It is an operator-owned file with
free-form content. Instead a package recommends `libnss-myhostname`,
which resolves the local name whatever it is. Its install script appends
`myhostname` to the `hosts:` line of `/etc/nsswitch.conf`.

**As built (step 3): the insomnia package carries the `Recommends`, not
zebra-rs's.** The insomnia package is what turns the feature on (its
`zebra-rs.service` drop-in), so it is installed exactly where the name is
applied. zebra-rs's own package is also installed where the feature is
off, and there a `Recommends` would edit `nsswitch.conf` for nothing.

If that turns out not to be enough, a later step rewrites only a
`127.0.1.1` line whose name is the previous host name, and leaves every
other shape of the file alone.

---

## 9. Validation and show

**Validation.** The kernel refuses names longer than 64 bytes, and the
pattern allows values that are not host names (`r1..x`, `r1-`, `r1.`). A
value check for `/system/hostname` in `config/check.rs` requires:

- 1 to 64 characters in total;
- labels separated by single dots, each 1 to 63 characters of
  `[A-Za-z0-9-]`, not starting or ending with a hyphen.

It is registered as a start-up-tolerant check, like the ESI check: a
commit with a bad name is refused, a start-up file that an earlier release
accepted is loaded with a warning, and the applier skips a name that fails
the check (the system keeps the name it has; the saved one is not
restored). The check applies with and without the feature; one rule is
simpler than two and the stricter set is what every reader expects.

**Show.** `show hostname` keeps printing one line, the name. When the
feature is on and the OS name is not the configured one, a second line
says why:

```
r1# show hostname
r1
% not applied to the system: sethostname: Operation not permitted
```

The other reasons are the namespace rule's ("zebra-rs is not in the
default network namespace") and, when the name was applied and somebody
changed it since, "the system's host name is foo". A failed restore reads
`% not restored on the system: …`.

The JSON form gains three fields next to `hostname`: `managed` (bool:
this zebra-rs writes the system's name, so false without the feature and
false when the namespace rule said no), `os` (the system's name) and
`reason` (string or null).

---

## 10. Testing

**Unit tests** (no root, no real `/etc`):

- The validator's accept and reject sets.
- The namespace rule as a pure function of the two namespace identifiers
  (equal, different, unreadable).
- `reconcile` on an in-memory system that also models the disk: set,
  change, delete, an absent static name, and at every write of both
  orders a crash and a write that stays in view but misses the disk, each
  followed by a rerun. A property test adds a power failure after each of
  those and requires that the next delete gives back the name found. The
  model panics when the system's name is written while the record is not
  on disk, or the record removed while the restored name is not.
- The file code on the stand-in in a temporary directory: what is read as
  a name, the 0644 mode, the in-place write, a failed write leaving the
  old content, a record that does not parse, a directory sync failure
  failing the write and the removal, and the list of directories synced
  for a path.
- The RIB's commit path on the stand-in: applied at the commit's end and
  not at the `set` line, a replacing commit, the start-up commit without
  the name, the retry after a failure, and `show hostname` in each state.
- The feature helper: `insomnia`, the `iso` alias, `zebra-features:insomnia`,
  and off.
- The commit check: a bad name refused, the same name in a start-up
  config only warned about.

**BDD** (zebra-rs harness, feature `system_hostname_os`). Every BDD
daemon runs in a network namespace of its own, so under the rule in §5
none of them can apply the real name. Two kinds of scenario follow from
that.

*Through the stand-in*, for the path from the config to the applier:

- The harness sets `ZEBRA_HOSTNAME_STUB_DIR` to a per-namespace scratch
  directory for **every** zebra-rs it starts, as it does for the
  `resolvectl` stand-in. A BDD daemon is then kept off the real name twice
  over: by the namespace rule and by the stand-in.
- Scenarios, started with `--feature insomnia`: set, change, a refused
  name, delete restores, and a restart with the line removed restores.
  They assert on the stand-in's files and on `show hostname`.
- One scenario without the feature commits a name and asserts that the
  stand-in still holds the name the scenario before it left.

*In a sandbox*, for the real `sethostname(2)` and the real
`/etc/hostname`. `bdd/tests/scripts/system_hostname_sandbox.sh` unshares a
UTS and a mount namespace, mounts an overlay on `/etc` and a tmpfs on
`/var/lib`, and runs zebra-rs there without the stand-in. Nothing it does
reaches the machine it runs on, and the script checks that at the end.

- `apply` adds a PID and a network namespace, as a container has. PID 1
  is the sandbox's own, so zebra-rs is in the default network namespace:
  set, change, delete, and a restart with the line gone, each checked
  with `hostname`, `/etc/hostname` (and its mode under the daemon's
  umask) and the record.
- `refuse` keeps the host's PID namespace with a network namespace that
  is not PID 1's, as every `ip netns exec` daemon has: the name, `/etc`
  and `/var/lib` must stay as they were, and `show hostname` and the log
  must say why.

The sandbox is what lets the namespace rule be mutation-tested: a mutant
that ignores the rule renames the sandbox, and the `refuse` scenario
fails. Mutants run against the feature: the feature check removed from
`main.rs`, the rule ignored, and the applier never attached.

insomnia's BDD has its own copy of the harness, and node scripts that
start zebra-rs with the feature on. Step 3 sets the variable in both, so
its daemons have the same two guards.

**Still by hand, in a throwaway VM**, because it needs a real systemd and
a reboot: the three "not checked" items in §2 (journald, systemd-resolved
and `hostnamectl` picking the change up), the name at the start of the
next boot, and `sudo` with and without `libnss-myhostname`.

---

## 11. Steps

1. **Apply and restore** (§4, §5, §6, §9) — **done**: the feature
   helper, the namespace rule, `rib/hostname.rs`, validation,
   `show hostname`, unit tests, BDD. YANG description and feature
   description. Book: `--feature` and "System host name" in
   `ch-00-05-command-line-options.md`, `show hostname` in
   `ch-06-03-show-commands.md`. The CHANGELOG entry, with the upgrade
   note below, is written at the release cut like every other.
2. **Readers follow the name** (§7) — **done**: `RibRx::HostnameUpdate`
   with its replay, the IS-IS and BGP fallback order, IS-IS
   re-origination. BDD `system_hostname_protocols`.
3. **Packaging and insomnia** — **done, in the insomnia repository**
   (zebra-rs/insomnia#32): `Recommends: libnss-myhostname` in the insomnia package
   (§8); the insomnia book's "Before you start" section says that the
   drop-in now makes `system hostname` the system's name, with the upgrade
   note below; `ZEBRA_HOSTNAME_STUB_DIR` for every zebra-rs that
   insomnia's BDD harness and node scripts start. No insomnia daemon
   changes.

**Upgrade note.** A router that already runs `--feature insomnia` with
`system hostname` set gets its OS name changed at the first start after
the upgrade. Installing the insomnia package has the same effect, because
its drop-in turns the feature on. The CHANGELOG has to say so.

---

## 12. Decisions

All six were taken as recommended (2026-11-11). The alternatives stay
here for the record.

1. **Who applies it.** zebra-rs's RIB task (recommended), or the insomnia
   daemon over the config subscription (§3).
2. **`/etc/hostname`.** Write it, so the name holds from the start of
   every boot (recommended), or set only the kernel name and change
   nothing on disk.
3. **`delete system hostname`.** Restore the saved name (recommended), or
   leave the last applied name in place. Leaving it needs no record file,
   but the running config then has no hostname while the box keeps one
   that only zebra-rs ever set.
4. **`/etc/hosts`.** Leave it alone and recommend `libnss-myhostname`
   (recommended), or rewrite the `127.0.1.1` line in the first step.
5. **Opt-out.** None: unset `system hostname` to keep zebra-rs's hands off
   (recommended), or a knob for "insomnia features, but the host name is
   managed elsewhere".
6. **Step 2 without the feature.** `system hostname` becomes the fallback
   for IS-IS and BGP on every router (recommended), or only with the
   feature on.
