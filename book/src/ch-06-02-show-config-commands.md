# Show Config Commands

zebra-rs keeps two configuration views:

- **running config** — the configuration the daemon is currently
  acting on. Updated only by `commit`.
- **candidate config** — the editable buffer that accumulates `set`
  and `delete` statements until you `commit` (or `discard`) them.

This chapter covers the commands that display either view.

## Quick reference

All eight display commands work identically from both `exec` mode and
`configure` mode.

| Command | Output |
|---|---|
| `show candidate-config` | **CLI** (Cisco-style indented block) view of the candidate |
| `show candidate-config formal` | Set-style flat statement listing of the candidate |
| `show candidate-config json` | Pretty-printed JSON of the candidate |
| `show candidate-config yaml` | YAML of the candidate |
| `show running-config` | **CLI** view of the running config |
| `show running-config formal` | Set-style flat statement listing of the running config |
| `show running-config json` | Pretty-printed JSON of the running config |
| `show running-config yaml` | YAML of the running config |

The bare form (no trailing keyword) renders the **CLI** view — the
indented block format familiar from Cisco IOS, suitable for reading
on a terminal. The `formal` keyword names the flat statement form. The
`json` and `yaml` keywords are the equivalent serializations of the
same configuration tree. All four are formats `load` accepts and `save`
can write; which one `save` uses is decided by the config file itself
(see [Editing helpers](#editing-helpers) below).

## Output formats

### CLI (default, no trailing keyword)

Cisco-style indented block view. Easy to read on a terminal; the
default when you don't specify a serialization.

```
host(config)# show candidate-config
system {
  hostname r1;
}
router {
  bgp {
    global {
      as 65000;
      router-id 10.0.0.1;
    }
    neighbor 10.0.0.2 {
      remote-as 65001;
    }
  }
}
```

### `formal`

A flat listing, one `set` statement per configuration leaf, handy for
diffing in plain text, grepping for a single leaf, or pasting straight
into another router's configure mode.

```
host(config)# show candidate-config formal
set system hostname r1
set router bgp global as 65000
set router bgp global router-id 10.0.0.1
set router bgp neighbor 10.0.0.2 remote-as 65001
```

This is exactly the document `save formal` writes and the set/delete
loader reads, so the output also works as a config file as-is — the
`set` prefix is what makes it sniff as the set/delete format rather
than falling through to YAML.

### `json`

Pretty-printed (2-space indent), with key order preserved by the
internal `preserve_order` flag.

```json
{
  "system": {
    "hostname": "r1"
  },
  "router": {
    "bgp": {
      "global": {
        "as": 65000,
        "router-id": "10.0.0.1"
      },
      "neighbor": [
        {
          "remote-address": "10.0.0.2",
          "remote-as": 65001
        }
      ]
    }
  }
}
```

### `yaml`

Standard YAML serialization of the same tree.

```yaml
system:
  hostname: r1
router:
  bgp:
    global:
      as: 65000
      router-id: 10.0.0.1
    neighbor:
    - remote-address: 10.0.0.2
      remote-as: 65001
```

## Editing helpers

These commands manipulate the candidate or commit it; they live
under the top level of `configure` mode (not under `show`):

| Command | Effect |
|---|---|
| `set <path>` | Add a leaf or list item to the candidate |
| `delete <path>` | Remove a leaf or list item from the candidate |
| `commit` | Validate the candidate, apply diffs to subscribers, then promote candidate → running |
| `commit comment <text>` | Commit, with a note for the commit history |
| `commit confirmed [<minutes>]` | Commit, and roll the commit back after `minutes` (10 by default) unless a `commit` confirms it |
| `discard` | Revert candidate back to running (drops uncommitted edits) |
| `compare` | Show what `commit` would change, in the block format |
| `compare formal` | The same, as `set` lines |
| `compare rollback <n>` | What changed from commit `n` to the candidate |
| `compare rollback revision <id>` | The same, for the commit with that revision |
| `rollback <n>` | Load the configuration of commit `n` into the candidate |
| `rollback revision <id>` | Load the commit with that revision |
| `load` | Re-load the on-disk config file into the candidate, then commit |
| `save` | Write the running config to the on-disk file in its current format |
| `save { cli \| formal \| json \| yaml }` | Write it in that format instead, and keep the file in that format from then on |

`delete` names what it deletes in full. With `eth10` configured and no
`eth1`, `delete interface eth1` is refused; it is not read as the start
of `eth10`.

Both `load` and `save` operate on the file named by `--config-file`, or
on the resolved default when the flag is absent (see
[Command Line Options](ch-00-05-command-line-options.md)). `save` names
that file, and the format it wrote, in its reply:

```
host(config)# save
Configuration saved to /etc/zebra-rs/zebra-rs.conf (cli)
```

### Seeing what a commit would change

`compare` prints the difference between the candidate and the running
config: removed lines with `-`, added lines with `+`, and of the
unchanged lines only the blocks the changes are in. With nothing to
commit it prints nothing.

```
host(config)# set router bgp neighbor 10.0.0.3 description new
host(config)# set system hostname r1
host(config)# compare
 router {
   bgp {
     neighbor 10.0.0.3 {
-      description old;
+      description new;
     }
   }
 }
+system {
+  hostname r1;
+}
```

`show | compare`, as on Junos, gives the same output. The vty shell runs
the two sides of a `|` as a pipeline, and `compare` does not read what
`show` prints.

`compare formal` lists the changed `set` lines. It is the rendering
`commit` itself diffs, so a line appears here exactly when a commit
would act on it:

```
host(config)# compare formal
-router bgp neighbor 10.0.0.3 description old
+router bgp neighbor 10.0.0.3 description new
+system hostname r1
```

Bare `show` in configure mode is the other view of the same thing: the
whole candidate, with the changes marked in it.

### Going back to an earlier commit

The daemon keeps the configurations of its last 50 commits. Commit 0 is
the latest, which is the running config; commit 1 is the one before it.
`show commit history` lists them, in exec and configure mode:

```
host(config)# show commit history
0   2026-11-17 09:42:39 UTC  1794906748-3  by alice
    trying a new description
1   2026-11-17 09:41:53 UTC  1794906748-2  by root  apply
2   2026-11-17 09:41:52 UTC  1794906748-1  config file
```

Each line is a commit: its number, when it was made, its revision, and
who made it. A commit that was not a `commit` typed in configure mode
says what it was:

| Mark | The commit |
|---|---|
| `apply` | A `vtyctl apply` by another writer |
| `config file` | The config file, at startup or by `load` |
| `rollback, not confirmed` | The daemon, taking back a `commit confirmed` |
| `daemon start` | A daemon that started without the configuration last committed |

The line under a commit is its comment, given with `commit comment`.
The comment is the rest of the line, so it needs no quotes:

```
host(config)# commit comment trying a new description
host(config)# commit confirmed 5 comment moving the uplink
```

Every commit that changed something is listed, whoever made it. A commit
that changed nothing is not listed, and neither is the empty
configuration of a daemon that started with no config file and no
history: the list is then empty until the first commit.

Operators' commits and the others each keep at least half of the 50
places: a writer that applies often does not push the commits an
operator made out of the history.

From a program, `vtyctl show 'show commit history'` prints the same
listing, and with `-j` the commits as a JSON array, newest first, empty
when there is none:

```
$ vtyctl show -j 'show commit history'
[
  {
    "number": 0,
    "time": "2026-11-17T09:42:39Z",
    "revision": "1794906748-3",
    "origin": "commit",
    "config-file": false,
    "user": "alice",
    "comment": "trying a new description"
  },
  …
]
```

`rollback <n>` puts the configuration of commit `n` in the candidate, in
place of what is there, uncommitted edits included. Nothing changes
until `commit`, so the usual sequence is to look first:

```
host(config)# rollback 1
host(config)# compare
 system {
-  hostname r3;
+  hostname r2;
 }
host(config)# commit
```

That commit is a new commit 0, and what was running becomes commit 1, so
`rollback 1` again undoes the rollback. Bare `rollback` is `rollback 0`:
the running config, as `discard` leaves it. That one works with nothing
in the list too. A number with no commit behind it is refused, and the
candidate is left as it was:

```
host(config)# rollback 7
% No commit 7: commits 0 to 2 are kept
```

The same holds for a `rollback <n>` line in a document of `set` lines
given to `vtyctl apply`: when it names no commit, the apply is refused
at that line and nothing is committed.

The number of a commit is its place in the list, and goes up with every
commit made after it, by anyone: the commit read as 2 is commit 3 once a
`vtyctl apply` has landed. Its revision does not change. `rollback
revision <id>` loads the commit with that revision whatever its number
is by then, and is refused when that commit is no longer kept:

```
host(config)# rollback revision 1794906748-2
host(config)# rollback revision 1794906748-9
% No commit 1794906748-9
```

Tab after `revision` lists the revisions kept. A revision is the time
the daemon started, in seconds since the epoch, and the count of commits
the history has recorded. The count goes on across a restart, so it is
never used twice: a revision noted before a restart names the same
commit after it, also when the daemon comes back within the second or on
a box whose clock starts at the same time at every boot. Use the
revision where another writer may commit meanwhile, and in anything
scripted.

`compare rollback <n>` shows what turns commit `n` into the candidate
without loading anything, and `show | compare rollback <n>` is the same
command. `compare rollback revision <id>` names the commit by its
revision.

The history is kept on disk and is still there after a restart. It
lives in a directory beside the config file, named after it
(`/etc/zebra-rs/zebra-rs.conf.commits`), or in the one given with
[`--commit-history-dir`](ch-00-05-command-line-options.md). Each commit
is a file there, readable by its owner only: a header and the
configuration, one line for each thing set. A commit keeps its revision
across the restart.

When the daemon starts, the commit of the config file joins that
history. If the file is what was last committed, nothing is added. If it
is not (the last commits were never saved, or the file was edited), it
is the new commit 0, and `rollback 1` brings back what was running
before the restart. The same holds for a daemon that starts with no
config file, or with one it refuses: what it runs then is commit 0,
marked `daemon start`.

### A commit that takes itself back

`commit confirmed` is for a change that might cut you off from the
router. It commits the candidate and starts a timer in the daemon. A
plain `commit` before the timer runs out confirms the change. Without
one, the daemon commits the configuration from before, whether or not
your session is still there:

```
host(config)# set interface eth0 ipv4 address 192.0.2.1/24
host(config)# commit confirmed 5
Commit will be rolled back in 5 minutes unless confirmed by `commit`
host(config)# commit
```

- **Minutes:** 1 to 65535, and 10 when left out.
- **Confirming:** only a `commit` typed in configure mode confirms, in
  any session. A `vtyctl apply` by another writer does not, and neither
  does a `commit` line in its document: that commit is the apply's, and
  is listed as one.
- **Typed again while pending:** `commit confirmed` commits what has
  been edited since, if anything, and restarts the timer. The rollback
  still goes to the configuration before the first one.
- **What is rolled back:** the unconfirmed commit only. What another
  writer committed meanwhile is kept, and uncommitted edits are still
  uncommitted edits afterwards.
- **Saving:** `save` is refused while a commit is pending, so the config
  file never holds a change the daemon may take back.
- **The rollback itself:** it goes back to a configuration that was
  running, and is held to what the startup config is held to. A check
  that only warns about the startup config (a rule added since that
  config was first taken) does not stop the rollback either; the log has
  the warning.
- **A rollback that is refused:** what other writers committed meanwhile
  can leave the configuration to go back to invalid. The commit then
  stays pending. `show commit history` says that the rollback was
  refused and why, `save` is still refused, and the daemon tries again
  every minute. A `commit` keeps the change and ends the tries.

`show commit history` says when a commit is pending, and lists the
rollback as a commit of its own:

```
host# show commit history
0   2026-11-17 09:28:17 UTC  1794906748-3  rollback, not confirmed
1   2026-11-17 09:27:17 UTC  1794906748-2  by alice
2   2026-11-17 09:26:30 UTC  1794906748-1  config file
```

The timer is in the daemon's memory: a daemon that restarts while a
commit is pending starts from the config file, which does not have the
change.

### Each session has its own candidate

The candidate is the session's: the vty shell you are typing in. Two
operators in configure mode do not see each other's uncommitted edits,
and `commit` commits the edits of the session that typed it and nobody
else's. `discard`, `load` and `rollback` likewise change only the
candidate of their own session.

`vtyctl show 'show candidate-config'` run from a vty shell, or from a
script started there, shows that shell's candidate, as `show
candidate-config` typed in it does. Run from anywhere else it has no
session with a candidate, and shows the configuration with nobody's
edits.

When someone else commits (another session, or a `vtyctl apply`), the
running config changes under your candidate. Your edits stay, as edits
of the new running config: `compare` still shows what you typed and
nothing of what was committed. Your next `commit` goes ahead and says
so:

```
host(config)# commit
Note: others committed while these edits were pending; see `show commit history`
```

Where the other commit set or deleted the very leaf you had edited, your
edit is kept, and your `commit` is refused once so that you can look:

```
host(config)# commit
% Another commit changed what this session has edited. Your edits are kept:
  router bgp neighbor 10.0.0.1 description: committed other, yours mine
% `compare` shows what `commit` would now change; `commit` again to proceed
host(config)# compare formal
-router bgp neighbor 10.0.0.1 description other
+router bgp neighbor 10.0.0.1 description mine
host(config)# commit
```

Typed again, `commit` commits your value over theirs; `discard` takes
theirs. One case is not yours to decide: a leaf you edited inside a list
entry the other commit deleted goes with the entry.

A candidate lasts as long as its shell. It is still there after any idle
time, for piped commands too (`show | compare`), and it is gone when the
shell exits. A session is given its candidate by its first
configure-mode command; a shell that only looks has none.

### Leaving the shell with uncommitted changes

Edits live in the session's candidate until you `commit`, and the
candidate ends with the shell. So when you leave the vty shell — typed
`exit` at the exec prompt, Ctrl-D, or a closing terminal — after having
entered configure mode at some point, the shell checks whether the
candidate still differs from running and asks:

```
host# exit
You have uncommitted changes. Commit? [y=commit other=discard]
```

`y` commits. Anything else — `n`, just pressing Enter, or waiting out
the 30-second timeout — loses the edits with the session. The shell
exits in every case; the answer never cancels the exit.

A commit that does not go through cannot be put right later, so the
shell does what it can before it leaves:

- **The commit is refused** (a validation error, or another commit
  changed a leaf you edited): the reason is shown and the question is
  asked again. A second `y` commits over the other commit, as a second
  `commit` does in configure mode. A validation error can only be given
  up: answer `n`.
- **The admin role has lapsed** (it is held for 15 minutes past the last
  admin command): the shell takes it again, asking for the root password
  when your account needs one, and commits. The password prompt gives up
  after the same 30 seconds.
- **The daemon cannot be reached, or the role cannot be taken:** there
  is no committing.

Whenever you answered `y` and the edits were not committed, the last
line says so:

```
% Not committed: the uncommitted changes are lost with this session.
```

Three cases stay silent: a session that never entered configure mode, a
session with no terminal to ask on (a script piping commands in), and a
daemon that cannot answer the question.

The prompt is about your own edits only. What another operator has
typed is in that operator's candidate, and what a `vtyctl apply` brings
is committed by the apply itself (see the next section).

A vty started inside the vty shares the session of the shell it was
started from, its candidate included. Leaving the inner one does not end
the session; the edits are still there in the outer shell.

### An apply and uncommitted edits

`vtyctl apply`, and the gRPC `Apply` service behind it, commit **only
their own lines**. A config daemon uses the same service: on SONiC,
bgpcfgd applies a batch whenever CONFIG_DB changes. Edits typed in a
configure-mode session and not yet committed are not committed by an
apply, and are not lost when an apply is refused.

After the apply the edits are still pending, as edits of the new running
config. Where the apply changed something an edit also touches:

| The apply and the edit | The candidate afterwards |
|---|---|
| Both set the same leaf | The applied value, when the apply changed the leaf. A line that says what the running config already says changes nothing in the edits. |
| The apply deletes a leaf the edit set | The leaf is deleted. |
| One deletes a list entry, the other sets something under it | The entry stays deleted, whole. |
| Both add the same member to a leaf-list | The member, once. |
| The apply changes a list whose order matters (a segment list, a label stack) | The applied list, whatever the edit made of it. |
| Both add an entry to an `ordered-by user` list (interface addresses) | The applied entries in their order, then the edit's. |

The applied value replaces the pending one without a notice. `show` in
configure mode prints what is still pending.

Three more rules of an apply:

- A whole-config document (CLI block, JSON or YAML) replaces the
  configuration, and uncommitted edits with it. Only a `set`/`delete`
  document leaves them pending.
- A document with no line in it, or with comments only, applies nothing.
- A `delete` of something that is not configured is refused, and then
  nothing of the document is applied.

### The format `save` writes

A bare `save` writes the file back in the format it was **loaded** in,
so a `--config-file` handed to the daemon as YAML stays YAML, JSON stays
JSON, and a `set`/`delete` document stays `set`/`delete`:

```
$ zebra-rs --config-file /etc/zebra-rs/config.yaml
host(config)# set system hostname r2
host(config)# commit
host(config)# save
Configuration saved to /etc/zebra-rs/config.yaml (yaml)

$ cat /etc/zebra-rs/config.yaml
system:
  hostname: r2
```

The format is re-detected on every load — the startup load and the
`load` command both — from the file's first meaningful line, the same
sniffing `vtyctl apply -f` uses. Two cases fall back to the **CLI**
block format: a config file that carried no configuration when the
daemon started (missing, empty, or comment-only — the shipped
`/etc/zebra-rs/zebra-rs.conf` is comment-only, so a default install
saves CLI), and a daemon whose config only ever arrived over
`vtyctl apply`. Applying a document with `vtyctl apply` deliberately
does *not* change the format `save` writes — an applied document is a
config injection, not the on-disk file.

### Converting the config file

Name a format to convert the file. The keywords are the ones
`show running-config` uses — `cli`, `formal`, `json`, `yaml` — and the
choice sticks, so every later bare `save` keeps writing it:

```
host(config)# save yaml
Configuration saved to /etc/zebra-rs/zebra-rs.conf (yaml)
host(config)# save
Configuration saved to /etc/zebra-rs/zebra-rs.conf (yaml)
```

The file is a whole config document in the new format — the daemon
reads any of the four at startup, so a converted file boots unchanged.
A conversion that fails to write leaves both the file and the
remembered format alone.

The write is atomic — the config is serialized to a sibling temp file
and renamed into place, so an interrupted save leaves the previous file
intact. A save that fails (read-only filesystem, missing parent
directory, a file the daemon's user cannot write) reports the error and
leaves the daemon running:

```
host(config)# save
Failed to save configuration to /etc/zebra-rs/zebra-rs.conf: Permission denied (os error 13)
```

## Reorganization notes (history)

Earlier versions exposed the config viewers as top-level
configure-mode commands without the `show` prefix:

| Old | New |
|---|---|
| `list` | `show candidate-config formal` |
| `json` | `show candidate-config json` |
| `yaml` | `show candidate-config yaml` |
| `running` | `show running-config formal` |
| `candidate` | (removed — was effectively a duplicate of `list`) |
| `diff` | `compare` (bare `show` marks the changes in the whole candidate) |

The reorganization gives candidate and running configs a symmetric
set of viewers (`show {candidate,running}-config { formal | json |
yaml }`), so an operator can always say "show me the X view of the
Y config" without remembering which forms exist for which view.
