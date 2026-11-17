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
| `discard` | Revert candidate back to running (drops uncommitted edits) |
| `compare` | Show what `commit` would change, in the block format |
| `compare formal` | The same, as `set` lines |
| `compare rollback <n>` | What changed from commit `n` to the candidate |
| `rollback <n>` | Load the configuration of commit `n` into the candidate |
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
0   2026-11-17 09:41:07 UTC
1   2026-11-17 09:38:52 UTC
2   2026-11-17 09:12:30 UTC  config file
```

`config file` marks the commit of the config file, at startup or by
`load`. Every commit that changed something is listed, whoever made it:
a `vtyctl apply` is a commit too. A commit that changed nothing is not
listed, and neither is the empty configuration of a daemon that started
with no config file, or with one that sets nothing: the list is then
empty until the first commit.

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

`compare rollback <n>` shows what turns commit `n` into the candidate
without loading anything, and `show | compare rollback <n>` is the same
command.

The history is kept in memory. It is gone when the daemon restarts, and
then starts again from the config file.

### Leaving the shell with uncommitted changes

Edits live in the candidate until you `commit`, and until this release
nothing stopped a session from simply ending on top of them. Now, when
you leave the vty shell — typed `exit` at the exec prompt, Ctrl-D, or a
closing terminal — after having entered configure mode at some point,
the shell checks whether the candidate still differs from running and
asks:

```
host# exit
You have uncommitted changes. Commit? [y=commit n=discard other=keep]
```

`y` commits, `n` discards, and anything else — `keep`, including just
pressing Enter or waiting out the 30-second timeout — leaves the edits
in the candidate for the next session. The shell exits in every case;
the answer never cancels the exit.

Three cases stay silent: a session that never entered configure mode, a
session with no terminal to ask on (a script piping commands in), and a
daemon that cannot answer the question. If the commit is refused because
the session is no longer Admin, the reason is printed and the edits are
left untouched:

```
% commit failed (admin role required — run 'enable'); changes left uncommitted.
```

Note that the candidate is shared by every configure-mode session:
pending edits from another operator are part of what this prompt offers
to commit or discard. What a `vtyctl apply` brings is not: it is
committed by the apply itself (see the next section).

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
