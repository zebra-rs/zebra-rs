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

A flat listing, one configuration leaf per line, handy for diffing in
plain text or grepping for a single leaf.

```
host(config)# show candidate-config formal
system hostname r1
router bgp global as 65000
router bgp global router-id 10.0.0.1
router bgp neighbor 10.0.0.2 remote-as 65001
```

The display drops the leading `set` keyword. A *file* in this format
keeps it — `set system hostname r1` — which is what `save` writes and
what the set/delete loader reads; a file of bare lines is sniffed as
YAML and won't load. So paste from `show … formal` into a config file
only with the `set` prefix restored.

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
| `load` | Re-load the on-disk config file into the candidate, then commit |
| `save` | Write the running config to the on-disk file in its current format |
| `save { cli \| formal \| json \| yaml }` | Write it in that format instead, and keep the file in that format from then on |

Both `load` and `save` operate on the file named by `--config-file`, or
on the resolved default when the flag is absent (see
[Command Line Options](ch-00-05-command-line-options.md)). `save` names
that file, and the format it wrote, in its reply:

```
host(config)# save
Configuration saved to /etc/zebra-rs/zebra-rs.conf (cli)
```

### Leaving the shell with uncommitted changes

Edits live in the candidate until you `commit`, and until this release
nothing stopped a session from simply ending on top of them. Now, when
you leave the vty shell — typed `exit` at the exec prompt, Ctrl-D, or a
closing terminal — after having entered configure mode at some point,
the shell checks whether the candidate still differs from running and
asks:

```
host# exit
You have uncommitted changes. Commit? [y=commit, n=discard, other=leave pending]
```

`y` commits, `n` discards, and anything else (including just pressing
Enter, or waiting for the 30-second timeout) leaves the edits in the
candidate for the next session. The shell exits in every case — the
answer never cancels the exit.

Three cases stay silent: a session that never entered configure mode, a
session with no terminal to ask on (a script piping commands in), and a
daemon that cannot answer the question. If the commit is refused because
the session is no longer Admin, the reason is printed and the edits are
left untouched:

```
% commit failed (admin role required — run 'enable'); changes left uncommitted.
```

Note that the candidate is shared daemon-wide: pending edits from
another operator, or from a `vtyctl apply`, are part of what this prompt
offers to commit or discard.

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
block format: a config file that was missing or empty when the daemon
started, and a daemon whose config only ever arrived over
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
| `diff` | (removed — was running ↔ candidate textual diff) |

The reorganization gives candidate and running configs a symmetric
set of viewers (`show {candidate,running}-config { formal | json |
yaml }`), so an operator can always say "show me the X view of the
Y config" without remembering which forms exist for which view.
