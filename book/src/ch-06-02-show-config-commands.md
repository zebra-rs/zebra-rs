# Show Config Commands

zebra-rs keeps two configuration views:

- **running config** — the configuration the daemon is currently
  acting on. Updated only by `commit`.
- **candidate config** — the editable buffer that accumulates `set`
  and `delete` statements until you `commit` (or `discard`) them.

This chapter covers the commands that display either view.

## Quick reference

All six display commands work identically from both `exec` mode and
`configure` mode.

| Command | Output |
|---|---|
| `show candidate-config formal` | Set-style flat statement listing of the **candidate** |
| `show candidate-config json` | Pretty-printed JSON of the candidate |
| `show candidate-config yaml` | YAML of the candidate |
| `show running-config formal` | Set-style flat statement listing of the **running** config |
| `show running-config json` | Pretty-printed JSON of the running config |
| `show running-config yaml` | YAML of the running config |

The `formal` keyword names the canonical set/delete form — the same
format `load` and `save` consume. The `json` and `yaml` keywords are
the equivalent serializations of the same configuration tree.

## Output formats

### `formal`

A flat sequence of `set ...` statements, one configuration leaf per
line, suitable for `load` to replay or for diffing in plain text.

```
host(config)# show candidate-config formal
set system hostname r1
set router bgp 65000 router-id 10.0.0.1
set router bgp 65000 neighbor 10.0.0.2 peer-as 65001
```

### `json`

Pretty-printed (2-space indent), with key order preserved by the
internal `preserve_order` flag.

```json
{
  "system": {
    "hostname": "r1"
  },
  "router": {
    "bgp": [
      {
        "as": 65000,
        "router-id": "10.0.0.1"
      }
    ]
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
    - as: 65000
      router-id: 10.0.0.1
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
| `save` | Write the running config to the on-disk file |
| `running` | Legacy shortcut: equivalent to `show running-config formal` for the structured display |

## Reorganization notes (history)

Earlier versions exposed the candidate-config viewers as top-level
configure-mode commands without the `show` prefix:

| Old | New |
|---|---|
| `list` | `show candidate-config formal` |
| `json` | `show candidate-config json` |
| `yaml` | `show candidate-config yaml` |
| `candidate` | (removed — was effectively a duplicate of `list`) |
| `diff` | (removed — was running ↔ candidate textual diff) |

The reorganization gives the running config a symmetric set of
viewers (`show running-config { formal | json | yaml }`), so an
operator can always say "show me the X view of the Y config" without
remembering which forms exist for which view.
