# Conditional Tracing

Conditional tracing is a runtime debug switch: a category is silent
until you name it in the config, at which point the matching log
sites start emitting. It mirrors the BGP and IS-IS `tracing` model —
each toggle is a *presence* flag (name it to enable, delete it to
disable), and the gated log macros consult the live config on every
packet, transition, and event, so categories turn on and off without
a restart.

The block is identical for both versions, attached to `router ospf`
(OSPFv2) and `router ospfv3` (OSPFv3); the two emit `proto=ospf` and
`proto=ospfv3` respectively so their logs stay filterable apart.

```
router ospf {
  tracing {
    fsm { nfsm; }                    # neighbor FSM transitions
    packet {
      hello;                         # both directions, summary
      ls-update { detail; }          # both directions, full decode
      dd { direction receive; }      # received DBDs only
    }
    spf;                             # SPF calculation events
  }
}

router ospfv3 {
  tracing { all; }                   # master switch: every category
}
```

| Category | Toggles |
|---|---|
| `all` | master switch — traces every category below |
| `packet` | `hello`, `dd`, `ls-req`, `ls-update`, `ls-ack`, `all` |
| `fsm` | `ifsm`, `nfsm`, `all` |
| `spf` | SPF (shortest-path-first) calculation |
| `lsdb` | LSA origination / installation / flooding |

Each `packet` toggle is a presence container carrying two optional
refinements: `direction` (`send` or `receive`; omit for both) and
`detail` (log the fully decoded packet instead of a one-line
summary). Each `fsm` toggle carries an optional `detail` that widens
it from summary transitions to detail-level transition lines. `spf`
and `lsdb` are bare presence leaves.

Every gated line carries structured fields — `proto`, `category`
(`packet` / `fsm` / `event`), and, for packets, `packet`,
`direction`, and `detail` — so the output can be filtered downstream
by protocol and category.
