# Conditional Tracing

IS-IS shares the conditional-tracing model of BGP and OSPF: a typed
config block of per-category switches that turn detailed `info`-level
traces on at runtime, with no rebuild and no global log-level change.
Each toggle is a *presence* flag — name it in the config to enable,
delete it to disable — and the gated log sites consult the live config
on every PDU, transition and event. Absence means the category is
silent.

The block attaches at the `router isis` instance and applies to every
interface and neighbor:

```
router isis {
  tracing {
    packet {
      hello { direction receive; }   # received IIHs only
      lsp { level level-2; }         # Level-2 LSPs only
    }
    fsm { nfsm; }                    # adjacency state machine
    lsp-originate;                   # self-LSP (re)origination
  }
}
```

| Category | Toggles |
|---|---|
| `all` | master switch — traces every category below |
| `packet` | `hello`, `lsp`, `csnp`, `psnp`, `all` |
| `fsm` | `nfsm` (adjacency state machine) |
| `lsp-originate` | self-LSP origination |
| `lsp-purge` | LSP purge events |
| `lsdb` | link-state database install / flooding decisions |
| `bfd` | IS-IS↔BFD interaction (RFC 5882) — session state changes, subscribe, adjacency teardown, hold-down recovery |

## The `level` filter

The IS-IS-specific addition over the OSPF/BGP model is a functional
**level** refinement: every `packet` type and the `lsp-originate` /
`lsp-purge` / `lsdb` event toggles accept an optional
`level level-1` or `level level-2`. Omit it to trace both levels —
there is no explicit `both` value; absence means both.

```
router isis {
  tracing {
    lsdb { level level-1; }          # L1 database activity only
  }
}
```

## Packet tracing

Each PDU type (`hello` — the IIHs, `lsp`, `csnp`, `psnp`) is a presence
container; naming it enables tracing for that type in both directions
and levels. Two optional children narrow it: `direction`
(`send` / `receive`; omit for both) and the `level` filter above.
`all` covers every PDU type at once. Unlike OSPF and BGP, the IS-IS
packet toggles have no `detail` refinement — each trace is a one-line
summary of the PDU.

## Notes

- `fsm nfsm` traces the neighbor (adjacency) state machine. There is
  no `ifsm` toggle — the interface FSM has no trace sites yet.
- `bfd` is a bare presence flag with no `level` refinement: a BFD
  session is keyed per interface and neighbor address, not per IS-IS
  level.
- **Warnings stay on.** Tracing categories gate diagnostic detail
  only; operator-facing warnings and errors are always emitted
  (tagged `proto="isis"`) regardless of the tracing config.

## Structured fields

Every gated line is stamped `proto="isis"` plus a `category` and the
per-category fields, so the filtering recipes in
[Protocol-Specific Logging](ch-03-03-protocol-logging.md) apply
directly:

- `packet` lines carry `category="packet"`, `packet_type`,
  `direction`, and `level`.
- `lsp-originate` / `lsp-purge` lines carry `category="event"`,
  `event_type`, and `level`.
- `lsdb` lines carry `category="database"`, `db_type`, and `level`.

## Interaction with `RUST_LOG`

Tracing categories are a *content* filter — they decide which sites
emit — and the lines they emit are at `info` level. They are
independent of the
[`RUST_LOG`](ch-03-03-protocol-logging.md#protocol-specific-debug-levels)
*level* filter: a category produces nothing unless the IS-IS module's
level admits `info` (the default does). Use tracing categories to pick
*what* to see at runtime; use `RUST_LOG` only when you need a coarser
module-level sweep.
