# Conditional Tracing

OSPFv3 shares the conditional-tracing model of OSPFv2, BGP and
IS-IS: each category is a *presence* toggle — name it in the config
to enable, delete it to disable — and the gated log sites consult
the live config on every packet, transition and event, so
categories flip without a restart. The block is identical to the v2
one, attached to `router ospfv3`; its output carries
`proto=ospfv3` so v2 and v3 logs stay filterable apart.

```
router ospfv3 {
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
```

| Category | Toggles |
|---|---|
| `all` | master switch — traces every category below |
| `packet` | `hello`, `dd`, `ls-req`, `ls-update`, `ls-ack`, `all` |
| `fsm` | `ifsm`, `nfsm`, `all` |
| `spf` | SPF (shortest-path-first) calculation |
| `lsdb` | LSA origination / installation / flooding |

Each `packet` toggle accepts the optional `direction`
(`send` / `receive`) and `detail` refinements; each `fsm` toggle an
optional `detail`. See
[the v2 Conditional Tracing page](ch-08-10-ospf-tracing.md) for the
full field reference — the structured log fields (`proto`,
`category`, `packet`, `direction`, `detail`) are the same.
