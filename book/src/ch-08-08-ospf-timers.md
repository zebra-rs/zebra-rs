# Timer Configuration

The OSPF protocol timers are configured per interface, under the
area/interface entry. All defaults match RFC 2328 Appendix C
("Configurable Parameters").

```
router ospf {
  area 0.0.0.1 {
    interface enp0s7 {
      enable true;
      hello-interval 5;
      dead-interval 20;
    }
  }
}
```

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/ospf/area/<id>/interface/<n>/hello-interval` | 10 | 1..65535 | seconds |
| `/router/ospf/area/<id>/interface/<n>/dead-interval` | 40 | 1..4294967295 | seconds |
| `/router/ospf/area/<id>/interface/<n>/retransmit-interval` | 5 | 1..65535 | seconds |

Notes:

- **`hello-interval`** and **`dead-interval`** must match on all
  routers on the same segment for adjacency to form. The on-the-wire
  Hello carries both; mismatches cause Hellos to be silently
  discarded and the adjacency never leaves `Down`. The conventional
  ratio is `dead = 4 × hello`; sub-second adjacency detection is
  better delegated to [BFD](ch-08-02-ospf-bfd.md).
- **`retransmit-interval`** governs how often unacknowledged LSAs in
  the per-neighbor `ls_rxmt` list are re-sent. The default of 5 s
  is conservative and rarely needs tuning on healthy links.

## SPF throttle (`spf-interval`)

The route calculation is rate-limited by an adaptive
exponential-backoff throttle (IOS-XR style, shared with IS-IS),
configured at the instance level:

```
router ospf {
  spf-interval {
    initial-wait 50;
    secondary-wait 200;
    maximum-wait 5000;
  }
}
```

| YANG leaf (`/router/ospf[v3]/spf-interval/…`) | Default | Range | Units |
|---|---|---|---|
| `initial-wait` | 50 | 1..120000 | milliseconds |
| `secondary-wait` | 200 | 1..120000 | milliseconds |
| `maximum-wait` | 5000 | 1..120000 | milliseconds |

After a quiet period, the first topology change schedules SPF
`initial-wait` ms later — fast convergence when the network is
stable. If further changes arrive while a burst is in progress, the
hold-down grows to `secondary-wait`, then doubles on each successive
run up to `maximum-wait`, damping churn during instability. Once the
area has been quiet for longer than `2 × maximum-wait`, the backoff
resets to `initial-wait`.

The backoff *state* is per-area, so a flapping area backs off without
slowing convergence in a stable one. `show ospf` reports the
configured bounds (`SPF timers: initial … secondary … maximum …`).
OSPFv3 exposes the identical `spf-interval` block under
`router ospfv3`. These defaults replace the earlier fixed 1-second
coalescing timer.
