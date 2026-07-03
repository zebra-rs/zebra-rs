# Graceful Restart

OSPFv3 graceful restart is currently **helper-only**. When a
neighbor floods a Grace-LSA (LS type `0x000B`, RFC 5187) announcing
its restart, zebra-rs enters helper mode for it: the dead-interval
kill is suppressed, the neighbor's pre-restart LSAs are snapshotted,
and helping ends on grace expiry, on a topology change, or when the
restarter's re-originated LSAs differ from the snapshot. The helper
semantics are identical to OSPFv2's, described in
[the v2 Graceful Restart page](ch-08-17-ospf-graceful-restart.md).

The differences from v2:

- **No configuration surface.** The v3 helper runs with fixed
  defaults — helper enabled, 1800 s maximum grace period, strict
  LSA checking — and there is no
  `router ospfv3 graceful-restart` block to change them.
- **No restarter mode.** The staging commands
  (`clear ospf graceful-restart begin | commit | abort`) and the
  on-disk LSDB checkpoint exist for OSPFv2 only; there is no
  `clear ospfv3 graceful-restart` subtree. A zebra-rs OSPFv3
  instance can *help* a restarting neighbor but cannot itself
  restart gracefully.

Both are tracked as gaps — see
[Gaps Relative to FRR ospf6d](ch-15-15-ospfv3-frr-gaps.md). Helper
sessions are visible indirectly (the held adjacency stays Full
through the peer's restart); there is no v3
`show ospfv3 graceful-restart` command yet.
