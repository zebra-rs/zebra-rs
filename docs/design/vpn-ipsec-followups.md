# VPN IPsec (VyOS-style `vpn ipsec`) — deferred follow-ups

Status as of 2026-08-04. The core port of the VyOS 1.5 (circinus)
`vpn ipsec` tree landed in four PRs, all merged, all gated on
`--feature iso`:

- **#2241 schema** — `zebra-rs/yang/ipsec.yang` grouping library
  (firewall.yang style), instantiated in config.yang as
  `container vpn { if-feature feat:iso; container ipsec }`:
  `authentication psk`, `esp-group` / `ike-group` with the full VyOS
  proposal cipher/hash/DH lists, `interface`, `log`, `options`, and
  `site-to-site peer` with per-tunnel traffic selectors and VTI
  binding. Pre-shared-key authentication only.
- **#2242 backend** — `src/system/ipsec.rs` consumes `/vpn/ipsec` via
  `ConfigManager::subscribe_json` and renders `swanctl.conf`
  (connections/pools/secrets, faithful to vyos-1x `swanctl.conf.j2` +
  `swanctl/peer.j2`, including the `get_esp_ike_cipher` proposal
  builder and the overlap-derived passthrough children), loaded
  declaratively with `swanctl -q`. Shared serde helpers live in
  `src/system/json.rs`.
- **#2243 show** — `show vpn ipsec sa | connections | policy | state`;
  `sa`/`connections` over charon's VICI socket through the minimal
  in-tree client `src/system/vici.rs`, `state`/`policy` via
  `ip xfrm … list`. Tables mirror vyos-1x `src/op_mode/ipsec.py`.
- **#2244 BDD** — `bdd/tests/features/ipsec_s2s.feature`: two
  namespace nodes each running charon-systemd + zebra-rs, live IKEv2
  PSK tunnel, ESP traffic with counters, declarative unload,
  teardown. Each node runs under `unshare -m` with tmpfs over `/run`
  and `/etc/swanctl` (`bdd/tests/scripts/ipsec_node.sh`) because the
  filesystem is shared across network namespaces and swanctl's
  *enforced* AppArmor profile pins exactly `/etc/swanctl/**` and
  `/run/charon.vici` — private mounts keep every path stock.

Everything below is deliberately deferred, roughly ordered by how
much new infrastructure each item needs.

## Small, self-contained

- **Commit-time reference validation.** `ike-group` / `esp-group` /
  `default-esp-group` references are plain strings (the staging
  convention shared with the firewall port). A dangling reference is
  caught only at render time: the peer or child is skipped with a
  warning. VyOS rejects the commit in `verify()`. Doing the same
  needs a validation hook in the commit path — the same follow-up is
  open for firewall jump-targets and group references, so one
  mechanism should serve both.
- **`show` completeness.** Missing relative to VyOS: `sa detail`,
  per-peer filters (`sa peer <x>`), `show vpn ike sa`
  (`nat-traversal` / `peer` variants), `show vpn ike secrets`,
  `show vpn ipsec status`, and the `reset vpn ipsec …` /
  `reset vpn ike …` operational commands (vici `terminate` /
  `initiate` — the in-tree client already speaks the protocol; only
  the request plumbing and grammar are missing).
- **Table-cell newlines.** Multi-value traffic selectors join with
  `,` where VyOS embeds newlines inside table cells. Cosmetic; fix
  only if operator feedback wants byte-parity with VyOS output.

## Needs a charon-config mechanism

- **charon-level settings**: `log level` / `log subsystem`,
  `options disable-route-autoinstall`, `options flexvpn`,
  `options interface`, `options virtual-ip`, `disable-uniqreqids`,
  and the top-level `interface` leaf-list. In VyOS these render into
  `strongswan.d`/`charon.conf` (templates `ipsec/charon.j2`,
  `ipsec/interfaces_use.conf.j2`) and take effect on a charon
  restart. zebra-rs currently parses them and logs one warning per
  commit. Applying them means rendering a strongswan.conf snippet
  and deciding a reload story (see next item).
- **charon lifecycle.** zebra-rs assumes a running charon and only
  warns when `swanctl` is unavailable; VyOS
  `reload-or-restart`s strongswan.service on every commit. Options:
  keep the current hands-off contract (documented in the module
  header), spawn/supervise charon the way the cradle engine is
  supervised, or drive systemd. Decide before implementing the
  charon-level settings above, since those need a restart to apply.

## Needs other config trees first

- **rsa / x509 site-to-site authentication** — the peer
  `authentication mode` enum is `pre-shared-secret`-only until a
  `pki` tree exists (VyOS: `pki key-pair` / `pki certificate` with
  `authentication rsa` / `authentication x509` referencing it, plus
  `use-x509-id`). The swanctl secrets sections for private keys are
  already mapped out in the VyOS template (`private_*` / `rsa_*`
  blocks).
- **`remote-access` (IKEv2 RA VPN)** — needs PKI plus RADIUS and
  local-user (EAP) trees, address pools, and the charon dhcp/eap
  plugins. Large; treat as its own arc.
- **`profile` (DMVPN)** — needs the tunnel-interface tree (GRE) and
  NHRP. The include fragments map 1:1 onto existing groupings
  (`esp-group` / `ike-group` refs + `bind tunnel`).
- **`dhcp-interface`** (peer local address learned from a DHCP
  lease) — needs the ISO DHCP-client integration; VyOS excludes such
  peers until a lease exists and re-renders on lease events. zebra-rs
  currently warns and skips the peer, which matches the no-lease
  behavior.
- **VTI end-to-end.** The schema carries `vti bind`/`vti esp-group`
  and the renderer emits the VTI child (shifted `if_id`, updown
  hook), but zebra-rs has no `interfaces vti` tree to create the
  XFRM/vti device and does not ship the `/etc/ipsec.d/vti-up-down`
  script the child references. Needs an interface-tree addition plus
  either shipping an updown helper or moving to charon's
  `if_id`-based XFRM interfaces without an updown script.
- **l2tp glue** — `swanctl.conf.j2` renders an L2TP connection from
  the `vpn l2tp` tree; out of scope until that tree exists.

## Testing

- **BDD depth.** `ipsec_s2s` covers establishment, traffic,
  declarative unload and teardown. Not covered: rekey (short
  lifetimes), DPD action on peer loss, transport-mode tunnels,
  IKEv1/aggressive, VTI. Each fits the existing two-node recipe.
- **Host prerequisite.** The feature needs `charon-systemd` +
  `strongswan-swanctl` installed (documented on the `ipsec_s2s`
  Makefile target); it fails fast with a clear message otherwise.
