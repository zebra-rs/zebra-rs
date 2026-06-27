# MCP Server Authentication — Design & Phasing Plan

Tracks the addition of authentication and authorization to the zebra-rs
MCP (Model Context Protocol) server that ships inside `vtyctl` (the
`vtyctl mcp` subcommand). This document is the living plan + status: it
captures the trust model, how it reuses the daemon's existing VTY
auth/authz stack, the architecture decisions, the transport/credential
choices, the phase-by-phase slice, and **what has landed vs what's left**
so a contributor can resume without the conversation history.

Read this first if you're touching `vtyctl/src/mcp/*`, the daemon VTY
gRPC server `zebra-rs/src/config/serve.rs`, session/RBAC in
`zebra-rs/src/config/session.rs`, the VTY proto `proto/vty.proto`, or
`zebra-rs/yang/vty.yang`.

References:

- Model Context Protocol — base spec and **Authorization** spec (OAuth 2.1
  for the Streamable HTTP transport). <https://modelcontextprotocol.io/>
- RFC 9728 — OAuth 2.0 Protected Resource Metadata (required by the MCP
  auth spec for resource-server discovery).
- RFC 6749 / OAuth 2.1 draft — authorization framework; PKCE mandatory.
- RFC 7519 / RFC 7515 / RFC 7517 — JWT, JWS, JWKS (access-token validation).
- `book/src/ch-06-01-session-design.md` — the existing VTY session/RBAC
  design (decisions D1–D26). **This plan extends it; new decisions are
  numbered D27+.**
- `book/src/ch-13-00-mcp-server.md` — the user-facing MCP chapter.

## Decisions captured up front

The scope was fixed by three product decisions:

1. **Both transports** — keep local **stdio** (subprocess) and add a
   network-exposed **Streamable HTTP** transport. Build stdio first.
2. **Read + write** — MCP tools may run `show` *and* push configuration
   (`configure`/`apply`/`clear`), not read-only.
3. **OAuth 2.1** — the network transport authenticates clients with OAuth
   2.1 bearer tokens per the MCP Authorization spec.

## 1. The core problem

The daemon's trust anchor is **`SO_PEERCRED`**: the VTY gRPC server reads
the connecting process's uid/gid/pid from the kernel and derives identity
and role from it (`serve.rs` `VtyPeerInterceptor`, ~lines 621–716). A
client cannot forge this.

That model is exact for **stdio**: one human spawns their *own*
`vtyctl mcp` process, so their uid flows to the daemon and existing RBAC
(`View`/`Admin`) applies directly.

It **breaks for HTTP**: a single long-lived `vtyctl mcp` process serves
many remote OAuth users. `SO_PEERCRED` only tells the daemon "this is
vtyctl's uid" — it cannot distinguish remote user Alice from Bob, so the
daemon's per-uid RBAC cannot apply to remote identities.

**Resolution — Trusted Subsystem (constrained delegation).** In HTTP mode
`vtyctl mcp` runs as a dedicated, *allowlisted* service-account uid. It
authenticates the remote client itself (OAuth), then **asserts** the
authenticated principal + requested role to the daemon via gRPC metadata.
The daemon honors that assertion **only** when the connecting
`SO_PEERCRED` uid is in a new "trusted asserter" allowlist. The kernel
remains the root of trust; an authorized front-end is permitted to speak
for end users. **The daemon never sees the OAuth token.**

This is the spine of the design; everything else hangs off it.

## 2. Identity & role model

| Transport | Authn of MCP client | Identity reaching daemon | Role source |
| --- | --- | --- | --- |
| **stdio** | OS — user spawns their own `vtyctl mcp` | `SO_PEERCRED` uid (unchanged) | Existing RBAC; new `enable` tool (PAM) for Admin |
| **HTTP** | OAuth 2.1 bearer JWT | **Asserted** principal + role in gRPC metadata; vtyctl runs as a *trusted-asserter* service account | Token `scope` → View/Admin, bounded by asserter's max grant |

Two invariants hold across both transports:

- **The daemon is the source of truth.** The MCP server pre-checks the
  required role for fast, clear errors, but `enforce_admin()` in the
  daemon (`serve.rs` ~lines 44–64, applied to `Apply`/`Clear`/configure
  entry) is the real gate. The front-end check is defense in depth, never
  the sole control.
- **Least privilege by default.** Every session starts `View`. Writes
  require explicit elevation: the OAuth `zebra.write` scope (HTTP) or a
  PAM `enable` (stdio). Existing admin-session TTLs (15-min idle / 4-h
  hard cap, session-design D2) apply unchanged.

## 3. Tool surface (read + write)

Today the server exposes a single tool, `get-isis-graph` (read-only,
backed by `Show`). For read+write it becomes a small generic set, each
tagged with a required role the server enforces *and* the daemon
re-checks:

| Tool | Daemon RPC | Required role | Notes |
| --- | --- | --- | --- |
| `show` (+ keep `get-isis-graph`) | `Show` (stream) | View | unchanged path |
| `configure` / `apply` | `Apply` (stream) | Admin | every call audited (principal + lines) |
| `clear` | `Clear` | Admin | audited |
| `enable` | `Enable` (PAM) | — | **stdio only**; elevates the session for the TTL window |

For HTTP, `enable` is unnecessary: elevation comes from the token's
`scope`, not an interactive password.

## 4. Daemon-side changes (new — D27+)

Slots into the existing `serve.rs` / `session.rs` design:

- **D27 — Trusted-asserter allowlist.** `ZEBRA_VTY_TRUSTED_ASSERTERS`
  (env, CSV uids) **and** YANG `vty trusted-asserter uid N`, unioned the
  same way the existing service-account sources are (env
  `ZEBRA_VTY_SERVICE_ACCOUNTS` ∪ YANG `vty service-account uid N`).
- **D28 — Asserted-identity metadata.** New gRPC metadata keys
  (`x-zebra-principal`, `x-zebra-role`, `x-zebra-auth-method`).
  `VtyPeerInterceptor` reads them **only** if the peer `SO_PEERCRED` uid ∈
  trusted asserters; otherwise it ignores them and falls back to plain uid
  identity. A non-asserter that sets the headers is rejected
  (`permission_denied`).
- **D29 — Session keying for asserted sessions.** Key on
  `(asserter_uid, principal)` instead of `(uid, pid)`, so each remote
  principal gets its own View/Admin session and independent TTL.
- **D30 — Bounded grant.** An asserter may only assert *up to* a
  configured maximum role, so a compromised front-end cannot exceed its
  mandate. Default cap configurable per asserter.
- **D31 — Audit.** Record the asserted principal + auth method on every
  `Apply`/`Clear` (extend existing logging). This is what makes exposing
  "read + write" safe.

All of D27–D31 is testable with a fake asserter and **zero MCP/HTTP
code**, which is why it is its own phase (Phase 1).

## 5. vtyctl `mcp` changes (new)

1. **Streamable-HTTP transport** alongside stdio (`axum` + `tower` /
   `hyper-util`, already in the dep tree). **Open decision (§8):** evaluate
   adopting the `rmcp` SDK here for a spec-compliant Streamable HTTP
   implementation + OAuth resource-server scaffolding, versus hand-rolling
   the JSON-RPC loop a second time.
2. **OAuth 2.1 resource server:**
   - Serve **Protected Resource Metadata** (RFC 9728) at
     `/.well-known/oauth-protected-resource`, and emit `WWW-Authenticate`
     with the `resource_metadata` pointer on 401 — both required by the
     MCP auth spec.
   - Validate the bearer JWT: signature via the AS's **JWKS**, plus `iss`,
     `exp`, and **strict `aud`** equal to this server's canonical URI.
   - **Reject any token whose `aud` is not this server** — closes the
     confused-deputy / token-passthrough hole the MCP spec calls out. The
     daemon never receives the token; only the validated principal +
     mapped role.
   - Map `scope` → role: `zebra.read` → View, `zebra.write` → Admin.
3. **Trusted-asserter client.** HTTP mode connects to the daemon as the
   configured asserter service account and sets the asserted-identity
   metadata (D28) per request. Pool/reuse gRPC channels.
4. **stdio `enable` tool.** Thin wrapper over the daemon `Enable` RPC —
   reuses PAM, rate-limiting, and TTL as-is.
5. **Config home.** Follow the existing env-∪-YANG convention: listen
   addr, TLS cert/key, OAuth `issuer` / `jwks_uri` / `audience` /
   `required_scopes`, asserter identity. CLI flags for dev, YANG
   (`vty mcp …`) for production.

## 6. Phase map (smallest shippable first)

| Phase | Scope | Touches |
| --- | --- | --- |
| 0 | **stdio least-privilege + tool surface.** Generalize tools to `show`/`configure`/`clear`, gate writes, add the `enable` tool. Delivers authenticated read+write **locally** with *zero* new trust mechanisms — pure reuse of `SO_PEERCRED` + RBAC + PAM. Audit writes with the OS principal. This is the entire "stdio first" deliverable and ships independently. | `vtyctl/src/mcp/*` |
| 1 | **Daemon trusted-asserter + asserted identity** (D27–D31). Daemon-only; fake-asserter tests. No MCP/HTTP code yet. | `serve.rs`, `session.rs`, `vty.yang`, `proto/vty.proto` (metadata) |
| 2 | **MCP HTTP transport, loopback, no OAuth yet.** Streamable HTTP up, connecting as the asserter service account with a fixed principal. Proves transport + assertion path end-to-end. | `vtyctl/src/mcp/*` |
| 3 | **OAuth 2.1 resource server** (§5.2). PRM, JWT/JWKS validation, audience binding, scope→role, TLS. | `vtyctl/src/mcp/*` |
| 4 | **Hardening.** JWKS refresh/caching, rate-limit, structured write audit, TTL alignment, full YANG config, BDD coverage, threat-model doc + book chapter update. | all of the above |

## 7. Security properties (threat model summary)

- **Trust anchor stays the kernel.** Asserted identity is honored only
  from allowlisted asserter uids → a random local process cannot
  impersonate a user.
- **No token passthrough.** Strict `aud` binding + the daemon never seeing
  the OAuth token kills the confused-deputy class.
- **Bounded blast radius.** A compromised asserter is capped by its
  max-grant role (D30) and fully audited (D31).
- **TLS mandatory** for the HTTP transport (bearer tokens require
  confidentiality).
- **Defense in depth.** Front-end pre-check + daemon `enforce_admin()`
  re-check; daemon is authoritative.

## 8. Open decisions

1. **`rmcp` SDK vs. extend the hand-rolled server** for the HTTP transport
   (§5.1). Leaning `rmcp` for spec compliance; biggest architectural call.
2. **Which OAuth Authorization Server** (Keycloak / Auth0 / Okta /
   internal)? The resource server is AS-agnostic but needs `issuer` /
   `jwks_uri` / `audience`. Also: support **Dynamic Client Registration**
   (spec-recommended) or pre-register clients?
3. **Authz granularity** — scope→role (View/Admin) only for now, or start
   leveraging the proto's currently-unused `privilege` field for
   per-command levels later?

## Status

- **2026-06-27** — Plan drafted. No code landed yet. Current MCP server is
  stdio-only, unauthenticated, single read-only tool (`get-isis-graph`).
  Daemon-side VTY auth stack (SO_PEERCRED, service accounts, RBAC, PAM)
  already exists and is reused, not rebuilt.
