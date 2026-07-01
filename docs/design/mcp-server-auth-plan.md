# MCP Server Authentication — Design & Phasing Plan (stdio)

Tracks the addition of authentication and authorization to the zebra-rs
MCP (Model Context Protocol) server that ships inside `vtyctl` (the
`vtyctl mcp` subcommand). This document is the living plan + status: it
captures the trust model, how it reuses the daemon's existing VTY
auth/authz stack, the architecture decisions, the tool surface, the
phase-by-phase slice, and **what has landed vs what's left** so a
contributor can resume without the conversation history.

**Scope: stdio transport only.** A network-exposed transport (Streamable
HTTP) and OAuth 2.1 are **out of scope** and were dropped 2026-06-27 (see
Status). The MCP server runs only as a **local subprocess spawned per
user** over stdin/stdout — there is no network listener, no bearer
tokens, and no trusted-asserter delegation. If a network transport is
revived later, restore it from git history rather than carrying dead
HTTP/OAuth scaffolding in this plan.

Read this first if you're touching `vtyctl/src/mcp/*`. You should **not**
need to touch the daemon for this work — the daemon's VTY auth stack is
reused unchanged (see §4).

References:

- Model Context Protocol — base spec. <https://modelcontextprotocol.io/>
- `book/src/ch-06-01-session-design.md` — the existing VTY session/RBAC
  design (decisions D1–D26). **This plan reuses it as-is; stdio requires
  no new daemon-side decisions.**
- `book/src/ch-13-00-mcp-server.md` — the user-facing MCP chapter.

## Decisions captured up front

The scope is fixed by three product decisions:

1. **stdio only** — local subprocess (stdin/stdout) transport. No network
   transport, no OAuth. (HTTP + OAuth 2.1 were considered and dropped.)
2. **Read + write** — MCP tools may run `show` *and* push configuration
   (`configure`/`apply`/`clear`), not read-only.
3. **Least privilege by default** — a session exposes read-only tools
   unless the human who spawned it explicitly opts the process into write
   mode (see §5 / §8.1). The daemon's RBAC remains the hard gate
   regardless.

## 1. Trust model — `SO_PEERCRED`, exact reuse

The daemon's trust anchor is **`SO_PEERCRED`**: the VTY gRPC server reads
the connecting process's uid/gid/pid from the kernel and derives identity
and role from it (`serve.rs` `VtyPeerInterceptor`, ~lines 621–716). A
client cannot forge this.

That model is **exact** for stdio: one human spawns their *own*
`vtyctl mcp` process, so their uid flows to the daemon and existing RBAC
(`View`/`Admin`) applies directly. The MCP server is just another VTY
client — JSON-RPC to an AI assistant on one side, gRPC to the daemon on
the other — that happens to run as the invoking user.

**Consequence: no new trust mechanism, and no daemon-side change.** This
is the whole reason stdio ships cleanly on its own. The entire
trusted-asserter / asserted-identity apparatus that a multi-user network
transport would require (a single front-end process speaking for many
remote principals) is unnecessary here and has been removed from this
plan.

## 2. Identity & role model

| Transport | Authn of MCP client | Identity reaching daemon | Role source |
| --- | --- | --- | --- |
| **stdio** | OS — user spawns their own `vtyctl mcp` | `SO_PEERCRED` uid (unchanged) | Existing RBAC (uid/gid → View/Admin) |

Two invariants:

- **The daemon is the source of truth.** The MCP server pre-checks the
  required role for fast, clear errors, but `enforce_admin()` in the
  daemon (`serve.rs` ~lines 44–64, applied to `Apply`/`Clear`/configure
  entry) is the real gate. The front-end check is defense in depth, never
  the sole control.
- **Least privilege by default.** A spawned MCP session exposes read-only
  tools unless the user opted it into write mode at launch (§5). Even in
  write mode, a write only succeeds if the user's uid already maps to
  `Admin` in daemon RBAC. Existing admin-session TTLs (15-min idle / 4-h
  hard cap, session-design D2) apply unchanged.

## 3. Tool surface (read + write)

Today the server exposes a single tool, `get-isis-graph` (read-only,
backed by `Show`). For read+write it becomes a small generic set, each
tagged with a required role the server enforces *and* the daemon
re-checks:

| Tool | Daemon RPC | Required role | Notes |
| --- | --- | --- | --- |
| `list-show-commands` | `Exec` (completion) | View | discovery; flat `command → help` list generated live from the grammar |
| `show` (+ keep `get-isis-graph`) | `Show` (stream) | View | unchanged path; rejects any command not starting with `show` |
| `configure` / `apply` | `Apply` (stream) | Admin | only registered in write mode; every call audited (principal + lines) |
| `clear` | `Clear` | Admin | only registered in write mode; audited |

Write tools are **not even advertised** in `tools/list` unless the
process was launched in write mode — the AI cannot call a tool it cannot
see, and a read-only session has no write surface to misuse.

**Command discovery.** The MCP client cannot guess zebra-rs's
YANG-defined command surface, so `list-show-commands` enumerates it by
walking the daemon's completion engine (`DoExec` with
`COMPLETE_TRAILING_SPACE`, the same path that backs CLI `?`/TAB) from
`show` downward. Every token already carries an `ext:help` string in
`exec.yang`, so each entry gets a one-line explanation *and* a `kind`
(`command` runnable keyword / `category` has subcommands / `value` expects
an argument) and a `runnable` flag — all generated live, no hand-maintained
list to drift. `<cr>` markers are folded into `runnable`; bare value
placeholders (`<A.B.C.D>`) are never descended into. The result is cached
for the process lifetime.

## 4. Daemon-side changes — none

Dropping the network transport removes the entire daemon-side workstream.
The former plan's D27–D31 (trusted-asserter allowlist, asserted-identity
metadata, asserted-session keying, bounded grant, asserted-write audit)
existed **only** to let one front-end process speak for many remote OAuth
users. stdio has no such multiplexing: each user is their own process.

So stdio needs **zero** changes to `serve.rs`, `session.rs`, `vty.yang`,
or `proto/vty.proto`. It is pure reuse of the existing `SO_PEERCRED` +
RBAC stack. Audit of writes (§5) is done by the MCP front-end with the OS
principal; the daemon's existing logging is unchanged.

## 5. vtyctl `mcp` changes (new)

1. **Generalize the tool set** from the single `get-isis-graph` to
   `show` / `configure` / `clear` (keep `get-isis-graph`). Each tool is
   tagged with its required role; the server pre-checks and the daemon
   re-checks.
2. **Write-mode gating.** Default the process to **read-only**: only
   `View` tools are registered. A human opts the process into write mode
   at spawn (e.g. a `--write` / `--allow-write` flag on `vtyctl mcp`, or
   equivalent env var) — this is the *human's* decision, made outside the
   AI's control. In write mode, `configure`/`apply`/`clear` are
   registered; the daemon still gates each on the uid's `Admin` role, so
   write mode on a non-admin uid simply yields `permission_denied`.
3. **Audit writes.** Log the OS principal (uid + resolved username) and
   the submitted lines on every `configure`/`apply`/`clear`.
4. **Config home.** Minimal: the daemon host/port to connect to (already
   present as `vtyctl mcp` args). No listen address, TLS, or OAuth config
   — none of that exists in stdio mode.

## 6. Phase map (smallest shippable first)

| Phase | Scope | Touches |
| --- | --- | --- |
| 0 | **Read-only generalization.** Replace the single hard-coded tool with a generic `show` tool (plus the kept `get-isis-graph`), still read-only. No new privileges, no behavior change to writes. Smallest useful slice. | `vtyctl/src/mcp/*` |
| 1 | **Write tools + write-mode gating + audit.** Add `configure`/`apply`/`clear`, register them only in write mode, audit every write with the OS principal. Daemon `enforce_admin()` is the hard gate. | `vtyctl/src/mcp/*` |
| 2 | **Hardening.** Error-path polish, rate/size limits on tool input, BDD coverage for stdio read + write, threat-model note + book chapter (`ch-13-00`) update. | `vtyctl/src/mcp/*`, `book/` |

All three phases are confined to `vtyctl/src/mcp/*`. The daemon is not
touched.

## 7. Security properties (threat model summary)

- **Trust anchor stays the kernel.** Identity is the `SO_PEERCRED` uid of
  the user who spawned the process; a user can only ever act as
  themselves. No impersonation surface exists.
- **No network surface.** No listener, no bearer tokens, no TLS to
  misconfigure, no remote-auth code to get wrong.
- **Least privilege.** Read-only by default; write tools are not even
  advertised unless the human opted in at spawn, and the daemon still
  requires `Admin` for each write.
- **Defense in depth.** Front-end pre-check + daemon `enforce_admin()`
  re-check; the daemon is authoritative.
- **Audited writes.** Every `configure`/`apply`/`clear` records the OS
  principal and the lines submitted.
- **Residual risk (inherent to MCP):** the tools are driven by an AI
  assistant running as the user, so the AI can do anything the user's
  role permits. Read-only-by-default + explicit, human-gated write mode
  bound the blast radius; the AI never gains privilege the user didn't
  deliberately grant.

## 8. Decisions resolved / still open

1. **Write mode & `enable`/PAM — RESOLVED (2026-06-27): no `enable` tool.**
   In stdio the process already runs as the user's uid, so daemon RBAC
   grants `Admin` to admin users directly — no Cisco-style `enable`
   password is needed to *have* the role. A PAM `enable` flow would also
   force a **secret through the AI assistant** (the human would paste the
   enable password into the chat, where it is visible to and logged by the
   model), which is undesirable. **Decision:** drop the `enable` tool
   entirely. Writes are gated purely by (a) a human-set spawn flag
   (`--write`) that decides whether write tools are advertised, plus
   (b) the daemon's existing uid→`Admin` RBAC check. Revisit only if a
   future use case needs elevation *within* a running session.
2. **Authz granularity — OPEN.** View/Admin only for now, or start
   leveraging the proto's currently-unused `privilege` field for
   per-command levels later? Not needed for the initial stdio slice.

## Status

- **2026-06-27** — **Scope reduced to stdio only; HTTP transport and
  OAuth 2.1 dropped.** This removes the entire trusted-asserter /
  asserted-identity design (former decisions D27–D31), the OAuth 2.1
  resource server (PRM, JWT/JWKS validation, audience binding,
  scope→role), the Streamable HTTP transport, and the
  `rmcp`-vs-hand-rolled open question — all of which existed only to serve
  many remote users through one process. stdio needs **no daemon-side
  changes**: it reuses `SO_PEERCRED` + RBAC directly. (If a network
  transport is ever revived, recover the prior design from this file's git
  history.)
- **2026-07-01** — **Phase 0 merged to `main` (PR #1703).** Added the
  generic `show` tool (rejects non-`show` commands) and
  `list-show-commands` (live grammar discovery), alongside the kept
  `get-isis-graph`. Response wrapping factored into a shared helper for
  the upcoming write tools. Also fixed a pre-existing bug: the MCP
  entrypoint prepended `http://` to the host, corrupting `unix:` sockets
  — including the default `unix:zebra-rs/vty` — so the server could never
  reach a socket daemon; it now passes the host through to
  `ZebraClient::endpoint()` for normalization. Verified end-to-end against
  a live daemon (`show version` runs, `configure terminal` rejected,
  discovery returns 188 entries with help/kind/runnable). 7 unit tests;
  CI green (`cargo fmt`/`clippy`/`test`/`clippy (no-lua)`). **Next:
  Phase 1** (write tools + `--write` gating + audit).
- **2026-06-27** — Plan drafted. No code landed yet. Current MCP server is
  stdio-only, unauthenticated, single read-only tool (`get-isis-graph`).
  Daemon-side VTY auth stack (SO_PEERCRED, service accounts, RBAC, PAM)
  already exists and is reused, not rebuilt.
