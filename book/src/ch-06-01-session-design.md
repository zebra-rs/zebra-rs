# VTY Session Management Design

This chapter documents the design of session management for the VTY
gRPC channel between zebra-rs and its clients (`vty`, `vtyhelper`,
`vtyctl`). It captures the rationale behind the architecture so that
future implementation work and reviewers have the full context.

User-facing configuration is documented in
[VTY Access and Authentication](ch-06-00-vty-access.md). This chapter
is concerned with the implementation beneath those interfaces.

## Goals

- Allow operators to type `enable` once per VTY shell and have the
  privilege persist across subsequent commands in the same shell.
- Derive peer identity from kernel-guaranteed sources only — never
  trust client-supplied session tokens.
- Compose with PAM for authentication (TACACS+ via `pam_tacplus`,
  local accounts via `pam_unix`).
- Detect parent-shell death (including `kill -9`) and clean up
  promptly.
- Support per-network-namespace deployments transparently.

## Non-goals

- True OS-level uid=0 escalation. `enable` is an **application-level**
  role transition; the daemon already holds the network capabilities
  it needs.
- Cross-tab session sharing. Each interactive shell is its own
  session, mirroring the behavior of Cisco IOS vty lines.
- Persistence of `enable` state across daemon restart. Re-authentication
  is required after restart.
- Configure-mode locking. Deferred (see [Deferred Work](#deferred-work)).

## Background: How vty invokes vtyhelper

The `vty` shell is a patched GNU bash 5.2. Its `vty.sh` startup
script invokes `vtyhelper` via shell command substitution
(`$(vtyhelper ...)`) on four events:

| Event | Command | Purpose |
|---|---|---|
| Tab | `vtyhelper -t -m MODE WORDS...` | Token completion |
| `?` | `vtyhelper -t -m MODE WORDS...` | Help with descriptions |
| Enter | `vtyhelper [-j] -m MODE LINE` | Execute command |
| Startup / mode change | `vtyhelper -f -m MODE` | List first-level commands |

Each invocation is a fresh fork+exec — `vtyhelper` runs to
completion, writes to stdout, and exits. A single user keystroke
sequence may trigger 5-10 invocations.

Critically, `$(...)` does **not** alter the parent-process chain:
bash forks once, the child execs `vtyhelper` in place, and
`vtyhelper`'s `PPid` is the original vty bash. This invariant is the
foundation of the session-key design below.

## Architecture

```
+-----------------+           +--------------------+
|  vty (bash)     |           |  zebra-rs (daemon) |
|  pid = 1000     |   gRPC    |                    |
|                 |  abstract |  +--------------+  |
|  +-----------+  | UDS @vty  |  | SessionTable |  |
|  | vtyhelper |--+---------->|  |              |  |
|  | pid=1234  |  |           |  | key:(uid,    |  |
|  | ppid=1000 |  |           |  |   bash_pid)  |  |
|  +-----------+  |           |  |              |  |
|                 |           |  +--------------+  |
|  (one per key   |           |                    |
|   event, short  |           |  reads /proc to    |
|   lived)        |           |  derive bash_pid   |
+-----------------+           +--------------------+
```

The daemon owns a `SessionTable` keyed by `(peer_uid, parent_pid)`.
Both components are derived from the kernel (`SO_PEERCRED` plus
`/proc/{peer_pid}/status`), never from client-supplied data.

## Session key derivation

For every incoming gRPC request the daemon resolves a session key:

```rust
fn resolve_session_key(peer_uid: u32, peer_pid: u32)
    -> Result<(u32, u32), Status>
{
    // Guard 0: PID-namespace mismatch (D12).
    // SO_PEERCRED returns 0 when the peer is not visible in the
    // daemon's PID namespace.
    if peer_pid == 0 {
        return Err(Status::failed_precondition(
            "client not visible in daemon's PID namespace"
        ));
    }

    let stat = procfs::process::Process::new(peer_pid as i32)
        .and_then(|p| p.status())
        .map_err(|_| Status::internal("cannot read /proc"))?;
    let ppid = stat.ppid as u32;

    // Guard 1: orphan client (parent died, reparented to init).
    if ppid <= 1 {
        return Err(Status::unauthenticated(
            "orphan client (no parent shell)"
        ));
    }

    // Guard 2: parent uid must match peer uid (PID-reuse race).
    let parent = procfs::process::Process::new(ppid as i32)
        .map_err(|_| Status::unauthenticated("parent shell vanished"))?;
    if parent.status().map(|s| s.ruid).unwrap_or(u32::MAX) != peer_uid {
        return Err(Status::unauthenticated("parent uid mismatch"));
    }

    Ok((peer_uid, ppid))
}
```

Why this design:

- **`SO_PEERCRED` cannot be forged** by the client. Kernel guarantees
  the uid/pid reflect the peer as it appeared at `connect(2)`.
- **`/proc/{pid}/status` `PPid`** is likewise kernel-backed.
- **The client never supplies a session id**, so there is no token to
  leak, no env var to manage, no replay risk.
- The same key `(uid, bash_pid)` is derived for every `vtyhelper`
  invocation spawned from the same vty bash, automatically grouping
  all RPCs from one shell into one session.

Performance: completion events fire frequently, so the resolver
short-circuits to a single `/proc/{pid}/status` read for known
sessions and only walks the parent chain on first-seen keys.

## Lifecycle

```
[create]  Lazy on first RPC; no explicit OpenSession call.
[active]  Each RPC updates Session.last_active.
[end]     Triggered by any of:
            - Parent bash death (pidfd, immediate)
            - Idle TTL expiry (~10 min, periodic sweep)
            - Explicit Logout RPC (bash EXIT trap)
            - Daemon shutdown
```

Bash-death detection uses a three-tier strategy:

1. **`pidfd_open(bash_pid)`** wrapped in `tokio::io::unix::AsyncFd`.
   Fires immediately when the bash process exits, including via
   `kill -9`. (Linux 5.3+.)
2. **`Logout` RPC** sent from the bash EXIT trap. Covers normal
   `exit` cleanly even if pidfd notification is briefly delayed.
3. **Periodic `/proc/{bash_pid}` sweep** every 60s. Backstop for
   any case the above miss.

On session termination, the daemon aborts any streaming RPCs bound
to the session (see [Streaming RPCs](#streaming-rpcs-phase-7)) and
releases per-session resources.

## Authentication

### enable command flow

```
vty bash         vtyhelper            daemon                vtypam
  |                  |                  |                     |
  |--enable-------->-|                  |                     |
  |  (read passwd    |--Enable RPC---->|                     |
  |   with echo off) |  {password}     |--spawn pipe-------->|
  |                  |                  |  username via argv  |
  |                  |                  |  password via stdin |
  |                  |                  |<--exit code---------|
  |                  |                  |  0=ok 1=auth_fail   |
  |                  |<--EnableReply--- |  2=acct_invalid     |
  |<--prompt change--|  {ok, ttl_secs} |  3=sys_error        |
  |                  |                  |                     |
  |                  |                  | session.enabled=true|
  |                  |                  | session.expires=... |
```

### vtypam helper

`vtypam` is a small, dedicated PAM helper binary:

- Installed at `/usr/sbin/vtypam` in distribution packages, or
  `${HOME}/.zebra/bin/vtypam` in development builds.
- Setuid root (or with `cap_dac_read_search,cap_audit_write=ep` to
  avoid the full setuid surface, depending on packaging).
- Reads username from `argv[1]`, password from stdin (never argv,
  to keep it out of `/proc/*/cmdline`).
- Calls `pam_start("zebra-rs", ...)` → `pam_authenticate` →
  `pam_acct_mgmt` → `pam_end` and exits with a numeric code.
- Does not communicate priv-lvl or AV-pairs back to the daemon
  (D14).

Isolating PAM in a separate process keeps the daemon free of
shadow-read privileges and confines libpam (a C library invoking
arbitrary modules) inside a minimal helper.

### PAM service file

```
# /etc/pam.d/zebra-rs
auth     required pam_unix.so
account  required pam_unix.so
```

Or, for TACACS+ deployments:

```
# /etc/pam.d/zebra-rs
auth     [success=done default=ignore] \
         pam_tacplus.so server=10.0.0.1 secret=KEY encrypt
auth     required  pam_unix.so   # local fallback
account  required  pam_unix.so
```

TACACS+ integration is **authentication-only** (D13). zebra-rs does
not consume priv-lvl from TACACS+ responses, does not send TACACS+
accounting, and does not perform per-command authorization. The
role decision lives entirely in the daemon (see [RBAC](#rbac)).

### enable TTL

Successful `enable` sets two timestamps on the session:

- `enable_expires`: sliding idle TTL (15 min). Each authorized RPC
  pushes it forward by 15 min.
- `enable_hard_deadline`: absolute deadline (4 h from the original
  `enable`). Not extended by activity.

The session drops back to unprivileged when either deadline is
reached, or on explicit `disable`. There is no persistence across
daemon restart.

## RBAC

The Session struct carries a `role` field (`View`, `Operator`,
`Admin`). Three ways to acquire `Admin`:

- **Root (uid=0)**: implicit Admin from session creation, no enable
  required (D20). The `enable` RPC short-circuits to success
  without invoking PAM.
- **Interactive**: type `enable`, authenticate via PAM, hold Admin
  for the TTL.
- **Service account** (for automation): a uid listed in the env
  var `ZEBRA_VTY_SERVICE_ACCOUNTS` (CSV of decimal uids) is
  permanently Admin without enable. Typically set in the
  daemon's systemd unit:

  ```ini
  # /etc/systemd/system/zebra-rs.service.d/service-accounts.conf
  [Service]
  Environment=ZEBRA_VTY_SERVICE_ACCOUNTS=999,1001
  ```

  Service accounts bypass PAM (no password to ship in scripts) and
  are identified by uid alone via SO_PEERCRED. The env var is read
  once at daemon startup (D21); changes require restart. Future
  YANG-driven runtime mutability is the deferred Phase 4-d-ii.

`vtyctl` invocations are short-lived; their sessions exist for one
or two RPCs and then idle out. Because session state is per-bash_pid
and `vtyctl` rarely has a long-lived parent shell, **interactive
`enable` is effectively a `vty` shell-only feature**. Automated
admin work uses service accounts.

## Pipeline / parent-process conventions

vty's `vty.sh` invokes `vtyhelper` via `$(vtyhelper ...)` so the
parent process is always the vty bash directly. The shell never
runs `vtyhelper` inside explicit subshells `( ... )` or command
substitutions other than top-level assignment. This invariant is
not enforced by code; it is a convention of the patched bash.

If a user invokes `vtyhelper` manually from a normal shell, its
parent becomes that shell and the session becomes scoped to that
shell's pid. This is intentional and supported (for debugging), but
the resulting "session" lasts only as long as that shell.

## PID-namespace assumption

The daemon and all clients must run in the **same PID namespace**.
`ip netns exec` does not change PID namespace by default, so typical
per-VRF deployments work without configuration.

Container deployments require either:
- daemon and client in the same container, or
- `--pid host` to share the host's PID namespace.

A daemon in container A cannot serve a client in container B: the
abstract Unix socket is also netns-scoped, so the connection cannot
even be established.

When `SO_PEERCRED` returns `peer_pid == 0`, the peer is not visible
in the daemon's PID namespace; the connection is rejected with
`FailedPrecondition`.

## Streaming RPCs (Phase 7)

Some commands need server-streaming RPCs rather than unary calls:

- `ping count N` — one reply per ICMP echo.
- `traceroute` — one reply per hop.
- `monitor terminal` — live log tail, filtered by severity/protocol.
- `commit confirmed` — countdown / confirmation events.

Streams are bound to a session via `Session.active_streams:
Vec<AbortHandle>`. When the session ends (pidfd, GC, Logout), every
attached stream is aborted, ensuring the daemon never leaks
subscribers when bash dies.

`vtyhelper` for streaming commands stays alive for the duration of
the stream and forwards SIGINT (Ctrl-C from vty bash) to cancel the
stream cleanly. Whether a command is streaming is declared by the
daemon in the first-level command listing (`-f`) so `vty.sh` can
dispatch with or without `$(...)` capture.

## Implementation phases

| Phase | Scope |
|---|---|
| 1 | SessionTable, `(uid, ppid)` resolver, peer-validation guards. No proto changes. |
| 2 | Idle TTL + periodic procfs sweep. |
| 3 | pidfd-based immediate parent-death detection. |
| 4 | RBAC, enable RPC, vtypam helper, PAM service file, service-accounts in YANG. |
| 5 | *(deferred)* configure-mode lock. |
| 6 | Logout RPC + bash EXIT trap integration. |
| 7 | Streaming RPCs (ping, traceroute, monitor terminal, commit confirmed). |

Each phase is intended to ship as an independent PR.

## Decisions

| # | Decision |
|---|---|
| D1 | Default `enable` backing store is PAM; YANG-local-hash mode is a future option. |
| D2 | enable TTL is sliding 15 min with a 4 h hard cap. |
| D3 | enable state is not persisted across daemon restart. |
| D4 | enable does not propagate to other shell tabs. Each bash is its own session. |
| D5 | The Phase 1 Session struct is minimal; enable-related fields are added in Phase 4. |
| D6 | PAM is invoked via a separate setuid (or capability-restricted) helper named `vtypam`, installed at `/usr/sbin/vtypam` for distribution. |
| D7 | The initial Enable RPC uses a single password field. Bidirectional PAM conversation (for OTP, password change) is deferred. |
| D8 | Session key derivation assumes the direct vty-bash-to-vtyhelper parent relationship; the daemon verifies via `/proc` (orphan check + parent uid match) but does not inspect the parent's command name. |
| D9 | vtyctl receives no special-casing. Stateful RPCs (configure, enable, monitor) naturally fail across vtyctl invocations because the session is not continuous. |
| D10 | Script-driven admin operations use YANG `service-accounts` (permanent admin by uid), not interactive enable. |
| D11 | Configure-mode locking is not part of the initial implementation. Concurrent edits are tolerated; conflict-resolution policy is left to commit semantics. |
| D12 | The daemon and its clients must share a PID namespace. `peer_pid == 0` from SO_PEERCRED is rejected as cross-PID-ns access. |
| D13 | TACACS+ integration is authentication-only via `pam_tacplus`. No login/command accounting, no per-command authorization. |
| D14 | vtypam communicates result via exit code only. priv-lvl and TACACS+ AV-pairs are not propagated to the daemon. |
| D15 | vtypam is installed with file capabilities `cap_dac_read_search,cap_audit_write=ep`, not setuid root. setuid root is documented as a fallback for environments where file caps are stripped by packaging. |
| D16 | The daemon does **not** install `/etc/pam.d/zebra-rs`. A `zebra-rs.example` sample (minimal `pam_unix` stack) is shipped and the admin copies it into place, optionally rewriting it as `@include common-auth` on Debian/Ubuntu. |
| D17 | enable failure rate-limit lives in the daemon (per-uid counter, 5 failures within 30 s triggers a 30 s lockout, in-memory only). `pam_faillock` is documented as an optional stronger layer that admins can stack in the PAM service file. |
| D18 | RBAC is 3-tier: `View`, `Operator`, `Admin`. Maps cleanly onto Cisco priv-lvl ranges 0-1 / 2-14 / 15. YANG-configurable roles are explicitly out of scope. |
| D19 | Default idle session TTL is **600 s** with a 60 s sweep interval (Cisco IOS `exec-timeout 10 0` convention). Configurable later if a deployment needs it. |
| D20 | **Root (uid=0) is implicitly Admin.** New sessions for uid=0 are created with `role=Admin` / `enabled=true` / no deadlines; the `enable` RPC short-circuits to success without spawning vtypam. Service-account configuration (Phase 4-d) does not need to list uid 0. Reason: root already owns the host and `pam_unix` against the daemon's own owning account is awkward UX. |
| D21 | **Service-accounts via env var** for Phase 4-d initial implementation. `ZEBRA_VTY_SERVICE_ACCOUNTS=999,1001,...` (CSV of decimal uids) names uids that are permanent Admin from session creation, with the same shape as root (no deadlines, enable short-circuits to success). State is fixed at daemon startup; runtime changes require a restart. Full YANG integration is deferred to a follow-up (Phase 4-d-ii) if a deployment demands runtime mutability. |
| D22 | **Initial admin gates: Apply and Clear RPCs.** `SessionTable::require_admin` checks `enabled`, enforces sliding TTL + hard cap (with auto-downgrade on expiry), and slides the idle deadline on each authorized call. |
| D23 | **Configure-mode admin gate** on `DoExec`. For `ExecType::Exec` only (completion paths remain free): admin is required when `mode != "exec"` (catches a client that sets `mode=configure` directly) and when `mode == "exec" && first_word == "configure"` (UX courtesy — block at entry so the prompt doesn't flip uselessly). Configure-mode mutex/lock is deliberately NOT included; multiple admins can enter configure simultaneously (D11 still deferred). |
| D24 | **Auto-elevate on `configure`**. When a non-admin user types `configure`, the vty bash shell function optimistically tries first (admins succeed silently). On `PermissionDenied` it prompts for `Password:` (echo off) and sends an `Enable` RPC with `auth_user="root"` — su-style PAM authentication against the `root` account regardless of who the caller is. On success it retries `configure` and flips `CLI_PRIVILEGE`. `EnableRequest` gains an optional `auth_user` field for this; empty string keeps the original sudo-style behavior. |
| D25 | **YANG-driven service-accounts** (Phase 4-d-ii). New `vty.yang` module with `list service-account { key uid; leaf description; }` under `container vty` in the global `grouping config`. `ConfigManager` maintains an `Arc<RwLock<HashSet<u32>>>` updated by `commit_config` on `vty service-account uid N` Set/Delete diffs; `SessionTable` reads the union of this set and the env-var set in `is_service_account`. The env var (D21) remains as a startup-only seed for environments where YANG config is unavailable; YANG is the runtime-mutable path. |

## Deferred work

Items intentionally left out of the initial roadmap:

- **Configure-mode lock** (Phase 5). Add if multi-operator
  contention becomes a real problem.
- **TACACS+ per-command authorization and accounting**. Requires
  a TACACS+ client in the daemon (Rust `tacacs-plus` crate or
  in-house). Add when an operator deployment demands it.
- **priv-lvl-based role mapping**. Tied to the TACACS+ expansion
  above. Requires expanding vtypam's output format to JSON.
- **PAM session API (`pam_open_session`/`pam_close_session`)** for
  login accounting. Requires the daemon to hold a long-lived
  `pam_handle_t`, which is feasible but adds libpam linkage to
  the daemon process.
- **YANG-local-hash enable mode** as an alternative to PAM. Useful
  for appliances with no system user accounts.
- **Bidirectional PAM conversation** for multi-step authentication
  (OTP, forced password change). Requires a streaming Enable RPC.

## Open questions

These were identified during design and require decisions before
the relevant phase begins:

| # | Question | Phase |
|---|---|---|
| Q12a | vtyhelper streaming model: per-command subcommands vs unified streaming dispatch | 7 |
| Q12b | `monitor terminal` output format: human-readable, JSON, or both | 7 |
| Q12c | `monitor terminal` max concurrent subscribers | 7 |
| Q12d | `monitor terminal` drop policy under backpressure | 7 |
| Q12e | ping/traceroute implementation: in-daemon raw sockets vs spawning system binaries | 7 |
