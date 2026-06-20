# zebra-rs APT repository — maintainer notes

How users `apt install zebra-rs` on Ubuntu. Two pieces:

- **Binaries + signed metadata** live as assets on per-codename GitHub Releases
  in the **`zebra-rs/zebra-rs.github.io`** repo (deliberately *not* the main repo,
  so `zebra-rs/zebra-rs`'s `/releases` page shows only `v*` + `nightly`). They are
  built by `build-debs.yaml` and published by `publish-apt.yaml` (reusable
  `workflow_call` workflows in `zebra-rs/zebra-rs`), driven by `nightly.yaml` and
  `release.yaml`. Cross-repo publishing uses the `APT_REPO_TOKEN` PAT (Step 2).
- **The public signing key + a landing page** live in the separate Pages repo
  `zebra-rs/zebra-rs.github.io`, served on the custom domain **`https://zebra.rs/`**:

  ```
  zebra-rs.github.io/apt/
  ├── index.html                      # landing page with install instructions
  └── zebra-rs-archive-keyring.asc    # archive signing PUBLIC key (placeholder until Step 1)
  ```

  Canonical key URL: `https://zebra.rs/apt/zebra-rs-archive-keyring.asc`.

## Architecture (why it's shaped this way)

- **Binaries on Releases, not Pages.** Pages has soft size/bandwidth limits and
  would mean committing `.deb`s into git. Releases have no metered bandwidth and
  a 2 GB/file limit — the right home for binaries.
- **Flat repository, one per codename.** A GitHub Release's assets are a flat
  namespace (no subdirectories), incompatible with the structured
  `dists/…/binary-<arch>/` layout but a perfect match for APT's *flat* repo
  format. Each Ubuntu codename gets its own release (`apt-jammy`, `nightly-noble`, …);
  the user's machine auto-selects via `$VERSION_CODENAME`. A flat repo's single
  `Packages` index lists every architecture; APT filters by the `Architecture:`
  field, so amd64 and arm64 share one repo per codename.
- **Pages serves only the public key + landing page** (a few KB), under `/apt/`.
  The Pages root (`https://zebra.rs/`) is a client-side password gate; that gate
  is JS-only and does **not** protect static files, so the key under `/apt/` is
  directly fetchable by `curl` (which is what apt needs — the key is public).
  Conversely, anything placed under `/apt/` is publicly reachable by URL, so push
  it only when you're ready for the project to be discoverable.

## Workflows

| File | Trigger | Role |
|------|---------|------|
| `build-debs.yaml`  | `workflow_call` | Builds all six `.deb`s (jammy/noble/resolute × amd64/arm64). `nightly: true` stamps the `~nightly` version. |
| `publish-apt.yaml` | `workflow_call` | Per codename: signs a flat repo and uploads it to a `<channel>-<codename>` release. |
| `nightly.yaml`     | cron / dispatch | Calls build (`nightly: true`) → `nightly` direct-download release + `nightly-<codename>` apt repos. |
| `release.yaml`     | push tag `v*`   | Verifies tag == `version` file → build → `v<X.Y.Z>` release + `apt-<codename>` apt repos. |

The two reusable workflows are the single source of truth for build and publish;
`nightly.yaml` and `release.yaml` differ only in trigger, version stamping, and
channel (`nightly` vs `apt`).

## Activation checklist

### Step 1 — Generate the archive signing key (once, on a trusted machine)

```bash
cat >/tmp/keyspec <<'EOF'
%echo Generating zebra-rs apt archive key
Key-Type: RSA
Key-Length: 4096
Name-Real: zebra-rs apt archive
Name-Email: apt@zebra.rs
Expire-Date: 0
Passphrase: REPLACE_WITH_A_STRONG_PASSPHRASE
%commit
EOF
gpg --batch --gen-key /tmp/keyspec
KEYID=$(gpg --list-keys --with-colons apt@zebra.rs | awk -F: '/^pub:/{print $5; exit}')

# Public key -> replace the placeholder in the Pages repo, then commit + push it
gpg --export --armor "$KEYID" \
  > ../zebra-rs.github.io/apt/zebra-rs-archive-keyring.asc

# Private key (base64), for the repo secret below
gpg --export-secret-keys --armor "$KEYID" | base64 -w0 > /tmp/apt-private.b64
```

Back up the private key somewhere safe — losing it means every user has to
re-trust a new key.

### Step 2 — Configure this repository (`zebra-rs/zebra-rs`)

Settings → Secrets and variables → Actions:

- **Secrets** tab:
  - `APT_GPG_PRIVATE_KEY` = contents of `/tmp/apt-private.b64` (then delete the file)
  - `APT_GPG_PASSPHRASE` = the passphrase from the keyspec
  - `APT_REPO_TOKEN` = a fine-grained PAT with **Contents: read & write** scoped to
    `zebra-rs/zebra-rs.github.io` (the repo where apt releases are published)
- **Variables** tab:
  - `APT_PUBLISH_ENABLED` = `true`   ← the on-switch; set this *last*

Until `APT_PUBLISH_ENABLED` is `true`, the `publish-apt` job is skipped (kept
green), so nightly runs don't fail before the key exists.

### Step 3 — Publish the Pages assets

Pages is already configured (`zebra.rs`, `main` branch, `/`). Just commit + push
the `apt/` directory in the `zebra-rs.github.io` repo (with the real key from
Step 1). The key then resolves at `https://zebra.rs/apt/zebra-rs-archive-keyring.asc`,
matching the URLs in `apt/index.html`.

### Step 4 — Run it

Trigger `nightly.yaml` (`workflow_dispatch`, or wait for the cron). This creates
`nightly-jammy` / `nightly-noble` / `nightly-resolute` releases carrying the
signed flat repo. Test from a clean Ubuntu box using the nightly instructions at
`https://zebra.rs/apt/`.

## Channels

| Channel | Release tag          | Version string                        | Trigger                            |
|---------|----------------------|---------------------------------------|------------------------------------|
| nightly | `nightly-<codename>` | `26.6.2~nightlyYYYYMMDD` *(see note)*  | nightly cron / dispatch            |
| stable  | `apt-<codename>`     | `26.6.2`                              | push tag `v<X.Y.Z>` (`release.yaml`) |

> **Nightly upgradability (wired up):** each build job stamps a monotonic,
> pre-release-sorting version `26.6.2~nightlyYYYYMMDD` into the nfpm config before
> packaging, with `version_schema: none` so the Debian `~` survives verbatim
> (nfpm's default `semver` schema would mangle it). The `~` sorts *below* a future
> stable `26.6.2`, and the date makes each night an upgrade over the last.
>
> One subtlety the `publish-apt` job handles: GitHub rewrites release-asset names,
> replacing any char outside `[A-Za-z0-9._-]` with `.` — so a `~` in the filename
> would survive in the `Filename:` index but become `.` on the uploaded asset, and
> apt would 404. The job normalizes filenames to that safe set before scanning, so
> asset name == index == on-disk. The `~` stays only where it matters: the package
> version inside each `.deb`.

### Cutting a stable release

1. Bump the `version` file, then run `packaging/version-update.sh` (syncs
   `Cargo.toml` + the nfpm configs).
2. Commit, then tag and push:
   ```bash
   git tag "v$(cat version)" && git push origin "v$(cat version)"
   ```
3. `release.yaml` verifies the tag matches the `version` file, builds all six
   `.deb`s (clean version, no `~nightly`), publishes a `v<X.Y.Z>` GitHub release
   for direct download, and — when `APT_PUBLISH_ENABLED` is set — the
   `apt-<codename>` flat repos. A tag that doesn't match the `version` file fails
   fast in the `check` job.

## Operational notes

- The `apt-*` / `nightly-*` releases **are** the repository — don't delete them.
  `--clobber` updates assets in place.
- GitHub serves release assets via a 302 to `objects.githubusercontent.com`;
  apt follows it. Behind a proxy, allowlist both hosts.
- Old-version `.deb` assets accumulate across version bumps (storage is free);
  add a prune step if you want to cap history.
- The install line uses `${VERSION_CODENAME}`; an unsupported release (or a
  non-Ubuntu derivative) gets a clean 404 rather than an untested package.
