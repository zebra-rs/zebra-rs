# Build image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner,
# projects/zebra-rs). The scanner builds this file with the repository as the
# context and with network access, then scans the finished image OFFLINE: every
# crate cargo needs — including dev-dependencies for `cargo test` — is fetched
# and compiled here. See .oss-scanner/threat_model.md for what to look at.

# rust:1-trixie floats with the latest stable toolchain, as CI does
# (.github/workflows/ci.yaml installs stable on every run).
FROM rust:1-trixie

# protobuf-compiler (tonic/prost codegen) and libpam0g-dev (vtypam) are the only
# system packages `cargo build` needs (packaging/setup-build-env.sh). iproute2
# and python3-scapy are for reproductions: run the daemon in a network namespace
# and hand-craft BGP/OSPF/IS-IS/BFD packets at it.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      protobuf-compiler libpam0g-dev iproute2 python3-scapy \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy rustfmt

COPY . /src
WORKDIR /src

# Frame pointers everywhere and line tables in release. These stay set in the
# image, so an offline rebuild after a patch reuses the artifacts below instead
# of recompiling the dependency graph.
ENV RUSTFLAGS="-C force-frame-pointers=yes" \
    CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
    CARGO_TERM_COLOR=never

# Cargo.lock is not committed, so this resolves the git branch dependencies
# (nom-derive, netlink-packet-route, rtnetlink) the same way CI does.
RUN cargo fetch

# Debug build of every binary and test target: the fast profile to iterate in.
RUN cargo build --workspace --bins \
    && cargo test --workspace --exclude bdd --no-run

# Clippy keeps its own check artifacts; warm them so a patch can be linted
# offline with CI's gate. main is clippy-clean, so a failure here is only noise.
RUN cargo clippy --workspace --all-targets -- -D warnings \
    || echo "WARNING: cargo clippy reported problems"

# Release daemon: overflow checks are off here, as in the shipped .deb, so a
# debug-only arithmetic panic can be checked against what users actually run.
RUN cargo build --release -p zebra-rs --bin zebra-rs

# The unit tests run unprivileged and offline (CI's `cargo test` lane). bdd/ is
# left out: it needs root, network namespaces and the cradle-rs data plane.
RUN cargo test --workspace --exclude bdd \
    || echo "WARNING: cargo test reported failures"

# Nothing is fetched from here on; fail fast instead of timing out.
ENV CARGO_NET_OFFLINE=true
