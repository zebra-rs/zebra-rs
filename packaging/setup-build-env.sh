#!/usr/bin/env bash
#
# setup-build-env.sh — prepare a build host for zebra-rs.
#
# Installs everything needed to build the Rust workspace, the `vty` shell, the
# XDP/eBPF BFD Echo helper, and the Debian package, mirroring the steps in
# README.md and the CI workflows under .github/workflows/ (ci.yaml,
# build-amd64.yaml, build-arm64.yaml).
#
# What it installs:
#   * APT system packages (build-essential, protobuf-compiler, libpam0g-dev,
#     bison, xxd, ...) for the workspace and the `vty` build.
#   * The stable Rust toolchain via rustup (if cargo is not already present).
#   * The nightly Rust toolchain + rust-src for the bpfel-unknown-none target.
#   * LLVM (default 18) from apt.llvm.org, required to link bpf-linker.
#   * bpf-linker (default 0.10.3, the locally validated combo with LLVM 18.1).
#   * nfpm from the goreleaser APT repo, the Debian package builder.
#
# Usage:
#   packaging/setup-build-env.sh [options]
#
# Options:
#   --no-xdp     Skip the XDP/eBPF toolchain (nightly rust-src, LLVM, bpf-linker).
#                Use this if you only build with `make all` / `cargo test`.
#   --no-nfpm    Skip nfpm (only needed to build the .deb package).
#   --no-rust    Do not install rustup/Rust (assume a toolchain is present).
#   -h, --help   Show this help and exit.
#
# Environment overrides:
#   LLVM_VERSION        LLVM major version to install (default: 18).
#   BPF_LINKER_VERSION  bpf-linker version to install (default: 0.10.3).
#
# The script is idempotent: re-running it skips work that is already done.

set -euo pipefail

# ---- configuration -----------------------------------------------------------

LLVM_VERSION="${LLVM_VERSION:-18}"
BPF_LINKER_VERSION="${BPF_LINKER_VERSION:-0.10.3}"

INSTALL_XDP=1
INSTALL_NFPM=1
INSTALL_RUST=1

# System packages. build-essential/pkg-config/curl drive the `vty` C build (GNU
# bash compiled from source); protobuf-compiler + libpam0g-dev are the only ones
# the plain `cargo build`/`cargo test` needs; bison/xxd complete
# the `vty` shell build. wget is used to fetch the LLVM installer; git/make round
# out the build.
APT_PACKAGES=(
    build-essential
    pkg-config
    curl
    wget
    git
    make
    protobuf-compiler
    libpam0g-dev
    bison
    xxd
)

# ---- helpers -----------------------------------------------------------------

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33m warning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"
}

# sudo wrapper: use sudo only when not already root.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---- argument parsing --------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --no-xdp)   INSTALL_XDP=0 ;;
        --no-nfpm)  INSTALL_NFPM=0 ;;
        --no-rust)  INSTALL_RUST=0 ;;
        -h|--help)  usage; exit 0 ;;
        *)          die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# ---- preflight ---------------------------------------------------------------

if ! need_cmd apt-get; then
    die "this script targets Ubuntu/Debian (apt-get not found). See README.md 'Build Requirements' for other distributions."
fi

if [ -n "$SUDO" ] && ! need_cmd sudo; then
    die "not running as root and 'sudo' is not installed; re-run as root or install sudo."
fi

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
log "Preparing zebra-rs build environment (arch: ${ARCH})"

# ---- 1. system packages ------------------------------------------------------

log "Installing system packages via apt"
$SUDO apt-get update
$SUDO apt-get install -y "${APT_PACKAGES[@]}"

# ---- 2. Rust stable ----------------------------------------------------------

# Make an existing rustup/cargo visible even if the current shell was started
# before it was installed.
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

if [ "$INSTALL_RUST" -eq 1 ]; then
    if need_cmd cargo && need_cmd rustup; then
        log "Rust toolchain already present ($(rustc --version 2>/dev/null || echo unknown)); skipping rustup install"
    else
        log "Installing the stable Rust toolchain via rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
else
    info "Skipping Rust install (--no-rust)"
fi

need_cmd cargo || die "cargo not found on PATH. Install Rust (rustup) or drop --no-rust, then re-run."

# ---- 3. XDP/eBPF toolchain: nightly rust-src, LLVM, bpf-linker ---------------

if [ "$INSTALL_XDP" -eq 1 ]; then
    log "Installing nightly Rust toolchain with rust-src (for bpfel-unknown-none)"
    rustup toolchain install nightly --component rust-src

    LLVM_BIN="/usr/lib/llvm-${LLVM_VERSION}/bin"
    if [ -x "${LLVM_BIN}/llvm-config" ] || [ -x "${LLVM_BIN}/clang" ]; then
        log "LLVM ${LLVM_VERSION} already installed at ${LLVM_BIN}; skipping"
    else
        log "Installing LLVM ${LLVM_VERSION} from apt.llvm.org"
        tmp_llvm="$(mktemp --suffix=.sh)"
        wget -qO "$tmp_llvm" https://apt.llvm.org/llvm.sh
        chmod +x "$tmp_llvm"
        $SUDO "$tmp_llvm" "${LLVM_VERSION}"
        rm -f "$tmp_llvm"
    fi

    # bpf-linker links against the LLVM we just installed, so put it on PATH for
    # the build. This export lives only for this script's lifetime.
    export PATH="${LLVM_BIN}:$PATH"

    installed_bpf_linker="$(cargo install --list 2>/dev/null \
        | awk '/^bpf-linker /{gsub(/[v:()]/,""); print $2}')"
    if [ "$installed_bpf_linker" = "$BPF_LINKER_VERSION" ]; then
        log "bpf-linker ${BPF_LINKER_VERSION} already installed; skipping"
    else
        log "Installing bpf-linker ${BPF_LINKER_VERSION} (linked against LLVM ${LLVM_VERSION})"
        cargo install bpf-linker --version "${BPF_LINKER_VERSION}" --locked
    fi
else
    info "Skipping XDP/eBPF toolchain (--no-xdp). 'make xdp-bfd-echo' and the .deb build need it."
fi

# ---- 4. nfpm (Debian package builder) ---------------------------------------

if [ "$INSTALL_NFPM" -eq 1 ]; then
    if need_cmd nfpm; then
        log "nfpm already installed ($(nfpm --version 2>/dev/null | head -n1)); skipping"
    else
        log "Installing nfpm from the goreleaser APT repo"
        echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' \
            | $SUDO tee /etc/apt/sources.list.d/goreleaser.list >/dev/null
        $SUDO apt-get update
        $SUDO apt-get install -y nfpm
    fi
else
    info "Skipping nfpm (--no-nfpm). Only needed to build the .deb package."
fi

# ---- done --------------------------------------------------------------------

log "Build environment ready."
echo
info "Next steps:"
info "  make all                 # build the workspace + vty shell"
if [ "$INSTALL_XDP" -eq 1 ]; then
    info "  make xdp-bfd-echo        # build the XDP BFD Echo helper"
    info ""
    info "  If a shell can't find bpf-linker's LLVM, add it to PATH:"
    info "      export PATH=\"/usr/lib/llvm-${LLVM_VERSION}/bin:\$PATH\""
fi
if [ "$INSTALL_NFPM" -eq 1 ]; then
    info "  cd packaging && make ${ARCH}   # build the .deb package"
fi
if [ "$INSTALL_RUST" -eq 1 ] && [ -f "$HOME/.cargo/env" ]; then
    info ""
    info "  If 'cargo' isn't found in a new shell, run: . \"\$HOME/.cargo/env\""
fi
