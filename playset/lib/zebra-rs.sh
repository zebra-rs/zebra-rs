# zebra-rs / vtyctl helpers. Requires common.sh and netns.sh.

playset_zebra_rs_bin() {
    if [[ -n "${ZEBRA_RS_BIN:-}" && -x "$ZEBRA_RS_BIN" ]]; then
        echo "$ZEBRA_RS_BIN"
        return
    fi
    local built="${PLAYSET_ROOT}/../target/debug/zebra-rs"
    if [[ -x "$built" ]]; then
        echo "$built"
        return
    fi
    local staged="${PLAYSET_ROOT}/../bdd/.stage/bin/zebra-rs"
    if [[ -x "$staged" ]]; then
        echo "$staged"
        return
    fi
    echo "zebra-rs"
}

# The YANG schemas matching the binary playset_zebra_rs_bin picked — the
# BDD `.stage` contract (see bdd/Makefile): a worktree binary must run
# against this worktree's YANG, never /usr's, or a schema the binary
# knows is rejected at apply (and vice versa). Emitted as `--yang-path`
# args; empty for a PATH-resolved (installed) binary, whose schemas are
# the installed ones.
playset_zebra_rs_yang_args() {
    local bin
    bin="$(playset_zebra_rs_bin)"
    case "$bin" in
        "${PLAYSET_ROOT}/../target/debug/zebra-rs")
            echo "--yang-path=${PLAYSET_ROOT}/../zebra-rs/yang"
            ;;
        "${PLAYSET_ROOT}/../bdd/.stage/bin/zebra-rs")
            echo "--yang-path=${PLAYSET_ROOT}/../bdd/.stage/share/zebra-rs/yang"
            ;;
        *)
            :
            ;;
    esac
}

playset_vtyctl_bin() {
    if [[ -n "${VTYCTL_BIN:-}" && -x "$VTYCTL_BIN" ]]; then
        echo "$VTYCTL_BIN"
        return
    fi
    local built="${PLAYSET_ROOT}/../target/debug/vtyctl"
    if [[ -x "$built" ]]; then
        echo "$built"
        return
    fi
    echo "vtyctl"
}

playset_pid_file() {
    local netns=$1
    echo "${PLAYSET_RUN_DIR}/${netns}.pid"
}

# The startup config the daemon in `netns` loads at boot — and the file
# its `save` writes back to, since `--config-file` names both. It is a
# copy under PLAYSET_RUN_DIR, never the demo directory's own <netns>.yaml:
# the daemon runs as root and `save` replaces the file (create + rename),
# and the demo directory may be the packaged, read-only
# /usr/share/zebra-rs/playset tree. So the lab's YAML stays the pristine
# source and this copy is what the running daemon owns.
playset_config_file() {
    local netns=$1
    echo "${PLAYSET_RUN_DIR}/${netns}.yaml"
}

# Seed that copy from the demo directory. Plain `cp`, not `run cp`: the
# file starts out owned by the invoking user, so it can be hand-edited
# before the daemon has ever saved over it. A node with no YAML in the
# demo directory is left without a config file and boots unconfigured.
playset_seed_config() {
    local netns=$1
    local src="${PLAYSET_DEMO_DIR}/${netns}.yaml"
    local dst
    dst="$(playset_config_file "$netns")"
    if [[ "${PLAYSET_KEEP_CONFIG:-0}" == 1 && -f "$dst" ]]; then
        return 0
    fi
    if [[ -f "$src" ]]; then
        cp "$src" "$dst"
    fi
}

# `--config-file` for the daemon in `netns`, or nothing when the node has
# no seeded config — an unconfigured daemon, which is what every node got
# before the config file was handed to the daemon directly. Emitted as an
# arg so `playset_start_zebra` can splice it in like the yang path.
playset_zebra_rs_config_args() {
    local netns=$1
    local config
    config="$(playset_config_file "$netns")"
    if [[ -f "$config" ]]; then
        echo "--config-file=${config}"
    fi
}

playset_stop_zebra_daemon() {
    local pid_file=$1
    if [[ ! -f "$pid_file" ]]; then
        return 0
    fi

    local pid
    pid=$(<"$pid_file")
    if [[ -n "$pid" ]]; then
        run kill "$pid" 2>/dev/null || run kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pid_file"
}

playset_stop_zebra() {
    local netns
    for netns in "${PLAYSET_DAEMONS[@]}"; do
        playset_stop_zebra_daemon "$(playset_pid_file "$netns")"
    done
}

playset_start_zebra() {
    local netns=$1
    local log_file pid_file
    log_file="${PLAYSET_RUN_DIR}/${netns}.log"
    pid_file="$(playset_pid_file "$netns")"
    # shellcheck disable=SC2046 — the yang and config args are each a
    # zero-or-one flag, deliberately word-split.
    run_in_netns "$netns" "$(playset_zebra_rs_bin)" \
        $(playset_zebra_rs_yang_args) \
        $(playset_zebra_rs_config_args "$netns") \
        --daemon \
        --log-output=file \
        --log-file="$log_file" \
        --pid-file="$pid_file"
}

# Stream a config document into a running daemon. Bring-up no longer uses
# this — each node loads its own `--config-file` at boot — but it stays the
# way to inject a config mid-walkthrough, and the READMEs teach it.
# Deliberately not the same thing as the startup config: `vtyctl apply` does
# not change the file `save` writes to.
playset_apply_config() {
    local netns=$1
    local config=$2
    run_in_netns "$netns" "$(playset_vtyctl_bin)" apply -f "$config"
}
