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
    # shellcheck disable=SC2046 — the yang args are zero-or-one flag,
    # deliberately word-split.
    run_in_netns "$netns" "$(playset_zebra_rs_bin)" \
        $(playset_zebra_rs_yang_args) \
        --daemon \
        --log-output=file \
        --log-file="$log_file" \
        --pid-file="$pid_file"
}

playset_apply_config() {
    local netns=$1
    local config=$2
    run_in_netns "$netns" "$(playset_vtyctl_bin)" apply -f "$config"
}
