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
    echo "zebra-rs"
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
    run_in_netns "$netns" "$(playset_zebra_rs_bin)" \
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
