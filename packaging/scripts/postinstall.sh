#! /bin/bash

# Configuration operators belong to this group for passwordless enable.
if ! getent group zebra-rs >/dev/null 2>&1; then
    groupadd -r zebra-rs
fi

setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' /usr/bin/zebra-rs

# Grant vtypam the minimum capabilities it needs to authenticate users
# without running as setuid root (D15). cap_dac_read_search lets it
# read /etc/shadow for pam_unix; cap_audit_write lets it emit PAM
# audit records.
if [ -x /usr/sbin/vtypam ]; then
    setcap 'cap_dac_read_search,cap_audit_write=ep' /usr/sbin/vtypam
fi

# The per-interface BFD Echo helper (spawned by zebra-rs) attaches an XDP
# program (reflect) — needs cap_bpf (kernel 5.8+) + cap_net_admin — and, when
# zebra-rs also originates Echo, sends/receives raw frames on an AF_PACKET
# socket — needs cap_net_raw. The deb ships it at /usr/sbin (built by the
# packaging Makefile); the guard keeps this safe if it isn't.
if [ -x /usr/sbin/xdp-bfd-echo ]; then
    setcap 'cap_net_admin,cap_bpf,cap_net_raw=ep' /usr/sbin/xdp-bfd-echo
fi

sudo systemctl daemon-reload
sudo systemctl restart zebra-rs
