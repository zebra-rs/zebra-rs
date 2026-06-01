#! /bin/bash

setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' /usr/bin/zebra-rs

# Grant vtypam the minimum capabilities it needs to authenticate users
# without running as setuid root (D15). cap_dac_read_search lets it
# read /etc/shadow for pam_unix; cap_audit_write lets it emit PAM
# audit records.
if [ -x /usr/sbin/vtypam ]; then
    setcap 'cap_dac_read_search,cap_audit_write=ep' /usr/sbin/vtypam
fi

# The XDP BFD Echo reflector (spawned by zebra-rs to honour a non-zero
# Required Min Echo RX Interval) loads/attaches an XDP program, which needs
# cap_bpf (kernel 5.8+) and cap_net_admin. The deb ships it at /usr/sbin
# (built by the packaging Makefile); the guard keeps this safe if it isn't.
if [ -x /usr/sbin/bfd-echo-reflector ]; then
    setcap 'cap_net_admin,cap_bpf=ep' /usr/sbin/bfd-echo-reflector
fi

sudo systemctl daemon-reload
sudo systemctl restart zebra-rs
