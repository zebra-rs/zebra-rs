#! /bin/bash

setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' /usr/bin/zebra-rs

# Grant vtypam the minimum capabilities it needs to authenticate users
# without running as setuid root (D15). cap_dac_read_search lets it
# read /etc/shadow for pam_unix; cap_audit_write lets it emit PAM
# audit records.
if [ -x /usr/sbin/vtypam ]; then
    setcap 'cap_dac_read_search,cap_audit_write=ep' /usr/sbin/vtypam
fi

sudo systemctl daemon-reload
sudo systemctl restart zebra-rs
