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

# The XDP BFD Echo and TC EVPN replication helpers moved to cradle-rs; its .deb
# ships them to /usr/sbin and applies the file caps (zebra-rs Recommends:
# cradle-rs). zebra-rs no longer installs or caps them here.

sudo systemctl daemon-reload
sudo systemctl restart zebra-rs
