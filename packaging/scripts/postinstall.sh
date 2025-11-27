#! /bin/bash

setcap 'cap_net_bind_service=ep cap_net_admin=ep cap_net_bind_service=ep cap_net_broadcast=ep cap_net_raw=ep' /usr/bin/zebra-rs

sudo systemctl daemon-reload
sudo systemctl restart zebra-rs
