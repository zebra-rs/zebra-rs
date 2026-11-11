#!/bin/sh
# A DHCP server for the DHCP client features: dnsmasq on one interface
# of the namespace this script runs in.
#
#   dhcp_server.sh TAG start IFACE ADDR/24 FIRST LAST LEASE_SECONDS [dnsmasq options…]
#   dhcp_server.sh TAG start6 IFACE ADDR/64 FIRST LAST LEASE_SECONDS [dnsmasq options…]
#   dhcp_server.sh TAG require-source ADDR
#   dhcp_server.sh TAG any-source
#   dhcp_server.sh TAG stop
#
# `require-source ADDR` makes the namespace drop every DHCP message whose
# IP source is neither 0.0.0.0 nor ADDR (nftables): a server, or a filter
# in front of one, that insists a client talk from the address it leased.
# `any-source` takes that back.
#
# TAG names the scratch directory (pid file, lease file, log), so two
# features' servers never share one. The server's own address is the
# lease's router and the namespace gets 198.51.100.1/32 on lo: a
# destination beyond the gateway, reachable only through the default
# route the lease gives. dnsmasq's shortest lease is two minutes.
#
# `start6` is the DHCPv6 server, and the router: dnsmasq also sends the
# Router Advertisements. They give the prefix as on-link and as
# autonomous (`slaac`), so a client may form a SLAAC address beside the
# one it leases, if it is configured to. The namespace gets
# 2001:db8:ffff::1/128 on lo, reachable only through the default route
# the advertisements give.
set -eu
tag=$1
action=$2
dir=/tmp/zebra-bdd-dhcp/$tag

case $action in
start)
    iface=$3
    addr=$4
    first=$5
    last=$6
    lease=$7
    shift 7
    mkdir -p "$dir"
    ip link set lo up
    ip addr replace 198.51.100.1/32 dev lo
    ip addr replace "$addr" dev "$iface"
    ip link set "$iface" up
    dnsmasq --conf-file=/dev/null --port=0 --interface="$iface" --bind-interfaces \
        --dhcp-range="$first,$last,255.255.255.0,$lease" \
        --dhcp-option=option:router,"${addr%/*}" \
        --dhcp-option=option:dns-server,198.51.100.53 \
        --dhcp-option=option:domain-name,example.com \
        --dhcp-authoritative --log-dhcp --log-facility="$dir/dnsmasq.log" \
        --pid-file="$dir/dnsmasq.pid" --dhcp-leasefile="$dir/leases" --user=root "$@"
    ;;
start6)
    iface=$3
    addr=$4
    first=$5
    last=$6
    lease=$7
    shift 7
    mkdir -p "$dir"
    ip link set lo up
    ip -6 addr replace 2001:db8:ffff::1/128 dev lo
    ip -6 addr replace "$addr" dev "$iface" nodad
    ip link set "$iface" up
    dnsmasq --conf-file=/dev/null --port=0 --interface="$iface" --bind-interfaces \
        --enable-ra --dhcp-range="$first,$last,slaac,64,$lease" \
        --dhcp-option=option6:dns-server,"[2001:db8:53::53]" \
        --dhcp-option=option6:domain-search,example.com \
        --log-dhcp --log-facility="$dir/dnsmasq.log" \
        --pid-file="$dir/dnsmasq.pid" --dhcp-leasefile="$dir/leases" --user=root "$@"
    ;;
require-source)
    nft -f - <<EOF
table inet dhcp_bdd {
  chain input {
    type filter hook input priority 0;
    udp dport 67 ip saddr != { 0.0.0.0, $3 } drop
  }
}
EOF
    ;;
any-source)
    nft delete table inet dhcp_bdd 2>/dev/null || true
    ;;
stop)
    nft delete table inet dhcp_bdd 2>/dev/null || true
    if [ -f "$dir/dnsmasq.pid" ]; then
        kill "$(cat "$dir/dnsmasq.pid")" 2>/dev/null || true
    fi
    rm -rf "$dir"
    ;;
*)
    echo "usage: $0 TAG start IFACE ADDR/24 FIRST LAST LEASE_SECONDS | TAG start6 IFACE ADDR/64 FIRST LAST LEASE_SECONDS | TAG require-source ADDR | TAG any-source | TAG stop" >&2
    exit 2
    ;;
esac
