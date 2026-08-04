# Site-to-site IPsec with strongSwan (vpn ipsec, ISO feature)

## Overview

zebra-rs consumes the VyOS-style `vpn ipsec` config subtree
(enabled with `--feature iso`), renders strongSwan swanctl
configuration and loads it into charon over the vici socket;
`show vpn ipsec` reads live SA state back over the same socket
(sa/connections) and from the kernel (state/policy).

Topology: two nodes, IKEv2 with a pre-shared key, one policy-based
tunnel between dummy-anchored subnets.

Each node runs charon-systemd + zebra-rs inside a private mount
namespace (tests/scripts/ipsec_node.sh) so both instances use the
stock /etc/swanctl and /run/charon.vici paths without colliding on
the shared filesystem — see the script header. Requires
charon-systemd and strongswan-swanctl installed on the host.

## Config Files

- z1.conf, z2.conf: psk table with both endpoint ids, esp/ike
  groups (AES-256-GCM, DH group 19), one site-to-site peer with
  tunnel 1 between the dummy subnets.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup two IPsec nodes and establish the tunnel | |
| Traffic flows through the ESP tunnel and counters move | |
| Deleting the config unloads the tunnel declaratively | |
| Teardown topology | |
