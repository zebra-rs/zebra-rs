# DHCPv4 client on an interface in a VRF

## Overview

A DHCP interface in a VRF leases through that VRF: the client's sockets
are bound to the interface, and the lease's routes go to the VRF's
table. Nothing of it reaches the default table.

Topology:

## Config Files

- r1.yaml: VRF red, wan0 in it, `address dhcp` on wan0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the server and a router whose DHCP uplink is in VRF red | |
| The lease and its route are in the VRF only | |
| Release and renew stay in the VRF | |
| Teardown topology | |
