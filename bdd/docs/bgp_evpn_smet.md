# BGP EVPN IGMP/MLD Proxy — Selective Multicast (RFC 9251)

## Overview

As a network operator
I want zebra-rs to originate a Type-6 SMET route from locally-snooped
IGMP/MLD membership and install received SMET routes as selective
kernel bridge MDB entries, so multicast is delivered only to PEs that
asked for it instead of flooded over the Type-3 BUM tree.
Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
bridge br0, each with a local VXLAN (VNI 10) enslaved to a per-node
IGMP-snooping bridge br10:
```
┌───────────────────────────────────────────┐
│                    br0                     │
└───────────┬───────────────────┬───────────┘
```
z2 carries a local (*,G)=239.1.1.1 membership (injected via
`bridge mdb add`); the kernel emits RTM_NEWMDB, zebra-rs maps br10 to
VNI 10 and originates a Type-6 SMET. z1 imports it and programs a
selective kernel bridge MDB entry on br10 with `dst` = z2's VTEP.
NOTE: the per-VTEP assertions read `dst`/`src_vni` from
`bridge mdb show dev vxlan10`, which iproute2 renders only from 6.5 on
(VXLAN MDB support). The stock Ubuntu 24.04 `bridge` (6.1) lists the
group but silently omits `dst`, failing the assertion even though the
kernel entry is correct — keep a >= 6.5 `bridge` on the BDD host
(e.g. `sudo install ~/iproute2/bridge/bridge /usr/local/sbin/bridge`;
`sudo` resolves /usr/local/sbin ahead of /usr/sbin).

## Notes

z2 carries a local (*,G)=239.1.1.1 membership (injected via
`bridge mdb add`); the kernel emits RTM_NEWMDB, zebra-rs maps br10 to
VNI 10 and originates a Type-6 SMET. z1 imports it and programs a
selective kernel bridge MDB entry on br10 with `dst` = z2's VTEP.
NOTE: the per-VTEP assertions read `dst`/`src_vni` from
`bridge mdb show dev vxlan10`, which iproute2 renders only from 6.5 on
(VXLAN MDB support). The stock Ubuntu 24.04 `bridge` (6.1) lists the
group but silently omits `dst`, failing the assertion even though the
kernel entry is correct — keep a >= 6.5 `bridge` on the BDD host
(e.g. `sudo install ~/iproute2/bridge/bridge /usr/local/sbin/bridge`;
`sudo` resolves /usr/local/sbin ahead of /usr/sbin).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology, EVPN iBGP, and per-node snooping bridges | |
| A snooped (*,G) join makes z2 originate a Type-6 SMET that z1 imports | |
| z1 programs the received SMET into its kernel MDB (per-VTEP dst) | |
| A leave withdraws the SMET and removes the MDB entry on z1 | |
| An (S,G) join originates a source-specific SMET with the right source | |
| Teardown topology | |
