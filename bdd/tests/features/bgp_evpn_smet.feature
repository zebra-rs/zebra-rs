@serial
@bgp_evpn_smet
Feature: BGP EVPN IGMP/MLD Proxy — Selective Multicast (RFC 9251)
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
              │                   │
         ┌────┴────┐         ┌────┴────┐
         │   z1    │         │   z2    │
         │ .0.1/24 │         │ .0.2/24 │
         │  br10   │         │  br10   │
         │ vxlan10 │         │ vxlan10 │
         │         │         │  host0  │  <- local (*,G) member
         └─────────┘         └─────────┘
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

  Scenario: Setup topology, EVPN iBGP, and per-node snooping bridges
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    # zebra-rs created vxlan10 from config; enslave it to a snooping
    # bridge so membership (and received SMET) map to VNI 10.
    And I execute "ip link add br10 type bridge mcast_snooping 1" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add br10 type bridge mcast_snooping 1" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    # z2's local host-facing port carries the snooped (*,G) membership.
    And I execute "ip link add host0 type dummy" in namespace "z2"
    And I execute "ip link set host0 master br10" in namespace "z2"
    And I execute "ip link set host0 up" in namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"

  Scenario: A snooped (*,G) join makes z2 originate a Type-6 SMET that z1 imports
    Given the test topology exists
    When I execute "bridge mdb add dev br10 port host0 grp 239.1.1.1 permanent" in namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[6]:[0]:[0]:[*]:[32]:[239.1.1.1]:[32]:[192.168.0.2]"
    And show command "show bgp evpn" in namespace "z1" should eventually contain "RT:65001:10"
    # The snooping bridge also auto-joins IPv6 link-local control groups
    # (ff02::…); those must NOT be proxied as SMET. Ordered after the
    # positive assert above so z1 already has EVPN routes (non-vacuous).
    And show command "show bgp evpn" in namespace "z1" should not contain "ff02"

  Scenario: z1 programs the received SMET into its kernel MDB (per-VTEP dst)
    Given the test topology exists
    # The received SMET drives two installs on z1: the bridge MDB
    # (`dev br10 port vxlan10 grp 239.1.1.1`, local membership so the
    # bridge forwards the group into the overlay) and the VXLAN MDB on the
    # `external vnifilter` device (`dev vxlan10 grp 239.1.1.1 src_vni 10
    # dst 192.168.0.2`), which delivers the group selectively to z2's VTEP
    # instead of BUM-flooding every peer (RFC 9251). z1 has no local
    # member, so the group can only appear via the SMET install.
    Then bridge mdb "br10" in namespace "z1" should eventually contain "239.1.1.1"
    And bridge mdb "vxlan10" in namespace "z1" should eventually contain "239.1.1.1"
    # The per-VTEP `dst` — the whole point: G is targeted at z2 (192.168.0.2).
    And bridge mdb "vxlan10" in namespace "z1" should eventually contain "192.168.0.2"

  Scenario: A leave withdraws the SMET and removes the MDB entry on z1
    Given the test topology exists
    When I execute "bridge mdb del dev br10 port host0 grp 239.1.1.1 permanent" in namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually not contain "[6]:[0]:[0]:[*]:[32]:[239.1.1.1]"
    And bridge mdb "br10" in namespace "z1" should not contain "239.1.1.1"
    And bridge mdb "vxlan10" in namespace "z1" should not contain "239.1.1.1"

  Scenario: An (S,G) join originates a source-specific SMET with the right source
    Given the test topology exists
    # Source-specific (IGMPv3) membership. Validates the kernel MDB
    # EATTR_SOURCE decode — z1 must see the source 192.0.2.9 in the SMET
    # key, not a (*,G) wildcard.
    When I execute "bridge mdb add dev br10 port host0 src 192.0.2.9 grp 232.1.1.1 permanent" in namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[6]:[0]:[32]:[192.0.2.9]:[32]:[232.1.1.1]:[32]:[192.168.0.2]"
    # (S,G) per-VTEP VXLAN MDB on z1: the source-specific entry carries
    # the group and z2's dst (the source rides in the MDB SET nest).
    And bridge mdb "vxlan10" in namespace "z1" should eventually contain "232.1.1.1"
    And bridge mdb "vxlan10" in namespace "z1" should eventually contain "192.168.0.2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
