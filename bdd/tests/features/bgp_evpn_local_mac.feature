@serial
@bgp_evpn_local_mac
Feature: BGP EVPN — a node's own MAC addresses are neither originated nor overwritten
  As a network operator
  I want `advertise-all-vni` to originate Type-2 routes only for stations
  learned behind a port — never for the bridge's own (SVI) address or an
  enslaved port's own address — and I want a peer's Type-2 for one of
  those addresses to leave the kernel's local FDB row alone,
  so that peers hold no rows for another node's devices and an anycast
  gateway shared by several PEs keeps answering its own hosts.

  The kernel keeps the bridge's own address and every port's own address
  in the same FDB as learned stations, marked `permanent` (BR_FDB_LOCAL)
  so it can deliver frames for them locally. FRR's zebra drops those rows
  before EVPN sees them; zebra-rs used to originate them (issue #2362).
  On the receive side a peer's Type-2 for such an address used to be
  installed over the local row, and its withdraw then deleted the row —
  leaving the SVI unreachable from its own hosts.

  Two iBGP (AS 65001) EVPN speakers on a shared transport bridge br0, each
  with a config-created VXLAN (VNI 10) enslaved to a bridge br10 whose
  address is fixed (the SVI MAC), plus a dummy access port host0 with a
  fixed address:
  ```
  ┌───────────────────────────────────────────┐
  │                    br0                     │
  └───────────┬───────────────────┬───────────┘
         ┌────┴────┐         ┌────┴────┐
         │   z1    │         │   z2    │
         │ .0.1/24 │         │ .0.2/24 │
         │  br10   │ fe:01   │  br10   │ fe:02
         │ vxlan10 │         │ vxlan10 │
         │  host0  │ 0a:01   │  host0  │ 0a:02
         └─────────┘         └─────────┘
  ```

  Scenario: Setup topology and establish the EVPN session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    # Each node: a bridge with a fixed address (the SVI MAC), the
    # config-created vxlan10 enslaved to it, and a dummy access port with
    # a fixed address. The kernel records both addresses as `permanent`
    # rows in br10's FDB the moment the devices exist.
    And I execute "ip link add br10 address 02:00:00:00:fe:01 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 address 02:00:00:00:0a:01 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I execute "ip link add br10 address 02:00:00:00:fe:02 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    And I execute "ip link add host0 address 02:00:00:00:0a:02 type dummy" in namespace "z2"
    And I execute "ip link set host0 master br10" in namespace "z2"
    And I execute "ip link set host0 up" in namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: A station on the access port is originated; the bridge's and the port's own addresses are not
    Given the test topology exists
    When I execute "bridge fdb add aa:bb:cc:dd:ee:01 dev host0 master static" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"
    # The kernel holds br10's and host0's own addresses right next to the
    # station, as `permanent` rows ...
    And bridge fdb "br10" in namespace "z1" should eventually contain "02:00:00:00:fe:01 master br10 permanent"
    And bridge fdb "host0" in namespace "z1" should eventually contain "02:00:00:00:0a:01 master br10 permanent"
    # ... and neither is a Type-2, locally or at the peer. (FRR does not
    # originate them either; `advertise-svi-ip` / `advertise-default-gw`
    # are how an SVI address is advertised on purpose.)
    And show command "show bgp evpn" in namespace "z1" should not contain "02:00:00:00:fe:01"
    And show command "show bgp evpn" in namespace "z1" should not contain "02:00:00:00:0a:01"
    And show command "show bgp evpn" in namespace "z2" should not contain "02:00:00:00:fe:01"
    And show command "show bgp evpn" in namespace "z2" should not contain "02:00:00:00:0a:01"

  Scenario: A station that becomes a device's own address is withdrawn
    Given the test topology exists
    When I execute "bridge fdb add aa:bb:cc:dd:ee:02 dev host0 master static" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:02"
    # The kernel updates the row in place (no delete first), so the
    # withdraw must come from the row's change of state alone.
    When I execute "bridge fdb replace aa:bb:cc:dd:ee:02 dev host0 master permanent" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z1" should eventually not contain "aa:bb:cc:dd:ee:02"
    And show command "show bgp evpn" in namespace "z2" should eventually not contain "aa:bb:cc:dd:ee:02"

  Scenario: A peer's Type-2 for this node's own SVI address never touches the local FDB row
    Given the test topology exists
    # z2 parks z1's SVI address on its access port as if it were a station,
    # so z2's Type-2 for that address reaches z1 — the shape of an anycast
    # gateway advertised by another PE.
    When I execute "bridge fdb replace 02:00:00:00:fe:01 dev host0 master static" in namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "02:00:00:00:fe:01"
    # The route reached z1's install path and was refused there — the
    # positive evidence, so the row checks below cannot pass by timing.
    And daemon log in namespace "z1" should eventually contain "mac_add: VNI 10 mac 02:00:00:00:fe:01 is a local address on bridge ifindex"
    # z1's own row (the tagged one the data path consults) stays where it
    # is, and nothing for that address lands on the VXLAN port.
    And bridge fdb "br10" in namespace "z1" should eventually contain "02:00:00:00:fe:01 vlan 1 master br10 permanent"
    And bridge fdb "vxlan10" in namespace "z1" should not contain "02:00:00:00:fe:01"
    # The withdraw is the step that used to delete the local row outright.
    When I execute "bridge fdb del 02:00:00:00:fe:01 dev host0 master" in namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually not contain "02:00:00:00:fe:01"
    And I wait 3 seconds
    And bridge fdb "br10" in namespace "z1" should eventually contain "02:00:00:00:fe:01 vlan 1 master br10 permanent"
    And bridge fdb "vxlan10" in namespace "z1" should not contain "02:00:00:00:fe:01"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
