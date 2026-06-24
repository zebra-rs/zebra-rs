@serial
@bgp_evpn_igmp_sync
Feature: BGP EVPN IGMP/MLD Join/Leave Synch routes (RFC 9251 Type 7/8)
  As a network operator
  I want zebra-rs to originate, store, and route-reflect the RFC 9251
  multihoming synch routes — Type 7 (IGMP/MLD Join Synch) and Type 8
  (IGMP/MLD Leave Synch) — carrying their ES-Import RT and EVI-RT
  extended communities, so the control-plane foundation for all-active
  multihoming is exercised end to end. (DF election and the kernel-MDB
  synch dataplane are still deferred — there is no organic ES-snoop
  trigger yet, so origination is driven by the `clear bgp debug
  igmp-*-sync-*` test command.)

  Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
  bridge br0:
  ```
  ┌─────────────────────────────────┐
  │               br0               │
  └───────┬─────────────────┬───────┘
          │                 │
     ┌────┴────┐       ┌────┴────┐
     │   z1    │       │   z2    │
     │ .0.1/24 │       │ .0.2/24 │   <- originates Type-7/8 via debug cmd
     └─────────┘       └─────────┘
  ```

  z2 originates a Type-7/8 synch route via
  `clear bgp debug igmp-{join,leave}-sync-{originate,withdraw} <spec>`
  (spec = `vni,esi,group[,source]`); z1 imports it into its EVPN RIB and
  renders it under `show bgp evpn`, with the ES-Import RT and EVI-RT
  extended communities preserved.

  Scenario: Setup topology and EVPN iBGP
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"

  Scenario: z2 originates a (*,G) Type-7 Join Synch route that z1 imports
    Given the test topology exists
    When I run "clear bgp debug igmp-join-sync-originate 10,00:01:02:03:04:05:06:07:08:09,239.1.1.1" in namespace "z2"
    # The (*,G) Join Synch NLRI: ESI in the key, source wildcard, group +
    # z2's VTEP (192.168.0.2) as the Originator.
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[7]:[00:01:02:03:04:05:06:07:08:09]:[0]:[0]:[*]:[32]:[239.1.1.1]:[32]:[192.168.0.2]"
    # RFC 9251 §9.5 mandates an ES-Import RT (auto-derived from the ESI's
    # high-order 6 octets) and exactly one EVI-RT EC (carrying the EVI RT).
    And show command "show bgp evpn" in namespace "z1" should eventually contain "es-import:01:02:03:04:05:06"
    And show command "show bgp evpn" in namespace "z1" should eventually contain "evi-rt:rt:65001:10"
    # The route-type filter (RFC 9251 Type 7) selects only the Join Synch route.
    And show command "show bgp evpn route-type igmp-join-sync" in namespace "z1" should eventually contain "[7]:[00:01:02:03:04:05:06:07:08:09]"

  Scenario: Withdrawing the Type-7 route removes it from z1
    Given the test topology exists
    When I run "clear bgp debug igmp-join-sync-withdraw 10,00:01:02:03:04:05:06:07:08:09,239.1.1.1" in namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually not contain "[7]:[00:01:02:03:04:05:06:07:08:09]"

  Scenario: z2 originates a source-specific (S,G) Type-8 Leave Synch route
    Given the test topology exists
    # (S,G) Leave Synch: source 192.0.2.9 present in the key, group 232.1.1.1.
    When I run "clear bgp debug igmp-leave-sync-originate 10,00:01:02:03:04:05:06:07:08:09,232.1.1.1,192.0.2.9" in namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[8]:[00:01:02:03:04:05:06:07:08:09]:[0]:[32]:[192.0.2.9]:[32]:[232.1.1.1]:[32]:[192.168.0.2]"
    And show command "show bgp evpn route-type igmp-leave-sync" in namespace "z1" should eventually contain "[8]:[00:01:02:03:04:05:06:07:08:09]"

  Scenario: Withdrawing the Type-8 route removes it from z1
    Given the test topology exists
    When I run "clear bgp debug igmp-leave-sync-withdraw 10,00:01:02:03:04:05:06:07:08:09,232.1.1.1,192.0.2.9" in namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually not contain "[8]:[00:01:02:03:04:05:06:07:08:09]"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
