@serial
@bgp_tcp_mss
Feature: BGP TCP MSS (neighbor tcp-mss)
  As a network operator
  I want to cap the TCP Maximum Segment Size of a BGP session so the
  daemon stays under a path MTU smaller than the interface MTU (a tunnel,
  an MPLS core, a link that cannot carry full-size frames) instead of
  stalling on a black-holed large UPDATE.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Config files:
  - z1-1.yaml: AS 65001, neighbor 192.168.0.2 with `tcp-mss 500`.
  - z2-1.yaml: AS 65002, neighbor 192.168.0.1 with `tcp-mss 500`.

  `tcp-mss` is applied before the TCP handshake on both the active connect
  socket and the listening socket, so the kernel negotiates the reduced
  MSS. `getsockopt(TCP_MAXSEG)` reads back the negotiated value (the
  "synced" MSS) a little below the configured one — the kernel subtracts
  the 12-byte TCP timestamp option, so a configured 500 syncs to 488.
  Both ends must advertise the clamp for both to read it back, which is
  why both neighbors set `tcp-mss 500`.

  Scenario: Session establishes and reports configured and synced tcp-mss
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    # The clamp does not break the session: MSS 500 is well above the
    # kernel minimum, so the eBGP session comes up normally.
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    # show bgp neighbor reports both the configured tcp-mss and the MSS
    # the kernel actually negotiated on the live socket.
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "Configured tcp-mss is 500"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "synced tcp-mss is 488"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "Configured tcp-mss is 500"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "synced tcp-mss is 488"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
