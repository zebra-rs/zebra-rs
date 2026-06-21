@mirror_sid_mpls
@isis
Feature: IS-IS SR-MPLS Mirror SID egress link protection — steady-state baseline
  A dual-homed CE (ce2) hangs off both the primary egress pea and the
  protector peb. pea carries the BGP L3VPN service for ce2 over SR-MPLS
  (IS-IS Prefix-SID transport + per-VRF VPN label), and peb advertises a
  Mirror Context binding (SID/Label Binding TLV 149, M-flag, RFC 8679) for
  pea's loopback with via-vrf vrf-cust, installing a context-label ILM
  that decaps into the VRF. On a pea PE-CE link failure pea can redirect
  its VPN traffic to peb's context label. This feature validates the
  steady state the failover builds on: VPNv4 forwards via pea over the
  SR-MPLS transport, the context binding is advertised and its ILM
  installs on peb, and pea's per-VRF VPN-label ILM is in place. The live
  link-failure redirect is exercised separately.

  Topology (loopback 1.1.1.X/32, Prefix-SID index X -> label 1600X):
  ```
    ce1 ── pe1 ──── pea ──── ce2      pea: protected egress (1.1.1.3)
   (.2)   (.1)   (.3) │      │ \      peb: protector (1.1.1.4),
                      │      │  \          context label for 1.1.1.3/32
                      peb ───┘   ce2 dual-homed (lo 10.20.20.20/32)
                     (.4)
  ```
  ce2 returns to ce1 via peb in both states (peb imports ce1), so the
  forward path is the only thing that changes on failover. peb does not
  originate ce2 into BGP — pe1 always forwards ce2-bound traffic via pea.

  Scenario: Build topology and confirm IS-IS SR-MPLS + BGP VPNv4
    Given a clean test environment
    When I create namespace "pe1"
    And I create namespace "pea"
    And I create namespace "peb"
    And I create namespace "ce1"
    And I create namespace "ce2"
    And I connect namespace "pe1" interface "pe1-pea" to namespace "pea" interface "pea-pe1"
    And I connect namespace "pea" interface "pea-peb" to namespace "peb" interface "peb-pea"
    And I connect namespace "pe1" interface "ce1" to namespace "ce1" interface "eth0"
    And I connect namespace "pea" interface "pea-ce2" to namespace "ce2" interface "eth-a"
    And I connect namespace "peb" interface "peb-ce2" to namespace "ce2" interface "eth-b"
    And I add address "10.1.1.2/30" to interface "eth0" in namespace "ce1"
    And I add route "0.0.0.0/0" via "10.1.1.1" in namespace "ce1"
    And I make namespace "ce2" interface "lo" up
    And I add address "10.20.20.20/32" to interface "lo" in namespace "ce2"
    And I add address "10.2.2.2/30" to interface "eth-a" in namespace "ce2"
    And I add address "10.3.3.2/30" to interface "eth-b" in namespace "ce2"
    And I add route "10.1.1.0/30" via "10.3.3.1" in namespace "ce2"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "pea"
    And I start zebra-rs in namespace "peb"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "pea.yaml" to namespace "pea"
    And I apply config "peb.yaml" to namespace "peb"
    And I wait 45 seconds
    Then BGP session in "pe1" to "1.1.1.3" should be "Established"
    And BGP session in "pe1" to "1.1.1.4" should be "Established"
    And BGP session in "pea" to "1.1.1.1" should be "Established"
    # SR-MPLS transport LSP to pea's loopback is installed on pe1.
    And mpls ilm in namespace "pe1" should contain label 16003

  Scenario: The VPN service forwards ce1 to ce2 via pea (primary egress)
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "pe1" should contain "10.20.20.20/32"
    And ping from "ce1" to "10.20.20.20" should eventually succeed

  Scenario: peb advertises the Mirror Context binding and installs its ILM
    Given the test topology exists
    Then show command "show isis egress-protection" in namespace "peb" should contain "1.1.1.3/32"
    And show command "show isis database detail" in namespace "pe1" should contain "Mirror Context"
    # peb's context-label ILM pops the context label and decaps into vrf-cust.
    And show command "show mpls ilm" in namespace "peb" should contain "Mirror Ctx"

  Scenario: pea installs its per-VRF VPN-label ILM
    Given the test topology exists
    Then show command "show mpls ilm" in namespace "pea" should contain "VPN Decap"

  Scenario: PE-CE link failure redirects via the Mirror Context label
    Given the test topology exists
    # Baseline: ce1 -> ce2 flows via pea (the primary egress).
    Then ping from "ce1" to "10.20.20.20" should eventually succeed
    # Fail pea's PE-CE link. pea stays up (IS-IS/BGP intact, still
    # advertising ce2), so pe1 keeps forwarding with pea's VPN label under
    # the SR transport — but pea can no longer deliver locally. As its own
    # PLR pea swaps its VPN-label ILM to push peb's context label toward
    # peb; peb pops the context label and decaps into vrf-cust, delivering
    # over peb-ce2. A successful ping proves the redirect carries live
    # traffic.
    When I make namespace "pea" interface "pea-ce2" down
    And I wait 8 seconds
    Then ping from "ce1" to "10.20.20.20" should eventually succeed
    # Recover the link: pea restores the normal VPN decap.
    When I make namespace "pea" interface "pea-ce2" up
    And I wait 8 seconds
    Then ping from "ce1" to "10.20.20.20" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "pea"
    And I stop zebra-rs in namespace "peb"
    And I delete namespace "pe1"
    And I delete namespace "pea"
    And I delete namespace "peb"
    And I delete namespace "ce1"
    And I delete namespace "ce2"
    Then the test environment should be clean
