@mirror_sid_srv6
@isis
Feature: IS-IS SRv6 Mirror SID egress protection — control plane + install
  As a network operator
  I want a protector PE to advertise a Mirror SID (SRv6 End.M) for a
  primary egress's locator, and a PLR to install an H.Encaps-to-the-
  Mirror-SID backup, so that on egress failure traffic can be redirected
  to the protector (draft-ietf-rtgwg-srv6-egress-protection).

  This feature validates the control + install path that needs no BGP
  L3VPN service: advertisement, reception, the protector's End.M localsid
  install, and the PLR backup install. The mirror-context table
  population (via-vrf) and live traffic failover need a VRF/VPN service
  and are covered separately.

  Test Topology (loopback 2001:db8::X, SRv6 locator fcbb:bbbb:X::/48):
  ```
    pe1 ──── p1 ──── pea
   (::1)   (::2,PLR)  (::3, protected, fcbb:bbbb:3::/48)
                \    /
                 peb           (::4, protector, fcbb:bbbb:4::/48)
                              Mirror SID fcbb:bbbb:4:1:: protects
                              fcbb:bbbb:3::/48
  ```
  All circuits are IS-IS Level-2, point-to-point, SRv6 uSID. p1 reaches
  both pea and peb directly, so the backup to peb is valid when pea fails.

  Scenario: Build the topology and confirm IS-IS + SRv6 convergence
    Given a clean test environment
    When I create namespace "pe1"
    And I create namespace "p1"
    And I create namespace "pea"
    And I create namespace "peb"
    And I connect namespace "pe1" interface "pe1-p1" to namespace "p1" interface "p1-pe1"
    And I connect namespace "p1" interface "p1-pea" to namespace "pea" interface "pea-p1"
    And I connect namespace "p1" interface "p1-peb" to namespace "peb" interface "peb-p1"
    And I connect namespace "pea" interface "pea-peb" to namespace "peb" interface "peb-pea"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "p1"
    And I start zebra-rs in namespace "pea"
    And I start zebra-rs in namespace "peb"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "p1.yaml" to namespace "p1"
    And I apply config "pea.yaml" to namespace "pea"
    And I apply config "peb.yaml" to namespace "peb"
    And I wait 25 seconds
    Then ping from "pe1" to "2001:db8::3" should succeed
    And ping from "pe1" to "2001:db8::4" should succeed
    And ping from "p1" to "2001:db8::4" should succeed

  Scenario: peb advertises the Mirror SID and p1 receives it
    Given the test topology exists
    # The protector shows the configured entry as advertised (SRv6
    # dataplane, in-locator Mirror SID).
    Then show command "show isis egress-protection" in namespace "peb" should contain "fcbb:bbbb:3::/48"
    And show command "show isis egress-protection" in namespace "peb" should contain "yes"
    # Every peer sees the Mirror SID sub-TLV in peb's LSP.
    And show command "show isis database detail" in namespace "p1" should contain "Mirror SID"
    And show command "show isis database detail" in namespace "p1" should contain "End.M"
    # The PLR lists the received advertisement.
    And show command "show isis egress-protection" in namespace "p1" should contain "Received Mirror SIDs"
    And show command "show isis egress-protection" in namespace "p1" should contain "fcbb:bbbb:4:1::"
    And show command "show isis egress-protection" in namespace "p1" should contain "fcbb:bbbb:3::/48"

  Scenario: peb installs the End.M localsid
    Given the test topology exists
    # The Mirror SID is registered as an End.M SID and installed in the
    # kernel as a seg6local decap into the mirror-context table.
    Then show command "show segment-routing srv6 sid" in namespace "peb" should contain "End.M"
    And show command "show segment-routing srv6 sid" in namespace "peb" should contain "fcbb:bbbb:4:1::"
    And kernel route "fcbb:bbbb:4:1::" in namespace "peb" should eventually contain "seg6local"

  Scenario: p1 installs the PLR Mirror SID backup
    Given the test topology exists
    # The PLR's route to the protected locator carries an H.Encaps
    # backup whose segment list is the Mirror SID.
    Then show command "show isis route detail" in namespace "p1" should contain "fcbb:bbbb:3::/48"
    And show command "show isis route detail" in namespace "p1" should contain "fcbb:bbbb:4:1::"

  Scenario: peb withdraws the Mirror SID and the PLR backup clears
    Given the test topology exists
    # Remove peb's Mirror SID. peb re-originates its LSP without it; because
    # peb's LSP is still present, this is a genuine withdrawal (not a
    # convergence-transient empty scan), so every receiver drops the
    # protection rather than sticky-keeping it. (The withdrawal-vs-PIC
    # distinction itself is unit-tested in `authoritative_protections`;
    # here we confirm the live end-to-end propagation.)
    When I apply command "delete router isis egress-protection protect fcbb:bbbb:3::/48 mirror-sid fcbb:bbbb:4:1::" in namespace "peb"
    And I wait 5 seconds
    # peb no longer advertises the Mirror SID...
    Then show command "show isis egress-protection" in namespace "peb" should not contain "fcbb:bbbb:4:1::"
    # ...so the PLR's route to the protected locator no longer carries the
    # Mirror SID backup, nor does its received view.
    And show command "show isis route detail" in namespace "p1" should not contain "fcbb:bbbb:4:1::"
    And show command "show isis egress-protection" in namespace "p1" should not contain "fcbb:bbbb:4:1::"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "p1"
    And I stop zebra-rs in namespace "pea"
    And I stop zebra-rs in namespace "peb"
    And I delete namespace "pe1"
    And I delete namespace "p1"
    And I delete namespace "pea"
    And I delete namespace "peb"
    Then the test environment should be clean
