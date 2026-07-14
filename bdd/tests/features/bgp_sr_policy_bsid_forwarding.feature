@bgp_sr_policy_bsid_forwarding
Feature: BGP SR Policy Binding-SID steering — end-to-end forwarding (RFC 9256 §8.5)
  A headend (crs1) receives a service route AND an SR Policy over SAFI 73
  from a controller (crs2), colours the route on ingress, and steers it
  onto the policy. With `steering-mode binding-sid` the installed route
  pushes only the policy's Binding SID (label 16100); with
  `steering-mode segment-list` it pushes the policy's whole SID list
  (label 16002). The two labels are distinct, so `show ip route` proves,
  at the FIB, both that steering fires on *received* SR-policy state and
  that the mode selects the Binding SID vs the inline segment list.

  This is the forwarding-plane companion to @bgp_sr_policy_bsid_steering
  (which covers the config/show surface). It exercises the real receive →
  consume → colour → steer path, not just config.

  Topology (single link, iBGP AS 65000):
  ```
   crs1 [ headend, steering-mode binding-sid ] i1 ── i1 [ crs2 controller ]
        192.168.12.1/24                            192.168.12.2/24
        consumes SR Policy <color 100, endpoint 192.168.12.2>:
          binding-sid-label 16100, segment {16002}, route-target 10.0.0.1
        colours received 10.99.0.0/24 with colour 100 and steers it
  ```

  Scenario: crs1 consumes the received SR Policy and installs the service route
    Given a clean test environment
    When I create namespace "crs1"
    And I create namespace "crs2"
    And I connect namespace "crs1" interface "i1" to namespace "crs2" interface "i1"
    And I start zebra-rs in namespace "crs1"
    And I start zebra-rs in namespace "crs2"
    And I apply config "crs1.yaml" to namespace "crs1"
    And I apply config "crs2.yaml" to namespace "crs2"
    And I wait 15 seconds
    # The SR Policy advertised by crs2 was consumed into crs1's headend DB.
    Then show command "show bgp sr-policy" in namespace "crs1" should eventually contain "endpoint 192.168.12.2"
    And show command "show bgp sr-policy" in namespace "crs1" should contain "Steering mode: binding-sid"
    # The service route is installed via crs2 — not yet coloured, so not steered.
    And show command "show ip route 10.99.0.0/24" in namespace "crs1" should eventually contain "192.168.12.2"

  Scenario: Colouring the route inbound steers it onto the Binding SID
    Given the test topology exists
    # Attaching the inbound route-map re-evaluates received routes, so
    # 10.99.0.0/24 is now coloured 100 with the policy already consumed.
    When I apply command "set router bgp neighbor 192.168.12.2 afi-safi ipv4 policy in COLOR100" in namespace "crs1"
    # binding-sid mode: the route pushes the policy's Binding SID (16100),
    # NOT the inline segment list (16002).
    Then show command "show ip route 10.99.0.0/24" in namespace "crs1" should eventually contain "label 16100"

  Scenario: Switching to segment-list mode pushes the inline SID list instead
    Given the test topology exists
    When I apply command "set router bgp sr-policy steering-mode segment-list" in namespace "crs1"
    # Re-trigger the inbound re-evaluation (detach + re-attach the colour
    # route-map) so the route re-installs under the new mode.
    And I apply command "delete router bgp neighbor 192.168.12.2 afi-safi ipv4 policy in COLOR100" in namespace "crs1"
    And I apply command "set router bgp neighbor 192.168.12.2 afi-safi ipv4 policy in COLOR100" in namespace "crs1"
    # segment-list mode: the route now pushes the policy's SID list (16002),
    # not the Binding SID.
    Then show command "show ip route 10.99.0.0/24" in namespace "crs1" should eventually contain "label 16002"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "crs1"
    And I stop zebra-rs in namespace "crs2"
    And I delete namespace "crs1"
    And I delete namespace "crs2"
    Then the test environment should be clean
