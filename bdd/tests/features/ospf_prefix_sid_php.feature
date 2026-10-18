@ospf_prefix_sid_php
@ospf
Feature: The hop before a Prefix-SID's owner pops its label only without NP
  As a network operator
  I want the router next to a Prefix-SID's owner to pop the label
  (penultimate-hop popping) only when the owner's Prefix-SID leaves the
  NP flag clear, and to keep the label when NP is set (RFC 8665 §5,
  RFC 8666 §5) — for traffic it originates (FTN) and traffic it
  forwards (ILM), in OSPFv2 and OSPFv3 alike.

  zebra-rs sets NP on an index-form Prefix-SID and leaves it clear on an
  absolute-label one. OSPFv2 used to pop next to every owner, NP or not;
  OSPFv3 used to keep every label, NP or not.

  Test Topology:
  ```
    r1 ---------------- r2 ---------------- r3
    absolute-label SID                      index SID
    v2 17001, v3 17021                      v2 index 3 = 16003
    (NP clear)                              v3 index 23 = 16023 (NP set)
  ```

  r2 is the penultimate hop toward both: it pops r1's labels and keeps
  r3's.

  Scenario: Build the topology
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I connect namespace "r2" interface "r2-r3" to namespace "r3" interface "r3-r2"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    Then show command "show ospf neighbor" in namespace "r2" should eventually contain "10.0.0.3"
    And show command "show ospfv3 neighbor" in namespace "r2" should eventually contain "10.0.0.3"

  Scenario: OSPFv2 keeps r3's label and pops r1's
    Given the test topology exists
    Then show command "show mpls ilm" in namespace "r2" should eventually contain "16003"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "17001"
    And mpls ilm outgoing label for label 16003 in namespace "r2" should be "16003"
    And mpls ilm outgoing label for label 17001 in namespace "r2" should be "Pop"
    # r2's own traffic: the label is pushed toward r3, implicit null
    # (rendered in parentheses) toward r1.
    And show command "show ip route 10.0.0.3/32" in namespace "r2" should eventually contain "r2-r3, label 16003"
    And show command "show ip route 10.0.0.1/32" in namespace "r2" should eventually contain "r2-r1, label (17001)"
    # End to end over both labels.
    And ping from "r1" to "10.0.0.3" should eventually succeed
    And ping from "r3" to "10.0.0.1" should eventually succeed

  Scenario: OSPFv3 keeps r3's label and pops r1's
    Given the test topology exists
    Then show command "show mpls ilm" in namespace "r2" should eventually contain "16023"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "17021"
    And mpls ilm outgoing label for label 16023 in namespace "r2" should be "16023"
    And mpls ilm outgoing label for label 17021 in namespace "r2" should be "Pop"
    And show command "show ipv6 route 2001:db8::3/128" in namespace "r2" should eventually contain "r2-r3, label 16023"
    And show command "show ipv6 route 2001:db8::1/128" in namespace "r2" should eventually contain "r2-r1, label (17021)"
    And ping from "r1" to "2001:db8::3" should eventually succeed
    And ping from "r3" to "2001:db8::1" should eventually succeed

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    Then the test environment should be clean
