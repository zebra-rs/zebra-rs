@isis_hello_padding_mtu
@isis
Feature: IS-IS Hello padding fills the interface MTU exactly, with padding-size and padding disable as the mismatch escape hatches
  As a network operator
  I want IS-IS Hellos padded to exactly the interface MTU (and no further),
  so an adjacency only forms when the link really carries full-MTU PDUs in
  both directions — and when the peer's MTU accounting disagrees with mine,
  I want `hello padding-size <bytes>` to pad to the exact frame length the
  peer accepts (the number read straight out of a capture), or
  `hello padding disable` to skip the probe entirely.

  Wire arithmetic this feature pins down (the recurring interop question):
  the padder fills the IIH PDU to MTU - 3, the send path prepends the
  3-byte LLC header (FE FE 03), so the Ethernet payload is EXACTLY the
  interface MTU, and a capture shows MTU + 14 (Ethernet header; +4 more
  with FCS on a physical wire). MTU 1600 here means 1614-byte frames in
  tcpdump — precisely as MTU 4096 means 4110-byte frames. That is correct
  under Linux/IETF MTU semantics (MTU = max L2 payload); a peer whose
  configured "MTU" counts the Ethernet header and FCS inside the number
  (media-MTU semantics, 18 bytes of overhead) will both send smaller
  padded Hellos and DROP ours as giants, exactly like a receiver whose
  kernel MTU is simply lower — which is how the mismatch scenario below
  models it.

  Test Topology:
  ```
   a1 ───────────── a2
   i2  10.0.12.0/30  i1
   lo 10.0.0.1/32   lo 10.0.0.2/32
  ```

  Both routers are level-2-only on a broadcast (LAN) circuit with 1 s
  Hellos and hold-time 5 s, so MTU-change fallout lands within seconds.

  Scenario: Matched MTUs — Hellos are padded to exactly MTU + 14 on the wire and the adjacency forms
    Given a clean test environment
    When I create namespace "a1"
    And I create namespace "a2"
    And I connect namespace "a1" interface "i2" to namespace "a2" interface "i1"
    And I set mtu 1600 on interface "i2" in namespace "a1"
    And I set mtu 1600 on interface "i1" in namespace "a2"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    Then isis neighbor in namespace "a1" at level 2 on interface "i2" should be up
    And isis neighbor in namespace "a2" at level 2 on interface "i1" should be up
    # The padded IIH occupies the full 1600-byte payload; tcpdump adds the
    # 14-byte Ethernet header. Anything larger would be an overshoot bug
    # (frames the peer must drop); anything below 1612 would be under-padding.
    And IS-IS hellos sent on interface "i2" in namespace "a1" should be 1614 bytes on the wire
    And IS-IS hellos sent on interface "i1" in namespace "a2" should be 1614 bytes on the wire
    And ping from "a2" to "10.0.0.1" should succeed

  Scenario: Receiver with a smaller MTU silently drops the padded Hellos — adjacency refuses to form while ordinary traffic still flows
    Given the test topology exists
    # a2 now models the mismatched peer: its kernel drops ingress frames
    # over ~1518 bytes, while a1 keeps probing at its own MTU. This is the
    # vendor-interop trap in miniature — link fine, pings fine, IS-IS down.
    When I set mtu 1500 on interface "i1" in namespace "a2"
    And I wait 10 seconds
    Then IS-IS hellos sent on interface "i2" in namespace "a1" should be 1614 bytes on the wire
    And isis neighbor in namespace "a2" at level 2 on interface "i1" should not be up
    And isis neighbor in namespace "a1" at level 2 on interface "i2" should not be up
    # Small frames still traverse the link: only the full-MTU Hellos die.
    And ping from "a2" to "10.0.12.1" should succeed
    And ping from "a2" to "10.0.0.1" should fail

  Scenario: hello padding-size pads to an explicit wire length the smaller-MTU peer accepts
    Given the test topology exists
    # The surgical fix when the peer's MTU number cannot be changed: tell
    # a1 to pad its Hellos to a 1514-byte frame — the size read from the
    # peer-side capture — instead of its own 1600 MTU. The MTU probe
    # still runs, just at the length both sides agree on. This is the
    # miniature of `padding-size 4092` against a media-MTU-4096 vendor.
    When I apply command "set router isis interface i2 hello padding-size 1514" in namespace "a1"
    Then isis neighbor in namespace "a2" at level 2 on interface "i1" should be up
    And isis neighbor in namespace "a1" at level 2 on interface "i2" should be up
    And IS-IS hellos sent on interface "i2" in namespace "a1" should be 1514 bytes on the wire
    And ping from "a2" to "10.0.0.1" should eventually succeed
    # Deleting the override restores the default full-MTU probe (1600+14),
    # which this link (still 1500 on the a2 side) again cannot carry.
    When I apply command "delete router isis interface i2 hello padding-size" in namespace "a1"
    Then IS-IS hellos sent on interface "i2" in namespace "a1" should be 1614 bytes on the wire

  Scenario: hello padding disable on the big-MTU side brings the adjacency back up
    Given the test topology exists
    When I apply command "set router isis interface i2 hello padding disable" in namespace "a1"
    Then isis neighbor in namespace "a2" at level 2 on interface "i1" should be up
    And isis neighbor in namespace "a1" at level 2 on interface "i2" should be up
    And IS-IS hellos sent on interface "i2" in namespace "a1" should be smaller than 200 bytes on the wire
    And ping from "a2" to "10.0.0.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a1"
    And I stop zebra-rs in namespace "a2"
    And I delete namespace "a1"
    And I delete namespace "a2"
    Then the test environment should be clean
