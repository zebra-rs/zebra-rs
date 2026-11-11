@serial
@dhcp_client_dns
Feature: A DHCP lease's name servers for the host (system name-server dhcp)

  A lease names name servers and search domains. `show dhcp client
  leases` shows them; the host itself uses them only where
  `system name-server dhcp <if>` says so (the resolver task,
  docs/design/dhcp-client.md §13). They are then handed to
  systemd-resolved as that link's DNS configuration, by running
  `resolvectl`, and taken back when the lease ends or the entry is
  deleted.

  No resolver is running here, and none must be reached: every daemon
  of the suite runs in a network namespace, from which `resolvectl`
  would configure some other interface of the host. The harness names
  a stand-in to each daemon (ZEBRA_RESOLVECTL,
  tests/scripts/resolvectl_stub.sh). It keeps what it is told, per
  namespace, and `status` prints it: `wan0 dns …`, `wan0 domain …`. Like
  resolved it holds an interface's settings, not a name's: one deleted
  and made again under the same name holds nothing. It can also be told
  to fail (`break`), at once or after some seconds, or to do what it is
  asked and give no answer (`stall`).

  Topology: s1 is the ISP side, a dnsmasq with one address to lease. Its
  lease names 198.51.100.53 as name server, example.com as domain name
  and corp.example, lab.example as search list, until it is started
  again with another name server and no search list.

      s1 (dnsmasq) srv0 192.0.2.1/24 ──── wan0 (address dhcp) r1 (zebra-rs)

  Requires dnsmasq and nft on the host (tests/scripts/dhcp_server.sh).

  Config files:
  - r1.yaml: `address dhcp` on wan0.
  - r1-dns.yaml: the same with `system name-server dhcp wan0`.

  Scenario: Setup the server and a router with a DHCP WAN
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dns start srv0 192.0.2.1/24 192.0.2.100 192.0.2.100 120 --dhcp-option=option:domain-search,corp.example,lab.example" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcp client leases" in namespace "r1" should contain "DNS servers:  198.51.100.53"
    And show command "show dhcp client leases" in namespace "r1" should contain "Search:       corp.example, lab.example"

  Scenario: Without the entry the lease's name servers are only shown
    Given the test topology exists
    # Time enough for a daemon that set them unasked to have done so. The
    # next scenario has this same daemon reach the stand-in.
    When I wait 3 seconds
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "wan0"

  Scenario: The entry hands the lease's name servers and domains to the host
    Given the test topology exists
    When I apply command "set system name-server dhcp wan0" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.53"
    # The domain name first, then the search list.
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com corp.example lab.example"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers 198.51.100.53, search example.com corp.example lab.example"

  Scenario: Releasing the lease takes them back, and a new lease gives them again
    Given the test topology exists
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released the DHCP lease on wan0"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers withdrawn"
    And show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com corp.example lab.example"

  Scenario: Other name servers at a renewal replace the first
    Given the test topology exists
    # The server comes back naming another name server and no search
    # list: the renewal's answer replaces both, and the search list that
    # is gone is cleared, not left.
    When I execute "tests/scripts/dhcp_server.sh dhcp_client_dns stop" in namespace "s1"
    And I execute "env DHCP_BDD_DNS=198.51.100.54 tests/scripts/dhcp_server.sh dhcp_client_dns start srv0 192.0.2.1/24 192.0.2.100 192.0.2.100 120" in namespace "s1"
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "DNS servers:  198.51.100.54"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "corp.example"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"

  Scenario: A resolver that is away gets them once it is back
    Given the test topology exists
    # resolved not running yet, or not installed: the command fails, the
    # lease is none the worse, and the command is tried again.
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    When I execute "tests/scripts/resolvectl_stub.sh break" in namespace "r1"
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers not set:"
    And daemon log in namespace "r1" should eventually contain "Failed to dns: the resolver is away"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "wan0"
    When I execute "tests/scripts/resolvectl_stub.sh mend" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"

  Scenario: Name servers set by a command that got no answer are still taken back
    Given the test topology exists
    # The stand-in does what it is asked and then says nothing, as a
    # command does whose answer is lost: zebra-rs gives up on it after 10
    # seconds without knowing whether the servers went in. They did. The
    # entry is deleted before any later try has an answer, and they must
    # not be left behind for that.
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    When I execute "tests/scripts/resolvectl_stub.sh stall" in namespace "r1"
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And daemon log in namespace "r1" should eventually contain "no answer in 10 s"
    When I apply command "delete system name-server dhcp wan0" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    When I execute "tests/scripts/resolvectl_stub.sh mend" in namespace "r1"
    And I apply command "set system name-server dhcp wan0" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"

  Scenario: An interface made again is given its name servers again
    Given the test topology exists
    # wan0 is deleted and made again: another interface under the same
    # name, which holds none of the settings the first was given. The
    # lease it gets is the same as before, so nothing a lease says has
    # changed.
    #
    # The withdrawal for the old interface is refused, and only after 8
    # seconds, when the new interface is there. That leaves the old
    # one's entry in place, saying these very servers are held. They
    # are not, by this interface, and it must be given them.
    When I execute "tests/scripts/resolvectl_stub.sh break 8" in namespace "r1"
    And I execute "ip link del wan0" in namespace "r1"
    # Made under its own name. The harness's step makes a link under a
    # temporary name and renames it, and the running daemon would know
    # the interface by the first.
    And I execute "ip link add wan0 type veth peer name srv0 netns dhcp_client_dns_s1" in namespace "r1"
    And I execute "ip link set wan0 up" in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dns stop" in namespace "s1"
    And I execute "env DHCP_BDD_DNS=198.51.100.54 tests/scripts/dhcp_server.sh dhcp_client_dns start srv0 192.0.2.1/24 192.0.2.100 192.0.2.100 120" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh mend" in namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcp client leases" in namespace "r1" should contain "DNS servers:  198.51.100.54"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"

  Scenario: Deleting the entry takes them back and leaves the lease
    Given the test topology exists
    When I apply command "delete system name-server dhcp wan0" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"
    And show command "show dhcp client leases" in namespace "r1" should contain "DNS servers:  198.51.100.54"
    And show command "show ip route" in namespace "r1" should contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"

  Scenario: A restart hands the resumed lease's name servers over again
    Given the test topology exists
    When I apply command "set system name-server dhcp wan0" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    # The stand-in forgets, so that what it holds afterwards is what the
    # restarted daemon told it and not what the old one did.
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1-dns.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And daemon log in namespace "r1" should eventually contain "wan0: resumed 192.0.2.100/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dns stop" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
