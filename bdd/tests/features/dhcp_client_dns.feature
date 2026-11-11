@serial
@dhcp_client_dns
Feature: A DHCP lease's name servers for the host

  A lease names name servers and search domains. `show dhcp client
  leases` shows them, and the host itself uses them: nothing but
  `address dhcp` is configured for that. They are handed to
  systemd-resolved as the link's DNS configuration, by running
  `resolvectl` (the resolver task, docs/design/dhcp-client.md §13), and
  taken back when the lease ends. `dhcp-options no-name-server` keeps
  an interface's name servers from the host: they are then only shown.

  No resolver is running here, and none must be reached: every daemon
  of the suite runs in a network namespace, from which `resolvectl`
  would configure some other interface of the host. The harness names
  a stand-in to each daemon (ZEBRA_RESOLVECTL,
  tests/scripts/resolvectl_stub.sh). It keeps what it is told, per
  namespace, and `status` prints it: `wan0 dns …`, `wan0 domain …`. Like
  resolved it holds an interface's settings, not a name's: one deleted
  and made again under the same name holds nothing. It can also be told
  to fail (`break`), at once or after some seconds, to do what it is
  asked and give no answer (`stall`), or to fail after dropping the list
  it was to replace, as resolved does (`spoil`).

  Topology: s1 is the ISP side, a dnsmasq with one address to lease. Its
  lease names 198.51.100.53 as name server, example.com as domain name
  and corp.example, lab.example as search list, until it is started
  again with another name server and no search list.

      s1 (dnsmasq) srv0 192.0.2.1/24 ──── wan0 (address dhcp) r1 (zebra-rs)

  Requires dnsmasq and nft on the host (tests/scripts/dhcp_server.sh).

  Config files:
  - r1.yaml: `address dhcp` on wan0, and nothing else.
  - r1-no-name-server.yaml: the same with `dhcp-options no-name-server`.

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

  Scenario: The lease hands its name servers and domains to the host
    Given the test topology exists
    # Nothing was configured but `address dhcp`.
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

  Scenario: An error after the old name servers are gone does not leave them taken for held
    Given the test topology exists
    # The server names another name server, and the command that is to
    # set it fails the way resolved does when it cannot add to a new
    # list: the list it was replacing is dropped, and then comes the
    # error. So the interface holds no name server, while the last
    # command that worked set 198.51.100.54.
    #
    # The server goes back to naming 198.51.100.54 before any try has
    # worked. That is what was set last, and it is not what is held: it
    # must be set again once commands work.
    When I execute "tests/scripts/resolvectl_stub.sh spoil" in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dns stop" in namespace "s1"
    And I execute "env DHCP_BDD_DNS=198.51.100.55 tests/scripts/dhcp_server.sh dhcp_client_dns start srv0 192.0.2.1/24 192.0.2.100 192.0.2.100 120" in namespace "s1"
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "DNS servers:  198.51.100.55"
    And daemon log in namespace "r1" should eventually contain "Failed to dns: no room for it"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0 dns"
    When I execute "tests/scripts/dhcp_server.sh dhcp_client_dns stop" in namespace "s1"
    And I execute "env DHCP_BDD_DNS=198.51.100.54 tests/scripts/dhcp_server.sh dhcp_client_dns start srv0 192.0.2.1/24 192.0.2.100 192.0.2.100 120" in namespace "s1"
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "DNS servers:  198.51.100.54"
    When I execute "tests/scripts/resolvectl_stub.sh mend" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"

  Scenario: Name servers set by a command that got no answer are still taken back
    Given the test topology exists
    # The stand-in does what it is asked and then says nothing, as a
    # command does whose answer is lost: zebra-rs gives up on it after 10
    # seconds without knowing whether the servers went in. They did.
    # `no-name-server` is set before any later try has an answer, and
    # they must not be left behind for that.
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    When I execute "tests/scripts/resolvectl_stub.sh stall" in namespace "r1"
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And daemon log in namespace "r1" should eventually contain "no answer in 10 s"
    When I apply command "set interface wan0 ipv4 dhcp-options no-name-server" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    When I execute "tests/scripts/resolvectl_stub.sh mend" in namespace "r1"
    And I apply command "delete interface wan0 ipv4 dhcp-options no-name-server" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"

  Scenario: An interface made again is given its name servers again
    Given the test topology exists
    # wan0 is deleted and made again: another interface under the same
    # name, which holds none of the settings the first was given. The
    # lease it gets is the same as before, so nothing a lease says has
    # changed.
    #
    # The withdrawal for the old interface fails, and only after 8
    # seconds, when the new interface is there, so that something is
    # still noted for the name when the lease comes back. Whatever it
    # is, this interface holds nothing and must be given the servers.
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

  Scenario: no-name-server takes them back and leaves the lease
    Given the test topology exists
    When I apply command "set interface wan0 ipv4 dhcp-options no-name-server" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"
    And show command "show dhcp client leases" in namespace "r1" should contain "DNS servers:  198.51.100.54"
    And show command "show ip route" in namespace "r1" should contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"

  Scenario: A lease taken under no-name-server is only shown
    Given the test topology exists
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released"
    And show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcp client leases" in namespace "r1" should contain "DNS servers:  198.51.100.54"
    # Time enough for a daemon that set them all the same to have done so.
    When I wait 3 seconds
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "wan0"

  Scenario: Deleting no-name-server hands the held lease's name servers over
    Given the test topology exists
    When I apply command "delete interface wan0 ipv4 dhcp-options no-name-server" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"

  Scenario: A restart hands the resumed lease's name servers over again
    Given the test topology exists
    # The stand-in forgets, so that what it holds afterwards is what the
    # restarted daemon told it and not what the old one did.
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.54"
    And daemon log in namespace "r1" should eventually contain "wan0: resumed 192.0.2.100/24"

  Scenario: A restart under no-name-server resumes the lease and sets nothing
    Given the test topology exists
    # `address dhcp` and `no-name-server` arrive in one commit, the lease
    # is resumed from disk at once, and its name servers must not reach
    # the host even for a moment.
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1-no-name-server.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcp client leases" in namespace "r1" should contain "DNS servers:  198.51.100.54"
    And daemon log in namespace "r1" should eventually contain "wan0: resumed 192.0.2.100/24"
    When I wait 3 seconds
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "wan0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dns stop" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean