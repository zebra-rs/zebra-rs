# zebra-rs Routing Software

[zebra-rs Routing Software](ch-00-00-introduction.md)
- [Separation of Reachability Information and Forwarding Decision](ch-00-01-reachability-information.md)
- [Router ID Selection](ch-00-02-router-id.md)

## Static Route

- [Static Route](ch-01-00-what-is-static-route.md)
  - [Floating Static Route](ch-01-01-floating-static-route.md)
  - [Recursive Static Route](ch-01-02-recursive-static-route.md)

## Routing Protocols

- [BGP](ch-02-00-what-is-bgp.md)
  - [Dynamic Neighbors](ch-02-01-dynamic-neighbors.md)
  - [Session Authentication (TCP MD5 / TCP-AO)](ch-02-02-tcp-authentication.md)
  - [Timer Configuration](ch-02-03-bgp-timers.md)
  - [L3VPN and Per-VRF Labels](ch-02-04-bgp-l3vpn.md)
  - [L3VPN over an SRv6 Underlay](ch-02-05-bgp-l3vpn-srv6.md)
  - [EVPN Type-5 (IP Prefix Routes)](ch-02-06-bgp-evpn-type5.md)
  - [Route Target Constraint (RTC)](ch-02-07-bgp-rtc.md)
  - [BFD](ch-02-08-bgp-bfd.md)
- [IS-IS](ch-07-00-isis.md)
  - [Timer Configuration](ch-07-01-isis-timers.md)
  - [Shared Risk Link Group (SRLG)](ch-07-02-isis-srlg.md)
  - [BFD](ch-07-03-isis-bfd.md)
  - [Clearing IS-IS State](ch-07-04-isis-clear.md)
- [OSPFv2](ch-08-00-ospf.md)
  - [Configuration](ch-08-01-ospf-configuration.md)
  - [BFD](ch-08-02-ospf-bfd.md)
  - [Clearing OSPF State](ch-08-03-ospf-clear.md)

## Failure Detection

- [Bidirectional Forwarding Detection (BFD)](ch-10-00-bfd.md)

## Performance Measurement

- [Link Delay Measurement (TWAMP Light / STAMP)](ch-09-00-twamp-stamp.md)

## SRv6

- [SRv6](ch-04-00-srv6.md)

## Policy

- [Policy](ch-05-00-policy.md)
  - [Control Flow](ch-05-01-policy-control-flow.md)
  - [Match](ch-05-02-policy-match.md)
  - [Set](ch-05-03-policy-set.md)

## Management Interface

- [VTY Access and Authentication](ch-06-00-vty-access.md)
  - [Session Management Design](ch-06-01-session-design.md)
  - [Show Config Commands](ch-06-02-show-config-commands.md)

## Logging and Monitoring

- [Logging Configuration](ch-03-00-logging-overview.md)
  - [Log Output Destinations](ch-03-01-log-output-destinations.md)
  - [Log Formats](ch-03-02-log-formats.md)
  - [Protocol-Specific Logging](ch-03-03-protocol-logging.md)
  - [Logging Integration](ch-03-04-logging-integration.md)
  - [Logging Troubleshooting](ch-03-05-logging-troubleshooting.md)

## Testing

- [BDD Integration Tests](ch-11-00-bdd-tests.md)

---

# Appendices

- [Appendix A: Logging Quick Reference](appendix-a-logging-quick-reference.md)
