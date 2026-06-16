# zebra-rs Routing Software

[zebra-rs Routing Software](ch-00-00-introduction.md)
- [Separation of Reachability Information and Forwarding Decision](ch-00-01-reachability-information.md)
- [Router ID Selection](ch-00-02-router-id.md)
- [Interface Configuration](ch-00-03-interface-configuration.md)

## Static Route

- [Static Route](ch-01-00-what-is-static-route.md)
  - [Floating Static Route](ch-01-01-floating-static-route.md)
  - [Recursive Static Route](ch-01-02-recursive-static-route.md)

## Routing Protocols

- [BGP](ch-02-00-what-is-bgp.md)
  - [Neighbor Groups](ch-02-26-bgp-neighbor-group.md)
  - [Dynamic Neighbors](ch-02-01-dynamic-neighbors.md)
  - [IPv6 Unnumbered (interface-neighbor)](ch-02-27-bgp-unnumbered.md)
  - [Session Authentication (TCP MD5 / TCP-AO)](ch-02-02-tcp-authentication.md)
  - [TTL: eBGP Multihop & Security (GTSM)](ch-02-11-bgp-ttl-security.md)
  - [TCP MSS](ch-02-14-bgp-tcp-mss.md)
  - [TCP Port (listen & per-neighbor)](ch-02-23-bgp-port.md)
  - [AS Override](ch-02-12-bgp-as-override.md)
  - [Local AS (AS Migration)](ch-02-30-bgp-local-as.md)
  - [allowas-in (Inbound AS_PATH Loop Relaxation)](ch-02-13-bgp-allowas-in.md)
  - [Remove Private AS](ch-02-14-bgp-remove-private-as.md)
  - [Enforce First AS](ch-02-15-bgp-enforce-first-as.md)
  - [Well-Known Communities](ch-02-24-bgp-well-known-communities.md)
  - [Table-Map (Policy at the BGP→RIB Install Point)](ch-02-28-bgp-table-map.md)
  - [disable-connected-check](ch-02-16-bgp-disable-connected-check.md)
  - [ip-transparent (non-local update-source)](ch-02-29-bgp-ip-transparent.md)
  - [SRv6 Encapsulation Type (per-neighbor)](ch-02-17-bgp-srv6-encapsulation-type.md)
  - [Timer Configuration](ch-02-03-bgp-timers.md)
  - [L3VPN and Per-VRF Labels](ch-02-04-bgp-l3vpn.md)
  - [L3VPN over an SRv6 Underlay](ch-02-05-bgp-l3vpn-srv6.md)
  - [EVPN Type-5 (IP Prefix Routes)](ch-02-06-bgp-evpn-type5.md)
  - [Route Target Constraint (RTC)](ch-02-07-bgp-rtc.md)
  - [Inter-AS L3VPN](ch-02-18-bgp-interas.md)
    - [Option A (back-to-back VRFs)](ch-02-20-bgp-interas-option-a.md)
    - [Option B (VPNv4 between ASBRs)](ch-02-21-bgp-interas-option-b.md)
    - [Option C over SR-MPLS](ch-02-19-bgp-interas-option-c.md)
    - [Option AB (hybrid)](ch-02-22-bgp-interas-option-ab.md)
  - [BFD](ch-02-08-bgp-bfd.md)
  - [Route Reflector](ch-02-09-bgp-route-reflector.md)
  - [RIB Sharding (Parallel Route Processing)](ch-02-31-bgp-rib-sharding.md)
  - [Clearing BGP Sessions](ch-02-25-bgp-clear.md)
  - [Conditional Tracing](ch-02-10-bgp-tracing.md)
- [IS-IS](ch-07-00-isis.md)
  - [Timer Configuration](ch-07-01-isis-timers.md)
  - [Shared Risk Link Group (SRLG)](ch-07-02-isis-srlg.md)
  - [BFD](ch-07-03-isis-bfd.md)
  - [Clearing IS-IS State](ch-07-04-isis-clear.md)
  - [LSP MTU and Fragmentation](ch-07-05-isis-lsp-mtu.md)
  - [Route Redistribution](ch-07-06-isis-redistribution.md)
  - [Passive Interfaces](ch-07-07-isis-passive.md)
- [OSPFv2](ch-08-00-ospf.md)
  - [Configuration](ch-08-01-ospf-configuration.md)
  - [BFD](ch-08-02-ospf-bfd.md)
  - [Clearing OSPF State](ch-08-03-ospf-clear.md)

## Failure Detection

- [Bidirectional Forwarding Detection (BFD)](ch-10-00-bfd.md)
  - [The XDP/eBPF Data-Plane Helper](ch-10-01-bfd-xdp-helper.md)

## Fast Reroute

- [Fast Failover: TI-LFA + BFD (NexthopProtect)](ch-12-00-nexthop-protect.md)

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
  - [RIB/FIB Tracing](ch-03-06-rib-fib-tracing.md)
  - [Logging Integration](ch-03-04-logging-integration.md)
  - [Logging Troubleshooting](ch-03-05-logging-troubleshooting.md)

## Testing

- [BDD Integration Tests](ch-11-00-bdd-tests.md)

---

# Appendices

- [Appendix A: Logging Quick Reference](appendix-a-logging-quick-reference.md)
