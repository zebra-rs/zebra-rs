# IPv6 NLRI over a v4-addressed BGP session carries a usable next-hop

## Overview

As a network operator
I want IPv6 routes advertised across an IPv4-addressed BGP session to
carry a real IPv6 next-hop (RFC 2545 §2), so the receiver can resolve,
install and forward them — not just display them.
Regression guard: next-hop-self only fired when the session's local
end was itself IPv6, so v6 NLRI over v4 transport went out with `::`
as the MP_REACH next-hop. The receiver kept those routes best-path
selected but could never install them. The fix sources the next-hop
from the session interface's global IPv6 (the v4 local end's owning
interface), and skips the advertisement entirely when no usable v6
next-hop exists rather than emitting `::`.
Topology: one dual-stack point-to-point link, eBGP over the IPv4
addresses with both ipv4 and ipv6 afi-safi negotiated, both sides
redistributing connected (loopbacks 10.0.0.X/32 + 2001:db8::X/128,
link 192.168.0.0/30 + 2001:db8:12::/64).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| v6 routes arrive with the peer's interface global as next-hop | |
| The v6 routes resolve, install into the RIB and forward | |
| Teardown topology | |
