# Inter-AS Option C, RR-based (Cisco reference design) demo topology —
# the reference diagram (images/InterASOptionCRR.svg): three customers,
# two PEs in AS 65501, a route reflector per AS, BGP-LU at the border.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".
#
#            rr1 ══ multihop eBGP VPNv4 (next-hop-unchanged) ══ rr2
#             │                                                  │
#   ce1 ─┐    │                                                  │    ┌─ ce4  (cust1)
#   ce2 ─┴ pe1├                                                  │    ├─ ce5  (cust2)
#             p1 ── asbr1 ═══════ eBGP BGP-LU ═══════ asbr2 ── p2┴─ pe3
#   ce3 ── pe2┘          AS 65501                       AS 65502      └─ ce6  (cust3)

PLAYSET_NAMESPACES=(ce1 ce2 ce3 pe1 pe2 p1 rr1 asbr1 asbr2 rr2 p2 pe3 ce4 ce5 ce6)

PLAYSET_LINKS=(
    ce1:ce1-pe1:pe1:pe1-ce1
    ce2:ce2-pe1:pe1:pe1-ce2
    ce3:ce3-pe2:pe2:pe2-ce3
    pe1:pe1-p1:p1:p1-pe1
    pe2:pe2-p1:p1:p1-pe2
    p1:p1-rr1:rr1:rr1-p1
    p1:p1-asbr1:asbr1:asbr1-p1
    asbr1:asbr1-asbr2:asbr2:asbr2-asbr1
    asbr2:asbr2-p2:p2:p2-asbr2
    p2:p2-rr2:rr2:rr2-p2
    p2:p2-pe3:pe3:pe3-p2
    pe3:pe3-ce4:ce4:ce4-pe3
    pe3:pe3-ce5:ce5:ce5-pe3
    pe3:pe3-ce6:ce6:ce6-pe3
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(ce1 ce2 ce3 pe1 pe2 p1 rr1 asbr1 asbr2 rr2 p2 pe3 ce4 ce5 ce6)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(ce1 ce2 ce3 pe1 pe2 p1 rr1 asbr1 asbr2 rr2 p2 pe3 ce4 ce5 ce6)
