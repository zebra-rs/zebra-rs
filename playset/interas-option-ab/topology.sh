# Inter-AS Option AB (Cisco hybrid: per-VPN VRFs + one VPNv4 session)
# demo topology. Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".
#
#   ce1 ─┐                                                ┌─ ce3   (cust1)
#        pe1 ── p1 ── asbr1 ═══ one VPNv4 session ═══ asbr2 ── p2 ── pe2
#   ce2 ─┘        AS 65501   (per-VPN VRF lookup at    AS 65502     └─ ce4   (cust2)
#                             each ASBR, like Option A)

PLAYSET_NAMESPACES=(ce1 ce2 pe1 p1 asbr1 asbr2 p2 pe2 ce3 ce4)

PLAYSET_LINKS=(
    ce1:ce1-pe1:pe1:pe1-ce1
    ce2:ce2-pe1:pe1:pe1-ce2
    pe1:pe1-p1:p1:p1-pe1
    p1:p1-asbr1:asbr1:asbr1-p1
    asbr1:asbr1-asbr2:asbr2:asbr2-asbr1
    asbr2:asbr2-p2:p2:p2-asbr2
    p2:p2-pe2:pe2:pe2-p2
    pe2:pe2-ce3:ce3:ce3-pe2
    pe2:pe2-ce4:ce4:ce4-pe2
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(ce1 ce2 pe1 p1 asbr1 asbr2 p2 pe2 ce3 ce4)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(ce1 ce2 pe1 p1 asbr1 asbr2 p2 pe2 ce3 ce4)
