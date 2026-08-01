# EVPN over SRv6 (E-LAN in eBPF) demo topology.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(h1 pe1 pe2 h2)

PLAYSET_LINKS=(
    h1:h1-pe1:pe1:pe1-h1
    pe1:pe1-pe2:pe2:pe2-pe1
    pe2:pe2-h2:h2:h2-pe2
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(h1 pe1 pe2 h2)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(h1 pe1 pe2 h2)
