# BGP EVPN VXLAN demo topology.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(vtep1 vtep2 h1 h2)

PLAYSET_LINKS=(
    vtep1:vtep1-vtep2:vtep2:vtep2-vtep1
    h1:h1-vtep1:vtep1:vtep1-h1
    h2:h2-vtep2:vtep2:vtep2-h2
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(vtep1 vtep2 h1 h2)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(vtep1 vtep2 h1 h2)
