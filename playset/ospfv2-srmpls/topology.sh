# OSPFv2 SR-MPLS demo topology.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(e1 e2 s n1 n2 n3 r1 r2 r3 d)

PLAYSET_LINKS=(
    e1:e1-s:s:s-e1
    d:d-e2:e2:e2-d
    s:s-n1:n1:n1-s
    s:s-n2:n2:n2-s
    s:s-n3:n3:n3-s
    n1:n1-r1:r1:r1-n1
    n2:n2-r1:r1:r1-n2
    n3:n3-r1:r1:r1-n3
    n1:n1-r2:r2:r2-n1
    r1:r1-r2:r2:r2-r1
    r2:r2-r3:r3:r3-r2
    n1:n1-d:d:d-n1
    r3:r3-d:d:d-r3
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(e1 e2 s n1 n2 n3 r1 r2 r3 d)

# Routers with vtyctl YAML config (end hosts e1/e2 have no config).
PLAYSET_ROUTERS=(e1 e2 s n1 n2 n3 r1 r2 r3 d)
