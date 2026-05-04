# vty — GNU bash 5.2 with vtysh hooks

This directory builds `vty`, a router-CLI shell derived from GNU
bash 5.2 with patches that integrate it with the rest of zebra-rs.
Bash sources are fetched at build time; only the deltas live here.

## Build

    make

The first build downloads `bash-5.2.tar.gz` (~11 MB) into
`~/.cache/zebra-rs/`, verifies its SHA-256, extracts it under
`build/vty/`, lays additions on top, applies the patch, then runs
`./configure && make`. The resulting binary is `build/vty/vty`.

Override the cache location with `CACHE_DIR=/some/path`.

## Layout

    additions/                  vtysh-specific source files (real source)
    patches/0001-vty-hooks.patch  modifications to bash-5.2 sources
    Makefile                    build glue

## Tests

After `make`, bash's own regression suite is available:

    cd build/vty/tests && ./run-all
