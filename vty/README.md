# vty — GNU bash 5.3 with vty hooks

This directory builds `vty`, a router-CLI shell derived from GNU
bash 5.3 with patches that integrate it with the rest of
zebra-rs. Bash sources are fetched at build time; only the deltas
live here.

## Build

    make

The first build downloads `bash-5.3.tar.gz` (~11 MB) into
`~/.cache/zebra-rs/`, verifies its SHA-256, extracts it under
`build/` (via `tar --strip-components=1`, so no redundant
`build/bash-5.3/` layer), applies GNU's official bash-5.3 patches
from `patches/upstream/` in order (bringing it to 5.3.20), lays
additions on top, applies the vty patch, then runs
`./configure && make`. The resulting binary is `build/vty`, with
a copy at `vty` for packaging.

Override the cache location with `CACHE_DIR=/some/path`.

## Layout

    additions/                  vty-specific source files (real source)
    patches/upstream/bash53-NNN GNU's official bash-5.3 patches, verbatim
    patches/0001-vty-hooks.patch  modifications to bash-5.3 sources
    Makefile                    build glue

## Upstream patches

`patches/upstream/` holds GNU's bash-5.3 patch series exactly as
published at https://ftp.gnu.org/gnu/bash/bash-5.3-patches/. To
take a new one, download it with its `.sig`, check it against
Chet Ramey's key:

    curl -fLO https://ftp.gnu.org/gnu/gnu-keyring.gpg
    gpgv --keyring ./gnu-keyring.gpg bash53-NNN.sig bash53-NNN

then add the patch file (not the `.sig`) and bump
`BASH_PATCHLEVEL` in the Makefile. The build checks that
`patchlevel.h` ends up at that level.

## Tests

After `make`, bash's own regression suite is available:

    cd build/tests && ./run-all
