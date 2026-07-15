#! /bin/bash

# Propagate the top-level `version` file into the workspace Cargo.toml. The
# zebra-rs crate inherits it (version.workspace = true), and cargo-deb reads it
# straight from Cargo.toml, so this is the single place the package version is
# set (the former nfpm-*.yaml version fields are gone).
for file in ../Cargo.toml
do
    sed -i "s/^version = .*/version = \"$(cat ../version)\"/" ${file}
done

# Keep the `Recommends: cradle-rs (>= X)` floor in step with the pinned cradle
# release (the top-level `cradle-version` file). The release/publish-apt
# pipeline ingests exactly this cradle release into the APT repo, so
# `apt install zebra-rs` pulls a cradle engine that satisfies this floor. The
# floor now lives in [package.metadata.deb] of ../zebra-rs/Cargo.toml.
sed -i "s|^recommends = \"cradle-rs.*|recommends = \"cradle-rs (>= $(cat ../cradle-version))\"|" \
    ../zebra-rs/Cargo.toml
