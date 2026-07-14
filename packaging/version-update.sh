#! /bin/bash

for file in ../Cargo.toml
do
    sed -i "s/^version = .*/version = \"$(cat ../version)\"/" ${file}
done

for file in ./nfpm-amd64.yaml ./nfpm-arm64.yaml
do
    sed -i "s/^version: .*/version: \"$(cat ../version)\"/" ${file}
done

# Keep the `Recommends: cradle-rs (>= X)` floor in step with the pinned cradle
# release (the top-level `cradle-version` file). The release/publish-apt
# pipeline ingests exactly this cradle release into the APT repo, so
# `apt install zebra-rs` pulls a cradle engine that satisfies this floor.
for file in ./nfpm-amd64.yaml ./nfpm-arm64.yaml
do
    sed -i "s/^  - cradle-rs.*/  - cradle-rs (>= $(cat ../cradle-version))/" ${file}
done
