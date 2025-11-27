#! /bin/bash

for file in ../Cargo.toml \
                ../crates/bgp-packet/Cargo.toml \
                ../crates/ospf-packet/Cargo.toml \
                ../crates/isis-packet/Cargo.toml
do
    sed -i "s/^version = .*/version = \"$(cat ../version)\"/" ${file}
done

for file in ./nfpm-amd64.yaml ./nfpm-arm64.yaml
do
    sed -i "s/^version: .*/version: \"$(cat ../version)\"/" ${file}
done
