#! /bin/bash

for file in ../zebra-rs/Cargo.toml
do
    sed -i "s/^version = .*/version = \"$(cat ../version)\"/" ${file}
done

for file in ./nfpm-amd64.yaml ./nfpm-arm64.yaml
do
    sed -i "s/^version: .*/version: \"$(cat ../version)\"/" ${file}
done
