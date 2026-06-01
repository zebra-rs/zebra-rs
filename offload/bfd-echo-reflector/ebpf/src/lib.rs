#![no_std]

// This file exists only to provide a library target. Cargo builds it for the
// host as a (cache-tracking) build-dependency of the loader, while aya-build
// compiles the binary target (`src/main.rs`) for `bpfel-unknown-none`.
