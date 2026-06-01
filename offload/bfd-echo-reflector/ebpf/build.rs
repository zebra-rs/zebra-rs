use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary.
/// This build script makes the failure mode obvious (a clear "not found" error
/// instead of a confusing link failure) and asks cargo to rebuild when the
/// resolved `bpf-linker` path changes.
fn main() {
    let bpf_linker = which("bpf-linker").expect(
        "bpf-linker not found on $PATH — install it with `cargo install bpf-linker` \
         (needs LLVM; see this crate's README)",
    );
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
