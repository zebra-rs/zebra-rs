use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

/// Compile the `bfd-echo-reflector-ebpf` crate for the `bpfel-unknown-none`
/// target and emit the object into `OUT_DIR`, where `main.rs` embeds it via
/// `include_bytes_aligned!`. `Toolchain::default()` resolves to `nightly`, and
/// aya-build invokes it with `-Z build-std=core`.
fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "bfd-echo-reflector-ebpf")
        .ok_or_else(|| anyhow!("bfd-echo-reflector-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
