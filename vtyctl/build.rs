fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("../proto/vty.proto")?;
    // Running-config subscription API (`vtyctl watch`).
    tonic_prost_build::compile_protos("../proto/config.proto")?;
    Ok(())
}
