fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile(
        &["proto/handshaker.proto", "proto/shared_alts.proto"],
        &["proto"]
    )?;
    Ok(())
}
