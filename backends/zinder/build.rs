use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // If `zallet_build` is not set to a known value, use the default "wallet" build.
    // Keep this in sync with zallet-core and the other backend workspaces: the cfg
    // gates wallet-only trait methods in this package's sources and tests.
    #[cfg(not(any(zallet_build = "merchant_terminal", zallet_build = "wallet")))]
    println!("cargo:rustc-cfg=zallet_build=\"wallet\"");

    const PROTO_ROOT: &str = "proto/zinder";
    let proto_files = [
        "proto/zinder/zinder/v1/wallet/wallet.proto",
        "proto/zinder/zinder/v1/ops/server_info.proto",
    ];
    for proto_file in &proto_files {
        println!("cargo::rerun-if-changed={proto_file}");
    }

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&proto_files, &[PROTO_ROOT])?;

    Ok(())
}
