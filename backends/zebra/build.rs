fn main() {
    // If `zallet_build` is not set to a known value, use the default "wallet" build.
    // (Keep in sync with zallet-core's build script; the cfg gates wallet-only
    // functionality in this package's sources and tests.)
    #[cfg(not(any(zallet_build = "merchant_terminal", zallet_build = "wallet")))]
    println!("cargo:rustc-cfg=zallet_build=\"wallet\"");
}
