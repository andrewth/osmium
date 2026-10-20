//! Selects the bare-metal backend for freestanding targets, and the
//! host-simulation backend everywhere else.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(bare)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "none" || os == "uefi" {
        println!("cargo::rustc-cfg=bare");
    }
}
