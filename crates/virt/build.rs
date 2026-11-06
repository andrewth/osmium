// SPDX-License-Identifier: GPL-2.0-only
//! Names the AArch64 world switch this build has, if any: `aarch64_hw` for
//! an aarch64 target with `aarch64-el2` or `aarch64-vhe`, and `aarch64_vhe`
//! when it is the VHE one (`aarch64-el2` takes precedence over it).
fn main() {
    println!("cargo::rustc-check-cfg=cfg(aarch64_hw, aarch64_vhe)");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let el2 = std::env::var_os("CARGO_FEATURE_AARCH64_EL2").is_some();
    let vhe = std::env::var_os("CARGO_FEATURE_AARCH64_VHE").is_some();
    if arch == "aarch64" && (el2 || vhe) {
        println!("cargo::rustc-cfg=aarch64_hw");
        if !el2 {
            println!("cargo::rustc-cfg=aarch64_vhe");
        }
    }
}
