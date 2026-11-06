// SPDX-License-Identifier: GPL-2.0-only
//! Links with the linker script shared by the examples for this architecture.

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo::rustc-link-arg=-T{dir}/../link/riscv64.x");
    println!("cargo::rerun-if-changed=../link/riscv64.x");
}
