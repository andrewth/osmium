// SPDX-License-Identifier: GPL-2.0-only
//! Links with the M-mode script: QEMU virt starts M-mode code at the base of
//! RAM.

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo::rustc-link-arg=-T{dir}/link.x");
    println!("cargo::rerun-if-changed=link.x");
}
