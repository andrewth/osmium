// SPDX-License-Identifier: GPL-2.0-only
//! Links with the x86_64 PVH script shared by the examples. The user
//! programs are built by the `demos` crate.

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo::rustc-link-arg=-T{dir}/../link/x86_64.x");
    println!("cargo::rerun-if-changed=../link/x86_64.x");
}
