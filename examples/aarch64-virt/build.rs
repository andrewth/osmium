//! Links with the AArch64 script shared by the examples. The user
//! programs are built by the `demos` crate.

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo::rustc-link-arg=-T{dir}/../link/aarch64.x");
    println!("cargo::rerun-if-changed=../link/aarch64.x");
}
