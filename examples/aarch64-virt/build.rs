use std::env;
use std::process::Command;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    println!("cargo::rustc-link-arg=-T{dir}/link.x");
    println!("cargo::rerun-if-changed=link.x");
    build_user_program("aarch64-unknown-none-softfloat", "0x8000000000", &[]);
}

/// Compiles `../user/hello.rs` and `../user/init.rs` into static ELFs for
/// `target` at `base`.
fn build_user_program(target: &str, base: &str, extra: &[&str]) {
    for name in ["hello", "init"] {
        build_one(name, target, base, extra);
    }
}

fn build_one(name: &str, target: &str, base: &str, extra: &[&str]) {
    let dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let out = env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    println!("cargo::rerun-if-changed=../user/{name}.rs");
    let status = Command::new(rustc)
        .args(["--edition=2024", "--crate-type=bin", "-Cpanic=abort", "-Copt-level=s", "-Crelocation-model=static"])
        .arg(format!("--target={target}"))
        .arg(format!("-Clink-arg=--image-base={base}"))
        .args(extra)
        .arg("-o")
        .arg(format!("{out}/{name}.elf"))
        .arg(format!("{dir}/../user/{name}.rs"))
        .status()
        .expect("failed to run rustc for a user program");
    assert!(status.success(), "building ../user/{name}.rs failed");
}
