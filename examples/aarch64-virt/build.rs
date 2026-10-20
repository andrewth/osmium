use std::env;
use std::process::Command;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo::rustc-link-arg=-T{dir}/link.x");
    println!("cargo::rerun-if-changed=link.x");
    build_user_program("aarch64-unknown-none-softfloat", "0x8000000000", &[]);
}

/// Compiles `../user/hello.rs` into a static ELF for `target` at `base`.
fn build_user_program(target: &str, base: &str, extra: &[&str]) {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out = env::var("OUT_DIR").unwrap();
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    println!("cargo::rerun-if-changed=../user/hello.rs");
    let status = Command::new(rustc)
        .args(["--edition=2024", "--crate-type=bin", "-Cpanic=abort", "-Copt-level=s", "-Crelocation-model=static"])
        .arg(format!("--target={target}"))
        .arg(format!("-Clink-arg=--image-base={base}"))
        .args(extra)
        .arg("-o")
        .arg(format!("{out}/hello.elf"))
        .arg(format!("{dir}/../user/hello.rs"))
        .status()
        .expect("failed to run rustc for the user program");
    assert!(status.success(), "building the user program failed");
}
