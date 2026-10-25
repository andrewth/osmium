use std::env;
use std::process::Command;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    println!("cargo::rustc-link-arg=-T{dir}/link.x");
    println!("cargo::rerun-if-changed=link.x");
    // User code lives at 64 GiB: the medium code model is PC-relative.
    build_user_program("riscv64imac-unknown-none-elf", "0x1000000000", &["-Ccode-model=medium"]);
    build_pie_programs("riscv64imac-unknown-none-elf");
}

/// Compiles the position-independent programs: `../user/pie.rs` twice, as a
/// static PIE (`pie.elf`) that the kernel relocates and as a dynamically
/// linked program (`dyn.elf`) that names `/bin/ld`, and the interpreter
/// `../user/ld.rs` (`ld.elf`), which is itself a PIE.
fn build_pie_programs(target: &str) {
    let pic = ["-Crelocation-model=pic", "-Clink-arg=-pie", "-Clink-arg=-znorelro"];
    build_as("pie", "pie", target, &pic);
    build_as("pie", "dyn", target, &[&pic[..], &["-Clink-arg=--dynamic-linker=/bin/ld"]].concat());
    build_as("ld", "ld", target, &pic);
}

fn build_as(source: &str, name: &str, target: &str, extra: &[&str]) {
    let dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let out = env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    println!("cargo::rerun-if-changed=../user/{source}.rs");
    let status = Command::new(rustc)
        .args(["--edition=2024", "--crate-type=bin", "-Cpanic=abort", "-Copt-level=s"])
        .arg(format!("--target={target}"))
        .args(extra)
        .arg("-o")
        .arg(format!("{out}/{name}.elf"))
        .arg(format!("{dir}/../user/{source}.rs"))
        .status()
        .expect("failed to run rustc for a user program");
    assert!(status.success(), "building ../user/{source}.rs failed");
}

/// Compiles `../user/hello.rs`, `../user/init.rs` and `../user/net.rs` into static ELFs for
/// `target` at `base`.
fn build_user_program(target: &str, base: &str, extra: &[&str]) {
    for name in ["hello", "init", "net"] {
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
