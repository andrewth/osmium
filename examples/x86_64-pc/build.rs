use std::env;
use std::process::Command;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo::rustc-link-arg=-T{dir}/link.x");
    println!("cargo::rerun-if-changed=link.x");

    // Compile the user program into a static ELF at the user base address.
    let out = env::var("OUT_DIR").unwrap();
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    println!("cargo::rerun-if-changed=user/hello.rs");
    let status = Command::new(rustc)
        .args([
            "--edition=2024",
            "--crate-type=bin",
            "--target=x86_64-unknown-none",
            "-Cpanic=abort",
            "-Copt-level=s",
            "-Crelocation-model=static",
            // User code lives at 512 GiB, outside the default kernel code
            // model's +-2 GiB range.
            "-Ccode-model=large",
            "-Clink-arg=--image-base=0x8000000000",
            "-o",
        ])
        .arg(format!("{out}/hello.elf"))
        .arg(format!("{dir}/user/hello.rs"))
        .status()
        .expect("failed to run rustc for the user program");
    assert!(status.success(), "building the user program failed");
}
