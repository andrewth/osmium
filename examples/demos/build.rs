//! Builds the user programs in `examples/user` for the kernel's target, for
//! `demos::user` to embed: static ELFs linked at `demos::user::USER_BASE`
//! and, on RISC-V, the position-independent programs too.

use std::env;
use std::process::Command;

fn main() {
    // Only `demos::user` embeds them.
    if env::var_os("CARGO_FEATURE_USER").is_none() {
        return;
    }
    let (Ok(target), Ok(arch)) = (env::var("TARGET"), env::var("CARGO_CFG_TARGET_ARCH")) else {
        fail("cargo did not say what the target is");
    };
    // The link addresses match `USER_BASE` in src/user.rs.
    let (base, extra): (&str, &[&str]) = match arch.as_str() {
        // User code lives at 64 GiB: the medium code model is PC-relative.
        "riscv64" => ("0x1000000000", &["-Ccode-model=medium"]),
        // At 512 GiB, outside the default code model's +-2 GiB range.
        "x86_64" => ("0x8000000000", &["-Ccode-model=large"]),
        "aarch64" => ("0x8000000000", &[]),
        // Not a target the example kernels run on: nothing to embed.
        _ => return,
    };
    let fixed = ["-Crelocation-model=static".to_string(), format!("-Clink-arg=--image-base={base}")];
    let fixed: Vec<&str> = fixed.iter().map(String::as_str).chain(extra.iter().copied()).collect();
    for name in ["hello", "init"] {
        build(name, name, &target, &fixed);
    }
    if arch == "riscv64" {
        build("net", "net", &target, &fixed);
        // `pie.rs` twice, as a static PIE (`pie.elf`) that the kernel
        // relocates and as a dynamically linked program (`dyn.elf`) that
        // names `/bin/ld`, and the interpreter `ld.rs` (`ld.elf`), itself a PIE.
        let pic = ["-Crelocation-model=pic", "-Clink-arg=-pie", "-Clink-arg=-znorelro"];
        build("pie", "pie", &target, &pic);
        build("pie", "dyn", &target, &[&pic[..], &["-Clink-arg=--dynamic-linker=/bin/ld"]].concat());
        build("ld", "ld", &target, &pic);
    }
}

/// Stops the build with `why`.
fn fail(why: &str) -> ! {
    eprintln!("error: {why}");
    std::process::exit(1)
}

/// Compiles `../user/<source>.rs` into `$OUT_DIR/<name>.elf` for `target`.
fn build(source: &str, name: &str, target: &str, extra: &[&str]) {
    let dir = env!("CARGO_MANIFEST_DIR");
    let Ok(out) = env::var("OUT_DIR") else { fail("cargo did not set OUT_DIR") };
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    println!("cargo::rerun-if-changed=../user/{source}.rs");
    let status = Command::new(rustc)
        .args(["--edition=2024", "--crate-type=bin", "-Cpanic=abort", "-Copt-level=s"])
        .arg(format!("--target={target}"))
        .args(extra)
        .arg("-o")
        .arg(format!("{out}/{name}.elf"))
        .arg(format!("{dir}/../user/{source}.rs"))
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(_) => fail(&format!("building ../user/{source}.rs failed")),
        Err(e) => fail(&format!("running rustc for ../user/{source}.rs: {e}")),
    }
}
